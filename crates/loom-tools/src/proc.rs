//! Running a command so that its output and exit status survive whatever happens to this process.
//!
//! CONTRACT (bodies are placeholders for the implementer; signatures and types are fixed).
//!
//! A command writes its output to a file and its exit status to another, both opened by us and
//! inherited as file descriptors (so they can live where the sandbox forbids the command to open
//! files). Nothing depends on this process staying alive: a restarted daemon can pick the command up
//! again with [`Running::adopt`].
//!
//! ## `spawn`
//! Runs, via `Sandbox::command`, this wrapper script with `spec.script` as `$0`:
//!
//! ```text
//! /bin/bash -c "$0" 2>&1; echo $? >&2
//! ```
//!
//! with stdin `/dev/null`, stdout = `out_path` (created, append), stderr = `exit_path` (created,
//! truncated), working directory `spec.cwd`, environment exactly `spec.env` (cleared first), and its
//! own process group (`process_group(0)`). So `out_path` holds stdout and stderr of the command in
//! the order they were written, and `exit_path` ends up holding the status as a decimal number.
//! Anything else in `exit_path` (the sandbox launcher or the shell complaining) means the command did
//! not start properly: [`Ended::Failed`] carries that text.
//!
//! ## `poll`
//! Non-blocking. If we are the parent, reap the child when it has exited (`try_wait`). The command
//! has ended only when the leader has exited and its process group has no live members. The
//! leader's status is retained while descendants finish, including descendants that keep writing
//! after the shell exits. Zombie-only groups are complete: their file descriptors are closed.
//! The status comes from `exit_path`: a number `n < 128` → `Exit(n)`; `n >= 128` →
//! `Signal(n - 128)`; empty → `Signal(sig)` if the reaped status carries a signal, else `Unknown`;
//! other text → `Failed(text)`. Until then `None`. Once it has returned `Some`, it keeps returning
//! the same value.
//!
//! ## `wait`
//! Polls every 50 ms (25 ms for the first second) until the command ends, `cancel` fires, `deadline`
//! elapses, or the output file is larger than `max_bytes` — whichever happens first — and says
//! which. It never kills anything.
//!
//! ## `terminate`
//! Sends TERM to the process group; polls for up to `grace`; if anything in the group is still alive,
//! sends KILL to the group and waits for live members to disappear. Returns what `poll`
//! then reports. Safe to call after the leader exits while descendants remain. A persisted owner
//! marker refuses a replacement leader when adopting an old pid; an uninspectable group is never
//! signalled blindly. Safe to call on a group that has already ended (does nothing).
//!
//! ## Output
//! `output_len` is the current size of the output file; `read_output(from)` returns its bytes from
//! offset `from` to the end (empty when `from` is at or past the end).
//!
//! Tests required (real processes, `Sandbox` in mode `none`, everything under a `tempfile` dir):
//! exit 0 and non-zero; stdout/stderr interleaved in order; a command killed by a signal; a command
//! that does not exist (exit 127); `wait` ending by deadline, by cancel and by size; `terminate`
//! kills a whole tree (`sleep 300 & sleep 300 & wait`) and a process that ignores TERM; environment
//! is exactly what was given; cwd; output readable incrementally while running; `adopt` of a running
//! command sees it end and reads its status; scripts with quotes, newlines and `$` reach bash intact.

use crate::sandbox::Sandbox;
use std::collections::BTreeMap;
use std::io;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio_util::sync::CancellationToken;

/// Runs the script in `$0` and then appends its exit status, as a number, to stderr (the exit file).
const WRAPPER: &str = "/bin/bash -c \"$0\" 2>&1; echo $? >&2";

/// How long `terminate` waits for the leader and group to disappear after KILL.
const KILL_SETTLE: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
pub struct Spawn {
    pub script: String,
    pub cwd: PathBuf,
    pub env: BTreeMap<String, String>,
    pub out_path: PathBuf,
    pub exit_path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ended {
    Exit(i32),
    Signal(i32),
    /// The process is gone and left no status.
    Unknown,
    /// The command could not be started; the text says why.
    Failed(String),
    /// Ownership or process inspection failed after the command started; its effects may continue.
    TrackingFailed(String),
}

fn signal_name(sig: i32) -> Option<&'static str> {
    Some(match sig {
        libc::SIGHUP => "HUP",
        libc::SIGINT => "INT",
        libc::SIGQUIT => "QUIT",
        libc::SIGILL => "ILL",
        libc::SIGTRAP => "TRAP",
        libc::SIGABRT => "ABRT",
        libc::SIGBUS => "BUS",
        libc::SIGFPE => "FPE",
        libc::SIGKILL => "KILL",
        libc::SIGUSR1 => "USR1",
        libc::SIGSEGV => "SEGV",
        libc::SIGUSR2 => "USR2",
        libc::SIGPIPE => "PIPE",
        libc::SIGALRM => "ALRM",
        libc::SIGTERM => "TERM",
        _ => return None,
    })
}

impl Ended {
    /// An exit, signal, missing status, start failure, or explicit process-tracking failure.
    pub fn outcome(&self) -> String {
        match self {
            Ended::Exit(n) => format!("exit {n}"),
            Ended::Signal(s) => match signal_name(*s) {
                Some(name) => format!("killed by signal {s} ({name})"),
                None => format!("killed by signal {s}"),
            },
            Ended::Unknown => "ended without a status".to_string(),
            Ended::Failed(_) => "could not start".to_string(),
            Ended::TrackingFailed(_) => "process tracking failed".to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WaitEnd {
    Ended(Ended),
    Deadline,
    Cancelled,
    TooMuchOutput,
}

#[derive(Debug)]
pub struct Running {
    pub pid: u32,
    pub out_path: PathBuf,
    pub exit_path: PathBuf,
    pub started_ms: u64,
    child: Option<tokio::process::Child>,
    leader_ended: Option<Ended>,
    ended: Option<Ended>,
    owner: Option<String>,
}

/// The pid as a signal target; pids 0 and 1 are never targets (0 would mean our own group).
fn target(pid: u32) -> Option<i32> {
    i32::try_from(pid).ok().filter(|p| *p > 1)
}

fn kill_ok(pid: i32, sig: i32) -> bool {
    // SAFETY: kill(2) takes plain integers and has no memory effects.
    let r = unsafe { libc::kill(pid, sig) };
    r == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn process_alive(pid: u32) -> bool {
    target(pid).is_some_and(|p| kill_ok(p, 0))
}

fn group_alive(pgid: u32) -> bool {
    target(pgid).is_some_and(|p| kill_ok(-p, 0))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GroupState {
    Gone,
    Live,
    Replaced,
    Unknown,
}

fn owner_path(exit_path: &std::path::Path) -> PathBuf {
    let mut path = exit_path.as_os_str().to_os_string();
    path.push(".owner");
    PathBuf::from(path)
}

/// The marker is an inert argument of the wrapper, not an environment variable or command text.
/// It distinguishes a restored wrapper from an unrelated process that later received its pid.
fn new_owner(spec: &Spawn) -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nonce = format!("{}:{:?}:{}:{}", std::process::id(), SystemTime::now(), NEXT.fetch_add(1, Ordering::Relaxed), spec.exit_path.display());
    format!("loom-owner-{}", loom_core::sha256_hex(nonce.as_bytes()))
}

/// `kill(-pgid, 0)` counts unreaped zombies. Query only ids and states until a live group leader
/// needs an ownership check; other processes' command lines are never read.
fn group_state(pgid: u32, owner: Option<&str>, own_leader: bool) -> GroupState {
    if !group_alive(pgid) {
        return GroupState::Gone;
    }
    let output = match std::process::Command::new("/bin/ps").args(["-A", "-o", "pid=", "-o", "pgid=", "-o", "stat="]).output() {
        Ok(output) if output.status.success() => output,
        _ => return GroupState::Unknown,
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut live = false;
    let mut leader = false;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let pid = fields.next().and_then(|p| p.parse::<u32>().ok());
        let group = fields.next().and_then(|p| p.parse::<u32>().ok());
        let state = fields.next();
        if group == Some(pgid) && state.is_some_and(|s| !s.starts_with('Z')) {
            live = true;
            leader |= pid == Some(pgid);
        }
    }
    if !live {
        return GroupState::Gone;
    }
    if !leader || own_leader {
        return GroupState::Live;
    }
    let Some(owner) = owner else { return GroupState::Replaced };
    let args = match std::process::Command::new("/bin/ps").args(["-ww", "-p", &pgid.to_string(), "-o", "stat=", "-o", "command="]).output() {
        Ok(output) if output.status.success() => output,
        // The wrapper can disappear between the membership snapshot and this lookup. A missing
        // leader cannot be a replacement leader; the next poll checks remaining members again.
        _ if !process_alive(pgid) => return GroupState::Live,
        _ => return GroupState::Unknown,
    };
    let text = String::from_utf8_lossy(&args.stdout);
    let mut fields = text.split_whitespace();
    // A leader can exit after the membership snapshot: zombies have no original argv, and do not
    // mean its pid was reused. The next poll inspects any remaining live descendants.
    if fields.next().is_some_and(|state| state.starts_with('Z')) || fields.any(|argument| argument == owner) {
        GroupState::Live
    } else {
        GroupState::Replaced
    }
}

fn signal_group(pgid: u32, sig: i32) {
    if let Some(p) = target(pgid) {
        kill_ok(-p, sig);
    }
}

/// A last-chance stop when the job table is dropped. Keep the same replacement-leader check as
/// normal cancellation instead of signalling an unchecked numeric pid from an old record.
pub(crate) fn kill_recorded_group(pid: u32, exit_path: &std::path::Path) {
    let owner = std::fs::read_to_string(owner_path(exit_path)).ok();
    if group_state(pid, owner.as_deref(), false) == GroupState::Live {
        signal_group(pid, libc::SIGKILL);
    }
}

pub fn spawn(sandbox: &Sandbox, spec: &Spawn) -> io::Result<Running> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let out = std::fs::OpenOptions::new().create(true).append(true).open(&spec.out_path)?;
    let exit = std::fs::OpenOptions::new().create(true).write(true).truncate(true).open(&spec.exit_path)?;
    let owner = new_owner(spec);
    let mut marker = std::fs::OpenOptions::new().create(true).truncate(true).write(true).mode(0o600).open(owner_path(&spec.exit_path))?;
    marker.write_all(owner.as_bytes())?;
    marker.sync_data()?;
    let (program, mut args) = sandbox.command(WRAPPER);
    args.push(spec.script.clone());
    args.push(owner.clone());
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args)
        .env_clear()
        .envs(&spec.env)
        .current_dir(&spec.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(exit))
        .process_group(0)
        .kill_on_drop(false);
    let child = match cmd.spawn() {
        Ok(child) => child,
        Err(error) => {
            let _ = std::fs::remove_file(owner_path(&spec.exit_path));
            return Err(error);
        }
    };
    let pid = child.id().ok_or_else(|| io::Error::other("the command exited before it could be tracked; run it again"))?;
    let started_ms = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)).unwrap_or(0);
    Ok(Running {
        pid,
        out_path: spec.out_path.clone(),
        exit_path: spec.exit_path.clone(),
        started_ms,
        child: Some(child),
        leader_ended: None,
        ended: None,
        owner: Some(owner),
    })
}

impl Running {
    /// A command started by an earlier run of this program.
    pub fn adopt(pid: u32, out_path: PathBuf, exit_path: PathBuf, started_ms: u64) -> Running {
        let owner = std::fs::read_to_string(owner_path(&exit_path)).ok().filter(|s| s.starts_with("loom-owner-") && !s.chars().any(char::is_whitespace));
        Running { pid, out_path, exit_path, started_ms, child: None, leader_ended: None, ended: None, owner }
    }

    /// The status the exit file holds; `signal` is the signal of the reaped leader, if any.
    fn read_status(&self, signal: Option<i32>) -> Ended {
        let text = std::fs::read_to_string(&self.exit_path).unwrap_or_default();
        let text = text.trim();
        if text.is_empty() {
            return signal.map_or(Ended::Unknown, Ended::Signal);
        }
        // The status line is written last, by the wrapper shell, so when it is there the command did
        // start; what precedes it is the shell's own notice (`Killed: 9`) and is not a failure.
        let last = text.lines().next_back().unwrap_or_default().trim();
        match last.parse::<i32>() {
            Ok(n) if (0..128).contains(&n) => Ended::Exit(n),
            Ok(n) if n >= 128 => Ended::Signal(n - 128),
            _ => Ended::Failed(text.to_string()),
        }
    }

    pub fn poll(&mut self) -> Option<Ended> {
        if let Some(e) = &self.ended {
            return Some(e.clone());
        }
        let (gone, signal) = match self.child.as_mut() {
            Some(child) => match child.try_wait() {
                Ok(Some(status)) => (true, status.signal()),
                Ok(None) => (false, None),
                Err(_) => (!process_alive(self.pid), None),
            },
            None => (!process_alive(self.pid), None),
        };
        if gone && self.leader_ended.is_none() {
            self.leader_ended = Some(self.read_status(signal));
            self.child = None;
        }
        if !gone && self.child.is_some() {
            return None;
        }
        match group_state(self.pid, self.owner.as_deref(), self.child.is_some()) {
            GroupState::Gone => {
                let end = self.leader_ended.clone().unwrap_or_else(|| self.read_status(signal));
                self.ended = Some(end.clone());
                Some(end)
            }
            GroupState::Replaced => {
                let end = Ended::TrackingFailed("the recorded process-group id now belongs to a different leader; it was not signalled".to_string());
                self.ended = Some(end.clone());
                Some(end)
            }
            GroupState::Live | GroupState::Unknown => None,
        }
    }

    pub async fn wait(&mut self, cancel: &CancellationToken, deadline: Option<Duration>, max_bytes: u64) -> WaitEnd {
        let start = Instant::now();
        loop {
            if let Some(e) = self.poll() {
                return WaitEnd::Ended(e);
            }
            if cancel.is_cancelled() {
                return WaitEnd::Cancelled;
            }
            let elapsed = start.elapsed();
            if deadline.is_some_and(|d| elapsed >= d) {
                return WaitEnd::Deadline;
            }
            if self.output_len() > max_bytes {
                return WaitEnd::TooMuchOutput;
            }
            let step = Duration::from_millis(if elapsed < Duration::from_secs(1) { 25 } else { 50 });
            tokio::select! {
                () = cancel.cancelled() => {}
                () = tokio::time::sleep(step) => {}
            }
        }
    }

    pub async fn terminate(&mut self, grace: Duration) -> Ended {
        if let Some(e) = self.poll() {
            return e;
        }
        if !self.signal(libc::SIGTERM) {
            return Ended::TrackingFailed("the process group could not be inspected safely; it may still be running and was not signalled".to_string());
        }
        let until = Instant::now() + grace;
        loop {
            if let Some(end) = self.poll() {
                return end;
            }
            if Instant::now() >= until {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        if !self.signal(libc::SIGKILL) {
            return Ended::TrackingFailed("the process group could not be inspected safely; it may still be running and was not signalled".to_string());
        }
        let limit = Instant::now() + KILL_SETTLE;
        loop {
            if let Some(end) = self.poll() {
                return end;
            }
            if Instant::now() >= limit { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        self.poll().unwrap_or_else(|| Ended::TrackingFailed("the process group has not stopped after KILL; its effects may still continue".to_string()))
    }

    fn signal(&mut self, signal: i32) -> bool {
        match group_state(self.pid, self.owner.as_deref(), self.child.is_some()) {
            GroupState::Gone => true,
            GroupState::Live => { signal_group(self.pid, signal); true }
            GroupState::Replaced | GroupState::Unknown => false,
        }
    }

    pub(crate) fn remove_owner(&self) {
        let _ = std::fs::remove_file(owner_path(&self.exit_path));
    }

    pub fn output_len(&self) -> u64 {
        std::fs::metadata(&self.out_path).map(|m| m.len()).unwrap_or(0)
    }

    pub fn read_output(&self, from: u64) -> io::Result<Vec<u8>> {
        use std::io::{Read, Seek, SeekFrom};
        let mut f = std::fs::File::open(&self.out_path)?;
        if from >= f.metadata()?.len() {
            return Ok(Vec::new());
        }
        f.seek(SeekFrom::Start(from))?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loom_core::config::{SandboxCfg, SandboxMode};
    use std::path::Path;

    struct Fx {
        _dir: tempfile::TempDir,
        root: PathBuf,
        sb: Sandbox,
    }

    fn fx_with(mode: SandboxMode) -> Fx {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().canonicalize().expect("canonical");
        for d in ["ws", "tmp", "home"] {
            std::fs::create_dir_all(root.join(d)).expect("mkdir");
        }
        let cfg = SandboxCfg { mode, ..SandboxCfg::default() };
        let sb = Sandbox::new(&cfg, &root.join("ws"), &root.join("tmp"), &root.join("home"), None).expect("sandbox");
        Fx { _dir: dir, root, sb }
    }

    fn fx() -> Fx {
        fx_with(SandboxMode::None)
    }

    impl Fx {
        fn spec(&self, script: &str) -> Spawn {
            let env = [("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")].iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
            Spawn {
                script: script.to_string(),
                cwd: self.root.clone(),
                env,
                out_path: self.root.join("out"),
                exit_path: self.root.join("exit"),
            }
        }

        fn start(&self, script: &str) -> Running {
            spawn(&self.sb, &self.spec(script)).expect("spawn")
        }

        fn pidfile(&self) -> PathBuf {
            self.root.join("pids")
        }
    }

    fn never() -> CancellationToken {
        CancellationToken::new()
    }

    async fn finish(r: &mut Running) -> Ended {
        match r.wait(&never(), Some(Duration::from_secs(20)), u64::MAX).await {
            WaitEnd::Ended(e) => e,
            other => panic!("expected the command to end, got {other:?}"),
        }
    }

    fn alive(pid: i32) -> bool {
        // SAFETY: signal 0 only tests for existence.
        unsafe { libc::kill(pid, 0) == 0 }
    }

    /// Waits until the file holds `n` pids (one per line).
    async fn read_pids(path: &Path, n: usize) -> Vec<i32> {
        for _ in 0..200 {
            let text = std::fs::read_to_string(path).unwrap_or_default();
            let pids: Vec<i32> = text.lines().filter_map(|l| l.trim().parse().ok()).collect();
            if pids.len() >= n {
                return pids;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("pids never appeared in {}", path.display());
    }

    async fn assert_gone(pids: &[i32]) {
        for _ in 0..200 {
            if pids.iter().all(|p| !alive(*p)) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let left: Vec<_> = pids.iter().filter(|p| alive(**p)).collect();
        panic!("processes survived: {left:?}");
    }

    struct GroupCleanup {
        pid: u32,
        status: PathBuf,
    }

    impl GroupCleanup {
        fn for_running(running: &Running) -> Self {
            Self { pid: running.pid, status: running.exit_path.clone() }
        }
    }

    impl Drop for GroupCleanup {
        fn drop(&mut self) {
            kill_recorded_group(self.pid, &self.status);
        }
    }

    async fn leader_exited(running: &mut Running) {
        for _ in 0..200 {
            running.poll();
            if running.leader_ended.is_some() { return; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the wrapper did not exit");
    }

    #[tokio::test]
    async fn leader_exit_does_not_finish_a_live_group_or_lose_late_output() {
        let f = fx();
        let mut running = f.start("(sleep 1; echo late) & echo first; exit 7");
        let _cleanup = GroupCleanup::for_running(&running);
        leader_exited(&mut running).await;
        assert_eq!(running.leader_ended, Some(Ended::Exit(7)));
        assert_eq!(running.poll(), None, "a surviving descendant still owns the output");
        assert_eq!(finish(&mut running).await, Ended::Exit(7));
        assert_eq!(running.read_output(0).expect("read"), b"first\nlate\n");
    }

    #[tokio::test]
    async fn termination_still_reaches_descendants_after_the_wrapper_exits() {
        let f = fx();
        let script = format!("(trap '' TERM; sleep 300) & echo $! > {}; exit 4", f.pidfile().display());
        let mut running = f.start(&script);
        let _cleanup = GroupCleanup::for_running(&running);
        let pids = read_pids(&f.pidfile(), 1).await;
        leader_exited(&mut running).await;
        assert_eq!(running.poll(), None);
        let end = running.terminate(Duration::from_millis(100)).await;
        assert_eq!(end, Ended::Exit(4), "retain the already known shell status");
        assert_gone(&pids).await;
        assert!(running.poll().is_some());
    }

    #[tokio::test]
    async fn late_descendant_output_is_still_subject_to_the_output_limit() {
        let f = fx();
        let script = format!("(sleep 0.4; head -c 5000 /dev/zero; sleep 300) & echo $! > {}; exit 0", f.pidfile().display());
        let mut running = f.start(&script);
        let _cleanup = GroupCleanup::for_running(&running);
        let pids = read_pids(&f.pidfile(), 1).await;
        leader_exited(&mut running).await;
        assert_eq!(running.wait(&never(), Some(Duration::from_secs(10)), 2000).await, WaitEnd::TooMuchOutput);
        assert_eq!(running.terminate(Duration::from_millis(100)).await, Ended::Exit(0));
        assert_gone(&pids).await;
    }

    #[tokio::test]
    async fn adopted_group_keeps_late_output_after_its_leader_is_reaped() {
        let f = fx();
        let mut running = f.start("(sleep 1; echo late) & echo first; exit 6");
        let _cleanup = GroupCleanup::for_running(&running);
        leader_exited(&mut running).await;
        let mut adopted = Running::adopt(running.pid, running.out_path.clone(), running.exit_path.clone(), running.started_ms);
        drop(running);
        assert_eq!(adopted.poll(), None);
        assert_eq!(finish(&mut adopted).await, Ended::Exit(6));
        assert_eq!(adopted.read_output(0).expect("read"), b"first\nlate\n");
    }

    #[tokio::test]
    async fn adopting_a_replacement_group_leader_never_signals_it() {
        use std::os::unix::process::CommandExt;
        struct Other(std::process::Child);
        impl Drop for Other {
            fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
        }
        let f = fx();
        let mut other = Other(std::process::Command::new("/bin/sleep").arg("300").process_group(0).spawn().expect("spawn unrelated"));
        let spec = f.spec("");
        std::fs::write(&spec.out_path, "").expect("output");
        std::fs::write(&spec.exit_path, "0\n").expect("status");
        std::fs::write(owner_path(&spec.exit_path), "loom-owner-old-job").expect("owner");
        let mut adopted = Running::adopt(other.0.id(), spec.out_path, spec.exit_path, 0);
        assert!(matches!(adopted.poll(), Some(Ended::TrackingFailed(reason)) if reason.contains("different leader")));
        assert!(matches!(adopted.terminate(Duration::ZERO).await, Ended::TrackingFailed(_)));
        assert!(other.0.try_wait().expect("probe unrelated").is_none(), "the unrelated leader was not signalled");
    }

    #[tokio::test]
    async fn a_zombie_only_group_is_complete_without_waiting_for_its_reaper() {
        use std::os::unix::process::CommandExt;
        struct Reap(std::process::Child);
        impl Drop for Reap {
            fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
        }
        let f = fx();
        let child = Reap(std::process::Command::new("/usr/bin/true").process_group(0).spawn().expect("spawn"));
        let pid = child.0.id();
        for _ in 0..100 {
            if group_state(pid, None, false) == GroupState::Gone { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(group_alive(pid), "the unreaped zombie still owns a numeric process-group id");
        assert_eq!(group_state(pid, None, false), GroupState::Gone);
        let spec = f.spec("");
        std::fs::write(&spec.out_path, "").expect("output");
        std::fs::write(&spec.exit_path, "0\n").expect("status");
        let mut adopted = Running::adopt(pid, spec.out_path, spec.exit_path, 0);
        assert_eq!(adopted.poll(), Some(Ended::Exit(0)));
    }

    /// Background children and grandchildren, then `tail`. Their pids go to the pid file.
    fn tree(f: &Fx, tail: &str) -> String {
        let p = f.pidfile();
        let p = p.display();
        format!("sleep 300 & echo $! >> {p}; (sleep 300 & echo $! >> {p}); {tail}")
    }

    #[tokio::test]
    async fn exit_codes_and_outcomes() {
        let f = fx();
        let mut r = f.start("echo hello");
        assert_eq!(finish(&mut r).await, Ended::Exit(0));
        assert_eq!(r.read_output(0).expect("read"), b"hello\n");
        assert_eq!(Ended::Exit(0).outcome(), "exit 0");

        let f = fx();
        let mut r = f.start("exit 3");
        assert_eq!(finish(&mut r).await, Ended::Exit(3));
        assert_eq!(Ended::Exit(3).outcome(), "exit 3");
        // Once ended, it stays ended.
        assert_eq!(r.poll(), Some(Ended::Exit(3)));
        assert_eq!(r.poll(), Some(Ended::Exit(3)));
        assert_eq!(r.terminate(Duration::from_millis(100)).await, Ended::Exit(3));
    }

    #[test]
    fn outcome_texts() {
        assert_eq!(Ended::Signal(9).outcome(), "killed by signal 9 (KILL)");
        assert_eq!(Ended::Signal(15).outcome(), "killed by signal 15 (TERM)");
        assert_eq!(Ended::Signal(40).outcome(), "killed by signal 40");
        assert_eq!(Ended::Unknown.outcome(), "ended without a status");
        assert_eq!(Ended::Failed("x".into()).outcome(), "could not start");
        assert_eq!(Ended::TrackingFailed("x".into()).outcome(), "process tracking failed");
    }

    #[tokio::test]
    async fn output_is_interleaved_in_write_order() {
        let f = fx();
        let mut r = f.start("echo one; echo two >&2; echo three; echo four >&2");
        assert_eq!(finish(&mut r).await, Ended::Exit(0));
        assert_eq!(r.read_output(0).expect("read"), b"one\ntwo\nthree\nfour\n");
    }

    #[tokio::test]
    async fn killed_by_signal_and_missing_command() {
        let f = fx();
        let mut r = f.start("kill -9 $$");
        assert_eq!(finish(&mut r).await, Ended::Signal(9));

        let f = fx();
        let mut r = f.start("definitely-not-a-command-xyz");
        assert_eq!(finish(&mut r).await, Ended::Exit(127));
        assert!(String::from_utf8_lossy(&r.read_output(0).expect("read")).contains("not found"));
    }

    #[tokio::test]
    async fn output_written_just_before_exit_is_complete() {
        let f = fx();
        let mut r = f.start("for i in $(seq 1 3000); do echo line$i; done; echo last >&2; exit 4");
        assert_eq!(finish(&mut r).await, Ended::Exit(4));
        let text = String::from_utf8(r.read_output(0).expect("read")).expect("utf-8");
        assert_eq!(text.lines().count(), 3001);
        assert!(text.ends_with("line3000\nlast\n"));
        assert_eq!(r.output_len(), text.len() as u64);
    }

    #[tokio::test]
    async fn status_file_failure_text_is_reported() {
        let f = fx();
        let (out, exit) = (f.root.join("o"), f.root.join("e"));
        std::fs::write(&out, "").expect("write");
        // A pid that is certainly gone.
        let mut gone = std::process::Command::new("/usr/bin/true").spawn().expect("spawn");
        gone.wait().expect("wait");
        let pid = gone.id();
        let cases = [
            ("", Ended::Unknown),
            ("0\n", Ended::Exit(0)),
            ("5\n", Ended::Exit(5)),
            ("127\n", Ended::Exit(127)),
            ("130\n", Ended::Signal(2)),
            ("137\n", Ended::Signal(9)),
            ("sandbox-exec: bad profile\n", Ended::Failed("sandbox-exec: bad profile".into())),
            ("bash: line 1: 77 Killed: 9  /bin/bash -c \"$0\"\n137\n", Ended::Signal(9)),
        ];
        for (text, want) in cases {
            std::fs::write(&exit, text).expect("write");
            let mut r = Running::adopt(pid, out.clone(), exit.clone(), 0);
            assert_eq!(r.poll(), Some(want), "exit file {text:?}");
        }
    }

    #[tokio::test]
    async fn wait_ends_by_deadline_cancel_and_size() {
        let f = fx();
        let mut r = f.start("sleep 30");
        let t = Instant::now();
        assert_eq!(r.wait(&never(), Some(Duration::from_millis(300)), u64::MAX).await, WaitEnd::Deadline);
        assert!(t.elapsed() >= Duration::from_millis(300) && t.elapsed() < Duration::from_secs(5));
        // wait kills nothing.
        assert!(r.poll().is_none());
        let end = r.terminate(Duration::from_secs(2)).await;
        assert_eq!(end, Ended::Signal(15));

        let f = fx();
        let mut r = f.start("sleep 30");
        let token = never();
        let t2 = token.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            t2.cancel();
        });
        assert_eq!(r.wait(&token, None, u64::MAX).await, WaitEnd::Cancelled);
        assert!(r.poll().is_none());
        r.terminate(Duration::from_secs(2)).await;

        let f = fx();
        let mut r = f.start("while :; do echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; done");
        assert_eq!(r.wait(&never(), Some(Duration::from_secs(20)), 10_000).await, WaitEnd::TooMuchOutput);
        assert!(r.output_len() > 10_000);
        assert!(r.poll().is_none());
        r.terminate(Duration::from_secs(2)).await;
        assert!(r.poll().is_some());
    }

    #[tokio::test]
    async fn terminate_kills_the_whole_tree() {
        let f = fx();
        let mut r = f.start(&tree(&f, "wait"));
        let pids = read_pids(&f.pidfile(), 2).await;
        assert!(pids.iter().all(|p| alive(*p)));
        let end = r.terminate(Duration::from_secs(2)).await;
        assert!(matches!(end, Ended::Signal(_)), "{end:?}");
        assert_gone(&pids).await;
        assert!(!alive(r.pid as i32));
    }

    #[tokio::test]
    async fn cancellation_leaves_no_survivors() {
        let f = fx();
        let mut r = f.start(&tree(&f, "wait"));
        let pids = read_pids(&f.pidfile(), 2).await;
        let token = never();
        token.cancel();
        assert_eq!(r.wait(&token, None, u64::MAX).await, WaitEnd::Cancelled);
        r.terminate(Duration::from_secs(2)).await;
        assert_gone(&pids).await;
    }

    #[tokio::test]
    async fn deadline_leaves_no_survivors() {
        let f = fx();
        let mut r = f.start(&tree(&f, "wait"));
        let pids = read_pids(&f.pidfile(), 2).await;
        assert_eq!(r.wait(&never(), Some(Duration::from_millis(200)), u64::MAX).await, WaitEnd::Deadline);
        r.terminate(Duration::from_secs(2)).await;
        assert_gone(&pids).await;
    }

    #[tokio::test]
    async fn output_limit_leaves_no_survivors() {
        let f = fx();
        let mut r = f.start(&tree(&f, "while :; do echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; done"));
        let pids = read_pids(&f.pidfile(), 2).await;
        assert_eq!(r.wait(&never(), Some(Duration::from_secs(20)), 5_000).await, WaitEnd::TooMuchOutput);
        r.terminate(Duration::from_secs(2)).await;
        assert_gone(&pids).await;
    }

    #[tokio::test]
    async fn a_process_that_ignores_term_is_killed_after_the_grace_period() {
        let f = fx();
        let p = f.pidfile();
        let script = format!("trap '' TERM; echo $$ >> {p}; while :; do sleep 1; done", p = p.display());
        let mut r = f.start(&script);
        let pids = read_pids(&p, 1).await;
        let t = Instant::now();
        let end = r.terminate(Duration::from_millis(400)).await;
        assert!(t.elapsed() >= Duration::from_millis(400), "returned before the grace period: {:?}", t.elapsed());
        assert!(matches!(end, Ended::Signal(_)), "{end:?}");
        assert_gone(&pids).await;
        assert!(!group_alive(r.pid));
    }

    #[tokio::test]
    async fn environment_is_exactly_what_was_given() {
        let f = fx();
        let mut spec = f.spec("env");
        spec.env.insert("FOO".into(), "bar baz".into());
        let mut r = spawn(&f.sb, &spec).expect("spawn");
        assert_eq!(finish(&mut r).await, Ended::Exit(0));
        let text = String::from_utf8(r.read_output(0).expect("read")).expect("utf-8");
        let mut names: Vec<&str> = text.lines().filter_map(|l| l.split_once('=').map(|(k, _)| k)).collect();
        names.retain(|n| !["PWD", "SHLVL", "_", "OLDPWD"].contains(n));
        names.sort_unstable();
        assert_eq!(names, ["FOO", "PATH"]);
        assert!(text.contains("FOO=bar baz\n"));
    }

    #[tokio::test]
    async fn working_directory_is_used() {
        let f = fx();
        let mut spec = f.spec("pwd -P");
        spec.cwd = f.root.join("ws");
        let mut r = spawn(&f.sb, &spec).expect("spawn");
        assert_eq!(finish(&mut r).await, Ended::Exit(0));
        assert_eq!(String::from_utf8(r.read_output(0).expect("read")).expect("utf-8"), format!("{}\n", f.root.join("ws").display()));
        let mut spec = f.spec("true");
        spec.cwd = f.root.join("missing");
        assert!(spawn(&f.sb, &spec).is_err());
    }

    #[tokio::test]
    async fn output_can_be_read_while_running() {
        let f = fx();
        let mut r = f.start("echo first; sleep 1; echo second");
        for _ in 0..200 {
            if r.output_len() > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(r.read_output(0).expect("read"), b"first\n");
        assert!(r.poll().is_none());
        let seen = r.output_len();
        assert_eq!(finish(&mut r).await, Ended::Exit(0));
        assert_eq!(r.read_output(seen).expect("read"), b"second\n");
        assert_eq!(r.read_output(0).expect("read"), b"first\nsecond\n");
        assert!(r.read_output(r.output_len()).expect("read").is_empty());
        assert!(r.read_output(10_000).expect("read").is_empty());
    }

    #[tokio::test]
    async fn adopt_picks_up_a_running_command() {
        let f = fx();
        let r = f.start("echo started; sleep 1; echo done; exit 5");
        let (pid, out, exit, ms) = (r.pid, r.out_path.clone(), r.exit_path.clone(), r.started_ms);
        drop(r);
        let mut adopted = Running::adopt(pid, out, exit, ms);
        assert!(adopted.poll().is_none());
        let end = adopted.wait(&never(), Some(Duration::from_secs(20)), u64::MAX).await;
        assert_eq!(end, WaitEnd::Ended(Ended::Exit(5)));
        assert_eq!(adopted.read_output(0).expect("read"), b"started\ndone\n");
    }

    #[tokio::test]
    async fn adopted_commands_can_be_terminated_as_a_group() {
        let f = fx();
        let r = f.start(&tree(&f, "wait"));
        let pids = read_pids(&f.pidfile(), 2).await;
        let (pid, out, exit, ms) = (r.pid, r.out_path.clone(), r.exit_path.clone(), r.started_ms);
        drop(r);
        let mut adopted = Running::adopt(pid, out, exit, ms);
        assert!(adopted.poll().is_none());
        adopted.terminate(Duration::from_secs(2)).await;
        assert!(adopted.poll().is_some());
        assert_gone(&pids).await;
    }

    #[tokio::test]
    async fn scripts_reach_bash_intact() {
        let f = fx();
        let script = "x='a \"quoted\" it'\"'\"'s'\nprintf '%s|' \"$x\" '$HOME' \"$((1+2))\"\necho\n";
        let mut r = f.start(script);
        assert_eq!(finish(&mut r).await, Ended::Exit(0));
        assert_eq!(String::from_utf8(r.read_output(0).expect("read")).expect("utf-8"), "a \"quoted\" it's|$HOME|3|\n");
    }

    #[tokio::test]
    async fn output_is_appended_and_exit_file_truncated() {
        let f = fx();
        let mut r = f.start("echo one; exit 1");
        assert_eq!(finish(&mut r).await, Ended::Exit(1));
        let mut r = f.start("echo two");
        assert_eq!(finish(&mut r).await, Ended::Exit(0));
        assert_eq!(r.read_output(0).expect("read"), b"one\ntwo\n");
    }

    #[tokio::test]
    async fn works_under_the_seatbelt_sandbox() {
        if !Path::new("/usr/bin/sandbox-exec").exists() {
            return;
        }
        let f = fx_with(SandboxMode::Seatbelt);
        let mut spec = f.spec("echo inside > made.txt; echo to-out; cat /Users/nonexistent-dir-xyz/x; exit 7");
        spec.cwd = f.root.join("ws");
        let mut r = spawn(&f.sb, &spec).expect("spawn");
        assert_eq!(finish(&mut r).await, Ended::Exit(7));
        assert_eq!(std::fs::read_to_string(f.root.join("ws/made.txt")).expect("read"), "inside\n");
        assert!(String::from_utf8_lossy(&r.read_output(0).expect("read")).starts_with("to-out\n"));
        // The group dies as a group under the sandbox as well.
        let mut r = f.start(&tree(&f, "wait"));
        let pids = read_pids(&f.pidfile(), 2).await;
        r.terminate(Duration::from_secs(2)).await;
        assert_gone(&pids).await;
    }
}
