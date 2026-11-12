//! Running a command so that its output and exit status survive whatever happens to this process.
//!
//! CONTRACT.
//!
//! A command writes its output to a file and its exit status to another, both opened by us and
//! inherited as file descriptors (so they can live where the sandbox forbids the command to open
//! files). The files outlive this process; a command is not carried over: a restarted daemon does not
//! adopt it but kills what its pid record lets it confirm (`jobs::clear_leftovers`).
//!
//! ## `spawn`
//! Runs, via `Sandbox::command`, this wrapper script with `spec.script` as `$0`:
//!
//! ```text
//! /bin/bash -c "$0" 2>&1; echo $? >&2
//! ```
//!
//! with stdin `/dev/null`, stdout = `out_path` and stderr = `exit_path` (both created fresh: a
//! leftover file of that name is removed first, never appended to), working directory `spec.cwd`,
//! environment exactly `spec.env` (cleared first), and its
//! own process group (`process_group(0)`). So `out_path` holds stdout and stderr of the command in
//! the order they were written, and `exit_path` ends up holding the status as a decimal number.
//! Anything else in `exit_path` (the sandbox launcher or the shell complaining) means the command did
//! not start properly: [`Ended::Failed`] carries that text.
//!
//! ## `poll`
//! Non-blocking. If we are the parent, reap the child when it has exited (`try_wait`). The command
//! has ended when the child was reaped or — adopted commands — `kill(pid, 0)` says the process is
//! gone. Then the status comes from `exit_path`: a number `0..=255` → `Exit(n)` (a code above 128 is
//! only conventionally a signal; see [`Ended::fact`]); empty → `Signal(sig)` if the reaped leader
//! itself reports a signal, else `Unknown`; other text → `Failed(text)`. Until then `None`. Once it
//! has returned `Some`, it keeps returning the same value.
//!
//! ## `wait`
//! Polls every 50 ms (25 ms for the first second) until the command ends, `cancel` fires, `deadline`
//! elapses, or the output file is larger than `max_bytes` — whichever happens first — and says
//! which. It never kills anything.
//!
//! ## Process groups
//! A command is not over while its group has live members. `poll` and `wait` report the leader;
//! `group_alive` and `wait_group` look at the whole group. Once the leader has ended and the group has
//! been seen empty the command is over for good: its group id may be reused, so it is never probed or
//! signalled again. A `Running` that is dropped while armed (not over, and not `disarm`ed, as
//! `JobTable::register` does) SIGKILLs its group.
//!
//! ## Pid record
//! `spawn` writes `<job>.pid` beside the output file, `<pid> <start time>` of the leader, for crash
//! recovery, and an `owner <pid> <start time>` line naming this process; a command whose record
//! cannot be written is stopped and the spawn fails. While `wait_group` sees the group outlive its
//! leader it adds a `member <pid> <start time>` line for each process then in the group, and
//! replaces them when none of those is left. `kill_recorded_group` signals a recorded group only when
//! its leader, or a recorded member that is still in the group, is alive with the recorded start
//! time.
//!
//! ## `terminate`
//! Sends TERM to the process group; polls for up to `grace`; if anything in the group is still alive
//! (`kill(-pgid, 0)`), sends KILL to the group and waits for the leader to go. Returns what `poll`
//! then reports. On a command whose leader has ended and whose group is empty it does nothing; a
//! group that outlived its leader is stopped all the same.
//! `terminate_within(grace, max_bytes)` also ends the grace period as soon as the output file passes
//! `max_bytes`, so that a command which ignores TERM cannot write through it.
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
use std::path::{Path, PathBuf};
use std::process::Stdio;
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

/// The highest signal number of this platform; a larger `code - 128` is not a signal.
const MAX_SIGNAL: i32 = if cfg!(target_os = "linux") { 64 } else { 31 };

impl Ended {
    /// A line explaining an exit code above 128, which conventionally means death by signal `code - 128`.
    /// The signal is named only when `code - 128` is a signal number at all.
    pub fn fact(&self) -> Option<String> {
        match self {
            Ended::Exit(n) if *n > 128 => {
                let sig = n - 128;
                let convention = format!("exit code {n}: 128+N conventionally means the command was killed by signal N");
                Some(if sig <= MAX_SIGNAL {
                    let name = signal_name(sig).map(|s| format!(" ({s})")).unwrap_or_default();
                    format!("{convention}, here signal {sig}{name}")
                } else {
                    format!("{convention}, but {sig} is not a signal number, so this is the command's own exit code")
                })
            }
            _ => None,
        }
    }

    /// `exit 0`, `exit 3`, `killed by signal 9 (KILL)`, `ended without a status`, `could not start`.
    pub fn outcome(&self) -> String {
        match self {
            Ended::Exit(n) => format!("exit {n}"),
            Ended::Signal(s) => match signal_name(*s) {
                Some(name) => format!("killed by signal {s} ({name})"),
                None => format!("killed by signal {s}"),
            },
            Ended::Unknown => "ended without a status".to_string(),
            Ended::Failed(_) => "could not start".to_string(),
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
    ended: Option<Ended>,
    /// While set, dropping this value kills the command's process group.
    armed: bool,
    /// Set once the leader has ended and the group has been seen empty; the group id is not ours after that.
    over: bool,
    /// The leader's start time, as written to the pid record.
    start: Option<String>,
    /// The group members named in the pid record (none while the leader runs).
    members: Vec<(u32, String)>,
}

impl Drop for Running {
    fn drop(&mut self) {
        if self.armed && group_alive(self.pid) {
            signal_group(self.pid, libc::SIGKILL);
        }
    }
}

/// Where `spawn` records the leader's pid and start time for a command whose output goes to `out_path`.
pub fn pid_path(out_path: &Path) -> PathBuf {
    out_path.with_extension("pid")
}

/// The start time of process `pid` as the OS reports it (text, comparable only with itself), or `None`
/// when it cannot be read or the process is gone.
pub fn process_start(pid: u32) -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let p = i32::try_from(pid).ok()?;
        let size = i32::try_from(std::mem::size_of::<libc::proc_bsdinfo>()).ok()?;
        // SAFETY: proc_bsdinfo is plain integers, for which all-zero is a valid value.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        // SAFETY: the buffer is `size` bytes of a live, exclusively borrowed struct.
        let n = unsafe { libc::proc_pidinfo(p, libc::PROC_PIDTBSDINFO, 0, (&mut info as *mut libc::proc_bsdinfo).cast(), size) };
        (n == size).then(|| format!("{}.{:06}", info.pbi_start_tvsec, info.pbi_start_tvusec))
    }
    #[cfg(target_os = "linux")]
    {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        // Field 22 (start time in ticks); fields after the parenthesised name begin at field 3.
        let rest = stat.rsplit_once(')')?.1;
        rest.split_whitespace().nth(19).map(str::to_string)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = pid;
        None
    }
}

/// What a pid record says about a command's process group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PidRecord {
    /// The leader's pid, which is also the id of the process group.
    pub pid: u32,
    /// The leader's start time (`None` when it could not be read at spawn).
    pub start: Option<String>,
    /// Processes seen in the group after its leader had exited, each with its start time.
    pub members: Vec<(u32, String)>,
    /// The process that started the command (pid and start time), when it could be read.
    pub owner: Option<(u32, String)>,
}

impl PidRecord {
    /// Whether the command was started by this very process (not by an earlier run of it).
    pub fn is_ours(&self) -> bool {
        self.owner.is_some() && self.owner == this_process()
    }
}

/// This process as a pid record names it: its pid and start time.
fn this_process() -> Option<(u32, String)> {
    static ME: std::sync::OnceLock<Option<(u32, String)>> = std::sync::OnceLock::new();
    ME.get_or_init(|| {
        let pid = std::process::id();
        process_start(pid).map(|start| (pid, start))
    })
    .clone()
}

/// What became of a recorded process group (see [`kill_recorded_group`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordedGroup {
    /// No process group with the recorded id is alive.
    Gone,
    /// A group with the recorded id is alive, but nothing confirms that it is the recorded one: not signalled.
    Unconfirmed,
    /// The group was confirmed and SIGKILLed.
    Killed,
}

/// At most this many group members are named in a pid record; one that is still there confirms the group.
const MAX_RECORDED_MEMBERS: usize = 32;

/// The record as text: `<pid> <start time or ->`, then one `member <pid> <start time>` line per member
/// and an `owner <pid> <start time>` line.
fn write_pid_record(path: &Path, record: &PidRecord) -> io::Result<()> {
    let mut text = format!("{} {}\n", record.pid, record.start.as_deref().unwrap_or("-"));
    for (pid, start) in &record.members {
        text.push_str(&format!("member {pid} {start}\n"));
    }
    if let Some((pid, start)) = &record.owner {
        text.push_str(&format!("owner {pid} {start}\n"));
    }
    std::fs::write(path, text)
}

/// The pid record left by an earlier run, or `None` when there is none or it cannot be understood.
pub fn read_pid_record(path: &Path) -> Option<PidRecord> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut lines = text.lines();
    let mut leader = lines.next()?.split_whitespace();
    let pid = leader.next()?.parse().ok()?;
    let start = leader.next().filter(|s| *s != "-").map(str::to_string);
    let (mut members, mut owner) = (Vec::new(), None);
    for line in lines {
        let mut parts = line.split_whitespace();
        let (Some(kind), Some(pid), Some(start)) = (parts.next(), parts.next(), parts.next()) else { continue };
        let Ok(pid) = pid.parse() else { continue };
        match kind {
            "member" => members.push((pid, start.to_string())),
            "owner" => owner = Some((pid, start.to_string())),
            _ => {}
        }
    }
    Some(PidRecord { pid, start, members, owner })
}

/// The process group of `pid`, when that process exists.
fn pgid_of(pid: u32) -> Option<u32> {
    let p = target(pid)?;
    // SAFETY: getpgid(2) takes a plain integer and has no memory effects.
    u32::try_from(unsafe { libc::getpgid(p) }).ok()
}

/// The pids of the processes in group `pgid`, as far as the OS lists them.
fn group_pids(pgid: u32) -> Vec<u32> {
    #[cfg(target_os = "macos")]
    {
        const MAX_PIDS: usize = 1024;
        let Some(pg) = target(pgid) else { return Vec::new() };
        let mut buf: [libc::pid_t; MAX_PIDS] = [0; MAX_PIDS];
        let bytes = i32::try_from(std::mem::size_of_val(&buf)).unwrap_or(0);
        // SAFETY: the buffer is `bytes` bytes of live, exclusively borrowed integers.
        let n = unsafe { libc::proc_listpgrppids(pg, buf.as_mut_ptr().cast(), bytes) };
        let n = usize::try_from(n).unwrap_or(0).min(MAX_PIDS);
        buf.iter().take(n).filter_map(|p| u32::try_from(*p).ok()).filter(|p| target(*p).is_some()).collect()
    }
    #[cfg(target_os = "linux")]
    {
        let Ok(entries) = std::fs::read_dir("/proc") else { return Vec::new() };
        entries
            .flatten()
            .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
            .filter(|pid| pgid_of(*pid) == Some(pgid))
            .collect()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = pgid;
        Vec::new()
    }
}

/// The live processes of group `pgid` with their start times: what identifies a group whose leader is gone.
fn group_members(pgid: u32) -> Vec<(u32, String)> {
    let mut members: Vec<(u32, String)> = group_pids(pgid).into_iter().filter_map(|pid| Some((pid, process_start(pid)?))).collect();
    members.sort();
    members.truncate(MAX_RECORDED_MEMBERS);
    members
}

/// Whether `pid` is still the process that started at `start` and is in group `pgid`.
fn is_member(pgid: u32, pid: u32, start: &str) -> bool {
    process_start(pid).as_deref() == Some(start) && pgid_of(pid) == Some(pgid)
}

/// SIGKILLs the recorded group when it is alive and confirmed to be the recorded one: its leader is
/// still the recorded process (same start time), or a recorded member is (same start time, still in
/// the group). A group whose identity cannot be confirmed is never signalled.
pub fn kill_recorded_group(record: &PidRecord) -> RecordedGroup {
    if !group_alive(record.pid) {
        return RecordedGroup::Gone;
    }
    let leader = record.start.as_deref().is_some_and(|start| process_start(record.pid).as_deref() == Some(start));
    if !leader && !record.members.iter().any(|(pid, start)| is_member(record.pid, *pid, start)) {
        return RecordedGroup::Unconfirmed;
    }
    signal_group(record.pid, libc::SIGKILL);
    RecordedGroup::Killed
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

fn signal_group(pgid: u32, sig: i32) {
    if let Some(p) = target(pgid) {
        kill_ok(-p, sig);
    }
}

/// Removes a leftover file of an earlier command so that the new one starts from nothing.
fn remove_stale(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

pub fn spawn(sandbox: &Sandbox, spec: &Spawn) -> io::Result<Running> {
    let pid_file = pid_path(&spec.out_path);
    for stale in [&spec.out_path, &spec.exit_path, &pid_file] {
        remove_stale(stale)?;
    }
    let out = std::fs::OpenOptions::new().create_new(true).append(true).open(&spec.out_path)?;
    let exit = std::fs::OpenOptions::new().create_new(true).write(true).open(&spec.exit_path)?;
    let (program, mut args) = sandbox.command(WRAPPER);
    args.push(spec.script.clone());
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
    let child = cmd.spawn()?;
    let pid = child.id().ok_or_else(|| io::Error::other("the command exited before it could be tracked; run it again"))?;
    let started_ms = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)).unwrap_or(0);
    let running = Running {
        pid,
        out_path: spec.out_path.clone(),
        exit_path: spec.exit_path.clone(),
        started_ms,
        child: Some(child),
        ended: None,
        armed: true,
        over: false,
        start: process_start(pid),
        members: Vec::new(),
    };
    recorded(running, &pid_file)
}

/// Writes the command's pid record. A command that cannot be recorded would be unknown after a crash,
/// so it is not left running: dropping the armed `Running` kills its group, and the spawn fails.
fn recorded(running: Running, pid_file: &Path) -> io::Result<Running> {
    let record = PidRecord { pid: running.pid, start: running.start.clone(), members: Vec::new(), owner: this_process() };
    match write_pid_record(pid_file, &record) {
        Ok(()) => Ok(running),
        Err(e) => {
            let _ = std::fs::remove_file(pid_file);
            Err(io::Error::new(e.kind(), format!("its pid record {} could not be written: {e}", pid_file.display())))
        }
    }
}

impl Running {
    /// A command started by an earlier run of this program.
    pub fn adopt(pid: u32, out_path: PathBuf, exit_path: PathBuf, started_ms: u64) -> Running {
        let (child, ended, start, members) = (None, None, None, Vec::new());
        Running { pid, out_path, exit_path, started_ms, child, ended, armed: false, over: false, start, members }
    }

    /// Ends the drop guard: the command's group is now somebody else's to stop.
    pub fn disarm(&mut self) {
        self.armed = false;
    }

    /// Whether any process of the command's group is alive, the leader or not. Once the leader has
    /// ended and the group has been seen empty the answer stays `false` and the drop guard is off:
    /// the group id may be reused from then on, so it is not probed or signalled again.
    pub fn group_alive(&mut self) -> bool {
        if self.over {
            return false;
        }
        if group_alive(self.pid) {
            return true;
        }
        if self.poll().is_some() {
            self.over = true;
            self.armed = false;
        }
        false
    }

    /// Keeps the pid record able to identify the group once its leader is gone: when none of the
    /// members recorded so far is left in the group, the processes now in it are recorded instead.
    fn record_members(&mut self) {
        if self.members.iter().any(|(pid, start)| is_member(self.pid, *pid, start)) {
            return;
        }
        let members = group_members(self.pid);
        if members == self.members {
            return;
        }
        let pid_file = pid_path(&self.out_path);
        let record = PidRecord { pid: self.pid, start: self.start.clone(), members, owner: this_process() };
        if let Err(e) = write_pid_record(&pid_file, &record) {
            let path = pid_file.display();
            tracing::warn!(pid = self.pid, "pid record {path} not updated ({e}); after a crash this group would not be recognised");
        }
        self.members = record.members;
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
            Ok(n) if (0..=255).contains(&n) => Ended::Exit(n),
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
        if !gone {
            return None;
        }
        let e = self.read_status(signal);
        self.ended = Some(e.clone());
        Some(e)
    }

    pub async fn wait(&mut self, cancel: &CancellationToken, deadline: Option<Duration>, max_bytes: u64) -> WaitEnd {
        self.wait_with(cancel, deadline, max_bytes, false).await
    }

    /// Like [`Running::wait`], but the command is over only when its whole process group is gone;
    /// `Ended` then carries the leader's status.
    pub async fn wait_group(&mut self, cancel: &CancellationToken, deadline: Option<Duration>, max_bytes: u64) -> WaitEnd {
        self.wait_with(cancel, deadline, max_bytes, true).await
    }

    async fn wait_with(&mut self, cancel: &CancellationToken, deadline: Option<Duration>, max_bytes: u64, whole_group: bool) -> WaitEnd {
        let start = Instant::now();
        loop {
            if let Some(e) = self.poll() {
                // Asked in either mode: seeing the group empty is what ends the drop guard.
                if !self.group_alive() || !whole_group {
                    return WaitEnd::Ended(e);
                }
                self.record_members();
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
        self.terminate_within(grace, u64::MAX).await
    }

    /// Like [`Running::terminate`], but the grace period is over as soon as the output file is larger
    /// than `max_bytes`: a command that ignores TERM must not go on writing until the grace has run out.
    pub async fn terminate_within(&mut self, grace: Duration, max_bytes: u64) -> Ended {
        if let Some(e) = self.poll().filter(|_| !self.group_alive()) {
            return e;
        }
        signal_group(self.pid, libc::SIGTERM);
        let until = Instant::now() + grace;
        loop {
            let ended = self.poll().is_some();
            if (ended && !self.group_alive()) || Instant::now() >= until || self.output_len() > max_bytes {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        if self.group_alive() {
            return self.kill().await;
        }
        self.poll().unwrap_or(Ended::Unknown)
    }

    /// SIGKILLs the whole group at once (no TERM, no grace: used when the command must stop writing
    /// now) and waits for the leader and the group to go.
    pub async fn kill(&mut self) -> Ended {
        if self.group_alive() {
            signal_group(self.pid, libc::SIGKILL);
        }
        let limit = Instant::now() + KILL_SETTLE;
        loop {
            let ended = self.poll().is_some();
            if (ended && !self.group_alive()) || Instant::now() >= limit {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        self.poll().unwrap_or(Ended::Unknown)
    }

    pub fn output_len(&self) -> u64 {
        std::fs::metadata(&self.out_path).map(|m| m.len()).unwrap_or(0)
    }

    /// The first `max` bytes of the output file and the file's size when it was opened.
    pub fn read_output_capped(&self, max: u64) -> io::Result<(Vec<u8>, u64)> {
        use std::io::Read;
        let f = std::fs::File::open(&self.out_path)?;
        let len = f.metadata()?.len();
        let mut buf = Vec::new();
        f.take(max).read_to_end(&mut buf)?;
        Ok((buf, len))
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
    }

    #[tokio::test]
    async fn exit_128_and_255_are_exit_codes_and_above_128_has_a_fact() {
        for (code, want_fact) in [(128, false), (255, true)] {
            let f = fx();
            let mut r = f.start(&format!("exit {code}"));
            let end = finish(&mut r).await;
            assert_eq!(end, Ended::Exit(code));
            assert_eq!(end.outcome(), format!("exit {code}"));
            assert_eq!(end.fact().is_some(), want_fact);
        }
        let fact = Ended::Exit(137).fact().expect("fact");
        assert!(fact.contains("128+N") && fact.contains("here signal 9 (KILL)"), "{fact}");
        assert!(Ended::Exit(128 + 31).fact().expect("fact").contains("here signal 31"));
        // 255 - 128 is not a signal number: the convention is stated, no signal is claimed.
        for code in [255, 128 + MAX_SIGNAL + 1] {
            let fact = Ended::Exit(code).fact().expect("fact");
            assert!(fact.contains("128+N conventionally means") && !fact.contains("here signal"), "{fact}");
            assert!(fact.contains(&format!("{} is not a signal number", code - 128)), "{fact}");
        }
        assert!(Ended::Signal(9).fact().is_none() && Ended::Exit(3).fact().is_none());
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
        // The inner shell dies of the signal; the wrapper survives and reports 137 as an exit code.
        let mut r = f.start("kill -9 $$");
        assert_eq!(finish(&mut r).await, Ended::Exit(137));

        // The leader itself killed by a signal is a signal.
        let f = fx();
        let mut r = f.start("kill -9 $PPID");
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
            ("128\n", Ended::Exit(128)),
            ("130\n", Ended::Exit(130)),
            ("137\n", Ended::Exit(137)),
            ("255\n", Ended::Exit(255)),
            ("256\n", Ended::Failed("256".into())),
            ("sandbox-exec: bad profile\n", Ended::Failed("sandbox-exec: bad profile".into())),
            ("bash: line 1: 77 Killed: 9  /bin/bash -c \"$0\"\n137\n", Ended::Exit(137)),
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
    async fn a_term_ignoring_writer_is_killed_at_once_and_the_read_is_bounded() {
        let f = fx();
        let script = "trap '' TERM; while :; do echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; done";
        let mut r = f.start(script);
        assert_eq!(r.wait(&never(), Some(Duration::from_secs(20)), 5_000).await, WaitEnd::TooMuchOutput);
        let t = Instant::now();
        r.kill().await;
        assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
        assert!(!r.group_alive());
        let (kept, size) = r.read_output_capped(5_000).expect("read");
        assert_eq!(kept.len(), 5_000);
        assert!(size >= 5_000);
    }

    #[tokio::test]
    async fn the_group_outlives_its_leader_and_is_still_tracked() {
        let f = fx();
        let p = f.pidfile();
        let mut r = f.start(&format!("sleep 300 & echo $! >> {}", p.display()));
        let pids = read_pids(&p, 1).await;
        assert_eq!(finish(&mut r).await, Ended::Exit(0));
        assert!(r.group_alive());
        // `wait_group` does not report the end while the child lives.
        assert_eq!(r.wait_group(&never(), Some(Duration::from_millis(300)), u64::MAX).await, WaitEnd::Deadline);
        // terminate acts on the group although the leader is gone.
        r.terminate(Duration::from_secs(2)).await;
        assert_gone(&pids).await;
        assert!(!r.group_alive());

        let mut r = f.start("sleep 0.5 & exit 3");
        assert_eq!(r.wait_group(&never(), Some(Duration::from_secs(20)), u64::MAX).await, WaitEnd::Ended(Ended::Exit(3)));
        assert!(!r.group_alive());
    }

    #[tokio::test]
    async fn dropping_an_armed_running_kills_its_group_and_a_disarmed_one_does_not() {
        let f = fx();
        let r = f.start(&tree(&f, "wait"));
        let pids = read_pids(&f.pidfile(), 2).await;
        drop(r);
        assert_gone(&pids).await;

        let f = fx();
        let mut r = f.start(&tree(&f, "wait"));
        let pids = read_pids(&f.pidfile(), 2).await;
        r.disarm();
        let pid = r.pid;
        drop(r);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(pids.iter().all(|p| alive(*p)));
        let mut adopted = Running::adopt(pid, f.root.join("out"), f.root.join("exit"), 0);
        adopted.terminate(Duration::from_secs(2)).await;
        assert_gone(&pids).await;
    }

    #[tokio::test]
    async fn the_pid_record_names_the_leader_and_its_start_time() {
        let f = fx();
        let mut r = f.start("sleep 300");
        let record = read_pid_record(&pid_path(&r.out_path)).expect("record");
        let me = std::process::id();
        let owner = Some((me, process_start(me).expect("own start time")));
        assert_eq!(record, PidRecord { pid: r.pid, start: process_start(r.pid), members: Vec::new(), owner });
        assert!(record.start.is_some());
        // The record says it is this process's; one with another owner, or none, is not.
        assert!(record.is_ours());
        assert!(!PidRecord { owner: Some((me, "1.000000".to_string())), ..record.clone() }.is_ours());
        assert!(!PidRecord { owner: None, ..record }.is_ours());
        r.terminate(Duration::from_secs(2)).await;
    }

    #[tokio::test]
    async fn a_command_whose_pid_record_cannot_be_written_is_stopped() {
        let f = fx();
        let r = f.start(&tree(&f, "wait"));
        let pids = read_pids(&f.pidfile(), 2).await;
        let e = recorded(r, &f.root.join("missing/j1.pid")).expect_err("no record, no command");
        assert!(e.to_string().contains("pid record") && e.to_string().contains("could not be written"), "{e}");
        assert_gone(&pids).await;
    }

    #[tokio::test]
    async fn once_the_leader_has_exited_the_pid_record_names_who_is_in_the_group() {
        let f = fx();
        let p = f.pidfile();
        // A subshell outlives the leader for a second, starts a long sleep and exits.
        let mut r = f.start(&format!("(sleep 1; sleep 300 & echo $! >> {p}) & echo $! >> {p}", p = p.display()));
        assert_eq!(finish(&mut r).await, Ended::Exit(0));
        let path = pid_path(&r.out_path);
        assert!(read_pid_record(&path).expect("record").members.is_empty());
        assert_eq!(r.wait_group(&never(), Some(Duration::from_millis(50)), u64::MAX).await, WaitEnd::Deadline);
        let subshell = u32::try_from(read_pids(&p, 1).await[0]).expect("pid");
        let record = read_pid_record(&path).expect("record");
        assert_eq!((record.pid, &record.start), (r.pid, &r.start));
        assert!(record.members.contains(&(subshell, process_start(subshell).expect("start"))), "{record:?}");

        // When the recorded members are gone and the group is not, the record names who is in it now.
        let sleeper = read_pids(&p, 2).await[1];
        let want = vec![(u32::try_from(sleeper).expect("pid"), process_start(u32::try_from(sleeper).expect("pid")).expect("start"))];
        let mut record = record;
        for _ in 0..100 {
            if record.members == want {
                break;
            }
            assert_eq!(r.wait_group(&never(), Some(Duration::from_millis(100)), u64::MAX).await, WaitEnd::Deadline);
            record = read_pid_record(&path).expect("record");
        }
        assert_eq!(record.members, want);

        // A record that names neither a live leader nor a live member of the group is not acted on …
        let stranger = PidRecord { members: vec![(want[0].0, "1.000000".to_string())], ..record.clone() };
        assert_eq!(kill_recorded_group(&stranger), RecordedGroup::Unconfirmed);
        assert!(alive(sleeper));
        // … one whose member is still there is, although the leader is long gone.
        assert_eq!(kill_recorded_group(&record), RecordedGroup::Killed);
        assert_gone(&[sleeper]).await;
        assert_eq!(kill_recorded_group(&record), RecordedGroup::Gone);
        assert!(!r.group_alive());
    }

    #[tokio::test]
    async fn a_finished_command_is_over_for_good_and_no_longer_guarded() {
        let f = fx();
        let mut r = f.start("exit 0");
        assert_eq!(finish(&mut r).await, Ended::Exit(0));
        // Seen ended with an empty group: nothing is probed or signalled through this pid again.
        assert!(r.over && !r.armed);
        assert!(!r.group_alive());
        assert_eq!(r.terminate(Duration::from_millis(100)).await, Ended::Exit(0));

        // The same after we stopped it.
        let mut r = f.start("sleep 300");
        r.terminate(Duration::from_secs(2)).await;
        assert!(r.over && !r.armed);

        // A leader that left processes behind is not over, and dropping it still kills them.
        let p = f.pidfile();
        let mut r = f.start(&format!("sleep 300 & echo $! >> {}", p.display()));
        let pids = read_pids(&p, 1).await;
        assert_eq!(finish(&mut r).await, Ended::Exit(0));
        assert!(r.group_alive() && r.armed && !r.over);
        drop(r);
        assert_gone(&pids).await;
    }

    #[tokio::test]
    async fn terminate_within_ends_the_grace_period_when_the_output_passes_the_limit() {
        let f = fx();
        // Quiet until TERM has been sent and ignored, then it writes without end.
        let script = "trap '' TERM; sleep 1; while :; do echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; done";
        let mut r = f.start(script);
        tokio::time::sleep(Duration::from_millis(200)).await;
        let t = Instant::now();
        r.terminate_within(Duration::from_secs(60), 5_000).await;
        assert!(t.elapsed() < Duration::from_secs(20), "the grace period was waited out: {:?}", t.elapsed());
        assert!(r.output_len() > 5_000);
        assert!(!r.group_alive());
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
        let mut r = f.start("echo started; sleep 1; echo done; exit 5");
        let (pid, out, exit, ms) = (r.pid, r.out_path.clone(), r.exit_path.clone(), r.started_ms);
        r.disarm();
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
        let mut r = f.start(&tree(&f, "wait"));
        let pids = read_pids(&f.pidfile(), 2).await;
        let (pid, out, exit, ms) = (r.pid, r.out_path.clone(), r.exit_path.clone(), r.started_ms);
        r.disarm();
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
    async fn leftover_files_of_the_same_name_are_never_appended_to() {
        let f = fx();
        let mut r = f.start("echo one; exit 1");
        assert_eq!(finish(&mut r).await, Ended::Exit(1));
        let mut r = f.start("echo two");
        assert_eq!(finish(&mut r).await, Ended::Exit(0));
        assert_eq!(r.read_output(0).expect("read"), b"two\n");
        // Even a stale file that holds a plausible status does not leak into the new command.
        let f = fx();
        std::fs::write(f.root.join("out"), "stale output\n").expect("write");
        std::fs::write(f.root.join("exit"), "9\n").expect("write");
        let mut r = f.start("echo fresh");
        assert_eq!(finish(&mut r).await, Ended::Exit(0));
        assert_eq!(r.read_output(0).expect("read"), b"fresh\n");
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
