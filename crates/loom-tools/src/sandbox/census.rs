//! Which processes belong to which session, and what they listen on: found by the sandbox they run in.
//!
//! CONTRACT.
//!
//! A process group and an environment are things a command controls (`setsid`, a double fork, `env -i`): a
//! process that did any of them is no longer found by `proc`'s group, and a census by environment misses it.
//! What a command cannot change is the sandbox profile it was started under, which its children inherit. Every
//! seatbelt profile refuses to read the loom home and, of everything inside it, opens only the session's own temp
//! directory (`<home>/sessions/<id>/tmp`) and its analysis directory. macOS reports whether a given process is
//! refused a path (`sandbox_check(pid, "file-read-data", path)`, a private libsystem call that the operating
//! system's own tools use; the path must exist, a missing one always reads as refused), so:
//! - a process is under a loom profile (or another sandbox) when it is refused the loom home;
//! - it is a process of session `<id>` when it is, and is not refused `<home>/sessions/<id>/tmp`. Another session's
//!   profile refuses that directory (it lies in the home), and an unsandboxed process is refused neither.
//!
//! The marker is therefore a path that already exists and that the profile already allows to its own session only
//! (the design said "a read-allow on `/private/var/empty/loom-<sid>`": that path cannot exist, `/private/var/empty`
//! is protected, and a missing path is always refused). A child's commands in an agent's copy run under the parent's
//! profile and are the parent's. Processes under a profile of a session that is not listed are not reported: a
//! sandboxed application of the user's also refuses the home, so a process is only ever attributed to a session
//! it matches positively, and nothing is killed on a guess.
//!
//! ## `probe()`
//! Runs once per daemon (the result is kept) and says whether the question works on this host: a command started
//! under a real profile (a throwaway home, workspace and session temp dirs) is refused the home and not its own temp
//! dir, is refused another session's temp dir, and neither an unsandboxed child nor this process is refused the
//! home. `Probe { works, detail }`; `detail` names what was seen when it does not work. It takes up to about 3
//! seconds and runs `sandbox-exec` and `sleep`. Off macOS, and where `sandbox-exec` is missing, it does not work
//! (and says so).
//!
//! ## `take(home, sessions, groups)` and `Census`
//! `home` is the loom home; `sessions` are `Member { id, tmp }` (a session id and its temp dir) to attribute processes to; `groups` are `(session, process group)` pairs the
//! caller knows (a job's leader). `Census { taken_ms, readable, identity, processes }`:
//! - `readable` is false when the process table could not be read (the census then says nothing; it never claims
//!   that a session has no processes then);
//! - `identity` is true when processes were found by sandbox identity (`probe().works`), false when by the
//!   fallback: the environment variable `LOOM_SANDBOX_ID=<id>` that `Sandbox::env` sets, plus `groups`. The
//!   fallback is best effort: `env -i` and a double fork defeat the first, `setsid` the second (`docs/MONITOR.md`
//!   X7);
//! - `processes` are the live (not zombie) processes of this user other than this process that belong to a listed
//!   session, with `session` (the id), `pid`, `ppid`, `pgid`, `start`, `exe`, `via` (`identity`, `environment` or `group`) and `listeners`
//!   (`procinfo::Listener`: TCP sockets in the listening state and bound UDP sockets), sorted by pid.
//!
//! ## `kill(home, sessions, groups)`
//! Stops every process the census finds for `sessions`:
//! each round takes a census, sends SIGSTOP to every process (so nothing forks while it is being killed), then
//! SIGKILL, and takes the next; at most 5 rounds, stopping at the first that finds nothing. A process is signalled
//! only while it still has the start time the census recorded (a pid that was reused is not signalled).
//! `Killed { rounds, killed, left }`: `left` is what the last census still found, empty when it succeeded.
//! It never signals this process, or a pid of 1 or less, and uses only `kill(2)` and the kernel's tables: it
//! works when the process table is full.
//!
//! Tests required (macOS with `sandbox-exec`; others skip): `an_identity_is_validated_and_marks_the_environment`,
//! `the_identity_probe_works_on_this_host`, `a_setsid_orphan_with_a_cleared_environment_is_found_and_killed`,
//! `the_census_lists_what_a_session_listens_on`, `a_pid_that_was_reused_is_not_signalled`,
//! `without_identity_the_environment_and_the_groups_find_what_they_can`, `an_unreadable_table_is_not_an_empty_one`.

use crate::procinfo::{self, Listener};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// The environment variable `Sandbox::env` sets in a sandbox that has an identity (the census's fallback).
pub const ENV_MARK: &str = "LOOM_SANDBOX_ID";

/// At most this many rounds of stop-and-kill.
const MAX_ROUNDS: u32 = 5;

/// Whether `id` can be a sandbox identity: 1 to 64 letters, digits, `-` and `_`.
pub fn valid_id(id: &str) -> Result<(), String> {
    let ok = !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if ok {
        Ok(())
    } else {
        Err(format!(
            "The sandbox identity {id:?} is not usable: it must be 1 to 64 letters, digits, '-' and '_'. Use the session id."
        ))
    }
}

/// A session to attribute processes to: its id and its temp directory (`<home>/sessions/<id>/tmp`), which only
/// that session's profile opens.
#[derive(Clone, Copy, Debug)]
pub struct Member<'a> {
    pub id: &'a str,
    pub tmp: &'a Path,
}

/// Whether `pid` is refused reading `path` by its sandbox: `Some(true)` refused, `Some(false)` not (an
/// unsandboxed process is never refused), `None` when the question could not be asked.
#[cfg(target_os = "macos")]
fn refused(pid: u32, path: &Path) -> Option<bool> {
    extern "C" {
        fn sandbox_check(pid: libc::pid_t, operation: *const libc::c_char, filter: libc::c_int, ...) -> libc::c_int;
    }
    // SANDBOX_FILTER_PATH, and SANDBOX_CHECK_NO_REPORT so that a refusal is not logged.
    const FILTER_PATH: libc::c_int = 1;
    const NO_REPORT: libc::c_int = 0x4000_0000;
    let pid = libc::pid_t::try_from(pid).ok().filter(|p| *p > 0)?;
    let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).ok()?;
    // SAFETY: both strings are NUL-terminated and outlive the call; the filter takes one path argument.
    let rc = unsafe { sandbox_check(pid, c"file-read-data".as_ptr(), FILTER_PATH | NO_REPORT, path.as_ptr()) };
    match rc {
        0 => Some(false),
        1.. => Some(true),
        _ => None,
    }
}

#[cfg(not(target_os = "macos"))]
fn refused(_pid: u32, _path: &Path) -> Option<bool> {
    None
}

/// Whether `pid` is under a sandbox that refuses the loom home.
fn in_a_sandbox(pid: u32, home: &Path) -> bool {
    refused(pid, home) == Some(true)
}

/// Whether `pid` is under the profile of the session whose temp dir is `tmp`: it may read it.
fn in_session(pid: u32, tmp: &Path) -> bool {
    refused(pid, tmp) == Some(false)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Probe {
    pub works: bool,
    /// What was seen, in a sentence.
    pub detail: String,
}

/// Whether sandbox identity can be asked on this host; see the contract. Run once, then remembered.
pub fn probe() -> &'static Probe {
    static PROBE: OnceLock<Probe> = OnceLock::new();
    PROBE.get_or_init(run_probe)
}

#[cfg(target_os = "macos")]
fn run_probe() -> Probe {
    use crate::sandbox::Sandbox;
    use loom_core::config::{SandboxCfg, SandboxMode};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    struct Reap(std::process::Child);
    impl Drop for Reap {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    struct Dir(std::path::PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let fail = |detail: String| Probe { works: false, detail };
    if !Path::new(super::SANDBOX_EXEC).exists() {
        return fail(format!("{} is missing, so no command runs under a profile", super::SANDBOX_EXEC));
    }
    let root =
        std::env::temp_dir().join(format!("loom-census-probe-{}-{:08x}", std::process::id(), rand::random::<u32>()));
    let guard = Dir(root.clone());
    let (home, ws) = (root.join("home"), root.join("ws"));
    let (tmp, other) =
        (home.join("sessions").join("probe").join("tmp"), home.join("sessions").join("other").join("tmp"));
    for dir in [&ws, &tmp, &other] {
        if let Err(e) = std::fs::create_dir_all(dir) {
            return fail(format!("the probe directory {} could not be made: {e}", dir.display()));
        }
    }
    let (Ok(home), Ok(ws), Ok(tmp), Ok(other)) =
        (home.canonicalize(), ws.canonicalize(), tmp.canonicalize(), other.canonicalize())
    else {
        return fail("the probe directories could not be resolved".to_string());
    };
    let cfg = SandboxCfg { mode: SandboxMode::Seatbelt, protect_credentials: false, ..SandboxCfg::default() };
    let sandbox = match Sandbox::new(&cfg, &ws, &tmp, &home, None) {
        Ok(sandbox) => sandbox,
        Err(e) => return fail(format!("the probe sandbox could not be built: {e}")),
    };
    let (program, args) = sandbox.command("exec /bin/sleep 30");
    let spawn = |mut cmd: Command| {
        cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).process_group(0).spawn().map(Reap)
    };
    let mut inside = Command::new(program);
    inside.args(args);
    let mut outside = Command::new("/bin/sleep");
    outside.arg("30");
    let (inside, outside) = match (spawn(inside), spawn(outside)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) | (_, Err(e)) => return fail(format!("a probe command could not be started: {e}")),
    };
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut seen: String;
    loop {
        let (class, own, foreign) =
            (refused(inside.0.id(), &home), refused(inside.0.id(), &tmp), refused(inside.0.id(), &other));
        let (plain, me) = (refused(outside.0.id(), &home), refused(std::process::id(), &home));
        seen = format!(
            "under a profile: the home {class:?}, its own temp dir {own:?}, another session's {foreign:?}; \
             an unsandboxed child: {plain:?}, this process: {me:?}"
        );
        if class == Some(true)
            && own == Some(false)
            && foreign == Some(true)
            && plain == Some(false)
            && me == Some(false)
        {
            drop(guard);
            return Probe { works: true, detail: "sandbox_check tells the sessions' sandboxes apart".to_string() };
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    fail(format!("sandbox_check did not tell a sandboxed process from others ({seen})"))
}

#[cfg(not(target_os = "macos"))]
fn run_probe() -> Probe {
    Probe { works: false, detail: "sandbox identity is a macOS Seatbelt feature".to_string() }
}

/// How a process was attributed to its session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Via {
    Identity,
    Environment,
    Group,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Process {
    pub session: String,
    pub pid: u32,
    pub ppid: u32,
    pub pgid: u32,
    pub start: String,
    pub exe: String,
    pub via: Via,
    pub listeners: Vec<Listener>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Census {
    pub taken_ms: u64,
    /// The process table could be read.
    pub readable: bool,
    /// Processes were found by sandbox identity (otherwise by environment and group: best effort).
    pub identity: bool,
    pub processes: Vec<Process>,
}

impl Census {
    /// The processes of `session`.
    pub fn of<'a>(&'a self, session: &'a str) -> impl Iterator<Item = &'a Process> {
        self.processes.iter().filter(move |p| p.session == session)
    }

    /// Whether `session` has no live process (false when the table could not be read).
    pub fn is_empty_for(&self, session: &str) -> bool {
        self.readable && self.of(session).next().is_none()
    }
}

/// The census; see the contract.
pub fn take(home: &Path, sessions: &[Member<'_>], groups: &[(String, u32)]) -> Census {
    take_by(home, sessions, groups, probe().works)
}

/// `take` with the method chosen (a test forces the fallback).
fn take_by(home: &Path, sessions: &[Member<'_>], groups: &[(String, u32)], identity: bool) -> Census {
    let taken_ms = loom_core::now_ms();
    let Some(pids) = procinfo::pids() else {
        return Census { taken_ms, readable: false, identity, processes: Vec::new() };
    };
    let me = std::process::id();
    // SAFETY: geteuid takes no arguments.
    let uid = unsafe { libc::geteuid() };
    let mut found: BTreeMap<u32, Process> = BTreeMap::new();
    let mut add = |info: procinfo::ProcInfo, session: &str, via: Via| {
        let listeners = procinfo::listeners(info.pid);
        let exe = procinfo::exe_path(info.pid).unwrap_or_default();
        found.entry(info.pid).or_insert(Process {
            session: session.to_string(),
            pid: info.pid,
            ppid: info.ppid,
            pgid: info.pgid,
            start: info.start,
            exe,
            via,
            listeners,
        });
    };
    for pid in pids {
        if pid <= 1 || pid == me {
            continue;
        }
        let Some(info) = procinfo::info(pid).filter(|i| !i.zombie && i.uid == uid) else { continue };
        if identity {
            if in_a_sandbox(pid, home) {
                if let Some(member) = sessions.iter().find(|m| in_session(pid, m.tmp)) {
                    add(info, member.id, Via::Identity);
                }
            }
        } else if let Some(mark) = procinfo::command_line(pid).and_then(|line| {
            let prefix = format!("{ENV_MARK}=");
            line.env.iter().find_map(|e| e.strip_prefix(&prefix).map(str::to_string))
        }) {
            if let Some(member) = sessions.iter().find(|m| m.id == mark) {
                add(info, member.id, Via::Environment);
            }
        }
    }
    for (session, pgid) in groups {
        for member in procinfo::group(*pgid).unwrap_or_default() {
            if !member.zombie && member.pid != me && member.pid > 1 {
                add(member, session, Via::Group);
            }
        }
    }
    Census { taken_ms, readable: true, identity, processes: found.into_values().collect() }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Killed {
    pub rounds: u32,
    pub killed: usize,
    pub left: Vec<Process>,
}

/// Signals `process` while it still is the process the census saw.
fn signal(process: &Process, sig: i32) -> bool {
    let Ok(pid) = i32::try_from(process.pid) else { return false };
    if process.pid <= 1 || process.pid == std::process::id() {
        return false;
    }
    let same = procinfo::info(process.pid).is_some_and(|i| i.start == process.start && !i.zombie);
    // SAFETY: kill(2) takes plain integers and has no memory effects.
    same && unsafe { libc::kill(pid, sig) } == 0
}

/// Stops what the census finds for `sessions`; see the contract.
pub fn kill(home: &Path, sessions: &[Member<'_>], groups: &[(String, u32)]) -> Killed {
    kill_by(home, sessions, groups, probe().works)
}

fn kill_by(home: &Path, sessions: &[Member<'_>], groups: &[(String, u32)], identity: bool) -> Killed {
    let (mut rounds, mut killed) = (0, 0);
    loop {
        let targets = take_by(home, sessions, groups, identity).processes;
        if targets.is_empty() || rounds >= MAX_ROUNDS {
            return Killed { rounds, killed, left: targets };
        }
        rounds += 1;
        // Stopped first, so that nothing forks while the rest is being killed.
        for p in &targets {
            signal(p, libc::SIGSTOP);
        }
        for p in &targets {
            if signal(p, libc::SIGKILL) {
                killed += 1;
            }
        }
        std::thread::sleep(Duration::from_millis(30));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::Sandbox;
    use loom_core::config::{SandboxCfg, SandboxMode};
    use std::path::PathBuf;
    use std::process::Stdio;

    fn available() -> bool {
        cfg!(target_os = "macos") && Path::new(super::super::SANDBOX_EXEC).exists()
    }

    /// The production layout: one loom home, sessions under it, each with a temp dir.
    struct Rig {
        _dir: tempfile::TempDir,
        ws: PathBuf,
        home: PathBuf,
        spawned: Vec<std::process::Child>,
    }

    impl Rig {
        fn new() -> Rig {
            let dir = tempfile::tempdir().expect("tempdir");
            let root = dir.path().canonicalize().expect("canonical");
            let (ws, home) = (root.join("ws"), root.join("home"));
            std::fs::create_dir_all(&ws).expect("mkdir");
            std::fs::create_dir_all(&home).expect("mkdir");
            Rig { _dir: dir, ws, home, spawned: Vec::new() }
        }

        fn tmp(&self, id: &str) -> PathBuf {
            let tmp = self.home.join("sessions").join(id).join("tmp");
            std::fs::create_dir_all(&tmp).expect("mkdir");
            tmp
        }

        fn sandbox(&self, id: &str) -> Sandbox {
            let cfg = SandboxCfg { mode: SandboxMode::Seatbelt, protect_credentials: false, ..SandboxCfg::default() };
            Sandbox::new(&cfg, &self.ws, &self.tmp(id), &self.home, None)
                .expect("sandbox")
                .with_identity(id)
                .expect("identity")
        }

        /// Runs `script` under `sb` with the environment `sb` gives (or none), in its own process group.
        fn run(&mut self, sb: &Sandbox, script: &str, clear_env: bool) {
            use std::os::unix::process::CommandExt;
            let (program, args) = sb.command(script);
            let mut cmd = std::process::Command::new(program);
            cmd.args(args).current_dir(&self.ws).env_clear();
            if !clear_env {
                cmd.envs(sb.env(&BTreeMap::new()));
            }
            let child = cmd
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .process_group(0)
                .spawn()
                .expect("spawn");
            self.spawned.push(child);
        }
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            for child in &mut self.spawned {
                if let Ok(pid) = i32::try_from(child.id()) {
                    // SAFETY: kill(2) takes plain integers.
                    unsafe { libc::kill(-pid, libc::SIGKILL) };
                }
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    /// Takes censuses until `ready` is satisfied (a command needs a moment to get going).
    fn until(
        home: &Path,
        sessions: &[Member<'_>],
        groups: &[(String, u32)],
        identity: bool,
        ready: impl Fn(&Census) -> bool,
    ) -> Census {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let census = take_by(home, sessions, groups, identity);
            if ready(&census) || Instant::now() >= deadline {
                return census;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn alive(pid: u32) -> bool {
        procinfo::info(pid).is_some_and(|i| !i.zombie)
    }

    #[test]
    fn an_identity_is_validated_and_marks_the_environment() {
        for good in ["s-0abc_9", "a", &"x".repeat(64)] {
            assert_eq!(valid_id(good), Ok(()));
        }
        for bad in ["", "a b", "a/b", "a\"b", "a.b", &"x".repeat(65), "é"] {
            let e = valid_id(bad).unwrap_err();
            assert!(e.contains("not usable") && e.contains("Use the session id"), "{e}");
        }
        if !available() {
            return;
        }
        let rig = Rig::new();
        let sb = rig.sandbox("s-1");
        assert_eq!(sb.identity(), Some("s-1"));
        assert_eq!(sb.env(&BTreeMap::new()).get(ENV_MARK).map(String::as_str), Some("s-1"));
        let cfg = SandboxCfg { mode: SandboxMode::Seatbelt, protect_credentials: false, ..SandboxCfg::default() };
        let plain = Sandbox::new(&cfg, &rig.ws, &rig.tmp("s-2"), &rig.home, None).expect("sandbox");
        assert_eq!(plain.identity(), None);
        assert!(!plain.env(&BTreeMap::new()).contains_key(ENV_MARK));
        assert!(plain.with_identity("a b").is_err());
    }

    #[test]
    fn the_identity_probe_works_on_this_host() {
        if !available() {
            assert!(!probe().works);
            return;
        }
        let p = probe();
        assert!(p.works, "{}", p.detail);
        // Remembered: the second answer is the first.
        assert!(std::ptr::eq(p, probe()));
    }

    #[test]
    fn a_setsid_orphan_with_a_cleared_environment_is_found_and_killed() {
        if !available() {
            return;
        }
        assert!(probe().works, "{}", probe().detail);
        let mut rig = Rig::new();
        let (one, two) = (rig.sandbox("s-census-1"), rig.sandbox("s-census-2"));
        let (tmp1, tmp2) = (rig.tmp("s-census-1"), rig.tmp("s-census-2"));
        let members = [Member { id: "s-census-1", tmp: &tmp1 }, Member { id: "s-census-2", tmp: &tmp2 }];
        // The orphan leaves its process group (setsid), is orphaned (fork + exit) and has no environment.
        rig.run(
            &one,
            "/usr/bin/env -i /usr/bin/perl -MPOSIX -e 'POSIX::setsid(); fork && exit 0; exec \"/bin/sleep\", \"61\"'; \
             /bin/sleep 62",
            false,
        );
        rig.run(&two, "/bin/sleep 63", false);
        rig.spawned.push(
            std::process::Command::new("/bin/sleep")
                .arg("64")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("plain sleep"),
        );
        let home = rig.home.clone();
        let leader_group = rig.spawned[0].id();
        let census = until(&home, &members, &[], true, |c| {
            c.of("s-census-1").any(|p| p.exe.ends_with("sleep") && p.ppid == 1)
                && c.of("s-census-1").count() >= 2
                && c.of("s-census-2").any(|p| p.exe.ends_with("sleep"))
        });
        assert!(census.readable && census.identity);
        let ours: Vec<&Process> = census.of("s-census-1").collect();
        let orphan = ours
            .iter()
            .find(|p| p.exe.ends_with("sleep") && p.ppid == 1)
            .unwrap_or_else(|| panic!("the setsid orphan was not found: {ours:?}"));
        assert_eq!(orphan.via, Via::Identity);
        assert_ne!(orphan.pgid, leader_group, "setsid took it out of the command's process group");
        assert!(census.processes.iter().all(|p| p.session == "s-census-1" || p.session == "s-census-2"));
        let orphan_pid = orphan.pid;
        let other = census.of("s-census-2").next().map(|p| p.pid).expect("the other session");
        assert!(ours.iter().all(|p| p.pid != other));
        assert!(
            !census.processes.iter().any(|p| p.exe.ends_with("sleep") && p.session.is_empty()),
            "the unsandboxed sleep was attributed"
        );

        let killed = kill(&home, &members[..1], &[]);
        assert!(killed.killed >= 2 && killed.left.is_empty(), "{killed:?}");
        let mut gone = false;
        for _ in 0..100 {
            if !alive(orphan_pid) {
                gone = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(30));
        }
        assert!(gone, "the orphan survived");
        assert!(alive(other), "another session's process was killed");
        assert!(take(&home, &members, &[]).is_empty_for("s-census-1"));
        assert!(!take(&home, &members, &[]).is_empty_for("s-census-2"));
        // A session that is not listed is not reported, and so is not killed.
        assert!(take(&home, &members[..1], &[]).of("s-census-2").next().is_none());
        assert_eq!(kill(&home, &members[..1], &[]).killed, 0);
        assert!(alive(other));
        assert!(kill(&home, &members[1..], &[]).left.is_empty());
    }

    #[test]
    fn the_census_lists_what_a_session_listens_on() {
        if !available() {
            return;
        }
        assert!(probe().works, "{}", probe().detail);
        let mut rig = Rig::new();
        let sb = rig.sandbox("s-census-3");
        let tmp = rig.tmp("s-census-3");
        let port_file = tmp.join("port");
        let script = format!(
            "/usr/bin/perl -MIO::Socket::INET -e '$s=IO::Socket::INET->new(Listen=>1,LocalAddr=>\"127.0.0.1\",\
             LocalPort=>0,Proto=>\"tcp\") or die; open F,\">{}\"; print F $s->sockport; close F; sleep 60'",
            port_file.display()
        );
        rig.run(&sb, &script, false);
        let mut port = 0u16;
        for _ in 0..100 {
            if let Some(p) = std::fs::read_to_string(&port_file).ok().and_then(|t| t.trim().parse().ok()) {
                port = p;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(port > 0, "the listener did not start");
        let members = [Member { id: "s-census-3", tmp: &tmp }];
        let census = take(&rig.home, &members, &[]);
        let listening: Vec<&Listener> = census.of("s-census-3").flat_map(|p| &p.listeners).collect();
        assert!(
            listening.iter().any(|l| l.port == port && l.proto == procinfo::Proto::Tcp && l.addr == "127.0.0.1"),
            "{census:?}"
        );
        assert!(kill(&rig.home, &members, &[]).left.is_empty());
    }

    #[test]
    fn a_pid_that_was_reused_is_not_signalled() {
        let mut child = std::process::Command::new("/bin/sleep").arg("61").spawn().expect("spawn");
        let info = procinfo::info(child.id()).expect("info");
        let row = Process {
            session: "s".into(),
            pid: info.pid,
            ppid: info.ppid,
            pgid: info.pgid,
            start: "1.000000".into(),
            exe: String::new(),
            via: Via::Identity,
            listeners: Vec::new(),
        };
        assert!(!signal(&row, libc::SIGKILL));
        assert!(child.try_wait().expect("wait").is_none(), "a process with another start time was killed");
        assert!(signal(&Process { start: info.start, ..row.clone() }, libc::SIGKILL));
        child.wait().expect("reap");
        // This process and the init process are never signalled.
        assert!(!signal(&Process { pid: std::process::id(), ..row.clone() }, 0));
        assert!(!signal(&Process { pid: 1, ..row }, 0));
    }

    #[test]
    fn without_identity_the_environment_and_the_groups_find_what_they_can() {
        if !available() {
            return;
        }
        use std::os::unix::process::CommandExt;
        let mut rig = Rig::new();
        let sb = rig.sandbox("s-census-4");
        let tmp = rig.tmp("s-census-4");
        let members = [Member { id: "s-census-4", tmp: &tmp }];
        // Found by the variable: a command that kept its environment.
        rig.run(&sb, "/bin/sleep 61; /bin/sleep 62", false);
        // Not found by it: a command that cleared its environment (the stated limit of the fallback).
        rig.run(&sb, "/bin/sleep 63; /bin/sleep 64", true);
        // Found by its group, whatever its environment.
        let mut grouped = std::process::Command::new("/usr/bin/env")
            .args(["-i", "/bin/sleep", "65"])
            .process_group(0)
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn");
        let group = grouped.id();
        let groups = [("s-census-4".to_string(), group)];
        let home = rig.home.clone();
        let census = until(&home, &members, &groups, false, |c| {
            c.of("s-census-4").any(|p| p.via == Via::Environment) && c.of("s-census-4").any(|p| p.via == Via::Group)
        });
        assert!(!census.identity && census.readable);
        let by_env: Vec<&Process> = census.of("s-census-4").filter(|p| p.via == Via::Environment).collect();
        assert!(!by_env.is_empty(), "{census:?}");
        let by_group: Vec<&Process> = census.of("s-census-4").filter(|p| p.via == Via::Group).collect();
        assert!(by_group.iter().any(|p| p.pgid == group), "{census:?}");
        // The cleared environment's sleeps are in no listed group and carry no variable.
        assert!(
            !census
                .of("s-census-4")
                .any(|p| p.exe.ends_with("sleep") && p.pgid != group && p.ppid != 0 && { p.via == Via::Group }),
            "{census:?}"
        );
        let killed = kill_by(&home, &members, &groups, false);
        assert!(killed.left.is_empty(), "{killed:?}");
        let _ = grouped.wait();
    }

    #[test]
    fn an_unreadable_table_is_not_an_empty_one() {
        let home = std::env::temp_dir();
        procinfo::UNREADABLE.with(|u| u.set(true));
        let census = take_by(&home, &[], &[], true);
        procinfo::UNREADABLE.with(|u| u.set(false));
        assert!(!census.readable && census.processes.is_empty());
        assert!(!census.is_empty_for("s-x"), "an unreadable census must not read as 'no processes'");
        assert!(take_by(&home, &[], &[], false).readable);
    }
}
