//! Which processes belong to which session, and what they listen on: found by the sandbox they run in.
//!
//! CONTRACT.
//!
//! A process group and an environment are things a command controls (`setsid`, a double fork, `env -i`): a
//! process that did any of them is no longer found by `proc`'s group, and a census by environment misses it.
//! What a command cannot change is the sandbox profile it was started under, which its children inherit. Every
//! seatbelt profile refuses to read the ferret home and, of everything inside it, opens only the session's own temp
//! directory (`<home>/sessions/<id>/tmp`) and its analysis directory. macOS reports whether a given process is
//! refused a path (`sandbox_check(pid, "file-read-data", path)`, a private libsystem call that the operating
//! system's own tools use; the path must exist, a missing one always reads as refused), so:
//! - a process is under a ferret profile (or another sandbox) when it is refused the ferret home;
//! - it is a process of session `<id>` when it is, and is not refused `<home>/sessions/<id>/tmp`. Another session's
//!   profile refuses that directory (it lies in the home), and an unsandboxed process is refused neither.
//!
//! The marker is therefore a path that already exists and that the profile already allows to its own session only
//! (the design said "a read-allow on `/private/var/empty/ferret-<sid>`": that path cannot exist, `/private/var/empty`
//! is protected, and a missing path is always refused). A child's commands in an agent's copy run under the parent's
//! profile and are the parent's. Processes under a profile of a session that is not listed are not reported: a
//! sandboxed application of the user's also refuses the home, so a process is only ever attributed to a session
//! it matches positively, and nothing is killed on a guess.
//!
//! ## `probe()`
//! Says whether the question works on this host: a command started under a real profile (a throwaway home,
//! workspace and session temp dirs) is refused the home and not its own temp dir, is refused another session's temp
//! dir, and neither an unsandboxed child nor this process is refused the home. `Probe { works, undetermined, detail }`;
//! `detail` names what was seen when it does not work. It takes up to about 3 seconds and runs `sandbox-exec` and
//! `sleep`. Only a settled answer is kept for the daemon's life: `works`, or a host where the question was asked and
//! did not tell the sandboxes apart (or where `sandbox-exec` is missing, or off macOS). A probe that could not run
//! (`undetermined`: a process could not be started, a directory could not be made, or the processes were not yet
//! visible to the query within the time) is not kept and is run again by the next `take` and `kill`: a full process
//! table or busy CPUs at the daemon's start must not turn identity off for its whole life.
//!
//! ## `take(home, sessions, groups, confined)` and `Census`
//! `home` is the ferret home; `sessions` are `Member { id, tmp }` (a session id and its temp dir) to attribute processes
//! to; `groups` are `(session, process group)` pairs the caller knows (a job's leader); `confined` is whether the
//! daemon runs commands under Seatbelt (`sandbox.mode`): with `none` nothing is refused the home, so no process is
//! attributable by identity. `Census { taken_ms, readable, identity, processes }`:
//! - `readable` is false when the process table could not be read (the census then says nothing; it never claims
//!   that a session has no processes then);
//! - `identity` is true when processes were found by sandbox identity (`confined` and `probe().works`), false when by
//!   the fallback: the environment variable `FERRET_SANDBOX_ID=<id>` that `Sandbox::env` sets, plus `groups`. The
//!   fallback is best effort: `env -i` and a double fork defeat the first, `setsid` the second (`docs/MONITOR.md`
//!   X7). A fallback census never reads as empty: `is_empty_for` is true only when `identity` holds;
//! - in identity mode a process under a sandbox that no listed session's temp dir matches (a replay of the oracle
//!   runs under `Sandbox::isolated_replay`, which refuses every session's temp dir) is attributed by its
//!   `FERRET_SANDBOX_ID` when that names a listed session (`via: environment`; only sandboxed processes, so nothing
//!   unconfined is guessed at). The replay itself is cleaned up by `kill_under`;
//! - `processes` are the live (not zombie) processes of this user other than this process that belong to a listed
//!   session, with `session` (the id), `pid`, `ppid`, `pgid`, `start`, `exe`, `via` (`identity`, `environment` or
//!   `group`) and `listeners` (`procinfo::Listener`: TCP sockets in the listening state and bound UDP sockets),
//!   sorted by pid.
//!
//! ## `kill(home, sessions, groups, known_groups, confined)` and `kill_under(home, tmp)`
//! Stops every process the census finds for `sessions`. A process that keeps forking and exiting from a new pid
//! (`setsid`, then a loop of `fork; exit if parent`) is gone by the time a pid list taken earlier reaches it, so the
//! scan itself does the stopping: as soon as the scan attributes a process it sends SIGSTOP, and when every live
//! member of that process's group is also attributed to the same session (checked by identity, so a group that
//! someone else's process joined is never signalled) it stops the whole group at once with `killpg`, which also
//! catches the generation that does not exist yet. Then SIGKILL goes to those groups and to each process found, and
//! the next scan runs; it repeats until two scans in a row find nothing, at most 20 rounds and 15 s. The groups that
//! were stopped whole, and `known_groups` (`(session, process group)` pairs an earlier census showed), are signalled
//! again before every scan while they have a live member, whether or not the scan finds one: a process that lives
//! microseconds is found by a scan only by luck, and once any census has seen one generation its group is known. A
//! `known_groups` entry is signalled only after the same check (every live member is the session's by its profile),
//! so a stale pgid that another process now has is never signalled. A process is signalled
//! only while it still has the start time the census recorded (a pid that was reused is not signalled); a group is
//! never signalled when it is this process's own, or has pgid 1 or less.
//! `Killed { rounds, killed, readable, left }`: `left` is what the last census still found, empty when it succeeded;
//! `readable` is false when the process table could not be read (then `left` is empty and nothing was stopped: it is
//! not a success). It uses only `kill(2)` and the kernel's tables: it works when the process table is full.
//! `kill_under(home, tmp)` is the same for what runs under a profile that may read `tmp` and not the home (the oracle's
//! replay, once it has returned).
//!
//! ## `listener_of(home, sessions, to, client, confined, own)` (E4e)
//! Who holds the other end of the proxy's connection to `to`, an address of this machine (loopback, unspecified or one
//! of its interface addresses), for the proxy's check that a lab port is not squatted by a sandboxed process.
//! `client` is the local end of the connection the proxy opened (its ephemeral port names the connection). The
//! holders are, in this order: the processes that hold the **accepted** socket of that connection (a TCP socket
//! whose local port is `to.port` and whose remote port is `client.port`), which are the processes the bytes reach
//! whatever else listens, and so a squatter that closes its listening socket as it accepts is still named; when no
//! process holds one (the connection waits in a backlog, or `client` is `None`), every process with a **listening**
//! socket on `to.port` bound to `to.ip` or to the wildcard (a listener on another address of the machine does not
//! answer the connection). `own` lists the sessions of the connector's own mission: a holder attributed to one of
//! them is skipped, so a lead's callback server is not a squatter for its children, but a foreign holder is still
//! reported when an own one is listed first, or later, in the table. Results: `Nobody` (no process holds the
//! connection or listens there), `Outside` (holders found, none attributed to a ferret sandbox of another mission: the
//! operator's own service, which a lab target usually is, or the connector's own mission's), `Sandboxed { pid,
//! session, via }` (the first holder attributed to a ferret sandbox that is not `own`: by identity when `confined` and
//! `probe().works`, `session` being the listed session whose temp dir its profile opens, or, for a sandbox no listed
//! session matches, the session its `FERRET_SANDBOX_ID` names; without identity, by the variable alone; `session` is
//! `None` only when an identity-attributed process names no session) and `Unknown` (the process table could not be
//! read, so nothing is claimed). Attribution is the census's: a process under a profile that no session claims, and
//! carries no mark, is not attributed (a sandboxed application of the operator's refuses the home too). Sandboxes
//! run as this user, so every process that could hold such a socket is readable here: `Nobody` after a connection
//! that succeeded means that the holder belongs to another user (a service of the machine), not to a sandbox. It
//! reads every process's descriptors, so it costs a scan of the table: call it on a blocking thread, and only for
//! connections to this machine (the proxy bounds the scans that run at once).
//!
//! Tests required (macOS with `sandbox-exec`; others skip): `an_identity_is_validated_and_marks_the_environment`,
//! `the_identity_probe_works_on_this_host`, `a_probe_that_could_not_run_is_asked_again`,
//! `a_setsid_orphan_with_a_cleared_environment_is_found_and_killed`,
//! `a_process_that_forks_and_exits_in_a_loop_is_killed_by_its_group`,
//! `a_group_is_signalled_only_when_all_of_it_is_the_sessions`, `a_replay_orphan_is_found_and_killed`,
//! `the_census_lists_what_a_session_listens_on`, `a_pid_that_was_reused_is_not_signalled`,
//! `without_identity_the_environment_and_the_groups_find_what_they_can`,
//! `an_unconfined_daemon_does_not_claim_an_empty_census`, `an_unreadable_table_is_not_an_empty_one`,
//! `a_listener_is_told_apart_by_the_profile_it_runs_under`, `a_one_shot_listener_is_found_by_the_connection_it_accepted`,
//! `another_sessions_listener_is_found_behind_the_connectors_own_wildcard_listener`,
//! `a_socket_covers_its_address_and_the_wildcard_and_no_other` and `an_unreadable_table_says_unknown_for_a_listener`.

use crate::procinfo::{self, Listener};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The environment variable `Sandbox::env` sets in a sandbox that has an identity (the census's fallback).
pub const ENV_MARK: &str = "FERRET_SANDBOX_ID";

/// At most this many rounds of stop-and-kill, and this long.
const MAX_ROUNDS: u32 = 20;
const MAX_KILL_TIME: Duration = Duration::from_secs(15);

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

/// Whether `pid` is under a sandbox that refuses the ferret home.
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
    /// The probe could not run (a process or directory could not be made, or the query could not be asked in time):
    /// the answer is not kept, and the next call asks again.
    pub undetermined: bool,
    /// What was seen, in a sentence.
    pub detail: String,
}

/// Whether sandbox identity can be asked on this host; see the contract. A settled answer is kept.
pub fn probe() -> Probe {
    static PROBE: Mutex<Option<Probe>> = Mutex::new(None);
    probe_cached(&PROBE, run_probe)
}

/// The kept answer in `cell`, or `run`'s, kept only when it is settled.
fn probe_cached(cell: &Mutex<Option<Probe>>, run: impl FnOnce() -> Probe) -> Probe {
    if let Some(kept) = cell.lock().unwrap_or_else(|p| p.into_inner()).clone() {
        return kept;
    }
    let answer = run();
    if !answer.undetermined {
        *cell.lock().unwrap_or_else(|p| p.into_inner()) = Some(answer.clone());
    }
    answer
}

#[cfg(target_os = "macos")]
fn run_probe() -> Probe {
    use crate::sandbox::Sandbox;
    use ferret_core::config::{SandboxCfg, SandboxMode};
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
    let fail = |detail: String| Probe { works: false, undetermined: false, detail };
    // The probe could not run: nothing was learned about the host.
    let unrun = |detail: String| Probe { works: false, undetermined: true, detail };
    if !Path::new(super::SANDBOX_EXEC).exists() {
        return fail(format!("{} is missing, so no command runs under a profile", super::SANDBOX_EXEC));
    }
    let root =
        std::env::temp_dir().join(format!("ferret-census-probe-{}-{:08x}", std::process::id(), rand::random::<u32>()));
    let guard = Dir(root.clone());
    let (home, ws) = (root.join("home"), root.join("ws"));
    let (tmp, other) =
        (home.join("sessions").join("probe").join("tmp"), home.join("sessions").join("other").join("tmp"));
    for dir in [&ws, &tmp, &other] {
        if let Err(e) = std::fs::create_dir_all(dir) {
            return unrun(format!("the probe directory {} could not be made: {e}", dir.display()));
        }
    }
    let (Ok(home), Ok(ws), Ok(tmp), Ok(other)) =
        (home.canonicalize(), ws.canonicalize(), tmp.canonicalize(), other.canonicalize())
    else {
        return unrun("the probe directories could not be resolved".to_string());
    };
    let cfg = SandboxCfg { mode: SandboxMode::Seatbelt, protect_credentials: false, ..SandboxCfg::default() };
    let sandbox = match Sandbox::new(&cfg, &ws, &tmp, &home, None) {
        Ok(sandbox) => sandbox,
        Err(e) => return unrun(format!("the probe sandbox could not be built: {e}")),
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
        (Err(e), _) | (_, Err(e)) => return unrun(format!("a probe command could not be started: {e}")),
    };
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut seen: String;
    let mut asked;
    loop {
        let (class, own, foreign) =
            (refused(inside.0.id(), &home), refused(inside.0.id(), &tmp), refused(inside.0.id(), &other));
        let (plain, me) = (refused(outside.0.id(), &home), refused(std::process::id(), &home));
        seen = format!(
            "under a profile: the home {class:?}, its own temp dir {own:?}, another session's {foreign:?}; \
             an unsandboxed child: {plain:?}, this process: {me:?}"
        );
        asked = [class, own, foreign, plain, me].iter().all(Option::is_some);
        if class == Some(true)
            && own == Some(false)
            && foreign == Some(true)
            && plain == Some(false)
            && me == Some(false)
        {
            drop(guard);
            return Probe {
                works: true,
                undetermined: false,
                detail: "sandbox_check tells the sessions' sandboxes apart".to_string(),
            };
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let detail = format!("sandbox_check did not tell a sandboxed process from others ({seen})");
    // A question that could not be asked (a process not yet visible, a table that would not answer) is not an answer.
    if asked {
        fail(detail)
    } else {
        unrun(detail)
    }
}

#[cfg(not(target_os = "macos"))]
fn run_probe() -> Probe {
    Probe { works: false, undetermined: false, detail: "sandbox identity is a macOS Seatbelt feature".to_string() }
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

    /// Whether `session` has no live process: false when the table could not be read, and false for a census that
    /// was not taken by sandbox identity (the fallback finds only what it can, so it cannot say "none").
    pub fn is_empty_for(&self, session: &str) -> bool {
        self.readable && self.identity && self.of(session).next().is_none()
    }
}

/// Who listens on a loopback port; see the contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Listening {
    Nobody,
    Outside,
    Sandboxed { pid: u32, session: Option<String>, via: Via },
    Unknown,
}

/// Whether a socket bound to `bound` (as `procinfo::Socket` prints it) answers a connection to `dest`: it is bound to
/// that address, or to the wildcard.
fn covers(bound: &str, dest: IpAddr) -> bool {
    let Ok(bound) = bound.parse::<IpAddr>() else { return false };
    let canon = |ip: IpAddr| match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    };
    let (bound, dest) = (canon(bound), canon(dest));
    bound.is_unspecified() || bound == dest
}

/// The session a sandboxed `pid` is attributed to, and how; `None` for a process that is not attributed to a ferret
/// sandbox (outside any, or under a profile no listed session claims and carrying no mark).
fn attribute(pid: u32, identity: bool, home: &Path, sessions: &[Member<'_>]) -> Option<(Option<String>, Via)> {
    if identity {
        if !in_a_sandbox(pid, home) {
            return None;
        }
        if let Some(m) = sessions.iter().find(|m| in_session(pid, m.tmp)) {
            return Some((Some(m.id.to_string()), Via::Identity));
        }
    }
    marked_session(pid).map(|mark| (Some(mark), Via::Environment))
}

/// Who holds the other end of a connection to `to` on this machine; see the contract.
pub fn listener_of(
    home: &Path,
    sessions: &[Member<'_>],
    to: SocketAddr,
    client: Option<SocketAddr>,
    confined: bool,
    own: &[&str],
) -> Listening {
    let Some(pids) = procinfo::pids() else { return Listening::Unknown };
    let identity = confined && probe().works;
    // The processes that hold the accepted end of the connection, else every listener that covers `to`.
    let (mut accepted, mut listening): (BTreeSet<u32>, BTreeSet<u32>) = (BTreeSet::new(), BTreeSet::new());
    for pid in pids {
        if pid <= 1 {
            continue;
        }
        for socket in procinfo::tcp_sockets(pid) {
            if socket.port != to.port() || !covers(&socket.addr, to.ip()) {
                continue;
            }
            if socket.listening {
                listening.insert(pid);
            } else if client.is_some_and(|c| c.port() == socket.peer_port) {
                accepted.insert(pid);
            }
        }
    }
    // A listener that closed after accepting is gone from the table but its accepted socket is not: the process
    // that holds the connection is the one the bytes reach, whatever else listens there.
    let holders = if accepted.is_empty() { listening } else { accepted };
    if holders.is_empty() {
        return Listening::Nobody;
    }
    for pid in holders {
        let Some((session, via)) = attribute(pid, identity, home, sessions) else { continue };
        // The connector's own processes (its mission's) are not what the check looks for.
        if session.as_deref().is_some_and(|s| own.contains(&s)) {
            continue;
        }
        return Listening::Sandboxed { pid, session, via };
    }
    Listening::Outside
}

/// The census; see the contract.
pub fn take(home: &Path, sessions: &[Member<'_>], groups: &[(String, u32)], confined: bool) -> Census {
    take_by(home, sessions, groups, confined && probe().works)
}

/// `take` with the method chosen (a test forces the fallback).
fn take_by(home: &Path, sessions: &[Member<'_>], groups: &[(String, u32)], identity: bool) -> Census {
    scan(home, sessions, groups, identity, false).0
}

/// The session a process says it belongs to, by the environment variable `Sandbox::env` sets.
fn marked_session(pid: u32) -> Option<String> {
    let prefix = format!("{ENV_MARK}=");
    procinfo::command_line(pid)?.env.iter().find_map(|e| e.strip_prefix(&prefix).map(str::to_string))
}

/// Whether `member`'s session owns `pid` by its profile: refused the home, and not refused the session's temp dir.
/// `None` when the process is gone or cannot be asked about.
fn owned_by_profile(pid: u32, home: &Path, member: &Member<'_>) -> Option<bool> {
    if refused(pid, home)? {
        Some(!refused(pid, member.tmp)?)
    } else {
        Some(false)
    }
}

/// Whether every live member of process group `pgid` is a process of `member` by its profile (and of this user),
/// so that the whole group can be signalled: a group that anything else has joined is not ours to signal.
fn group_is_ours(pgid: u32, member: &Member<'_>, home: &Path, uid: u32) -> bool {
    // SAFETY: getpgrp takes no arguments.
    let own = unsafe { libc::getpgrp() };
    if pgid <= 1 || i64::from(own) == i64::from(pgid) {
        return false;
    }
    let Some(members) = procinfo::group(pgid) else { return false };
    let mut any = false;
    for m in members.iter().filter(|m| !m.zombie) {
        if m.uid != uid {
            return false;
        }
        // A member that exited since the list was read cannot be asked about: it is no longer a member.
        match owned_by_profile(m.pid, home, member) {
            Some(true) => any = true,
            Some(false) => return false,
            None => {}
        }
    }
    any
}

/// Sends `sig` to the process group `pgid`.
fn signal_group(pgid: u32, sig: i32) -> bool {
    let Ok(pg) = i32::try_from(pgid) else { return false };
    if pgid <= 1 {
        return false;
    }
    // SAFETY: kill(2) takes plain integers and has no memory effects.
    unsafe { libc::kill(-pg, sig) == 0 }
}

/// The census, stopping what it finds as it finds it when `stop` (see `kill`): the process groups that were
/// stopped as a whole come back with it, with the index in `sessions` of the session each belongs to.
fn scan(
    home: &Path,
    sessions: &[Member<'_>],
    groups: &[(String, u32)],
    identity: bool,
    stop: bool,
) -> (Census, BTreeMap<u32, usize>) {
    let taken_ms = ferret_core::now_ms();
    let mut frozen: BTreeMap<u32, usize> = BTreeMap::new();
    let Some(pids) = procinfo::pids() else {
        return (Census { taken_ms, readable: false, identity, processes: Vec::new() }, frozen);
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
        let attributed: Option<(usize, Via)> = if identity {
            if in_a_sandbox(pid, home) {
                sessions
                    .iter()
                    .position(|m| in_session(pid, m.tmp))
                    .map(|i| (i, Via::Identity))
                    // A sandbox no listed session's profile matches (a replay): what it was started with.
                    .or_else(|| {
                        let mark = marked_session(pid)?;
                        sessions.iter().position(|m| m.id == mark).map(|i| (i, Via::Environment))
                    })
            } else {
                None
            }
        } else {
            marked_session(pid)
                .and_then(|mark| sessions.iter().position(|m| m.id == mark))
                .map(|i| (i, Via::Environment))
        };
        let Some((index, via)) = attributed else { continue };
        let Some(member) = sessions.get(index) else { continue };
        if stop {
            // Before anything else is read about it: a process that exits and forks on has no time to wait for that.
            if via == Via::Identity
                && group_is_ours(info.pgid, member, home, uid)
                && signal_group(info.pgid, libc::SIGSTOP)
            {
                frozen.insert(info.pgid, index);
            }
            signal_pid(info.pid, &info.start, libc::SIGSTOP);
        }
        add(info, member.id, via);
    }
    for (session, pgid) in groups {
        for member in procinfo::group(*pgid).unwrap_or_default() {
            if !member.zombie && member.pid != me && member.pid > 1 {
                if stop {
                    signal_pid(member.pid, &member.start, libc::SIGSTOP);
                }
                add(member, session, Via::Group);
            }
        }
    }
    (Census { taken_ms, readable: true, identity, processes: found.into_values().collect() }, frozen)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Killed {
    pub rounds: u32,
    pub killed: usize,
    /// The process table could be read. When it could not, nothing was stopped and `left` says nothing.
    pub readable: bool,
    pub left: Vec<Process>,
}

/// Signals process `pid` while it still has the start time `start`.
fn signal_pid(pid: u32, start: &str, sig: i32) -> bool {
    let Ok(raw) = i32::try_from(pid) else { return false };
    if pid <= 1 || pid == std::process::id() {
        return false;
    }
    let same = procinfo::info(pid).is_some_and(|i| i.start == start && !i.zombie);
    // SAFETY: kill(2) takes plain integers and has no memory effects.
    same && unsafe { libc::kill(raw, sig) } == 0
}

/// Signals `process` while it still is the process the census saw.
fn signal(process: &Process, sig: i32) -> bool {
    signal_pid(process.pid, &process.start, sig)
}

/// Stops what the census finds for `sessions`; see the contract. `known_groups` are `(session, process group)` pairs
/// seen in an earlier census.
pub fn kill(
    home: &Path,
    sessions: &[Member<'_>],
    groups: &[(String, u32)],
    known_groups: &[(String, u32)],
    confined: bool,
) -> Killed {
    kill_by(home, sessions, groups, known_groups, confined && probe().works)
}

/// Stops what runs under a profile that may read `tmp` and not the ferret home (a replay of the oracle).
pub fn kill_under(home: &Path, tmp: &Path) -> Killed {
    kill_by(home, &[Member { id: "replay", tmp }], &[], &[], probe().works)
}

fn kill_by(
    home: &Path,
    sessions: &[Member<'_>],
    groups: &[(String, u32)],
    known_groups: &[(String, u32)],
    identity: bool,
) -> Killed {
    // SAFETY: geteuid takes no arguments.
    let uid = unsafe { libc::geteuid() };
    let (mut rounds, mut killed, mut quiet) = (0, 0, 0);
    let began = Instant::now();
    // Process groups known to be wholly a session's (index into `sessions`): signalled before each scan, whether or
    // not the scan finds a member (a process that forks and exits has no pid to find).
    let mut watch: BTreeMap<u32, usize> = BTreeMap::new();
    if identity {
        for (session, pgid) in known_groups {
            if let Some(index) = sessions.iter().position(|m| m.id == session) {
                watch.insert(*pgid, index);
            }
        }
    }
    loop {
        for (pgid, index) in &watch {
            if sessions.get(*index).is_some_and(|m| group_is_ours(*pgid, m, home, uid)) {
                let members = procinfo::group(*pgid).map_or(0, |g| g.iter().filter(|m| !m.zombie).count());
                if signal_group(*pgid, libc::SIGSTOP) && signal_group(*pgid, libc::SIGKILL) {
                    killed += members;
                }
            }
        }
        // Everything it finds is already stopped when it returns.
        let (census, frozen) = scan(home, sessions, groups, identity, true);
        if !census.readable {
            return Killed { rounds, killed, readable: false, left: Vec::new() };
        }
        let targets = census.processes;
        watch.extend(frozen.iter().map(|(pgid, index)| (*pgid, *index)));
        let alive =
            |pgid: &u32, _: &mut usize| procinfo::group(*pgid).is_some_and(|members| members.iter().any(|m| !m.zombie));
        let settled = targets.is_empty();
        if settled {
            watch.retain(alive);
        }
        if settled && watch.is_empty() {
            // Twice: a process that comes and goes can be missed by one scan.
            quiet += 1;
            if quiet >= 2 {
                return Killed { rounds, killed, readable: true, left: Vec::new() };
            }
            std::thread::sleep(Duration::from_millis(30));
            continue;
        }
        quiet = 0;
        if rounds >= MAX_ROUNDS || began.elapsed() >= MAX_KILL_TIME {
            return Killed { rounds, killed, readable: true, left: targets };
        }
        rounds += 1;
        for pgid in frozen.keys() {
            signal_group(*pgid, libc::SIGKILL);
        }
        for p in &targets {
            // A group that was killed whole counts its found members (their pids may be gone already).
            if signal(p, libc::SIGKILL) || frozen.contains_key(&p.pgid) {
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
    use ferret_core::config::{SandboxCfg, SandboxMode};
    use std::path::PathBuf;
    use std::process::Stdio;

    fn available() -> bool {
        cfg!(target_os = "macos") && Path::new(super::super::SANDBOX_EXEC).exists()
    }

    /// The production layout: one ferret home, sessions under it, each with a temp dir.
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
        assert!(p.works && !p.undetermined, "{}", p.detail);
        // Remembered: the second answer is the first.
        assert_eq!(p, probe());
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

        let killed = kill(&home, &members[..1], &[], &[], true);
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
        assert!(take(&home, &members, &[], true).is_empty_for("s-census-1"));
        assert!(!take(&home, &members, &[], true).is_empty_for("s-census-2"));
        // A session that is not listed is not reported, and so is not killed.
        assert!(take(&home, &members[..1], &[], true).of("s-census-2").next().is_none());
        assert_eq!(kill(&home, &members[..1], &[], &[], true).killed, 0);
        assert!(alive(other));
        assert!(kill(&home, &members[1..], &[], &[], true).left.is_empty());
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
        let census = take(&rig.home, &members, &[], true);
        let listening: Vec<&Listener> = census.of("s-census-3").flat_map(|p| &p.listeners).collect();
        assert!(
            listening.iter().any(|l| l.port == port && l.proto == procinfo::Proto::Tcp && l.addr == "127.0.0.1"),
            "{census:?}"
        );
        assert!(kill(&rig.home, &members, &[], &[], true).left.is_empty());
    }

    /// Starts a perl listener under `sb` on a loopback port and returns the port.
    fn listen_under(rig: &mut Rig, sb: &Sandbox, tmp: &Path, clear_env: bool) -> u16 {
        let port_file = tmp.join(format!("port-{}", rig.spawned.len()));
        let script = format!(
            "/usr/bin/perl -MIO::Socket::INET -e '$s=IO::Socket::INET->new(Listen=>1,LocalAddr=>\"127.0.0.1\",\
             LocalPort=>0,Proto=>\"tcp\") or die; open F,\">{}\"; print F $s->sockport; close F; sleep 60'",
            port_file.display()
        );
        let script = if clear_env { format!("/usr/bin/env -i {script}") } else { script };
        rig.run(sb, &script, false);
        for _ in 0..100 {
            if let Some(p) = std::fs::read_to_string(&port_file).ok().and_then(|t| t.trim().parse().ok()) {
                return p;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("the listener did not start");
    }

    #[test]
    fn a_listener_is_told_apart_by_the_profile_it_runs_under() {
        if !available() {
            return;
        }
        assert!(probe().works, "{}", probe().detail);
        let mut rig = Rig::new();
        let (one, two) = (rig.sandbox("s-listen-1"), rig.sandbox("s-listen-2"));
        let (tmp1, tmp2) = (rig.tmp("s-listen-1"), rig.tmp("s-listen-2"));
        let members = [Member { id: "s-listen-1", tmp: &tmp1 }, Member { id: "s-listen-2", tmp: &tmp2 }];
        let home = rig.home.clone();
        let plain_port = listen_under(&mut rig, &one, &tmp1, false);
        // A squatter that cleared its environment is still found: identity is the profile, not the variable.
        let cleared_port = listen_under(&mut rig, &two, &tmp2, true);
        // The operator's own service: this process.
        let own = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let own_port = own.local_addr().expect("addr").port();
        let at = |port: u16| SocketAddr::from(([127, 0, 0, 1], port));
        let ours = |port: u16| listener_of(&home, &members, at(port), None, true, &[]);
        match ours(plain_port) {
            Listening::Sandboxed { session, via, .. } => {
                assert_eq!(session.as_deref(), Some("s-listen-1"));
                assert_eq!(via, Via::Identity);
            }
            other => panic!("a sandboxed listener was read as {other:?}"),
        }
        assert!(
            matches!(ours(cleared_port), Listening::Sandboxed { session: Some(ref s), .. } if s == "s-listen-2"),
            "{:?}",
            ours(cleared_port)
        );
        assert_eq!(ours(own_port), Listening::Outside);
        let free = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            l.local_addr().expect("addr").port()
        };
        assert_eq!(ours(free), Listening::Nobody);
        // A sandbox that no listed session claims and that carries no mark is not attributed: only the first
        // session is listed here, so the second's listener without its variable reads as outside.
        assert_eq!(listener_of(&home, &members[..1], at(cleared_port), None, true, &[]), Listening::Outside);
        // Without identity (the daemon runs commands unconfined) only the variable tells, so a cleared
        // environment is missed: the stated limit of the fallback.
        assert!(matches!(
            listener_of(&home, &members, at(plain_port), None, false, &[]),
            Listening::Sandboxed { via: Via::Environment, .. }
        ));
        assert_eq!(listener_of(&home, &members, at(cleared_port), None, false, &[]), Listening::Outside);
        assert!(kill(&rig.home, &members, &[], &[], true).left.is_empty());
    }

    /// Starts a perl listener under `sb` on `bind`:`port` (0: any), with SO_REUSEADDR; with `one_shot` it accepts one
    /// connection, closes its listening socket and keeps the accepted one. Returns the port.
    fn listen_on(rig: &mut Rig, sb: &Sandbox, tmp: &Path, bind: &str, port: u16, one_shot: bool) -> u16 {
        let port_file = tmp.join(format!("port-{}", rig.spawned.len()));
        let after = if one_shot { "$c=$s->accept; close $s; sleep 60;" } else { "sleep 60;" };
        let script = format!(
            "/usr/bin/perl -MIO::Socket::INET -e '$s=IO::Socket::INET->new(Listen=>5,LocalAddr=>\"{bind}\",\
             LocalPort=>{port},Proto=>\"tcp\",ReuseAddr=>1) or die; open F,\">{}\"; print F $s->sockport; close F; {after}'",
            port_file.display()
        );
        rig.run(sb, &script, false);
        for _ in 0..100 {
            if let Some(p) = std::fs::read_to_string(&port_file).ok().and_then(|t| t.trim().parse().ok()) {
                return p;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("the listener did not start");
    }

    #[test]
    fn a_one_shot_listener_is_found_by_the_connection_it_accepted() {
        if !available() {
            return;
        }
        let mut rig = Rig::new();
        let squatter = rig.sandbox("s-shot-1");
        let tmp = rig.tmp("s-shot-1");
        let members = [Member { id: "s-shot-1", tmp: &tmp }];
        let home = rig.home.clone();
        let port = listen_on(&mut rig, &squatter, &tmp, "127.0.0.1", 0, true);
        let to = SocketAddr::from(([127, 0, 0, 1], port));
        let client = std::net::TcpStream::connect(to).expect("connect");
        let me = client.local_addr().expect("addr");
        // The squatter accepts and closes its listening socket; only the accepted socket names it from then on.
        let mut found = Listening::Nobody;
        for _ in 0..50 {
            std::thread::sleep(Duration::from_millis(100));
            let listening = procinfo::pids()
                .unwrap_or_default()
                .into_iter()
                .any(|p| procinfo::tcp_sockets(p).iter().any(|s| s.listening && s.port == port));
            found = listener_of(&home, &members, to, Some(me), true, &[]);
            if !listening {
                break;
            }
        }
        match found {
            Listening::Sandboxed { session, via, .. } => {
                assert_eq!(session.as_deref(), Some("s-shot-1"));
                assert_eq!(via, Via::Identity);
            }
            other => panic!("a one-shot squatter was read as {other:?}"),
        }
        // Without the connection's end the listener, if it still listened, would be all there is: nobody now.
        assert_eq!(listener_of(&home, &members, to, None, true, &[]), Listening::Nobody);
        // The connector's own mission's processes are not what the check looks for.
        assert_eq!(listener_of(&home, &members, to, Some(me), true, &["s-shot-1"]), Listening::Outside);
        assert!(kill(&rig.home, &members, &[], &[], true).left.is_empty());
    }

    #[test]
    fn another_sessions_listener_is_found_behind_the_connectors_own_wildcard_listener() {
        if !available() {
            return;
        }
        let mut rig = Rig::new();
        let (squat, decoy) = (rig.sandbox("s-wild-b"), rig.sandbox("s-wild-a"));
        let (tmp_b, tmp_a) = (rig.tmp("s-wild-b"), rig.tmp("s-wild-a"));
        let members = [Member { id: "s-wild-a", tmp: &tmp_a }, Member { id: "s-wild-b", tmp: &tmp_b }];
        let home = rig.home.clone();
        // B listens on the loopback address; A, the connector, listens on the wildcard of the same port.
        let port = listen_on(&mut rig, &squat, &tmp_b, "127.0.0.1", 0, false);
        listen_on(&mut rig, &decoy, &tmp_a, "0.0.0.0", port, false);
        let to = SocketAddr::from(([127, 0, 0, 1], port));
        // Whichever listener the table lists first, B's is reported and A's own is not an excuse.
        match listener_of(&home, &members, to, None, true, &["s-wild-a"]) {
            Listening::Sandboxed { session, .. } => assert_eq!(session.as_deref(), Some("s-wild-b")),
            other => panic!("the squatter was masked: {other:?}"),
        }
        // A listener on another address of the machine does not answer a connection to this one.
        let elsewhere = SocketAddr::from(([127, 0, 0, 2], port));
        assert_eq!(listener_of(&home, &members, elsewhere, None, true, &["s-wild-a"]), Listening::Outside);
        assert!(kill(&rig.home, &members, &[], &[], true).left.is_empty());
    }

    #[test]
    fn a_socket_covers_its_address_and_the_wildcard_and_no_other() {
        let ip = |s: &str| s.parse::<IpAddr>().expect("ip");
        assert!(covers("127.0.0.1", ip("127.0.0.1")));
        assert!(covers("0.0.0.0", ip("127.0.0.1")));
        assert!(covers("::", ip("::1")));
        assert!(covers("::ffff:127.0.0.1", ip("127.0.0.1")));
        assert!(covers("192.168.0.2", ip("::ffff:192.168.0.2")));
        assert!(!covers("127.0.0.2", ip("127.0.0.1")));
        assert!(!covers("192.168.0.2", ip("127.0.0.1")));
        assert!(!covers("not an address", ip("127.0.0.1")));
    }

    #[test]
    fn an_unreadable_table_says_unknown_for_a_listener() {
        let home = std::env::temp_dir();
        procinfo::UNREADABLE.with(|u| u.set(true));
        let got = listener_of(&home, &[], SocketAddr::from(([127, 0, 0, 1], 1)), None, true, &[]);
        procinfo::UNREADABLE.with(|u| u.set(false));
        assert_eq!(got, Listening::Unknown);
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
        let killed = kill_by(&home, &members, &groups, &[], false);
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

    #[test]
    fn a_probe_that_could_not_run_is_asked_again() {
        let unrun = Probe { works: false, undetermined: true, detail: "no process could be started".into() };
        let works = Probe { works: true, undetermined: false, detail: "ok".into() };
        let cell = Mutex::new(None);
        assert_eq!(probe_cached(&cell, || unrun.clone()), unrun);
        // Not kept: the next call runs the probe again, and its answer is kept.
        assert_eq!(probe_cached(&cell, || works.clone()), works);
        assert_eq!(probe_cached(&cell, unreachable_probe), works);
        // A settled failure (the question was asked and did not tell the sandboxes apart) is kept too.
        let no = Probe { works: false, undetermined: false, detail: "does not tell them apart".into() };
        let cell = Mutex::new(None);
        assert_eq!(probe_cached(&cell, || no.clone()), no);
        assert_eq!(probe_cached(&cell, || works.clone()), no);
    }

    fn unreachable_probe() -> Probe {
        Probe { works: false, undetermined: true, detail: "the probe ran although an answer was kept".into() }
    }

    #[test]
    fn an_unconfined_daemon_does_not_claim_an_empty_census() {
        // With `sandbox.mode = "none"` no process is refused the home: the census is the fallback and cannot say none.
        let home = std::env::temp_dir();
        let census = take(&home, &[], &[], false);
        assert!(census.readable && !census.identity);
        assert!(!census.is_empty_for("s-x"), "a fallback census read as empty");
        let by_identity = Census { taken_ms: 1, readable: true, identity: true, processes: Vec::new() };
        assert!(by_identity.is_empty_for("s-x"));
    }

    /// The part of `procinfo::group(pgid)` that is not a zombie.
    fn live_members(pgid: u32) -> usize {
        procinfo::group(pgid).map_or(0, |g| g.iter().filter(|m| !m.zombie).count())
    }

    #[test]
    fn a_process_that_forks_and_exits_in_a_loop_is_killed_by_its_group() {
        if !available() {
            return;
        }
        assert!(probe().works, "{}", probe().detail);
        let mut rig = Rig::new();
        let sb = rig.sandbox("s-census-6");
        let tmp = rig.tmp("s-census-6");
        let members = [Member { id: "s-census-6", tmp: &tmp }];
        // (The trailing command keeps the shell from becoming the perl, which as a group leader cannot setsid.)
        // After setsid each generation forks the next and exits, so its pid is gone within milliseconds; the group
        // and the session stay.
        rig.run(
            &sb,
            "/usr/bin/env -i /usr/bin/perl -MPOSIX -e 'POSIX::setsid(); while (1) { select(undef, undef, undef, 0.003); \
             fork && exit 0 }'; /bin/sleep 75",
            false,
        );
        let home = rig.home.clone();
        let census = until(&home, &members, &[], true, |c| c.of("s-census-6").any(|p| p.exe.ends_with("perl")));
        let hopper = census.of("s-census-6").find(|p| p.exe.ends_with("perl")).expect("the hopper was not found");
        let group = hopper.pgid;
        assert_eq!(hopper.via, Via::Identity);
        assert_ne!(group, rig.spawned[0].id(), "setsid took it out of the command's group");
        // The group is known from the census; no pid in it lasts long enough to be found again.
        let known = [("s-census-6".to_string(), group)];
        let killed = kill(&home, &members, &[], &known, true);
        assert!(killed.readable && killed.left.is_empty(), "{killed:?}");
        for _ in 0..50 {
            if live_members(group) == 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(30));
        }
        assert_eq!(live_members(group), 0, "the hopper's group survived: {:?}", procinfo::group(group));
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(live_members(group), 0, "the hopper came back");
        assert!(take(&home, &members, &[], true).is_empty_for("s-census-6"));
    }

    #[test]
    fn a_group_is_signalled_only_when_all_of_it_is_the_sessions() {
        if !available() {
            return;
        }
        use std::os::unix::process::CommandExt;
        assert!(probe().works, "{}", probe().detail);
        let mut rig = Rig::new();
        let one = rig.sandbox("s-census-7");
        let (tmp1, tmp2) = (rig.tmp("s-census-7"), rig.tmp("s-census-8"));
        let (m1, m2) = (Member { id: "s-census-7", tmp: &tmp1 }, Member { id: "s-census-8", tmp: &tmp2 });
        rig.run(&one, "/bin/sleep 66 & /bin/sleep 67 & wait", false);
        let plain = std::process::Command::new("/bin/sleep").arg("68").process_group(0).spawn().expect("spawn");
        let plain_group = plain.id();
        rig.spawned.push(plain);
        let home = rig.home.clone();
        let group = rig.spawned[0].id();
        // Not until the shell has become its sandboxed self and started its sleeps.
        for _ in 0..100 {
            if live_members(group) >= 3 {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        // SAFETY: geteuid takes no arguments.
        let uid = unsafe { libc::geteuid() };
        assert!(group_is_ours(group, &m1, &home, uid), "the session's own group");
        assert!(!group_is_ours(group, &m2, &home, uid), "another session's group");
        assert!(!group_is_ours(plain_group, &m1, &home, uid), "a group of an unsandboxed process");
        assert!(!group_is_ours(1, &m1, &home, uid) && !group_is_ours(0, &m1, &home, uid));
        // SAFETY: getpgrp takes no arguments.
        assert!(!group_is_ours(u32::try_from(unsafe { libc::getpgrp() }).unwrap_or(0), &m1, &home, uid));
        // A stale hint naming another session's group signals nothing.
        let hinted = kill(&home, &[m2], &[], &[("s-census-8".to_string(), group)], true);
        assert_eq!(hinted.killed, 0, "{hinted:?}");
        assert!(live_members(group) >= 3);
        assert!(live_members(plain_group) >= 1);
    }

    #[test]
    fn a_replay_orphan_is_found_and_killed() {
        if !available() {
            return;
        }
        assert!(probe().works, "{}", probe().detail);
        let mut rig = Rig::new();
        let caller = rig.sandbox("s-census-9");
        let tmp = rig.tmp("s-census-9");
        // The oracle's layout: private staging under the home's oracle-runs.
        let private = caller.oracle_staging_root().join("run-1");
        let (rws, rtmp) = (private.join("workspace"), private.join("tmp"));
        for d in [&rws, &rtmp] {
            std::fs::create_dir_all(d).expect("mkdir");
        }
        let replay = caller.isolated_replay(&rws, &rtmp).expect("replay");
        let members = [Member { id: "s-census-9", tmp: &tmp }];
        // The candidate's program leaves a process behind: its own session, no environment, nobody to wait for it.
        rig.run(
            &replay,
            "/usr/bin/env -i /usr/bin/perl -MPOSIX -e 'POSIX::setsid(); fork && exit 0; exec \"/bin/sleep\", \"69\"'; \
             /bin/sleep 70",
            false,
        );
        let home = rig.home.clone();
        // A replay refuses the session's temp dir, so the environment it was started with is what names the session.
        let census = until(&home, &members, &[], true, |c| c.of("s-census-9").any(|p| p.exe.ends_with("sleep")));
        assert!(census.of("s-census-9").any(|p| p.via == Via::Environment), "{census:?}");
        // The orphan has no environment: only the replay's own profile finds it.
        let replay_member = [Member { id: "replay", tmp: &rtmp }];
        let under = until(&home, &replay_member, &[], true, |c| c.of("replay").any(|p| p.ppid == 1));
        assert!(under.of("replay").any(|p| p.exe.ends_with("sleep") && p.ppid == 1), "{under:?}");
        let killed = kill_under(&home, &rtmp);
        assert!(killed.readable && killed.left.is_empty() && killed.killed >= 1, "{killed:?}");
        assert!(take(&home, &replay_member, &[], true).is_empty_for("replay"));
    }
}
