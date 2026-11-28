//! The process and listener census of the daemon's sessions: what each session left running, found by sandbox identity.
//!
//! CONTRACT.
//!
//! This is the floor's knowledge of processes (`docs/MONITOR.md` §2.2, E3). `ferret_tools::sandbox::census` finds the
//! processes a session started by the sandbox profile they run under, whatever they did to their process group
//! and environment (`setsid`, a double fork, `env -i`), with the TCP sockets each listens on; this module asks it for
//! the daemon's sessions every `EVERY` (60 s), keeps the answer, and reports what is new.
//!
//! - `CensusView { taken_ms, readable, identity, identity_detail, sessions }`: the last census. `readable` is false
//!   when the kernel's process table could not be read (the view then says nothing about any session: it never reads
//!   as "no processes"); `identity` is true when processes were found by sandbox identity, false when by the
//!   environment variable and groups (best effort: `env -i` and a double fork defeat it; `identity_detail` says why
//!   the identity probe did not work); `sessions` maps a session id to its running processes
//!   (`ferret_tools::sandbox::census::Process`, with their listeners), sessions with none left out. It is serialised for
//!   `GET /api/census`.
//! - `members(sessions)`: the `(id, temp dir)` pairs a census is asked about, from the daemon's sessions that are not
//!   archived (`Runtime::archive` stops what a session left running when it archives it). The temp dir is the
//!   canonical path of the one the session's sandbox was built with (a profile opens real paths, and the question is
//!   asked about the path given); `canonical_home(home)` is the ferret home the same way.
//! - `take(home, members, confined)` (blocking: the identity probe, when it has not settled, takes up to 3 s) builds a
//!   `CensusView`. `confined` is whether commands run under Seatbelt (`sandbox.mode`); `identity_detail` says why
//!   identity was not used (the probe's sentence, or that the daemon runs commands unconfined). A census without
//!   identity never reads as "none": `Census::is_empty_for` is false for it.
//! - `has_ended(finished, phase, last_end)`: whether nothing of a session should be running: it is finished (a
//!   settlement or `Phase::Ended`) or it was stopped (not running, its last turn ended `Stopped`).
//! - `tell(told, now, ended)`: the sentences (`survivor_line`) for the processes in `now` that belong to a session in
//!   `ended` and have not been told, and remembers them in `told` (a set of `(session, pid, start)`: what has been
//!   told, not what was seen, so a process that was running before its session ended is told once the session has).
//!   `told` keeps only what `now` still shows; a view that was not `readable` tells nothing and changes nothing. The
//!   daemon logs each as a warning naming the session, the process, what it listens on and what stops it
//!   (`POST /api/sessions/{id}/census/kill`). Text that comes from a process (its executable's path) is written with
//!   `{:?}`, so a newline or control character in it cannot forge a log line.
//! - `blind_notice(detail)`: the sentence the daemon logs and notifies once when a census runs without identity
//!   although commands are confined.
//! - `known_groups(view, session)`: the `(session, pgid)` pairs `view` shows for a session, which `census_kill` gives
//!   the kill as hints for its groups.
//! - `Runtime` runs the census in the background from start (not under `cfg(test)`), keeps the last view
//!   (`Runtime::census()`, `None` until the first finishes), takes one on demand (`Runtime::census_now()`) and stops a
//!   session's processes (`Runtime::census_kill(session)`: SIGSTOP then SIGKILL of everything the census finds for
//!   it and of its known groups, repeated until two scans find nothing; a pid that was reused is not signalled; the
//!   answer is `census::Killed`; a process table that cannot be read is an error, not a success). Neither stops
//!   anything on its own: a command may have started a server on purpose.
//!
//! Tests required: `a_view_names_only_sessions_with_processes_and_round_trips`,
//! `a_process_is_told_once_after_its_session_has_ended`, `an_unreadable_census_tells_nothing`,
//! `a_stopped_session_has_ended_for_the_census`, `a_process_cannot_forge_a_log_line`,
//! `members_are_the_temp_dirs_of_the_sessions_given`.

use ferret_tools::sandbox::census::{Member, Process};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// How often the census runs.
pub const EVERY: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessView {
    pub pid: u32,
    pub ppid: u32,
    pub pgid: u32,
    pub start: String,
    pub exe: String,
    /// `identity`, `environment` or `group`.
    pub via: String,
    pub listeners: Vec<ferret_tools::procinfo::Listener>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CensusView {
    pub taken_ms: u64,
    pub readable: bool,
    pub identity: bool,
    pub identity_detail: String,
    pub sessions: BTreeMap<String, Vec<ProcessView>>,
}

fn via_name(via: ferret_tools::sandbox::census::Via) -> &'static str {
    use ferret_tools::sandbox::census::Via;
    match via {
        Via::Identity => "identity",
        Via::Environment => "environment",
        Via::Group => "group",
    }
}

fn view_of(p: &Process) -> ProcessView {
    ProcessView {
        pid: p.pid,
        ppid: p.ppid,
        pgid: p.pgid,
        start: p.start.clone(),
        exe: p.exe.clone(),
        via: via_name(p.via).to_string(),
        listeners: p.listeners.clone(),
    }
}

/// The `(id, temp dir)` pairs of `sessions` (ids), the temp dir being where `paths` puts it, canonical when it exists
/// (the sandbox profile opens the canonical path, and the question is asked about the path it is given).
pub fn members(paths: &ferret_core::config::Paths, sessions: &[ferret_core::SessionId]) -> Vec<(String, PathBuf)> {
    sessions
        .iter()
        .map(|id| {
            let tmp = paths.session_tmp(id);
            (id.as_str().to_string(), tmp.canonicalize().unwrap_or(tmp))
        })
        .collect()
}

/// The ferret home as the sandbox profile names it (canonical when it exists).
pub fn canonical_home(home: &Path) -> PathBuf {
    home.canonicalize().unwrap_or_else(|_| home.to_path_buf())
}

/// What is told about a process once: `(session, pid, start)`.
pub type Told = BTreeSet<(String, u32, String)>;

/// The census of `members` under `home`; see the contract.
pub fn take(home: &Path, members: &[(String, PathBuf)], confined: bool) -> CensusView {
    let asked: Vec<Member<'_>> = members.iter().map(|(id, tmp)| Member { id, tmp }).collect();
    let home = canonical_home(home);
    let census = ferret_tools::sandbox::census::take(&home, &asked, &[], confined);
    let identity_detail = if census.identity {
        String::new()
    } else if !confined {
        "the daemon runs commands unconfined (sandbox.mode is not seatbelt), so no process can be told from the \
         operator's own by its sandbox; processes are found by the FERRET_SANDBOX_ID variable only (best effort)"
            .to_string()
    } else {
        ferret_tools::sandbox::census::probe().detail
    };
    let mut sessions: BTreeMap<String, Vec<ProcessView>> = BTreeMap::new();
    for p in &census.processes {
        sessions.entry(p.session.clone()).or_default().push(view_of(p));
    }
    CensusView {
        taken_ms: census.taken_ms,
        readable: census.readable,
        identity: census.identity,
        identity_detail,
        sessions,
    }
}

/// Whether nothing of a session should be running; see the contract.
pub fn has_ended(
    finished: bool,
    phase: crate::session::Phase,
    last_end: Option<ferret_core::event::TurnEndReason>,
) -> bool {
    finished
        || (phase != crate::session::Phase::Running && last_end == Some(ferret_core::event::TurnEndReason::Stopped))
}

/// The sentences for what is new among the sessions in `ended`; see the contract.
pub fn tell(told: &mut Told, now: &CensusView, ended: &BTreeSet<String>) -> Vec<String> {
    if !now.readable {
        return Vec::new();
    }
    let mut lines = Vec::new();
    for (session, procs) in now.sessions.iter().filter(|(session, _)| ended.contains(*session)) {
        for p in procs {
            if told.insert((session.clone(), p.pid, p.start.clone())) {
                lines.push(survivor_line(session, p));
            }
        }
    }
    told.retain(|(session, pid, start)| {
        now.sessions.get(session).is_some_and(|procs| procs.iter().any(|p| p.pid == *pid && p.start == *start))
    });
    lines
}

/// The `(session, pgid)` pairs `view` shows for `session`.
pub fn known_groups(view: Option<&CensusView>, session: &str) -> Vec<(String, u32)> {
    let Some(procs) = view.and_then(|v| v.sessions.get(session)) else { return Vec::new() };
    let groups: BTreeSet<u32> = procs.iter().map(|p| p.pgid).filter(|g| *g > 1).collect();
    groups.into_iter().map(|g| (session.to_string(), g)).collect()
}

/// The sentence the daemon logs, and notifies once, when a census runs without identity under a sandbox.
pub fn blind_notice(detail: &str) -> String {
    format!(
        "The process census cannot tell a session's processes by their sandbox ({detail}). It finds only what still \
         carries the FERRET_SANDBOX_ID variable, so a command that cleared its environment or started a new session \
         can leave a process it does not list, and an empty census proves nothing. It tries the identity query again \
         at every census; check GET /api/census."
    )
}

/// The sentence the daemon logs for a survivor.
pub fn survivor_line(session: &str, p: &ProcessView) -> String {
    let listening = if p.listeners.is_empty() {
        String::new()
    } else {
        let ports: Vec<String> =
            p.listeners.iter().map(|l| format!("{} {}:{}", l.proto.name(), l.addr, l.port)).collect();
        format!(", listening on {}", ports.join(", "))
    };
    // The path is the process's own text: escaped, so that it cannot add a line to the log or rewrite one.
    let program = if p.exe.is_empty() { "unknown program".to_string() } else { format!("{:?}", p.exe) };
    format!(
        "Session {session} has ended but process {} ({program}) is still running under its sandbox{listening}. Stop it with POST /api/sessions/{session}/census/kill.",
        p.pid
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferret_tools::procinfo::{Listener, Proto};

    fn proc(pid: u32, listening: bool) -> ProcessView {
        ProcessView {
            pid,
            ppid: 1,
            pgid: pid,
            start: format!("1.{pid:06}"),
            exe: "/bin/sleep".into(),
            via: "identity".into(),
            listeners: if listening {
                vec![Listener { pid, proto: Proto::Tcp, addr: "127.0.0.1".into(), port: 4000 }]
            } else {
                Vec::new()
            },
        }
    }

    fn view(readable: bool, sessions: &[(&str, Vec<ProcessView>)]) -> CensusView {
        CensusView {
            taken_ms: 1,
            readable,
            identity: true,
            identity_detail: String::new(),
            sessions: sessions.iter().map(|(s, p)| (s.to_string(), p.clone())).collect(),
        }
    }

    #[test]
    fn a_view_names_only_sessions_with_processes_and_round_trips() {
        let v = view(true, &[("s-a", vec![proc(10, true)])]);
        let text = serde_json::to_string(&v).expect("json");
        assert!(text.contains("\"s-a\"") && text.contains("\"tcp\""), "{text}");
        assert_eq!(serde_json::from_str::<CensusView>(&text).expect("back"), v);
        // A real census of nobody lists nobody.
        let none = take(Path::new("/nonexistent-home"), &[], true);
        assert!(none.readable && none.sessions.is_empty());
        let unconfined = take(Path::new("/nonexistent-home"), &[], false);
        assert!(!unconfined.identity && unconfined.identity_detail.contains("unconfined"), "{unconfined:?}");
        assert!(none.sessions.is_empty());
    }

    #[test]
    fn a_process_is_told_once_after_its_session_has_ended() {
        let mut told = Told::new();
        let live: BTreeSet<String> = BTreeSet::new();
        let ended: BTreeSet<String> = ["s-done".to_string()].into();
        // A listener that was started while its session ran is seen by a census, and told of nothing.
        let running = view(true, &[("s-done", vec![proc(10, true)]), ("s-live", vec![proc(20, false)])]);
        assert!(tell(&mut told, &running, &live).is_empty());
        // The session ends; the next census, which sees nothing new, still tells of what was left running.
        let lines = tell(&mut told, &running, &ended);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains("s-done") && lines[0].contains("tcp 127.0.0.1:4000") && lines[0].contains("/census/kill"),
            "{}",
            lines[0]
        );
        // Told once: the same process is not told again, a new one is, and a live session's is not.
        assert!(tell(&mut told, &running, &ended).is_empty());
        let later = view(
            true,
            &[("s-done", vec![proc(10, true), proc(11, false)]), ("s-live", vec![proc(20, false), proc(21, false)])],
        );
        assert_eq!(tell(&mut told, &later, &ended).len(), 1);
        // The same pid with another start time is another process; what is gone is forgotten.
        let mut reused = later.clone();
        reused.sessions.get_mut("s-done").expect("session")[0].start = "9.000000".into();
        assert_eq!(tell(&mut told, &reused, &ended).len(), 1);
        assert_eq!(told.len(), 2, "{told:?}");
        assert!(tell(&mut told, &view(true, &[]), &ended).is_empty() && told.is_empty());
    }

    #[test]
    fn an_unreadable_census_tells_nothing() {
        let ended: BTreeSet<String> = ["s-done".to_string()].into();
        let mut told = Told::new();
        let now = view(true, &[("s-done", vec![proc(10, false)])]);
        assert!(tell(&mut told, &view(false, &[]), &ended).is_empty());
        assert_eq!(tell(&mut told, &now, &ended).len(), 1);
        // A census that could not read the table changes nothing: what was told stays told.
        assert!(tell(&mut told, &view(false, &[]), &ended).is_empty());
        assert!(tell(&mut told, &now, &ended).is_empty());
    }

    #[test]
    fn a_stopped_session_has_ended_for_the_census() {
        use crate::session::Phase;
        use ferret_core::event::TurnEndReason as R;
        assert!(has_ended(true, Phase::Ended, None));
        assert!(has_ended(false, Phase::Idle, Some(R::Stopped)), "a stopped lead is idle");
        assert!(!has_ended(false, Phase::Running, Some(R::Stopped)), "running again");
        assert!(!has_ended(false, Phase::Idle, Some(R::Waiting)), "idle between turns is not ended");
        assert!(!has_ended(false, Phase::Idle, None));
    }

    #[test]
    fn a_process_cannot_forge_a_log_line() {
        let mut p = proc(12, false);
        p.exe = "/tmp/x\n2026-11-17T01:00:00Z  INFO ferret_agent::census: census kill of s-x: nothing left\r".into();
        let line = survivor_line("s-done", &p);
        assert!(!line.contains('\n') && !line.contains('\r'), "{line:?}");
        assert!(line.contains("\\n2026-11-17"), "{line:?}");
        // The known groups of a session are what the view shows, and never the first process's.
        let v = view(true, &[("s-a", vec![proc(10, false), proc(1, false)])]);
        assert_eq!(known_groups(Some(&v), "s-a"), [("s-a".to_string(), 10)]);
        assert!(known_groups(Some(&v), "s-b").is_empty() && known_groups(None, "s-a").is_empty());
    }

    #[test]
    fn members_are_the_temp_dirs_of_the_sessions_given() {
        let paths = ferret_core::config::Paths::at(Path::new("/h"));
        let ids = [ferret_core::SessionId::from("s-1"), ferret_core::SessionId::from("s-2")];
        let m = members(&paths, &ids);
        assert_eq!(m[0], ("s-1".to_string(), paths.session_tmp(&ids[0])));
        assert_eq!(m.len(), 2);
    }
}
