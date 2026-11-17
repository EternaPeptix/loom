//! The process and listener census of the daemon's sessions: what each session left running, found by sandbox identity.
//!
//! CONTRACT.
//!
//! This is the floor's knowledge of processes (`docs/MONITOR.md` §2.2, E3). `loom_tools::sandbox::census` finds the
//! processes a session started by the sandbox profile they run under, whatever they did to their process group
//! and environment (`setsid`, a double fork, `env -i`), with the TCP sockets each listens on; this module asks it for
//! the daemon's sessions every `EVERY` (60 s), keeps the answer, and reports what is new.
//!
//! - `CensusView { taken_ms, readable, identity, identity_detail, sessions }`: the last census. `readable` is false
//!   when the kernel's process table could not be read (the view then says nothing about any session: it never reads
//!   as "no processes"); `identity` is true when processes were found by sandbox identity, false when by the
//!   environment variable and groups (best effort: `env -i` and a double fork defeat it; `identity_detail` says why
//!   the identity probe did not work); `sessions` maps a session id to its running processes
//!   (`loom_tools::sandbox::census::Process`, with their listeners), sessions with none left out. It is serialised for
//!   `GET /api/census`.
//! - `members(sessions)`: the `(id, temp dir)` pairs a census is asked about, from the daemon's non-archived sessions.
//! - `take(home, members)` (blocking: the identity probe, the first time, takes up to 3 s) builds a `CensusView`.
//! - `survivors(previous, now, ended)`: the `(session, process)` pairs in `now` that belong to a session in `ended`
//!   (finished or stopped: nothing of it should be running) and were not in `previous`: what the daemon tells the
//!   operator once, as a warning in its log naming the session, the process, what it listens on and what stops it
//!   (`POST /api/sessions/{id}/census/kill`). A process that was there already is not told
//!   again; a view that was not `readable` tells nothing.
//! - `Runtime` runs the census in the background from start (not under `cfg(test)`), keeps the last view
//!   (`Runtime::census()`, `None` until the first finishes), takes one on demand (`Runtime::census_now()`) and stops a
//!   session's processes (`Runtime::census_kill(session)`: SIGSTOP then SIGKILL of everything the census finds for
//!   it, repeated until none is left or 5 rounds; a pid that was reused is not signalled; the answer is
//!   `census::Killed`). Neither stops anything on its own: a command may have started a server on purpose.
//!
//! Tests required: `a_view_names_only_sessions_with_processes_and_round_trips`,
//! `survivors_are_the_new_processes_of_ended_sessions`, `an_unreadable_census_tells_nothing`,
//! `members_are_the_temp_dirs_of_the_sessions_given`.

use loom_tools::sandbox::census::{Member, Process};
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
    pub listeners: Vec<loom_tools::procinfo::Listener>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CensusView {
    pub taken_ms: u64,
    pub readable: bool,
    pub identity: bool,
    pub identity_detail: String,
    pub sessions: BTreeMap<String, Vec<ProcessView>>,
}

fn via_name(via: loom_tools::sandbox::census::Via) -> &'static str {
    use loom_tools::sandbox::census::Via;
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

/// The `(id, temp dir)` pairs of `sessions` (ids), the temp dir being where `paths` puts it.
pub fn members(paths: &loom_core::config::Paths, sessions: &[loom_core::SessionId]) -> Vec<(String, PathBuf)> {
    sessions.iter().map(|id| (id.as_str().to_string(), paths.session_tmp(id))).collect()
}

/// The census of `members` under `home`; see the contract.
pub fn take(home: &Path, members: &[(String, PathBuf)]) -> CensusView {
    let asked: Vec<Member<'_>> = members.iter().map(|(id, tmp)| Member { id, tmp }).collect();
    let probe = loom_tools::sandbox::census::probe();
    let census = loom_tools::sandbox::census::take(home, &asked, &[]);
    let mut sessions: BTreeMap<String, Vec<ProcessView>> = BTreeMap::new();
    for p in &census.processes {
        sessions.entry(p.session.clone()).or_default().push(view_of(p));
    }
    CensusView {
        taken_ms: census.taken_ms,
        readable: census.readable,
        identity: census.identity,
        identity_detail: if probe.works { String::new() } else { probe.detail.clone() },
        sessions,
    }
}

/// What is new in `now` among the sessions in `ended`; see the contract.
pub fn survivors<'a>(
    previous: Option<&CensusView>,
    now: &'a CensusView,
    ended: &BTreeSet<String>,
) -> Vec<(&'a str, &'a ProcessView)> {
    if !now.readable {
        return Vec::new();
    }
    let known: BTreeSet<(&str, u32, &str)> = previous
        .filter(|p| p.readable)
        .map(|p| {
            p.sessions
                .iter()
                .flat_map(|(s, procs)| procs.iter().map(move |q| (s.as_str(), q.pid, q.start.as_str())))
                .collect()
        })
        .unwrap_or_default();
    now.sessions
        .iter()
        .filter(|(session, _)| ended.contains(*session))
        .flat_map(|(session, procs)| procs.iter().map(move |p| (session.as_str(), p)))
        .filter(|(session, p)| !known.contains(&(*session, p.pid, p.start.as_str())))
        .collect()
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
    format!(
        "Session {session} has ended but process {} ({}) is still running under its sandbox{listening}. Stop it with POST /api/sessions/{session}/census/kill.",
        p.pid,
        if p.exe.is_empty() { "unknown program" } else { &p.exe }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use loom_tools::procinfo::{Listener, Proto};

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
        let none = take(Path::new("/nonexistent-home"), &[]);
        assert!(none.sessions.is_empty());
    }

    #[test]
    fn survivors_are_the_new_processes_of_ended_sessions() {
        let ended: BTreeSet<String> = ["s-done".to_string()].into();
        let before = view(true, &[("s-done", vec![proc(10, false)]), ("s-live", vec![proc(20, false)])]);
        let now = view(
            true,
            &[("s-done", vec![proc(10, false), proc(11, true)]), ("s-live", vec![proc(20, false), proc(21, false)])],
        );
        let new = survivors(Some(&before), &now, &ended);
        assert_eq!(new.len(), 1);
        assert_eq!((new[0].0, new[0].1.pid), ("s-done", 11));
        // Without a previous census every process of an ended session is new; none of a live session is.
        assert_eq!(survivors(None, &now, &ended).len(), 2);
        let line = survivor_line(new[0].0, new[0].1);
        assert!(
            line.contains("s-done") && line.contains("tcp 127.0.0.1:4000") && line.contains("/census/kill"),
            "{line}"
        );
        // The same pid with another start time is another process.
        let mut reused = before.clone();
        reused.sessions.get_mut("s-done").expect("session")[0].start = "9.000000".into();
        assert_eq!(survivors(Some(&reused), &now, &ended).len(), 2);
    }

    #[test]
    fn an_unreadable_census_tells_nothing() {
        let ended: BTreeSet<String> = ["s-done".to_string()].into();
        let blind = view(false, &[]);
        let now = view(true, &[("s-done", vec![proc(10, false)])]);
        assert!(survivors(Some(&now), &blind, &ended).is_empty());
        // After a blind census the next one cannot tell what is new, so it tells everything once.
        assert_eq!(survivors(Some(&blind), &now, &ended).len(), 1);
    }

    #[test]
    fn members_are_the_temp_dirs_of_the_sessions_given() {
        let paths = loom_core::config::Paths::at(Path::new("/h"));
        let ids = [loom_core::SessionId::from("s-1"), loom_core::SessionId::from("s-2")];
        let m = members(&paths, &ids);
        assert_eq!(m[0], ("s-1".to_string(), paths.session_tmp(&ids[0])));
        assert_eq!(m.len(), 2);
    }
}
