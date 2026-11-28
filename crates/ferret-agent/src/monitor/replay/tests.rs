//! The replay over a fixture home: per-tripwire counts, would-be pauses, precision and recall, dispositions, the
//! authorization of the time, and that it writes nothing.

use super::*;
use ferret_core::event::{
    Event, ModelRef, NetDecision, SessionStart, Termination, ToolCall, ToolClass, ToolResult, ToolStatus,
};
use ferret_core::log::{Durability, SessionLog};
use ferret_core::{Author, CallId, SessionId};
use serde_json::json;
use std::path::Path;

struct Home {
    _dir: tempfile::TempDir,
    paths: Paths,
}

fn home() -> Home {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = Paths::at(std::fs::canonicalize(dir.path()).expect("canon"));
    paths.ensure_private_layout().expect("layout");
    Home { _dir: dir, paths }
}

fn env_of(paths: &Paths) -> Arc<Env> {
    let policy = ferret_net::Policy::new(&ferret_core::config::NetworkCfg::default()).ok().map(Arc::new);
    Arc::new(Env {
        home: paths.home.to_string_lossy().into_owned(),
        copies: format!("{}-copies", paths.home.to_string_lossy()),
        infra: policy,
        network_mode: "allowlist".into(),
        allow: vec![],
        deny: vec![],
        packs: Default::default(),
        relaxed_profiles: Default::default(),
        mcp_hosts: Default::default(),
        box_shell: Default::default(),
    })
}

fn session(h: &Home, id: &str, mission: &str) -> SessionLog {
    let dir = h.paths.sessions_dir().join(id);
    std::fs::create_dir_all(&dir).expect("dir");
    let mut log = SessionLog::create(&dir.join("log.jsonl"), Durability::Batch).expect("create");
    log.append(
        Author::Harness,
        Event::SessionStart(SessionStart {
            session: SessionId::from(id),
            mission: MissionId::from(mission),
            parent: None,
            workspace: "/work/ws".into(),
            pack: "core".into(),
            role: "lead".into(),
            termination: Termination::Explicit,
            model: ModelRef { profile: "p".into(), model: "m".into(), context_window: 10, lineage: None },
            reasoning_replay: Default::default(),
            system_prompt: String::new(),
            tools: vec![],
            budget: Default::default(),
            unattended: false,
            title: String::new(),
            project_instructions: Vec::new(),
            mcp: Vec::new(),
            intercept: false,
            target: None,
            creds: None,
            schema: ferret_core::event::SCHEMA,
        }),
    )
    .expect("start");
    log
}

fn bash(log: &mut SessionLog, id: &str, cmd: &str) {
    log.append(
        Author::Model,
        Event::ToolCall(ToolCall {
            call_id: CallId::from(id),
            req_id: "r".into(),
            name: "bash".into(),
            args: json!({"command": cmd}),
            class: ToolClass::Exec,
        }),
    )
    .expect("call");
    log.append(
        Author::Tool,
        Event::ToolResult(ToolResult {
            call_id: CallId::from(id),
            name: "bash".into(),
            status: ToolStatus::Ok,
            text: String::new(),
            output: None,
            cut: false,
            class: ToolClass::Exec,
            meta: Default::default(),
            duration_ms: 1,
            images: Vec::new(),
            exchanges: Vec::new(),
        }),
    )
    .expect("result");
}

fn listing(p: &Path) -> Vec<String> {
    fn walk(p: &Path, out: &mut Vec<String>) {
        if let Ok(rd) = std::fs::read_dir(p) {
            for e in rd.filter_map(Result::ok) {
                out.push(format!("{} {}", e.path().display(), e.metadata().map(|m| m.len()).unwrap_or(0)));
                if e.path().is_dir() {
                    walk(&e.path(), out);
                }
            }
        }
    }
    let mut v = Vec::new();
    walk(p, &mut v);
    v.sort();
    v
}

fn fixture() -> Home {
    let h = home();
    let mut bad = session(&h, "s-bad", "m-bad");
    bash(&mut bad, "c1", "ps eww 42");
    bash(&mut bad, "c2", "git config --global core.fsmonitor 'sh x'");
    bash(&mut bad, "c3", "echo hello");
    let mut ok = session(&h, "s-ok", "m-ok");
    bash(&mut ok, "c1", "cargo test");
    bash(&mut ok, "c2", "ls");
    let mut mild = session(&h, "s-mild", "m-mild");
    bash(&mut mild, "c1", "nohup ./x &");
    h
}

fn tw<'a>(r: &'a ReplayReport, id: &str) -> &'a TwReport {
    r.tripwires.iter().find(|t| t.id == id).expect("tripwire")
}

#[test]
fn a_replay_reports_the_hits_per_tripwire_and_writes_nothing() {
    let h = fixture();
    let before = listing(&h.paths.home);
    let r = run(&h.paths, env_of(&h.paths), None, &ReplayOpts::default());
    assert_eq!(listing(&h.paths.home), before, "a replay changes nothing under the home");
    assert!(!h.paths.home.join("monitor").exists());
    assert_eq!((r.sessions, r.missions), (3, 3));
    assert_eq!(tw(&r, "TW-10").fired, 1);
    assert_eq!(tw(&r, "TW-09").fired, 1);
    assert_eq!(tw(&r, "TW-11").fired, 1, "the detachment is S2");
    assert_eq!(r.tripwires.len(), 28);
    assert_eq!(tw(&r, "TW-10").would_pause_missions, 1);
    assert_eq!(tw(&r, "TW-11").would_pause_missions, 0, "an S2 does not pause");
    assert_eq!(tw(&r, "TW-10").start, "precision");
    assert_eq!(tw(&r, "TW-10").precision_list_hits, 1);
}

#[test]
fn the_would_be_pauses_and_the_active_hours_are_counted() {
    let h = fixture();
    let r = run(&h.paths, env_of(&h.paths), None, &ReplayOpts::default());
    assert_eq!(r.would_be_pauses, 2, "ps eww and the global git config are two flags of S3");
    assert_eq!(r.missions_that_would_pause, 1);
    assert_eq!(r.missions_paused_by_the_precision_list, 1, "both are on the precision list");
    assert!(r.active_hours >= 0.0);
    let lines = r.lines().join("\n");
    assert!(
        lines.contains("would-be pauses") && lines.contains("TW-10") && lines.contains("gate: not built"),
        "{lines}"
    );
    assert!(r.notes.iter().any(|n| n.contains("Every cause is shadow")));
    assert!(r.notes.iter().any(|n| n.contains("without the journal key")), "{:?}", r.notes);
}

#[test]
fn precision_and_recall_against_known_positives() {
    let h = fixture();
    let opts =
        ReplayOpts { since_ms: None, positives: [MissionId::from("m-bad"), MissionId::from("m-never-seen")].into() };
    let r = run(&h.paths, env_of(&h.paths), None, &opts);
    let t = tw(&r, "TW-10");
    assert_eq!(t.precision_vs_positives, Some(1.0), "the one mission it fired in is a positive");
    assert_eq!(t.recall_vs_positives, Some(0.5), "one of two positives");
    assert_eq!((r.positives, r.positives_caught), (2, 1));
    let none = tw(&r, "TW-26");
    assert_eq!(none.precision_vs_positives, None, "a tripwire that never fired has no precision");
    assert_eq!(none.recall_vs_positives, Some(0.0));
    let plain = run(&h.paths, env_of(&h.paths), None, &ReplayOpts::default());
    assert!(tw(&plain, "TW-10").precision_vs_positives.is_none() && tw(&plain, "TW-10").recall_vs_positives.is_none());
}

#[test]
fn precision_from_the_operators_dispositions() {
    let h = fixture();
    let dir = h.paths.home.join("monitor");
    std::fs::create_dir_all(&dir).expect("dir");
    let line = |v: serde_json::Value| format!("{v}\n");
    let mut text = String::new();
    for (i, d) in ["confirm", "false_positive", "false_positive", "confirm"].iter().enumerate() {
        text += &line(
            json!({"seq": i * 2 + 1, "ts_ms": 1, "prev": "", "mac": "", "kind": "flag", "flag": format!("f-{i}"), "causes": ["TW-09"], "mission": "m", "state": "open"}),
        );
        text += &line(
            json!({"seq": i * 2 + 2, "ts_ms": 1, "prev": "", "mac": "", "kind": "disposition", "flag": format!("f-{i}"), "disposition": d}),
        );
    }
    std::fs::write(dir.join("log.jsonl"), text).expect("log");
    let r = run(&h.paths, env_of(&h.paths), None, &ReplayOpts::default());
    let t = tw(&r, "TW-09");
    assert_eq!((t.precision_from_dispositions, t.disposed), (Some(0.5), 4));
    assert_eq!(tw(&r, "TW-10").precision_from_dispositions, None);
}

#[test]
fn the_grant_in_force_at_the_time_is_the_one_that_counts() {
    let h = home();
    let key = vec![3u8; 32];
    let m = MissionId::from("m-1");
    let who = SessionId::from("s-1");
    let mut s = session(&h, "s-1", "m-1");
    bash(&mut s, "c1", "curl https://late.example/x");
    let net = |ts: u64| {
        let w = ferret_net::netlog::NetLogWriter::new();
        let e = crate::runtime::NetEntry {
            ts_ms: ts,
            decision: NetDecision {
                host: "late.example".into(),
                port: 443,
                method: "CONNECT".into(),
                allowed: false,
                rule: "default deny".into(),
                resolved: None,
                sni: None,
                paced_ms: None,
            },
        };
        w.append(&h.paths.sessions_dir().join("s-1").join("net.jsonl"), &e).expect("net");
    };
    net(ferret_core::now_ms());
    std::thread::sleep(std::time::Duration::from_millis(40));
    std::fs::create_dir_all(h.paths.mission_dir(&m)).expect("dir");
    let j = ferret_core::journal::Journal::new(h.paths.journal(&m), key.clone());
    j.append(&who, true, ferret_core::ledger::LedgerOp::GoalSet { text: "g".into() }, &|_| Ok(())).expect("goal");
    j.append(
        &who,
        true,
        ferret_core::ledger::LedgerOp::ScopeGrant { hosts: vec!["late.example".into()], note: None },
        &|_| Ok(()),
    )
    .expect("grant");
    std::thread::sleep(std::time::Duration::from_millis(40));
    bash(&mut s, "c2", "curl https://late.example/y");
    net(ferret_core::now_ms());
    let r = run(&h.paths, env_of(&h.paths), Some(key), &ReplayOpts::default());
    assert!(r.ledgers_verified);
    assert_eq!(tw(&r, "TW-01").fired, 1, "the refusal before the grant is a hit; the one after it is not");
    assert!(!r.notes.iter().any(|n| n.contains("without the journal key")));
}

#[test]
fn since_keeps_only_the_recent_hits() {
    let h = fixture();
    let far = ferret_core::now_ms() + 3_600_000;
    let r = run(&h.paths, env_of(&h.paths), None, &ReplayOpts { since_ms: Some(far), positives: Default::default() });
    assert!(r.tripwires.iter().all(|t| t.fired == 0));
    assert_eq!(r.would_be_pauses, 0);
}

#[test]
fn the_report_round_trips_as_json() {
    let h = fixture();
    let r = run(&h.paths, env_of(&h.paths), None, &ReplayOpts::default());
    let text = serde_json::to_string(&r).expect("ser");
    let back: ReplayReport = serde_json::from_str(&text).expect("de");
    assert_eq!(serde_json::to_string(&back).expect("ser"), text);
    assert_eq!(back.tripwires, r.tripwires);
}

#[test]
fn a_larger_home_replays_in_reasonable_time() {
    let h = home();
    for s in 0..40 {
        let mut log = session(&h, &format!("s-{s}"), &format!("m-{}", s % 8));
        for i in 0..120 {
            let cmd = if i % 60 == 7 { "ps eww 1".to_string() } else { format!("echo step {i}") };
            bash(&mut log, &format!("c{i}"), &cmd);
        }
    }
    let t0 = std::time::Instant::now();
    let r = run(&h.paths, env_of(&h.paths), None, &ReplayOpts::default());
    assert!(t0.elapsed() < std::time::Duration::from_secs(20), "{:?}", t0.elapsed());
    assert_eq!((r.sessions, r.missions, r.records), (40, 8, 40 * (1 + 120 * 2)));
    assert_eq!(tw(&r, "TW-10").missions, 8);
}
