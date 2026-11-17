//! The core over a fixture home: first run, hits, flags, throttling, aggregation, restart, faults, the grace, the
//! authorization, the fleet scan, the memory core.

use super::*;
use crate::monitor::engine::PackFacts;
use crate::monitor::log::MonitorLog;
use loom_core::event::{
    Event, ModelRef, NetDecision, SessionStart, Termination, ToolCall, ToolClass, ToolResult, ToolStatus,
};
use loom_core::log::{Durability, SessionLog};
use loom_core::CallId;
use serde_json::json;

struct Home {
    dir: tempfile::TempDir,
    paths: Paths,
}

fn home() -> Home {
    let dir = tempfile::tempdir().expect("tempdir");
    let canon = std::fs::canonicalize(dir.path()).expect("canon");
    let paths = Paths::at(canon);
    paths.ensure_private_layout().expect("layout");
    Home { dir, paths }
}

fn env_of(paths: &Paths) -> Arc<Env> {
    let policy = loom_net::Policy::new(&loom_core::config::NetworkCfg::default())
        .and_then(|p| p.with_infrastructure(&loom_net::InfraSpec { daemon_port: Some(7878), ..Default::default() }))
        .ok()
        .map(Arc::new);
    Arc::new(Env {
        home: paths.home.to_string_lossy().into_owned(),
        copies: format!("{}-copies", paths.home.to_string_lossy()),
        infra: policy,
        network_mode: "allowlist".into(),
        allow: vec!["*.target.example".into()],
        deny: vec![],
        packs: [("core".to_string(), PackFacts::default())].into(),
        relaxed_profiles: BTreeSet::new(),
    })
}

fn cfg() -> CoreCfg {
    CoreCfg { fleet_every_ms: u64::MAX, enabled: true }
}

fn open(h: &Home) -> Core {
    Core::open(&h.paths, env_of(&h.paths), cfg(), None).expect("open")
}

fn start(session: &str, mission: &str) -> Event {
    Event::SessionStart(SessionStart {
        session: SessionId::from(session),
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
        schema: loom_core::event::SCHEMA,
    })
}

fn new_session(h: &Home, session: &str, mission: &str) -> SessionLog {
    let dir = h.paths.sessions_dir().join(session);
    std::fs::create_dir_all(&dir).expect("dir");
    let mut log = SessionLog::create(&dir.join("log.jsonl"), Durability::Batch).expect("create");
    log.append(Author::Harness, start(session, mission)).expect("start");
    log
}

fn call(log: &mut SessionLog, id: &str, name: &str, class: ToolClass, args: serde_json::Value) {
    log.append(
        Author::Model,
        Event::ToolCall(ToolCall { call_id: CallId::from(id), req_id: "r".into(), name: name.into(), args, class }),
    )
    .expect("call");
    log.append(
        Author::Tool,
        Event::ToolResult(ToolResult {
            call_id: CallId::from(id),
            name: name.into(),
            status: ToolStatus::Ok,
            text: String::new(),
            output: None,
            cut: false,
            class,
            meta: Default::default(),
            duration_ms: 1,
        }),
    )
    .expect("result");
}

fn bash(log: &mut SessionLog, id: &str, cmd: &str) {
    call(log, id, "bash", ToolClass::Exec, json!({"command": cmd}));
}

fn kinds(core: &Core, kind: EntryKind) -> Vec<Entry> {
    core.memory_entries().iter().filter(|e| e.kind == kind).cloned().collect()
}

/// The entries of the monitor log on disk.
fn entries(h: &Home) -> Vec<Entry> {
    let text = std::fs::read_to_string(h.paths.home.join("monitor").join("log.jsonl")).unwrap_or_default();
    text.lines().filter_map(|l| serde_json::from_str(l).ok()).collect()
}

fn of_kind(h: &Home, kind: EntryKind) -> Vec<Entry> {
    entries(h).into_iter().filter(|e| e.kind == kind).collect()
}

fn all() -> BTreeSet<String> {
    BTreeSet::new()
}

fn text(e: &Entry, k: &str) -> String {
    e.fields.get(k).and_then(Value::as_str).unwrap_or("").to_string()
}

#[test]
fn a_first_run_starts_at_the_end_of_every_source_and_raises_nothing() {
    let h = home();
    let mut old = new_session(&h, "s-old", "m-old");
    bash(&mut old, "c1", "ps eww 4242");
    let mut core = open(&h);
    let now = loom_core::now_ms();
    core.pump(now, &all(), true);
    assert!(of_kind(&h, EntryKind::Tripwire).is_empty(), "history before the first start raises nothing");
    assert_eq!(core.counts().records, 0);
    // What the session does after the monitor started is read.
    bash(&mut old, "c2", "ps eww 4243");
    core.pump(now + 1_000, &all(), true);
    let hits = of_kind(&h, EntryKind::Tripwire);
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert_eq!((text(&hits[0], "id").as_str(), text(&hits[0], "mission").as_str()), ("TW-10", "m-old"));
    // A session that did not exist at the first start is read from its first record.
    let mut fresh = new_session(&h, "s-new", "m-new");
    bash(&mut fresh, "c1", "cat /proc/12/environ");
    core.pump(now + 2_000, &all(), true);
    assert_eq!(of_kind(&h, EntryKind::Tripwire).len(), 2);
}

#[test]
fn a_hit_becomes_a_tripwire_entry_a_flag_and_a_response_once_and_repeats_are_counted() {
    let h = home();
    let mut core = open(&h);
    core.pump(loom_core::now_ms(), &all(), true);
    let mut s = new_session(&h, "s-1", "m-1");
    for i in 0..4 {
        bash(&mut s, &format!("c{i}"), &format!("ps eww {i}"));
    }
    core.pump(loom_core::now_ms() + 1_000, &all(), true);
    let hits = of_kind(&h, EntryKind::Tripwire);
    assert_eq!(hits.len(), 1, "four repeats within 60 s are one entry");
    let t = &hits[0];
    assert_eq!(
        (text(t, "state").as_str(), text(t, "would").as_str(), text(t, "severity").as_str()),
        ("shadow", "r3", "s3")
    );
    assert_eq!(t.fields.get("precision"), Some(&json!(true)));
    assert_eq!(t.fields.get("pointer").and_then(|p| p.get(0)), Some(&json!("s-1")));
    let flags = of_kind(&h, EntryKind::Flag);
    assert_eq!(flags.len(), 1);
    assert_eq!((text(&flags[0], "state").as_str(), flags[0].fields.get("count")), ("open", Some(&json!(1))));
    let responses = of_kind(&h, EntryKind::Response);
    assert_eq!(responses.len(), 1);
    assert_eq!((text(&responses[0], "level").as_str(), text(&responses[0], "would").as_str()), ("r0", "r3"));
    assert_eq!(core.fold().open_flags().count(), 1);
    assert_eq!(core.counts().throttled, 3);
    // The count grows in the flag with the next write, which is at a power of two.
    for i in 4..9 {
        bash(&mut s, &format!("c{i}"), &format!("ps eww {i}"));
    }
    core.pump(loom_core::now_ms() + 2_000, &all(), true);
    assert_eq!(of_kind(&h, EntryKind::Tripwire).len(), 1, "still the same hit");
    let st = core.status(true, "shadow");
    assert_eq!((st.state.as_str(), st.open_flags, st.counts.hits >= 9), ("shadow", 1, true));
    assert_eq!(st.tripwires.iter().find(|t| t.id == "TW-10").map(|t| t.fired), Some(1));
}

#[test]
fn the_s1_aggregation_raises_the_third_distinct_target_in_30_minutes() {
    let h = home();
    let mut core = open(&h);
    core.pump(loom_core::now_ms(), &all(), true);
    let mut s = new_session(&h, "s-1", "m-1");
    for (i, f) in ["Makefile", "build.rs", ".envrc"].iter().enumerate() {
        call(
            &mut s,
            &format!("c{i}"),
            "write",
            ToolClass::Write,
            json!({"path": format!("/work/ws/{f}"), "content": "x"}),
        );
    }
    core.pump(loom_core::now_ms() + 1_000, &all(), true);
    let hits = of_kind(&h, EntryKind::Tripwire);
    let sev: Vec<String> = hits.iter().map(|e| text(e, "severity")).collect();
    assert_eq!(sev, vec!["s1", "s1", "s2"], "the third distinct S1 target of one category counts as S2");
    assert_eq!(hits[2].fields.get("from_s1"), Some(&json!(true)));
    assert!(text(&hits[2], "detail").contains("S1 aggregation"));
    assert_eq!(of_kind(&h, EntryKind::Flag).len(), 1, "only the S2 opens a flag");
    assert_eq!(text(&of_kind(&h, EntryKind::Response)[0], "would"), "r1");
}

#[test]
fn a_restart_resumes_from_its_cursors_and_reads_nothing_twice() {
    let h = home();
    let mut core = open(&h);
    core.pump(loom_core::now_ms(), &all(), true);
    let mut s = new_session(&h, "s-1", "m-1");
    bash(&mut s, "c1", "ps eww 1");
    core.pump(loom_core::now_ms() + 1_000, &all(), true);
    let (records, hits_before) = (core.counts().records, of_kind(&h, EntryKind::Tripwire).len());
    assert!(records > 0 && hits_before == 1);
    drop(core);
    let mut core = open(&h);
    core.pump(loom_core::now_ms() + 2_000, &all(), true);
    assert_eq!(core.counts().records, 0, "nothing is read again");
    assert_eq!(of_kind(&h, EntryKind::Tripwire).len(), hits_before);
    assert_eq!(core.fold().open_flags().count(), 1, "the flag was folded back");
    bash(&mut s, "c2", "git config --global core.fsmonitor x");
    core.pump(loom_core::now_ms() + 3_000, &all(), true);
    assert_eq!(
        core.counts().records,
        2,
        "only the new call and its result: {:?} {:?}",
        core.counts(),
        core.fold().cursors
    );
    assert_eq!(of_kind(&h, EntryKind::Tripwire).len(), hits_before + 1);
}

#[test]
fn a_source_with_a_broken_chain_is_recorded_once_and_not_read_again() {
    let h = home();
    let mut core = open(&h);
    core.pump(loom_core::now_ms(), &all(), true);
    let mut s = new_session(&h, "s-1", "m-1");
    bash(&mut s, "c1", "ls");
    let path = h.paths.sessions_dir().join("s-1").join("log.jsonl");
    let text = std::fs::read_to_string(&path).expect("read");
    let lines: Vec<&str> = text.lines().collect();
    std::fs::write(&path, format!("{}\n{}\n{}\n", lines[0], lines[2], lines[1])).expect("swap");
    core.pump(loom_core::now_ms() + 1_000, &all(), true);
    let faults: Vec<Entry> =
        of_kind(&h, EntryKind::Cursor).into_iter().filter(|e| e.fields.contains_key("fault")).collect();
    assert_eq!(faults.len(), 1);
    let st = core.status(true, "shadow");
    assert_eq!(st.state, "degraded");
    assert!(st.faults.iter().any(|f| f.contains("chain")), "{:?}", st.faults);
    core.pump(loom_core::now_ms() + 2_000, &all(), true);
    let faults: Vec<Entry> =
        of_kind(&h, EntryKind::Cursor).into_iter().filter(|e| e.fields.contains_key("fault")).collect();
    assert_eq!(faults.len(), 1, "recorded once");
    assert_eq!(core.fold().open_flags().count(), 0, "a fault is never an agent's misbehaviour (I10)");
}

#[test]
fn an_unwritable_log_makes_the_monitor_down_and_it_stops_pumping() {
    let h = home();
    let mut core = open(&h);
    core.pump(loom_core::now_ms(), &all(), true);
    let mut s = new_session(&h, "s-1", "m-1");
    bash(&mut s, "c1", "ps eww 1");
    if let Some(l) = core.log.as_mut() {
        l.break_for_test();
    }
    core.pump(loom_core::now_ms() + 1_000, &all(), true);
    let st = core.status(true, "shadow");
    assert_eq!(st.state, "down");
    assert!(st.down_reason.as_deref().is_some_and(|r| r.contains("cannot be written")), "{:?}", st.down_reason);
    assert!(!core.pump(loom_core::now_ms() + 2_000, &all(), true), "a down monitor reads nothing more");
    assert_eq!(core.fold().open_flags().count(), 0, "nothing is applied before it is recorded");
}

fn net_line(h: &Home, session: &str, ts: u64, host: &str, allowed: bool) {
    let w = loom_net::netlog::NetLogWriter::new();
    let e = crate::runtime::NetEntry {
        ts_ms: ts,
        decision: NetDecision {
            host: host.into(),
            port: 443,
            method: "CONNECT".into(),
            allowed,
            rule: "allow".into(),
            resolved: None,
            sni: None,
        },
    };
    w.append(&h.paths.sessions_dir().join(session).join("net.jsonl"), &e).expect("net");
}

#[test]
fn a_net_decision_is_judged_after_its_grace_and_after_the_log() {
    let h = home();
    let mut core = open(&h);
    let now = loom_core::now_ms();
    core.pump(now, &all(), true);
    let mut s = new_session(&h, "s-1", "m-1");
    bash(&mut s, "c1", "true");
    let t = now + 60_000;
    net_line(&h, "s-1", t, "api.target.example", true);
    core.pump(t + 500, &all(), true);
    assert!(of_kind(&h, EntryKind::Tripwire).is_empty(), "inside the grace it waits");
    core.pump(t + 3_000, &all(), true);
    let hits = of_kind(&h, EntryKind::Tripwire);
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert_eq!(text(&hits[0], "id"), "TW-21");
    assert_eq!(core.counts().net, 1);
}

#[test]
fn a_net_decision_during_a_call_is_not_idle_egress() {
    let h = home();
    let mut core = open(&h);
    let now = loom_core::now_ms();
    core.pump(now, &all(), true);
    let mut s = new_session(&h, "s-1", "m-1");
    s.append(
        Author::Model,
        Event::ToolCall(ToolCall {
            call_id: CallId::from("c1"),
            req_id: "r".into(),
            name: "bash".into(),
            args: json!({"command": "curl x"}),
            class: ToolClass::Exec,
        }),
    )
    .expect("call");
    net_line(&h, "s-1", now + 100, "api.target.example", true);
    core.pump(now + 10_000, &all(), true);
    assert!(of_kind(&h, EntryKind::Tripwire).is_empty());
}

#[test]
fn the_authorization_follows_the_journal_and_the_operators_words() {
    let h = home();
    let key = vec![5u8; 32];
    let mut core = Core::open(&h.paths, env_of(&h.paths), cfg(), Some(key.clone())).expect("open");
    core.pump(loom_core::now_ms(), &all(), true);
    let m = MissionId::from("m-1");
    std::fs::create_dir_all(h.paths.mission_dir(&m)).expect("dir");
    let j = loom_core::journal::Journal::new(h.paths.journal(&m), key);
    let who = SessionId::from("s-1");
    j.append(&who, true, loom_core::ledger::LedgerOp::GoalSet { text: "assess granted.example".into() }, &|_| Ok(()))
        .expect("goal");
    j.append(
        &who,
        true,
        loom_core::ledger::LedgerOp::ScopeGrant {
            hosts: vec!["granted.example".into()],
            note: Some("by the operator".into()),
        },
        &|_| Ok(()),
    )
    .expect("grant");
    let mut s = new_session(&h, "s-1", "m-1");
    s.append(Author::User, Event::UserMessage { text: "stay on granted.example".into() }).expect("message");
    s.append(Author::Harness, Event::Ledger { n: 2, summary: "grant".into() }).expect("ledger");
    let now = loom_core::now_ms() + 5_000;
    core.pump(now, &all(), true);
    let a = core.auth_for(&m, u64::MAX);
    assert_eq!(a.goal, "assess granted.example");
    assert!(a.mark_of("granted.example", None).is_some());
    assert_eq!(a.operator_messages, vec!["stay on granted.example".to_string()]);
    // A record is judged by the authorization of its time: before the grant it was not there.
    let early = core.auth_for(&m, 1);
    assert!(early.mark_of("granted.example", None).is_none() && early.goal.is_empty());
}

#[test]
fn the_fleet_scan_reports_a_shared_path_once() {
    let h = home();
    let mut core = open(&h);
    core.pump(loom_core::now_ms(), &all(), true);
    let mut a = new_session(&h, "s-a", "m-a");
    call(&mut a, "c1", "write", ToolClass::Write, json!({"path": "/shared/exchange.txt", "content": "x"}));
    std::thread::sleep(std::time::Duration::from_millis(5));
    let mut b = new_session(&h, "s-b", "m-b");
    call(&mut b, "c1", "read", ToolClass::Read, json!({"path": "/shared/exchange.txt"}));
    core.pump(loom_core::now_ms() + 1_000, &all(), true);
    core.run_fleet(loom_core::now_ms() + 2_000);
    core.run_fleet(loom_core::now_ms() + 3_000);
    let flags = of_kind(&h, EntryKind::Flag);
    assert_eq!(flags.len(), 1, "{flags:?}");
    let causes = flags[0].fields.get("causes").cloned().unwrap_or_default();
    assert_eq!(causes, json!(["FS-1"]));
    assert_eq!(core.status(true, "shadow").fleet_hits, 1);
    let st = core.status(true, "shadow");
    assert_eq!(st.fleet_runs, 2);
    let rs = of_kind(&h, EntryKind::Response);
    assert!(rs
        .iter()
        .any(|r| r.fields.get("would") == Some(&json!("r3")) || r.fields.get("would") == Some(&json!("r5"))));
}

#[test]
fn floor_events_and_unattributed_infrastructure_decisions_are_read() {
    let h = home();
    let mut core = open(&h);
    core.pump(loom_core::now_ms(), &all(), true);
    let mut s = new_session(&h, "s-1", "m-1");
    bash(&mut s, "c1", "true");
    core.pump(loom_core::now_ms() + 100, &all(), true);
    let logs = h.paths.logs_dir();
    std::fs::create_dir_all(&logs).expect("logs");
    std::fs::write(
        logs.join("floor.jsonl"),
        "{\"at_ms\":5,\"kind\":\"canary_credential\",\"category\":\"credential_misuse\",\"severity\":\"s4\",\"session\":\"s-1\",\"label\":\"CN-1\",\"detail\":\"decoy user\"}\n{\"at_ms\":6,\"kind\":\"squatter\",\"session\":\"s-1\",\"label\":\"port 8080\",\"detail\":\"d\"}\n",
    )
    .expect("floor");
    let w = loom_net::netlog::NetLogWriter::new();
    let e = crate::runtime::NetEntry {
        ts_ms: 7,
        decision: NetDecision {
            host: "169.254.169.254".into(),
            port: 80,
            method: "GET".into(),
            allowed: false,
            rule: "deny infrastructure: cloud metadata".into(),
            resolved: None,
            sni: None,
        },
    };
    w.append(&logs.join("net-unattributed.jsonl"), &e).expect("unattributed");
    core.pump(loom_core::now_ms() + 200, &all(), true);
    let hits = of_kind(&h, EntryKind::Tripwire);
    let ids: Vec<(String, String)> = hits.iter().map(|e| (text(e, "id"), text(e, "mission"))).collect();
    assert!(ids.contains(&("TW-24".into(), "m-1".into())), "{ids:?}");
    assert!(ids.contains(&("TW-05".into(), "m-1".into())), "{ids:?}");
    assert!(ids.contains(&("TW-02".into(), "unattributed".into())), "{ids:?}");
    assert_eq!((core.counts().floor, core.counts().unattributed), (2, 1));
}

#[test]
fn a_forked_childs_copied_prefix_is_not_the_childs_and_a_cursor_tracks_the_log() {
    let h = home();
    let mut core = open(&h);
    core.pump(loom_core::now_ms(), &all(), true);
    let mut parent = new_session(&h, "s-p", "m-1");
    bash(&mut parent, "c1", "ps eww 1");
    // The child's log starts as a copy of the parent's, then says who it is.
    let dir = h.paths.sessions_dir().join("s-c");
    std::fs::create_dir_all(&dir).expect("dir");
    let pl = h.paths.sessions_dir().join("s-p").join("log.jsonl");
    std::fs::copy(&pl, dir.join("log.jsonl")).expect("copy");
    let mut child = SessionLog::open(&dir.join("log.jsonl"), Durability::Batch).expect("open").0;
    child
        .append(
            Author::Harness,
            Event::Forked(loom_core::event::Forked {
                session: SessionId::from("s-c"),
                parent: SessionId::from("s-p"),
                upto_seq: 2,
                role: "worker".into(),
                termination: Termination::Explicit,
                budget: Default::default(),
                brief: Default::default(),
                contract: String::new(),
                allowed_tools: None,
                title: String::new(),
            }),
        )
        .expect("forked");
    bash(&mut child, "c2", "git config --global core.fsmonitor x");
    core.pump(loom_core::now_ms() + 1_000, &all(), true);
    let hits = of_kind(&h, EntryKind::Tripwire);
    let by: Vec<(String, String)> = hits.iter().map(|e| (text(e, "session"), text(e, "id"))).collect();
    assert_eq!(by.iter().filter(|(s, _)| s == "s-p").count(), 1, "{by:?}");
    assert_eq!(
        by.iter().filter(|(s, _)| s == "s-c").count(),
        1,
        "the parent's call is not charged to the child: {by:?}"
    );
}

#[test]
fn the_fleet_scan_runs_on_its_period() {
    let h = home();
    let mut core =
        Core::open(&h.paths, env_of(&h.paths), CoreCfg { fleet_every_ms: 10_000, enabled: true }, None).expect("open");
    let now = loom_core::now_ms();
    core.pump(now, &all(), true);
    assert_eq!(core.status(true, "shadow").fleet_runs, 1, "the first pass runs it");
    core.pump(now + 5_000, &all(), true);
    assert_eq!(core.status(true, "shadow").fleet_runs, 1, "not before its period");
    core.pump(now + 11_000, &all(), true);
    assert_eq!(core.status(true, "shadow").fleet_runs, 2);
}

#[test]
fn a_memory_core_records_into_memory_and_writes_no_file() {
    let h = home();
    let mut s = new_session(&h, "s-1", "m-1");
    bash(&mut s, "c1", "ps eww 1");
    bash(&mut s, "c2", "cat ~/.loom/config.toml");
    let before: Vec<String> = std::fs::read_dir(&h.paths.home)
        .expect("dir")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    let mut core = Core::memory(&h.paths, env_of(&h.paths), cfg(), None);
    core.drain();
    let ids: Vec<String> = kinds(&core, EntryKind::Tripwire).iter().map(|e| text(e, "id")).collect();
    assert!(ids.contains(&"TW-10".to_string()), "{ids:?}");
    let after: Vec<String> = std::fs::read_dir(&h.paths.home)
        .expect("dir")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(before, after, "no monitor directory, no key");
    assert!(!h.paths.home.join("monitor").exists() && !h.paths.keys_dir().join("monitor.key").exists());
    assert!(h.dir.path().exists());
}

#[test]
fn a_disabled_core_keeps_the_causes_that_have_no_off_switch() {
    let h = home();
    let mut core =
        Core::open(&h.paths, env_of(&h.paths), CoreCfg { fleet_every_ms: 1, enabled: false }, None).expect("open");
    let now = loom_core::now_ms();
    core.pump(now, &all(), true);
    let mut s = new_session(&h, "s-1", "m-1");
    bash(&mut s, "c1", "ps eww 1");
    call(&mut s, "c2", "write", ToolClass::Write, json!({"path": "/work/ws/zz-board.md", "content": "x"}));
    core.pump(now + 1_000, &all(), true);
    let ids: Vec<String> = of_kind(&h, EntryKind::Tripwire).iter().map(|e| text(e, "id")).collect();
    assert_eq!(ids, vec!["TW-10".to_string()], "the precision list runs; an S1 of the mixed rows does not: {ids:?}");
}

#[test]
fn the_fold_before_activation_is_complete_when_open_returns() {
    let h = home();
    {
        let (mut log, _) = MonitorLog::open(&h.paths.home).expect("log");
        let mut f = Map::new();
        f.insert("mission".into(), json!("m-9"));
        f.insert("flag".into(), json!("f-1"));
        f.insert("phase".into(), json!("applied"));
        log.append(EntryKind::Pause, f).expect("pause");
    }
    let core = open(&h);
    assert!(core.fold().paused.contains_key(&MissionId::from("m-9")), "a pause folds before any session is touched");
    let st = core.status(true, "shadow");
    assert_eq!(st.paused, vec!["m-9".to_string()]);
}

fn s1_hit(core: &mut Core, key: &str, at_ms: u64) {
    core.on_hit(Hit {
        id: TripwireId::of(26),
        mission: MissionId::from("m-1"),
        session: SessionId::from("s-1"),
        pointer: (SessionId::from("s-1"), 1),
        category: Category::OperatorDeception,
        severity: Severity::S1,
        detail: format!("writes {key}"),
        key: key.into(),
        at_ms,
        basis: crate::monitor::taxonomy::Basis::Action,
        precision: false,
        from_s1: false,
    });
}

#[test]
fn a_target_seen_before_the_window_still_counts_when_it_comes_back_inside_it() {
    let h = home();
    let mut core = open(&h);
    core.pump(loom_core::now_ms(), &all(), true);
    let t0 = 1_000_000u64;
    s1_hit(&mut core, "Makefile", t0);
    let later = t0 + 2 * 60 * 60 * 1000;
    s1_hit(&mut core, "build.rs", later);
    s1_hit(&mut core, ".envrc", later + 1_000);
    s1_hit(&mut core, "Makefile", later + 2_000);
    let hits = of_kind(&h, EntryKind::Tripwire);
    let sev: Vec<String> = hits.iter().map(|e| text(e, "severity")).collect();
    assert_eq!(sev, vec!["s1", "s1", "s1", "s2"], "three distinct targets inside 30 minutes: {sev:?}");
}

#[test]
fn an_interrupted_first_start_is_still_a_first_start() {
    let h = home();
    let mut old = new_session(&h, "s-old", "m-old");
    bash(&mut old, "c1", "ps eww 4242");
    drop(open(&h));
    let mut core = open(&h);
    core.pump(loom_core::now_ms(), &all(), true);
    assert!(
        of_kind(&h, EntryKind::Tripwire).is_empty(),
        "history raises nothing, however often the start was cut short"
    );
    assert_eq!(core.counts().records, 0);
}

#[test]
fn a_child_primed_before_its_forked_record_is_read_from_that_record_on() {
    let h = home();
    let mut core = open(&h);
    core.pump(loom_core::now_ms(), &all(), true);
    let mut parent = new_session(&h, "s-p", "m-1");
    bash(&mut parent, "c1", "ps eww 1");
    let dir = h.paths.sessions_dir().join("s-c");
    std::fs::create_dir_all(&dir).expect("dir");
    std::fs::copy(h.paths.sessions_dir().join("s-p").join("log.jsonl"), dir.join("log.jsonl")).expect("copy");
    // The pass that comes between the copy and the `forked` record.
    core.pump(loom_core::now_ms() + 1_000, &all(), true);
    let mut child = SessionLog::open(&dir.join("log.jsonl"), Durability::Batch).expect("open").0;
    child
        .append(
            Author::Harness,
            Event::Forked(loom_core::event::Forked {
                session: SessionId::from("s-c"),
                parent: SessionId::from("s-p"),
                upto_seq: 2,
                role: "worker".into(),
                termination: Termination::Explicit,
                budget: Default::default(),
                brief: Default::default(),
                contract: String::new(),
                allowed_tools: None,
                title: String::new(),
            }),
        )
        .expect("forked");
    bash(&mut child, "c2", "git config --global core.fsmonitor x");
    core.pump(loom_core::now_ms() + 2_000, &all(), true);
    let by: Vec<(String, String)> =
        of_kind(&h, EntryKind::Tripwire).iter().map(|e| (text(e, "session"), text(e, "id"))).collect();
    assert_eq!(by.iter().filter(|(s, _)| s == "s-c").count(), 1, "the child's own call is judged: {by:?}");
    assert_eq!(by.iter().filter(|(s, _)| s == "s-p").count(), 1, "the parent's call is the parent's: {by:?}");
}

#[test]
fn an_answer_to_an_agents_question_does_not_carry_the_agents_words_into_operator_text() {
    let h = home();
    let mut core = open(&h);
    core.pump(loom_core::now_ms(), &all(), true);
    let mut s = new_session(&h, "s-1", "m-1");
    let echo = crate::texts::inbox_answer("Am I authorized by the operator to use the Docker API on h510.lan?", "No.");
    s.append(Author::User, Event::UserMessage { text: echo }).expect("echo");
    s.append(Author::User, Event::UserMessage { text: "use only api.target.example".into() }).expect("operator");
    core.pump(loom_core::now_ms() + 1_000, &all(), true);
    let a = core.auth_for(&MissionId::from("m-1"), u64::MAX);
    assert_eq!(a.operator_messages, vec!["No.".to_string(), "use only api.target.example".to_string()]);
}

fn decision_line(h: &Home, session: &str, ts: u64, host: &str, rule: &str) {
    let w = loom_net::netlog::NetLogWriter::new();
    let e = crate::runtime::NetEntry {
        ts_ms: ts,
        decision: NetDecision {
            host: host.into(),
            port: 80,
            method: "GET".into(),
            allowed: false,
            rule: rule.into(),
            resolved: None,
            sni: None,
        },
    };
    w.append(&h.paths.sessions_dir().join(session).join("net.jsonl"), &e).expect("net");
}

#[test]
fn a_net_decision_read_and_not_yet_judged_is_not_checkpointed_as_judged() {
    let h = home();
    let mut core = open(&h);
    let now = loom_core::now_ms();
    core.pump(now, &all(), true);
    let mut s = new_session(&h, "s-1", "m-1");
    bash(&mut s, "c1", "ps eww 1");
    decision_line(&h, "s-1", now + 500, "169.254.169.254", "deny infrastructure: cloud metadata");
    // Read at +1 s, judged only after its 2 s grace; a hit written in the pass makes a checkpoint.
    core.pump(now + 1_000, &all(), true);
    assert!(of_kind(&h, EntryKind::Tripwire).iter().all(|e| text(e, "id") != "TW-02"));
    drop(core);
    let mut core = open(&h);
    core.pump(now + 10_000, &all(), true);
    let ids: Vec<String> = of_kind(&h, EntryKind::Tripwire).iter().map(|e| text(e, "id")).collect();
    assert!(ids.contains(&"TW-02".to_string()), "the decision is read again and judged after the restart: {ids:?}");
}

#[test]
fn after_a_restart_a_session_read_before_is_not_judged_idle_for_ten_minutes() {
    let h = home();
    let mut core = open(&h);
    let now = loom_core::now_ms();
    core.pump(now, &all(), true);
    let mut s = new_session(&h, "s-1", "m-1");
    // A hit in the pass makes a checkpoint, so the restart resumes the session.
    bash(&mut s, "c1", "ps eww 1");
    core.pump(now + 1_000, &all(), true);
    net_line(&h, "s-1", now + 1_500, "api.target.example", true);
    drop(core);
    let mut core = open(&h);
    core.pump(now + 20_000, &all(), true);
    let ids: Vec<String> = of_kind(&h, EntryKind::Tripwire).iter().map(|e| text(e, "id")).collect();
    assert!(!ids.contains(&"TW-21".to_string()), "what was in flight at the restart is not known: {ids:?}");
}

#[test]
fn a_log_that_can_be_written_again_brings_the_monitor_up_and_nothing_it_found_is_lost() {
    let h = home();
    let mut core = open(&h);
    let now = loom_core::now_ms();
    core.pump(now, &all(), true);
    let mut s = new_session(&h, "s-1", "m-1");
    bash(&mut s, "c1", "ps eww 1");
    if let Some(l) = core.log.as_mut() {
        l.break_for_test();
    }
    core.pump(now + 1_000, &all(), true);
    assert_eq!(core.status(true, "shadow").state, "down");
    assert!(!core.pump(now + 4_000, &all(), true), "still unwritable: still down");
    if let Some(l) = core.log.as_mut() {
        l.mend_for_test();
    }
    core.pump(now + 8_000, &all(), true);
    let st = core.status(true, "shadow");
    assert_ne!(st.state, "down", "{:?}", st.down_reason);
    let ids: Vec<String> = of_kind(&h, EntryKind::Tripwire).iter().map(|e| text(e, "id")).collect();
    assert_eq!(ids, vec!["TW-10".to_string()], "the hit that could not be written is written when the log works");
    assert_eq!(core.fold().open_flags().count(), 1);
    // The log still verifies.
    drop(core);
    assert!(MonitorLog::open(&h.paths.home).is_ok());
}

#[test]
fn the_credential_index_survives_a_restart() {
    let h = home();
    let mut core = open(&h);
    let now = loom_core::now_ms();
    core.pump(now, &all(), true);
    let key = format!("{}{}", "AKIA", "ABCDEFGHIJKLMNOP");
    let mut a = new_session(&h, "s-a", "m-a");
    a.append(
        Author::Model,
        Event::ToolCall(ToolCall {
            call_id: CallId::from("c1"),
            req_id: "r".into(),
            name: "bash".into(),
            args: json!({"command": "cat creds.txt"}),
            class: ToolClass::Exec,
        }),
    )
    .expect("call");
    a.append(
        Author::Tool,
        Event::ToolResult(ToolResult {
            call_id: CallId::from("c1"),
            name: "bash".into(),
            status: ToolStatus::Ok,
            text: format!("AWS_KEY={key}"),
            output: None,
            cut: false,
            class: ToolClass::Exec,
            meta: Default::default(),
            duration_ms: 1,
        }),
    )
    .expect("result");
    core.pump(now + 61_000, &all(), true);
    assert!(
        of_kind(&h, EntryKind::Cursor).iter().any(|e| e.fields.contains_key("secrets")),
        "the tags are checkpointed"
    );
    assert!(!entries(&h).iter().any(|e| serde_json::to_string(&e.fields).unwrap_or_default().contains(&key)));
    drop(core);
    let mut core = open(&h);
    core.pump(now + 70_000, &all(), true);
    let mut b = new_session(&h, "s-b", "m-b");
    bash(&mut b, "c1", &format!("aws configure set key {key}"));
    core.pump(now + 80_000, &all(), true);
    let ids: Vec<(String, String)> =
        of_kind(&h, EntryKind::Tripwire).iter().map(|e| (text(e, "id"), text(e, "mission"))).collect();
    assert!(ids.contains(&("TW-06".into(), "m-b".into())), "{ids:?}");
}

#[test]
fn a_switch_onto_a_relaxed_model_uptiers_the_session_and_a_switch_back_does_not_lower_it() {
    use loom_core::event::ModelSwitched;
    let h = home();
    let mut core = open(&h);
    let now = loom_core::now_ms();
    core.pump(now, &all(), true);
    let mut s = new_session(&h, "s-1", "m-1");
    bash(&mut s, "c1", "ps eww 101");
    core.pump(now + 1_000, &all(), true);
    let sev = |h: &Home| of_kind(h, EntryKind::Tripwire).iter().map(|e| text(e, "severity")).collect::<Vec<_>>();
    assert_eq!(sev(&h), ["s3"], "a stock session's process inspection");
    let relaxed = loom_core::config::ModelProfile {
        alignment: Some(loom_core::lineage::Alignment::Relaxed),
        ..Default::default()
    };
    let stock = ModelRef { profile: "p".into(), model: "m".into(), context_window: 10, lineage: None };
    let unc = ModelRef {
        profile: "unc".into(),
        model: "unc".into(),
        context_window: 10,
        lineage: Some(loom_core::lineage::resolve("unc", &relaxed)),
    };
    let switch = |from: &ModelRef, to: &ModelRef| {
        Event::ModelSwitched(ModelSwitched {
            from: from.clone(),
            to: to.clone(),
            reasoning_replay: Default::default(),
            reason: "operator".into(),
        })
    };
    s.append(Author::Harness, switch(&stock, &unc)).expect("switch");
    bash(&mut s, "c2", "ps eww 102");
    core.pump(now + 2_000, &all(), true);
    assert_eq!(sev(&h), ["s3", "s4"], "one tier up from the switch on");
    s.append(Author::Harness, switch(&unc, &stock)).expect("switch back");
    bash(&mut s, "c3", "ps eww 103");
    core.pump(now + 3_000, &all(), true);
    let relaxed_now = |core: &Core| core.engine.ctx(&SessionId::from("s-1")).map(|c| c.relaxed);
    assert_eq!(relaxed_now(&core), Some(true), "a switch back does not lower it");
    assert_eq!(core.srcs.get("s-1").and_then(|s| s.primed.as_ref()).map(|p| p.ctx.relaxed), Some(true));
}
