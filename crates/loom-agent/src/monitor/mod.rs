//! The adversarial monitor: deterministic tripwires, a cross-family reviewer, a gate for irreversible actions, a
//! durable pause, and "keep going". The specification is `docs/MONITOR.md` (overview: `docs/DESIGN.md` §15); this
//! comment and the comments of the submodules are its precise form. When they disagree, one of them is a bug.
//!
//! CONTRACT.
//!
//! ## Status
//! Phases P0, M1 and M2 (this tree): the vocabulary (`taxonomy`), the record and log shapes (`log`), the tripwire table
//! (`tripwire`) and the functions behind it (`engine`, `patterns`), the cursors over the durable sources (`source`),
//! the core that runs them (`core`), the fleet joins (`fleet`), the replay (`replay`), the gated classes (`classify`),
//! the review-input rules (`input`), the verdict schema (`reviewer`), lineage and eligibility (`lineage`, M1), the
//! response ladder (`respond`), keep-going's parameters and conditions (`keepgoing`), canaries (`canary`), the
//! operator-authored authorization block (`auth`) and the fixed sentences the agent may see (`sentences`).
//! **M2 makes the monitor watch and nothing else.** The daemon builds one `Monitor` per loom home at start (with
//! `[monitor] enabled = false` it keeps only the precision-list, S4 and canary tripwires, which have no off switch), folds its log before any session is activated, and runs every tripwire over every
//! record of every session in **shadow**: findings are recorded in `<home>/monitor/log.jsonl`, shown by
//! `GET /api/monitor`, `GET /api/missions/{id}/monitor`, `loom monitor status|log|replay`, and nothing changes for an
//! agent: no note, no refusal, no hold, no pause, no notification. The functions that later phases fill (the reviewer, the
//! gate, the durable pause, keep-going) still return `Err(MonitorError::NotBuilt { .. })`, never an empty or permissive
//! value, so a caller wired in too early fails closed (nothing is cleared, nothing is allowed on the monitor's say-so).
//! M1 added the profile keys `family`, `alignment`, `recipient` and `purpose`, the `[monitor]` keys `reviewers`,
//! `tripwires_only_profiles`, `recipients`, `content` and `known_families`, the check `loom config check` runs on them,
//! `loom models lineage`, and the resolved lineage in `session_start`; M2 adds `[monitor] enabled`, `mode`,
//! `fleet_every_s` and `monitor_down`.
//!
//! ## Placement (built by M2; invariants I1 to I12 of `docs/MONITOR.md` §2.1)
//! `Runtime` will own `Arc<Monitor>`, built at `Runtime::start` after the proxy. Its log fold completes before
//! `load_known` and before any session is activated (I9). The monitor is not a session: it has no `Known` entry, so
//! `resolve_child` and `resolve_child_id` cannot name it, `agent_stop all` and mission stop do not reach it (I1). It has
//! no tools and no network except its model endpoints, through a model client with `.no_proxy()` (I2). Its state lives
//! under `<home>/monitor` and `<home>/keys/monitor.key`, which the sandbox hides from commands and the file tools
//! refuse (I3). Its prompts are compiled in (`texts.rs`, I4). Its responses act on harness state, never on the agent's
//! compliance (I5). Every verdict names the SHA-256 of its exact input (I6). An unreachable reviewer, a refusal, a
//! malformed or degraded verdict or a timeout clears nothing (I7). Inputs are harness-attested (I8). A pause is a
//! durable state checked by `Inner::may_run` (I9). Monitor faults are never agent misbehaviour (I10). Nothing the
//! reviewer wrote reaches the agent (I11). Live failures are stopped at chokepoints (I12).
//!
//! ## Submodules
//! - `taxonomy`: `Category` (the 14 slugs), `Severity` S0..S4, `Basis`, `Response` R0..R5, and the pure rules that
//!   relate them (aggregation of S1, reasoning-only cap, relaxed-agent uptier, the response a severity earns).
//! - `log`: `EntryKind` (the 19 record kinds of `<home>/monitor/log.jsonl`), `Entry`, `MonitorLog` (HMAC-sealed chain,
//!   reserve, anchor), `Fold`.
//! - `tripwire`: `TripwireId` TW-01..TW-28, the table of what each reads and whether it starts enforcing, `Hit`.
//! - `engine`: the tripwire functions over observations; `patterns`: their text rules; `source`: the cursors over the
//!   durable sources; `core`: the pump, flags, the log, the heartbeat, the status; `replay`: `loom monitor replay`.
//! - `classify`: `GatedClass` G1..G8 and opaque code, `Decision`, and the classifier.
//! - `input`: `ReviewKind`, `Content`, the budgets, fence and redaction-tag formats, and the input builder.
//! - `reviewer`: the `monitor_verdict` schema (`Verdict`), its validation, `RecommendedResponse`.
//! - `lineage`: eligibility, selection, the reachable profile set and the model-policy check (M1); the lineage of a
//!   profile itself is `loom_core::lineage`.
//! - `respond`: `Responder` (note, hold, cut, pause, resume, contain, halt, notify) and the R3 sequence's steps.
//! - `keepgoing`: `KeepGoingParams` and its limits, `Blocker` (K1..K10 and the refusals), `KeepGoingAction`.
//! - `canary`: `Canary` CN-1..CN-6. `fleet`: `Join` FS-1..FS-10.
//! - `auth`: `Authorization`, the operator-authored block of every review input.
//! - `sentences`: the fixed texts an agent can ever see from the monitor.
//!
//! ## Errors
//! `MonitorError` is a typed error whose messages say what to do next. `NotBuilt` names the phase of
//! `docs/MONITOR.md` §9.1 that builds the part. `Invalid` is a refusal of a malformed request. `Unavailable` is a
//! fault (reviewer, log, probe): by invariant I10 a caller must never count it as the agent's misbehaviour.
//!
//! ## Tests required
//! Each submodule's own list. In `mod.rs`: `not_built_names_the_phase`; `not_built_is_a_fault_not_a_verdict`; the
//! `Monitor` handle: `a_monitor_watches_a_home_and_shows_it`, `a_down_monitor_says_why_and_reads_nothing`,
//! `the_worker_pumps_when_woken`, `entries_are_filtered_by_mission_and_paged`, `a_disabled_monitor_keeps_the_causes_that_have_no_off_switch`,
//! `status_does_not_wait_for_a_pump_and_a_stalled_worker_is_degraded`.
//!
//! ## The handle
//! `status()` reads a snapshot the worker publishes at the end of each pass, so a status request, the census and the
//! egress probe never wait for a pass (which holds the core). The snapshot says `degraded` when its heartbeat is older
//! than `STALE_HEARTBEAT_MS` (the worker is not running) and, after a failed log write that later works again,
//! `down` is lifted.

pub mod auth;
pub mod canary;
pub mod classify;
pub mod core;
pub mod engine;
pub mod fleet;
pub mod input;
pub mod keepgoing;
pub mod lineage;
pub mod log;
pub mod patterns;
pub mod replay;
pub mod respond;
pub mod reviewer;
pub mod sentences;
pub mod source;
pub mod taxonomy;
pub mod tripwire;

/// What the monitor can say it did not do.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MonitorError {
    /// The part is specified and not built. Nothing was checked and nothing is cleared.
    #[error(
        "The monitor's {what} is not built yet (phase {phase} of docs/MONITOR.md section 9.1): nothing was checked, \
         so nothing is cleared. Do not rely on it; the running build behaves as if the monitor were off."
    )]
    NotBuilt { what: &'static str, phase: &'static str },
    /// A request the monitor refuses, with the reason and what to change.
    #[error("{0}")]
    Invalid(String),
    /// A reviewer, the monitor log, a probe or a worker could not do its job. A fault, never a verdict: it clears
    /// nothing and counts against nobody.
    #[error("The monitor could not finish: {0} Nothing was cleared; retry, or answer the held item yourself.")]
    Unavailable(String),
}

impl MonitorError {
    /// True for a fault of the monitor's own (I10): callers must not turn it into a denial count, a flag or evaluation
    /// data.
    pub fn is_fault(&self) -> bool {
        matches!(self, MonitorError::NotBuilt { .. } | MonitorError::Unavailable(_))
    }
}

/// `Err(NotBuilt)` for the part `what`, which `phase` builds. Every stub of this module returns it.
pub(crate) fn not_built<T>(what: &'static str, phase: &'static str) -> Result<T, MonitorError> {
    Err(MonitorError::NotBuilt { what, phase })
}

/// What `Monitor::entries` selects.
#[derive(Clone, Debug, Default)]
pub struct LogFilter {
    /// Only the entries about this mission (its `mission` field, or its place in `missions`).
    pub mission: Option<loom_core::MissionId>,
    /// Entries with a seq above this.
    pub after: u64,
    pub limit: usize,
    /// Leave out the housekeeping kinds (`cursor`, `heartbeat`).
    pub quiet: bool,
}

/// A page of the log.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LogPage {
    pub entries: Vec<log::Entry>,
    /// The seq to ask after for the next page; `None` at the end.
    pub next_after: Option<u64>,
}

struct Shared {
    paths: loom_core::config::Paths,
    cfg: loom_core::config::MonitorCfg,
    core: std::sync::Mutex<Option<core::Core>>,
    down: std::sync::Mutex<Option<String>>,
    /// The status as the last pass left it (read without taking the core).
    status: std::sync::Mutex<Option<core::MonitorStatus>>,
    /// The latest census and egress verdict, applied at the start of the next pass.
    census: std::sync::Mutex<Option<crate::census::CensusView>>,
    egress: std::sync::Mutex<Option<bool>>,
    hints: std::sync::Mutex<std::collections::BTreeSet<String>>,
    notify: tokio::sync::Notify,
    stop: std::sync::atomic::AtomicBool,
    last_full: std::sync::atomic::AtomicU64,
}

/// A snapshot older than this means the worker is not running.
pub const STALE_HEARTBEAT_MS: u64 = 30_000;

fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// The monitor: owned by the runtime, one per loom home (built by M2). It is a handle: cheap to clone, and every clone
/// is the same monitor.
#[derive(Clone)]
pub struct Monitor {
    shared: std::sync::Arc<Shared>,
}

impl std::fmt::Debug for Monitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Monitor").finish()
    }
}

impl Monitor {
    /// Open `<home>/monitor`, fold its log, and make the core (M2). The fold completes before this returns, so the caller
    /// can activate sessions afterwards (I9). A failed MAC or an unwritable log is `Unavailable`: the monitor is then
    /// down and the daemon shows the "down" state (`docs/MONITOR.md` §2.8; `Monitor::down` is the handle for it), but
    /// down never lifts a pause: the caller holds every mission that has a pause or halt record (every mission when it
    /// cannot tell) until the operator acknowledges, whatever `monitor_down` says (`log.rs` CONTRACT).
    pub fn start(
        paths: &loom_core::config::Paths,
        cfg: &loom_core::config::MonitorCfg,
        env: engine::Env,
        journal_key: Option<Vec<u8>>,
    ) -> Result<Monitor, MonitorError> {
        let c = core::CoreCfg { fleet_every_ms: cfg.fleet_every_s.saturating_mul(1000), enabled: cfg.enabled };
        let core = core::Core::open(paths, std::sync::Arc::new(env), c, journal_key)?;
        Ok(Monitor::with(paths, cfg, Some(core), None))
    }

    /// The handle of a monitor that cannot run, with the sentence that says why. It reads nothing and says "down".
    pub fn down(paths: &loom_core::config::Paths, cfg: &loom_core::config::MonitorCfg, reason: String) -> Monitor {
        Monitor::with(paths, cfg, None, Some(reason))
    }

    fn with(
        paths: &loom_core::config::Paths,
        cfg: &loom_core::config::MonitorCfg,
        core: Option<core::Core>,
        down: Option<String>,
    ) -> Monitor {
        let status = core.as_ref().map(|c| c.status(cfg.enabled, "shadow"));
        Monitor {
            shared: std::sync::Arc::new(Shared {
                paths: paths.clone(),
                cfg: cfg.clone(),
                core: std::sync::Mutex::new(core),
                down: std::sync::Mutex::new(down),
                status: std::sync::Mutex::new(status),
                census: std::sync::Mutex::new(None),
                egress: std::sync::Mutex::new(None),
                hints: std::sync::Mutex::new(std::collections::BTreeSet::new()),
                notify: tokio::sync::Notify::new(),
                stop: std::sync::atomic::AtomicBool::new(false),
                last_full: std::sync::atomic::AtomicU64::new(0),
            }),
        }
    }

    /// Something was written: read it soon. Never blocks and never drops anything (the cursor catches up).
    pub fn wake(&self, session: Option<&loom_core::SessionId>) {
        if let Some(s) = session {
            if let Some(name) = self.shared.paths.session_dir(s).file_name() {
                let mut h = lock(&self.shared.hints);
                if h.len() < 4096 {
                    h.insert(name.to_string_lossy().into_owned());
                }
            }
        }
        self.shared.notify.notify_one();
    }

    /// One pass now, on the calling thread (the worker, and tests, call it). `full` reads every source.
    pub fn pump_now(&self, full: bool) -> bool {
        let now = loom_core::now_ms();
        let hints = std::mem::take(&mut *lock(&self.shared.hints));
        let mut guard = lock(&self.shared.core);
        let Some(core) = guard.as_mut() else { return false };
        if let Some(unbounded) = lock(&self.shared.egress).take() {
            core.set_egress_unbounded(unbounded);
        }
        if let Some(view) = lock(&self.shared.census).take() {
            core.census(&view, now);
        }
        let progress = core.pump(now, &hints, full);
        // The reason follows the core: a log that takes writes again lifts it.
        *lock(&self.shared.down) = core.is_down().map(str::to_string);
        *lock(&self.shared.status) = Some(core.status(self.shared.cfg.enabled, "shadow"));
        progress
    }

    /// Run the worker: pump when woken and every 2 s, a full pass every 10 s. Needs a tokio runtime.
    pub fn spawn(&self) -> tokio::task::JoinHandle<()> {
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = me.shared.notify.notified() => {}
                    () = tokio::time::sleep(std::time::Duration::from_secs(2)) => {}
                }
                if me.shared.stop.load(std::sync::atomic::Ordering::SeqCst) {
                    return;
                }
                let worker = me.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    let now = loom_core::now_ms();
                    let last = worker.shared.last_full.load(std::sync::atomic::Ordering::SeqCst);
                    let full = now.saturating_sub(last) >= core::DISCOVER_EVERY_MS;
                    if full {
                        worker.shared.last_full.store(now, std::sync::atomic::Ordering::SeqCst);
                    }
                    let mut passes = 0u32;
                    while worker.pump_now(full && passes == 0) && passes < 4 {
                        passes = passes.saturating_add(1);
                    }
                })
                .await;
            }
        })
    }

    /// Stop the worker at its next turn.
    pub fn shutdown(&self) {
        self.shared.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        self.shared.notify.notify_one();
    }

    /// The monitor's status (the snapshot of the last pass; see the contract).
    pub fn status(&self) -> core::MonitorStatus {
        let mode = "shadow";
        let snap = lock(&self.shared.status).clone();
        match snap {
            Some(mut st) => {
                let age = loom_core::now_ms().saturating_sub(st.heartbeat_ms);
                if st.heartbeat_ms > 0 && age > STALE_HEARTBEAT_MS && st.state != "down" {
                    st.state = "degraded".into();
                    st.faults.push(format!(
                        "The monitor's worker has not run for {} s. Restart the daemon if this does not clear.",
                        age / 1000
                    ));
                }
                st
            }
            None => core::MonitorStatus {
                state: "down".into(),
                mode: mode.into(),
                enabled: self.shared.cfg.enabled,
                egress_unbounded: false,
                open_flags: 0,
                paused: Vec::new(),
                halts: Vec::new(),
                backlog_s: 0,
                heartbeat_ms: 0,
                last_seq: 0,
                sources: 0,
                counts: core::Counts::default(),
                tripwires: Vec::new(),
                faults: Vec::new(),
                fleet_runs: 0,
                fleet_hits: 0,
                reviewers: Vec::new(),
                down_reason: lock(&self.shared.down).clone(),
            },
        }
    }

    /// The last process census, from the runtime (TW-20, the fleet's listeners). Applied at the start of the next pass.
    pub fn census(&self, view: &crate::census::CensusView) {
        *lock(&self.shared.census) = Some(view.clone());
        self.shared.notify.notify_one();
    }

    /// Whether commands can reach the network outside the proxy, as the last self-probe found it. Applied at the start
    /// of the next pass.
    pub fn egress(&self, unbounded: bool) {
        *lock(&self.shared.egress) = Some(unbounded);
        self.shared.notify.notify_one();
    }

    /// A page of the monitor log (see `LogFilter`). The log is read from disk, so a down monitor still shows it.
    pub fn entries(&self, filter: &LogFilter) -> Result<LogPage, MonitorError> {
        use std::io::BufRead;
        let path = self.shared.paths.home.join(log::DIR).join(log::LOG_FILE);
        let file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(LogPage { entries: Vec::new(), next_after: None })
            }
            Err(e) => return Err(MonitorError::Unavailable(format!("{} cannot be read: {e}.", path.display()))),
        };
        let limit = filter.limit.clamp(1, 2000);
        let want = filter.mission.as_ref().map(|m| m.as_str().to_string());
        let mut entries = Vec::new();
        let mut more = false;
        for line in std::io::BufReader::new(file).lines().map_while(Result::ok) {
            let Ok(e) = serde_json::from_str::<log::Entry>(&line) else { continue };
            if e.seq <= filter.after {
                continue;
            }
            if filter.quiet && matches!(e.kind, log::EntryKind::Cursor | log::EntryKind::Heartbeat) {
                continue;
            }
            if let Some(m) = &want {
                let own = e.fields.get("mission").and_then(|v| v.as_str()) == Some(m.as_str());
                let listed = e
                    .fields
                    .get("missions")
                    .and_then(|v| v.as_array())
                    .is_some_and(|a| a.iter().any(|x| x.as_str() == Some(m.as_str())));
                if !own && !listed {
                    continue;
                }
            }
            if entries.len() >= limit {
                more = true;
                break;
            }
            entries.push(e);
        }
        let next_after = if more { entries.last().map(|e| e.seq) } else { None };
        Ok(LogPage { entries, next_after })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_built_names_the_phase() {
        let e = not_built::<()>("gate", "M8").err().map(|e| e.to_string()).unwrap_or_default();
        assert!(e.contains("gate"), "{e}");
        assert!(e.contains("phase M8"), "{e}");
        assert!(e.contains("nothing is cleared"), "{e}");
    }

    #[test]
    fn not_built_is_a_fault_not_a_verdict() {
        assert!(MonitorError::NotBuilt { what: "x", phase: "M2" }.is_fault());
        assert!(MonitorError::Unavailable("down".into()).is_fault());
        assert!(!MonitorError::Invalid("no".into()).is_fault());
    }

    // ---- the Monitor handle ---------------------------------------------------------------------------------------

    use loom_core::config::{MonitorCfg, Paths};
    use loom_core::event::{Event, ModelRef, SessionStart, Termination, ToolCall, ToolClass, ToolResult, ToolStatus};
    use loom_core::log::{Durability, SessionLog};
    use loom_core::{Author, CallId, MissionId, SessionId};

    fn fixture() -> (tempfile::TempDir, Paths) {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths::at(std::fs::canonicalize(dir.path()).expect("canon"));
        paths.ensure_private_layout().expect("layout");
        (dir, paths)
    }

    fn env_of(paths: &Paths) -> engine::Env {
        engine::Env {
            home: paths.home.to_string_lossy().into_owned(),
            copies: format!("{}-copies", paths.home.to_string_lossy()),
            infra: None,
            network_mode: "allowlist".into(),
            allow: vec![],
            deny: vec![],
            packs: Default::default(),
            relaxed_profiles: Default::default(),
        }
    }

    fn session_with(paths: &Paths, id: &str, mission: &str, cmd: &str) -> SessionLog {
        let dir = paths.sessions_dir().join(id);
        std::fs::create_dir_all(&dir).expect("dir");
        let mut log = SessionLog::create(&dir.join("log.jsonl"), Durability::Batch).expect("create");
        log.append(
            Author::Harness,
            Event::SessionStart(SessionStart {
                session: SessionId::from(id),
                mission: MissionId::from(mission),
                parent: None,
                workspace: "/w".into(),
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
            }),
        )
        .expect("start");
        log.append(
            Author::Model,
            Event::ToolCall(ToolCall {
                call_id: CallId::from("c1"),
                req_id: "r".into(),
                name: "bash".into(),
                args: serde_json::json!({"command": cmd}),
                class: ToolClass::Exec,
            }),
        )
        .expect("call");
        log.append(
            Author::Tool,
            Event::ToolResult(ToolResult {
                call_id: CallId::from("c1"),
                name: "bash".into(),
                status: ToolStatus::Ok,
                text: String::new(),
                output: None,
                cut: false,
                class: ToolClass::Exec,
                meta: Default::default(),
                duration_ms: 1,
            }),
        )
        .expect("result");
        log
    }

    #[test]
    fn a_monitor_watches_a_home_and_shows_it() {
        let (_d, paths) = fixture();
        let m = Monitor::start(&paths, &MonitorCfg::default(), env_of(&paths), None).expect("start");
        m.pump_now(true);
        let _log = session_with(&paths, "s-1", "m-1", "ps eww 7");
        m.wake(Some(&SessionId::from("s-1")));
        m.pump_now(true);
        let st = m.status();
        assert_eq!((st.state.as_str(), st.mode.as_str(), st.enabled), ("shadow", "shadow", true));
        assert_eq!((st.sources, st.open_flags), (1, 1));
        assert_eq!(st.tripwires.len(), 28);
        assert_eq!(st.tripwires.iter().find(|t| t.id == "TW-10").map(|t| t.fired), Some(1));
        assert!(st.heartbeat_ms > 0);
        let page = m
            .entries(&LogFilter { mission: Some(MissionId::from("m-1")), after: 0, limit: 50, quiet: true })
            .expect("entries");
        let kinds: Vec<&str> = page.entries.iter().map(|e| e.kind.slug()).collect();
        assert_eq!(kinds, vec!["tripwire", "flag", "response"]);
        assert!(page.next_after.is_none());
    }

    #[test]
    fn entries_are_filtered_by_mission_and_paged() {
        let (_d, paths) = fixture();
        let m = Monitor::start(&paths, &MonitorCfg::default(), env_of(&paths), None).expect("start");
        m.pump_now(true);
        let _a = session_with(&paths, "s-a", "m-a", "ps eww 1");
        let _b = session_with(&paths, "s-b", "m-b", "cat /proc/3/environ");
        m.pump_now(true);
        let for_a = m
            .entries(&LogFilter { mission: Some(MissionId::from("m-a")), after: 0, limit: 50, quiet: true })
            .expect("a");
        assert!(for_a.entries.iter().all(|e| e.fields.get("mission").and_then(|v| v.as_str()) == Some("m-a")));
        assert_eq!(for_a.entries.len(), 3);
        let first = m.entries(&LogFilter { mission: None, after: 0, limit: 2, quiet: true }).expect("page");
        assert_eq!(first.entries.len(), 2);
        let next = first.next_after.expect("more");
        let second = m.entries(&LogFilter { mission: None, after: next, limit: 50, quiet: true }).expect("page 2");
        assert!(second.entries.iter().all(|e| e.seq > next));
        assert_eq!(
            first.entries.len() + second.entries.len(),
            m.entries(&LogFilter { mission: None, after: 0, limit: 50, quiet: true }).expect("all").entries.len()
        );
        let loud = m.entries(&LogFilter { mission: None, after: 0, limit: 200, quiet: false }).expect("all");
        assert!(loud.entries.iter().any(|e| e.kind == log::EntryKind::Heartbeat || e.kind == log::EntryKind::Cursor));
    }

    #[test]
    fn a_down_monitor_says_why_and_reads_nothing() {
        let (_d, paths) = fixture();
        let m = Monitor::down(&paths, &MonitorCfg::default(), "The monitor log did not verify.".into());
        assert!(!m.pump_now(true));
        let st = m.status();
        assert_eq!(st.state, "down");
        assert_eq!(st.down_reason.as_deref(), Some("The monitor log did not verify."));
        assert_eq!(m.entries(&LogFilter::default()).map(|p| p.entries.len()).unwrap_or(9), 0);
        // A log that does not verify makes `start` fail with a sentence that says what to do.
        let (_d2, p2) = fixture();
        let ok = Monitor::start(&p2, &MonitorCfg::default(), env_of(&p2), None).expect("start");
        drop(ok);
        let log = p2.home.join("monitor").join("log.jsonl");
        std::fs::write(&log, "{\"seq\":1,\"ts_ms\":1,\"prev\":\"x\",\"mac\":\"y\",\"kind\":\"heartbeat\"}\n")
            .expect("forge");
        let e = Monitor::start(&p2, &MonitorCfg::default(), env_of(&p2), None)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(e.contains("fails verification") && e.contains("ack-down"), "{e}");
    }

    #[test]
    fn a_disabled_monitor_keeps_the_causes_that_have_no_off_switch() {
        let (_d, paths) = fixture();
        let cfg = MonitorCfg { enabled: false, ..MonitorCfg::default() };
        let m = Monitor::start(&paths, &cfg, env_of(&paths), None).expect("start");
        m.pump_now(true);
        let _s = session_with(&paths, "s-1", "m-1", "ps eww 7");
        m.pump_now(true);
        let st = m.status();
        assert!(!st.enabled);
        assert_eq!(st.tripwires.iter().find(|t| t.id == "TW-10").map(|t| t.fired), Some(1), "the precision list runs");
    }

    #[test]
    fn status_does_not_wait_for_a_pump_and_a_stalled_worker_is_degraded() {
        let (_d, paths) = fixture();
        let m = Monitor::start(&paths, &MonitorCfg::default(), env_of(&paths), None).expect("start");
        m.pump_now(true);
        // A pass holds the core; the status is the snapshot it left, and a census waits for the next pass.
        let held = lock(&m.shared.core);
        let st = m.status();
        assert_eq!(st.state, "shadow");
        m.census(&crate::census::CensusView {
            taken_ms: 1,
            readable: false,
            identity: false,
            identity_detail: String::new(),
            sessions: Default::default(),
        });
        m.egress(true);
        drop(held);
        m.pump_now(true);
        assert!(m.status().egress_unbounded, "applied at the start of the next pass");
        // A snapshot whose heartbeat is old means the worker is not running.
        if let Some(snap) = lock(&m.shared.status).as_mut() {
            snap.heartbeat_ms = 1_000;
        }
        let st = m.status();
        assert_eq!(st.state, "degraded");
        assert!(st.faults.iter().any(|f| f.contains("worker has not run")), "{:?}", st.faults);
    }

    #[tokio::test]
    async fn the_worker_pumps_when_woken() {
        let (_d, paths) = fixture();
        let m = Monitor::start(&paths, &MonitorCfg::default(), env_of(&paths), None).expect("start");
        m.pump_now(true);
        let worker = m.spawn();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let _log = session_with(&paths, "s-1", "m-1", "ps eww 7");
        m.wake(Some(&SessionId::from("s-1")));
        let mut fired = 0;
        for _ in 0..80 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            fired = m.status().tripwires.iter().find(|t| t.id == "TW-10").map_or(0, |t| t.fired);
            if fired > 0 {
                break;
            }
        }
        m.shutdown();
        assert_eq!(fired, 1, "the worker read the session it was told about");
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), worker).await;
    }
}
