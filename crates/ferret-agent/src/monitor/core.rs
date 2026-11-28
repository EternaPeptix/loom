//! The monitor core: cursors over the sources, the tripwires, flags, the log, the heartbeat, the fleet scan (M2).
//!
//! CONTRACT.
//!
//! - `Core` is the whole of Duty W in shadow mode, with no thread of its own: `pump(now_ms, hints, full)` reads what is
//!   new in every source it is told about (`hints`: session directories to read now; `full`: also discover sessions
//!   and read every source), runs the tripwires over it through `Engine`, and records what they find. `Monitor` (below)
//!   runs a core on a worker. A core with no `MonitorLog` is a memory core: it records into a vector and changes no
//!   file (the replay of `replay.rs` is one).
//! - **Order within a pump:** session logs first (every log the pump reads), then each session's `net.jsonl`, the floor
//!   events, the ledger journals of the missions whose sessions wrote a ledger record, the fleet joins when
//!   `fleet_every_s` has passed, the heartbeat, the cursor checkpoint. A net decision is judged `IDLE_GRACE_MS` after
//!   its time, never before, and only after every log of the pump has been read (its own session's read to its end),
//!   so a call that had started is on the engine's books (the `tool_call` record is synced before the tool starts,
//!   `session.rs`). With main's box proxy bridge (`Env::box_bridge`) a decision of the session the bridge carries
//!   depends on the box calls of its mission's other sessions: a pump reads every primed session of a mission it reads
//!   one of, and holds the mission's decisions for a later pump while one of them has more to read; a replay
//!   (`drain`) reads every log to its end before it judges any decision (a lead's log sorts before its children's). A
//!   journal is read for the authorization of its mission's first record (`load_ledger`), but its entries are judged
//!   only in the ledger step, after the logs, so an entry comes after the records of the call that wrote it (TW-23
//!   reads a `security_ingest` result's `entry`).
//! - **Records:** every hit of severity S1 and above is a `tripwire` entry (S0 is counted only). `state` is `shadow`
//!   for every one in M2 (the precision list enforces from M4); `precision` says whether the hit is a part of the §4.8
//!   list; `would` is the response its severity earns once promoted (`Response::earned(sev, true)`). The S1
//!   aggregation (§1.5) raises the hit that makes 3 distinct S1 targets of one category in 30 minutes, or 10 S1 hits
//!   in the mission, to S2. A hit with the same (tripwire, key) as one logged in the last 60 s at the same or a lower
//!   severity is not logged again; the flag counts it. A hit of S2 or more opens or counts a **flag**, deduplicated per
//!   (mission, category, key): `f-` and the first 8 hex characters of the SHA-256 of `mission|category|key`; its entry
//!   is the whole record and is written when the flag is new, its severity rises, or its count reaches a power of two.
//!   A flag's first (and each raised) appearance also writes a `response{level: r0, would}`. Nothing here changes what an
//!   agent can see, hear, run or reach.
//! - **Cursors:** one per source (`s:<dir>`, `n:<dir>`, `u`, `f`, `j:<mission>`), advanced as records are read and
//!   checkpointed as one `cursor` entry per pump that wrote anything, and at least every `CHECKPOINT_EVERY_MS`. A
//!   restart resumes from the checkpoint; the few records between the last entry and the crash are read again and
//!   their hits are deduplicated by the throttle above. A source that cannot be read (a chain that breaks, a file that
//!   is shorter than its cursor) is recorded once as a `cursor` entry with a `fault` and is not read again until the
//!   process restarts; it is shown in the status as faulty and is never an agent's misbehaviour (I10). On the very first
//!   start (a log with no cursor, flag or tripwire: nothing was ever read, whatever the first-start marker says, so a
//!   start that was cut short is still the first) every source that exists begins at its end, so a first run raises
//!   nothing retroactive. The `n:<dir>` cursor a checkpoint holds is the one after the last net decision that was
//!   *judged*: decisions that wait out their grace are read again after a restart. A checkpoint may carry `secrets`
//!   (the new credential tags, `log::SecretIndex`), which the fold keeps and `Core::open` hands to the engine.
//! - **Context after a restart:** the engine's per-session memory (the calls in flight, the hosts the agent named, the
//!   last arguments, the baseline of the script) starts empty for a session that was read before; the counters
//!   (distinct hosts, S1 targets, repeats) and the credential index are exact, because they come from the log. What a
//!   restart loses can only make a tripwire quieter (TW-01 reads a refused host as unnamed, TW-19 and TW-25 start
//!   over), and the one tripwire it could make louder, TW-21, is held: a session read before the restart is not
//!   judged for idle egress until `RESTART_BLIND_MS` after the start (what was in flight is not known), and a result
//!   whose call is not on the books is an interval of its own duration.
//! - **Heartbeat:** `heartbeat_ms` is set at every pump, and a `heartbeat` entry is written every `HEARTBEAT_LOG_MS`.
//!   `Monitor::status().heartbeat_ms` older than 30 s means the worker is not running.
//! - **Faults of its own** (an unwritable log, a source that cannot be read) never open a flag, never count toward a
//!   denial counter and are not evaluation data (I10). An unwritable log makes the monitor `down`: pumping stops, the
//!   status says why, and pause entries go to the reserve (`log.rs`). Nothing is applied before it is recorded. A
//!   full disk is not forever: the entries that failed are kept in order (4096 at most), every pump tries the log
//!   again after `RETRY_DOWN_MS`, writes them first and a heartbeat after, and the monitor is up again (no restart);
//!   the cursors were not checkpointed meanwhile, so nothing unread is lost.
//! - **`enabled = false`** keeps the precision-list, S4 and canary tripwires (they have no off switch, design 7.1): the
//!   core reads and logs only the hits that are `precision`, S4 or TW-24; the rest are dropped.
//! - **Authorization:** `auth_for(mission, ts)` is `Authorization::build` over the mission's journal entries up to `ts`
//!   and the operator's messages up to `ts`, cached per mission until the journal, the messages or the revoked hosts
//!   change. A mission's journal is read when a session of it wrote a `ledger` record (debounced by
//!   `LEDGER_DEBOUNCE_MS`), verified with the journal key when the core has it. Its facts carry the mission's named
//!   target (scope and exclusions, from the first session primed with one: `source::prime`), the hosts of the lead's
//!   pack's MCP servers (`Env::mcp_hosts`) and the hosts the operator revoked (`<mission dir>/scope_revoked.json`). That
//!   file is read when the mission is first seen and again, before a pump reads the mission's sessions, whenever its
//!   length or time changed; an entry counts from the time the file was written when the core first saw it. An
//!   operator's revoke writes no `ledger` record to any session's log, so a change of the file also has the journal
//!   read again (the `ScopeRevoke` of a recorded grant).
//! - **Priming** a session tells the engine when it started (`Engine::started_at`) and, for a session resumed past
//!   records (a cursor not at 0), where its shell was left (`source::last_shell_dir`, `Engine::set_shell_dir`).
//! - **Model switches:** a session is relaxed-alignment (one tier up for six categories) when its `session_start`'s
//!   lineage or its profile says so (`source::prime`), and from a `model_switched` onto a relaxed model on (its
//!   `to.lineage`, or `to.profile` among the configuration's relaxed profiles); a switch back does not lower it. The
//!   session is named in the `relaxed` of the `cursor` entry that checkpoints the switch, and `prime` reads the fold's
//!   set, so a restart that resumes past the switch keeps the uptier: after a switch back too, and for a model whose
//!   served id, not its configured one, made it relaxed.
//! - **Census:** `Monitor::census` hands the core the last process census and the sessions that have ended; the core
//!   runs TW-20 over it (S2 for processes of an ended session, S3 when one listens or connects) and feeds the fleet
//!   book's listeners.
//!
//! Tests required: a first run starts at the end of every source and raises nothing; a hit becomes a tripwire entry, a
//! flag and a response, once; repeats are throttled and counted; the S1 aggregation raises the third distinct target;
//! a restart resumes from its cursors and does not read twice; a source with a broken chain is recorded once and not
//! read again; an unwritable log makes the monitor down and a log that works again lifts it without losing the hits;
//! an interrupted first start is still a first start; a child primed before its `forked` record is read from it on; a
//! net decision that waited out no grace is read again after a restart; the credential index survives a restart; a
//! disabled core keeps the precision list; an S1 target back inside the window counts; a net decision is judged after its grace and after the log; a
//! mission's authorization follows its journal and its operator messages, and an operator's revoke (the revoked-hosts
//! file, and the journal it appended to) without any session record; the fleet scan runs on its period and reports
//! once; a memory core writes no file; the status counts what was read; a switch onto a relaxed model uptiers the
//! session's later hits and a switch back does not lower them, across a restart too. After the merge of main (ef34aa4):
//! `with_the_bridge_a_pump_reads_the_missions_other_sessions_before_it_judges_a_decision`, and in the replay
//! `a_replay_judges_a_leads_bridged_decision_after_its_childs_box_call` and
//! `a_replay_judges_a_journal_entry_after_the_records_of_the_call_that_wrote_it`.

use crate::census::CensusView;
use crate::monitor::auth::{AuthFacts, Authorization};
use crate::monitor::engine::{Engine, Env, SessionCtx, IDLE_GRACE_MS};
use crate::monitor::fleet::FleetHit;
use crate::monitor::log::{Cursor, Entry, EntryKind, FlagRec, Fold, MonitorLog};
use crate::monitor::respond::Cohort;
use crate::monitor::source::{self, Primed};
use crate::monitor::taxonomy::{s1_escalates, Category, Response, Severity, S1_WINDOW_MS};
use crate::monitor::tripwire::{Hit, Start, TripwireId, TRIPWIRES};
use crate::monitor::MonitorError;
use crate::runtime::NetEntry;
use ferret_core::config::Paths;
use ferret_core::event::{Author, Event};
use ferret_core::ledger::Entry as LedgerEntry;
use ferret_core::{MissionId, SessionId};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

/// A hit with the same (tripwire, key) within this long is not logged again.
pub const THROTTLE_MS: u64 = 60_000;
/// The longest between two cursor checkpoints while there is something to checkpoint.
pub const CHECKPOINT_EVERY_MS: u64 = 60_000;
/// The heartbeat entry's period.
pub const HEARTBEAT_LOG_MS: u64 = 60_000;
/// The longest a mission's journal is not read again after it was.
pub const LEDGER_DEBOUNCE_MS: u64 = 2_000;
/// How often a pump discovers sessions without being asked (`full`).
pub const DISCOVER_EVERY_MS: u64 = 10_000;
/// A session with no record for this long has its tripwire memory freed.
pub const QUIET_FREE_MS: u64 = 60 * 60 * 1000;
/// How long after a start a resumed session's net decisions are not judged for TW-21: what was in flight when the
/// daemon stopped is not known.
pub const RESTART_BLIND_MS: u64 = 10 * 60 * 1000;
/// The longest a failed entry waits to be written again.
const RETRY_DOWN_MS: u64 = 2_000;
/// The most entries held for a log that cannot be written.
const UNWRITTEN_MAX: usize = 4_096;
/// Passes over one source per pump (each reads at most `source::MAX_BYTES`).
const PASSES: usize = 8;

/// One session's source state.
struct Src {
    dir: std::path::PathBuf,
    cur: Cursor,
    net: Cursor,
    primed: Option<Primed>,
    skip_below: u64,
    /// Net decisions read and not yet judged, each with the cursor after it.
    pending_net: VecDeque<(NetEntry, Cursor)>,
    /// The cursor after the last net decision that was judged: what a checkpoint may say about `n:<dir>` while
    /// decisions wait out their grace.
    net_judged: Cursor,
    fault: Option<String>,
    net_fault: Option<String>,
    last_ts: u64,
}

#[derive(Default)]
struct MState {
    entries: Vec<LedgerEntry>,
    loaded_ms: u64,
    dirty: bool,
    /// The journal was read at least once (for the authorization of the mission's first records: `load_ledger`).
    read_once: bool,
    pack: String,
    role: String,
    facts: AuthFacts,
    /// (journal entries, operator messages, revoked entries) in force at the time the cached block is for.
    cache: Option<(usize, usize, usize, Arc<Authorization>)>,
    prior: Vec<MissionId>,
    /// The revoked-hosts file has been read once; `revoked_stamp` is its (length, time) then, `None` when it was absent.
    revoked_read: bool,
    revoked_stamp: Option<(u64, Option<std::time::SystemTime>)>,
}

#[derive(Default)]
struct Activity {
    clock_ms: u64,
    gap_ms: u64,
    running: BTreeMap<String, u64>,
    last: BTreeMap<String, u64>,
}

/// What the core has done, for the status.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counts {
    pub records: u64,
    pub net: u64,
    pub unattributed: u64,
    pub floor: u64,
    pub ledger: u64,
    pub hits: u64,
    pub throttled: u64,
    pub opaque: u64,
}

/// One tripwire in the status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwStatus {
    pub id: String,
    pub name: String,
    /// `precision`, `mixed` or `shadow`: how it starts (`tripwire::Start`).
    pub start: String,
    /// `shadow` for every tripwire until M4.
    pub state: String,
    pub fired: u64,
    pub by_severity: [u64; 5],
    pub missions: u64,
}

/// The monitor's status (`GET /api/monitor`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MonitorStatus {
    /// `shadow`, `degraded` (a source is faulty, or `Monitor::status` found the heartbeat older than
    /// `STALE_HEARTBEAT_MS`: the worker is not running) or `down` (the log cannot be written or verified).
    pub state: String,
    pub mode: String,
    pub enabled: bool,
    pub egress_unbounded: bool,
    pub open_flags: u64,
    pub paused: Vec<String>,
    pub halts: Vec<Cohort>,
    /// Seconds the oldest unread record has waited (0 when caught up).
    pub backlog_s: u64,
    pub heartbeat_ms: u64,
    pub last_seq: u64,
    pub sources: u64,
    pub counts: Counts,
    pub tripwires: Vec<TwStatus>,
    pub faults: Vec<String>,
    pub fleet_runs: u64,
    pub fleet_hits: u64,
    /// Reviewers: none before M6.
    pub reviewers: Vec<Value>,
    pub down_reason: Option<String>,
}

/// What `Core::new` takes.
pub struct CoreCfg {
    pub fleet_every_ms: u64,
    pub enabled: bool,
}

pub struct Core {
    env: Arc<Env>,
    paths: Paths,
    log: Option<MonitorLog>,
    mem: Vec<Entry>,
    mem_seq: u64,
    fold: Fold,
    engine: Engine,
    srcs: BTreeMap<String, Src>,
    missions: BTreeMap<MissionId, MState>,
    activity: BTreeMap<MissionId, Activity>,
    journal_key: Option<Vec<u8>>,
    floor_cur: Cursor,
    unattr_cur: Cursor,
    shared_faults: BTreeMap<String, String>,
    dirty_cursors: BTreeSet<String>,
    /// Sessions a switch uptiered since the last checkpoint, written with it (`relaxed` of a `cursor` entry).
    new_relaxed: BTreeSet<String>,
    first_start: bool,
    started: bool,
    last_discover: u64,
    last_checkpoint: u64,
    last_log_heartbeat: u64,
    last_fleet: u64,
    fleet_every_ms: u64,
    pub heartbeat_ms: u64,
    clock_ms: u64,
    counts: Counts,
    flag_extra: BTreeMap<String, u64>,
    fleet_runs: u64,
    fleet_hits: u64,
    egress_unbounded: bool,
    enabled: bool,
    down: Option<String>,
    backlog_since: Option<u64>,
    /// Entries that could not be written (a full disk), in order, written first when the log takes writes again.
    unwritten: VecDeque<(EntryKind, Map<String, Value>)>,
    last_retry: u64,
    started_ms: u64,
}

fn word(r: Response) -> &'static str {
    match r {
        Response::R0Record => "r0",
        Response::R1Steer => "r1",
        Response::R2Refuse => "r2",
        Response::R3Pause => "r3",
        Response::R4Contain => "r4",
        Response::R5Halt => "r5",
    }
}

fn obj(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

impl Core {
    /// A core that records into the monitor log of `paths`. The fold is complete when this returns (I9).
    pub fn open(
        paths: &Paths,
        env: Arc<Env>,
        cfg: CoreCfg,
        journal_key: Option<Vec<u8>>,
    ) -> Result<Core, MonitorError> {
        let (log, fold, opened) = MonitorLog::open_with_report(&paths.home)?;
        // A log that holds no cursor, flag or tripwire has read nothing yet, whatever the marker says: a start that
        // was cut short before its first checkpoint is still the first start.
        let first = fold.cursors.is_empty() && fold.flags.is_empty() && fold.stats.is_empty();
        let _ = opened;
        let mut c = Core::blank(paths, env, cfg, journal_key);
        c.log = Some(log);
        c.engine.restore_secrets(fold.secrets.clone());
        c.fold = fold;
        c.first_start = first;
        Ok(c)
    }

    /// A core that records into memory and touches no file (a replay).
    pub fn memory(paths: &Paths, env: Arc<Env>, cfg: CoreCfg, journal_key: Option<Vec<u8>>) -> Core {
        Core::blank(paths, env, cfg, journal_key)
    }

    fn blank(paths: &Paths, env: Arc<Env>, cfg: CoreCfg, journal_key: Option<Vec<u8>>) -> Core {
        Core {
            engine: Engine::new(env.clone()),
            env,
            paths: paths.clone(),
            log: None,
            mem: Vec::new(),
            mem_seq: 0,
            fold: Fold::default(),
            srcs: BTreeMap::new(),
            missions: BTreeMap::new(),
            activity: BTreeMap::new(),
            journal_key,
            floor_cur: Cursor::default(),
            unattr_cur: Cursor::default(),
            shared_faults: BTreeMap::new(),
            dirty_cursors: BTreeSet::new(),
            new_relaxed: BTreeSet::new(),
            first_start: false,
            started: false,
            last_discover: 0,
            last_checkpoint: 0,
            last_log_heartbeat: 0,
            last_fleet: 0,
            fleet_every_ms: cfg.fleet_every_ms,
            heartbeat_ms: 0,
            clock_ms: 0,
            counts: Counts::default(),
            flag_extra: BTreeMap::new(),
            fleet_runs: 0,
            fleet_hits: 0,
            egress_unbounded: false,
            enabled: cfg.enabled,
            down: None,
            backlog_since: None,
            unwritten: VecDeque::new(),
            last_retry: 0,
            started_ms: 0,
        }
    }

    pub fn fold(&self) -> &Fold {
        &self.fold
    }

    pub fn engine_mut(&mut self) -> &mut Engine {
        &mut self.engine
    }

    /// The entries a memory core recorded.
    pub fn memory_entries(&self) -> &[Entry] {
        &self.mem
    }

    pub fn is_down(&self) -> Option<&str> {
        self.down.as_deref().or_else(|| self.log.as_ref().and_then(|l| l.down_reason()))
    }

    pub fn set_egress_unbounded(&mut self, unbounded: bool) {
        self.egress_unbounded = unbounded;
    }

    /// The newest record time the core has seen: the clock a replay uses for the fleet scan.
    pub fn clock_ms(&self) -> u64 {
        self.clock_ms
    }

    // ---- recording ------------------------------------------------------------------------------------------------------

    fn emit(&mut self, kind: EntryKind, fields: Map<String, Value>) -> Option<Entry> {
        if self.log.is_some() && !self.unwritten.is_empty() {
            // Order is kept: what failed before is written first, or this one waits behind it.
            if self.down.is_some() {
                if self.unwritten.len() < UNWRITTEN_MAX {
                    self.unwritten.push_back((kind, fields));
                }
                return None;
            }
        }
        let fields_back = if self.log.is_some() { fields.clone() } else { Map::new() };
        match self.log.as_mut() {
            Some(log) => match log.append(kind, fields) {
                Ok(e) => {
                    self.fold.apply(&e);
                    Some(e)
                }
                Err(e) => {
                    if self.down.is_none() {
                        tracing::error!("the monitor log cannot be written: {e}");
                    }
                    self.down = Some(e.to_string());
                    if self.unwritten.len() < UNWRITTEN_MAX {
                        self.unwritten.push_back((kind, fields_back));
                    }
                    None
                }
            },
            None => {
                self.mem_seq = self.mem_seq.saturating_add(1);
                let e = Entry {
                    seq: self.mem_seq,
                    ts_ms: self.clock_ms,
                    prev: String::new(),
                    mac: String::new(),
                    kind,
                    fields,
                };
                self.fold.apply(&e);
                self.mem.push(e.clone());
                Some(e)
            }
        }
    }

    /// Try the log again after a failed write (a full disk is not forever): what failed is written first and, when all of
    /// it is, the monitor is up again. Nothing was read meanwhile that the failed entries do not cover.
    fn recover(&mut self, now: u64) -> bool {
        if self.down.is_none() && !self.log.as_ref().is_some_and(|l| l.is_down()) {
            return true;
        }
        if now.saturating_sub(self.last_retry) < RETRY_DOWN_MS {
            return false;
        }
        self.last_retry = now;
        let Some(log) = self.log.as_mut() else { return true };
        while let Some((kind, fields)) = self.unwritten.pop_front() {
            match log.append(kind, fields.clone()) {
                Ok(e) => self.fold.apply(&e),
                Err(_) => {
                    self.unwritten.push_front((kind, fields));
                    return false;
                }
            }
        }
        // The heartbeat proves the log takes writes again.
        match log.append(EntryKind::Heartbeat, Map::new()) {
            Ok(e) => {
                self.fold.apply(&e);
                self.down = None;
                tracing::warn!("the monitor log takes writes again; the monitor is up");
                true
            }
            Err(_) => false,
        }
    }

    fn flag_id(mission: &MissionId, category: &str, key: &str) -> String {
        let h = ferret_core::sha256_hex(format!("{}|{category}|{key}", mission.as_str()).as_bytes());
        format!("f-{}", h.get(..8).unwrap_or(&h))
    }

    fn on_hit(&mut self, mut hit: Hit) {
        self.counts.hits = self.counts.hits.saturating_add(1);
        if hit.severity == Severity::S0 {
            return;
        }
        // With `[monitor] enabled = false` only what has no off switch runs: the precision list, S4 and the canaries.
        let kept = hit.precision || hit.severity >= Severity::S4 || hit.id.number() == 24;
        if !self.enabled && !kept {
            return;
        }
        let number = hit.id.number();
        let cat = hit.category.slug().to_string();
        if hit.severity == Severity::S1 {
            let book = self.fold.s1.get(&(hit.mission.clone(), cat.clone()));
            let since = hit.at_ms.saturating_sub(S1_WINDOW_MS);
            let in_window = book.is_some_and(|b| b.has_key_since(&hit.key, since));
            let window = book.map_or(0, |b| b.distinct_since(since)).saturating_add(usize::from(!in_window));
            let lifetime = book.map_or(0, |b| b.count).saturating_add(1);
            if s1_escalates(u32::try_from(window).unwrap_or(u32::MAX), u32::try_from(lifetime).unwrap_or(u32::MAX)) {
                hit.severity = Severity::S2;
                hit.from_s1 = true;
                hit.detail = format!(
                    "{} (S1 aggregation: {window} distinct in 30 minutes, {lifetime} in the mission)",
                    hit.detail
                );
            }
        }
        // Throttle repeats.
        let repeat = self.fold.book(&hit.mission, number).is_some_and(|b| {
            b.recent.iter().rev().take(32).any(|r| {
                r.key == hit.key && hit.at_ms.saturating_sub(r.at_ms) < THROTTLE_MS && r.severity >= hit.severity
            })
        });
        if repeat {
            self.counts.throttled = self.counts.throttled.saturating_add(1);
            if hit.severity >= Severity::S2 {
                let id = Core::flag_id(&hit.mission, &cat, &hit.key);
                let slot = self.flag_extra.entry(id).or_default();
                *slot = slot.saturating_add(1);
            }
            return;
        }
        let would = Response::earned(hit.severity, true);
        let mut f = obj(serde_json::json!({
            "id": hit.id.to_string(),
            "mission": hit.mission.as_str(),
            "session": hit.session.as_str(),
            "pointer": [hit.pointer.0.as_str(), hit.pointer.1],
            "category": cat,
            "severity": hit.severity,
            "detail": hit.detail,
            "key": hit.key,
            "at_ms": hit.at_ms,
            "basis": hit.basis,
            "state": "shadow",
            "precision": hit.precision,
            "would": word(would),
        }));
        if hit.from_s1 {
            f.insert("from_s1".into(), Value::Bool(true));
        }
        // An entry the log would not take is held and written when it can (`recover`); the flag follows it either way.
        self.emit(EntryKind::Tripwire, f);
        if hit.severity >= Severity::S2 {
            self.flag(
                &hit.mission,
                &hit.session,
                hit.category,
                hit.severity,
                &hit.key,
                hit.id.to_string(),
                hit.at_ms,
                would,
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn flag(
        &mut self,
        mission: &MissionId,
        session: &SessionId,
        category: Category,
        severity: Severity,
        key: &str,
        cause: String,
        at_ms: u64,
        would: Response,
    ) {
        let cat = category.slug().to_string();
        let id = Core::flag_id(mission, &cat, key);
        let extra = self.flag_extra.remove(&id).unwrap_or(0);
        let old = self.fold.flags.get(&id).filter(|f| f.state == "open").cloned();
        let (rec, write, announce) = match old {
            Some(mut f) => {
                f.count = f.count.saturating_add(1).saturating_add(extra);
                let raised = severity > f.severity;
                f.severity = f.severity.max(severity);
                let new_cause = f.causes.insert(cause);
                f.last_ms = at_ms;
                let write = raised || new_cause || f.count.is_power_of_two();
                (f, write, raised)
            }
            None => (
                FlagRec {
                    flag: id,
                    mission: mission.clone(),
                    category: cat,
                    severity,
                    key: key.to_string(),
                    count: 1,
                    causes: [cause].into(),
                    state: "open".into(),
                    first_ms: at_ms,
                    last_ms: at_ms,
                    disposition: None,
                },
                true,
                true,
            ),
        };
        if !write {
            // The count is kept for the next write.
            self.fold.flags.insert(rec.flag.clone(), rec);
            return;
        }
        let causes: Vec<String> = rec.causes.iter().cloned().collect();
        let fields = obj(serde_json::to_value(&rec).unwrap_or(Value::Null));
        self.emit(EntryKind::Flag, fields);
        if announce {
            self.emit(
                EntryKind::Response,
                obj(serde_json::json!({
                    "level": "r0",
                    "mission": mission.as_str(),
                    "sessions": [session.as_str()],
                    "causes": causes,
                    "effects": [],
                    "would": word(would),
                    "state": "shadow",
                })),
            );
        }
    }

    fn on_fleet_hit(&mut self, h: FleetHit) {
        self.fleet_hits = self.fleet_hits.saturating_add(1);
        let Some(mission) = h.missions.first().cloned() else { return };
        let session = h.sessions.first().cloned().unwrap_or_else(|| SessionId::from(""));
        let join = serde_json::to_string(&h.join).unwrap_or_default().trim_matches('"').to_string();
        let would = if h.r5 { Response::R5Halt } else { Response::earned(h.severity, true) };
        let id = Core::flag_id(&mission, h.category.slug(), &h.key);
        let seen = self.fold.flags.get(&id).is_some_and(|f| f.state == "open" && f.causes.contains(&join));
        if h.severity >= Severity::S2 {
            self.flag(&mission, &session, h.category, h.severity, &h.key, join.clone(), h.at_ms, would);
        }
        if h.severity < Severity::S2 || seen {
            // A fleet finding below S2 is a record, like a tripwire's S1.
            self.emit(
                EntryKind::Response,
                obj(serde_json::json!({
                    "level": "r0",
                    "mission": mission.as_str(),
                    "sessions": h.sessions.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
                    "causes": [join],
                    "effects": [],
                    "would": word(would),
                    "state": "shadow",
                    "key": h.key,
                    "detail": h.detail,
                    "missions": h.missions.iter().map(|m| m.as_str()).collect::<Vec<_>>(),
                })),
            );
        }
    }

    // ---- authorization --------------------------------------------------------------------------------------------------

    fn mstate(&mut self, mission: &MissionId, pack: &str, role: &str) -> &mut MState {
        if !self.missions.contains_key(mission) {
            let env = self.env.clone();
            let p = env.pack(pack);
            let mut m = MState {
                dirty: true,
                pack: pack.to_string(),
                role: role.to_string(),
                facts: AuthFacts {
                    network_mode: env.network_mode.clone(),
                    allow: env.allow.clone(),
                    deny: env.deny.clone(),
                    solvable: p.solvable,
                    requires_restricted_network: p.requires_restricted_network,
                    live_targets: p.live_targets,
                    role: role.to_string(),
                    mcp_hosts: env.mcp_hosts(pack),
                    ..AuthFacts::default()
                },
                ..MState::default()
            };
            read_revoked(&self.paths, self.clock_ms, mission, &mut m);
            self.missions.insert(mission.clone(), m);
        }
        self.missions.entry(mission.clone()).or_default()
    }

    /// Read the revoked-hosts file of `mission` again when it changed (see `read_revoked`).
    fn refresh_revoked(&mut self, mission: &MissionId) {
        if let Some(m) = self.missions.get_mut(mission) {
            read_revoked(&self.paths, self.clock_ms, mission, m);
        }
    }

    /// The authorization in force for `mission` at `ts`.
    fn auth_for(&mut self, mission: &MissionId, ts: u64) -> Arc<Authorization> {
        let Some(m) = self.missions.get_mut(mission) else {
            return Arc::new(Authorization::build(
                mission,
                &[],
                ts,
                &AuthFacts {
                    network_mode: self.env.network_mode.clone(),
                    allow: self.env.allow.clone(),
                    deny: self.env.deny.clone(),
                    ..AuthFacts::default()
                },
            ));
        };
        let k = m.entries.iter().filter(|e| e.ts_ms <= ts).count();
        let msgs = m.facts.operator_messages.iter().filter(|(t, _)| *t <= ts).count();
        let revoked = m.facts.revoked.iter().filter(|(t, _)| *t <= ts).count();
        if let Some((ck, cm, cr, a)) = &m.cache {
            if *ck == k && *cm == msgs && *cr == revoked {
                return a.clone();
            }
        }
        let a = Arc::new(Authorization::build(mission, &m.entries, ts, &m.facts));
        m.cache = Some((k, msgs, revoked, a.clone()));
        a
    }

    /// Read a mission's journal again when a session of it wrote a ledger record (and once when it first appears).
    fn refresh_ledger(&mut self, mission: &MissionId, now: u64) {
        let key = self.journal_key.clone();
        let Some(m) = self.missions.get_mut(mission) else { return };
        if !m.dirty || now.saturating_sub(m.loaded_ms) < LEDGER_DEBOUNCE_MS && m.loaded_ms != 0 {
            return;
        }
        m.dirty = false;
        m.loaded_ms = now;
        m.read_once = true;
        let read = source::read_journal(&self.paths, mission, key.as_deref());
        if let Some(f) = read.fault {
            self.shared_faults.insert(format!("j:{}", mission.as_str()), f);
            return;
        }
        m.entries = read.entries;
        m.cache = None;
        let last = m.entries.last().map_or(0, |e| e.n);
        let cursor_key = format!("j:{}", mission.as_str());
        let from = match self.fold.cursors.get(&cursor_key) {
            Some(c) => c.seq,
            None => 0,
        };
        let fresh: Vec<LedgerEntry> = m.entries.iter().filter(|e| e.n > from).cloned().collect();
        if fresh.is_empty() {
            return;
        }
        for e in fresh {
            let ctx = self
                .srcs
                .values()
                .filter_map(|s| s.primed.as_ref())
                .find(|p| p.ctx.session == e.session)
                .map(|p| p.ctx.clone())
                .or_else(|| {
                    self.srcs
                        .values()
                        .filter_map(|s| s.primed.as_ref())
                        .find(|p| &p.ctx.mission == mission && p.ctx.parent.is_none())
                        .map(|p| p.ctx.clone())
                });
            let Some(ctx) = ctx else { continue };
            let auth = self.auth_for(mission, e.ts_ms);
            self.counts.ledger = self.counts.ledger.saturating_add(1);
            let hits = self.engine.ledger(&ctx, &e, &auth);
            for h in hits {
                self.on_hit(h);
            }
        }
        self.fold.cursors.insert(cursor_key.clone(), Cursor { off: 0, seq: last, hash: String::new() });
        self.dirty_cursors.insert(cursor_key);
    }

    /// The journal of `mission` read for the authorization of its first record (`auth_for`), without judging its
    /// entries: `refresh_ledger` judges them (`Engine::ledger`) once the pump has read its session logs, so an entry is
    /// judged after the records of the call that wrote it (a `security_ingest` result names the entry it wrote).
    fn load_ledger(&mut self, mission: &MissionId) {
        let key = self.journal_key.clone();
        let Some(m) = self.missions.get_mut(mission) else { return };
        m.read_once = true;
        let read = source::read_journal(&self.paths, mission, key.as_deref());
        // A journal that cannot be read is recorded by `refresh_ledger`.
        if read.fault.is_none() {
            m.entries = read.entries;
            m.cache = None;
        }
    }

    // ---- reading --------------------------------------------------------------------------------------------------------

    fn discover(&mut self) {
        for (name, dir) in source::list_sessions(&self.paths) {
            if self.srcs.contains_key(&name) {
                continue;
            }
            let log = dir.join("log.jsonl");
            let key = format!("s:{name}");
            let nkey = format!("n:{name}");
            let (mut cur, mut net) = (self.fold.cursors.get(&key).cloned(), self.fold.cursors.get(&nkey).cloned());
            if self.first_start && cur.is_none() {
                cur = Some(source::first_start_cursor(&log));
                net = Some(source::first_start_cursor(&dir.join("net.jsonl")));
                self.dirty_cursors.insert(key.clone());
                self.dirty_cursors.insert(nkey.clone());
            }
            let cur = cur.unwrap_or_default();
            let net = net.unwrap_or_default();
            if cur.off > 0 && !self.fold.cursors.contains_key(&key) {
                self.fold.cursors.insert(key.clone(), cur.clone());
            }
            self.srcs.insert(
                name.clone(),
                Src {
                    dir,
                    cur,
                    net_judged: net.clone(),
                    net,
                    primed: None,
                    skip_below: 0,
                    pending_net: VecDeque::new(),
                    fault: None,
                    net_fault: None,
                    last_ts: 0,
                },
            );
        }
    }

    fn prime(&mut self, name: &str) -> bool {
        let Some(src) = self.srcs.get(name) else { return false };
        if src.primed.is_some() {
            return true;
        }
        let Some(p) = source::prime(&src.dir, name) else { return false };
        // A switch onto a relaxed model that a checkpoint passed before a restart is not read again: the fold keeps it.
        let relaxed =
            p.ctx.relaxed || self.env.relaxed_profiles.contains(&p.profile) || self.fold.relaxed.contains(name);
        let mut ctx = p.ctx.clone();
        ctx.relaxed = relaxed;
        let mission = ctx.mission.clone();
        let (pack, role) = (ctx.pack.clone(), ctx.role.clone());
        let prior = p.prior.clone();
        self.engine.set_ctx(ctx.clone());
        self.engine.started_at(&ctx.session, p.started_ms);
        let resumed = self.srcs.get(name).map_or(0, |s| s.cur.off);
        if resumed > 0 {
            // A restart that resumes past the session's `bash` results learns where they left the shell.
            let log = self.srcs.get(name).map(|s| s.dir.join("log.jsonl"));
            let dir = log.and_then(|l| source::last_shell_dir(&l, resumed));
            self.engine.set_shell_dir(&ctx.session, dir);
        }
        if resumed > 0 && self.started_ms > 0 {
            // Read before (or begun at its end): what was in flight at the start is not known.
            self.engine.blind_until(&ctx.session, self.started_ms.saturating_add(RESTART_BLIND_MS));
        }
        let target = p.target.clone();
        let credentials = p.credentials.clone();
        let mcp_hosts = self.env.mcp_hosts(&pack);
        let ms = self.mstate(&mission, &pack, &role);
        if ms.prior.is_empty() && !prior.is_empty() {
            ms.prior = prior.clone();
        }
        if ctx.parent.is_none() {
            ms.facts.mcp_hosts = mcp_hosts;
            ms.pack = pack;
            ms.role = role;
        }
        // The mission's target (recorded at its lead's start, inherited by every agent) is the operator's scope.
        if let Some(t) = target {
            if (&ms.facts.target_scope, &ms.facts.target_exclude) != (&t.scope, &t.exclude) {
                ms.facts.target_scope = t.scope;
                ms.facts.target_exclude = t.exclude;
                ms.cache = None;
            }
        }
        // And the credential profiles the operator attached to it (main's multi-principal profiles): names and
        // redaction-safe summaries only.
        if !credentials.is_empty() && ms.facts.credentials != credentials {
            ms.facts.credentials = credentials;
            ms.cache = None;
        }
        if !prior.is_empty() {
            self.engine.fleet.set_prior(&mission, prior);
        }
        if let Some(src) = self.srcs.get_mut(name) {
            src.skip_below = p.skip_below;
            src.primed = Some(Primed { ctx, ..p });
        }
        true
    }

    /// Read what is new in the log of session `name` (at most `PASSES` reads): (whether a cursor moved, whether the log
    /// was read to its end). Its net decisions are judged apart (`pump_net`), after every log the pump reads.
    fn pump_session(&mut self, name: &str) -> (bool, bool) {
        if !self.prime(name) {
            return (false, false);
        }
        let mut progress = false;
        let mut caught_up = false;
        for _ in 0..PASSES {
            let Some(src) = self.srcs.get(name) else { return (progress, caught_up) };
            if src.fault.is_some() {
                break;
            }
            let read = source::read_session(&src.dir.join("log.jsonl"), &src.cur);
            let mut skip_below = src.skip_below;
            let mut ctx = match src.primed.as_ref() {
                Some(p) => p.ctx.clone(),
                None => return (progress, caught_up),
            };
            self.counts.opaque = self.counts.opaque.saturating_add(read.opaque);
            let key = format!("s:{name}");
            let more = read.more;
            let n = read.records.len();
            let newest = read.records.iter().map(|r| r.ts_ms).max().unwrap_or(0);
            for rec in &read.records {
                self.counts.records = self.counts.records.saturating_add(1);
                self.clock_ms = self.clock_ms.max(rec.ts_ms);
                // The child's own `forked` record ends the parent's copy, so it is judged before the skip test: a
                // child primed between its copy and that record (the fork writes them apart) is read from here on.
                let mut skip = rec.seq < skip_below;
                if let Event::Forked(f) = &rec.event {
                    if f.session.as_str() == name {
                        if let Some(src) = self.srcs.get_mut(name) {
                            if src.skip_below == u64::MAX {
                                src.skip_below = rec.seq;
                                skip_below = rec.seq;
                            }
                        }
                        skip = false;
                        ctx.role = f.role.clone();
                        ctx.parent = Some(f.parent.clone());
                        self.engine.set_ctx(ctx.clone());
                    }
                }
                // A switch onto a relaxed-alignment model uptiers the session from here on, as its `session_start` would
                // have; a switch off one does not lower it, since its context holds what the relaxed model wrote. Read
                // in the parent's copy too: a fork runs on the model its parent had when it was made.
                if let Event::ModelSwitched(m) = &rec.event {
                    if !ctx.relaxed && self.switched_to_relaxed(m) {
                        ctx.relaxed = true;
                        self.engine.set_ctx(ctx.clone());
                        // Checkpointed with the cursor that passes this record, so a restart keeps it.
                        self.new_relaxed.insert(name.to_string());
                    }
                }
                if skip {
                    continue;
                }
                self.observe(&mut ctx, rec, name);
            }
            if let Some(src) = self.srcs.get_mut(name) {
                if read.cursor != src.cur {
                    src.cur = read.cursor.clone();
                    self.fold.cursors.insert(key.clone(), read.cursor);
                    self.dirty_cursors.insert(key.clone());
                    progress = true;
                }
                src.last_ts = src.last_ts.max(newest);
                if let Some(f) = read.fault {
                    src.fault = Some(f.clone());
                    self.shared_faults.insert(key.clone(), f.clone());
                    self.emit(EntryKind::Cursor, obj(serde_json::json!({"cursors": {}, "fault": f, "source": key})));
                }
            }
            if let Some(p) = self.srcs.get_mut(name).and_then(|s| s.primed.as_mut()) {
                p.ctx = ctx.clone();
            }
            if !more || n == 0 {
                caught_up = true;
                break;
            }
        }
        (progress, caught_up)
    }

    /// The model a `model_switched` moved to is relaxed-alignment: by the lineage it was recorded with, or by the
    /// configuration's profiles as `prime` reads them.
    fn switched_to_relaxed(&self, m: &ferret_core::event::ModelSwitched) -> bool {
        m.to.lineage.as_ref().is_some_and(|l| l.alignment == ferret_core::lineage::Alignment::Relaxed)
            || self.env.relaxed_profiles.contains(&m.to.profile)
    }

    fn observe(&mut self, ctx: &mut SessionCtx, rec: &ferret_core::event::Record, name: &str) {
        let mission = ctx.mission.clone();
        // Operator words are authorization.
        if matches!(rec.author, Author::User) {
            let text = match &rec.event {
                // The echo of an answered item carries the agent's own text in its header; only the operator's
                // answer is authorization (the answer itself is in `InboxResolved`).
                Event::UserMessage { text, .. } => Some(crate::texts::without_inbox_echo(text).to_string()),
                Event::InboxResolved { answer, .. } => Some(answer.clone()),
                _ => None,
            };
            if let Some(t) = text.filter(|t| !t.is_empty()) {
                let m = self.mstate(&mission, &ctx.pack.clone(), &ctx.role.clone());
                m.facts.operator_messages.push((rec.ts_ms, t));
                m.cache = None;
            }
        }
        match &rec.event {
            Event::Ledger { .. } => {
                let m = self.mstate(&mission, &ctx.pack.clone(), &ctx.role.clone());
                m.dirty = true;
            }
            Event::BudgetClock { running } => {
                let a = self.activity.entry(mission.clone()).or_default();
                if *running {
                    a.running.insert(name.to_string(), rec.ts_ms);
                } else if let Some(t0) = a.running.remove(name) {
                    a.clock_ms = a.clock_ms.saturating_add(rec.ts_ms.saturating_sub(t0));
                }
            }
            _ => {}
        }
        {
            let a = self.activity.entry(mission.clone()).or_default();
            if let Some(prev) = a.last.insert(name.to_string(), rec.ts_ms) {
                let gap = rec.ts_ms.saturating_sub(prev);
                if gap < 10 * 60 * 1000 {
                    a.gap_ms = a.gap_ms.saturating_add(gap);
                }
            }
        }
        if self.missions.get(&mission).is_some_and(|m| m.loaded_ms == 0 && !m.read_once) {
            self.load_ledger(&mission);
        }
        let auth = self.auth_for(&mission, rec.ts_ms);
        let hits = self.engine.record(ctx, rec, &auth, &self.fold);
        for h in hits {
            self.on_hit(h);
        }
    }

    fn pump_net(&mut self, name: &str, horizon: u64, replay: bool) {
        let Some(src) = self.srcs.get_mut(name) else { return };
        if src.net_fault.is_none() {
            for _ in 0..PASSES {
                let read = source::read_net(&src.dir.join("net.jsonl"), &src.net);
                let more = read.more;
                let n = read.entries.len();
                src.pending_net.extend(read.entries.into_iter().zip(read.ends));
                self.counts.net = self.counts.net.saturating_add(n as u64);
                src.net = read.cursor.clone();
                if let Some(f) = read.fault {
                    src.net_fault = Some(f.clone());
                    self.shared_faults.insert(format!("n:{name}"), f);
                    break;
                }
                if !more || n == 0 {
                    break;
                }
            }
        }
        let Some(ctx) = self.srcs.get(name).and_then(|s| s.primed.as_ref()).map(|p| p.ctx.clone()) else { return };
        loop {
            let ready = self
                .srcs
                .get(name)
                .and_then(|s| s.pending_net.front())
                .is_some_and(|(e, _)| replay || e.ts_ms.saturating_add(IDLE_GRACE_MS) <= horizon);
            if !ready {
                break;
            }
            let Some((e, after)) = self.srcs.get_mut(name).and_then(|s| s.pending_net.pop_front()) else { break };
            if let Some(src) = self.srcs.get_mut(name) {
                src.net_judged = after;
            }
            self.clock_ms = self.clock_ms.max(e.ts_ms);
            if let Some(src) = self.srcs.get_mut(name) {
                src.last_ts = src.last_ts.max(e.ts_ms);
            }
            let auth = self.auth_for(&ctx.mission, e.ts_ms);
            let hits = self.engine.net(&ctx, e.ts_ms, &e.decision, &auth, &self.fold);
            for h in hits {
                self.on_hit(h);
            }
        }
        // A checkpoint says only what was judged: decisions that wait out their grace are read again after a restart.
        let key = format!("n:{name}");
        if let Some(src) = self.srcs.get_mut(name) {
            let at = if src.pending_net.is_empty() { src.net.clone() } else { src.net_judged.clone() };
            if self.fold.cursors.get(&key) != Some(&at)
                && (at != Cursor::default() || self.fold.cursors.contains_key(&key))
            {
                src.net_judged = at.clone();
                self.fold.cursors.insert(key.clone(), at);
                self.dirty_cursors.insert(key);
            }
        }
    }

    fn pump_floor(&mut self) {
        let floor = self.paths.logs_dir().join("floor.jsonl");
        let read = source::read_floor(&floor, &self.floor_cur);
        for ev in read.events {
            self.counts.floor = self.counts.floor.saturating_add(1);
            let session = SessionId::from(ev.session.clone().unwrap_or_default());
            let (ctx, mission) = match self.srcs.get(session.as_str()).and_then(|s| s.primed.as_ref()) {
                Some(p) => (Some(p.ctx.clone()), p.ctx.mission.clone()),
                None => (None, MissionId::from("unattributed")),
            };
            let hits = self.engine.floor(ctx.as_ref(), &mission, &session, ev.at_ms, &ev.kind, &ev.label, &ev.detail);
            for h in hits {
                self.on_hit(h);
            }
        }
        if read.cursor != self.floor_cur {
            self.floor_cur = read.cursor.clone();
            self.fold.cursors.insert("f".into(), read.cursor);
            self.dirty_cursors.insert("f".into());
        }
        if let Some(f) = read.fault {
            self.shared_faults.insert("f".into(), f);
        }
    }

    fn pump_unattributed(&mut self) {
        let path = self.paths.logs_dir().join("net-unattributed.jsonl");
        let read = source::read_net(&path, &self.unattr_cur);
        for e in &read.entries {
            self.counts.unattributed = self.counts.unattributed.saturating_add(1);
            let d = &e.decision;
            if !d.allowed && d.rule.starts_with("deny infrastructure")
                || d.allowed && d.rule.starts_with("deny infrastructure")
            {
                let hits = self.engine.floor(
                    None,
                    &MissionId::from("unattributed"),
                    &SessionId::from(""),
                    e.ts_ms,
                    "infrastructure",
                    &d.host,
                    &format!("{} {}:{} ({})", d.method, d.host, d.port, d.rule),
                );
                for h in hits {
                    self.on_hit(h);
                }
            }
        }
        if read.cursor != self.unattr_cur {
            self.unattr_cur = read.cursor.clone();
            self.fold.cursors.insert("u".into(), read.cursor);
            self.dirty_cursors.insert("u".into());
        }
        if let Some(f) = read.fault {
            self.shared_faults.insert("u".into(), f);
        }
    }

    /// The last process census (TW-20, the fleet's listeners).
    pub fn census(&mut self, view: &CensusView, now: u64) {
        let ctxs: BTreeMap<String, SessionCtx> =
            self.srcs.iter().filter_map(|(n, s)| s.primed.as_ref().map(|p| (n.clone(), p.ctx.clone()))).collect();
        let hits = self.engine.census(view, now, &ctxs);
        for h in hits {
            self.on_hit(h);
        }
    }

    // ---- the pump -------------------------------------------------------------------------------------------------------

    fn start(&mut self, now: u64) {
        if self.started {
            return;
        }
        self.started = true;
        self.started_ms = now;
        self.discover();
        self.last_discover = now;
        if self.first_start {
            for m in source::list_missions(&self.paths) {
                let key = format!("j:{}", m.as_str());
                let last = source::last_entry_n(&self.paths.journal(&m));
                self.fold.cursors.insert(key.clone(), Cursor { off: 0, seq: last, hash: String::new() });
                self.dirty_cursors.insert(key);
            }
            let floor = self.paths.logs_dir().join("floor.jsonl");
            self.floor_cur = source::first_start_cursor(&floor);
            self.unattr_cur = source::first_start_cursor(&self.paths.logs_dir().join("net-unattributed.jsonl"));
            self.fold.cursors.insert("f".into(), self.floor_cur.clone());
            self.fold.cursors.insert("u".into(), self.unattr_cur.clone());
            self.dirty_cursors.insert("f".into());
            self.dirty_cursors.insert("u".into());
            self.first_start = false;
        } else {
            self.floor_cur = self.fold.cursors.get("f").cloned().unwrap_or_default();
            self.unattr_cur = self.fold.cursors.get("u").cloned().unwrap_or_default();
        }
    }

    /// One pass (see the contract). `hints` are session directory names that wrote something; `full` reads every source.
    pub fn pump(&mut self, now: u64, hints: &BTreeSet<String>, full: bool) -> bool {
        if self.is_down().is_some() && !self.recover(now) {
            return false;
        }
        self.start(now);
        self.heartbeat_ms = now;
        if full || now.saturating_sub(self.last_discover) >= DISCOVER_EVERY_MS {
            self.discover();
            self.last_discover = now;
        }
        for h in hints {
            if !self.srcs.contains_key(h) {
                self.discover();
                break;
            }
        }
        let mut names: Vec<String> = if full || now.saturating_sub(self.last_checkpoint) >= DISCOVER_EVERY_MS * 3 {
            self.srcs.keys().cloned().collect()
        } else {
            hints.iter().filter(|h| self.srcs.contains_key(*h)).cloned().collect()
        };
        // The operator's revokes reach no session's log as a ledger record: the mission's revoked-hosts file is looked
        // at before its sessions' records are judged.
        let watched: BTreeSet<MissionId> = names
            .iter()
            .filter_map(|n| self.srcs.get(n).and_then(|s| s.primed.as_ref()).map(|p| p.ctx.mission.clone()))
            .collect();
        for m in &watched {
            self.refresh_revoked(m);
        }
        // With the box proxy bridge, a decision of the session the bridge carries is judged against the box calls and
        // jobs of every session of its mission: they are all read in this pump, before any decision is judged.
        if self.env.box_bridge {
            let siblings: Vec<String> = self
                .srcs
                .iter()
                .filter(|(n, s)| {
                    !names.contains(*n) && s.primed.as_ref().is_some_and(|p| watched.contains(&p.ctx.mission))
                })
                .map(|(n, _)| n.clone())
                .collect();
            names.extend(siblings);
        }
        let mut progress = false;
        let before = self.fold.last_seq;
        if full {
            // A session that has been quiet for an hour gives its memory back; its identity stays, and what it needs
            // is made again from its next record.
            let quiet: Vec<SessionId> = self
                .srcs
                .values()
                .filter(|s| now.saturating_sub(s.last_ts) > QUIET_FREE_MS)
                .filter_map(|s| s.primed.as_ref().map(|p| p.ctx.session.clone()))
                .collect();
            for id in quiet {
                self.engine.drop_session(&id);
            }
        }
        // Every log first, then the net decisions of the sessions read to their end: a decision is judged after its own
        // session's log and, with the bridge, after its mission's other sessions (a child's log sorts after its lead's).
        // With the bridge, a mission one of whose sessions still has more to read waits for a later pump.
        let mut caught: Vec<String> = Vec::new();
        let mut behind: BTreeSet<MissionId> = BTreeSet::new();
        for n in &names {
            let (moved, done) = self.pump_session(n);
            progress |= moved;
            if done {
                caught.push(n.clone());
            } else if let Some(p) = self.srcs.get(n).filter(|s| s.fault.is_none()).and_then(|s| s.primed.as_ref()) {
                behind.insert(p.ctx.mission.clone());
            }
        }
        for n in &caught {
            let held = self.env.box_bridge
                && self.srcs.get(n).and_then(|s| s.primed.as_ref()).is_some_and(|p| behind.contains(&p.ctx.mission));
            self.pump_net(n, if held { 0 } else { now }, false);
        }
        self.pump_floor();
        self.pump_unattributed();
        let missions: Vec<MissionId> = self.missions.iter().filter(|(_, m)| m.dirty).map(|(k, _)| k.clone()).collect();
        for m in missions {
            self.refresh_ledger(&m, now);
        }
        if now.saturating_sub(self.last_fleet) >= self.fleet_every_ms {
            self.last_fleet = now;
            self.run_fleet(now);
        }
        self.backlog_since = if progress { self.backlog_since.or(Some(now)) } else { None };
        self.housekeeping(now, before);
        progress
    }

    /// The fleet joins now.
    pub fn run_fleet(&mut self, now: u64) {
        self.fleet_runs = self.fleet_runs.saturating_add(1);
        let hits = self.engine.fleet.joins(now);
        for h in hits {
            self.on_fleet_hit(h);
        }
    }

    fn housekeeping(&mut self, now: u64, before_seq: u64) {
        if self.log.is_none() {
            self.engine.take_new_secrets();
            self.new_relaxed.clear();
            return;
        }
        let wrote = self.fold.last_seq != before_seq;
        let pending = !self.dirty_cursors.is_empty() || self.engine.has_new_secrets() || !self.new_relaxed.is_empty();
        if pending && (wrote || now.saturating_sub(self.last_checkpoint) >= CHECKPOINT_EVERY_MS) {
            let mut map = Map::new();
            for k in std::mem::take(&mut self.dirty_cursors) {
                if let Some(c) = self.fold.cursors.get(&k) {
                    map.insert(k, serde_json::to_value(c).unwrap_or(Value::Null));
                }
            }
            let secrets: Vec<Value> = self
                .engine
                .take_new_secrets()
                .into_iter()
                .map(|(tag, mission, ts)| serde_json::json!([tag, mission, ts]))
                .collect();
            let mut f = obj(serde_json::json!({ "cursors": map }));
            if !secrets.is_empty() {
                f.insert("secrets".into(), Value::Array(secrets));
            }
            let relaxed: Vec<Value> = std::mem::take(&mut self.new_relaxed).into_iter().map(Value::String).collect();
            if !relaxed.is_empty() {
                f.insert("relaxed".into(), Value::Array(relaxed));
            }
            self.emit(EntryKind::Cursor, f);
            self.last_checkpoint = now;
        }
        if now.saturating_sub(self.last_log_heartbeat) >= HEARTBEAT_LOG_MS {
            self.last_log_heartbeat = now;
            self.emit(EntryKind::Heartbeat, Map::new());
        }
    }

    /// Everything, until nothing is new (a replay, or a test). The clock is that of the newest record.
    pub fn drain(&mut self) {
        self.start(0);
        let mut guard = 0u32;
        loop {
            self.discover();
            let names: Vec<String> = self.srcs.keys().cloned().collect();
            let mut progress = false;
            let mut caught: Vec<String> = Vec::new();
            for n in &names {
                let (moved, done) = self.pump_session(n);
                progress |= moved;
                if done {
                    caught.push(n.clone());
                }
            }
            guard = guard.saturating_add(1);
            let last = !progress || guard > 10_000;
            // The net decisions once every log has been read to its end: a lead's log sorts before its children's, and
            // with the box proxy bridge its decisions are judged against their box calls.
            if last {
                for n in &caught {
                    // Each call reads at most `PASSES` chunks of the file: on until its cursor stays.
                    for _ in 0..10_000 {
                        let before = self.srcs.get(n).map(|s| s.net.clone());
                        self.pump_net(n, u64::MAX, true);
                        if self.srcs.get(n).map(|s| s.net.clone()) == before {
                            break;
                        }
                    }
                }
            }
            self.pump_floor();
            self.pump_unattributed();
            let missions: Vec<MissionId> = self.missions.keys().cloned().collect();
            for m in missions {
                if self.missions.get(&m).is_some_and(|s| s.dirty) {
                    if let Some(s) = self.missions.get_mut(&m) {
                        s.loaded_ms = 0;
                    }
                    self.refresh_ledger(&m, 1);
                }
            }
            if last {
                break;
            }
        }
        // A replay reads the whole history, so the joins read it too (the live ones read the last window).
        self.fleet_runs = self.fleet_runs.saturating_add(1);
        let now = self.clock_ms;
        let hits = self.engine.fleet.joins_over_history(now);
        for h in hits {
            self.on_fleet_hit(h);
        }
    }

    /// Active time of a mission in milliseconds: the budget clock when the mission has one, else the sum of the gaps
    /// between records shorter than 10 minutes.
    pub fn active_ms(&self, mission: &MissionId) -> u64 {
        self.activity.get(mission).map_or(0, |a| if a.clock_ms > 0 { a.clock_ms } else { a.gap_ms })
    }

    /// Every mission the core has seen, with its pack and the session names.
    pub fn missions(&self) -> BTreeMap<MissionId, String> {
        self.missions.iter().map(|(k, v)| (k.clone(), v.pack.clone())).collect()
    }

    pub fn counts(&self) -> &Counts {
        &self.counts
    }

    pub fn status(&self, enabled: bool, mode: &str) -> MonitorStatus {
        let tripwires: Vec<TwStatus> = TRIPWIRES
            .iter()
            .map(|t| {
                let stat = self.fold.stats.get(&t.number);
                TwStatus {
                    id: TripwireId::of(t.number).to_string(),
                    name: t.name.to_string(),
                    start: match t.start {
                        Start::Precision => "precision",
                        Start::Mixed => "mixed",
                        Start::Shadow => "shadow",
                    }
                    .into(),
                    state: "shadow".into(),
                    fired: stat.map_or(0, |s| s.fired),
                    by_severity: stat.map_or([0; 5], |s| s.by_severity),
                    missions: stat.map_or(0, |s| s.missions.len() as u64),
                }
            })
            .collect();
        let faults: Vec<String> = self.shared_faults.values().cloned().collect();
        let down = self.is_down().map(str::to_string);
        let state = if down.is_some() {
            "down"
        } else if !faults.is_empty() {
            "degraded"
        } else {
            "shadow"
        };
        MonitorStatus {
            state: state.into(),
            mode: mode.into(),
            enabled,
            egress_unbounded: self.egress_unbounded,
            open_flags: self.fold.open_flags().count() as u64,
            paused: self.fold.paused.keys().map(|m| m.as_str().to_string()).collect(),
            halts: self.fold.halts.iter().cloned().collect(),
            backlog_s: self.backlog_since.map_or(0, |t| self.heartbeat_ms.saturating_sub(t) / 1000),
            heartbeat_ms: self.heartbeat_ms,
            last_seq: self.fold.last_seq,
            sources: self.srcs.len() as u64,
            counts: self.counts.clone(),
            tripwires,
            faults,
            fleet_runs: self.fleet_runs,
            fleet_hits: self.fleet_hits,
            reviewers: Vec::new(),
            down_reason: down,
        }
    }
}

/// Read the revoked-hosts file of `mission` (`<mission dir>/scope_revoked.json`, which the runtime's `revoke_scope`
/// and `grant_scope` write) into `m` when it changed since the last read (its length and time), or on the first read.
/// An entry new to the list is in force from the time the file was written (`clock_ms`, the newest record's time,
/// when the time cannot be read), one already known keeps its time, one that is gone (granted again) leaves. A change
/// after the first read marks the journal to be read again: a revoke of a recorded grant appended `ScopeRevoke` to it,
/// which no session's log announces with a `ledger` record.
fn read_revoked(paths: &Paths, clock_ms: u64, mission: &MissionId, m: &mut MState) {
    let path = crate::runtime::revoked_hosts_path(paths, mission);
    let meta = std::fs::metadata(&path).ok();
    let stamp = meta.as_ref().map(|md| (md.len(), md.modified().ok()));
    if m.revoked_read && m.revoked_stamp == stamp {
        return;
    }
    let first = !m.revoked_read;
    m.revoked_read = true;
    m.revoked_stamp = stamp;
    let hosts = if stamp.is_some() { crate::runtime::load_revoked(&path) } else { Vec::new() };
    let written = stamp
        .and_then(|(_, t)| t)
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(clock_ms, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let revoked: Vec<(u64, String)> = hosts
        .into_iter()
        .map(|h| {
            let since = m.facts.revoked.iter().find(|(_, x)| x.eq_ignore_ascii_case(&h)).map_or(written, |(t, _)| *t);
            (since, h)
        })
        .collect();
    if revoked != m.facts.revoked {
        m.facts.revoked = revoked;
        m.cache = None;
    }
    if !first {
        m.dirty = true;
    }
}

#[cfg(test)]
mod tests;
