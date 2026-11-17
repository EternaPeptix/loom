//! The monitor log: `<home>/monitor/log.jsonl`, the monitor's only durable state (`docs/MONITOR.md` §2.1, §7.3).
//!
//! CONTRACT.
//!
//! - Files, under the loom home: `monitor/log.jsonl` (0600, append-only), `monitor/inputs/<sha256>` (the exact rendered
//!   input of each review, content-addressed, 0600; made by M6), `monitor/reserve` (preallocated with `RESERVE_BYTES`
//!   of zeros, so a pause record can be written on a full disk), `monitor/first-start` (written with the key),
//!   `keys/monitor.key` (0600, the HMAC key; created beside `keys/journal.key`) and `keys/monitor.anchor` (the last
//!   `seq` and `mac`, rewritten after every append). The directory is 0700. The sandbox hides all of it from commands
//!   and the file tools refuse it (#34); review blobs are outside every mission's output index (#36).
//! - An `Entry` has `seq` (from 1, gapless), `ts_ms`, `prev` (the previous entry's `mac`; 64 zeros for the first),
//!   `mac` (HMAC-SHA256 under `monitor.key` over the entry's canonical JSON with `mac` empty, hex), `kind`
//!   (`EntryKind::slug`) and the kind's own fields flattened beside them. The kinds and their fields are those of
//!   `docs/MONITOR.md` §7.3: `cursor`, `heartbeat`, `selfprobe`, `review_requested`, `verdict`, `tripwire`, `flag`,
//!   `response`, `pause`, `halt`, `halt_cleared`, `disposition`, `allow_rule`, `annotation`, `keep_going_set`,
//!   `keep_going`, `promotion`, `observe_only`, `vet` (19). A reader that meets another kind reads it as
//!   `EntryKind::Unknown` (not in `ALL`, written as `unknown`), verifies its MAC over the line's own bytes, keeps the
//!   line and ignores it, so a newer monitor's log stays readable (additive, like `Event::Unknown`). A kind's own field
//!   names never equal one of the five `RESERVED_FIELDS` (`seq`, `ts_ms`, `prev`, `mac`, `kind`), which would collide
//!   with the flattened discriminator: `review_requested` names its scope `scope` (gate, step, tree or fleet), and
//!   `check_fields` refuses a reserved name before an append.
//! - The M2 records, each beside the fields of §7.3 (every extra field is additive):
//!   `cursor{cursors: {source: {off, seq, hash}}}` where a source is `s:<session>` (a session log: byte offset, last
//!   seq, SHA-256 of the last line), `n:<session>` (a `net.jsonl`: byte offset, line count, hash), `u` (`net-unattributed`),
//!   `f` (`floor.jsonl`) or `j:<mission>` (a journal: the last entry number in `seq`); `heartbeat{torn_bytes?}`;
//!   `tripwire{id, mission, session, pointer: [session, seq], category, severity, detail, key, at_ms, basis, state,
//!   precision, would, from_s1}` where `state` is `shadow` (nothing enforces before M4) and `would` is the response the severity
//!   earns once the cause is promoted (`r0` to `r4`); `flag{flag, mission, category, severity, key, count, causes,
//!   state, first_ms, last_ms}` (the whole current record, so the latest entry of a flag id is the flag); `response{level,
//!   mission, sessions, causes, effects, would}`; `selfprobe{probe, result}`.
//! - The pause and halt entries fold as follows. `pause{mission, flag, phase}`: a mission is paused while it has at
//!   least one open flag; `begun` and `applied` open the flag, `lifted` closes only its own flag. `halt{cohort, reason,
//!   client}` and `halt_cleared{cohort, client}`: halts are a set of cohorts (`respond::Cohort`); `halt_cleared` removes
//!   only its own cohort. A `pause` or `halt` whose mission or cohort cannot be read is kept as the widest reading
//!   (flag `""`, cohort `all`); a `halt_cleared` that cannot be read clears nothing.
//! - `MonitorLog::open` folds the whole log into a `Fold` before returning (periodic fold snapshots are deferred: the log
//!   holds hits and checkpoints, not records), and fails with `Unavailable` when a `mac`, a `prev` or a `seq` does not
//!   verify: the monitor is then **down** (§2.8). Down does not lift a pause: the fold also replays `monitor/reserve`
//!   (the pause and halt entries written there while the log was unwritable, each sealed under the key) before
//!   activation, moves them into the log and clears the reserve, and when the fold cannot be built at all (a bad MAC, an
//!   unreadable log or reserve, a log shorter than the last seq anchored in `keys/monitor.anchor`, or a missing log
//!   when `monitor/first-start` was written with the key) the runtime holds **every mission that has any pause or halt
//!   record, and every mission when it cannot tell, whatever `monitor_down` says**, until the operator acknowledges
//!   (`loom monitor ack-down`, M3). A missing log with no `first-start` marker is a first start. The fold derives the
//!   open flags, the cursors, the per-mission tripwire history, the paused and halted sets, the allow rules, the
//!   keep-going state, the promotions and the open reviews. It is a hard barrier: the runtime activates no session
//!   before it is done (I9).
//! - `append` writes one entry, syncs it, and only then returns; a write that works after a failed one lifts the down
//!   state (a full disk is not forever) when the reserve holds nothing; a pause, halt or halt-cleared entry that cannot be
//!   written to the log is written to the reserve file, the entry is applied to no state, and the monitor goes down
//!   (`monitor_down`, `is_down`). Appending is the single point at which state changes: nothing is applied before the
//!   entry that records it (write-ahead). A failed write of any kind is truncated back, so the log never keeps half an
//!   entry.
//! - A torn last line (bytes after the last newline that are not an entry) is cut at open and recorded by a `heartbeat`
//!   with `torn_bytes`.
//! - First-start cursors begin at the end of each source log (the monitor core does this when the fold has no cursor at
//!   all and the first-start marker was just written), so the first run raises no retroactive pause.
//! - A `cursor` entry may carry `secrets: [[tag, mission, ts_ms], ...]`: the hashed credential values that missions'
//!   results showed since the last checkpoint (TW-06). The fold keeps them as a `SecretIndex` (30 days; at most
//!   `SECRETS_PER_MISSION` per mission, the oldest of that mission first), so a restart keeps the index.
//! - A restart marks every review that was requested and has no verdict `fault: restart`; that is not counted (I10).
//!
//! Built by: M2 (open, fold, append, heartbeat, reserve, anchor); M3 (pause and halt entries are applied through
//! `Inner::may_run`).
//!
//! Tests required (M2): the kinds list is exactly the 19 above; append then open reproduces the fold; a flipped byte,
//! a deleted middle entry or a swapped order fails the open with `Unavailable`; a torn last line is cut and recorded;
//! the reserve file takes a pause entry when the disk write fails and a restart replays it into the fold (the mission
//! stays paused, also when the log is still unwritable); a truncated tail and a deleted log are detected against the
//! anchor and the first-start marker; a failed fold holds every mission that has a pause or halt record; a write-ahead
//! `pause{begun}` folds to paused even with no `applied`; an unknown kind is kept and skipped; the tripwire history,
//! flags and cursors fold back; a request with no verdict gets `fault: restart`.
//! In P0: `entry_kinds_are_the_nineteen`, `an_entry_round_trips_with_its_fields_flattened`,
//! `no_field_of_the_spec_collides_with_the_entry_envelope`, `review_requested_round_trips_with_scope`,
//! `an_unknown_kind_is_read_as_unknown`, `a_pause_holds_until_every_flag_is_lifted`,
//! `a_halt_holds_its_cohort_and_clear_halt_clears_only_that_cohort`.

use crate::monitor::respond::{Cohort, Membership};
use crate::monitor::taxonomy::Severity;
use crate::monitor::MonitorError;
use loom_core::MissionId;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};

/// The directory under the loom home.
pub const DIR: &str = "monitor";
pub const LOG_FILE: &str = "log.jsonl";
pub const INPUTS_DIR: &str = "inputs";
pub const RESERVE_FILE: &str = "reserve";
pub const FIRST_START_FILE: &str = "first-start";
/// The key file under `<home>/keys`.
pub const KEY_FILE: &str = "monitor.key";
/// The anchor file under `<home>/keys`.
pub const ANCHOR_FILE: &str = "monitor.anchor";
/// The `prev` of the first entry.
pub const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// The size of the reserve file.
pub const RESERVE_BYTES: u64 = 64 * 1024;
/// How many recent hits per (mission, tripwire) the fold keeps.
pub const HIT_HISTORY: usize = 256;
/// How many distinct keys per (mission, tripwire) the fold keeps.
pub const HIT_KEYS: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    Cursor,
    Heartbeat,
    Selfprobe,
    ReviewRequested,
    Verdict,
    Tripwire,
    Flag,
    Response,
    Pause,
    Halt,
    HaltCleared,
    Disposition,
    AllowRule,
    Annotation,
    KeepGoingSet,
    KeepGoing,
    Promotion,
    ObserveOnly,
    Vet,
    /// A kind this build does not know (a newer monitor's log): kept and skipped. Not in `ALL`.
    #[serde(other)]
    Unknown,
}

/// Field names of the entry envelope. No kind's own field may use one, because the fields are flattened beside them.
pub const RESERVED_FIELDS: [&str; 5] = ["seq", "ts_ms", "prev", "mac", "kind"];

/// Refuse `fields` that name an envelope field, with the sentence that says what to rename.
pub fn check_fields(fields: &Map<String, Value>) -> Result<(), MonitorError> {
    match RESERVED_FIELDS.iter().find(|r| fields.contains_key(**r)) {
        Some(r) => Err(MonitorError::Invalid(format!(
            "The monitor-log field \"{r}\" is the entry's own; give the record's field another name (review_requested uses `scope`)."
        ))),
        None => Ok(()),
    }
}

impl EntryKind {
    pub const ALL: [EntryKind; 19] = [
        EntryKind::Cursor,
        EntryKind::Heartbeat,
        EntryKind::Selfprobe,
        EntryKind::ReviewRequested,
        EntryKind::Verdict,
        EntryKind::Tripwire,
        EntryKind::Flag,
        EntryKind::Response,
        EntryKind::Pause,
        EntryKind::Halt,
        EntryKind::HaltCleared,
        EntryKind::Disposition,
        EntryKind::AllowRule,
        EntryKind::Annotation,
        EntryKind::KeepGoingSet,
        EntryKind::KeepGoing,
        EntryKind::Promotion,
        EntryKind::ObserveOnly,
        EntryKind::Vet,
    ];

    pub fn slug(self) -> &'static str {
        match self {
            EntryKind::Cursor => "cursor",
            EntryKind::Heartbeat => "heartbeat",
            EntryKind::Selfprobe => "selfprobe",
            EntryKind::ReviewRequested => "review_requested",
            EntryKind::Verdict => "verdict",
            EntryKind::Tripwire => "tripwire",
            EntryKind::Flag => "flag",
            EntryKind::Response => "response",
            EntryKind::Pause => "pause",
            EntryKind::Halt => "halt",
            EntryKind::HaltCleared => "halt_cleared",
            EntryKind::Disposition => "disposition",
            EntryKind::AllowRule => "allow_rule",
            EntryKind::Annotation => "annotation",
            EntryKind::KeepGoingSet => "keep_going_set",
            EntryKind::KeepGoing => "keep_going",
            EntryKind::Promotion => "promotion",
            EntryKind::ObserveOnly => "observe_only",
            EntryKind::Vet => "vet",
            EntryKind::Unknown => "unknown",
        }
    }

    /// The kinds that must survive a full disk: they go to the reserve file when the log cannot be written.
    pub fn is_pause_state(self) -> bool {
        matches!(self, EntryKind::Pause | EntryKind::Halt | EntryKind::HaltCleared)
    }
}

/// The phases of a pause entry: written before anything is applied, after it is applied, and when it is lifted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PausePhase {
    Begun,
    Applied,
    Lifted,
}

/// One line of the monitor log.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub seq: u64,
    pub ts_ms: u64,
    pub prev: String,
    pub mac: String,
    pub kind: EntryKind,
    /// The kind's own fields, beside the five above.
    #[serde(flatten)]
    pub fields: Map<String, Value>,
}

impl Entry {
    fn text(&self, key: &str) -> Option<String> {
        self.fields.get(key).and_then(Value::as_str).map(str::to_string)
    }

    fn number(&self, key: &str) -> Option<u64> {
        self.fields.get(key).and_then(Value::as_u64)
    }
}

/// Where a reader of one source stands: the byte offset, the last record (seq or line count) and the hash of the last
/// line, which the next read checks the chain against.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor {
    pub off: u64,
    pub seq: u64,
    #[serde(default)]
    pub hash: String,
}

/// One hit as the fold remembers it: what the next tripwire needs to count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HitRec {
    pub at_ms: u64,
    pub key: String,
    pub severity: Severity,
    pub session: String,
}

/// The history of one tripwire in one mission.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HitBook {
    pub recent: VecDeque<HitRec>,
    pub keys: BTreeSet<String>,
    /// Every hit logged (S1 and above), however many `recent` still holds.
    pub count: u64,
}

impl HitBook {
    fn push(&mut self, rec: HitRec) {
        self.count = self.count.saturating_add(1);
        if self.keys.len() < HIT_KEYS {
            self.keys.insert(rec.key.clone());
        }
        self.recent.push_back(rec);
        while self.recent.len() > HIT_HISTORY {
            self.recent.pop_front();
        }
    }

    /// Distinct keys of hits at or after `since_ms`.
    pub fn distinct_since(&self, since_ms: u64) -> usize {
        self.recent.iter().filter(|r| r.at_ms >= since_ms).map(|r| r.key.as_str()).collect::<BTreeSet<_>>().len()
    }

    /// Is `key` among the hits at or after `since_ms` (the window's count, not the mission's)?
    pub fn has_key_since(&self, key: &str, since_ms: u64) -> bool {
        self.recent.iter().any(|r| r.at_ms >= since_ms && r.key == key)
    }

    /// Hits at or after `since_ms`.
    pub fn count_since(&self, since_ms: u64) -> usize {
        self.recent.iter().filter(|r| r.at_ms >= since_ms).count()
    }
}

/// A flag as the log last wrote it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlagRec {
    pub flag: String,
    pub mission: MissionId,
    pub category: String,
    pub severity: Severity,
    pub key: String,
    pub count: u64,
    pub causes: BTreeSet<String>,
    /// `open`, or `closed` once a disposition names it.
    pub state: String,
    pub first_ms: u64,
    pub last_ms: u64,
    /// Who ruled on it, once one did (`disposition`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disposition: Option<String>,
}

/// Per tripwire, what it has fired: the counts the status and the promotion rule read.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwStat {
    pub fired: u64,
    pub by_severity: [u64; 5],
    pub missions: BTreeSet<String>,
}

/// How long a credential tag is remembered.
pub const SECRET_RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1000;
/// The most credential tags one mission may have in the index; its oldest go first, so one agent printing many
/// fake keys can evict only its own.
pub const SECRETS_PER_MISSION: usize = 10_000;

/// The credential values the missions' results showed, as hashed tags (never the values), for TW-06: which missions
/// saw a tag, when. Persisted in the `secrets` field of `cursor` entries, so a restart keeps it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SecretIndex {
    tags: BTreeMap<String, BTreeMap<MissionId, u64>>,
    order: VecDeque<(u64, String, MissionId)>,
    counts: BTreeMap<MissionId, usize>,
}

impl SecretIndex {
    /// Remember that `mission`'s results showed `tag` at `ts`; true when that is new.
    pub fn note(&mut self, tag: &str, mission: &MissionId, ts: u64) -> bool {
        self.expire(ts);
        let slot = self.tags.entry(tag.to_string()).or_default();
        if slot.contains_key(mission) {
            return false;
        }
        slot.insert(mission.clone(), ts);
        self.order.push_back((ts, tag.to_string(), mission.clone()));
        let n = self.counts.entry(mission.clone()).or_default();
        *n = n.saturating_add(1);
        if *n > SECRETS_PER_MISSION.saturating_add(SECRETS_PER_MISSION / 10) {
            self.evict(mission);
        }
        true
    }

    /// A mission, other than `mission`, whose results showed `tag`, when `mission`'s own did not.
    pub fn other_owner(&self, tag: &str, mission: &MissionId) -> Option<&MissionId> {
        let owners = self.tags.get(tag)?;
        if owners.contains_key(mission) {
            return None;
        }
        owners.keys().next()
    }

    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    fn remove(&mut self, tag: &str, mission: &MissionId) {
        if let Some(s) = self.tags.get_mut(tag) {
            s.remove(mission);
            if s.is_empty() {
                self.tags.remove(tag);
            }
        }
        if let Some(n) = self.counts.get_mut(mission) {
            *n = n.saturating_sub(1);
        }
    }

    fn expire(&mut self, now: u64) {
        while self.order.front().is_some_and(|(t, _, _)| t.saturating_add(SECRET_RETENTION_MS) < now) {
            if let Some((_, tag, mission)) = self.order.pop_front() {
                self.remove(&tag, &mission);
            }
        }
    }

    /// Drop `mission`'s oldest tags down to the cap.
    fn evict(&mut self, mission: &MissionId) {
        let mut drop = self.counts.get(mission).copied().unwrap_or(0).saturating_sub(SECRETS_PER_MISSION);
        let mut kept = VecDeque::with_capacity(self.order.len());
        let mut gone: Vec<(String, MissionId)> = Vec::new();
        for (t, tag, m) in std::mem::take(&mut self.order) {
            if drop > 0 && &m == mission {
                drop = drop.saturating_sub(1);
                gone.push((tag, m));
            } else {
                kept.push_back((t, tag, m));
            }
        }
        self.order = kept;
        for (tag, m) in gone {
            self.remove(&tag, &m);
        }
    }
}

/// The state the log folds to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Fold {
    /// Credential tags by mission (TW-06), from the `secrets` of `cursor` entries.
    pub secrets: SecretIndex,
    pub last_seq: u64,
    pub last_mac: String,
    /// Each paused mission with its open pause flags. `Inner::may_run` is false while the set is non-empty.
    pub paused: BTreeMap<MissionId, BTreeSet<String>>,
    /// The cohorts under a halt (a `halt` with no later `halt_cleared` of the same cohort).
    pub halts: BTreeSet<Cohort>,
    /// The latest checkpoint of every source.
    pub cursors: BTreeMap<String, Cursor>,
    /// Flags by id, as last written.
    pub flags: BTreeMap<String, FlagRec>,
    /// The history of each (mission, tripwire number).
    pub hits: BTreeMap<(MissionId, u8), HitBook>,
    /// The S1 hits of each (mission, category): what the S1 aggregation of §1.5 counts.
    pub s1: BTreeMap<(MissionId, String), HitBook>,
    /// Counts per tripwire number.
    pub stats: BTreeMap<u8, TwStat>,
    /// Cause (a tripwire id) to its state, from `promotion` entries; absent means the table's start.
    pub promotions: BTreeMap<String, String>,
    /// Missions the operator put in observe-only, with the entry's fields.
    pub observe_only: BTreeMap<MissionId, Map<String, Value>>,
    /// The allow rules of held calls, newest last (M8 reads them).
    pub allow_rules: Vec<Map<String, Value>>,
    /// The keep-going state by lead, newest entry (M9 reads it).
    pub keep_going: BTreeMap<String, Map<String, Value>>,
    /// Reviews requested and not answered by a verdict.
    pub open_reviews: BTreeSet<String>,
    /// Hits that were steered (an R1 note was sent for the (mission, tripwire, key)); empty until M4.
    pub steered: BTreeSet<(MissionId, u8, String)>,
    /// The `ts_ms` of the last heartbeat entry.
    pub last_heartbeat_ms: u64,
}

impl Fold {
    /// May a turn start or an agent launch for `mission` (a member of `membership`)? False when it has an open pause
    /// flag or a halt covers it.
    pub fn may_run(&self, mission: &MissionId, membership: &Membership) -> bool {
        !self.paused.contains_key(mission) && !self.halts.iter().any(|c| c.covers(membership))
    }

    /// The history of tripwire `number` in `mission`.
    pub fn book(&self, mission: &MissionId, number: u8) -> Option<&HitBook> {
        self.hits.get(&(mission.clone(), number))
    }

    /// The flags that are open.
    pub fn open_flags(&self) -> impl Iterator<Item = &FlagRec> {
        self.flags.values().filter(|f| f.state == "open")
    }

    /// Apply one entry's effect on the folded state.
    pub fn apply(&mut self, e: &Entry) {
        match e.kind {
            EntryKind::Pause => self.apply_pause(e),
            EntryKind::Halt => {
                let cohort =
                    e.fields.get("cohort").and_then(|v| serde_json::from_value(v.clone()).ok()).unwrap_or(Cohort::All);
                self.halts.insert(cohort);
            }
            EntryKind::HaltCleared => {
                if let Some(c) = e.fields.get("cohort").and_then(|v| serde_json::from_value::<Cohort>(v.clone()).ok()) {
                    self.halts.remove(&c);
                }
            }
            EntryKind::Cursor => {
                if let Some(rows) = e.fields.get("secrets").and_then(Value::as_array) {
                    for row in rows {
                        if let (Some(tag), Some(m), Some(ts)) = (
                            row.get(0).and_then(Value::as_str),
                            row.get(1).and_then(Value::as_str),
                            row.get(2).and_then(Value::as_u64),
                        ) {
                            self.secrets.note(tag, &MissionId::from(m), ts);
                        }
                    }
                }
                if let Some(map) = e.fields.get("cursors").and_then(Value::as_object) {
                    for (source, v) in map {
                        if let Ok(c) = serde_json::from_value::<Cursor>(v.clone()) {
                            self.cursors.insert(source.clone(), c);
                        }
                    }
                }
            }
            EntryKind::Heartbeat => self.last_heartbeat_ms = e.ts_ms,
            EntryKind::Tripwire => self.apply_tripwire(e),
            EntryKind::Flag => {
                if let Ok(rec) = serde_json::from_value::<FlagRec>(Value::Object(e.fields.clone())) {
                    self.flags.insert(rec.flag.clone(), rec);
                }
            }
            EntryKind::Disposition => {
                if let Some(flag) = e.text("flag") {
                    if let Some(f) = self.flags.get_mut(&flag) {
                        f.state = "closed".into();
                        f.disposition = e.text("disposition");
                    }
                }
            }
            EntryKind::Promotion => {
                if let (Some(cause), Some(state)) = (e.text("cause"), e.text("state")) {
                    self.promotions.insert(cause, state);
                }
            }
            EntryKind::ObserveOnly => {
                if let Some(m) = e.text("mission") {
                    self.observe_only.insert(MissionId::from(m), e.fields.clone());
                }
            }
            EntryKind::AllowRule => self.allow_rules.push(e.fields.clone()),
            EntryKind::KeepGoingSet | EntryKind::KeepGoing => {
                if let Some(lead) = e.text("lead").or_else(|| e.text("mission")) {
                    self.keep_going.insert(lead, e.fields.clone());
                }
            }
            EntryKind::ReviewRequested => {
                if let Some(r) = e.text("review") {
                    self.open_reviews.insert(r);
                }
            }
            EntryKind::Verdict => {
                if let Some(r) = e.text("review") {
                    self.open_reviews.remove(&r);
                }
            }
            _ => {}
        }
        self.last_seq = e.seq;
        self.last_mac = e.mac.clone();
    }

    fn apply_pause(&mut self, e: &Entry) {
        let Some(mission) = e.text("mission").map(MissionId::from) else { return };
        let flag = e.text("flag").unwrap_or_default();
        match e.fields.get("phase").and_then(Value::as_str) {
            Some("lifted") => {
                if let Some(open) = self.paused.get_mut(&mission) {
                    open.remove(&flag);
                    if open.is_empty() {
                        self.paused.remove(&mission);
                    }
                }
            }
            _ => {
                self.paused.entry(mission).or_default().insert(flag);
            }
        }
    }

    fn apply_tripwire(&mut self, e: &Entry) {
        let number = e.text("id").and_then(|id| crate::monitor::tripwire::TripwireId::parse(&id)).map(|t| t.number());
        let (Some(number), Some(mission)) = (number, e.text("mission")) else { return };
        let severity = e
            .fields
            .get("severity")
            .and_then(|v| serde_json::from_value::<Severity>(v.clone()).ok())
            .unwrap_or(Severity::S1);
        let rec = HitRec {
            at_ms: e.number("at_ms").unwrap_or(e.ts_ms),
            key: e.text("key").unwrap_or_default(),
            severity,
            session: e.text("session").unwrap_or_default(),
        };
        let stat = self.stats.entry(number).or_default();
        stat.fired = stat.fired.saturating_add(1);
        let slot = match severity {
            Severity::S0 => 0,
            Severity::S1 => 1,
            Severity::S2 => 2,
            Severity::S3 => 3,
            Severity::S4 => 4,
        };
        if let Some(c) = stat.by_severity.get_mut(slot) {
            *c = c.saturating_add(1);
        }
        if stat.missions.len() < HIT_KEYS {
            stat.missions.insert(mission.clone());
        }
        let from_s1 = e.fields.get("from_s1").and_then(Value::as_bool).unwrap_or(false);
        if severity == Severity::S1 || from_s1 {
            let cat = e.text("category").unwrap_or_default();
            self.s1.entry((MissionId::from(mission.clone()), cat)).or_default().push(rec.clone());
        }
        self.hits.entry((MissionId::from(mission), number)).or_default().push(rec);
    }
}

fn now_ms() -> u64 {
    loom_core::now_ms()
}

fn io_fault(what: &str, path: &Path, e: &std::io::Error) -> MonitorError {
    MonitorError::Unavailable(format!("{what} {}: {e}.", path.display()))
}

fn seal(key: &[u8], e: &Entry) -> Result<String, MonitorError> {
    let mut v =
        serde_json::to_value(e).map_err(|x| MonitorError::Unavailable(format!("An entry cannot be encoded: {x}.")))?;
    if let Some(o) = v.as_object_mut() {
        o.insert("mac".into(), Value::String(String::new()));
    }
    loom_core::journal::hmac_sha256_hex(key, v.to_string().as_bytes())
        .map_err(|x| MonitorError::Unavailable(format!("The monitor key cannot seal an entry: {x}.")))
}

/// The MAC a stored line should carry: the HMAC over the line's own JSON with `mac` empty.
fn line_mac(key: &[u8], line: &str) -> Option<String> {
    let mut v: Value = serde_json::from_str(line).ok()?;
    v.get("mac")?.as_str()?;
    v.as_object_mut()?.insert("mac".into(), Value::String(String::new()));
    loom_core::journal::hmac_sha256_hex(key, v.to_string().as_bytes()).ok()
}

/// The log, open for appending.
#[derive(Debug)]
pub struct MonitorLog {
    dir: PathBuf,
    anchor: PathBuf,
    key: Vec<u8>,
    file: std::fs::File,
    seq: u64,
    last_mac: String,
    down: Option<String>,
}

/// What `open` found, beside the fold.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Opened {
    /// The monitor wrote its key and marker this time: the first start.
    pub first_start: bool,
    /// Bytes of a torn last line that were cut.
    pub torn_bytes: u64,
    /// Entries replayed from the reserve file.
    pub from_reserve: usize,
    /// Reviews marked `fault: restart`.
    pub restarted_reviews: usize,
}

impl MonitorLog {
    /// Open `<home>/monitor`, verify the chain and fold it (M2). The fold is complete when this returns.
    pub fn open(home: &Path) -> Result<(MonitorLog, Fold), MonitorError> {
        Self::open_with_report(home).map(|(l, f, _)| (l, f))
    }

    /// `open`, with what it found.
    pub fn open_with_report(home: &Path) -> Result<(MonitorLog, Fold, Opened), MonitorError> {
        let dir = home.join(DIR);
        let keys = home.join("keys");
        make_private_dir(&dir).map_err(|e| io_fault("The monitor directory cannot be made at", &dir, &e))?;
        make_private_dir(&keys).map_err(|e| io_fault("The keys directory cannot be made at", &keys, &e))?;
        let key_path = keys.join(KEY_FILE);
        let marker = dir.join(FIRST_START_FILE);
        let key = loom_core::journal::load_or_create_key(&key_path)
            .map_err(|e| io_fault("The monitor key cannot be read or made at", &key_path, &e))?;
        let log_path = dir.join(LOG_FILE);
        let mut opened = Opened::default();
        let marker_before = marker.exists();
        let anchor_path = keys.join(ANCHOR_FILE);
        if !log_path.exists() && marker_before {
            return Err(MonitorError::Unavailable(format!(
                "The monitor log {} is missing although the monitor has run here before ({} exists). Restore it from a backup; to accept the loss, stop the daemon, move monitor/log.jsonl, monitor/first-start, monitor/reserve and keys/monitor.anchor out of the loom home and start it again (`loom monitor ack-down` will do this from M3).",
                log_path.display(),
                marker.display()
            )));
        }
        if !marker_before {
            opened.first_start = !log_path.exists();
            std::fs::write(&marker, now_ms().to_string())
                .map_err(|e| io_fault("The first-start marker cannot be written at", &marker, &e))?;
        }
        let text = match std::fs::read_to_string(&log_path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(io_fault("The monitor log cannot be read at", &log_path, &e)),
        };
        let whole_len = text.rfind('\n').map_or(0, |i| i.saturating_add(1));
        let (whole, torn) = text.split_at(whole_len);
        let mut fold = Fold::default();
        let mut prev = GENESIS_PREV.to_string();
        let mut expect = 1u64;
        for (i, line) in whole.lines().enumerate() {
            let n = i.saturating_add(1);
            let bad = |why: &str| {
                MonitorError::Unavailable(format!(
                    "The monitor log {} fails verification at line {n}: {why}. Nothing was cleared and the monitor is down; restore the log from a backup or accept the loss by stopping the daemon, moving monitor/log.jsonl, monitor/first-start, monitor/reserve and keys/monitor.anchor out of the loom home and starting it again (`loom monitor ack-down` will do this from M3).",
                    log_path.display()
                ))
            };
            let want = line_mac(&key, line).ok_or_else(|| bad("the line is not an entry"))?;
            let entry: Entry = serde_json::from_str(line).map_err(|_| bad("the line is not an entry"))?;
            if entry.mac != want {
                return Err(bad("its mac does not verify (an entry was edited)"));
            }
            if entry.prev != prev {
                return Err(bad("its prev does not follow the entry before it (an entry was removed or reordered)"));
            }
            if entry.seq != expect {
                return Err(bad("its seq is not the next one (an entry was removed or reordered)"));
            }
            prev = entry.mac.clone();
            expect = expect.saturating_add(1);
            fold.apply(&entry);
        }
        if let Ok(a) = std::fs::read_to_string(&anchor_path) {
            if let Ok(v) = serde_json::from_str::<Value>(&a) {
                let aseq = v.get("seq").and_then(Value::as_u64).unwrap_or(0);
                let amac = v.get("mac").and_then(Value::as_str).unwrap_or("");
                if fold.last_seq < aseq {
                    return Err(MonitorError::Unavailable(format!(
                        "The monitor log {} ends at entry {} but entry {aseq} was written: it was cut short. Restore it from a backup or accept the loss by stopping the daemon, moving monitor/log.jsonl, monitor/first-start, monitor/reserve and keys/monitor.anchor out of the loom home and starting it again (`loom monitor ack-down` will do this from M3).",
                        log_path.display(),
                        fold.last_seq
                    )));
                }
                if fold.last_seq == aseq && aseq > 0 && fold.last_mac != amac {
                    return Err(MonitorError::Unavailable(format!(
                        "The last entry of the monitor log {} is not the one that was anchored. Restore it from a backup or accept the loss by stopping the daemon, moving monitor/log.jsonl, monitor/first-start, monitor/reserve and keys/monitor.anchor out of the loom home and starting it again (`loom monitor ack-down` will do this from M3).",
                        log_path.display()
                    )));
                }
            }
        }
        // Cut a torn tail before appending.
        opened.torn_bytes = torn.len() as u64;
        if !torn.is_empty() {
            let f = std::fs::OpenOptions::new()
                .write(true)
                .open(&log_path)
                .map_err(|e| io_fault("The monitor log cannot be opened at", &log_path, &e))?;
            f.set_len(whole_len as u64)
                .map_err(|e| io_fault("The torn end of the monitor log cannot be cut at", &log_path, &e))?;
        }
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let file = options
            .open(&log_path)
            .map_err(|e| io_fault("The monitor log cannot be opened for appending at", &log_path, &e))?;
        let mut log = MonitorLog {
            dir: dir.clone(),
            anchor: anchor_path,
            key,
            file,
            seq: fold.last_seq,
            last_mac: if fold.last_seq == 0 { GENESIS_PREV.to_string() } else { fold.last_mac.clone() },
            down: None,
        };
        // The reserve: pause and halt entries written while the log could not be.
        let reserve = log.read_reserve()?;
        opened.from_reserve = reserve.len();
        let (kept_seq, kept_mac) = (fold.last_seq, fold.last_mac.clone());
        for e in &reserve {
            fold.apply(e);
        }
        fold.last_seq = kept_seq;
        fold.last_mac = kept_mac;
        for e in reserve {
            let mut fields = e.fields.clone();
            fields.insert("from_reserve".into(), Value::Bool(true));
            let kept = log.append(e.kind, fields)?;
            fold.last_seq = kept.seq;
            fold.last_mac = kept.mac;
        }
        if opened.from_reserve > 0 {
            log.clear_reserve()?;
        } else {
            log.ensure_reserve()?;
        }
        if opened.torn_bytes > 0 {
            let mut f = Map::new();
            f.insert("torn_bytes".into(), Value::from(opened.torn_bytes));
            let e = log.append(EntryKind::Heartbeat, f)?;
            fold.apply(&e);
        }
        // A review with no verdict was cut by the restart: a fault, never counted against anyone (I10).
        for review in fold.open_reviews.clone() {
            let mut f = Map::new();
            f.insert("review".into(), Value::String(review));
            f.insert("fault".into(), Value::String("restart".into()));
            let e = log.append(EntryKind::Verdict, f)?;
            fold.apply(&e);
            opened.restarted_reviews = opened.restarted_reviews.saturating_add(1);
        }
        Ok((log, fold, opened))
    }

    /// Make the next write fail, as a full disk does (tests only).
    #[cfg(test)]
    pub(crate) fn break_for_test(&mut self) {
        if let Ok(f) = std::fs::File::open(self.dir.join(LOG_FILE)) {
            self.file = f;
        }
    }

    /// Make writes work again, as freed space does (tests only).
    #[cfg(test)]
    pub(crate) fn mend_for_test(&mut self) {
        if let Ok(f) = std::fs::OpenOptions::new().append(true).open(self.dir.join(LOG_FILE)) {
            self.file = f;
        }
    }

    /// The directory of the log (`<home>/monitor`).
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// True once a write failed: the monitor is down and the reason is `down_reason`.
    pub fn is_down(&self) -> bool {
        self.down.is_some()
    }

    pub fn down_reason(&self) -> Option<&str> {
        self.down.as_deref()
    }

    pub fn last_seq(&self) -> u64 {
        self.seq
    }

    /// Append one entry of `kind` with `fields`, sync it, and return it (see the contract).
    pub fn append(&mut self, kind: EntryKind, fields: Map<String, Value>) -> Result<Entry, MonitorError> {
        check_fields(&fields)?;
        let mut entry = Entry {
            seq: self.seq.saturating_add(1),
            ts_ms: now_ms(),
            prev: self.last_mac.clone(),
            mac: String::new(),
            kind,
            fields,
        };
        entry.mac = seal(&self.key, &entry)?;
        let mut line = serde_json::to_string(&entry)
            .map_err(|e| MonitorError::Unavailable(format!("An entry cannot be encoded: {e}.")))?;
        line.push('\n');
        let before = self.file.metadata().map(|m| m.len()).ok();
        let written = self.file.write_all(line.as_bytes()).and_then(|()| self.file.sync_data());
        if let Err(e) = written {
            if let Some(len) = before {
                let _ = self.file.set_len(len);
            }
            let reason = format!("the monitor log cannot be written: {e}");
            self.down = Some(reason.clone());
            if kind.is_pause_state() {
                // The reserve entry is sealed on its own: no seq, no chain, so a replay does not depend on the log.
                let mut r = Entry {
                    seq: 0,
                    ts_ms: entry.ts_ms,
                    prev: String::new(),
                    mac: String::new(),
                    kind,
                    fields: entry.fields.clone(),
                };
                r.mac = seal(&self.key, &r)?;
                self.write_reserve(&r)?;
            }
            return Err(MonitorError::Unavailable(format!(
                "{reason}. Free space under the loom home; pauses are kept in the reserve file until then."
            )));
        }
        self.seq = entry.seq;
        self.last_mac = entry.mac.clone();
        // A write that works again lifts the down state, unless pause entries sit in the reserve (those are folded in
        // at the next open and the operator acknowledges them).
        if self.down.is_some() && self.read_reserve().is_ok_and(|r| r.is_empty()) {
            self.down = None;
        }
        let anchor = serde_json::json!({"seq": entry.seq, "mac": entry.mac}).to_string();
        // Not synced: the anchor only has to survive a deletion of the tail, which a sync would not stop either.
        let _ = std::fs::write(&self.anchor, anchor);
        Ok(entry)
    }

    fn reserve_path(&self) -> PathBuf {
        self.dir.join(RESERVE_FILE)
    }

    fn ensure_reserve(&self) -> Result<(), MonitorError> {
        let p = self.reserve_path();
        if p.exists() {
            return Ok(());
        }
        self.clear_reserve()
    }

    fn clear_reserve(&self) -> Result<(), MonitorError> {
        let p = self.reserve_path();
        let mut options = std::fs::OpenOptions::new();
        options.create(true).write(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut f = options.open(&p).map_err(|e| io_fault("The reserve file cannot be made at", &p, &e))?;
        let zeros = vec![0u8; 4096];
        let mut left = RESERVE_BYTES;
        while left > 0 {
            let n = left.min(zeros.len() as u64) as usize;
            f.write_all(zeros.get(..n).unwrap_or(&zeros))
                .map_err(|e| io_fault("The reserve file cannot be filled at", &p, &e))?;
            left = left.saturating_sub(n as u64);
        }
        f.sync_all().map_err(|e| io_fault("The reserve file cannot be synced at", &p, &e))
    }

    /// The entries in the reserve, each checked against the key; a line that does not verify stops the monitor.
    fn read_reserve(&self) -> Result<Vec<Entry>, MonitorError> {
        let p = self.reserve_path();
        let bytes = match std::fs::read(&p) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(io_fault("The reserve file cannot be read at", &p, &e)),
        };
        let used = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
        let text = String::from_utf8_lossy(bytes.get(..used).unwrap_or(&[])).into_owned();
        let mut out = Vec::new();
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let bad = || {
                MonitorError::Unavailable(format!(
                    "The reserve file {} holds a line that does not verify. Nothing was cleared; check the pauses by hand, then accept the loss by stopping the daemon, moving monitor/log.jsonl, monitor/first-start, monitor/reserve and keys/monitor.anchor out of the loom home and starting it again (`loom monitor ack-down` will do this from M3).",
                    p.display()
                ))
            };
            let want = line_mac(&self.key, line).ok_or_else(bad)?;
            let entry: Entry = serde_json::from_str(line).map_err(|_| bad())?;
            if entry.mac != want {
                return Err(bad());
            }
            out.push(entry);
        }
        Ok(out)
    }

    fn write_reserve(&self, e: &Entry) -> Result<(), MonitorError> {
        use std::io::{Seek, SeekFrom};
        let p = self.reserve_path();
        let existing = std::fs::read(&p).unwrap_or_default();
        let used = existing.iter().position(|b| *b == 0).unwrap_or(existing.len());
        let mut line = serde_json::to_string(e)
            .map_err(|x| MonitorError::Unavailable(format!("An entry cannot be encoded: {x}.")))?;
        line.push('\n');
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&p)
            .map_err(|x| io_fault("The reserve file cannot be opened at", &p, &x))?;
        f.seek(SeekFrom::Start(used as u64)).map_err(|x| io_fault("The reserve file cannot be written at", &p, &x))?;
        f.write_all(line.as_bytes())
            .and_then(|()| f.sync_all())
            .map_err(|x| io_fault("The reserve file cannot be written at", &p, &x))
    }
}

#[cfg(unix)]
fn make_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(dir)
}

#[cfg(not(unix))]
fn make_private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_kinds_are_the_nineteen() {
        let slugs: Vec<&str> = EntryKind::ALL.iter().map(|k| k.slug()).collect();
        assert_eq!(slugs.len(), 19);
        let unique: BTreeSet<&str> = slugs.iter().copied().collect();
        assert_eq!(unique.len(), 19);
        for k in EntryKind::ALL {
            assert_eq!(serde_json::to_string(&k).unwrap_or_default(), format!("\"{}\"", k.slug()));
        }
        assert!(slugs.contains(&"keep_going_set") && slugs.contains(&"halt_cleared"));
    }

    #[test]
    fn an_entry_round_trips_with_its_fields_flattened() {
        let mut fields = Map::new();
        fields.insert("mission".into(), Value::String("m-1".into()));
        fields.insert("phase".into(), serde_json::to_value(PausePhase::Begun).unwrap_or(Value::Null));
        let e = Entry { seq: 1, ts_ms: 5, prev: GENESIS_PREV.into(), mac: "ab".into(), kind: EntryKind::Pause, fields };
        let line = serde_json::to_string(&e).unwrap_or_default();
        assert!(line.contains("\"kind\":\"pause\"") && line.contains("\"phase\":\"begun\""), "{line}");
        assert!(!line.contains("\"fields\""), "{line}");
        assert_eq!(serde_json::from_str::<Entry>(&line).ok(), Some(e));
    }

    fn entry(seq: u64, kind: EntryKind, fields: Value) -> Entry {
        let fields = match fields {
            Value::Object(m) => m,
            _ => Map::new(),
        };
        Entry { seq, ts_ms: seq, prev: GENESIS_PREV.into(), mac: format!("m{seq}"), kind, fields }
    }

    fn member(pack: &str, family: &str) -> Membership {
        Membership { pack: pack.into(), families: [family.to_string()].into(), rootbox: false }
    }

    #[test]
    fn a_pause_holds_until_every_flag_is_lifted() {
        let mut f = Fold::default();
        let m = MissionId::from("m-1");
        let who = member("core", "qwen");
        assert!(f.may_run(&m, &who));
        f.apply(&entry(1, EntryKind::Pause, serde_json::json!({"mission": "m-1", "flag": "f1", "phase": "begun"})));
        f.apply(&entry(2, EntryKind::Pause, serde_json::json!({"mission": "m-1", "flag": "f1", "phase": "applied"})));
        assert!(!f.may_run(&m, &who));
        assert!(f.may_run(&MissionId::from("m-2"), &who));
        // A second flag arrives from a later review; the operator lifts the first only.
        f.apply(&entry(3, EntryKind::Pause, serde_json::json!({"mission": "m-1", "flag": "f2", "phase": "begun"})));
        f.apply(&entry(4, EntryKind::Pause, serde_json::json!({"mission": "m-1", "flag": "f1", "phase": "lifted"})));
        assert!(!f.may_run(&m, &who), "lifting f1 must not lift f2");
        f.apply(&entry(5, EntryKind::Pause, serde_json::json!({"mission": "m-1", "flag": "f2", "phase": "lifted"})));
        assert!(f.may_run(&m, &who));
        assert!(f.paused.is_empty());
        assert_eq!((f.last_seq, f.last_mac.as_str()), (5, "m5"));
    }

    #[test]
    fn a_halt_holds_its_cohort_and_clear_halt_clears_only_that_cohort() {
        let mut f = Fold::default();
        let a = Cohort::PackFamily("ctf".into(), "qwen".into());
        let b = Cohort::Rootbox;
        let ctf_qwen = member("ctf", "qwen");
        let core_deepseek = member("core", "deepseek");
        let rootbox = Membership { rootbox: true, ..member("core", "deepseek") };
        let m = MissionId::from("m-1");
        f.apply(&entry(1, EntryKind::Halt, serde_json::json!({"cohort": a, "reason": "canary"})));
        assert!(!f.may_run(&m, &ctf_qwen));
        assert!(f.may_run(&m, &core_deepseek), "a halt of cohort A leaves cohort B runnable");
        f.apply(&entry(2, EntryKind::Halt, serde_json::json!({"cohort": b, "reason": "x"})));
        assert!(!f.may_run(&m, &rootbox));
        f.apply(&entry(3, EntryKind::HaltCleared, serde_json::json!({"cohort": a})));
        assert!(f.may_run(&m, &ctf_qwen), "A is cleared");
        assert!(!f.may_run(&m, &rootbox), "clearing A leaves the halt on B in place");
        // An unreadable cohort is the widest halt, and an unreadable clear clears nothing.
        f.apply(&entry(4, EntryKind::Halt, serde_json::json!({"reason": "no cohort"})));
        assert!(!f.may_run(&m, &core_deepseek));
        f.apply(&entry(5, EntryKind::HaltCleared, serde_json::json!({"cohort": "nonsense"})));
        assert!(!f.may_run(&m, &core_deepseek));
    }

    #[test]
    fn no_field_of_the_spec_collides_with_the_entry_envelope() {
        let doc = include_str!("../../../../docs/MONITOR.md");
        let start = doc.find("### 7.3 Monitor log").unwrap_or(0);
        let end = doc[start..].find("### 7.4").map_or(doc.len(), |i| start + i);
        let table: Vec<&str> =
            doc[start..end].lines().filter(|l| l.starts_with("| `") && l.matches('`').count() >= 2).collect();
        assert!(table.len() >= 19, "the kinds table of 7.3 was not found");
        for row in table {
            let braces = row.split_once('{').map(|(_, r)| r).unwrap_or("");
            for word in braces.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
                assert!(!RESERVED_FIELDS.contains(&word), "{row} names the envelope field {word}");
            }
        }
        let mut f = Map::new();
        f.insert("kind".into(), Value::String("step".into()));
        assert!(check_fields(&f).is_err());
    }

    #[test]
    fn review_requested_round_trips_with_scope() {
        let e = entry(
            7,
            EntryKind::ReviewRequested,
            serde_json::json!({"review": "r-1", "scope": "step", "mission": "m-1"}),
        );
        let line = serde_json::to_string(&e).unwrap_or_default();
        assert_eq!(serde_json::from_str::<Entry>(&line).ok(), Some(e));
        assert!(check_fields(&Map::new()).is_ok());
    }

    #[test]
    fn an_unknown_kind_is_read_as_unknown() {
        let line = r#"{"seq":3,"ts_ms":1,"prev":"p","mac":"m","kind":"future_kind","x":1}"#;
        let e = serde_json::from_str::<Entry>(line).ok();
        assert_eq!(e.as_ref().map(|e| e.kind), Some(EntryKind::Unknown));
        let mut f = Fold::default();
        if let Some(e) = e {
            f.apply(&e);
        }
        assert_eq!(f.last_seq, 3);
        assert!(f.paused.is_empty() && f.halts.is_empty());
        assert!(!EntryKind::ALL.contains(&EntryKind::Unknown));
    }

    fn fields(v: Value) -> Map<String, Value> {
        match v {
            Value::Object(m) => m,
            _ => Map::new(),
        }
    }

    fn home() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn tripwire(session: &str, key: &str, at: u64) -> Map<String, Value> {
        fields(serde_json::json!({
            "id": "TW-01", "mission": "m-1", "session": session, "pointer": [session, 3], "category": "scope_escape",
            "severity": "s1", "detail": "d", "key": key, "at_ms": at, "state": "shadow"
        }))
    }

    #[test]
    fn append_then_open_reproduces_the_fold() {
        let h = home();
        let (mut log, fold, opened) = MonitorLog::open_with_report(h.path()).expect("open");
        assert!(opened.first_start && fold.last_seq == 0);
        log.append(EntryKind::Tripwire, tripwire("s-1", "a.test", 100)).expect("a");
        log.append(EntryKind::Tripwire, tripwire("s-1", "b.test", 200)).expect("b");
        log.append(EntryKind::Pause, fields(serde_json::json!({"mission": "m-1", "flag": "f-1", "phase": "begun"})))
            .expect("p");
        log.append(
            EntryKind::Cursor,
            fields(serde_json::json!({"cursors": {"s:s-1": {"off": 99, "seq": 4, "hash": "h"}}})),
        )
        .expect("c");
        log.append(
            EntryKind::Flag,
            fields(serde_json::json!({"flag": "f-9", "mission": "m-1", "category": "scope_escape", "severity": "s2", "key": "a.test", "count": 2, "causes": ["TW-01"], "state": "open", "first_ms": 1, "last_ms": 2})),
        )
        .expect("f");
        let last = log.last_seq();
        drop(log);
        let (_log, fold, opened) = MonitorLog::open_with_report(h.path()).expect("reopen");
        assert!(!opened.first_start);
        assert_eq!(fold.last_seq, last);
        assert!(fold.paused.contains_key(&MissionId::from("m-1")));
        assert_eq!(fold.cursors.get("s:s-1").map(|c| (c.off, c.seq)), Some((99, 4)));
        assert_eq!(fold.flags.get("f-9").map(|f| f.count), Some(2));
        let book = fold.book(&MissionId::from("m-1"), 1).expect("book");
        assert_eq!((book.count, book.distinct_since(0), book.distinct_since(150)), (2, 2, 1));
        assert_eq!(fold.stats.get(&1).map(|s| s.fired), Some(2));
    }

    fn two_entries(h: &Path) -> PathBuf {
        let (mut log, _) = MonitorLog::open(h).expect("open");
        for i in 0..3 {
            log.append(EntryKind::Tripwire, tripwire("s-1", &format!("h{i}.test"), i)).expect("append");
        }
        h.join(DIR).join(LOG_FILE)
    }

    #[test]
    fn a_flipped_byte_a_deleted_middle_entry_or_a_swapped_order_fails_the_open() {
        let h = home();
        let path = two_entries(h.path());
        let text = std::fs::read_to_string(&path).expect("read");
        let lines: Vec<&str> = text.lines().collect();
        let write = |body: String| std::fs::write(&path, body).expect("write");
        write(text.replace("h1.test", "h9.test"));
        let e = MonitorLog::open(h.path()).err().map(|e| e.to_string()).unwrap_or_default();
        assert!(e.contains("fails verification at line 2") && e.contains("edited"), "{e}");
        write(format!("{}\n{}\n", lines.first().copied().unwrap_or(""), lines.get(2).copied().unwrap_or("")));
        let e = MonitorLog::open(h.path()).err().map(|e| e.to_string()).unwrap_or_default();
        assert!(e.contains("line 2") && e.contains("removed or reordered"), "{e}");
        write(format!(
            "{}\n{}\n{}\n",
            lines.get(1).copied().unwrap_or(""),
            lines.first().copied().unwrap_or(""),
            lines.get(2).copied().unwrap_or("")
        ));
        assert!(MonitorLog::open(h.path()).is_err());
        write(text.clone());
        assert!(MonitorLog::open(h.path()).is_ok(), "the untouched log opens");
    }

    #[test]
    fn a_torn_last_line_is_cut_and_recorded() {
        let h = home();
        let path = two_entries(h.path());
        let mut f = std::fs::OpenOptions::new().append(true).open(&path).expect("open");
        f.write_all(b"{\"seq\":4,\"ts_ms\":1,\"pre").expect("tear");
        drop(f);
        let (_log, fold, opened) = MonitorLog::open_with_report(h.path()).expect("open");
        assert_eq!(opened.torn_bytes, 23);
        assert_eq!(fold.last_seq, 4, "three entries and the heartbeat that records the cut");
        let text = std::fs::read_to_string(&path).expect("read");
        assert!(text.lines().last().unwrap_or("").contains("torn_bytes"));
        assert!(MonitorLog::open(h.path()).is_ok());
    }

    #[test]
    fn a_truncated_tail_and_a_deleted_log_are_detected() {
        let h = home();
        let path = two_entries(h.path());
        let text = std::fs::read_to_string(&path).expect("read");
        let first_two: String = text.lines().take(2).map(|l| format!("{l}\n")).collect();
        std::fs::write(&path, first_two).expect("cut");
        let e = MonitorLog::open(h.path()).err().map(|e| e.to_string()).unwrap_or_default();
        assert!(e.contains("cut short") && e.contains("entry 3"), "{e}");
        std::fs::write(&path, text).expect("restore");
        std::fs::remove_file(&path).expect("delete");
        let e = MonitorLog::open(h.path()).err().map(|e| e.to_string()).unwrap_or_default();
        assert!(e.contains("is missing") && e.contains("ack-down"), "{e}");
    }

    #[test]
    fn the_reserve_takes_a_pause_when_the_log_cannot_be_written_and_a_restart_replays_it() {
        let h = home();
        let (mut log, _) = MonitorLog::open(h.path()).expect("open");
        // Make the next write fail: a handle that cannot be written to.
        let ro = std::fs::File::open(h.path().join(DIR).join(LOG_FILE)).expect("ro");
        log.file = ro;
        let pause = fields(serde_json::json!({"mission": "m-7", "flag": "f-1", "phase": "begun"}));
        let err = log.append(EntryKind::Pause, pause).err().map(|e| e.to_string()).unwrap_or_default();
        assert!(err.contains("reserve file"), "{err}");
        assert!(log.is_down());
        let other = log.append(EntryKind::Tripwire, tripwire("s-1", "x", 1));
        assert!(other.is_err());
        drop(log);
        let (_log, fold, opened) = MonitorLog::open_with_report(h.path()).expect("restart");
        assert_eq!(opened.from_reserve, 1);
        assert!(fold.paused.contains_key(&MissionId::from("m-7")), "the mission stays paused");
        let again = MonitorLog::open(h.path()).expect("again").1;
        assert!(
            again.paused.contains_key(&MissionId::from("m-7")),
            "the pause is in the log now, not only the reserve"
        );
        // A tampered reserve line does not verify.
        let r = h.path().join(DIR).join(RESERVE_FILE);
        std::fs::write(
            &r,
            "{\"seq\":0,\"ts_ms\":1,\"prev\":\"\",\"mac\":\"00\",\"kind\":\"pause\",\"mission\":\"m-1\"}\n",
        )
        .expect("forge");
        assert!(MonitorLog::open(h.path()).is_err());
    }

    #[test]
    fn a_review_with_no_verdict_gets_fault_restart() {
        let h = home();
        let (mut log, _) = MonitorLog::open(h.path()).expect("open");
        log.append(
            EntryKind::ReviewRequested,
            fields(serde_json::json!({"review": "r-1", "scope": "step", "mission": "m-1"})),
        )
        .expect("req");
        drop(log);
        let (_log, fold, opened) = MonitorLog::open_with_report(h.path()).expect("restart");
        assert_eq!(opened.restarted_reviews, 1);
        assert!(fold.open_reviews.is_empty());
        let text = std::fs::read_to_string(h.path().join(DIR).join(LOG_FILE)).expect("read");
        assert!(text.contains("\"fault\":\"restart\""), "{text}");
    }

    #[test]
    fn a_reserved_field_is_refused_on_append() {
        let h = home();
        let (mut log, _) = MonitorLog::open(h.path()).expect("open");
        let e = log.append(EntryKind::Tripwire, fields(serde_json::json!({"kind": "x"}))).err();
        assert!(matches!(e, Some(MonitorError::Invalid(_))));
        assert_eq!(log.last_seq(), 0);
    }

    #[test]
    fn the_log_is_private() {
        let h = home();
        let (_log, _) = MonitorLog::open(h.path()).expect("open");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: PathBuf| std::fs::metadata(p).map(|m| m.permissions().mode() & 0o777).unwrap_or(0);
            assert_eq!(mode(h.path().join(DIR)), 0o700);
            assert_eq!(mode(h.path().join(DIR).join(LOG_FILE)), 0o600);
            assert_eq!(mode(h.path().join("keys").join(KEY_FILE)), 0o600);
        }
        assert_eq!(
            std::fs::metadata(h.path().join(DIR).join(RESERVE_FILE)).map(|m| m.len()).unwrap_or(0),
            RESERVE_BYTES
        );
    }
}
