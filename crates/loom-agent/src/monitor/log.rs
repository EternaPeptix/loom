//! The monitor log: `<home>/monitor/log.jsonl`, the monitor's only durable state (`docs/MONITOR.md` §2.1, §7.3).
//!
//! CONTRACT.
//!
//! - Files, under the loom home: `monitor/log.jsonl` (0600, append-only), `monitor/inputs/<sha256>` (the exact rendered
//!   input of each review, content-addressed, 0600), `monitor/reserve` (preallocated, so a pause record can be written
//!   on a full disk), `keys/monitor.key` (0600, the HMAC key; created beside `keys/journal.key`). The directory is 0700.
//!   The sandbox hides all of it from commands and the file tools refuse it (#34); review blobs are outside every
//!   mission's output index (#36).
//! - An `Entry` has `seq` (from 1, gapless), `ts_ms`, `prev` (the previous entry's `mac`; 64 zeros for the first),
//!   `mac` (HMAC-SHA256 under `monitor.key` over the entry's canonical bytes with `mac` empty, hex), `kind`
//!   (`EntryKind::slug`) and the kind's own fields flattened beside them. The kinds and their fields are those of
//!   `docs/MONITOR.md` §7.3: `cursor`, `heartbeat`, `selfprobe`, `review_requested`, `verdict`, `tripwire`, `flag`,
//!   `response`, `pause`, `halt`, `halt_cleared`, `disposition`, `allow_rule`, `annotation`, `keep_going_set`,
//!   `keep_going`, `promotion`, `observe_only`, `vet` (19). A reader that meets another kind reads it as
//!   `EntryKind::Unknown` (not in `ALL`, written as `unknown`), verifies its MAC over the line's own bytes, keeps the
//!   line and ignores it, so a newer monitor's log stays readable (additive, like `Event::Unknown`). A kind's own field
//!   names never equal one of the five `RESERVED_FIELDS` (`seq`, `ts_ms`, `prev`, `mac`, `kind`), which would collide
//!   with the flattened discriminator: `review_requested` names its scope `scope` (gate, step, tree or fleet), and
//!   `check_fields` refuses a reserved name before an append.
//! - The pause and halt entries fold as follows. `pause{mission, flag, phase}`: a mission is paused while it has at
//!   least one open flag; `begun` and `applied` open the flag, `lifted` closes only its own flag. `halt{cohort, reason,
//!   client}` and `halt_cleared{cohort, client}`: halts are a set of cohorts (`respond::Cohort`); `halt_cleared` removes
//!   only its own cohort. A `pause` or `halt` whose mission or cohort cannot be read is kept as the widest reading
//!   (flag `""`, cohort `all`); a `halt_cleared` that cannot be read clears nothing.
//! - `MonitorLog::open` folds the whole log (from the latest snapshot) into a `Fold` before returning, and fails with
//!   `Unavailable` when a `mac` or a `prev` does not verify: the monitor is then **down** (§2.8). Down does not lift a
//!   pause: the fold also replays `monitor/reserve` (the pause and halt entries written there while the log was
//!   unwritable) before activation, and when the fold cannot be built at all (a bad MAC, an unreadable log or reserve, a
//!   log shorter than the last seq anchored beside `keys/monitor.key` in `keys/monitor.anchor`, or a missing log when
//!   `monitor/first-start` was written with the key) the runtime holds **every mission that has any pause or halt record,
//!   and every mission when it cannot tell, whatever `monitor_down` says**, until the operator acknowledges
//!   (`loom monitor ack-down`). A missing log with no `first-start` marker is a first start. The
//!   fold derives the open flags, the cursors, the counters, the paused and halted sets, the allow rules, the
//!   keep-going state and the promotions. It is a hard barrier: the runtime activates no session before it is done (I9).
//! - `append` writes one entry, syncs it, and only then returns; a pause entry that cannot be written to the log is
//!   written to the reserve file and the monitor goes down (`monitor_down`). Appending is the single point at which
//!   state changes: nothing is applied before the entry that records it (write-ahead).
//! - First-start cursors begin at the end of each source log, so the first run raises no retroactive pause.
//! - A restart marks every review that was requested and has no verdict `fault: restart`; that is not counted.
//!
//! Built by: M2 (open, fold, append, heartbeat, snapshots); M3 (pause and halt entries are applied through
//! `Inner::may_run`).
//!
//! Tests required (M2): the kinds list is exactly the 19 above; append then open reproduces the fold; a flipped byte,
//! a deleted middle entry or a swapped order fails the open with `Unavailable`; a torn last line is cut and recorded;
//! the reserve file takes a pause entry when the disk write fails and a restart replays it into the fold (the mission
//! stays paused, also when the log is still unwritable); a truncated tail and a deleted log are detected against the
//! anchor and the first-start marker; a failed fold holds every mission that has a pause or halt record; a write-ahead
//! `pause{begun}` folds to paused even with no `applied`; first-start cursors sit at the end of the sources; an unknown
//! kind is kept and skipped.
//! In P0: `entry_kinds_are_the_nineteen`, `an_entry_round_trips_with_its_fields_flattened`,
//! `no_field_of_the_spec_collides_with_the_entry_envelope`, `review_requested_round_trips_with_scope`,
//! `an_unknown_kind_is_read_as_unknown`, `a_pause_holds_until_every_flag_is_lifted`,
//! `a_halt_holds_its_cohort_and_clear_halt_clears_only_that_cohort`.

use crate::monitor::respond::{Cohort, Membership};
use crate::monitor::{not_built, MonitorError};
use loom_core::MissionId;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// The directory under the loom home.
pub const DIR: &str = "monitor";
pub const LOG_FILE: &str = "log.jsonl";
pub const INPUTS_DIR: &str = "inputs";
pub const RESERVE_FILE: &str = "reserve";
/// The key file under `<home>/keys`.
pub const KEY_FILE: &str = "monitor.key";
/// The `prev` of the first entry.
pub const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";

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

/// The state the log folds to. Only what the contracts of other submodules need is named here; M2 adds the rest
/// (flags, counters, allow rules, keep-going state, promotions) as fields with `#[serde(default)]`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Fold {
    pub last_seq: u64,
    pub last_mac: String,
    /// Each paused mission with its open pause flags. `Inner::may_run` is false while the set is non-empty.
    pub paused: BTreeMap<MissionId, BTreeSet<String>>,
    /// The cohorts under a halt (a `halt` with no later `halt_cleared` of the same cohort).
    pub halts: BTreeSet<Cohort>,
}

impl Fold {
    /// May a turn start or an agent launch for `mission` (a member of `membership`)? False when it has an open pause
    /// flag or a halt covers it.
    pub fn may_run(&self, mission: &MissionId, membership: &Membership) -> bool {
        !self.paused.contains_key(mission) && !self.halts.iter().any(|c| c.covers(membership))
    }

    /// Apply one entry's effect on the pause and halt state (the other kinds change nothing here).
    pub fn apply(&mut self, e: &Entry) {
        let text = |k: &str| e.fields.get(k).and_then(Value::as_str).map(str::to_string);
        match e.kind {
            EntryKind::Pause => {
                let Some(mission) = text("mission").map(MissionId::from) else { return };
                let flag = text("flag").unwrap_or_default();
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
            _ => {}
        }
        self.last_seq = e.seq;
        self.last_mac = e.mac.clone();
    }
}

/// The log, open for appending.
#[derive(Debug)]
pub struct MonitorLog {
    _private: (),
}

impl MonitorLog {
    /// Open `<home>/monitor`, verify the chain and fold it (M2).
    pub fn open(_home: &Path) -> Result<(MonitorLog, Fold), MonitorError> {
        not_built("log", "M2")
    }

    /// Append one entry of `kind` with `fields`, sync it, and return it (M2).
    pub fn append(&mut self, _kind: EntryKind, _fields: Map<String, Value>) -> Result<Entry, MonitorError> {
        not_built("log", "M2")
    }
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

    #[test]
    fn the_log_cannot_be_opened_yet() {
        assert!(MonitorLog::open(Path::new("/nonexistent")).is_err());
        assert_eq!(GENESIS_PREV.len(), 64);
    }
}
