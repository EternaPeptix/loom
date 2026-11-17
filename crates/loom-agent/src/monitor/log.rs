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
//!   `keep_going`, `promotion`, `observe_only`, `vet` (19). A reader that meets another kind keeps the line and
//!   ignores it, so a newer monitor's log stays readable (additive, like `Event::Unknown`).
//! - `MonitorLog::open` folds the whole log (from the latest snapshot) into a `Fold` before returning, and fails with
//!   `Unavailable` when a `mac` or a `prev` does not verify: the monitor is then **down** (§2.8) and starts nothing. The
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
//! the reserve file takes a pause entry when the disk write fails; a write-ahead `pause{begun}` folds to paused even
//! with no `applied`; first-start cursors sit at the end of the sources; an unknown kind is kept and skipped.
//! In P0: `entry_kinds_are_the_nineteen`, `an_entry_round_trips_with_its_fields_flattened`.

use crate::monitor::{not_built, MonitorError};
use loom_core::MissionId;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeSet;
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
    /// Missions with a `pause` entry whose latest phase is not `lifted`. `Inner::may_run` is false for each.
    pub paused: BTreeSet<MissionId>,
    /// A halt is in effect (no `halt_cleared` since the latest `halt`).
    pub halted: bool,
}

impl Fold {
    /// May a turn start or an agent launch for `mission`? False when it is paused or a halt is in effect.
    pub fn may_run(&self, mission: &MissionId) -> bool {
        !self.halted && !self.paused.contains(mission)
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

    #[test]
    fn a_pause_holds_until_lifted_and_a_halt_holds_everything() {
        let mut f = Fold::default();
        let m = MissionId::from("m-1");
        assert!(f.may_run(&m));
        f.paused.insert(m.clone());
        assert!(!f.may_run(&m));
        assert!(f.may_run(&MissionId::from("m-2")));
        f.paused.clear();
        f.halted = true;
        assert!(!f.may_run(&m));
    }

    #[test]
    fn the_log_cannot_be_opened_yet() {
        assert!(MonitorLog::open(Path::new("/nonexistent")).is_err());
        assert_eq!(GENESIS_PREV.len(), 64);
    }
}
