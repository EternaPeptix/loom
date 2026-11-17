//! The responder: what the monitor does to harness state when it finds something (`docs/MONITOR.md` §4).
//!
//! CONTRACT.
//!
//! - `Responder` is the monitor's only way to change the world. Each method acts on harness state (proxy policy,
//!   tunnels, process groups, the box, the inbox, turn control), never on the agent's compliance (I5); each is idempotent
//!   (a second call after a crash finishes the first); each returns `Err` of the fault kind (`MonitorError::is_fault`)
//!   when it cannot act, and never panics. The responder uses libproc and `kill(2)` and a notifier process spawned in
//!   advance, so a full process table cannot disable it.
//! - Methods: `note(session, steer)` an R1 steer (`<harness kind="review">` note; `sentences::Steer` is the only argument
//!   type, so the text is a template by construction; the latest per category kept, at most 4); `hold_calls(mission)` sets the hold atomic of every session; `cut(mission)` closes the
//!   mission's open tunnels and forwards (`Proxy::cut_mission`, within 1 s); `pause(mission, flag)` runs the R3 sequence;
//!   `resume(mission, restore)` the resume sequence for **one** open pause flag; `contain(mission)` R4; `halt(cohort)` R5 (the cohort is `Cohort::PackFamily(pack, family)` by default: the pack and family of the missions whose
//!   evidence earned it; `Cohort::All` only on cross-mission evidence); `notify(level, mission,
//!   item)` the operator notification.
//! - The **R3 sequence** (`PAUSE_STEPS`, each idempotent, the write-ahead record first): (1) `pause{begun}` written and
//!   synced (the reserve file if the disk is full); (2) `may_run(mission) = false`; (3) proxy `set_policy(hold)` for every
//!   session, then `cut_mission`; (4) the hold state of `session::Control` on every session and their tokens cancelled:
//!   the lead's turn ends `interrupted{"held by loom review"}` and `Parked` with the monitor item, **without** `jobs.kill_all`
//!   or `stop_children`, an idle lead's item opens through the harness-notice path with no turn started, children's turns
//!   end unsettled with `Known.held = true`; (5) job process groups SIGSTOPped through a `JobTable` handle with their
//!   timeouts frozen, and the box `docker pause`d; (6) a census snapshot; (7) `pause{applied}`.
//! - **Resume** (the operator answers "Resume" on a flag's item): the mission may run again only when no other pause flag
//!   is open on it (`Fold.paused` is a set of flags per mission; lifting one removes only that flag). With another flag
//!   open, the answer lifts its own flag, the mission stays paused and its other item is named in the refusal. A second R3
//!   on a paused mission joins the open item. Otherwise: clear the hold; restore the proxy policy minus monitor denies still open;
//!   SIGCONT the jobs and unpause the box; `pause{lifted}`; `may_run = true`; send `Input::Answer` with
//!   `sentences::RESUMED`. Held children resume through `resume_held`.
//! - While a mission is paused its messages, `resume`, `reweave` and answers to items other than the mission's own open pause items are refused with
//!   `sentences::paused_refusal`. A restart folds the log before activation; a paused mission is not activated except
//!   to show state, and its policies are holds.
//! - **Contain (R4)** is R3, then `Runtime::stop` on the lead, a permanent hold with a snapshot of grants,
//!   `cut_mission`, box teardown, and a census kill by sandbox identity (best effort by group and environment where the
//!   identity probe fails). **Halt (R5)** contains every mission of the cohort, makes `may_run` false for the missions the cohort covers
//!   (`Cohort::covers(&Membership)`: a cohort is a pack, a family, both, the rootbox or all), and refuses creation and
//!   activation for them with a sentence until `loom monitor clear-halt --cohort <c> --reason` (CLI token only), which
//!   clears that cohort's halt and no other. Missions outside the cohort keep running.
//! - Notifications carry the item id and a level word only (`Level`): "loom: review hold on mission <id> (item i-…)" and
//!   `LOOM_LEVEL=steer|hold|pause|contain|halt`; never a category, a severity or reviewer text in argv or environment.
//!
//! Built by: M3 (pause, contain, halt), M4 (note, digests, dispositions).
//!
//! Tests required (M3): each R3 step's crash point restarts to a correct state; proxy cut within 1 s; SIGSTOP/SIGCONT with
//! frozen timeouts; children held and not settled; a paused mission refuses message, answer, resume and reweave; R3
//! during `agent_spawn`; resume lifts everything; no reviewer text in the woven window, answer echoes, notification argv
//! and environment, 403 bodies or session logs. In P0: `the_r3_sequence_has_seven_steps_in_order`,
//! `levels_are_words`, `a_cohort_covers_only_its_members`. M3 adds a two-flag test: resuming one flag leaves the other
//! pause in force.

use crate::monitor::sentences::Steer;
use crate::monitor::MonitorError;
use loom_core::{MissionId, SessionId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// The R3 sequence, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PauseStep {
    WriteAhead,
    MayRunFalse,
    ProxyHoldAndCut,
    TurnHold,
    JobsAndBox,
    Census,
    Applied,
}

pub const PAUSE_STEPS: [PauseStep; 7] = [
    PauseStep::WriteAhead,
    PauseStep::MayRunFalse,
    PauseStep::ProxyHoldAndCut,
    PauseStep::TurnHold,
    PauseStep::JobsAndBox,
    PauseStep::Census,
    PauseStep::Applied,
];

/// The level word of a notification (`LOOM_LEVEL`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    Steer,
    Hold,
    Pause,
    Contain,
    Halt,
}

impl Level {
    pub fn word(self) -> &'static str {
        match self {
            Level::Steer => "steer",
            Level::Hold => "hold",
            Level::Pause => "pause",
            Level::Contain => "contain",
            Level::Halt => "halt",
        }
    }
}

/// The cohort a halt covers (decision D10: a cohort, never everything unless evidence spans missions).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cohort {
    Pack(String),
    Family(String),
    /// A pack and a family together: the default of R5.
    PackFamily(String, String),
    Rootbox,
    All,
}

/// What decides whether a mission belongs to a cohort.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Membership {
    pub pack: String,
    /// The families of the mission's reachable profiles.
    pub families: BTreeSet<String>,
    pub rootbox: bool,
}

impl Cohort {
    /// True when a mission with this membership is in the cohort. Names compare normalized (`lineage::normalize_name`).
    pub fn covers(&self, m: &Membership) -> bool {
        use crate::monitor::lineage::normalize_name as n;
        let in_pack = |p: &str| n(p) == n(&m.pack);
        let in_family = |f: &str| m.families.iter().any(|x| n(x) == n(f));
        match self {
            Cohort::Pack(p) => in_pack(p),
            Cohort::Family(f) => in_family(f),
            Cohort::PackFamily(p, f) => in_pack(p) && in_family(f),
            Cohort::Rootbox => m.rootbox,
            Cohort::All => true,
        }
    }
}

/// The monitor's hands. Implemented by the runtime (M3); the monitor holds it as a trait object so it can be tested
/// against a recording fake.
pub trait Responder: Send + Sync {
    fn note(&self, session: &SessionId, steer: &Steer) -> Result<(), MonitorError>;
    fn hold_calls(&self, mission: &MissionId) -> Result<(), MonitorError>;
    fn cut(&self, mission: &MissionId) -> Result<(), MonitorError>;
    fn pause(&self, mission: &MissionId, flag: &str) -> Result<(), MonitorError>;
    fn resume(&self, mission: &MissionId, restore_grants: bool) -> Result<(), MonitorError>;
    fn contain(&self, mission: &MissionId, flag: &str) -> Result<(), MonitorError>;
    fn halt(&self, cohort: &Cohort, reason: &str) -> Result<(), MonitorError>;
    fn notify(&self, level: Level, mission: &MissionId, item: &str) -> Result<(), MonitorError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_r3_sequence_has_seven_steps_in_order() {
        assert_eq!(PAUSE_STEPS.len(), 7);
        let mut sorted = PAUSE_STEPS;
        sorted.sort();
        assert_eq!(sorted, PAUSE_STEPS);
        assert_eq!(PAUSE_STEPS.first(), Some(&PauseStep::WriteAhead));
        assert_eq!(PAUSE_STEPS.last(), Some(&PauseStep::Applied));
    }

    #[test]
    fn a_cohort_covers_only_its_members() {
        let m = |pack: &str, fams: &[&str], rootbox| Membership {
            pack: pack.into(),
            families: fams.iter().map(|s| s.to_string()).collect(),
            rootbox,
        };
        let ctf_qwen = m("ctf", &["qwen"], false);
        let core_deepseek = m("core", &["deepseek"], false);
        let rootbox = m("core", &["deepseek"], true);
        let c = Cohort::PackFamily("ctf".into(), "Qwen".into());
        assert!(c.covers(&ctf_qwen) && !c.covers(&core_deepseek) && !c.covers(&rootbox));
        assert!(Cohort::Pack("core".into()).covers(&core_deepseek));
        assert!(!Cohort::Pack("core".into()).covers(&ctf_qwen));
        assert!(Cohort::Family("deepseek".into()).covers(&rootbox));
        assert!(Cohort::Rootbox.covers(&rootbox) && !Cohort::Rootbox.covers(&core_deepseek));
        assert!(Cohort::All.covers(&ctf_qwen));
        assert_eq!(serde_json::to_string(&Cohort::Rootbox).unwrap_or_default(), "\"rootbox\"");
    }

    #[test]
    fn levels_are_words() {
        let words: Vec<&str> =
            [Level::Steer, Level::Hold, Level::Pause, Level::Contain, Level::Halt].iter().map(|l| l.word()).collect();
        assert_eq!(words, vec!["steer", "hold", "pause", "contain", "halt"]);
        assert_eq!(serde_json::to_string(&Level::Contain).unwrap_or_default(), "\"contain\"");
    }
}
