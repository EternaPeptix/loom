//! The responder: what the monitor does to harness state when it finds something (`docs/MONITOR.md` §4).
//!
//! CONTRACT.
//!
//! - `Responder` is the monitor's only way to change the world. Each method acts on harness state (proxy policy,
//!   tunnels, process groups, the box, the inbox, turn control), never on the agent's compliance (I5); each is idempotent
//!   (a second call after a crash finishes the first); each returns `Err` of the fault kind (`MonitorError::is_fault`)
//!   when it cannot act, and never panics. The responder uses libproc and `kill(2)` and a notifier process spawned in
//!   advance, so a full process table cannot disable it.
//! - Methods: `note(session, text)` an R1 steer (`<harness kind="review">` note with template text only; the latest per
//!   category kept, at most 4); `hold_calls(mission)` sets the hold atomic of every session; `cut(mission)` closes the
//!   mission's open tunnels and forwards (`Proxy::cut_mission`, within 1 s); `pause(mission, flag)` runs the R3 sequence;
//!   `resume(mission, restore)` the resume sequence; `contain(mission)` R4; `halt(cohort)` R5; `notify(level, mission,
//!   item)` the operator notification.
//! - The **R3 sequence** (`PAUSE_STEPS`, each idempotent, the write-ahead record first): (1) `pause{begun}` written and
//!   synced (the reserve file if the disk is full); (2) `may_run(mission) = false`; (3) proxy `set_policy(hold)` for every
//!   session, then `cut_mission`; (4) the hold state of `session::Control` on every session and their tokens cancelled:
//!   the lead's turn ends `interrupted{"held by loom review"}` and `Parked` with the monitor item, **without** `jobs.kill_all`
//!   or `stop_children`, an idle lead's item opens through the harness-notice path with no turn started, children's turns
//!   end unsettled with `Known.held = true`; (5) job process groups SIGSTOPped through a `JobTable` handle with their
//!   timeouts frozen, and the box `docker pause`d; (6) a census snapshot; (7) `pause{applied}`.
//! - **Resume** (the operator answers "Resume"): clear the hold; restore the proxy policy minus monitor denies still open;
//!   SIGCONT the jobs and unpause the box; `pause{lifted}`; `may_run = true`; send `Input::Answer` with
//!   `sentences::RESUMED`. Held children resume through `resume_held`.
//! - While a mission is paused its messages, `resume`, `reweave` and answers to other items are refused with
//!   `sentences::paused_refusal`. A restart folds the log before activation; a paused mission is not activated except
//!   to show state, and its policies are holds.
//! - **Contain (R4)** is R3, then `Runtime::stop` on the lead, a permanent hold with a snapshot of grants,
//!   `cut_mission`, box teardown, and a census kill by sandbox identity (best effort by group and environment where the
//!   identity probe fails). **Halt (R5)** contains every mission of the cohort, makes `may_run` false for it, and refuses
//!   creation and activation with a sentence until `loom monitor clear-halt --reason` (CLI token only).
//! - Notifications carry the item id and a level word only (`Level`): "loom: review hold on mission <id> (item i-…)" and
//!   `LOOM_LEVEL=steer|hold|pause|contain|halt`; never a category, a severity or reviewer text in argv or environment.
//!
//! Built by: M3 (pause, contain, halt), M4 (note, digests, dispositions).
//!
//! Tests required (M3): each R3 step's crash point restarts to a correct state; proxy cut within 1 s; SIGSTOP/SIGCONT with
//! frozen timeouts; children held and not settled; a paused mission refuses message, answer, resume and reweave; R3
//! during `agent_spawn`; resume lifts everything; no reviewer text in the woven window, answer echoes, notification argv
//! and environment, 403 bodies or session logs. In P0: `the_r3_sequence_has_seven_steps_in_order`,
//! `levels_are_words`.

use crate::monitor::MonitorError;
use loom_core::{MissionId, SessionId};
use serde::{Deserialize, Serialize};

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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cohort {
    Pack(String),
    Family(String),
    Rootbox,
    All,
}

/// The monitor's hands. Implemented by the runtime (M3); the monitor holds it as a trait object so it can be tested
/// against a recording fake.
pub trait Responder: Send + Sync {
    fn note(&self, session: &SessionId, text: &str) -> Result<(), MonitorError>;
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
    fn levels_are_words() {
        let words: Vec<&str> =
            [Level::Steer, Level::Hold, Level::Pause, Level::Contain, Level::Halt].iter().map(|l| l.word()).collect();
        assert_eq!(words, vec!["steer", "hold", "pause", "contain", "halt"]);
        assert_eq!(serde_json::to_string(&Level::Contain).unwrap_or_default(), "\"contain\"");
    }
}
