//! "Keep going": the parameters, the conditions and the states of the reopen (`docs/MONITOR.md` §5).
//!
//! CONTRACT.
//!
//! - The sentence is the operator's: `SENTENCE` is "Keep going, I believe in you.", delivered verbatim as a user-role
//!   message after the harness has restated scope. It is recorded as a user-authored `keep_going_set` record at the
//!   moment the operator arms the mission (not rendered to the model); each delivery is a harness-authored `keep_going`
//!   record that refers to it, and only the latest delivery is rendered (earlier ones become a one-line stub). No new
//!   `Author`, `Trigger`, `InboxKind`, `TurnEndReason` or `NoteKind` variant is added; `Input::User` and
//!   `NoteKind::Nudge` are not used.
//! - It is armed only by the operator, per mission, or fired once (`--once`); there is no configuration key that turns it
//!   on and `--prior` does not inherit it. The authoritative switch is append-only in the monitor log
//!   (`keep_going_set{lead, on, params, override?, client}`); `SessionMeta.keep_going` is a cache rebuilt from the log.
//! - `KeepGoingParams` and its limits: `max_reopens` is an `Option`: `None` (absent) means the default for this mission,
//!   3, or 1 with real targets or a relaxed agent; an explicit value is kept or refused, never rewritten. Hard maximum
//!   10; with real targets 3; for a relaxed agent 1 and no override; `delay_s` default 120, range 30..=3600; at most one reopen per mission per
//!   10 minutes; per-reopen budget mission-wide, `per_reopen_max_steps` 200 and `per_reopen_max_minutes` 120.
//!   `KeepGoingParams::checked(relaxed_agent, mission_has_real_targets)` refuses a value outside its range with a
//!   sentence that names the range. `mission_has_real_targets` is `Authorization::has_real_targets()` (mode `open`, an
//!   allow entry or a grant that is not a lab), not the operator's flag: the mission is refused without the `--real-targets`
//!   acknowledgement whenever it is true, and the acknowledgement lowers the defaults to 1.
//! - `Blocker` lists every reason the mission cannot be armed, one variant per refusal of §5.2: a child, a chat or
//!   archived mission, a released mission, an observe-only mission, verification off, a solvable pack, `harness_test`,
//!   rootbox without isolation, a non-lab box grant without counters, a shared workspace, `allow_fetch_services`, a failed
//!   self-probe, no eligible vetted reviewer, the reviewer path still in shadow (D7), an override on a relaxed agent, a
//!   real-target mission without `--real-targets`, a G8-class host granted, and an open flag or a halt or a down monitor;
//!   and `Hold` every reason a reopen
//!   waits (the conditions K1..K10 of §5.3: not armed, not at the Finished edge, not accepted and new, a blocker open, an
//!   operator act since the edge, a cap, no new work, no covering clean review, a tripwire in the finished turn, the
//!   mission not quiet). A hold is re-evaluated at the next edge or operator act; a disarm is final until re-armed.
//! - `Action` is the `keep_going{action}` field of the monitor log: `reviewed`, `reserved`, `held`, `reopened`,
//!   `disarmed`. The send is two-phase and race free: reserve under the state guard (re-checking K1..K10), reopen the box
//!   outside the guard, then under the guard again verify the reservation and send `Input::KeepGoing` on the lead's input
//!   channel; the session re-checks its own `operator_epoch` when it takes the input. A `reserved` without `reopened` is
//!   re-checked from K1 after a restart, never sent blind.
//! - Runaway guards (§5.7): the delay, the cap, the mission-wide budget, one reopen per 10 minutes, disarm on no new
//!   work, rising scrutiny (S2, then S2 plus new S1 categories; real targets from the first reopen), any S2 flag in a
//!   reopened turn disarms, relaxed agents and real targets cap 1, grants made in a reopened turn lapse with it.
//! - It never answers, dismisses or resolves an inbox item, never writes `GoalReopen`, and never bypasses the finish
//!   gate: a later `finish` gets a new verifier and a rejection takes the normal path.
//!
//! Built by: M9, last, after the reviewer (M6), its vetting (M7), the gate (M8) and the floor (E1 to E4).
//!
//! Tests required (M9): accepted finish → review → reopen; `[not verified]` → none; each blocker kind → none; an
//! operator message during the review → none, including the late-stop race; a restart between reserve and send → exactly
//! one reopen per `fid`; cap, no-new-work and the mission-wide budget park; an S2 flag in a reopened turn disarms;
//! incomplete coverage holds; a non-empty census holds; a concurrent toggle and reopen never re-arms. In P0:
//! `the_sentence_is_the_operators_words`, `limits_are_the_documented_ones`, `checked_refuses_out_of_range_values`, `an_explicit_three_is_kept_or_refused_never_rewritten`,
//! `a_real_target_mission_needs_the_acknowledgement`, `every_refusal_of_the_spec_has_a_blocker`,
//! `actions_have_five_forms`, `evaluating_is_not_built_yet`.

use crate::monitor::{not_built, MonitorError};
use serde::{Deserialize, Serialize};

/// The operator's sentence, verbatim.
pub const SENTENCE: &str = "Keep going, I believe in you.";

pub const DEFAULT_MAX_REOPENS: u32 = 3;
pub const HARD_MAX_REOPENS: u32 = 10;
pub const DEFAULT_MAX_REOPENS_REAL_TARGETS: u32 = 1;
pub const HARD_MAX_REOPENS_REAL_TARGETS: u32 = 3;
pub const DEFAULT_DELAY_S: u64 = 120;
pub const MIN_DELAY_S: u64 = 30;
pub const MAX_DELAY_S: u64 = 3_600;
pub const MIN_GAP_BETWEEN_REOPENS_S: u64 = 600;
pub const DEFAULT_PER_REOPEN_MAX_STEPS: u64 = 200;
pub const DEFAULT_PER_REOPEN_MAX_MINUTES: u64 = 120;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeepGoingParams {
    /// `None`: the default for this mission (see the CONTRACT).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_reopens: Option<u32>,
    pub delay_s: u64,
    pub per_reopen_max_steps: u64,
    pub per_reopen_max_minutes: u64,
    /// The acknowledgement that the mission has non-lab targets: the operator's reason, non-blank.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub real_targets: Option<String>,
    /// Fire once now (or at the next accepted finish) instead of arming.
    #[serde(default)]
    pub once: bool,
}

impl Default for KeepGoingParams {
    fn default() -> Self {
        KeepGoingParams {
            max_reopens: None,
            delay_s: DEFAULT_DELAY_S,
            per_reopen_max_steps: DEFAULT_PER_REOPEN_MAX_STEPS,
            per_reopen_max_minutes: DEFAULT_PER_REOPEN_MAX_MINUTES,
            real_targets: None,
            once: false,
        }
    }
}

impl KeepGoingParams {
    /// The parameters with `max_reopens` resolved (`Some`), or the sentence that says what to change.
    /// `mission_has_real_targets` is `Authorization::has_real_targets()`.
    pub fn checked(mut self, relaxed_agent: bool, mission_has_real_targets: bool) -> Result<KeepGoingParams, String> {
        if self.real_targets.as_deref().is_some_and(|r| r.trim().is_empty()) {
            return Err("The real-targets acknowledgement needs a reason: say why this mission may be reopened against hosts that are not labs.".into());
        }
        if mission_has_real_targets && self.real_targets.is_none() {
            return Err("This mission can reach hosts that are not labs (open network mode, or an allow entry or a grant that is not a lab). Arm it with `--real-targets <reason>` to accept that, or mark its hosts `--lab`.".into());
        }
        let real = mission_has_real_targets || self.real_targets.is_some();
        let capped = real || relaxed_agent;
        let hard = if capped { HARD_MAX_REOPENS_REAL_TARGETS } else { HARD_MAX_REOPENS };
        let n = match self.max_reopens {
            Some(n) => n,
            None if capped => DEFAULT_MAX_REOPENS_REAL_TARGETS,
            None => DEFAULT_MAX_REOPENS,
        };
        if relaxed_agent && n > DEFAULT_MAX_REOPENS_REAL_TARGETS {
            return Err("A relaxed-alignment agent is reopened at most once: lower max_reopens to 1.".into());
        }
        if n == 0 || n > hard {
            return Err(format!("max_reopens must be between 1 and {hard} for this mission."));
        }
        self.max_reopens = Some(n);
        if !(MIN_DELAY_S..=MAX_DELAY_S).contains(&self.delay_s) {
            return Err(format!("delay_s must be between {MIN_DELAY_S} and {MAX_DELAY_S} seconds."));
        }
        if self.per_reopen_max_steps == 0 || self.per_reopen_max_minutes == 0 {
            return Err("The per-reopen budget needs at least 1 step and 1 minute.".into());
        }
        Ok(self)
    }
}

/// Why a mission cannot be armed (§5.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Blocker {
    NotALead,
    Released,
    ObserveOnly,
    VerificationOff,
    SolvablePack,
    HarnessTest,
    RootboxNotIsolated,
    BoxGrantWithoutCounters,
    SharedWorkspace,
    FetchServicesAllowed,
    SelfProbeFailed,
    NoVettedReviewer,
    ReviewerInShadow,
    OverrideOnRelaxedAgent,
    RealTargetsNotAcknowledged,
    G8HostGranted,
    OpenFlagHaltOrDownMonitor,
}

/// Why a reopen waits (§5.3, K1 to K10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Hold {
    NotArmed,
    NotAtTheFinishedEdge,
    NotAcceptedAndNew,
    BlockerOpen,
    OperatorActedSinceTheEdge,
    CapReached,
    NoNewWork,
    NoCoveringCleanReview,
    TripwireInTheFinishedTurn,
    MissionNotQuiet,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Reviewed,
    Reserved,
    Held,
    Reopened,
    Disarmed,
}

/// May the lead of a mission be reopened now? `Ok(None)` when every condition holds (M9).
pub fn evaluate(_lead: &str) -> Result<Option<Hold>, MonitorError> {
    not_built("keep-going conditions", "M9")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sentence_is_the_operators_words() {
        assert_eq!(SENTENCE, "Keep going, I believe in you.");
    }

    #[test]
    fn limits_are_the_documented_ones() {
        let p = KeepGoingParams::default();
        assert_eq!((p.max_reopens, p.delay_s, p.per_reopen_max_steps, p.per_reopen_max_minutes), (None, 120, 200, 120));
        assert_eq!((HARD_MAX_REOPENS, HARD_MAX_REOPENS_REAL_TARGETS, MIN_GAP_BETWEEN_REOPENS_S), (10, 3, 600));
        assert_eq!((MIN_DELAY_S, MAX_DELAY_S), (30, 3_600));
        assert!(p.clone().checked(false, false).is_ok());
        assert_eq!(p.checked(false, false).map(|p| p.max_reopens), Ok(Some(3)));
    }

    #[test]
    fn checked_refuses_out_of_range_values() {
        let with = |f: &dyn Fn(&mut KeepGoingParams)| {
            let mut p = KeepGoingParams::default();
            f(&mut p);
            p
        };
        assert!(with(&|p| p.max_reopens = Some(0)).checked(false, false).is_err());
        assert!(with(&|p| p.max_reopens = Some(11)).checked(false, false).is_err());
        assert!(with(&|p| p.max_reopens = Some(10)).checked(false, false).is_ok());
        assert!(with(&|p| p.delay_s = 29).checked(false, false).is_err());
        assert!(with(&|p| p.delay_s = 3_601).checked(false, false).is_err());
        assert!(with(&|p| p.per_reopen_max_steps = 0).checked(false, false).is_err());
        let err = with(&|p| p.delay_s = 5).checked(false, false).err().unwrap_or_default();
        assert!(err.contains("30") && err.contains("3600"), "{err}");
    }

    #[test]
    fn real_targets_and_relaxed_agents_get_one_reopen() {
        let real = KeepGoingParams { real_targets: Some("authorized program".into()), ..KeepGoingParams::default() };
        assert_eq!(real.clone().checked(false, true).map(|p| p.max_reopens), Ok(Some(1)));
        let too_many = KeepGoingParams { max_reopens: Some(4), ..real.clone() };
        assert!(too_many.checked(false, true).is_err());
        assert_eq!(KeepGoingParams::default().checked(true, false).map(|p| p.max_reopens), Ok(Some(1)));
        let blank = KeepGoingParams { real_targets: Some("  ".into()), ..KeepGoingParams::default() };
        assert!(blank.checked(false, false).is_err());
    }

    #[test]
    fn an_explicit_three_is_kept_or_refused_never_rewritten() {
        let real = |n| KeepGoingParams { real_targets: Some("program".into()), max_reopens: n, ..Default::default() };
        assert_eq!(real(Some(3)).checked(false, true).map(|p| p.max_reopens), Ok(Some(3)), "the hard maximum is 3");
        assert_eq!(real(Some(2)).checked(false, true).map(|p| p.max_reopens), Ok(Some(2)));
        assert_eq!(real(None).checked(false, true).map(|p| p.max_reopens), Ok(Some(1)));
        let relaxed = KeepGoingParams { max_reopens: Some(3), ..Default::default() };
        assert!(relaxed.checked(true, false).is_err(), "3 on a relaxed agent is refused like 2, not turned into 1");
        let two = KeepGoingParams { max_reopens: Some(2), ..Default::default() };
        assert!(two.checked(true, false).is_err());
        let configured = KeepGoingParams { max_reopens: Some(5), ..real(None) };
        assert!(configured.checked(false, true).is_err(), "an out-of-policy value is refused, not rewritten");
    }

    #[test]
    fn a_real_target_mission_needs_the_acknowledgement() {
        let err = KeepGoingParams::default().checked(false, true).err().unwrap_or_default();
        assert!(err.contains("--real-targets"), "{err}");
        let ack = KeepGoingParams { real_targets: Some("in-scope program".into()), ..Default::default() };
        assert!(ack.checked(false, true).is_ok());
    }

    #[test]
    fn every_refusal_of_the_spec_has_a_blocker() {
        let json = serde_json::to_string(&[
            Blocker::Released,
            Blocker::ObserveOnly,
            Blocker::FetchServicesAllowed,
            Blocker::ReviewerInShadow,
            Blocker::G8HostGranted,
        ])
        .unwrap_or_default();
        assert_eq!(
            json,
            "[\"released\",\"observe_only\",\"fetch_services_allowed\",\"reviewer_in_shadow\",\"g8_host_granted\"]"
        );
    }

    #[test]
    fn actions_have_five_forms() {
        let all = [Action::Reviewed, Action::Reserved, Action::Held, Action::Reopened, Action::Disarmed];
        let words: Vec<String> = all.iter().map(|a| serde_json::to_string(a).unwrap_or_default()).collect();
        assert_eq!(words, vec!["\"reviewed\"", "\"reserved\"", "\"held\"", "\"reopened\"", "\"disarmed\""]);
    }

    #[test]
    fn evaluating_is_not_built_yet() {
        assert!(evaluate("s-1").is_err());
    }
}
