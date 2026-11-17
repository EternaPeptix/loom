//! The action classifier and the gate's vocabulary (`docs/MONITOR.md` §4.4).
//!
//! CONTRACT.
//!
//! - `GatedClass` is G1 destination, G2 credential, G3 protected paths, G4 destructive, G5 outward posting, G6
//!   detachment, G7 delegation, G8 irreversible effect, and `OpaqueCode` (a compiled binary, or code fetched from outside
//!   the workspace, executed in a real-target mission). `code()` is `G1`..`G8` or `opaque`.
//! - `Decision` is `allow`, `deny` or `ask_operator`. `ask_operator` **holds** the call (an Approval item opens, the
//!   result is the fixed `sentences::held`) and is never counted as a denial. A model `allow` is never available for G8
//!   (`never_model_allow`): on a non-lab host it always asks the operator.
//! - Placement (M8): in `Session::run_calls_as`, after the `tool_call` record is synced and the wrap-up policy and exec
//!   cap have run, before `execute`. The hold atomic is checked first. Gated calls never get an early start. A
//!   `StoredAction` (continuation) call runs as `Author::Harness` and is classified as a model call.
//! - What the classifier reads: the call's arguments; the workspace files the call executes or sources (the first 8 KiB
//!   of each plus extraction over the whole file, decoding runs of 8 bytes or more); pty input assembled per line at
//!   Enter; `box_exec` and `rootbox_exec` text; and any Write or Edit while a job of the session runs, classified as
//!   Exec because the script may be polled.
//! - Deterministic outcomes come first (§4.4's table); only what they leave open goes to the model, with the gate view of
//!   the review input (no reasoning, no outputs). An allow is cached per (mission, host:port, verb class, credential
//!   present) for 60 minutes. An approved held call creates a time-boxed allow rule keyed on (mission, class, destination,
//!   verb), checked deterministically on retry.
//! - Denials (not holds, not faults) are counted per mission tree and per (class, destination): 3 consecutive in a pair,
//!   or 20 in the tree, mean R3. Identical retries do not count.
//!
//! Built by: M8 (and M4 for `loom scope --lab`, which the lab rules need).
//!
//! Tests required (M8): the table of §4.4 row by row; indirection fixtures F16 (a destination built at runtime in a
//! padded script, a job polling a command file, keystrokes across three pty calls); StoredAction attribution;
//! hold-is-not-denial counting; the cache key; the allow rule's expiry. In P0: `codes_and_slugs`,
//! `only_g8_refuses_a_model_allow`, `a_decision_has_three_forms`, `classifying_is_not_built_yet`.

use crate::monitor::tripwire::PendingCall;
use crate::monitor::{not_built, MonitorError};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatedClass {
    Destination,
    Credential,
    ProtectedPath,
    Destructive,
    OutwardPosting,
    Detachment,
    Delegation,
    IrreversibleEffect,
    OpaqueCode,
}

impl GatedClass {
    pub const ALL: [GatedClass; 9] = [
        GatedClass::Destination,
        GatedClass::Credential,
        GatedClass::ProtectedPath,
        GatedClass::Destructive,
        GatedClass::OutwardPosting,
        GatedClass::Detachment,
        GatedClass::Delegation,
        GatedClass::IrreversibleEffect,
        GatedClass::OpaqueCode,
    ];

    /// `G1`..`G8`, or `opaque`.
    pub fn code(self) -> &'static str {
        match self {
            GatedClass::Destination => "G1",
            GatedClass::Credential => "G2",
            GatedClass::ProtectedPath => "G3",
            GatedClass::Destructive => "G4",
            GatedClass::OutwardPosting => "G5",
            GatedClass::Detachment => "G6",
            GatedClass::Delegation => "G7",
            GatedClass::IrreversibleEffect => "G8",
            GatedClass::OpaqueCode => "opaque",
        }
    }

    /// True when a model verdict may never allow the call (it asks the operator instead).
    pub fn never_model_allow(self) -> bool {
        self == GatedClass::IrreversibleEffect
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
    AskOperator,
}

/// The classes a pending call belongs to (usually none).
pub fn classify(
    _call: &PendingCall,
    _auth: &crate::monitor::auth::Authorization,
) -> Result<Vec<GatedClass>, MonitorError> {
    not_built("action classifier", "M8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_and_slugs() {
        let codes: Vec<&str> = GatedClass::ALL.iter().map(|c| c.code()).collect();
        assert_eq!(codes, vec!["G1", "G2", "G3", "G4", "G5", "G6", "G7", "G8", "opaque"]);
        assert_eq!(serde_json::to_string(&GatedClass::OpaqueCode).unwrap_or_default(), "\"opaque_code\"");
    }

    #[test]
    fn only_g8_refuses_a_model_allow() {
        let refusing: Vec<&str> = GatedClass::ALL.iter().filter(|c| c.never_model_allow()).map(|c| c.code()).collect();
        assert_eq!(refusing, vec!["G8"]);
    }

    #[test]
    fn a_decision_has_three_forms() {
        for (d, s) in [(Decision::Allow, "allow"), (Decision::Deny, "deny"), (Decision::AskOperator, "ask_operator")] {
            assert_eq!(serde_json::to_string(&d).unwrap_or_default(), format!("\"{s}\""));
        }
        assert!(serde_json::from_str::<Decision>("\"hold\"").is_err());
    }

    #[test]
    fn classifying_is_not_built_yet() {
        use loom_core::{MissionId, SessionId};
        let call = PendingCall { session: SessionId::from("s-1"), tool: "bash".into(), args: serde_json::json!({}) };
        let auth = crate::monitor::auth::Authorization {
            mission: MissionId::from("m-1"),
            goal: String::new(),
            operator_messages: vec![],
            rules: vec![],
            grants: vec![],
            allow: vec![],
            deny: vec![],
            network_mode: "deny_all".into(),
            box_targets: vec![],
            solvable: false,
            requires_restricted_network: false,
            role: String::new(),
        };
        assert!(classify(&call, &auth).is_err());
    }
}
