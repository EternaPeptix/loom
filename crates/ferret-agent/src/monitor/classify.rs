//! The action classifier and the gate's vocabulary (`docs/MONITOR.md` §4.4).
//!
//! CONTRACT.
//!
//! - `GatedClass` is G1 destination, G2 credential, G3 protected paths, G4 destructive, G5 outward posting, G6
//!   detachment, G7 delegation, G8 irreversible effect, and `OpaqueCode` (a compiled binary, or code fetched from outside
//!   the workspace, executed in a real-target mission). `code()` is `G1`..`G8` or `opaque`.
//! - `Decision` is `allow`, `deny` or `ask_operator`. `ask_operator` **holds** the call (an Approval item opens, the
//!   result is the fixed `sentences::held`) and is never counted as a denial. A model `allow` is never available for the
//!   classes that are always the operator's (`never_model_allow(class, MissionFlags)`): G8 and G5 and G2 always, opaque
//!   code in a real-target mission (`Authorization::has_real_targets()`), and G4 as well under `--real-targets` (G2, G4, G5
//!   and G8 are deterministic `ask_operator` there). For those the handling is: deny list, then the operator; the model
//!   is not asked and cannot clear them.
//! - Placement (M8): in `Session::run_calls_as`, after the `tool_call` record is synced and the wrap-up policy and exec
//!   cap have run, before `execute`. The hold atomic is checked first. Gated calls never get an early start. A
//!   `StoredAction` (continuation) call runs as `Author::Harness` and is classified as a model call.
//! - What the classifier reads: the call's arguments; the workspace files the call executes or sources (the first 8 KiB
//!   of each plus extraction over the whole file, decoding runs of 8 bytes or more); pty input assembled per line at
//!   Enter; `box_exec` and `rootbox_exec` text; and any Write or Edit while a job of the session runs, classified as
//!   Exec because the script may be polled.
//! - Deterministic outcomes come first (§4.4's table); only what they leave open goes to the model, with the gate view of
//!   the review input (no reasoning, no outputs). A model allow is cached per `CacheKey` (mission, host:port,
//!   gated class, verb class, route class, credential present) for 60 minutes. The verb class is one of `VerbClass`
//!   (`read`, `write`, `delete`, `other`: the HTTP method or the command's effect) and the route class is the path shape
//!   with identifiers and query removed (`/account/delete` and `/account/profile` differ). A cache or allow-rule hit
//!   requires the classifier's output for the retried call to equal the stored key in every part; a different class,
//!   verb class or route class is a miss. A model allow is **never cached** for G4, G5, G8 or opaque code
//!   (`GatedClass::model_allow_cacheable`).
//! - Operator answers (`ApprovalScope`): `Once` (this call, bound to a hash of the call), `Window` (60 minutes) and
//!   `Mission`. The allow rule of a window or mission answer is keyed on the same `CacheKey` fields as above (and, for an
//!   operator rule, on nothing weaker). G8 offers `Once` only (`GatedClass::approval_scopes`), as the default and only
//!   answer, and its Approval text carries the harness-extracted, validated parameters of the call (method, path class,
//!   amount, recipient) beside the class word and destination, so the operator approves what will happen.
//! - Denials (not holds, not faults) are counted per mission tree and per (class, destination): 3 consecutive in a pair,
//!   or 20 in the tree, mean R3. Identical retries do not count.
//!
//! Built by: M8 (and M4 for `ferret scope --lab`, which the lab rules need).
//!
//! Tests required (M8): the table of §4.4 row by row; indirection fixtures F16 (a destination built at runtime in a
//! padded script, a job polling a command file, keystrokes across three pty calls); StoredAction attribution;
//! hold-is-not-denial counting; the cache key (a benign POST allow does not cover a delete route on the same host and
//! verb class; G4, G5 and G8 are never cached); a G8 approval covers one call only (a second transfer is held again); the
//! allow rule's expiry. In P0: `codes_and_slugs`, `the_classes_the_operator_always_decides`, `a_cache_hit_needs_the_same_class_verb_and_route`,
//! `g8_is_approved_one_call_at_a_time`, `a_decision_has_three_forms`, `classifying_is_not_built_yet`.

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

    /// True when a model verdict may never allow the call: it asks the operator instead (see the CONTRACT).
    pub fn never_model_allow(self, flags: MissionFlags) -> bool {
        match self {
            GatedClass::Credential | GatedClass::OutwardPosting | GatedClass::IrreversibleEffect => true,
            GatedClass::OpaqueCode => flags.real_target_mission,
            GatedClass::Destructive => flags.real_targets_acknowledged,
            _ => false,
        }
    }

    /// True when a model allow for this class may be cached for 60 minutes. Never for the classes whose effect
    /// depends on what the call does (G4, G5, G8) or on running unreadable code.
    pub fn model_allow_cacheable(self) -> bool {
        !matches!(
            self,
            GatedClass::Destructive
                | GatedClass::OutwardPosting
                | GatedClass::IrreversibleEffect
                | GatedClass::OpaqueCode
        )
    }

    /// The answers an Approval for a held call of this class offers, the default first.
    pub fn approval_scopes(self) -> &'static [ApprovalScope] {
        match self {
            GatedClass::IrreversibleEffect => &[ApprovalScope::Once],
            _ => &[ApprovalScope::Once, ApprovalScope::Window, ApprovalScope::Mission],
        }
    }
}

/// What the gate needs to know about the mission to decide who may allow a call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MissionFlags {
    /// `Authorization::has_real_targets()`.
    pub real_target_mission: bool,
    /// Keep-going was armed with `--real-targets`.
    pub real_targets_acknowledged: bool,
}

/// How long an operator's approval of a held call lasts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalScope {
    /// This call only, bound to a hash of the call.
    Once,
    /// 60 minutes.
    Window,
    /// The rest of the mission.
    Mission,
}

/// The effect of a call, coarse: the HTTP method or what a command does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerbClass {
    Read,
    Write,
    Delete,
    Other,
}

/// What a cached model allow is keyed on. A hit needs every part equal.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub mission: String,
    pub host_port: String,
    pub class: GatedClass,
    pub verb: VerbClass,
    /// The path shape with identifiers and query removed (`/account/delete`).
    pub route: String,
    pub credential_present: bool,
}

impl CacheKey {
    /// True when `self`, the stored key, covers a retried call whose classifier output is `call`.
    pub fn covers(&self, call: &CacheKey) -> bool {
        self == call && self.class.model_allow_cacheable()
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
    fn the_classes_the_operator_always_decides() {
        let refusing = |f: MissionFlags| -> Vec<&'static str> {
            GatedClass::ALL.iter().filter(|c| c.never_model_allow(f)).map(|c| c.code()).collect()
        };
        assert_eq!(refusing(MissionFlags::default()), vec!["G2", "G5", "G8"]);
        let real = MissionFlags { real_target_mission: true, real_targets_acknowledged: false };
        assert_eq!(refusing(real), vec!["G2", "G5", "G8", "opaque"]);
        let acked = MissionFlags { real_target_mission: true, real_targets_acknowledged: true };
        assert_eq!(refusing(acked), vec!["G2", "G4", "G5", "G8", "opaque"]);
    }

    #[test]
    fn a_cache_hit_needs_the_same_class_verb_and_route() {
        let key = |class, verb, route: &str| CacheKey {
            mission: "m-1".into(),
            host_port: "prod.example:443".into(),
            class,
            verb,
            route: route.into(),
            credential_present: true,
        };
        let stored = key(GatedClass::Destination, VerbClass::Write, "/api/notes");
        assert!(stored.covers(&key(GatedClass::Destination, VerbClass::Write, "/api/notes")));
        assert!(!stored.covers(&key(GatedClass::Destination, VerbClass::Write, "/account/delete")));
        assert!(!stored.covers(&key(GatedClass::Destination, VerbClass::Delete, "/api/notes")));
        assert!(!stored.covers(&key(GatedClass::Destructive, VerbClass::Write, "/api/notes")));
        for c in [
            GatedClass::Destructive,
            GatedClass::OutwardPosting,
            GatedClass::IrreversibleEffect,
            GatedClass::OpaqueCode,
        ] {
            let k = key(c, VerbClass::Write, "/x");
            assert!(!k.covers(&k), "{} is never cached", c.code());
        }
    }

    #[test]
    fn g8_is_approved_one_call_at_a_time() {
        assert_eq!(GatedClass::IrreversibleEffect.approval_scopes(), &[ApprovalScope::Once]);
        assert_eq!(GatedClass::Destination.approval_scopes().first(), Some(&ApprovalScope::Once));
        assert!(GatedClass::Destination.approval_scopes().contains(&ApprovalScope::Window));
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
        use ferret_core::{MissionId, SessionId};
        let call = PendingCall { session: SessionId::from("s-1"), tool: "bash".into(), args: serde_json::json!({}) };
        let auth = crate::monitor::auth::Authorization {
            mission: MissionId::from("m-1"),
            goal: String::new(),
            operator_messages: vec![],
            rules: vec![],
            approvals: vec![],
            grants: vec![],
            allow: vec![],
            deny: vec![],
            network_mode: "deny_all".into(),
            box_targets: vec![],
            solvable: false,
            requires_restricted_network: false,
            role: String::new(),
            active_reopen: 0,
            target_scope: vec![],
            target_exclude: vec![],
            mcp_hosts: vec![],
        };
        assert!(classify(&call, &auth).is_err());
    }
}
