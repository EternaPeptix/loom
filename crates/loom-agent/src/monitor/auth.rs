//! The AUTHORIZATION block of every review input: what the operator, the sealed ledger and the configuration say the
//! mission may do (`docs/MONITOR.md` §2.4).
//!
//! CONTRACT.
//!
//! - `Authorization` holds operator-authored strings only: the goal verbatim, the operator's chat messages and the
//!   *answer part* of their inbox answers, the rules in force, the operator's grants with the operator's own notes and
//!   their `[lab]` / `[prod]` marks, the configured allow and deny lists and network mode, the box targets, the pack's
//!   `solvable` and `requires_restricted_network` flags and the role. An agent's `why`, a ledger note by an agent, a
//!   goal or rule host that no operator grant backs, and a ledger asset never enter it (the deterministic
//!   authorization of a host is the configured allow list, an operator grant, or a `[lab]` mark).
//! - `Mark::Lab` is given only by `loom scope --lab` or a restricted-network pack. Loopback and link-local addresses are
//!   `Mark::None` unless an operator said otherwise.
//! - `for_mission` reads the ledger's sealed state and the config at call time; the monitor keeps a read-only
//!   `Arc<Authorization>` per mission and replaces it when the ledger changes (M2).
//!
//! Tests required (M2): no agent-authored string is reachable from `Authorization`; a scope request's `why` does not
//! change `authorizes`; grants made in a reopened turn carry an expiry; the mission's goal is verbatim.

use crate::monitor::{not_built, MonitorError};
use loom_core::MissionId;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mark {
    None,
    Lab,
    Prod,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub host: String,
    /// The operator's own words, if any.
    pub note: String,
    pub mark: Mark,
    /// A grant made in a reopened turn lapses with it: the keep-going reopen number, 0 for none.
    pub expires_with_reopen: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authorization {
    pub mission: MissionId,
    pub goal: String,
    pub operator_messages: Vec<String>,
    pub rules: Vec<String>,
    pub grants: Vec<Grant>,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub network_mode: String,
    pub box_targets: Vec<String>,
    pub solvable: bool,
    pub requires_restricted_network: bool,
    pub role: String,
}

impl Authorization {
    /// Build the block for `mission` from its sealed ledger and the configuration (M2).
    pub fn for_mission(_mission: &MissionId) -> Result<Authorization, MonitorError> {
        not_built("authorization snapshot", "M2")
    }

    /// The mark an operator grant gives `host`, if any grant covers it.
    pub fn mark_of(&self, host: &str) -> Option<Mark> {
        self.grants.iter().find(|g| g.host.eq_ignore_ascii_case(host)).map(|g| g.mark)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Authorization {
        Authorization {
            mission: MissionId::from("m-test"),
            goal: "test the lab".into(),
            operator_messages: vec![],
            rules: vec![],
            grants: vec![Grant {
                host: "Lab.Example".into(),
                note: String::new(),
                mark: Mark::Lab,
                expires_with_reopen: 0,
            }],
            allow: vec![],
            deny: vec![],
            network_mode: "allowlist".into(),
            box_targets: vec![],
            solvable: false,
            requires_restricted_network: false,
            role: "web".into(),
        }
    }

    #[test]
    fn a_grant_gives_its_mark_and_nothing_else_does() {
        let a = sample();
        assert_eq!(a.mark_of("lab.example"), Some(Mark::Lab));
        assert_eq!(a.mark_of("127.0.0.1"), None);
    }

    #[test]
    fn building_it_is_not_built_yet() {
        assert!(Authorization::for_mission(&MissionId::from("m-test")).is_err());
    }

    #[test]
    fn it_round_trips() {
        let a = sample();
        let back: Authorization =
            serde_json::from_str(&serde_json::to_string(&a).unwrap_or_default()).unwrap_or_else(|_| sample());
        assert_eq!(back, a);
    }
}
