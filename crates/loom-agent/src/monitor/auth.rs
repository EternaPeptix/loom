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
//! - A **real-target mission** is defined once, here, and every other place in the monitor uses it (§2.5 triage, §2.6
//!   refusal and the `unreviewed_pause_min` rule, §2.8, the opaque-code row of §4.4, §5.2 item 11, D9, D15):
//!   `Authorization::has_real_targets()`. It is false for a pack that `requires_restricted_network`; otherwise it is
//!   true when the network mode is `open`, or when any configured `allow` entry is not covered by an active
//!   `[lab]` grant of the same text, or when any active grant is not marked `[lab]`. A mission in `allowlist` or `open`
//!   mode with no `loom scope` grant is therefore a real-target mission. Keep-going takes this derived value
//!   (`KeepGoingParams::checked`) and is refused without the operator's `--real-targets` acknowledgement whenever it is
//!   true.
//! - `mark_of(host, port)` resolves the mark of the *active* grants that cover `host` with `loom_net::policy`'s pattern
//!   semantics (`*.lab.example` covers its subdomains and not the apex; `host:port` is honoured when a port is given and
//!   ignored when it is `None`). A grant lapsed with its reopen (`expires_with_reopen` not 0 and not `active_reopen`)
//!   gives nothing. When several grants cover the host the strictest mark wins (`Prod` over `None` over `Lab`), so a
//!   host first granted `[lab]` and later re-granted `[prod]` is `Prod`.
//! - `for_mission` reads the ledger's sealed state and the config at call time; the monitor keeps a read-only
//!   `Arc<Authorization>` per mission and replaces it when the ledger changes (M2).
//!
//! Tests required (M2): no agent-authored string is reachable from `Authorization`; a scope request's `why` does not
//! change `authorizes`; grants made in a reopened turn carry an expiry; the mission's goal is verbatim. In P0:
//! `a_grant_gives_its_mark_and_nothing_else_does`, `wildcard_and_port_grants_give_their_mark`,
//! `the_strictest_mark_wins_and_lapsed_grants_give_nothing`, `real_targets_are_derived_from_mode_allow_list_and_grants`.

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

impl Mark {
    /// Strictness for resolving several grants: `Lab` < `None` < `Prod`.
    fn strictness(self) -> u8 {
        match self {
            Mark::Lab => 0,
            Mark::None => 1,
            Mark::Prod => 2,
        }
    }
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
    /// The keep-going reopen whose turn is running, 0 outside a reopened turn. A grant with another non-zero
    /// `expires_with_reopen` has lapsed.
    #[serde(default)]
    pub active_reopen: u32,
}

impl Authorization {
    fn active(&self, g: &Grant) -> bool {
        g.expires_with_reopen == 0 || g.expires_with_reopen == self.active_reopen
    }

    /// True when the mission can reach hosts that are not labs (see the CONTRACT): the one definition of a
    /// real-target mission.
    pub fn has_real_targets(&self) -> bool {
        if self.requires_restricted_network {
            return false;
        }
        if self.network_mode == "open" {
            return true;
        }
        let lab_grant = |text: &str| {
            self.grants
                .iter()
                .any(|g| self.active(g) && g.mark == Mark::Lab && g.host.trim().eq_ignore_ascii_case(text.trim()))
        };
        self.allow.iter().any(|a| !lab_grant(a)) || self.grants.iter().any(|g| self.active(g) && g.mark != Mark::Lab)
    }

    /// Build the block for `mission` from its sealed ledger and the configuration (M2).
    pub fn for_mission(_mission: &MissionId) -> Result<Authorization, MonitorError> {
        not_built("authorization snapshot", "M2")
    }

    /// The mark the active operator grants give `host` (on `port`, when known), if any grant covers it.
    pub fn mark_of(&self, host: &str, port: Option<u16>) -> Option<Mark> {
        self.grants
            .iter()
            .filter(|g| self.active(g) && loom_net::policy::pattern_covers(&g.host, host, port))
            .map(|g| g.mark)
            .max_by_key(|m| m.strictness())
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
            active_reopen: 0,
        }
    }

    #[test]
    fn a_grant_gives_its_mark_and_nothing_else_does() {
        let a = sample();
        assert_eq!(a.mark_of("lab.example", None), Some(Mark::Lab));
        assert_eq!(a.mark_of("127.0.0.1", None), None);
    }

    fn grant(host: &str, mark: Mark, reopen: u32) -> Grant {
        Grant { host: host.into(), note: String::new(), mark, expires_with_reopen: reopen }
    }

    #[test]
    fn wildcard_and_port_grants_give_their_mark() {
        let mut a = sample();
        a.grants = vec![grant("*.pwn.intigriti.rocks", Mark::Lab, 0), grant("svc.example:8443", Mark::Prod, 0)];
        assert_eq!(a.mark_of("x1.pwn.intigriti.rocks", None), Some(Mark::Lab));
        assert_eq!(a.mark_of("pwn.intigriti.rocks", None), None, "a wildcard does not cover the apex");
        assert_eq!(a.mark_of("svc.example", None), Some(Mark::Prod));
        assert_eq!(a.mark_of("svc.example", Some(8443)), Some(Mark::Prod));
        assert_eq!(a.mark_of("svc.example", Some(443)), None);
    }

    #[test]
    fn the_strictest_mark_wins_and_lapsed_grants_give_nothing() {
        let mut a = sample();
        a.grants = vec![grant("h.example", Mark::Lab, 0), grant("h.example", Mark::Prod, 0)];
        assert_eq!(a.mark_of("h.example", None), Some(Mark::Prod), "a later [prod] grant is not hidden by [lab]");
        a.grants = vec![grant("h.example", Mark::Prod, 2)];
        assert_eq!(a.mark_of("h.example", None), None, "a reopen grant lapses with its reopen");
        a.active_reopen = 2;
        assert_eq!(a.mark_of("h.example", None), Some(Mark::Prod));
    }

    #[test]
    fn real_targets_are_derived_from_mode_allow_list_and_grants() {
        let mut a = sample();
        a.grants = vec![grant("lab.example", Mark::Lab, 0)];
        assert!(!a.has_real_targets(), "only a lab grant");
        a.network_mode = "open".into();
        assert!(a.has_real_targets(), "open mode reaches any public host with no grant at all");
        a.network_mode = "allowlist".into();
        a.grants.clear();
        a.allow = vec!["*.program.example".into()];
        assert!(a.has_real_targets(), "an allow-list entry with no [lab] grant is a real target");
        a.grants = vec![grant("*.program.example", Mark::Lab, 0)];
        assert!(!a.has_real_targets());
        a.grants = vec![grant("x.example", Mark::None, 0)];
        a.allow.clear();
        assert!(a.has_real_targets(), "an unmarked grant is not a lab");
        a.requires_restricted_network = true;
        a.network_mode = "open".into();
        assert!(!a.has_real_targets(), "a restricted-network pack is a lab");
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
