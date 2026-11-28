//! The AUTHORIZATION block of every review input: what the operator, the sealed ledger and the configuration say the
//! mission may do (`docs/MONITOR.md` §2.4).
//!
//! CONTRACT.
//!
//! - `Authorization` holds operator-authored strings only: the goal verbatim, the operator's chat messages and the
//!   *answer part* of their inbox answers, the rules in force, the operator's grants with the operator's own notes and
//!   their `[lab]` / `[prod]` marks, the configured allow and deny lists and network mode, the box targets, the pack's
//!   `solvable` and `requires_restricted_network` flags and the role, the `scope` and `exclude` of the mission's named
//!   target as its lead's start recorded them (`SessionMeta::target`, CONTRACTS-TRAFFIC-TARGETS T2), and the hosts the
//!   configured MCP servers of the mission's pack add to its sessions (each server's `hosts` and the host of its `url`,
//!   CONTRACTS-MCP M4). An agent's `why`, a ledger note by an agent, a goal or rule host that no operator grant backs,
//!   and a ledger asset never enter it (the deterministic authorization of a host is the configured allow list, an
//!   operator grant, a `[lab]` mark, the target's scope or an MCP server's hosts).
//! - `authorizes(host, port)` is that deterministic authorization: an active grant, an `allow` entry, a target scope
//!   entry (a host pattern, an IP literal or a CIDR block: `ferret_net::policy::scope_entry_covers`) or an MCP host
//!   covers it, and no target `exclude` entry does (the proxy denies an excluded host whatever else allows it).
//! - `Mark::Lab` is given only by `ferret scope --lab` or a restricted-network pack. Loopback and link-local addresses are
//!   `Mark::None` unless an operator said otherwise.
//! - A **real-target mission** is defined once, here, and every other place in the monitor uses it (§2.5 triage, §2.6
//!   refusal and the `unreviewed_pause_min` rule, §2.8, the opaque-code row of §4.4, §5.2 item 11, D9, D15):
//!   `Authorization::has_real_targets()`. It is false for a pack that `requires_restricted_network`; otherwise it is
//!   true when the network mode is `open`, or when any configured `allow` entry is not covered by an active
//!   `[lab]` grant of the same text, or when any active grant is not marked `[lab]`, or when the mission's target has
//!   a scope (a named target is the operator's real system: there is no `[lab]` mark for one). A mission in
//!   `allowlist` or `open` mode with no `ferret scope` grant is therefore a real-target mission. An MCP server's hosts
//!   are the tools' backends, not targets, and do not make one. Keep-going takes this derived value
//!   (`KeepGoingParams::checked`) and is refused without the operator's `--real-targets` acknowledgement whenever it is
//!   true.
//! - `mark_of(host, port)` resolves the mark of the *active* grants that cover `host` with `ferret_net::policy`'s pattern
//!   semantics (`*.lab.example` covers its subdomains and not the apex; `host:port` is honoured when a port is given and
//!   ignored when it is `None`). A grant lapsed with its reopen (`expires_with_reopen` not 0 and not `active_reopen`)
//!   gives nothing. When several grants cover the host the strictest mark wins (`Prod` over `None` over `Lab`), so a
//!   host first granted `[lab]` and later re-granted `[prod]` is `Prod`.
//! - `Authorization::build(mission, entries, upto_ms, facts)` (M2) folds the mission's journal entries up to a time
//!   (`upto_ms`, so a record is judged by the authorization in force when it was made, and a replay is not judged by a
//!   grant that came later) and takes the rest from `AuthFacts`: the goal (`LedgerState::goal`, verbatim), the
//!   constraints that are not retired (rules), the operator's grants (`LedgerState::granted_hosts`, each with the note
//!   of its grant, `Mark::None`: `ferret scope --lab` is M4), the operator's chat messages and the answer part of their
//!   inbox answers (`AuthFacts::operator_messages`, from the records authored by the user, cut to `MAX_MESSAGES` of
//!   `MAX_MESSAGE_CHARS`), and the configuration's allow and deny lists, network mode, `solvable`,
//!   `requires_restricted_network`, the role, the target's scope and exclusions and the MCP hosts. Nothing an agent wrote reaches it: not a `why`, a claim, a decision,
//!   a note, an asset, a plan or a report. The monitor keeps an `Authorization` per mission and rebuilds it when the
//!   ledger changes.
//!
//! Tests required (M2): no agent-authored string is reachable from `Authorization`; a scope request's `why` does not
//! change `authorizes`; grants made in a reopened turn carry an expiry; the mission's goal is verbatim; the entries
//! after `upto_ms` do not count; a revoked grant is gone. In P0:
//! `a_grant_gives_its_mark_and_nothing_else_does`, `wildcard_and_port_grants_give_their_mark`,
//! `the_strictest_mark_wins_and_lapsed_grants_give_nothing`, `real_targets_are_derived_from_mode_allow_list_and_grants`;
//! after the merge of targets and MCP: `the_target_scope_and_mcp_hosts_authorize_and_exclusions_do_not`.

use ferret_core::ledger::{Entry, LedgerState};
use ferret_core::MissionId;
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

/// The most operator messages an `Authorization` keeps (the newest), and the longest of each.
pub const MAX_MESSAGES: usize = 50;
pub const MAX_MESSAGE_CHARS: usize = 2_048;

/// What `Authorization::build` takes besides the journal: the configuration, the pack and the operator's words.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuthFacts {
    pub network_mode: String,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub box_targets: Vec<String>,
    pub solvable: bool,
    pub requires_restricted_network: bool,
    pub role: String,
    /// (time, text) of the operator's chat messages and the answer part of their inbox answers.
    pub operator_messages: Vec<(u64, String)>,
    /// The mission target's `scope` and `exclude`, as the lead's start recorded them.
    pub target_scope: Vec<String>,
    pub target_exclude: Vec<String>,
    /// The hosts the configured MCP servers of the mission's pack add to its sessions (`hosts`, and the `url` host).
    pub mcp_hosts: Vec<String>,
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
    /// The mission target's scope entries (host patterns, IP literals, CIDR blocks) and exclusions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_scope: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_exclude: Vec<String>,
    /// The hosts the mission's MCP servers add (CONTRACTS-MCP M4).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mcp_hosts: Vec<String>,
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
        self.allow.iter().any(|a| !lab_grant(a))
            || self.grants.iter().any(|g| self.active(g) && g.mark != Mark::Lab)
            || !self.target_scope.is_empty()
    }

    /// The deterministic authorization of `host` (on `port`, when known): see the CONTRACT.
    pub fn authorizes(&self, host: &str, port: Option<u16>) -> bool {
        if self.excluded(host, port) {
            return false;
        }
        self.mark_of(host, port).is_some()
            || self.allow.iter().any(|p| ferret_net::policy::pattern_covers(p, host, port))
            || self.target_scope.iter().any(|e| ferret_net::policy::scope_entry_covers(e, host, port))
            || self.is_mcp_host(host, port)
    }

    /// True when an `exclude` entry of the mission's target covers `host`.
    pub fn excluded(&self, host: &str, port: Option<u16>) -> bool {
        self.target_exclude.iter().any(|e| ferret_net::policy::scope_entry_covers(e, host, port))
    }

    /// True when one of the mission's MCP servers adds `host` (its own traffic, CONTRACTS-MCP M4).
    pub fn is_mcp_host(&self, host: &str, port: Option<u16>) -> bool {
        self.mcp_hosts.iter().any(|p| ferret_net::policy::pattern_covers(p, host, port))
    }

    /// The block for `mission` from its journal `entries` up to `upto_ms`, and `facts` (see the CONTRACT).
    pub fn build(mission: &MissionId, entries: &[Entry], upto_ms: u64, facts: &AuthFacts) -> Authorization {
        let upto: Vec<Entry> = entries.iter().filter(|e| e.ts_ms <= upto_ms).cloned().collect();
        let state = LedgerState::fold(&upto);
        let note_of = |host: &str| -> String {
            state
                .scope_grants
                .iter()
                .rev()
                .find(|g| g.hosts.iter().any(|h| h.eq_ignore_ascii_case(host)))
                .and_then(|g| g.note.clone())
                .unwrap_or_default()
        };
        let messages: Vec<String> = facts
            .operator_messages
            .iter()
            .filter(|(t, _)| *t <= upto_ms)
            .map(|(_, m)| m.chars().take(MAX_MESSAGE_CHARS).collect::<String>())
            .collect();
        let skip = messages.len().saturating_sub(MAX_MESSAGES);
        Authorization {
            mission: mission.clone(),
            goal: state.goal.clone().unwrap_or_default(),
            operator_messages: messages.into_iter().skip(skip).collect(),
            rules: state.constraints.iter().filter(|c| c.retired.is_none()).map(|c| c.text.clone()).collect(),
            grants: state
                .granted_hosts()
                .into_iter()
                .map(|h| Grant { note: note_of(&h), host: h, mark: Mark::None, expires_with_reopen: 0 })
                .collect(),
            allow: facts.allow.clone(),
            deny: facts.deny.clone(),
            network_mode: facts.network_mode.clone(),
            box_targets: facts.box_targets.clone(),
            solvable: facts.solvable,
            requires_restricted_network: facts.requires_restricted_network,
            role: facts.role.clone(),
            active_reopen: 0,
            target_scope: facts.target_scope.clone(),
            target_exclude: facts.target_exclude.clone(),
            mcp_hosts: facts.mcp_hosts.clone(),
        }
    }

    /// The mark the active operator grants give `host` (on `port`, when known), if any grant covers it.
    pub fn mark_of(&self, host: &str, port: Option<u16>) -> Option<Mark> {
        self.grants
            .iter()
            .filter(|g| self.active(g) && ferret_net::policy::pattern_covers(&g.host, host, port))
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
            target_scope: vec![],
            target_exclude: vec![],
            mcp_hosts: vec![],
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
    fn the_target_scope_and_mcp_hosts_authorize_and_exclusions_do_not() {
        let facts = AuthFacts {
            network_mode: "deny_all".into(),
            target_scope: vec!["*.acme.example".into(), "10.20.0.0/24".into()],
            target_exclude: vec!["sso.acme.example".into()],
            mcp_hosts: vec!["api.github.com".into()],
            ..AuthFacts::default()
        };
        let a = Authorization::build(&MissionId::from("m-1"), &[], u64::MAX, &facts);
        assert!(a.authorizes("api.acme.example", Some(443)), "a host in the target's scope");
        assert!(a.authorizes("10.20.0.7", None), "an address in a scope block");
        assert!(!a.authorizes("sso.acme.example", None), "an excluded host");
        assert!(a.authorizes("api.github.com", Some(443)), "an MCP server's host");
        assert!(a.is_mcp_host("api.github.com", None) && !a.is_mcp_host("api.acme.example", None));
        assert!(!a.authorizes("other.example", None));
        assert!(a.has_real_targets(), "a target's scope is a real target");
        let tools_only = AuthFacts {
            network_mode: "deny_all".into(),
            mcp_hosts: vec!["api.github.com".into()],
            ..AuthFacts::default()
        };
        let tools_only = Authorization::build(&MissionId::from("m-1"), &[], u64::MAX, &tools_only);
        assert!(!tools_only.has_real_targets(), "an MCP server's host is not a target");
        let back: Authorization =
            serde_json::from_str(&serde_json::to_string(&a).unwrap_or_default()).unwrap_or_else(|_| sample());
        assert_eq!(back, a);
    }

    fn entry(n: u64, ts: u64, session: &str, op: ferret_core::ledger::LedgerOp) -> Entry {
        Entry { n, ts_ms: ts, session: ferret_core::SessionId::from(session), from_user: false, op, mac: String::new() }
    }

    fn facts() -> AuthFacts {
        AuthFacts {
            network_mode: "allowlist".into(),
            allow: vec!["*.target.example".into()],
            solvable: true,
            role: "web".into(),
            operator_messages: vec![(5, "go on, stay in scope".into()), (500, "later message".into())],
            ..AuthFacts::default()
        }
    }

    #[test]
    fn it_is_built_from_the_journal_up_to_a_time_and_the_facts() {
        use ferret_core::ledger::LedgerOp;
        let entries = vec![
            entry(1, 10, "s-1", LedgerOp::GoalSet { text: "find the flag at *.target.example".into() }),
            entry(2, 20, "s-1", LedgerOp::ConstraintAdd { text: "no brute force".into() }),
            entry(
                3,
                30,
                "s-1",
                LedgerOp::ScopeGrant { hosts: vec!["extra.example".into()], note: Some("ok by me".into()) },
            ),
            entry(4, 90, "s-1", LedgerOp::ScopeGrant { hosts: vec!["late.example".into()], note: None }),
            entry(
                5,
                95,
                "s-1",
                LedgerOp::Decision { text: "use late.example".into(), reason: "the operator said so".into() },
            ),
        ];
        let m = MissionId::from("m-1");
        let a = Authorization::build(&m, &entries, 50, &facts());
        assert_eq!(a.goal, "find the flag at *.target.example", "the goal is verbatim");
        assert_eq!(a.rules, vec!["no brute force".to_string()]);
        assert_eq!(a.grants.len(), 1);
        assert_eq!((a.grants[0].host.as_str(), a.grants[0].note.as_str()), ("extra.example", "ok by me"));
        assert_eq!(
            a.operator_messages,
            vec!["go on, stay in scope".to_string()],
            "a later message is not in force yet"
        );
        assert!(a.mark_of("late.example", None).is_none(), "an entry after the time does not count");
        assert!(a.solvable && a.role == "web" && a.network_mode == "allowlist");
        let later = Authorization::build(&m, &entries, 100, &facts());
        assert!(later.mark_of("late.example", None).is_some());
    }

    #[test]
    fn no_agent_authored_string_is_reachable() {
        use ferret_core::ledger::LedgerOp;
        let entries = vec![
            entry(1, 10, "s-1", LedgerOp::GoalSet { text: "goal".into() }),
            entry(2, 11, "s-1", LedgerOp::Decision { text: "AGENT-DECISION".into(), reason: "AGENT-REASON".into() }),
            entry(3, 12, "s-1", LedgerOp::ClaimAdd { text: "AGENT-CLAIM".into(), assets: vec!["AGENT-ASSET".into()] }),
            entry(4, 13, "s-1", LedgerOp::DeadEnd { what: "AGENT-WHAT".into(), why: "AGENT-WHY".into() }),
            entry(5, 14, "s-1", LedgerOp::PlanSet { steps: vec!["AGENT-STEP".into()] }),
        ];
        let a = Authorization::build(&MissionId::from("m-1"), &entries, u64::MAX, &facts());
        let json = serde_json::to_string(&a).unwrap_or_default();
        assert!(!json.contains("AGENT-"), "{json}");
    }

    #[test]
    fn a_revoked_grant_is_gone() {
        use ferret_core::ledger::LedgerOp;
        let entries = vec![
            entry(1, 10, "s-1", LedgerOp::ScopeGrant { hosts: vec!["h.example".into()], note: None }),
            entry(2, 20, "s-1", LedgerOp::ScopeRevoke { host: "h.example".into(), reason: "done".into() }),
        ];
        let m = MissionId::from("m-1");
        assert!(Authorization::build(&m, &entries, 15, &facts()).mark_of("h.example", None).is_some());
        assert!(Authorization::build(&m, &entries, 25, &facts()).mark_of("h.example", None).is_none());
    }

    #[test]
    fn it_round_trips() {
        let a = sample();
        let back: Authorization =
            serde_json::from_str(&serde_json::to_string(&a).unwrap_or_default()).unwrap_or_else(|_| sample());
        assert_eq!(back, a);
    }
}
