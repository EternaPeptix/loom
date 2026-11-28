//! The AUTHORIZATION block of every review input: what the operator, the sealed ledger and the configuration say the
//! mission may do (`docs/MONITOR.md` §2.4).
//!
//! CONTRACT.
//!
//! - `Authorization` holds operator-authored strings only: the goal verbatim, the operator's chat messages and the
//!   *answer part* of their inbox answers, the rules in force, the approvals not yet used (`[scope] text`, from the
//!   ledger: `ferret approve`, the web UI, Signal's `/approve`), the operator's grants with the operator's own notes and
//!   their `[lab]` / `[prod]` marks, the configured allow and deny lists and network mode, the box targets, the pack's
//!   `solvable`, `requires_restricted_network` and `live_targets` flags and the role, the `scope` and `exclude` of the mission's named
//!   target as its lead's start recorded them (`SessionMeta::target`, CONTRACTS-TRAFFIC-TARGETS T2), and the hosts the
//!   configured MCP servers of the mission's pack add to its sessions (each server's `hosts` and the host of its `url`,
//!   CONTRACTS-MCP M4), and the hosts the operator revoked from the mission (`<mission dir>/scope_revoked.json`, what
//!   `ferret scope revoke`, Signal's `/scope revoke` and the web UI's Revoke write), and the credential profiles the
//!   operator attached to the mission (`credentials`: `creds` and main's multi-principal `creds_profiles` from the lead's
//!   start, each `{profile} ({summary})`, never a value; they authorize no host). An agent's `why`, a ledger note by
//!   an agent, a goal or rule host that no operator grant backs, and a ledger asset never enter it (the deterministic
//!   authorization of a host is the configured allow list, an operator grant, a `[lab]` mark or the target's scope,
//!   less the target's exclusions and the revoked hosts).
//! - `authorizes(host, port)` is that deterministic authorization: an active grant, an `allow` entry or a target scope
//!   entry (a host pattern, an IP literal or a CIDR block: `ferret_net::policy::scope_entry_covers`) covers it, and no
//!   target `exclude` entry and no revoked entry does (the proxy denies an excluded host, and every policy of the
//!   mission denies a revoked one, `deny revoked {entry}`, whatever else allows it; a revoked entry is matched as
//!   `ferret_net::policy::revoke_entry_covers` matches it, so a carve-out under a wildcard grant, or a revoke of a host
//!   that `allow` or the target's scope reaches, is not authorized either). An MCP server's hosts do **not** authorize a
//!   session's own command (P0-7: they are on the server's isolated proxy grant, not on the session's policy, so the
//!   proxy refuses the session's own connection to them): they count only for the call of an MCP tool
//!   (`for_mcp_call`), whose server reaches them through its own grant, and for the monitor's reading of an allowed net
//!   decision toward them (the server's traffic, attributed to the session that owns it). `is_mcp_host` says whether a
//!   host is one.
//! - `Mark::Lab` is given only by `ferret scope --lab` or a restricted-network pack (one without `live_targets`).
//!   Loopback and link-local addresses are `Mark::None` unless an operator said otherwise.
//! - A **real-target mission** is defined once, here, and every other place in the monitor uses it (§2.5 triage, §2.6
//!   refusal and the `unreviewed_pause_min` rule, §2.8, the opaque-code row of §4.4, §5.2 item 11, D9, D15):
//!   `Authorization::has_real_targets()`. It is false for a pack that `requires_restricted_network` and does not
//!   declare `live_targets` (`restricted_lab`: main's `webapp` works on live bug-bounty targets, D16); otherwise it is
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
//!   constraints that are not retired (rules), the approvals not used (`LedgerState::approvals` without `used_for`), the
//!   operator's grants (`LedgerState::granted_hosts`, each with the note
//!   of its grant, `Mark::None`: `ferret scope --lab` is M4), the operator's chat messages and the answer part of their
//!   inbox answers (`AuthFacts::operator_messages`, from the records authored by the user, cut to `MAX_MESSAGES` of
//!   `MAX_MESSAGE_CHARS`), and the configuration's allow and deny lists, network mode, `solvable`,
//!   `requires_restricted_network`, the role, the target's scope and exclusions, the MCP hosts and the revoked hosts in
//!   force at `upto_ms` (`AuthFacts::revoked`: each entry with the time the monitor first saw it in the mission's
//!   revoked-hosts file, which is the time the file was written then; one that was granted again since is gone).
//!   Nothing an agent wrote reaches it: not a `why`, a claim, a decision, a note, an asset, a plan or a report. The
//!   monitor keeps an `Authorization` per mission and rebuilds it when the ledger or the revoked hosts change.
//!
//! Tests required (M2): no agent-authored string is reachable from `Authorization`; a scope request's `why` does not
//! change `authorizes`; grants made in a reopened turn carry an expiry; the mission's goal is verbatim; the entries
//! after `upto_ms` do not count; a revoked grant is gone. In P0:
//! `a_grant_gives_its_mark_and_nothing_else_does`, `wildcard_and_port_grants_give_their_mark`,
//! `the_strictest_mark_wins_and_lapsed_grants_give_nothing`, `real_targets_are_derived_from_mode_allow_list_and_grants`;
//! after the merge of targets and MCP: `the_target_scope_and_mcp_hosts_authorize_and_exclusions_do_not`; after the merge
//! of main (da5d310): `the_operators_approvals_not_yet_used_are_in_the_block`; after the merge of main (6be589b):
//! `a_revoked_host_is_not_authorized_whatever_covers_it`, `mcp_hosts_authorize_only_an_mcp_tools_call`; after the merge
//! of main (ef34aa4): `the_attached_credential_profiles_and_live_targets_are_in_the_block` and the live-targets case of
//! `real_targets_are_derived_from_mode_allow_list_and_grants`.

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
    /// (since, entry) of the hosts the operator revoked from the mission (`scope_revoked.json`): an entry counts for
    /// what is judged at `since` or later.
    pub revoked: Vec<(u64, String)>,
    /// The pack works on the operator's live systems (`live_targets`, main's `webapp`): its restricted network is not a
    /// lab.
    pub live_targets: bool,
    /// The credential profiles the operator attached to the mission (main's multi-principal `creds_profiles`, the
    /// default one first), as the lead's start recorded them: each one's name and redaction-safe summary.
    pub credentials: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authorization {
    pub mission: MissionId,
    pub goal: String,
    pub operator_messages: Vec<String>,
    pub rules: Vec<String>,
    /// The operator's approvals not yet used (`[scope] text`, verbatim): what `ferret approve`, the web UI and Signal's
    /// `/approve` record in the ledger.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approvals: Vec<String>,
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
    /// The entries the operator revoked from the mission (hosts, `*.suffix`, IP literals, CIDR blocks, optionally with
    /// a port), in force at the time the block is for: refused by every policy of the mission.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked: Vec<String>,
    /// Set by `for_mcp_call` only: the MCP servers' hosts authorize (an MCP tool's call). Never serialized.
    #[serde(skip)]
    pub mcp_call: bool,
    /// The pack works on the operator's live systems: a restricted network is not a lab for it (`restricted_lab`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub live_targets: bool,
    /// The credential profiles the operator attached to the mission (names and redaction-safe summaries; never a
    /// value): acting as each of them (main's `as_profile`, `http_authz_matrix`) is the operator's choice.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credentials: Vec<String>,
}

impl Authorization {
    fn active(&self, g: &Grant) -> bool {
        g.expires_with_reopen == 0 || g.expires_with_reopen == self.active_reopen
    }

    /// True when the mission can reach hosts that are not labs (see the CONTRACT): the one definition of a
    /// real-target mission.
    pub fn has_real_targets(&self) -> bool {
        if self.restricted_lab() {
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

    /// True when the pack's restricted network makes every host of the mission a lab (D16): the pack requires a
    /// restricted network and does not work on live targets.
    pub fn restricted_lab(&self) -> bool {
        self.requires_restricted_network && !self.live_targets
    }

    /// The deterministic authorization of `host` (on `port`, when known): see the CONTRACT.
    pub fn authorizes(&self, host: &str, port: Option<u16>) -> bool {
        if self.excluded(host, port) || self.revoked(host, port) {
            return false;
        }
        self.mark_of(host, port).is_some()
            || self.allow.iter().any(|p| ferret_net::policy::pattern_covers(p, host, port))
            || self.target_scope.iter().any(|e| ferret_net::policy::scope_entry_covers(e, host, port))
            || (self.mcp_call && self.is_mcp_host(host, port))
    }

    /// The block as an MCP tool's call reads it: the MCP servers' hosts authorize too (the server reaches them through
    /// its own isolated grant).
    pub fn for_mcp_call(&self) -> Authorization {
        Authorization { mcp_call: true, ..self.clone() }
    }

    /// True when an entry the operator revoked from the mission refuses `host` (on every port when `port` is `None`).
    pub fn revoked(&self, host: &str, port: Option<u16>) -> bool {
        self.revoked.iter().any(|e| ferret_net::policy::revoke_entry_covers(e, host, port))
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
            approvals: state
                .approvals
                .iter()
                .filter(|a| a.used_for.is_none())
                .map(|a| format!("[{}] {}", a.scope.trim(), a.text.trim()))
                .collect(),
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
            revoked: facts.revoked.iter().filter(|(t, _)| *t <= upto_ms).map(|(_, h)| h.clone()).collect(),
            mcp_call: false,
            live_targets: facts.live_targets,
            credentials: facts.credentials.clone(),
        }
    }

    /// The mark the active operator grants give `host` (on `port`, when known), if any grant covers it. A revoked host
    /// has none: no grant reaches it.
    pub fn mark_of(&self, host: &str, port: Option<u16>) -> Option<Mark> {
        if self.revoked(host, port) {
            return None;
        }
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
            approvals: vec![],
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
            revoked: vec![],
            mcp_call: false,
            live_targets: false,
            credentials: vec![],
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
        // Main's webapp pack works on live bug-bounty targets behind its restricted network: not a lab.
        a.live_targets = true;
        a.network_mode = "allowlist".into();
        assert!(!a.restricted_lab());
        assert!(a.has_real_targets(), "an unmarked grant of a live-targets pack is a real target");
        a.grants = vec![grant("juice.lab.example", Mark::Lab, 0)];
        assert!(!a.has_real_targets(), "its [lab] grants are still labs");
        a.target_scope = vec!["*.program.example".into()];
        assert!(a.has_real_targets(), "and a named target is the operator's real system");
    }

    /// Main's multi-principal credential profiles and the webapp pack's live targets reach the block from the facts. A
    /// profile is its name and redaction-safe summary, and it authorizes no host.
    #[test]
    fn the_attached_credential_profiles_and_live_targets_are_in_the_block() {
        let facts = AuthFacts {
            network_mode: "allowlist".into(),
            requires_restricted_network: true,
            live_targets: true,
            credentials: vec![
                "user_a (user_a · 1 cookie · api.acme.example)".into(),
                "admin (admin · 1 header)".into(),
            ],
            ..AuthFacts::default()
        };
        let a = Authorization::build(&MissionId::from("m-1"), &[], 10, &facts);
        assert_eq!(a.credentials, facts.credentials);
        assert!(a.live_targets && !a.restricted_lab());
        assert!(!a.authorizes("api.acme.example", None), "a credential profile is no grant");
        let json = serde_json::to_string(&a).unwrap_or_default();
        assert!(json.contains("\"credentials\":[\"user_a (user_a") && json.contains("\"live_targets\":true"), "{json}");
        let without = Authorization::build(&MissionId::from("m-1"), &[], 10, &AuthFacts::default());
        let json = serde_json::to_string(&without).unwrap_or_default();
        assert!(!json.contains("credentials") && !json.contains("live_targets"), "{json}");
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
        assert!(a.for_mcp_call().authorizes("api.github.com", Some(443)), "an MCP server's host, for its tool's call");
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

    /// An approval (`ferret approve`, the web UI, Signal's `/approve`) is the operator's words: it is in the block until
    /// it is used. An agent cannot write one (the ledger refuses `ApprovalGrant` not from the user).
    #[test]
    fn the_operators_approvals_not_yet_used_are_in_the_block() {
        use ferret_core::ledger::LedgerOp;
        let grant = |n, ts, text: &str, scope: &str| Entry {
            from_user: true,
            ..entry(n, ts, "s-1", LedgerOp::ApprovalGrant { text: text.into(), scope: scope.into() })
        };
        let entries = vec![
            grant(1, 10, "You may test staging.acme.example", "network"),
            grant(2, 11, "ok to push the fix branch", "git push"),
            entry(3, 12, "s-1", LedgerOp::ApprovalUse { id: "a2".into(), used_for: "pushed".into() }),
        ];
        let a = Authorization::build(&MissionId::from("m-1"), &entries, u64::MAX, &facts());
        assert_eq!(a.approvals, vec!["[network] You may test staging.acme.example".to_string()]);
        assert!(Authorization::build(&MissionId::from("m-1"), &entries, 5, &facts()).approvals.is_empty());
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

    /// A revoke the ledger does not hold (a carve-out under a wildcard grant, a host `allow` or the target's scope
    /// reaches) is refused by every policy of the mission: it is not authorized either, from the time it was seen.
    #[test]
    fn a_revoked_host_is_not_authorized_whatever_covers_it() {
        use ferret_core::ledger::LedgerOp;
        let entries = vec![entry(1, 10, "s-1", LedgerOp::ScopeGrant { hosts: vec!["*.lab.test".into()], note: None })];
        let facts = AuthFacts {
            network_mode: "allowlist".into(),
            allow: vec!["api.allowed.test".into()],
            target_scope: vec!["*.acme.test".into(), "10.9.0.0/24".into()],
            revoked: vec![
                (100, "web.lab.test".into()),
                (100, "api.allowed.test".into()),
                (100, "pay.acme.test".into()),
                (100, "10.9.0.0/28".into()),
                (100, "svc.lab.test:443".into()),
            ],
            ..AuthFacts::default()
        };
        let m = MissionId::from("m-1");
        let before = Authorization::build(&m, &entries, 50, &facts);
        assert!(before.authorizes("web.lab.test", None), "not revoked yet at 50");
        let a = Authorization::build(&m, &entries, 150, &facts);
        assert_eq!(a.revoked.len(), 5);
        assert!(!a.authorizes("web.lab.test", Some(443)), "a carve-out under a wildcard grant");
        assert_eq!(a.mark_of("web.lab.test", None), None);
        assert!(a.authorizes("www.lab.test", None), "the wildcard's other names stay");
        assert!(!a.authorizes("api.allowed.test", None), "an allow entry revoked");
        assert!(!a.authorizes("pay.acme.test", None), "a host the target's scope reaches, revoked");
        assert!(a.authorizes("www.acme.test", None));
        assert!(!a.authorizes("10.9.0.3", None) && a.authorizes("10.9.0.30", None), "a block, by address");
        assert!(!a.authorizes("svc.lab.test", Some(443)) && a.authorizes("svc.lab.test", Some(80)), "one port only");
        assert!(a.authorizes("svc.lab.test", None), "still authorized on another port");
        let json = serde_json::to_string(&a).unwrap_or_default();
        assert!(json.contains("\"revoked\"") && json.contains("pay.acme.test"), "the reviewer's block says so: {json}");
    }

    /// P0-7: an MCP server's hosts are on its own isolated grant, not on the session's policy. They authorize the call
    /// of an MCP tool, never a session's own command toward them.
    #[test]
    fn mcp_hosts_authorize_only_an_mcp_tools_call() {
        let facts = AuthFacts {
            network_mode: "allowlist".into(),
            allow: vec!["target.example".into()],
            mcp_hosts: vec!["api.github.com".into()],
            ..AuthFacts::default()
        };
        let a = Authorization::build(&MissionId::from("m-1"), &[], u64::MAX, &facts);
        assert!(!a.authorizes("api.github.com", Some(443)), "a session's own command does not reach it");
        assert!(a.is_mcp_host("api.github.com", Some(443)));
        assert!(a.for_mcp_call().authorizes("api.github.com", Some(443)));
        assert!(a.authorizes("target.example", None) && a.for_mcp_call().authorizes("target.example", None));
        let json = serde_json::to_string(&a.for_mcp_call()).unwrap_or_default();
        assert!(!json.contains("mcp_call"), "{json}");
    }

    #[test]
    fn it_round_trips() {
        let a = sample();
        let back: Authorization =
            serde_json::from_str(&serde_json::to_string(&a).unwrap_or_default()).unwrap_or_else(|_| sample());
        assert_eq!(back, a);
    }
}
