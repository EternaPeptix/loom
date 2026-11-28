//! MCP servers in a session (`docs/CONTRACTS-MCP.md` M4 and M6; the protocol is `ferret_tools::mcp`).
//!
//! - [`serves`] says whether a role gets a server; [`pack_servers`] which servers a mission's lead
//!   lists at its start; [`hosts_for_role`] which hosts a role's sessions add to their network policy.
//! - [`McpSession`] is what one session owns: one [`McpHandle`] per server it gets, the tools it
//!   presents (after the `tools` filter, name collisions and the size budget), the full listing it was
//!   made from (a child writes it into its own `session_start`), and the start note.
//! - [`list_servers`] connects to each server a mission's lead may use and records what it offers.
//! - Everything that decides is a pure function over hand-built [`McpListing`]s: [`serves`],
//!   [`fit_budget`], [`start_note`].

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use ferret_core::config::{McpCfg, McpServerCfg};
use ferret_core::event::{McpListing, McpToolDef, ToolClass, ToolSpec};
use ferret_tools::mcp::{McpHandle, McpServer, McpStatus, McpTool};
use ferret_tools::ToolCtx;
use serde::{Deserialize, Serialize};

/// Whether a role named `role` (`read_only`: it may change nothing) gets the tools of `server`.
/// Default roles: every role that is not read-only. A read-only role gets a server only when the
/// operator says `read_only = true` for it, whether or not the role is named.
pub fn serves(server: &McpServerCfg, role: &str, read_only: bool) -> bool {
    if read_only && !server.read_only {
        return false;
    }
    match &server.roles {
        Some(roles) => roles.iter().any(|r| r == role),
        None => true,
    }
}

/// The servers (names, in config order) a role gets.
pub fn role_servers<'a>(cfg: &'a McpCfg, role: &str, read_only: bool) -> Vec<&'a str> {
    cfg.servers.iter().filter(|(_, s)| serves(s, role, read_only)).map(|(n, _)| n.as_str()).collect()
}

/// The servers a mission's lead connects to at its start: those some role of the pack gets.
pub fn pack_servers<'a>(cfg: &'a McpCfg, roles: &[(&str, bool)]) -> Vec<&'a str> {
    cfg.servers.iter().filter(|(_, s)| roles.iter().any(|(r, ro)| serves(s, r, *ro))).map(|(n, _)| n.as_str()).collect()
}

/// The hosts the servers of a role add to its sessions' allowed hosts (M4), without repeats.
pub fn hosts_for_role(cfg: &McpCfg, role: &str, read_only: bool) -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();
    for name in role_servers(cfg, role, read_only) {
        for h in &cfg.servers[name].hosts {
            let h = h.trim();
            if !h.is_empty() && !hosts.iter().any(|x| x.eq_ignore_ascii_case(h)) {
                hosts.push(h.to_string());
            }
        }
    }
    hosts
}

/// Characters of a description the model sees (M5).
const DESCRIPTION_CHARS: usize = 2_000;

/// The definition as it is estimated for the size budget: the same JSON the request carries.
fn estimate_spec(name: &str, def: &McpToolDef) -> ToolSpec {
    let mut parameters = def.input_schema.clone();
    if let Some(o) = parameters.as_object_mut() {
        o.remove("$schema");
    }
    if !parameters.is_object() {
        parameters = serde_json::json!({"type": "object", "properties": {}});
    }
    ToolSpec {
        name: name.to_string(),
        description: def.description.chars().take(DESCRIPTION_CHARS).collect(),
        parameters,
        class: if def.read_only_hint == Some(true) { ToolClass::Read } else { ToolClass::Exec },
    }
}

/// Estimated tokens of one tool's definition.
pub fn def_tokens(name: &str, def: &McpToolDef) -> u64 {
    let chars = estimate_spec(name, def).to_openai().to_string().chars().count();
    ferret_core::estimate::TokenEstimator::default().tokens(chars)
}

/// The tools that fit in `remaining` tokens, in order: the first one that does not fit and every one
/// after it are left out (a later, smaller tool never jumps ahead of an earlier one). Returns what is
/// kept, how many were left out and the tokens used.
pub fn fit_budget(presented: Vec<(String, McpToolDef)>, remaining: u64) -> (Vec<(String, McpToolDef)>, usize, u64) {
    let mut used = 0u64;
    let mut kept = Vec::new();
    let mut left = 0usize;
    for (name, def) in presented {
        if left > 0 {
            left += 1;
            continue;
        }
        let t = def_tokens(&name, &def);
        if used.saturating_add(t) > remaining {
            left += 1;
            continue;
        }
        used += t;
        kept.push((name, def));
    }
    (kept, left, used)
}

/// What one server gave one session.
#[derive(Clone, Debug, PartialEq)]
pub struct ServerPick {
    pub server: String,
    pub transport: String,
    /// The tools the session presents, with their `mcp__…` names.
    pub presented: Vec<(String, McpToolDef)>,
    /// Tools the server listed that the `tools` filter does not name.
    pub by_filter: usize,
    /// Server tool names left out because their presented name was already taken.
    pub collisions: Vec<String>,
    /// Tools left out by the size budget.
    pub over_budget: usize,
    pub hosts: Vec<String>,
    pub error: Option<String>,
}

/// The harness note a session with MCP tools gets at its start (M6): per server, how many tools it
/// got, the hosts it added, what was left out and any start error.
pub fn start_note(picks: &[ServerPick], budget: u64) -> Option<String> {
    if picks.is_empty() {
        return None;
    }
    let mut out = String::from("MCP servers for this session. Their tools are named mcp__{server}__{tool}.");
    for p in picks {
        out.push_str(&format!("\n- {} ({}): ", p.server, p.transport));
        let mut parts: Vec<String> = Vec::new();
        match &p.error {
            Some(e) => parts.push(format!("could not be used, no tools: {e}")),
            None => {
                parts.push(format!("{} {}", p.presented.len(), if p.presented.len() == 1 { "tool" } else { "tools" }))
            }
        }
        if !p.hosts.is_empty() {
            parts.push(format!("added to the allowed hosts: {}", p.hosts.join(", ")));
        }
        let mut left: Vec<String> = Vec::new();
        if p.by_filter > 0 {
            left.push(format!("{} not in its `tools` list", p.by_filter));
        }
        if p.over_budget > 0 {
            left.push(format!("{} over the size budget of {budget} tokens for tool definitions", p.over_budget));
        }
        if !p.collisions.is_empty() {
            left.push(format!("{} with a name already taken ({})", p.collisions.len(), p.collisions.join(", ")));
        }
        if !left.is_empty() {
            parts.push(format!("left out: {}", left.join("; ")));
        }
        out.push_str(&parts.join("; "));
        out.push('.');
    }
    Some(out)
}

/// What one session owns of its MCP servers.
pub struct McpSession {
    /// The listing of the mission (every server its lead connected to), as recorded.
    listings: Vec<McpListing>,
    picks: Vec<ServerPick>,
    handles: Vec<(String, Arc<McpHandle>)>,
    note: Option<String>,
}

impl McpSession {
    /// A session without MCP tools.
    pub fn none() -> McpSession {
        McpSession { listings: Vec::new(), picks: Vec::new(), handles: Vec::new(), note: None }
    }

    /// What `role` gets of `listings`. `handles` are connections already made (the lead's listing
    /// ones); the others are made here and connect when first called. A server whose listing is not in
    /// `listings` (configured after the mission began) gives nothing, as does one whose settings cannot
    /// be resolved (the reason is in the note).
    pub fn plan(
        cfg: &McpCfg,
        role: &str,
        read_only: bool,
        listings: Vec<McpListing>,
        mut handles: BTreeMap<String, Arc<McpHandle>>,
    ) -> McpSession {
        let mut picks = Vec::new();
        let mut owned = Vec::new();
        let mut remaining = cfg.max_schema_tokens;
        for name in role_servers(cfg, role, read_only) {
            let scfg = &cfg.servers[name];
            let Some(listing) = listings.iter().find(|l| l.server == name) else { continue };
            let mut pick = ServerPick {
                server: name.to_string(),
                transport: listing.transport.clone(),
                presented: Vec::new(),
                by_filter: 0,
                collisions: Vec::new(),
                over_budget: 0,
                hosts: hosts_for_role_of(scfg),
                error: listing.error.clone(),
            };
            let handle = match handles.remove(name) {
                Some(h) => Ok(h),
                None => {
                    McpServer::resolve(name, scfg).map(|s| McpHandle::new(s, Duration::from_secs(cfg.idle_close_s)))
                }
            };
            let handle = match handle {
                Ok(h) => h,
                Err(e) => {
                    pick.error.get_or_insert(e);
                    picks.push(pick);
                    continue;
                }
            };
            if pick.error.is_none() {
                let (presented, collisions) = ferret_tools::mcp::presented_tools(listing, scfg.tools.as_deref());
                pick.by_filter = match &scfg.tools {
                    Some(f) => listing.tools.iter().filter(|t| !f.iter().any(|n| n == &t.name)).count(),
                    None => 0,
                };
                pick.collisions = collisions;
                let (kept, left, used) = fit_budget(presented, remaining);
                remaining = remaining.saturating_sub(used);
                pick.over_budget = left;
                pick.presented = kept;
            }
            owned.push((name.to_string(), handle));
            picks.push(pick);
        }
        // Connections made for the listing that this role does not use are not kept open.
        for (_, h) in handles {
            tokio::spawn(async move { h.close().await });
        }
        let note = start_note(&picks, cfg.max_schema_tokens);
        McpSession { listings, picks, handles: owned, note }
    }

    pub fn listings(&self) -> &[McpListing] {
        &self.listings
    }

    pub fn picks(&self) -> &[ServerPick] {
        &self.picks
    }

    /// The tools to put in the session's registry, in server and listing order.
    pub fn tools(&self) -> Vec<McpTool> {
        let mut out = Vec::new();
        for p in &self.picks {
            let Some((_, handle)) = self.handles.iter().find(|(n, _)| n == &p.server) else { continue };
            for (name, def) in &p.presented {
                out.push(McpTool { handle: handle.clone(), name: name.clone(), def: def.clone() });
            }
        }
        out
    }

    pub fn note(&self) -> Option<&str> {
        self.note.as_deref()
    }

    /// `(server, status)` of each connection the session owns.
    pub fn statuses(&self) -> Vec<(String, McpStatus)> {
        self.handles.iter().map(|(n, h)| (n.clone(), h.status())).collect()
    }

    /// Close every connection (the session ended or was archived).
    pub async fn close(&self) {
        for (_, h) in &self.handles {
            h.close().await;
        }
    }
}

fn hosts_for_role_of(s: &McpServerCfg) -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();
    for h in &s.hosts {
        let h = h.trim();
        if !h.is_empty() && !hosts.iter().any(|x| x.eq_ignore_ascii_case(h)) {
            hosts.push(h.to_string());
        }
    }
    hosts
}

/// Connect to each of `names` (in `ctx`'s sandbox), list its tools and keep the connection. A server
/// that cannot be resolved, started or listed is recorded with its `error` and no tools. The servers
/// are started together.
pub async fn list_servers(
    cfg: &McpCfg,
    names: &[&str],
    ctx: &ToolCtx,
) -> (Vec<McpListing>, BTreeMap<String, Arc<McpHandle>>) {
    let jobs = names.iter().map(|name| async move {
        let scfg = &cfg.servers[*name];
        let transport = if scfg.url.is_some() { "http" } else { "stdio" };
        let failed = |error: String| McpListing {
            server: (*name).to_string(),
            transport: transport.to_string(),
            protocol: String::new(),
            server_name: String::new(),
            server_version: String::new(),
            tools: Vec::new(),
            error: Some(error),
        };
        let server = match McpServer::resolve(name, scfg) {
            Ok(s) => s,
            Err(e) => return (failed(e), None),
        };
        let handle = McpHandle::new(server, Duration::from_secs(cfg.idle_close_s));
        let wait = Duration::from_secs(scfg.timeout_s.max(1));
        match tokio::time::timeout(wait, handle.list(ctx)).await {
            Ok(Ok(listing)) => (listing, Some(handle)),
            Ok(Err(e)) => (failed(e), Some(handle)),
            Err(_) => (failed(format!("the server did not list its tools within {}s", wait.as_secs())), Some(handle)),
        }
    });
    let done = futures_util::future::join_all(jobs).await;
    let mut listings = Vec::new();
    let mut handles = BTreeMap::new();
    for (listing, handle) in done {
        if let Some(h) = handle {
            handles.insert(listing.server.clone(), h);
        }
        listings.push(listing);
    }
    (listings, handles)
}

/// One server of a session as `GET /api/sessions/{id}/mcp` shows it (M7).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct McpServerView {
    pub server: String,
    pub transport: String,
    /// `not started`, `running`, `closed` or `failed`.
    pub state: String,
    pub tools: Vec<String>,
    pub error: Option<String>,
    pub stderr_tail: Vec<String>,
    pub list_changed: bool,
    pub calls: u64,
    pub last_call_ms: Option<u64>,
}

/// The view of `session`'s servers: the tools it presents with each connection's state. A server that
/// failed to list at the mission's start is `failed` with its recorded error.
pub fn views(session: &McpSession) -> Vec<McpServerView> {
    let statuses: BTreeMap<String, McpStatus> = session.statuses().into_iter().collect();
    session
        .picks()
        .iter()
        .map(|p| {
            let st = statuses.get(&p.server).cloned().unwrap_or_default();
            let (state, error) = match &p.error {
                Some(e) => ("failed".to_string(), Some(e.clone())),
                None => (if st.state.is_empty() { "not started".to_string() } else { st.state }, st.error),
            };
            McpServerView {
                server: p.server.clone(),
                transport: p.transport.clone(),
                state,
                tools: p.presented.iter().map(|(n, _)| n.clone()).collect(),
                error,
                stderr_tail: st.stderr_tail,
                list_changed: st.list_changed,
                calls: st.calls,
                last_call_ms: st.last_call_ms,
            }
        })
        .collect()
}

/// What `POST /api/mcp/{server}/check` answers: the server's listing from a scratch start, or the
/// reason it could not give one (`error`), with the last lines it wrote to stderr.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct McpCheckView {
    pub server: String,
    pub transport: String,
    pub protocol: String,
    pub server_name: String,
    pub server_version: String,
    pub tools: Vec<McpCheckTool>,
    pub error: Option<String>,
    pub stderr_tail: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct McpCheckTool {
    pub name: String,
    pub description: String,
    pub read_only_hint: Option<bool>,
}

/// One configured server as `ferret mcp list` shows it. Names only: no env or header value.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct McpConfigured {
    pub server: String,
    pub transport: String,
    /// The roles that get it; empty means every role that is not read-only.
    pub roles: Vec<String>,
    pub read_only: bool,
    pub hosts: Vec<String>,
    pub tools: Option<Vec<String>>,
}

pub fn configured(cfg: &McpCfg) -> Vec<McpConfigured> {
    cfg.servers
        .iter()
        .map(|(name, s)| McpConfigured {
            server: name.clone(),
            transport: if s.url.is_some() { "http" } else { "stdio" }.into(),
            roles: s.roles.clone().unwrap_or_default(),
            read_only: s.read_only,
            hosts: s.hosts.clone(),
            tools: s.tools.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cfg(roles: Option<&[&str]>, read_only: bool) -> McpServerCfg {
        McpServerCfg {
            command: Some(vec!["srv".into()]),
            roles: roles.map(|r| r.iter().map(|s| s.to_string()).collect()),
            read_only,
            ..Default::default()
        }
    }

    fn def(name: &str, desc: &str) -> McpToolDef {
        McpToolDef {
            name: name.into(),
            description: desc.into(),
            input_schema: json!({"type": "object", "properties": {"q": {"type": "string"}}}),
            read_only_hint: None,
        }
    }

    #[test]
    fn default_roles_are_the_ones_that_are_not_read_only() {
        let s = cfg(None, false);
        assert!(serves(&s, "lead", false));
        assert!(serves(&s, "worker", false));
        assert!(!serves(&s, "verifier", true));
    }

    #[test]
    fn a_read_only_role_gets_a_server_only_when_the_operator_says_it_is_read_only() {
        assert!(serves(&cfg(None, true), "verifier", true));
        assert!(!serves(&cfg(Some(&["verifier"]), false), "verifier", true));
        assert!(serves(&cfg(Some(&["verifier"]), true), "verifier", true));
        assert!(!serves(&cfg(Some(&["lead"]), true), "verifier", true));
    }

    #[test]
    fn named_roles_limit_a_server() {
        let s = cfg(Some(&["lead"]), false);
        assert!(serves(&s, "lead", false));
        assert!(!serves(&s, "worker", false));
    }

    #[test]
    fn the_lead_lists_every_server_some_role_of_its_pack_gets() {
        let mut c = McpCfg::default();
        c.servers.insert("a".into(), cfg(Some(&["worker"]), false));
        c.servers.insert("b".into(), cfg(Some(&["nobody"]), false));
        c.servers.insert("c".into(), cfg(None, true));
        let roles = [("lead", false), ("worker", false), ("verifier", true)];
        assert_eq!(pack_servers(&c, &roles), ["a", "c"]);
        assert_eq!(role_servers(&c, "lead", false), ["c"]);
        assert_eq!(role_servers(&c, "verifier", true), ["c"]);
    }

    #[test]
    fn hosts_come_only_from_the_servers_a_role_gets_and_have_no_repeats() {
        let mut c = McpCfg::default();
        let mut a = cfg(Some(&["lead"]), false);
        a.hosts = vec!["api.github.com".into(), " ".into(), "API.github.com".into()];
        let mut b = cfg(Some(&["worker"]), false);
        b.hosts = vec!["other.test".into()];
        c.servers.insert("a".into(), a);
        c.servers.insert("b".into(), b);
        assert_eq!(hosts_for_role(&c, "lead", false), ["api.github.com"]);
        assert_eq!(hosts_for_role(&c, "worker", false), ["other.test"]);
        assert!(hosts_for_role(&c, "verifier", true).is_empty());
    }

    #[test]
    fn the_budget_keeps_the_tools_in_order_up_to_the_limit() {
        let big = "x".repeat(1_900);
        let tools: Vec<_> = (0..6).map(|i| (format!("mcp__s__t{i}"), def(&format!("t{i}"), &big))).collect();
        let one = def_tokens(&tools[0].0, &tools[0].1);
        assert!(one > 400, "{one}");
        let (kept, left, used) = fit_budget(tools.clone(), one * 3 + one / 2);
        assert_eq!(kept.len(), 3);
        assert_eq!(left, 3);
        assert_eq!(used, one * 3);
        assert_eq!(kept[2].0, "mcp__s__t2");
        let (kept, left, _) = fit_budget(tools.clone(), 0);
        assert!(kept.is_empty());
        assert_eq!(left, 6);
        let (kept, left, _) = fit_budget(tools, u64::MAX);
        assert_eq!((kept.len(), left), (6, 0));
    }

    #[test]
    fn a_small_tool_never_jumps_ahead_of_a_large_one_that_did_not_fit() {
        let tools = vec![
            ("mcp__s__big".to_string(), def("big", &"y".repeat(1_900))),
            ("mcp__s__small".to_string(), def("small", "")),
        ];
        let small = def_tokens(&tools[1].0, &tools[1].1);
        let (kept, left, _) = fit_budget(tools, small + 5);
        assert!(kept.is_empty());
        assert_eq!(left, 2);
    }

    #[test]
    fn the_estimate_ignores_a_schema_key_the_model_is_not_sent() {
        let mut d = def("t", "d");
        let plain = def_tokens("mcp__s__t", &d);
        d.input_schema["$schema"] = json!("http://json-schema.org/draft-07/schema#".repeat(20));
        assert_eq!(def_tokens("mcp__s__t", &d), plain);
    }

    fn pick(server: &str) -> ServerPick {
        ServerPick {
            server: server.into(),
            transport: "stdio".into(),
            presented: vec![("mcp__github__a".into(), def("a", "")), ("mcp__github__b".into(), def("b", ""))],
            by_filter: 0,
            collisions: Vec::new(),
            over_budget: 0,
            hosts: Vec::new(),
            error: None,
        }
    }

    #[test]
    fn no_note_when_no_server_is_involved() {
        assert_eq!(start_note(&[], 20_000), None);
    }

    #[test]
    fn the_note_names_counts_hosts_and_everything_left_out() {
        let mut a = pick("github");
        a.hosts = vec!["api.github.com".into()];
        a.by_filter = 3;
        a.over_budget = 2;
        a.collisions = vec!["a b".into()];
        let mut b = pick("docs");
        b.transport = "http".into();
        b.presented.clear();
        b.error = Some("connection refused".into());
        let mut c = pick("one");
        c.presented.truncate(1);
        let note = start_note(&[a, b, c], 20_000).unwrap();
        assert_eq!(
            note,
            "MCP servers for this session. Their tools are named mcp__{server}__{tool}.\n\
- github (stdio): 2 tools; added to the allowed hosts: api.github.com; left out: 3 not in its `tools` list; 2 over the size budget of 20000 tokens for tool definitions; 1 with a name already taken (a b).\n\
- docs (http): could not be used, no tools: connection refused.\n\
- one (stdio): 1 tool."
        );
    }
}
