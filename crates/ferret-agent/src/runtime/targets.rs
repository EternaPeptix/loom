//! The runtime's side of targets (CONTRACTS-TRAFFIC-TARGETS T2, T4, T5): naming a target at the lead's
//! start, the prompt section, and the graph writes made as records are appended (exchanges, the security
//! state's assets and coverage, supported claims).

use super::*;
use ferret_core::event::TargetRef;
use ferret_core::ledger::{ClaimStatus, LedgerOp, LedgerState};
use ferret_core::security_state::{
    canonical_locator, AssetKind, CodeLocation, CoverageDisposition, Finding, FindingStatus, SecurityOp, SurfaceOutcome,
};
use ferret_core::target::{
    claim_hosts, locator_host, node_id, path_template, registrable_domain, GraphLine, NodeKind, Scope, TargetFinding,
    TargetStore,
};
use std::net::IpAddr;
use std::time::Instant;

/// The network sentence with what the target adds (T2) and, for a lead whose mission has credential
/// profile(s), the line that says they are attached (S11 + multi-principal). Without a target it is unchanged.
pub(super) fn network_with_target(text: String, meta: &SessionMeta) -> String {
    let Some(t) = meta.target.as_ref() else { return text };
    let mut s = format!("{text} Target `{}` adds these to what can be reached: {}.", t.name, t.scope.join(", "));
    if !t.exclude.is_empty() {
        s.push_str(&format!(" Refused even where something else would allow them: {}.", t.exclude.join(", ")));
    }
    if let (Some(c), None) = (meta.creds.as_ref(), meta.parent.as_ref()) {
        let via = if meta.intercept {
            "commands through the proxy, http_send, web_fetch"
        } else {
            "http_send, web_fetch, and plain-HTTP requests from commands; a command's HTTPS goes through an opaque tunnel and carries nothing"
        };
        s.push_str(&format!(
            " Credential profile {} is attached to your requests to those hosts ({via}); you never see its values, and a cookie or header your request sends itself overrides it.",
            c.summary
        ));
        if meta.creds_profiles.len() > 1 {
            let names: Vec<&str> = meta.creds_profiles.iter().map(|p| p.profile.as_str()).collect();
            s.push_str(&format!(
                " Additional mounted credential profiles available via `as_profile` / `http_authz_matrix` (default `{}`): {} (plus `anon`).",
                c.profile,
                names.join(", ")
            ));
        }
    }
    s
}

/// The `# Target` section of a lead's prompt: its name and the summary recorded at the start.
pub(super) fn prompt_target(meta: &SessionMeta) -> Option<(String, String)> {
    if meta.parent.is_some() {
        return None;
    }
    meta.target.as_ref().map(|t| (t.name.clone(), t.summary.clone()))
}

/// Last time a `target` event went out, and whether one is waiting to go.
fn throttle() -> &'static Mutex<HashMap<String, (Instant, bool)>> {
    static T: std::sync::OnceLock<Mutex<HashMap<String, (Instant, bool)>>> = std::sync::OnceLock::new();
    T.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The service and endpoint locators of an exchange with `host` (T3, T4): `host:port/tcp` and
/// `METHOD scheme://host:port/path-template`.
pub(super) fn exchange_locators(x: &ferret_core::event::Exchange, host: &str) -> (String, String) {
    let shown = if host.contains(':') { format!("[{host}]") } else { host.to_string() };
    let scheme = if x.scheme.is_empty() { "http" } else { x.scheme.as_str() };
    (
        format!("{shown}:{}/tcp", x.port),
        format!("{} {scheme}://{shown}:{}{}", x.method.to_ascii_uppercase(), x.port, path_template(&x.target)),
    )
}

fn ip_or_host(host: &str) -> NodeKind {
    if host.parse::<std::net::IpAddr>().is_ok() {
        NodeKind::Ip
    } else {
        NodeKind::Host
    }
}

/// Lines under construction for one write, with the identity every line carries.
struct Lines {
    out: Vec<GraphLine>,
    mission: String,
    session: String,
    ts: u64,
}

impl Lines {
    fn node(&mut self, kind: NodeKind, locator: &str, evidence: &[String]) -> String {
        let id = node_id(kind, locator);
        self.out.push(GraphLine::NodeSeen {
            id: id.clone(),
            kind,
            locator: locator.to_string(),
            mission: self.mission.clone(),
            session: self.session.clone(),
            ts_ms: self.ts,
            evidence: evidence.to_vec(),
            prev: String::new(),
        });
        id
    }

    fn edge(&mut self, kind: &str, from: &str, to: &str) {
        self.out.push(GraphLine::Edge {
            kind: kind.into(),
            from: from.into(),
            to: to.into(),
            mission: self.mission.clone(),
            session: self.session.clone(),
            ts_ms: self.ts,
            prev: String::new(),
        });
    }

    /// A host or IP node, with its domain and the `parent` edge for a name.
    fn host(&mut self, host: &str, evidence: &[String]) -> String {
        let kind = ip_or_host(host);
        let id = self.node(kind, host, evidence);
        if kind == NodeKind::Host {
            if let Some(d) = registrable_domain(host).filter(|d| d != host) {
                let did = self.node(NodeKind::Domain, &d, &[]);
                self.edge("parent", &id, &did);
            }
        }
        id
    }
}

impl Inner {
    pub(super) fn target_store(&self) -> TargetStore {
        TargetStore::new(self.paths.targets_dir())
    }

    /// The target a new mission names (T2), with its scope and full summary as of now. `None` for no name.
    pub(super) fn target_ref(&self, name: Option<&str>) -> Result<Option<TargetRef>, String> {
        let Some(name) = name.map(str::trim).filter(|n| !n.is_empty()) else { return Ok(None) };
        let store = self.target_store();
        let cfg = store.get(name)?;
        Scope::parse(&cfg.scope, &cfg.exclude)?;
        let summary_text = store.summary(name)?;
        Ok(Some(TargetRef {
            name: name.to_string(),
            scope: cfg.scope.clone(),
            exclude: cfg.exclude.clone(),
            upstream_insecure: cfg.upstream_insecure.clone(),
            intercept_passthrough: cfg.intercept_passthrough.clone(),
            summary: summary_text,
        }))
    }

    /// The target and mission of a session, when its mission has a target.
    fn target_of(&self, session: &SessionId) -> Option<(TargetRef, String)> {
        let st = self.st();
        let k = st.known.get(session)?;
        Some((k.meta.target.clone()?, k.meta.mission.as_str().to_string()))
    }

    pub(super) fn target_nodes_of(
        &self,
        session: &SessionId,
    ) -> Option<Result<(String, Vec<ferret_core::target::NodeView>), String>> {
        let (t, _) = self.target_of(session)?;
        Some(self.target_store().nodes(&t.name).map(|n| (t.name, n)))
    }

    /// Append `lines` to the target's graph; a failure is logged, never fatal to the mission.
    fn target_write(&self, t: &TargetRef, lines: Vec<GraphLine>) {
        if lines.is_empty() {
            return;
        }
        match self.target_store().append(&t.name, lines) {
            Ok(()) => self.target_changed(&t.name),
            Err(e) => tracing::warn!(target_name = %t.name, "graph write failed: {e}"),
        }
    }

    /// Tell the bus the graph changed: at most once a second per target, the last change always follows.
    fn target_changed(&self, name: &str) {
        let wait = {
            let mut m = lock(throttle());
            let e = m.entry(name.to_string()).or_insert((Instant::now() - Duration::from_secs(5), false));
            let since = e.0.elapsed();
            if since >= Duration::from_secs(1) {
                e.0 = Instant::now();
                None
            } else if e.1 {
                return;
            } else {
                e.1 = true;
                Some(Duration::from_secs(1) - since)
            }
        };
        match wait {
            None => self.publish(BusEvent::Target { name: name.to_string() }),
            Some(d) => {
                let (bus, name) = (self.bus.clone(), name.to_string());
                let send = move || {
                    let mut m = lock(throttle());
                    if let Some(e) = m.get_mut(&name) {
                        e.0 = Instant::now();
                        e.1 = false;
                    }
                    let _ = bus.send(BusEvent::Target { name });
                };
                match tokio::runtime::Handle::try_current() {
                    Ok(h) => {
                        h.spawn(async move {
                            tokio::time::sleep(d).await;
                            send();
                        });
                    }
                    Err(_) => send(),
                }
            }
        }
    }

    /// Prior-mission findings in the mission target's graph matching the 3-axis key
    /// `(vuln_class, surface, param_or_sink)`. Empty when the mission has no target or on read error.
    pub(super) fn target_duplicate_findings(
        &self,
        session: &SessionId,
        vuln_class: &str,
        surface: &str,
        param_or_sink: &str,
    ) -> Vec<TargetFinding> {
        let Some((t, mission)) = self.target_of(session) else { return Vec::new() };
        match self.target_store().find_duplicate_findings(&t.name, vuln_class, surface, param_or_sink) {
            Ok(matches) => matches.into_iter().filter(|f| f.mission != mission).collect(),
            Err(e) => {
                tracing::warn!(target_name = %t.name, "duplicate finding lookup failed: {e}");
                Vec::new()
            }
        }
    }

    /// Record a host -> IP DNS resolution observed by the proxy audit hook, deduplicated per `(target, host, ip)`.
    pub(super) fn target_resolves(&self, session: &SessionId, ts: u64, host: &str, ip: &str) {
        let host = host.trim().trim_end_matches('.').trim_matches(['[', ']']).to_ascii_lowercase();
        let ip = ip.trim().trim_matches(['[', ']']).to_string();
        if host.is_empty() || host.parse::<IpAddr>().is_ok() || ip.parse::<IpAddr>().is_err() {
            return;
        }
        let Some((t, mission)) = self.target_of(session) else { return };
        let Ok(scope) = Scope::parse(&t.scope, &t.exclude) else { return };
        if scope.excluded(&host) || scope.excluded(&ip) || (!scope.contains(&host) && !scope.contains(&ip)) {
            return;
        }
        {
            let mut seen = lock(&self.resolves_seen);
            if seen.len() >= 4096 {
                seen.clear();
            }
            if !seen.insert((t.name.clone(), host.clone(), ip.clone())) {
                return;
            }
        }
        self.target_write(&t, vec![GraphLine::Resolves { host, ip, mission, at_ms: ts, prev: String::new() }]);
    }

    /// An exchange of a session whose mission has a target (T4 + Wave B passive signals): the host, its
    /// domain, the service, the endpoint, and deduplicated passive signals when the host is in scope.
    pub(super) fn target_exchange(&self, session: &SessionId, ts: u64, x: &ferret_core::event::Exchange) {
        let Some((t, mission)) = self.target_of(session) else { return };
        let Ok(scope) = Scope::parse(&t.scope, &t.exclude) else { return };
        let host = x.host.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() || !scope.contains(&host) {
            return;
        }
        let mut l = Lines { out: Vec::new(), mission, session: session.as_str().to_string(), ts };
        let ev = vec![x.id.clone()];
        let hid = l.host(&host, &ev);
        let (svc, ep) = exchange_locators(x, &host);
        let sid = l.node(NodeKind::Service, &svc, &ev);
        l.edge("runs", &hid, &sid);
        let eid = l.node(NodeKind::Endpoint, &ep, &ev);
        l.edge("serves", &sid, &eid);
        if !x.passive_signals.is_empty() {
            let path = x.target.split(['?', '#']).next().unwrap_or("/");
            let path = if path.is_empty() { "/" } else { path };
            let mut seen_passive: HashSet<(&str, &str)> = HashSet::new();
            for sig in &x.passive_signals {
                if seen_passive.insert((sig.kind.as_str(), sig.summary.as_str())) {
                    l.out.push(GraphLine::Passive {
                        mission: l.mission.clone(),
                        exchange_id: x.id.clone(),
                        host: host.clone(),
                        path: path.to_string(),
                        signal: sig.clone(),
                        at_ms: ts,
                        prev: String::new(),
                    });
                }
            }
        }
        self.target_write(&t, l.out);
    }

    /// A ledger op the mission's ledger took (T4 + Wave B): assets, coverage, structured findings,
    /// risk-area dispositions, dead ends, host -> IP resolves, and claims.
    pub(super) fn target_ledger(&self, session: &SessionId, op: &LedgerOp, state: &LedgerState) {
        let Some((t, mission)) = self.target_of(session) else { return };
        let Ok(scope) = Scope::parse(&t.scope, &t.exclude) else { return };
        let mut l = Lines { out: Vec::new(), mission, session: session.as_str().to_string(), ts: now_ms() };
        match op {
            LedgerOp::Security(s) => security_lines(&mut l, s, state),
            LedgerOp::DeadEnd { what, why } => {
                let what_t = what.trim();
                let why_t = why.trim();
                if what_t.is_empty() {
                    return;
                }
                let surface = extract_dead_end_surface(what_t);
                let summary = if why_t.is_empty() { what_t.to_string() } else { format!("{what_t}: {why_t}") };
                l.out.push(GraphLine::DeadEnd {
                    mission: l.mission.clone(),
                    surface,
                    summary,
                    at_ms: l.ts,
                    prev: String::new(),
                });
            }
            LedgerOp::ClaimUpdate { id, status, .. } => {
                let Some(c) = state.claims.iter().find(|c| &c.id == id) else { return };
                let status = match status {
                    ClaimStatus::Supported => "open",
                    ClaimStatus::Refuted => "refuted",
                    ClaimStatus::Withdrawn => "withdrawn",
                    ClaimStatus::Open => return,
                };
                let nodes: Vec<String> = claim_hosts(&c.text, &[], Some(&scope))
                    .into_iter()
                    .filter(|h| scope.contains(h))
                    .map(|h| node_id(ip_or_host(&h), &h))
                    .collect();
                if nodes.is_empty() {
                    return;
                }
                l.out.push(GraphLine::Finding {
                    nodes,
                    claim: c.id.clone(),
                    text: c.text.clone(),
                    status: status.into(),
                    evidence: c.evidence.clone(),
                    mission: l.mission.clone(),
                    session: l.session.clone(),
                    ts_ms: l.ts,
                    prev: String::new(),
                });
            }
            _ => return,
        }
        self.target_write(&t, l.out);
    }
}

/// Curated vulnerability-class tokens used when a finding has no explicit CWE.
const VULN_CLASS_TOKENS: &[(&str, &str)] = &[
    ("missing authentication", "missing_authentication"),
    ("missing authorization", "missing_authorization"),
    ("broken access control", "broken_access_control"),
    ("incorrect authorization", "incorrect_authorization"),
    ("default credentials", "default_credentials"),
    ("hardcoded credentials", "hardcoded_credentials"),
    ("hardcoded secret", "hardcoded_secret"),
    ("hardcoded password", "hardcoded_password"),
    ("session fixation", "session_fixation"),
    ("open redirect", "open_redirect"),
    ("path traversal", "path_traversal"),
    ("directory traversal", "path_traversal"),
    ("command injection", "command_injection"),
    ("sql injection", "sql_injection"),
    ("sqli", "sql_injection"),
    ("code injection", "code_injection"),
    ("template injection", "template_injection"),
    ("ssti", "template_injection"),
    ("xpath injection", "xpath_injection"),
    ("ldap injection", "ldap_injection"),
    ("deserialization", "deserialization"),
    ("ssrf", "ssrf"),
    ("server-side request forgery", "ssrf"),
    ("xss", "xss"),
    ("cross-site scripting", "xss"),
    ("csrf", "csrf"),
    ("xxe", "xxe"),
    ("race condition", "race_condition"),
    ("toctou", "race_condition"),
    ("information disclosure", "information_disclosure"),
    ("insecure direct object reference", "idor"),
    ("idor", "idor"),
    ("bola", "bola"),
    ("bfla", "bfla"),
    ("auth bypass", "auth_bypass"),
];

/// Compute the 3-axis `(vuln_class, surface, param_or_sink)` tuple shared by `GraphLine::SecurityFinding`
/// writes and cross-mission `TargetStore::find_duplicate_findings` lookups.
pub(crate) fn finding_dedup_axes(
    cwe: Option<&str>,
    title: &str,
    target: &str,
    endpoint: Option<&str>,
    code_locations: &[CodeLocation],
) -> (String, String, String) {
    let vuln_class = if let Some(raw) = cwe.map(str::trim).filter(|s| !s.is_empty()) {
        raw.to_string()
    } else {
        let low = title.to_ascii_lowercase();
        VULN_CLASS_TOKENS
            .iter()
            .find_map(|(needle, canon)| low.contains(needle).then(|| (*canon).to_string()))
            .unwrap_or_else(|| title.trim().to_string())
    };

    let raw_ep = endpoint.map(str::trim).filter(|s| !s.is_empty()).map(|ep| match ep.split_once(char::is_whitespace) {
        Some((m, rest))
            if matches!(
                m.to_ascii_uppercase().as_str(),
                "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" | "TRACE"
            ) =>
        {
            rest.trim()
        }
        _ => ep,
    });

    let surface = match raw_ep {
        Some(ep) if ep.starts_with("http://") || ep.starts_with("https://") => {
            ep.split(['?', '#']).next().unwrap_or(ep).to_string()
        }
        Some(ep) if ep.starts_with('/') => {
            let path = ep.split(['?', '#']).next().unwrap_or(ep);
            let t = target.trim();
            if let Ok(u) = url::Url::parse(t) {
                if let Some(h) = u.host_str() {
                    let host_port = match u.port() {
                        Some(p) => format!("{h}:{p}"),
                        None => h.to_string(),
                    };
                    format!("{}://{host_port}{path}", u.scheme())
                } else {
                    path.to_string()
                }
            } else if !t.is_empty() && !t.chars().any(char::is_whitespace) {
                let host = t.split('/').next().unwrap_or(t);
                format!("https://{host}{path}")
            } else {
                path.to_string()
            }
        }
        Some(ep) => ep.split(['?', '#']).next().unwrap_or(ep).to_string(),
        None => target.trim().to_string(),
    };

    let param_or_sink = if let Some(ep) = raw_ep {
        if let Some((_, after_q)) = ep.split_once('?') {
            let query = after_q.split('#').next().unwrap_or(after_q);
            let mut keys: Vec<String> = query
                .split('&')
                .filter_map(|pair| {
                    let k = pair.split('=').next().unwrap_or("").trim().to_ascii_lowercase();
                    (!k.is_empty()).then_some(k)
                })
                .collect();
            keys.sort();
            keys.dedup();
            keys.join(",")
        } else if let Some(loc) = code_locations.first() {
            format!("{}:{}", loc.file.trim(), loc.start_line)
        } else {
            String::new()
        }
    } else if let Some(loc) = code_locations.first() {
        format!("{}:{}", loc.file.trim(), loc.start_line)
    } else {
        String::new()
    };

    (vuln_class, surface, param_or_sink)
}

fn extract_dead_end_surface(what: &str) -> String {
    for tok in what.split_whitespace() {
        let cleaned = tok.trim_matches(|c: char| matches!(c, '"' | '\'' | '`' | '(' | ')' | ',' | ';' | '<' | '>'));
        if cleaned.starts_with("http://") || cleaned.starts_with("https://") {
            return cleaned.to_string();
        }
    }
    what.to_string()
}

fn format_disposition_note(control: Option<&str>, location: Option<&str>, reason: Option<&str>) -> String {
    let mut parts = Vec::new();
    if let Some(r) = reason.map(str::trim).filter(|s| !s.is_empty()) {
        parts.push(r.to_string());
    }
    if let Some(c) = control.map(str::trim).filter(|s| !s.is_empty()) {
        parts.push(format!("control: {c}"));
    }
    if let Some(loc) = location.map(str::trim).filter(|s| !s.is_empty()) {
        parts.push(format!("at {loc}"));
    }
    parts.join("; ")
}

fn push_security_finding_line(l: &mut Lines, f: &Finding) {
    if f.status != FindingStatus::Active {
        return;
    }
    let (vuln_class, surface, param_or_sink) =
        finding_dedup_axes(f.cwe.as_deref(), &f.title, &f.target, f.endpoint.as_deref(), &f.code_locations);
    l.out.push(GraphLine::SecurityFinding {
        id: f.id.clone(),
        mission: l.mission.clone(),
        title: f.title.clone(),
        vuln_class,
        surface,
        param_or_sink,
        severity: f.severity.as_str().to_string(),
        confidence: f.confidence.as_str().to_string(),
        at_ms: l.ts,
        prev: String::new(),
    });
}

/// The graph lines of one security op (a batch is flattened).
fn security_lines(l: &mut Lines, op: &SecurityOp, state: &LedgerState) {
    match op {
        SecurityOp::Batch { operations } => {
            for o in operations {
                security_lines(l, o, state);
            }
        }
        SecurityOp::AssetUpsert { asset } => {
            let Ok(loc) = canonical_locator(asset.kind, &asset.locator) else { return };
            let ev = &asset.evidence;
            let ev: Vec<String> = ev.to_vec();
            match asset.kind {
                AssetKind::Host => {
                    l.host(&loc, &ev);
                }
                AssetKind::Service => {
                    let h = l.host(&locator_host(NodeKind::Service, &loc), &ev);
                    let s = l.node(NodeKind::Service, &loc, &ev);
                    l.edge("runs", &h, &s);
                }
                AssetKind::Endpoint => {
                    let host = locator_host(NodeKind::Endpoint, &loc);
                    let h = l.host(&host, &ev);
                    let e = l.node(NodeKind::Endpoint, &loc, &ev);
                    let parent = asset
                        .parent
                        .as_ref()
                        .and_then(|p| state.security.assets.get(p))
                        .filter(|p| p.kind == AssetKind::Service);
                    match parent {
                        Some(p) => {
                            let s = l.node(NodeKind::Service, &p.locator, &[]);
                            l.edge("serves", &s, &e);
                        }
                        None => l.edge("runs", &h, &e),
                    }
                }
                AssetKind::File | AssetKind::Identity => {}
            }
        }
        SecurityOp::RelationAdd { relation } => {
            if relation.kind.eq_ignore_ascii_case("resolves") {
                let from = state.security.assets.get(&relation.from);
                let to = state.security.assets.get(&relation.to);
                if let (Some(f), Some(t)) = (from, to) {
                    let host = locator_host(NodeKind::Host, &f.locator);
                    let ip = locator_host(NodeKind::Ip, &t.locator);
                    if !host.is_empty() && host.parse::<IpAddr>().is_err() && ip.parse::<IpAddr>().is_ok() {
                        l.out.push(GraphLine::Resolves {
                            host,
                            ip,
                            mission: l.mission.clone(),
                            at_ms: l.ts,
                            prev: String::new(),
                        });
                    }
                }
            }
        }
        SecurityOp::FactAssert { fact, .. } => {
            if fact.predicate.eq_ignore_ascii_case("resolves") && fact.args.len() >= 2 {
                let host = fact.args[0].trim().trim_end_matches('.').to_ascii_lowercase();
                let ip = fact.args[1].trim().trim_matches(['[', ']']).to_string();
                if !host.is_empty() && host.parse::<IpAddr>().is_err() && ip.parse::<IpAddr>().is_ok() {
                    l.out.push(GraphLine::Resolves {
                        host,
                        ip,
                        mission: l.mission.clone(),
                        at_ms: l.ts,
                        prev: String::new(),
                    });
                }
            }
        }
        SecurityOp::CoverageSet { asset, disposition } => {
            let Some(a) = state
                .security
                .assets
                .get(asset)
                .or_else(|| state.security.resolve(asset).ok().and_then(|id| state.security.assets.get(&id)))
            else {
                return;
            };
            let kind = match a.kind {
                AssetKind::Host => ip_or_host(&a.locator),
                AssetKind::Service => NodeKind::Service,
                AssetKind::Endpoint => NodeKind::Endpoint,
                AssetKind::File | AssetKind::Identity => return,
            };
            let (status, reason, evidence) = match disposition {
                CoverageDisposition::Tested { evidence } => ("tested", None, evidence.to_vec()),
                CoverageDisposition::Deferred { reason } => ("deferred", Some(reason.clone()), Vec::new()),
                CoverageDisposition::Untested => return,
            };
            l.out.push(GraphLine::Coverage {
                node: node_id(kind, &a.locator),
                status: status.into(),
                reason,
                evidence,
                mission: l.mission.clone(),
                session: l.session.clone(),
                ts_ms: l.ts,
                prev: String::new(),
            });
        }
        SecurityOp::CoverageRecord { surface, risk_area, outcome, control, location, reason, .. } => {
            if matches!(outcome, SurfaceOutcome::RuledOut | SurfaceOutcome::NeedsFollowUp) {
                l.out.push(GraphLine::Disposition {
                    mission: l.mission.clone(),
                    surface: surface.clone(),
                    risk_area: risk_area.clone(),
                    disposition: outcome.as_str().to_string(),
                    note: format_disposition_note(control.as_deref(), location.as_deref(), reason.as_deref()),
                    at_ms: l.ts,
                    prev: String::new(),
                });
            }
        }
        SecurityOp::CoverageUpdate { id, outcome, control, location, reason, .. } => {
            if matches!(outcome, SurfaceOutcome::RuledOut | SurfaceOutcome::NeedsFollowUp) {
                let entry = state.security.surface_coverage.get(id).or_else(|| {
                    state.security.resolve(id).ok().and_then(|rid| state.security.surface_coverage.get(&rid))
                });
                if let Some(entry) = entry {
                    l.out.push(GraphLine::Disposition {
                        mission: l.mission.clone(),
                        surface: entry.surface.clone(),
                        risk_area: entry.risk_area.clone(),
                        disposition: outcome.as_str().to_string(),
                        note: format_disposition_note(control.as_deref(), location.as_deref(), reason.as_deref()),
                        at_ms: l.ts,
                        prev: String::new(),
                    });
                }
            }
        }
        SecurityOp::FindingRecord { finding } => {
            let id = finding.id();
            if let Some(f) = state.security.findings.get(&id) {
                push_security_finding_line(l, f);
            }
        }
        SecurityOp::FindingUpdate { update } => {
            let finding =
                state.security.findings.get(&update.id).or_else(|| {
                    state.security.resolve(&update.id).ok().and_then(|rid| state.security.findings.get(&rid))
                });
            if let Some(f) = finding {
                push_security_finding_line(l, f);
            }
        }
        _ => {}
    }
}
