//! The runtime's side of targets (CONTRACTS-TRAFFIC-TARGETS T2, T4, T5): naming a target at the lead's
//! start, the prompt section, and the graph writes made as records are appended (exchanges, the security
//! state's assets and coverage, supported claims).

use super::*;
use loom_core::event::TargetRef;
use loom_core::ledger::{ClaimStatus, LedgerOp, LedgerState};
use loom_core::security_state::{canonical_locator, AssetKind, CoverageDisposition, SecurityOp};
use loom_core::target::{
    claim_hosts, locator_host, node_id, path_template, registrable_domain, summary, GraphLine, NodeKind, Scope,
    TargetStore,
};
use std::time::Instant;

/// The network sentence with what the target adds (T2). Without a target it is unchanged.
pub(super) fn network_with_target(text: String, target: Option<&TargetRef>) -> String {
    let Some(t) = target else { return text };
    let mut s = format!("{text} Target `{}` adds these to what can be reached: {}.", t.name, t.scope.join(", "));
    if !t.exclude.is_empty() {
        s.push_str(&format!(" Refused even where something else would allow them: {}.", t.exclude.join(", ")));
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
pub(super) fn exchange_locators(x: &loom_core::event::Exchange, host: &str) -> (String, String) {
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

    /// The target a new mission names (T2), with its scope and summary as of now. `None` for no name.
    pub(super) fn target_ref(&self, name: Option<&str>) -> Result<Option<TargetRef>, String> {
        let Some(name) = name.map(str::trim).filter(|n| !n.is_empty()) else { return Ok(None) };
        let store = self.target_store();
        let cfg = store.get(name)?;
        Scope::parse(&cfg.scope, &cfg.exclude)?;
        let nodes = store.nodes(name)?;
        Ok(Some(TargetRef {
            name: name.to_string(),
            scope: cfg.scope.clone(),
            exclude: cfg.exclude.clone(),
            upstream_insecure: cfg.upstream_insecure.clone(),
            intercept_passthrough: cfg.intercept_passthrough.clone(),
            summary: summary(name, &cfg, &nodes),
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
    ) -> Option<Result<(String, Vec<loom_core::target::NodeView>), String>> {
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

    /// An exchange of a session whose mission has a target (T4): the host, its domain, the service and the
    /// endpoint, when the host is in scope.
    pub(super) fn target_exchange(&self, session: &SessionId, ts: u64, x: &loom_core::event::Exchange) {
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
        self.target_write(&t, l.out);
    }

    /// A ledger op the mission's ledger took (T4): assets and coverage of the security state, and claims.
    pub(super) fn target_ledger(&self, session: &SessionId, op: &LedgerOp, state: &LedgerState) {
        let Some((t, mission)) = self.target_of(session) else { return };
        let Ok(scope) = Scope::parse(&t.scope, &t.exclude) else { return };
        let mut l = Lines { out: Vec::new(), mission, session: session.as_str().to_string(), ts: now_ms() };
        match op {
            LedgerOp::Security(s) => security_lines(&mut l, s, state),
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
        _ => {}
    }
}
