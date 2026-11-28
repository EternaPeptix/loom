//! What the API serves of targets (CONTRACTS-TRAFFIC-TARGETS T7): the targets, a target's graph and the
//! exchanges of a session or of a target's missions. The CA commands of the CLI also come through here.

use super::*;
use ferret_core::event::Exchange;
use ferret_core::target::{locator_host, node_id, registrable_domain, EdgeView, NodeKind, NodeView, TargetCfg};

/// `POST /api/targets` and `PUT /api/targets/{name}`: what is given replaces what the target has; what is
/// left out stays. `name` is required to create and ignored (or must match) on update.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TargetBody {
    pub name: Option<String>,
    pub scope: Option<Vec<String>>,
    pub exclude: Option<Vec<String>>,
    pub upstream_insecure: Option<Vec<String>>,
    pub intercept_passthrough: Option<Vec<String>>,
    pub notes: Option<String>,
}

/// A target as `GET /api/targets` and `GET /api/targets/{name}` serve it: its settings and how many nodes
/// have each status (`finding`, `tested`, `deferred`, `untested`, `not_seen`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TargetView {
    pub name: String,
    pub scope: Vec<String>,
    pub exclude: Vec<String>,
    pub upstream_insecure: Vec<String>,
    pub intercept_passthrough: Vec<String>,
    pub notes: String,
    pub counts: BTreeMap<String, usize>,
}

/// `GET /api/targets/{name}/graph`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphView {
    pub name: String,
    pub nodes: Vec<NodeView>,
    pub edges: Vec<EdgeView>,
}

/// One exchange of a session's log with where it is.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExchangeEntry {
    pub session: String,
    pub seq: u64,
    pub ts_ms: u64,
    pub exchange: Exchange,
}

/// Snapshot of the egress noise governor (`GET /api/network/noise`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoiseStatusView {
    pub profile: String,
    pub assessment_ua_origins: usize,
    pub hosts: Vec<ferret_net::HostNoise>,
}

fn word<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
}

fn counts(nodes: &[NodeView]) -> BTreeMap<String, usize> {
    let mut m: BTreeMap<String, usize> =
        ["finding", "tested", "deferred", "untested", "not_seen"].iter().map(|k| (k.to_string(), 0)).collect();
    for n in nodes {
        *m.entry(word(&n.status)).or_default() += 1;
    }
    m
}

fn view(name: &str, cfg: TargetCfg, nodes: &[NodeView]) -> TargetView {
    TargetView {
        name: name.to_string(),
        scope: cfg.scope,
        exclude: cfg.exclude,
        upstream_insecure: cfg.upstream_insecure,
        intercept_passthrough: cfg.intercept_passthrough,
        notes: cfg.notes,
        counts: counts(nodes),
    }
}

fn apply(cfg: &mut TargetCfg, b: &TargetBody) {
    if let Some(v) = &b.scope {
        cfg.scope = v.clone();
    }
    if let Some(v) = &b.exclude {
        cfg.exclude = v.clone();
    }
    if let Some(v) = &b.upstream_insecure {
        cfg.upstream_insecure = v.clone();
    }
    if let Some(v) = &b.intercept_passthrough {
        cfg.intercept_passthrough = v.clone();
    }
    if let Some(v) = &b.notes {
        cfg.notes = v.clone();
    }
}

/// The interception CA of the ferret home: its fingerprint and the file of its certificate.
pub fn ca_show(home: &Path) -> Result<(String, PathBuf), String> {
    let dir = home.join("ca");
    let ca = ferret_net::tls::Ca::load_or_create(&dir)?;
    Ok((ca.fingerprint_sha256.clone(), dir.join("ferret-ca.pem")))
}

/// A new interception CA in place of the old one.
pub fn ca_rotate(home: &Path) -> Result<(String, PathBuf), String> {
    let dir = home.join("ca");
    let ca = ferret_net::tls::Ca::rotate(&dir)?;
    Ok((ca.fingerprint_sha256.clone(), dir.join("ferret-ca.pem")))
}

impl Runtime {
    pub fn target_list(&self) -> Result<Vec<TargetView>, String> {
        let store = self.inner.target_store();
        let mut out = Vec::new();
        for (name, cfg) in store.list()? {
            let nodes = store.nodes(&name)?;
            out.push(view(&name, cfg, &nodes));
        }
        Ok(out)
    }

    pub fn target_show(&self, name: &str) -> Result<TargetView, String> {
        let store = self.inner.target_store();
        let cfg = store.get(name)?;
        let nodes = store.nodes(name)?;
        Ok(view(name, cfg, &nodes))
    }

    pub fn target_create(&self, body: &TargetBody) -> Result<TargetView, String> {
        let store = self.inner.target_store();
        let name = body
            .name
            .as_deref()
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .ok_or("Give the target a name, such as `acme`.")?;
        if !ferret_core::target::valid_target_name(name) {
            return Err(format!(
                "`{name}` is not a target name: use 1 to 64 characters from a-z, 0-9, `-` and `_`, starting with a letter or digit."
            ));
        }
        if store.exists(name) {
            return Err(format!(
                "Target `{name}` already exists; change it with PUT /api/targets/{name} or `ferret target scope`."
            ));
        }
        let mut cfg = TargetCfg::default();
        apply(&mut cfg, body);
        store.put(name, &cfg)?;
        self.inner.publish(BusEvent::Target { name: name.to_string() });
        self.target_show(name)
    }

    pub fn target_update(&self, name: &str, body: &TargetBody) -> Result<TargetView, String> {
        let store = self.inner.target_store();
        let mut cfg = store.get(name)?;
        apply(&mut cfg, body);
        store.put(name, &cfg)?;
        self.inner.publish(BusEvent::Target { name: name.to_string() });
        self.target_show(name)
    }

    /// The graph of a target; `status`, `kind` and `under` (a node id or locator) narrow the nodes, and the
    /// edges are those between the nodes kept.
    pub fn target_graph(
        &self,
        name: &str,
        status: Option<&str>,
        kind: Option<&str>,
        under: Option<&str>,
    ) -> Result<GraphView, String> {
        let store = self.inner.target_store();
        store.get(name)?;
        let mut nodes = store.nodes(name)?;
        let anchor = match under {
            Some(u) => Some(
                nodes
                    .iter()
                    .find(|n| n.id == u || n.locator == u)
                    .cloned()
                    .ok_or_else(|| format!("There is no node `{u}` in target `{name}`."))?,
            ),
            None => None,
        };
        let host_of = |n: &NodeView| locator_host(n.kind, &n.locator);
        nodes.retain(|n| {
            status.is_none_or(|s| word(&n.status) == s)
                && kind.is_none_or(|k| word(&n.kind) == k)
                && match &anchor {
                    None => true,
                    Some(a) if a.kind == NodeKind::Domain => {
                        n.id == a.id || host_of(n) == a.locator || host_of(n).ends_with(&format!(".{}", a.locator))
                    }
                    Some(a) => n.id == a.id || host_of(n) == host_of(a),
                }
        });
        let keep: std::collections::HashSet<&str> = nodes.iter().map(|n| n.id.as_str()).collect();
        let edges = store
            .edges(name)?
            .into_iter()
            .filter(|e| keep.contains(e.from.as_str()) && keep.contains(e.to.as_str()))
            .collect();
        Ok(GraphView { name: name.to_string(), nodes, edges })
    }

    /// The exchanges in a session's log, oldest first: from the host `host` only, after record `after`, at
    /// most `limit`.
    pub fn exchanges(
        &self,
        session: &SessionId,
        host: Option<&str>,
        after: Option<Seq>,
        limit: usize,
    ) -> Result<Vec<ExchangeEntry>, String> {
        self.inner.check_open()?;
        if !self.inner.st().known.contains_key(session) {
            return Err(no_session(session));
        }
        self.exchanges_of(session, |x| host.is_none_or(|h| x.host.eq_ignore_ascii_case(h)), after, limit)
    }

    /// The exchanges of every session of the target's missions with the node `node` (an id or a locator).
    pub fn target_exchanges(&self, name: &str, node: Option<&str>, limit: usize) -> Result<Vec<ExchangeEntry>, String> {
        self.inner.check_open()?;
        let store = self.inner.target_store();
        store.get(name)?;
        let wanted: Option<NodeView> = match node {
            Some(u) => Some(
                store
                    .nodes(name)?
                    .into_iter()
                    .find(|n| n.id == u || n.locator == u)
                    .ok_or_else(|| format!("There is no node `{u}` in target `{name}`."))?,
            ),
            None => None,
        };
        let sessions: Vec<SessionId> = {
            let st = self.inner.st();
            let mut v: Vec<_> = st
                .known
                .values()
                .filter(|k| k.meta.target.as_ref().is_some_and(|t| t.name == name))
                .map(|k| (k.meta.created_ms, k.meta.id.clone()))
                .collect();
            v.sort();
            v.into_iter().map(|(_, id)| id).collect()
        };
        let mut out = Vec::new();
        for s in sessions {
            let found = self.exchanges_of(&s, |x| matches_node(x, wanted.as_ref()), None, usize::MAX)?;
            out.extend(found);
        }
        out.sort_by_key(|e| (e.ts_ms, e.seq));
        if out.len() > limit {
            out.drain(..out.len() - limit);
        }
        Ok(out)
    }

    /// Export all captured exchanges of a mission as a HAR 1.2 JSON document.
    pub fn export_har(
        &self,
        mission: &MissionId,
        host: Option<&str>,
        limit: Option<usize>,
    ) -> Result<(serde_json::Value, ferret_core::har::HarExportMeta), String> {
        self.inner.check_open()?;
        let sessions: Vec<SessionId> = {
            let st = self.inner.st();
            let mut v: Vec<_> = st
                .known
                .values()
                .filter(|k| &k.meta.mission == mission)
                .map(|k| (k.meta.created_ms, k.meta.id.clone()))
                .collect();
            if v.is_empty() {
                return Err(format!("There is no mission {}.", mission.as_str()));
            }
            v.sort();
            v.into_iter().map(|(_, id)| id).collect()
        };
        let norm_filter = host.map(|h| h.trim().trim_end_matches('.').to_ascii_lowercase()).filter(|h| !h.is_empty());
        let mut entries = Vec::new();
        for s in sessions {
            let found = self.exchanges_of(
                &s,
                |x| {
                    norm_filter.as_deref().is_none_or(|want| {
                        x.host.trim().trim_end_matches('.').eq_ignore_ascii_case(want)
                    })
                },
                None,
                usize::MAX,
            )?;
            entries.extend(found);
        }
        entries.sort_by_key(|e| (e.ts_ms, e.seq));
        let pairs: Vec<(u64, &Exchange)> = entries.iter().map(|e| (e.ts_ms, &e.exchange)).collect();
        let mut opts = ferret_core::har::HarExportOptions::default();
        if let Some(n) = limit.filter(|&n| n > 0) {
            opts.max_entries = n.min(ferret_core::har::DEFAULT_MAX_IMPORT_ENTRIES);
        }
        ferret_core::har::export_har(&pairs, &self.inner.blobs, &opts)
    }

    /// Import a HAR 1.2 document into a mission's traffic log, deduplicating against existing exchange IDs.
    pub fn import_har(&self, mission: &MissionId, raw: &[u8]) -> Result<ferret_core::har::HarImportResult, String> {
        self.inner.check_open()?;
        let (lead, sessions) = {
            let st = self.inner.st();
            let mut v: Vec<_> = st
                .known
                .values()
                .filter(|k| &k.meta.mission == mission)
                .map(|k| (k.meta.parent.is_some(), k.meta.created_ms, k.meta.id.clone()))
                .collect();
            if v.is_empty() {
                return Err(format!("There is no mission {}.", mission.as_str()));
            }
            v.sort();
            let lead = v[0].2.clone();
            let all: Vec<SessionId> = v.into_iter().map(|(_, _, id)| id).collect();
            (lead, all)
        };

        let mut existing = std::collections::HashSet::new();
        for s in &sessions {
            for e in self.exchanges_of(s, |_| true, None, usize::MAX)? {
                existing.insert(e.exchange.id);
            }
        }
        if let Some(mt) = self
            .inner
            .mission_traffic
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(mission)
            .and_then(Weak::upgrade)
        {
            for x in mt.all() {
                existing.insert(x.id);
            }
        }

        let (imported, result) = ferret_core::har::import_har(
            raw,
            &self.inner.blobs,
            &existing,
            &ferret_core::har::HarImportOptions::default(),
        )?;
        if imported.is_empty() {
            return Ok(result);
        }

        let active_traffic = self
            .inner
            .traffic
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&lead)
            .and_then(Weak::upgrade);

        if let Some(traffic) = active_traffic {
            for item in imported {
                self.inner.target_exchange(&lead, item.ts_ms, &item.exchange);
                traffic.push_imported(item.exchange);
            }
            self.inner.send_input(&lead, Input::DrainQueued);
        } else {
            let log_path = self.inner.paths.session_log(&lead);
            let mut log = ferret_core::log::SessionLog::open(&log_path, ferret_core::log::Durability::Always)
                .map_err(|e| format!("Could not open session log for HAR import: {e}"))?
                .0;
            let live_mt = self
                .inner
                .mission_traffic
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(mission)
                .and_then(Weak::upgrade);
            for item in imported {
                if let Some(mt) = &live_mt {
                    mt.add(&item.exchange);
                }
                self.inner.target_exchange(&lead, item.ts_ms, &item.exchange);
                let _ = log
                    .append(Author::User, Event::Exchange(item.exchange))
                    .map_err(|e| format!("Could not write imported HAR exchange: {e}"))?;
            }
        }
        Ok(result)
    }

    fn exchanges_of(
        &self,
        session: &SessionId,
        keep: impl Fn(&Exchange) -> bool,
        after: Option<Seq>,
        limit: usize,
    ) -> Result<Vec<ExchangeEntry>, String> {
        let path = self.inner.paths.session_log(session);
        let report = match ferret_core::log::read_records(&path) {
            Ok(r) => r,
            Err(ferret_core::log::LogError::Io { .. }) if !path.exists() => return Ok(Vec::new()),
            Err(e) => return Err(format!("The log of session {} cannot be read: {e}", session.as_str())),
        };
        Ok(report
            .records
            .into_iter()
            .filter(|r| after.is_none_or(|a| r.seq > a))
            .filter_map(|r| match r.event {
                Event::Exchange(x) if keep(&x) => Some(ExchangeEntry {
                    session: session.as_str().to_string(),
                    seq: r.seq,
                    ts_ms: r.ts_ms,
                    exchange: x,
                }),
                _ => None,
            })
            .take(limit)
            .collect())
    }
}

/// Whether an exchange belongs to `node`: its host, domain, service or endpoint. `None` matches all.
fn matches_node(x: &Exchange, node: Option<&NodeView>) -> bool {
    let Some(n) = node else { return true };
    let host = x.host.trim().trim_end_matches('.').to_ascii_lowercase();
    let (svc, ep) = super::targets::exchange_locators(x, &host);
    match n.kind {
        NodeKind::Host | NodeKind::Ip => host == n.locator,
        NodeKind::Domain => registrable_domain(&host).as_deref() == Some(n.locator.as_str()),
        NodeKind::Service => n.id == node_id(NodeKind::Service, &svc),
        NodeKind::Endpoint => n.id == node_id(NodeKind::Endpoint, &ep),
    }
}
