//! Named targets and their shared asset graph. `docs/CONTRACTS-TRAFFIC-TARGETS.md` (part T) is normative.
//!
//! CONTRACT
//!
//! - [`Scope`] is implemented here and is final: entries are a host name (`acme.test`), a `*.` glob
//!   (`*.acme.test`: any name ending in `.acme.test`, not `acme.test` itself), an IPv4 or IPv6 address,
//!   or a CIDR (`10.20.0.0/24`). Matching is case-insensitive on names, ignores a trailing dot, and
//!   `exclude` always wins. [`Scope::parse`] refuses an entry that is none of these with a sentence.
//! - [`claim_hosts`] is implemented here and is final (F1): the hosts a claim names are those of its
//!   network assets, plus the host of every `http://` or `https://` URL in its text, plus, when a scope
//!   is given, every host name or IP in the text that the scope contains. Lower-cased, deduplicated,
//!   in first-seen order.
//! - [`TargetStore`], [`GraphLine`], [`NodeStatus`] and [`summary`] are signatures with `todo!()` bodies
//!   for the implementer of part T: `~/.loom/targets/{name}/target.toml` and the hash-chained
//!   `graph.jsonl`, node ids shared with the security state's asset ids, statuses as T6 says, and the
//!   summary text of T5.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// A target's scope: what is in, what is excluded (CONTRACTS-TRAFFIC-TARGETS T1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scope {
    include: Vec<Entry>,
    exclude: Vec<Entry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Entry {
    Host(String),
    /// `*.suffix`: the stored string is `.suffix`.
    Glob(String),
    Ip(IpAddr),
    Cidr(IpAddr, u8),
}

fn norm_host(h: &str) -> String {
    let h = h.trim().trim_end_matches('.').to_ascii_lowercase();
    // `[::1]` → `::1`
    h.strip_prefix('[').and_then(|x| x.strip_suffix(']')).map(str::to_string).unwrap_or(h)
}

fn parse_entry(raw: &str) -> Result<Entry, String> {
    let e = raw.trim();
    if e.is_empty() {
        return Err("An empty scope entry: give a host name, `*.domain`, an IP address or a CIDR.".into());
    }
    if let Some((addr, bits)) = e.split_once('/') {
        let ip: IpAddr = addr.parse().map_err(|_| format!("`{e}` is not a CIDR: `{addr}` is not an IP address."))?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        let bits: u8 = bits
            .parse()
            .ok()
            .filter(|b| *b <= max)
            .ok_or_else(|| format!("`{e}` is not a CIDR: the prefix length must be 0 to {max}."))?;
        return Ok(Entry::Cidr(ip, bits));
    }
    if let Ok(ip) = norm_host(e).parse::<IpAddr>() {
        return Ok(Entry::Ip(ip));
    }
    let lower = norm_host(e);
    if let Some(rest) = lower.strip_prefix("*.") {
        if valid_name(rest) {
            return Ok(Entry::Glob(format!(".{rest}")));
        }
        return Err(format!("`{e}` is not a scope entry: after `*.` give a domain name such as `acme.test`."));
    }
    if valid_name(&lower) {
        return Ok(Entry::Host(lower));
    }
    Err(format!(
        "`{e}` is not a scope entry: give a host name (`acme.test`), `*.acme.test`, an IP address or a CIDR (`10.0.0.0/24`), without a scheme, port or path."
    ))
}

fn valid_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 253
        && n.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                && !l.starts_with('-')
        })
}

fn in_cidr(ip: IpAddr, net: IpAddr, bits: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - u32::from(bits)) };
            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - u32::from(bits)) };
            u128::from(a) & mask == u128::from(n) & mask
        }
        _ => false,
    }
}

impl Entry {
    fn matches(&self, host: &str) -> bool {
        let h = norm_host(host);
        match self {
            Entry::Host(n) => h == *n,
            Entry::Glob(suffix) => h.len() > suffix.len() && h.ends_with(suffix.as_str()),
            Entry::Ip(ip) => h.parse::<IpAddr>().is_ok_and(|a| a == *ip),
            Entry::Cidr(net, bits) => h.parse::<IpAddr>().is_ok_and(|a| in_cidr(a, *net, *bits)),
        }
    }
}

impl Scope {
    /// Parses every entry; the first bad one is refused with a sentence that names it.
    pub fn parse(include: &[String], exclude: &[String]) -> Result<Scope, String> {
        Ok(Scope {
            include: include.iter().map(|e| parse_entry(e)).collect::<Result<_, _>>()?,
            exclude: exclude.iter().map(|e| parse_entry(e)).collect::<Result<_, _>>()?,
        })
    }

    /// The host (a name or an IP, without port) is in scope and not excluded.
    pub fn contains(&self, host: &str) -> bool {
        self.include.iter().any(|e| e.matches(host)) && !self.excluded(host)
    }

    /// The host matches an `exclude` entry.
    pub fn excluded(&self, host: &str) -> bool {
        self.exclude.iter().any(|e| e.matches(host))
    }

    pub fn is_empty(&self) -> bool {
        self.include.is_empty()
    }
}

/// The hosts a claim names (CONTRACTS-TRAFFIC-TARGETS F1). `asset_hosts` are the hosts of the claim's
/// `Host`, `Service` and `Endpoint` assets, already resolved by the caller.
pub fn claim_hosts(text: &str, asset_hosts: &[String], scope: Option<&Scope>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |h: String| {
        if !h.is_empty() && !out.contains(&h) {
            out.push(h);
        }
    };
    for h in asset_hosts {
        push(norm_host(h));
    }
    for (i, _) in text.match_indices("://") {
        let scheme_start = text[..i].rfind(|c: char| !c.is_ascii_alphabetic()).map_or(0, |p| p + 1);
        let scheme = text[scheme_start..i].to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            continue;
        }
        let rest = &text[i + 3..];
        let end = rest
            .find(|c: char| {
                c == '/' || c == '?' || c == '#' || c.is_whitespace() || matches!(c, '"' | '\'' | '`' | ')' | '>' | ',')
            })
            .unwrap_or(rest.len());
        let authority = &rest[..end];
        let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
        let host = if let Some(v6) = hostport.strip_prefix('[') {
            v6.split_once(']').map_or(v6, |(h, _)| h).to_string()
        } else {
            hostport.split_once(':').map_or(hostport, |(h, _)| h).to_string()
        };
        push(norm_host(&host));
    }
    if let Some(scope) = scope {
        for word in text.split(|c: char| {
            c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '(' | ')' | '<' | '>' | ',' | ';' | '/')
        }) {
            let w = word.trim_end_matches(['.', ':']);
            let w = w
                .split_once(':')
                .filter(|(h, p)| !h.contains(':') && p.chars().all(|c| c.is_ascii_digit()))
                .map_or(w, |(h, _)| h);
            let w = norm_host(w);
            if w.is_empty() || !(w.parse::<IpAddr>().is_ok() || (w.contains('.') && valid_name(&w))) {
                continue;
            }
            if scope.contains(&w) {
                push(w);
            }
        }
    }
    out
}

/// A target's settings file (T1).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TargetCfg {
    pub scope: Vec<String>,
    pub exclude: Vec<String>,
    pub upstream_insecure: Vec<String>,
    pub intercept_passthrough: Vec<String>,
    pub notes: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Domain,
    Host,
    Ip,
    Service,
    Endpoint,
}

/// T6.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeStatus {
    Finding,
    Tested,
    Deferred,
    Untested,
    /// A scope entry with no node seen yet.
    NotSeen,
}

/// One line of `graph.jsonl` (T3, T4). `prev` chains the lines as `net.jsonl` does.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum GraphLine {
    NodeSeen {
        id: String,
        kind: NodeKind,
        locator: String,
        mission: String,
        session: String,
        ts_ms: u64,
        evidence: Vec<String>,
        prev: String,
    },
    Edge {
        kind: String,
        from: String,
        to: String,
        mission: String,
        session: String,
        ts_ms: u64,
        prev: String,
    },
    Coverage {
        node: String,
        status: String,
        reason: Option<String>,
        evidence: Vec<String>,
        mission: String,
        session: String,
        ts_ms: u64,
        prev: String,
    },
    Finding {
        nodes: Vec<String>,
        claim: String,
        text: String,
        status: String,
        evidence: Vec<String>,
        mission: String,
        session: String,
        ts_ms: u64,
        prev: String,
    },
}

/// A node as the API and the UI see it (T7).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NodeView {
    pub id: String,
    pub kind: NodeKind,
    pub locator: String,
    pub status: NodeStatus,
    pub parent: Option<String>,
    /// Missions that saw it, tested it, deferred it or recorded a finding on it.
    pub missions: Vec<String>,
    pub evidence: Vec<String>,
    pub findings: Vec<FindingView>,
}

/// An edge as the API serves it (T7).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeView {
    pub kind: String,
    pub from: String,
    pub to: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FindingView {
    pub claim: String,
    pub text: String,
    pub status: String,
    pub mission: String,
    pub evidence: Vec<String>,
}

/// A target name: `[a-z0-9][a-z0-9_-]{0,63}` (T1).
pub fn valid_target_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

fn check_name(name: &str) -> Result<(), String> {
    if valid_target_name(name) {
        Ok(())
    } else {
        Err(format!(
            "`{name}` is not a target name: use 1 to 64 characters from a-z, 0-9, `-` and `_`, starting with a letter or digit."
        ))
    }
}

/// The id of a node: the security state's asset id for the same kind and locator, so a mission's asset
/// and the target's node share it (T3). `Ip` nodes share the id of a `Host` asset with that locator.
pub fn node_id(kind: NodeKind, locator: &str) -> String {
    let k = match kind {
        NodeKind::Domain => "Domain",
        NodeKind::Host | NodeKind::Ip => "Host",
        NodeKind::Service => "Service",
        NodeKind::Endpoint => "Endpoint",
    };
    crate::security_state::stable_id("as", &[k, locator])
}

/// The host (a name or an IP, no port) a node locator is about.
pub fn locator_host(kind: NodeKind, locator: &str) -> String {
    let rest = match kind {
        NodeKind::Domain | NodeKind::Host | NodeKind::Ip => locator,
        NodeKind::Service | NodeKind::Endpoint => {
            let l = locator.split_once(' ').map_or(locator, |(_, u)| u);
            let l = l.split_once("://").map_or(l, |(_, r)| r);
            l.split(['/', '?', '#']).next().unwrap_or(l)
        }
    };
    let rest = rest.rsplit_once('@').map_or(rest, |(_, h)| h);
    let host = if let Some(v6) = rest.strip_prefix('[') {
        v6.split_once(']').map_or(v6, |(h, _)| h)
    } else if rest.parse::<IpAddr>().is_ok() {
        rest
    } else if matches!(kind, NodeKind::Service | NodeKind::Endpoint) {
        rest.rsplit_once(':').map_or(rest, |(h, _)| h)
    } else {
        rest
    };
    norm_host(host)
}

/// The registrable domain of a host name: the last two labels, or three under a short second-level
/// suffix such as `co.uk`. `None` for an IP or a single label.
pub fn registrable_domain(host: &str) -> Option<String> {
    let h = norm_host(host);
    if h.parse::<IpAddr>().is_ok() {
        return None;
    }
    let labels: Vec<&str> = h.split('.').collect();
    let n = labels.len();
    if n < 2 {
        return None;
    }
    let second = ["co", "com", "org", "net", "gov", "ac", "edu"];
    let take = if n >= 3 && labels[n - 1].len() == 2 && second.contains(&labels[n - 2]) { 3 } else { 2 };
    Some(labels[n - take..].join("."))
}

/// A path with numeric and UUID-like segments replaced by `{id}` (T4); the query is dropped.
pub fn path_template(path: &str) -> String {
    let path = path.split(['?', '#']).next().unwrap_or("");
    let path = if path.is_empty() { "/" } else { path };
    path.split('/')
        .map(|seg| {
            let numeric = !seg.is_empty() && seg.chars().all(|c| c.is_ascii_digit());
            let uuid_like =
                seg.len() >= 8 && seg.contains('-') && seg.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
            let long_hex = seg.len() >= 24 && seg.chars().all(|c| c.is_ascii_hexdigit());
            if numeric || uuid_like || long_hex {
                "{id}"
            } else {
                seg
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

impl GraphLine {
    fn set_prev(&mut self, p: &str) {
        match self {
            GraphLine::NodeSeen { prev, .. }
            | GraphLine::Edge { prev, .. }
            | GraphLine::Coverage { prev, .. }
            | GraphLine::Finding { prev, .. } => *prev = p.to_string(),
        }
    }
    fn prev(&self) -> &str {
        match self {
            GraphLine::NodeSeen { prev, .. }
            | GraphLine::Edge { prev, .. }
            | GraphLine::Coverage { prev, .. }
            | GraphLine::Finding { prev, .. } => prev,
        }
    }
}

/// The targets under `~/.loom/targets`.
pub struct TargetStore {
    pub root: std::path::PathBuf,
}

/// Reads the valid prefix of a graph file: lines that parse and whose `prev` chains.
fn read_graph(path: &std::path::Path) -> Result<(Vec<GraphLine>, String), String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok((Vec::new(), crate::log::ZERO_HASH.to_string()));
        }
        Err(e) => return Err(format!("The graph {} could not be read: {e}.", path.display())),
    };
    let mut out = Vec::new();
    let mut last = crate::log::ZERO_HASH.to_string();
    for line in text.split_inclusive('\n') {
        let Some(body) = line.strip_suffix('\n') else { break };
        let Ok(g) = serde_json::from_str::<GraphLine>(body) else { break };
        if g.prev() != last {
            break;
        }
        last = crate::sha256_hex(body.as_bytes());
        out.push(g);
    }
    Ok((out, last))
}

impl TargetStore {
    pub fn new(root: std::path::PathBuf) -> TargetStore {
        TargetStore { root }
    }

    fn dir(&self, name: &str) -> Result<std::path::PathBuf, String> {
        check_name(name)?;
        Ok(self.root.join(name))
    }

    pub fn exists(&self, name: &str) -> bool {
        self.dir(name).is_ok_and(|d| d.join("target.toml").is_file())
    }

    pub fn graph_path(&self, name: &str) -> Result<std::path::PathBuf, String> {
        Ok(self.dir(name)?.join("graph.jsonl"))
    }

    pub fn list(&self) -> Result<Vec<(String, TargetCfg)>, String> {
        let rd = match std::fs::read_dir(&self.root) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(format!("The targets directory {} could not be read: {e}.", self.root.display())),
        };
        let mut names: Vec<String> = rd
            .filter_map(|e| e.ok())
            .filter(|e| e.path().join("target.toml").is_file())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| valid_target_name(n))
            .collect();
        names.sort();
        names.into_iter().map(|n| self.get(&n).map(|c| (n, c))).collect()
    }

    pub fn get(&self, name: &str) -> Result<TargetCfg, String> {
        let path = self.dir(name)?.join("target.toml");
        let text = std::fs::read_to_string(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                format!("There is no target `{name}`; create it with `loom target add {name} --scope <host>`.")
            } else {
                format!("The target `{name}` could not be read: {e}.")
            }
        })?;
        toml::from_str(&text).map_err(|e| format!("The settings of target `{name}` are not valid: {}.", e.message()))
    }

    /// The parsed scope of a target.
    pub fn scope(&self, name: &str) -> Result<Scope, String> {
        let c = self.get(name)?;
        Scope::parse(&c.scope, &c.exclude)
    }

    /// Creates or replaces the settings; the scope is checked with [`Scope::parse`] first.
    pub fn put(&self, name: &str, cfg: &TargetCfg) -> Result<(), String> {
        let dir = self.dir(name)?;
        Scope::parse(&cfg.scope, &cfg.exclude)?;
        for e in cfg.upstream_insecure.iter().chain(&cfg.intercept_passthrough) {
            parse_entry(e).map_err(|m| format!("{m} (in upstream_insecure or intercept_passthrough)"))?;
        }
        let fail = |e: std::io::Error| format!("The target settings could not be written: {e}.");
        std::fs::create_dir_all(&dir).map_err(fail)?;
        let text =
            toml::to_string_pretty(cfg).map_err(|e| format!("The target settings could not be written: {e}."))?;
        let tmp = dir.join("target.toml.tmp");
        std::fs::write(&tmp, text).map_err(fail)?;
        std::fs::rename(&tmp, dir.join("target.toml")).map_err(fail)
    }

    /// Appends lines to `graph.jsonl`, chaining `prev`; lines about out-of-scope locators are dropped (T4).
    /// Edges, coverage and findings are kept only when the nodes they name are in the graph.
    pub fn append(&self, name: &str, lines: Vec<GraphLine>) -> Result<(), String> {
        use std::io::Write;
        let dir = self.dir(name)?;
        let scope = self.scope(name)?;
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("graph.lock"))
            .map_err(|e| format!("The graph of target `{name}` could not be locked: {e}."))?;
        fs2::FileExt::lock_exclusive(&lock)
            .map_err(|e| format!("The graph of target `{name}` could not be locked: {e}."))?;
        let path = dir.join("graph.jsonl");
        let (existing, mut last) = read_graph(&path)?;
        let mut known: std::collections::HashSet<String> = existing
            .iter()
            .filter_map(|g| match g {
                GraphLine::NodeSeen { id, .. } => Some(id.clone()),
                _ => None,
            })
            .collect();
        for g in &lines {
            if let GraphLine::NodeSeen { id, kind, locator, .. } = g {
                if *kind != NodeKind::Domain && scope.contains(&locator_host(*kind, locator)) {
                    known.insert(id.clone());
                }
            }
        }
        // A domain is admitted when an in-scope node names it as its parent.
        let parents: Vec<String> = lines
            .iter()
            .filter_map(|g| match g {
                GraphLine::Edge { kind, from, to, .. } if kind == "parent" && known.contains(from) => Some(to.clone()),
                _ => None,
            })
            .collect();
        known.extend(parents);
        let keep: Vec<GraphLine> = lines
            .into_iter()
            .filter(|g| match g {
                GraphLine::NodeSeen { id, .. } => known.contains(id),
                GraphLine::Edge { from, to, .. } => known.contains(from) && known.contains(to),
                GraphLine::Coverage { node, .. } => known.contains(node),
                GraphLine::Finding { nodes, .. } => nodes.iter().any(|n| known.contains(n)),
            })
            .map(|g| match g {
                GraphLine::Finding { nodes, claim, text, status, evidence, mission, session, ts_ms, prev } => {
                    let nodes = nodes.into_iter().filter(|n| known.contains(n)).collect();
                    GraphLine::Finding { nodes, claim, text, status, evidence, mission, session, ts_ms, prev }
                }
                g => g,
            })
            .collect();
        if keep.is_empty() {
            return Ok(());
        }
        let mut buf = String::new();
        for mut g in keep {
            g.set_prev(&last);
            let body = serde_json::to_string(&g).map_err(|e| format!("A graph line could not be written: {e}."))?;
            last = crate::sha256_hex(body.as_bytes());
            buf.push_str(&body);
            buf.push('\n');
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| format!("The graph of target `{name}` could not be opened: {e}."))?;
        f.write_all(buf.as_bytes())
            .and_then(|_| f.sync_data())
            .map_err(|e| format!("The graph of target `{name}` could not be written: {e}."))
    }

    /// Whether `graph.jsonl` is an unbroken chain (every line parses and chains).
    pub fn verify(&self, name: &str) -> Result<bool, String> {
        let path = self.graph_path(name)?;
        let n = std::fs::read_to_string(&path).map(|t| t.lines().count()).unwrap_or(0);
        Ok(read_graph(&path)?.0.len() == n)
    }

    /// The edges of the graph, each once, in the order first written.
    pub fn edges(&self, name: &str) -> Result<Vec<EdgeView>, String> {
        let (lines, _) = read_graph(&self.graph_path(name)?)?;
        let mut out: Vec<EdgeView> = Vec::new();
        for g in lines {
            if let GraphLine::Edge { kind, from, to, .. } = g {
                let e = EdgeView { kind, from, to };
                if !out.contains(&e) {
                    out.push(e);
                }
            }
        }
        Ok(out)
    }

    /// Every node with its status (T6), plus `NotSeen` entries for scope entries with no node.
    /// Most recently seen first, ties by locator; `NotSeen` entries come last.
    pub fn nodes(&self, name: &str) -> Result<Vec<NodeView>, String> {
        use std::collections::{BTreeMap, BTreeSet};
        let cfg = self.get(name)?;
        let (lines, _) = read_graph(&self.graph_path(name)?)?;
        #[derive(Default)]
        struct Acc {
            kind: Option<NodeKind>,
            locator: String,
            last_seen: u64,
            parent: Option<String>,
            missions: BTreeSet<String>,
            evidence: BTreeSet<String>,
            cover: BTreeMap<String, String>,
            findings: BTreeMap<(String, String), FindingView>,
        }
        let mut acc: BTreeMap<String, Acc> = BTreeMap::new();
        for g in &lines {
            match g {
                GraphLine::NodeSeen { id, kind, locator, mission, ts_ms, evidence, .. } => {
                    let a = acc.entry(id.clone()).or_default();
                    a.kind = Some(*kind);
                    a.locator = locator.clone();
                    a.last_seen = a.last_seen.max(*ts_ms);
                    a.missions.insert(mission.clone());
                    a.evidence.extend(evidence.iter().cloned());
                }
                GraphLine::Edge { kind, from, to, .. } => {
                    if kind == "parent" {
                        acc.entry(from.clone()).or_default().parent = Some(to.clone());
                    }
                }
                GraphLine::Coverage { node, status, evidence, mission, .. } => {
                    let a = acc.entry(node.clone()).or_default();
                    a.missions.insert(mission.clone());
                    a.evidence.extend(evidence.iter().cloned());
                    a.cover.insert(mission.clone(), status.clone());
                }
                GraphLine::Finding { nodes, claim, text, status, evidence, mission, .. } => {
                    for n in nodes {
                        let a = acc.entry(n.clone()).or_default();
                        a.missions.insert(mission.clone());
                        a.evidence.extend(evidence.iter().cloned());
                        a.findings.insert(
                            (mission.clone(), claim.clone()),
                            FindingView {
                                claim: claim.clone(),
                                text: text.clone(),
                                status: status.clone(),
                                mission: mission.clone(),
                                evidence: evidence.clone(),
                            },
                        );
                    }
                }
            }
        }
        let mut out: Vec<(u64, NodeView)> = acc
            .into_iter()
            .filter_map(|(id, a)| {
                let kind = a.kind?;
                let findings: Vec<FindingView> = a.findings.into_values().collect();
                let open = findings.iter().any(|f| !matches!(f.status.as_str(), "withdrawn" | "refuted"));
                let status = if open {
                    NodeStatus::Finding
                } else if a.cover.values().any(|s| s == "tested") {
                    NodeStatus::Tested
                } else if a.cover.values().any(|s| s == "deferred") {
                    NodeStatus::Deferred
                } else {
                    NodeStatus::Untested
                };
                Some((
                    a.last_seen,
                    NodeView {
                        id,
                        kind,
                        locator: a.locator,
                        status,
                        parent: a.parent,
                        missions: a.missions.into_iter().collect(),
                        evidence: a.evidence.into_iter().collect(),
                        findings,
                    },
                ))
            })
            .collect();
        out.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.locator.cmp(&b.1.locator)).then_with(|| a.1.id.cmp(&b.1.id)));
        let mut nodes: Vec<NodeView> = out.into_iter().map(|(_, n)| n).collect();
        for entry in &cfg.scope {
            let Ok(one) = Scope::parse(std::slice::from_ref(entry), &[]) else { continue };
            if !nodes.iter().any(|n| one.contains(&locator_host(n.kind, &n.locator))) {
                nodes.push(NodeView {
                    id: crate::security_state::stable_id("as", &["Scope", entry]),
                    kind: NodeKind::Host,
                    locator: entry.clone(),
                    status: NodeStatus::NotSeen,
                    parent: None,
                    missions: Vec::new(),
                    evidence: Vec::new(),
                    findings: Vec::new(),
                });
            }
        }
        Ok(nodes)
    }
}

pub const SUMMARY_MAX_BYTES: usize = 8 * 1024;
const SUMMARY_UNTESTED: usize = 40;
const SUMMARY_FINDINGS: usize = 20;

fn kind_word(k: NodeKind) -> &'static str {
    match k {
        NodeKind::Domain => "domain",
        NodeKind::Host => "host",
        NodeKind::Ip => "ip",
        NodeKind::Service => "service",
        NodeKind::Endpoint => "endpoint",
    }
}

/// The text that goes under "# Target {name}" in a lead's system prompt (T5), at most 8 KiB.
/// Deterministic for a graph: `nodes` is taken in the order [`TargetStore::nodes`] returns.
pub fn summary(_name: &str, cfg: &TargetCfg, nodes: &[NodeView]) -> String {
    let mut s = String::new();
    let scope = if cfg.scope.is_empty() { "(none)".to_string() } else { cfg.scope.join(", ") };
    s.push_str(&format!("Scope: {scope}\n"));
    if !cfg.exclude.is_empty() {
        s.push_str(&format!("Excluded: {}\n", cfg.exclude.join(", ")));
    }
    let seen: Vec<&NodeView> = nodes.iter().filter(|n| n.status != NodeStatus::NotSeen).collect();
    let mut counts: Vec<String> = Vec::new();
    for k in [NodeKind::Domain, NodeKind::Host, NodeKind::Ip, NodeKind::Service, NodeKind::Endpoint] {
        let n = seen.iter().filter(|x| x.kind == k).count();
        if n > 0 {
            counts.push(format!("{n} {}{}", kind_word(k), if n == 1 { "" } else { "s" }));
        }
    }
    let known = if counts.is_empty() { "nothing seen yet".to_string() } else { counts.join(", ") };
    s.push_str(&format!("Known: {known}\n"));
    let unseen: Vec<&str> =
        nodes.iter().filter(|n| n.status == NodeStatus::NotSeen).take(20).map(|n| n.locator.as_str()).collect();
    if !unseen.is_empty() {
        s.push_str(&format!("In scope, not seen yet: {}\n", unseen.join(", ")));
    }
    let untested: Vec<&&NodeView> = seen
        .iter()
        .filter(|n| matches!(n.kind, NodeKind::Service | NodeKind::Endpoint) && n.status == NodeStatus::Untested)
        .collect();
    if !untested.is_empty() {
        s.push_str(&format!(
            "Untested services and endpoints ({} of {}, most recently seen first):\n",
            untested.len().min(SUMMARY_UNTESTED),
            untested.len()
        ));
        for n in untested.iter().take(SUMMARY_UNTESTED) {
            s.push_str(&format!("- {} {}\n", kind_word(n.kind), n.locator));
        }
    }
    let mut findings: Vec<String> = Vec::new();
    for n in &seen {
        for f in &n.findings {
            if !matches!(f.status.as_str(), "withdrawn" | "refuted") {
                let text: String = f.text.split_whitespace().collect::<Vec<_>>().join(" ");
                let text: String = text.chars().take(300).collect();
                findings.push(format!("- {} · {} · mission {}\n", n.locator, text, f.mission));
            }
        }
    }
    if !findings.is_empty() {
        s.push_str(&format!("Findings ({} of {}):\n", findings.len().min(SUMMARY_FINDINGS), findings.len()));
        for f in findings.iter().take(SUMMARY_FINDINGS) {
            s.push_str(f);
        }
    }
    let pointer = "Read the rest with security_query, view \"target\" (filters: kind, status, under, max).\n";
    if s.len() + pointer.len() > SUMMARY_MAX_BYTES {
        let mut cut = SUMMARY_MAX_BYTES - pointer.len() - 5;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
        s.push_str("\n...\n");
    }
    s.push_str(pointer);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(inc: &[&str], exc: &[&str]) -> Scope {
        Scope::parse(
            &inc.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            &exc.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
        .unwrap()
    }

    #[test]
    fn scope_matches_names_globs_ips_and_cidrs_and_exclude_wins() {
        let s = scope(
            &["acme.test", "*.acme.test", "10.20.0.0/24", "192.0.2.7", "2001:db8::/32"],
            &["admin.acme.test", "10.20.0.9"],
        );
        assert!(
            s.contains("acme.test")
                && s.contains("ACME.test.")
                && s.contains("api.acme.test")
                && s.contains("a.b.acme.test")
        );
        assert!(!s.contains("evilacme.test") && !s.contains("acme.test.evil"));
        assert!(
            s.contains("10.20.0.5")
                && !s.contains("10.20.1.5")
                && s.contains("192.0.2.7")
                && s.contains("[2001:db8::1]")
        );
        assert!(!s.contains("admin.acme.test") && !s.contains("10.20.0.9"));
        assert!(s.excluded("admin.acme.test"));
        let glob_only = scope(&["*.acme.test"], &[]);
        assert!(!glob_only.contains("acme.test"), "a glob does not include the bare domain");
    }

    #[test]
    fn a_bad_scope_entry_is_refused_by_name() {
        for bad in ["https://acme.test", "acme.test:443", "10.0.0.0/33", "*.", "", "a b"] {
            let e = Scope::parse(&[bad.to_string()], &[]).unwrap_err();
            assert!(e.contains("scope entry") || e.contains("CIDR"), "{bad}: {e}");
        }
    }

    #[test]
    fn claim_hosts_take_assets_urls_and_in_scope_names() {
        let s = scope(&["*.acme.test", "10.20.0.0/24"], &[]);
        let text = "The login at https://User@Login.acme.test:8443/auth?x=1 leaks; api.acme.test and 10.20.0.4:22 too, not example.com or http://other.test/x.";
        assert_eq!(
            claim_hosts(text, &["db.acme.test".into()], Some(&s)),
            vec!["db.acme.test", "login.acme.test", "other.test", "api.acme.test", "10.20.0.4"]
        );
        assert_eq!(
            claim_hosts(text, &[], None),
            vec!["login.acme.test", "other.test"],
            "without a scope only URLs count"
        );
        assert_eq!(claim_hosts("see http://[::1]:8080/x", &[], None), vec!["::1"]);
        assert!(claim_hosts("ftp://files.acme.test/x and no hosts", &[], None).is_empty());
    }

    fn store(dir: &tempfile::TempDir) -> TargetStore {
        let s = TargetStore::new(dir.path().join("targets"));
        let cfg = TargetCfg {
            scope: vec!["*.acme.test".into(), "acme.test".into(), "10.20.0.0/24".into()],
            exclude: vec!["vpn.acme.test".into()],
            ..Default::default()
        };
        s.put("acme", &cfg).unwrap();
        s
    }

    fn seen(kind: NodeKind, locator: &str, mission: &str, ts: u64) -> GraphLine {
        GraphLine::NodeSeen {
            id: node_id(kind, locator),
            kind,
            locator: locator.into(),
            mission: mission.into(),
            session: format!("s-{mission}"),
            ts_ms: ts,
            evidence: vec![],
            prev: String::new(),
        }
    }

    fn cover(node: &str, status: &str, mission: &str) -> GraphLine {
        GraphLine::Coverage {
            node: node.into(),
            status: status.into(),
            reason: (status == "deferred").then(|| "later".to_string()),
            evidence: vec!["ev1".into()],
            mission: mission.into(),
            session: format!("s-{mission}"),
            ts_ms: 9,
            prev: String::new(),
        }
    }

    #[test]
    fn the_store_round_trips_a_target_and_refuses_bad_names_and_scopes() {
        let d = tempfile::tempdir().unwrap();
        let s = store(&d);
        assert_eq!(s.list().unwrap().len(), 1);
        assert_eq!(s.get("acme").unwrap().exclude, vec!["vpn.acme.test"]);
        assert!(s.get("nope").unwrap_err().contains("no target"));
        assert!(s.put("Bad Name", &TargetCfg::default()).unwrap_err().contains("not a target name"));
        let bad = TargetCfg { scope: vec!["http://x.test/".into()], ..Default::default() };
        assert!(s.put("b", &bad).is_err());
        assert!(s.get("../etc").is_err());
    }

    #[test]
    fn graph_lines_are_hash_chained_and_out_of_scope_nodes_are_never_written() {
        let d = tempfile::tempdir().unwrap();
        let s = store(&d);
        s.append(
            "acme",
            vec![
                seen(NodeKind::Host, "www.acme.test", "m-1", 1),
                seen(NodeKind::Host, "evil.example", "m-1", 2),
                seen(NodeKind::Host, "vpn.acme.test", "m-1", 3),
                seen(NodeKind::Ip, "10.20.0.5", "m-1", 4),
                seen(NodeKind::Ip, "10.30.0.5", "m-1", 5),
            ],
        )
        .unwrap();
        s.append("acme", vec![cover(&node_id(NodeKind::Host, "www.acme.test"), "tested", "m-2")]).unwrap();
        assert!(s.verify("acme").unwrap());
        let text = std::fs::read_to_string(s.graph_path("acme").unwrap()).unwrap();
        assert!(!text.contains("evil.example") && !text.contains("vpn.acme.test") && !text.contains("10.30.0.5"));
        let locs: Vec<String> = s
            .nodes("acme")
            .unwrap()
            .into_iter()
            .filter(|n| n.status != NodeStatus::NotSeen)
            .map(|n| n.locator)
            .collect();
        assert!(locs.contains(&"www.acme.test".to_string()) && locs.contains(&"10.20.0.5".to_string()));
        assert_eq!(locs.len(), 2, "{locs:?}");
        // A changed line breaks the chain.
        let tampered = text.replacen("www.acme.test", "wwx.acme.test", 1);
        std::fs::write(s.graph_path("acme").unwrap(), tampered).unwrap();
        assert!(!s.verify("acme").unwrap());
    }

    #[test]
    fn node_status_follows_findings_then_tests_then_deferrals_and_keeps_the_missions() {
        let d = tempfile::tempdir().unwrap();
        let s = store(&d);
        let h = |n: &str| node_id(NodeKind::Host, n);
        s.append(
            "acme",
            vec![
                seen(NodeKind::Host, "a.acme.test", "m-1", 1),
                seen(NodeKind::Host, "b.acme.test", "m-1", 2),
                seen(NodeKind::Host, "c.acme.test", "m-1", 3),
                seen(NodeKind::Host, "d.acme.test", "m-1", 4),
                cover(&h("a.acme.test"), "tested", "m-1"),
                cover(&h("b.acme.test"), "deferred", "m-2"),
                cover(&h("c.acme.test"), "tested", "m-1"),
                GraphLine::Finding {
                    nodes: vec![h("c.acme.test")],
                    claim: "c1".into(),
                    text: "c.acme.test leaks".into(),
                    status: "open".into(),
                    evidence: vec![],
                    mission: "m-2".into(),
                    session: "s-m-2".into(),
                    ts_ms: 10,
                    prev: String::new(),
                },
            ],
        )
        .unwrap();
        let by = |nodes: &[NodeView], l: &str| nodes.iter().find(|n| n.locator == l).unwrap().clone();
        let nodes = s.nodes("acme").unwrap();
        assert_eq!(by(&nodes, "a.acme.test").status, NodeStatus::Tested);
        assert_eq!(by(&nodes, "b.acme.test").status, NodeStatus::Deferred);
        assert_eq!(by(&nodes, "b.acme.test").missions, vec!["m-1", "m-2"], "who saw it and who deferred it");
        assert_eq!(by(&nodes, "c.acme.test").status, NodeStatus::Finding);
        assert_eq!(by(&nodes, "c.acme.test").findings.len(), 1);
        assert_eq!(by(&nodes, "d.acme.test").status, NodeStatus::Untested);
        assert!(nodes.iter().any(|n| n.status == NodeStatus::NotSeen && n.locator == "10.20.0.0/24"));
        // Withdrawn: the finding no longer counts.
        s.append(
            "acme",
            vec![GraphLine::Finding {
                nodes: vec![h("c.acme.test")],
                claim: "c1".into(),
                text: "c.acme.test leaks".into(),
                status: "withdrawn".into(),
                evidence: vec![],
                mission: "m-2".into(),
                session: "s-m-2".into(),
                ts_ms: 11,
                prev: String::new(),
            }],
        )
        .unwrap();
        assert_eq!(by(&s.nodes("acme").unwrap(), "c.acme.test").status, NodeStatus::Tested);
    }

    #[test]
    fn the_summary_is_deterministic_and_cut_at_8_kib_with_the_pointer() {
        let d = tempfile::tempdir().unwrap();
        let s = store(&d);
        let lines: Vec<GraphLine> =
            (0..300).map(|i| seen(NodeKind::Service, &format!("h{i}.acme.test:{}/tcp", 1000 + i), "m-1", i)).collect();
        s.append("acme", lines).unwrap();
        let cfg = s.get("acme").unwrap();
        let a = summary("acme", &cfg, &s.nodes("acme").unwrap());
        let b = summary("acme", &cfg, &s.nodes("acme").unwrap());
        assert_eq!(a, b);
        assert!(a.len() <= SUMMARY_MAX_BYTES, "{}", a.len());
        assert!(a.contains("security_query"));
        assert!(a.contains("h299.acme.test:1299/tcp"), "most recently seen first");
        assert!(!a.contains("h0.acme.test:1000/tcp"), "at most 40 untested");
    }

    #[test]
    fn exchange_paths_become_templates() {
        assert_eq!(path_template("/users/42/files/3f2b8c1e-aaaa-bbbb-cccc-1234567890ab?x=1"), "/users/{id}/files/{id}");
        assert_eq!(path_template("/api/login"), "/api/login");
    }
}
