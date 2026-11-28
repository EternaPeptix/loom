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
//! - [`TargetStore`], [`GraphLine`], [`NodeStatus`] and [`summary`] (part T):
//!   `~/.ferret/targets/{name}/target.toml` and the hash-chained `graph.jsonl`, node ids shared with the
//!   security state's asset ids, statuses as T6 says, and the summary text of T5. Credential profiles
//!   live beside them under `creds/` (`crate::creds`, part S).

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
    fn canonical_key(&self) -> String {
        match self {
            Entry::Host(n) => n.clone(),
            Entry::Glob(suffix) => format!("*{suffix}"),
            Entry::Ip(ip) => ip.to_string(),
            Entry::Cidr(ip, bits) => format!("{ip}/{bits}"),
        }
    }

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
    /// Host → IP resolution edge observed for an in-scope host or IP.
    Resolves {
        host: String,
        ip: String,
        mission: String,
        at_ms: u64,
        #[serde(default)]
        prev: String,
    },
    /// Structured security finding indexed on a 3-axis `(vuln_class, surface, param_or_sink)` key
    /// for cross-mission deduplication and target summary highlights.
    SecurityFinding {
        id: String,
        mission: String,
        title: String,
        vuln_class: String,
        surface: String,
        param_or_sink: String,
        severity: String,
        confidence: String,
        at_ms: u64,
        #[serde(default)]
        prev: String,
    },
    /// Recorded risk-area disposition (`ruled_out` / `needs_follow_up`) on a target surface.
    Disposition {
        mission: String,
        surface: String,
        risk_area: String,
        disposition: String,
        note: String,
        at_ms: u64,
        #[serde(default)]
        prev: String,
    },
    /// Recorded dead-end exploration note on a target surface so later missions avoid repeating it.
    DeadEnd {
        mission: String,
        surface: String,
        summary: String,
        at_ms: u64,
        #[serde(default)]
        prev: String,
    },
    /// Passive security signal captured on an in-scope HTTP exchange.
    Passive {
        mission: String,
        exchange_id: String,
        host: String,
        path: String,
        signal: crate::event::PassiveSignal,
        at_ms: u64,
        #[serde(default)]
        prev: String,
    },
}

/// A persisted structured finding from a target's graph, used for cross-mission deduplication.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetFinding {
    pub id: String,
    pub mission: String,
    pub title: String,
    pub vuln_class: String,
    pub surface: String,
    pub param_or_sink: String,
    pub severity: String,
    pub confidence: String,
    pub at_ms: u64,
}

/// A persisted host → IP resolution record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetResolves {
    pub host: String,
    pub ip: String,
    pub mission: String,
    pub at_ms: u64,
}

/// A persisted risk-area disposition (`ruled_out` / `needs_follow_up`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetDisposition {
    pub mission: String,
    pub surface: String,
    pub risk_area: String,
    pub disposition: String,
    pub note: String,
    pub at_ms: u64,
}

/// A persisted dead-end exploration record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetDeadEnd {
    pub mission: String,
    pub surface: String,
    pub summary: String,
    pub at_ms: u64,
}

/// A persisted passive security signal from a captured exchange.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetPassive {
    pub mission: String,
    pub exchange_id: String,
    pub host: String,
    pub path: String,
    pub signal: crate::event::PassiveSignal,
    pub at_ms: u64,
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
            | GraphLine::Finding { prev, .. }
            | GraphLine::Resolves { prev, .. }
            | GraphLine::SecurityFinding { prev, .. }
            | GraphLine::Disposition { prev, .. }
            | GraphLine::DeadEnd { prev, .. }
            | GraphLine::Passive { prev, .. } => *prev = p.to_string(),
        }
    }
    fn prev(&self) -> &str {
        match self {
            GraphLine::NodeSeen { prev, .. }
            | GraphLine::Edge { prev, .. }
            | GraphLine::Coverage { prev, .. }
            | GraphLine::Finding { prev, .. }
            | GraphLine::Resolves { prev, .. }
            | GraphLine::SecurityFinding { prev, .. }
            | GraphLine::Disposition { prev, .. }
            | GraphLine::DeadEnd { prev, .. }
            | GraphLine::Passive { prev, .. } => prev,
        }
    }
}

fn surface_in_scope(surface: &str, scope: &Scope) -> bool {
    let trimmed = surface.trim();
    if trimmed.is_empty() {
        return false;
    }
    let without_method = match trimmed.split_once(char::is_whitespace) {
        Some((first, rest))
            if matches!(
                first.to_ascii_uppercase().as_str(),
                "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" | "TRACE"
            ) =>
        {
            rest.trim()
        }
        _ => trimmed,
    };
    if let Ok(u) = url::Url::parse(without_method) {
        if matches!(u.scheme(), "http" | "https" | "ws" | "wss") {
            return u.host_str().is_some_and(|h| scope.contains(&norm_host(h)));
        }
    }
    if without_method.starts_with('/') {
        return true;
    }
    let lead = without_method.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = lead.rsplit_once('@').map_or(lead, |(_, h)| h);
    let candidate = if let Some(v6) = hostport.strip_prefix('[') {
        v6.split_once(']').map_or(v6, |(h, _)| h)
    } else if hostport.parse::<IpAddr>().is_ok() {
        hostport
    } else {
        hostport.split_once(':').map_or(hostport, |(h, _)| h)
    };
    let cand_norm = norm_host(candidate);
    if !cand_norm.is_empty() && scope.excluded(&cand_norm) {
        return false;
    }
    if cand_norm.parse::<IpAddr>().is_ok() {
        return scope.contains(&cand_norm);
    }
    true
}

fn normalize_vuln_class(raw: &str) -> String {
    let lower = raw.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return String::new();
    }
    if let Some(rest) = lower.strip_prefix("cwe") {
        let rest = rest.trim_start_matches(['-', '_', ':', ' ']);
        if !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()) {
            let digits = rest.trim_start_matches('0');
            let digits = if digits.is_empty() { "0" } else { digits };
            return format!("cwe-{digits}");
        }
    }
    let mut out = String::with_capacity(lower.len());
    let mut prev_sep = false;
    for ch in lower.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            prev_sep = false;
        } else if !prev_sep && !out.is_empty() {
            out.push('_');
            prev_sep = true;
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    out
}

fn normalize_path_part(path: &str) -> String {
    let lower = path.to_ascii_lowercase();
    let templated = path_template(&lower);
    let mut collapsed = String::with_capacity(templated.len());
    let mut prev_slash = false;
    for ch in templated.chars() {
        if ch == '/' {
            if !prev_slash {
                collapsed.push('/');
                prev_slash = true;
            }
        } else {
            collapsed.push(ch);
            prev_slash = false;
        }
    }
    if collapsed.len() > 1 {
        while collapsed.ends_with('/') {
            collapsed.pop();
        }
    }
    if collapsed.is_empty() {
        "/".to_string()
    } else {
        collapsed
    }
}

fn normalize_surface(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let without_method = match trimmed.split_once(char::is_whitespace) {
        Some((first, rest))
            if matches!(
                first.to_ascii_uppercase().as_str(),
                "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" | "TRACE"
            ) =>
        {
            let rest = rest.trim();
            if rest.starts_with('/') || rest.contains("://") {
                rest
            } else {
                trimmed
            }
        }
        _ => trimmed,
    };
    if let Ok(u) = url::Url::parse(without_method) {
        if matches!(u.scheme(), "http" | "https") {
            if let Some(h) = u.host_str() {
                let host = norm_host(h);
                let host_port = match u.port() {
                    Some(p) => {
                        if host.contains(':') {
                            format!("[{host}]:{p}")
                        } else {
                            format!("{host}:{p}")
                        }
                    }
                    None => host,
                };
                let p = normalize_path_part(u.path());
                return format!("{host_port}{p}");
            }
        }
    }
    let no_query = without_method.split(['?', '#']).next().unwrap_or(without_method).trim();
    if no_query.starts_with('/') {
        return normalize_path_part(no_query);
    }
    if let Some((lead, rest)) = no_query.split_once('/') {
        let lead_norm = norm_host(lead);
        let p = normalize_path_part(&format!("/{rest}"));
        return format!("{lead_norm}{p}");
    }
    norm_host(no_query)
}

fn normalize_param_or_sink(raw: &str) -> String {
    raw.split_whitespace().collect::<Vec<_>>().join(" ").to_ascii_lowercase()
}

/// The targets under `~/.ferret/targets`.
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
                format!("There is no target `{name}`; create it with `ferret target add {name} --scope <host>`.")
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
                GraphLine::Resolves { host, ip, .. } => {
                    let h = norm_host(host);
                    let i = norm_host(ip);
                    !h.is_empty()
                        && !i.is_empty()
                        && !scope.excluded(&h)
                        && !scope.excluded(&i)
                        && (scope.contains(&h) || scope.contains(&i))
                }
                GraphLine::SecurityFinding { surface, .. }
                | GraphLine::Disposition { surface, .. }
                | GraphLine::DeadEnd { surface, .. } => surface_in_scope(surface, &scope),
                GraphLine::Passive { host, .. } => {
                    let h = norm_host(host);
                    !h.is_empty() && scope.contains(&h)
                }
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
            match g {
                GraphLine::Edge { kind, from, to, .. } => {
                    let e = EdgeView { kind, from, to };
                    if !out.contains(&e) {
                        out.push(e);
                    }
                }
                GraphLine::Resolves { host, ip, .. } => {
                    let e = EdgeView {
                        kind: "resolves".to_string(),
                        from: node_id(NodeKind::Host, &norm_host(&host)),
                        to: node_id(NodeKind::Ip, &norm_host(&ip)),
                    };
                    if !out.contains(&e) {
                        out.push(e);
                    }
                }
                _ => {}
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
                GraphLine::Resolves { .. }
                | GraphLine::SecurityFinding { .. }
                | GraphLine::Disposition { .. }
                | GraphLine::DeadEnd { .. }
                | GraphLine::Passive { .. } => {}
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

    /// All persisted structured security findings for `target` (deduplicated by `(mission, id)`,
    /// latest timestamp first).
    pub fn security_findings(&self, target: &str) -> Result<Vec<TargetFinding>, String> {
        let (lines, _) = read_graph(&self.graph_path(target)?)?;
        Ok(extract_security_findings(&lines))
    }

    /// All persisted host → IP resolution edges for `target` (deduplicated by `(host, ip)`,
    /// latest timestamp first).
    pub fn resolves(&self, target: &str) -> Result<Vec<TargetResolves>, String> {
        let (lines, _) = read_graph(&self.graph_path(target)?)?;
        Ok(extract_resolves(&lines))
    }

    /// All persisted risk-area dispositions (`ruled_out` / `needs_follow_up`) for `target`,
    /// deduplicated by `(surface, risk_area)` (latest wins).
    pub fn dispositions(&self, target: &str) -> Result<Vec<TargetDisposition>, String> {
        let (lines, _) = read_graph(&self.graph_path(target)?)?;
        Ok(extract_dispositions(&lines))
    }

    /// All persisted dead ends for `target`, latest timestamp first.
    pub fn dead_ends(&self, target: &str) -> Result<Vec<TargetDeadEnd>, String> {
        let (lines, _) = read_graph(&self.graph_path(target)?)?;
        Ok(extract_dead_ends(&lines))
    }

    /// All persisted passive security signals for `target`, deduplicated by `(host, path, kind, summary)`.
    pub fn passive_signals(&self, target: &str) -> Result<Vec<TargetPassive>, String> {
        let (lines, _) = read_graph(&self.graph_path(target)?)?;
        Ok(extract_passive(&lines))
    }

    /// Case-insensitive normalized 3-axis `(vuln_class, surface, param_or_sink)` duplicate matching
    /// across findings persisted in `target`'s graph.
    pub fn find_duplicate_findings(
        &self,
        target: &str,
        vuln_class: &str,
        surface: &str,
        param_or_sink: &str,
    ) -> Result<Vec<TargetFinding>, String> {
        let want_class = normalize_vuln_class(vuln_class);
        let want_surface = normalize_surface(surface);
        if want_class.is_empty() || want_surface.is_empty() {
            return Ok(Vec::new());
        }
        let want_param = normalize_param_or_sink(param_or_sink);
        let findings = self.security_findings(target)?;
        Ok(findings
            .into_iter()
            .filter(|f| {
                normalize_vuln_class(&f.vuln_class) == want_class
                    && normalize_surface(&f.surface) == want_surface
                    && normalize_param_or_sink(&f.param_or_sink) == want_param
            })
            .collect())
    }

    /// Validates `add_scope` and `add_exclude` with [`parse_entry`], deduplicates case-insensitively
    /// against existing entries in `target.toml`, persists the updated file, and returns
    /// `(updated_cfg, added_scope_count, added_exclude_count)`.
    pub fn merge_scope(
        &self,
        target: &str,
        add_scope: &[String],
        add_exclude: &[String],
    ) -> Result<(TargetCfg, usize, usize), String> {
        let mut cfg = self.get(target)?;
        let parsed_scope: Vec<(String, String)> = add_scope
            .iter()
            .map(|raw| {
                let entry = parse_entry(raw)?;
                Ok((entry.canonical_key(), raw.trim().to_string()))
            })
            .collect::<Result<_, String>>()?;
        let parsed_exclude: Vec<(String, String)> = add_exclude
            .iter()
            .map(|raw| {
                let entry = parse_entry(raw)?;
                Ok((entry.canonical_key(), raw.trim().to_string()))
            })
            .collect::<Result<_, String>>()?;

        let mut seen_scope: std::collections::HashSet<String> = cfg
            .scope
            .iter()
            .map(|e| parse_entry(e).map(|p| p.canonical_key()).unwrap_or_else(|_| norm_host(e)))
            .collect();
        let mut seen_exclude: std::collections::HashSet<String> = cfg
            .exclude
            .iter()
            .map(|e| parse_entry(e).map(|p| p.canonical_key()).unwrap_or_else(|_| norm_host(e)))
            .collect();

        let mut added_scope = 0usize;
        for (key, display) in parsed_scope {
            if seen_scope.insert(key) {
                cfg.scope.push(display);
                added_scope += 1;
            }
        }
        let mut added_exclude = 0usize;
        for (key, display) in parsed_exclude {
            if seen_exclude.insert(key) {
                cfg.exclude.push(display);
                added_exclude += 1;
            }
        }
        if added_scope > 0 || added_exclude > 0 {
            self.put(target, &cfg)?;
        }
        Ok((cfg, added_scope, added_exclude))
    }

    /// Full target summary for a lead's system prompt, capped at [`SUMMARY_MAX_BYTES`] (8 KiB).
    /// Includes concise, bounded highlights of recorded findings, `ruled_out` / `needs_follow_up`
    /// dispositions, dead ends, `resolves` edges, and `high` / `medium` passive signals.
    pub fn summary(&self, target: &str) -> Result<String, String> {
        let cfg = self.get(target)?;
        let nodes = self.nodes(target)?;
        let (lines, _) = read_graph(&self.graph_path(target)?)?;
        Ok(summary_with_lines(target, &cfg, &nodes, &lines))
    }
}

fn extract_security_findings(lines: &[GraphLine]) -> Vec<TargetFinding> {
    use std::collections::BTreeMap;
    let mut by_key: BTreeMap<(String, String), TargetFinding> = BTreeMap::new();
    for g in lines {
        if let GraphLine::SecurityFinding {
            id,
            mission,
            title,
            vuln_class,
            surface,
            param_or_sink,
            severity,
            confidence,
            at_ms,
            ..
        } = g
        {
            by_key.insert(
                (mission.clone(), id.clone()),
                TargetFinding {
                    id: id.clone(),
                    mission: mission.clone(),
                    title: title.clone(),
                    vuln_class: vuln_class.clone(),
                    surface: surface.clone(),
                    param_or_sink: param_or_sink.clone(),
                    severity: severity.clone(),
                    confidence: confidence.clone(),
                    at_ms: *at_ms,
                },
            );
        }
    }
    let mut out: Vec<TargetFinding> = by_key.into_values().collect();
    out.sort_by(|a, b| b.at_ms.cmp(&a.at_ms).then_with(|| a.mission.cmp(&b.mission)).then_with(|| a.id.cmp(&b.id)));
    out
}

fn extract_resolves(lines: &[GraphLine]) -> Vec<TargetResolves> {
    use std::collections::BTreeMap;
    let mut by_pair: BTreeMap<(String, String), TargetResolves> = BTreeMap::new();
    for g in lines {
        if let GraphLine::Resolves { host, ip, mission, at_ms, .. } = g {
            let h = norm_host(host);
            let i = norm_host(ip);
            by_pair.insert(
                (h.clone(), i.clone()),
                TargetResolves { host: h, ip: i, mission: mission.clone(), at_ms: *at_ms },
            );
        }
    }
    let mut out: Vec<TargetResolves> = by_pair.into_values().collect();
    out.sort_by(|a, b| b.at_ms.cmp(&a.at_ms).then_with(|| a.host.cmp(&b.host)).then_with(|| a.ip.cmp(&b.ip)));
    out
}

fn extract_dispositions(lines: &[GraphLine]) -> Vec<TargetDisposition> {
    use std::collections::BTreeMap;
    let mut by_key: BTreeMap<(String, String), TargetDisposition> = BTreeMap::new();
    for g in lines {
        if let GraphLine::Disposition { mission, surface, risk_area, disposition, note, at_ms, .. } = g {
            by_key.insert(
                (normalize_surface(surface), risk_area.trim().to_ascii_lowercase()),
                TargetDisposition {
                    mission: mission.clone(),
                    surface: surface.clone(),
                    risk_area: risk_area.clone(),
                    disposition: disposition.clone(),
                    note: note.clone(),
                    at_ms: *at_ms,
                },
            );
        }
    }
    let mut out: Vec<TargetDisposition> = by_key.into_values().collect();
    out.sort_by(|a, b| {
        b.at_ms.cmp(&a.at_ms).then_with(|| a.surface.cmp(&b.surface)).then_with(|| a.risk_area.cmp(&b.risk_area))
    });
    out
}

fn extract_dead_ends(lines: &[GraphLine]) -> Vec<TargetDeadEnd> {
    use std::collections::BTreeMap;
    let mut by_key: BTreeMap<(String, String), TargetDeadEnd> = BTreeMap::new();
    for g in lines {
        if let GraphLine::DeadEnd { mission, surface, summary, at_ms, .. } = g {
            by_key.insert(
                (normalize_surface(surface), summary.trim().to_ascii_lowercase()),
                TargetDeadEnd {
                    mission: mission.clone(),
                    surface: surface.clone(),
                    summary: summary.clone(),
                    at_ms: *at_ms,
                },
            );
        }
    }
    let mut out: Vec<TargetDeadEnd> = by_key.into_values().collect();
    out.sort_by(|a, b| b.at_ms.cmp(&a.at_ms).then_with(|| a.surface.cmp(&b.surface)));
    out
}

fn extract_passive(lines: &[GraphLine]) -> Vec<TargetPassive> {
    use std::collections::BTreeMap;
    let mut by_key: BTreeMap<(String, String, String, String), TargetPassive> = BTreeMap::new();
    for g in lines {
        if let GraphLine::Passive { mission, exchange_id, host, path, signal, at_ms, .. } = g {
            let h = norm_host(host);
            by_key.insert(
                (h.clone(), path.clone(), signal.kind.to_ascii_lowercase(), signal.summary.to_ascii_lowercase()),
                TargetPassive {
                    mission: mission.clone(),
                    exchange_id: exchange_id.clone(),
                    host: h,
                    path: path.clone(),
                    signal: signal.clone(),
                    at_ms: *at_ms,
                },
            );
        }
    }
    let mut out: Vec<TargetPassive> = by_key.into_values().collect();
    let rank = |sev: &str| match sev.to_ascii_lowercase().as_str() {
        "high" => 0u8,
        "medium" => 1,
        "low" => 2,
        _ => 3,
    };
    out.sort_by(|a, b| {
        rank(&a.signal.severity)
            .cmp(&rank(&b.signal.severity))
            .then_with(|| b.at_ms.cmp(&a.at_ms))
            .then_with(|| a.host.cmp(&b.host))
            .then_with(|| a.path.cmp(&b.path))
    });
    out
}

pub const SUMMARY_MAX_BYTES: usize = 8 * 1024;
const SUMMARY_UNTESTED: usize = 40;
const SUMMARY_FINDINGS: usize = 20;
const SUMMARY_SECURITY_FINDINGS: usize = 12;
const SUMMARY_DISPOSITIONS: usize = 12;
const SUMMARY_DEAD_ENDS: usize = 8;
const SUMMARY_RESOLVES: usize = 15;
const SUMMARY_PASSIVE: usize = 10;

fn one_line(text: &str, max_chars: usize) -> String {
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max_chars {
        flat
    } else {
        let cut: String = flat.chars().take(max_chars.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}

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
pub fn summary(name: &str, cfg: &TargetCfg, nodes: &[NodeView]) -> String {
    summary_with_lines(name, cfg, nodes, &[])
}

fn summary_with_lines(_name: &str, cfg: &TargetCfg, nodes: &[NodeView], lines: &[GraphLine]) -> String {
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
    let sec_findings = extract_security_findings(lines);
    if !sec_findings.is_empty() {
        s.push_str(&format!(
            "Recorded security findings ({} of {}):\n",
            sec_findings.len().min(SUMMARY_SECURITY_FINDINGS),
            sec_findings.len()
        ));
        for f in sec_findings.iter().take(SUMMARY_SECURITY_FINDINGS) {
            let param = if f.param_or_sink.trim().is_empty() {
                String::new()
            } else {
                format!(" ({})", one_line(&f.param_or_sink, 48))
            };
            s.push_str(&format!(
                "- [{}] {} · {} · {}{} · mission {}\n",
                one_line(&f.severity, 16),
                one_line(&f.title, 100),
                one_line(&f.vuln_class, 32),
                one_line(&f.surface, 80),
                param,
                f.mission
            ));
        }
    }
    let dispositions: Vec<TargetDisposition> = extract_dispositions(lines)
        .into_iter()
        .filter(|d| matches!(d.disposition.to_ascii_lowercase().as_str(), "ruled_out" | "needs_follow_up"))
        .collect();
    if !dispositions.is_empty() {
        s.push_str(&format!(
            "Dispositions ({} of {}):\n",
            dispositions.len().min(SUMMARY_DISPOSITIONS),
            dispositions.len()
        ));
        for d in dispositions.iter().take(SUMMARY_DISPOSITIONS) {
            let note = if d.note.trim().is_empty() { String::new() } else { format!(": {}", one_line(&d.note, 90)) };
            s.push_str(&format!(
                "- [{}] {} · {}{} (mission {})\n",
                one_line(&d.disposition, 20),
                one_line(&d.surface, 70),
                one_line(&d.risk_area, 40),
                note,
                d.mission
            ));
        }
    }
    let dead_ends = extract_dead_ends(lines);
    if !dead_ends.is_empty() {
        s.push_str(&format!("Dead ends ({} of {}):\n", dead_ends.len().min(SUMMARY_DEAD_ENDS), dead_ends.len()));
        for d in dead_ends.iter().take(SUMMARY_DEAD_ENDS) {
            s.push_str(&format!(
                "- {}: {} (mission {})\n",
                one_line(&d.surface, 70),
                one_line(&d.summary, 100),
                d.mission
            ));
        }
    }
    let resolves = extract_resolves(lines);
    if !resolves.is_empty() {
        s.push_str(&format!("Resolutions ({} of {}):\n", resolves.len().min(SUMMARY_RESOLVES), resolves.len()));
        for r in resolves.iter().take(SUMMARY_RESOLVES) {
            s.push_str(&format!("- {} -> {}\n", r.host, r.ip));
        }
    }
    let passive: Vec<TargetPassive> = extract_passive(lines)
        .into_iter()
        .filter(|p| matches!(p.signal.severity.to_ascii_lowercase().as_str(), "high" | "medium"))
        .collect();
    if !passive.is_empty() {
        s.push_str(&format!(
            "Passive signals ({} of {} high/medium):\n",
            passive.len().min(SUMMARY_PASSIVE),
            passive.len()
        ));
        for p in passive.iter().take(SUMMARY_PASSIVE) {
            s.push_str(&format!(
                "- [{}] {} · {}{}: {}\n",
                one_line(&p.signal.severity, 12),
                one_line(&p.signal.kind, 32),
                p.host,
                one_line(&p.path, 60),
                one_line(&p.signal.summary, 90)
            ));
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
        // JS sourcemaps (.map) are NOT filtered or mangled.
        assert_eq!(path_template("/static/assets/app.bundle.js.map?v=2"), "/static/assets/app.bundle.js.map");
    }

    #[test]
    fn graph_persists_resolves_findings_dispositions_dead_ends_passive_and_map_endpoints() {
        let d = tempfile::tempdir().unwrap();
        let s = store(&d);
        let map_ep = "GET https://www.acme.test:443/static/app.js.map";
        s.append(
            "acme",
            vec![
                seen(NodeKind::Host, "api.acme.test", "m-1", 10),
                seen(NodeKind::Endpoint, map_ep, "m-1", 11),
                GraphLine::Resolves {
                    host: "api.acme.test".into(),
                    ip: "203.0.113.10".into(),
                    mission: "m-1".into(),
                    at_ms: 100,
                    prev: String::new(),
                },
                // Out-of-scope and excluded resolutions must be dropped.
                GraphLine::Resolves {
                    host: "evil.example".into(),
                    ip: "198.51.100.7".into(),
                    mission: "m-1".into(),
                    at_ms: 101,
                    prev: String::new(),
                },
                GraphLine::Resolves {
                    host: "vpn.acme.test".into(),
                    ip: "10.20.0.1".into(),
                    mission: "m-1".into(),
                    at_ms: 102,
                    prev: String::new(),
                },
                GraphLine::SecurityFinding {
                    id: "fn-001".into(),
                    mission: "m-1".into(),
                    title: "BOLA on user order fetch".into(),
                    vuln_class: "CWE-639".into(),
                    surface: "GET https://api.acme.test/v1/orders/42".into(),
                    param_or_sink: "order_id".into(),
                    severity: "high".into(),
                    confidence: "high".into(),
                    at_ms: 200,
                    prev: String::new(),
                },
                // Out-of-scope URL finding is dropped.
                GraphLine::SecurityFinding {
                    id: "fn-bad".into(),
                    mission: "m-1".into(),
                    title: "Out of scope".into(),
                    vuln_class: "CWE-79".into(),
                    surface: "https://evil.example/search".into(),
                    param_or_sink: "q".into(),
                    severity: "medium".into(),
                    confidence: "high".into(),
                    at_ms: 201,
                    prev: String::new(),
                },
                GraphLine::Disposition {
                    mission: "m-1".into(),
                    surface: "https://api.acme.test/v1/auth/login".into(),
                    risk_area: "sqli".into(),
                    disposition: "ruled_out".into(),
                    note: "Parameterized query verified".into(),
                    at_ms: 300,
                    prev: String::new(),
                },
                GraphLine::Disposition {
                    mission: "m-1".into(),
                    surface: "https://api.acme.test/v1/export".into(),
                    risk_area: "ssrf".into(),
                    disposition: "needs_follow_up".into(),
                    note: "Need OAST callback test".into(),
                    at_ms: 301,
                    prev: String::new(),
                },
                GraphLine::DeadEnd {
                    mission: "m-1".into(),
                    surface: "https://api.acme.test/v1/legacy".into(),
                    summary: "Returns 410 Gone across all methods".into(),
                    at_ms: 400,
                    prev: String::new(),
                },
                GraphLine::Passive {
                    mission: "m-1".into(),
                    exchange_id: "ex-111111111111".into(),
                    host: "api.acme.test".into(),
                    path: "/v1/orders".into(),
                    signal: crate::event::PassiveSignal {
                        kind: "cors_misconfig".into(),
                        severity: "high".into(),
                        summary: "Reflected Origin with ACAC: true".into(),
                        detail: String::new(),
                    },
                    at_ms: 500,
                    prev: String::new(),
                },
                GraphLine::Passive {
                    mission: "m-1".into(),
                    exchange_id: "ex-222222222222".into(),
                    host: "api.acme.test".into(),
                    path: "/".into(),
                    signal: crate::event::PassiveSignal {
                        kind: "missing_security_headers".into(),
                        severity: "info".into(),
                        summary: "Missing CSP and XFO".into(),
                        detail: String::new(),
                    },
                    at_ms: 501,
                    prev: String::new(),
                },
                // Out-of-scope passive signal is dropped.
                GraphLine::Passive {
                    mission: "m-1".into(),
                    exchange_id: "ex-333333333333".into(),
                    host: "evil.example".into(),
                    path: "/".into(),
                    signal: crate::event::PassiveSignal {
                        kind: "secret_leak".into(),
                        severity: "high".into(),
                        summary: "Leaked key".into(),
                        detail: String::new(),
                    },
                    at_ms: 502,
                    prev: String::new(),
                },
            ],
        )
        .unwrap();

        assert!(s.verify("acme").unwrap());
        assert!(s.nodes("acme").unwrap().iter().any(|n| n.locator == map_ep));
        assert_eq!(s.resolves("acme").unwrap().len(), 1);
        assert!(s.edges("acme").unwrap().iter().any(|e| e.kind == "resolves"));
        assert_eq!(s.security_findings("acme").unwrap().len(), 1);
        assert_eq!(s.dispositions("acme").unwrap().len(), 2);
        assert_eq!(s.dead_ends("acme").unwrap().len(), 1);
        assert_eq!(s.passive_signals("acme").unwrap().len(), 2);

        // Cross-mission 3-axis duplicate matching (case-insensitive, normalized CWE + path template + param).
        let dups = s
            .find_duplicate_findings(
                "acme",
                "cwe_0639",
                "https://API.ACME.TEST:443/v1/orders/999/?debug=1",
                " ORDER_ID ",
            )
            .unwrap();
        assert_eq!(dups.len(), 1);
        assert_eq!(dups[0].id, "fn-001");
        assert_eq!(dups[0].mission, "m-1");

        // Different param, vuln_class, or surface do not match.
        assert!(s
            .find_duplicate_findings("acme", "CWE-639", "https://api.acme.test/v1/orders/42", "user_id")
            .unwrap()
            .is_empty());
        assert!(s
            .find_duplicate_findings("acme", "CWE-89", "https://api.acme.test/v1/orders/42", "order_id")
            .unwrap()
            .is_empty());
        assert!(s
            .find_duplicate_findings("acme", "CWE-639", "https://api.acme.test/v1/invoices/42", "order_id")
            .unwrap()
            .is_empty());

        // TargetStore::summary includes bounded highlights and omits low/info passive signals.
        let sum = s.summary("acme").unwrap();
        assert!(sum.len() <= SUMMARY_MAX_BYTES);
        assert!(sum.contains("BOLA on user order fetch"), "{sum}");
        assert!(sum.contains("[ruled_out]"), "{sum}");
        assert!(sum.contains("[needs_follow_up]"), "{sum}");
        assert!(sum.contains("Returns 410 Gone"), "{sum}");
        assert!(sum.contains("api.acme.test -> 203.0.113.10"), "{sum}");
        assert!(sum.contains("cors_misconfig"), "{sum}");
        assert!(!sum.contains("missing_security_headers"), "info passive should not bloat summary: {sum}");
        assert!(!sum.contains("evil.example"), "{sum}");
    }

    #[test]
    fn merge_scope_validates_deduplicates_and_persists() {
        let d = tempfile::tempdir().unwrap();
        let s = store(&d);
        let (cfg, added_s, added_e) = s
            .merge_scope(
                "acme",
                &[
                    "ACME.TEST.".into(),      // duplicate of existing acme.test
                    "*.acme.test".into(),     // duplicate of existing *.acme.test
                    "beta.acme.org".into(),   // new
                    "BETA.ACME.ORG".into(),   // duplicate within same batch
                    "198.51.100.0/24".into(), // new CIDR
                ],
                &[
                    "VPN.ACME.TEST".into(),    // duplicate of existing vpn.acme.test
                    "billing.acme.org".into(), // new
                ],
            )
            .unwrap();
        assert_eq!((added_s, added_e), (2, 1));
        assert!(cfg.scope.contains(&"beta.acme.org".to_string()));
        assert!(cfg.scope.contains(&"198.51.100.0/24".to_string()));
        assert!(cfg.exclude.contains(&"billing.acme.org".to_string()));
        // Persisted to disk.
        assert_eq!(s.get("acme").unwrap(), cfg);

        // Invalid entry fails cleanly without mutating target.toml.
        let err = s.merge_scope("acme", &["https://bad.example.com".into()], &[]).unwrap_err();
        assert!(err.contains("scope entry") || err.contains("CIDR"), "{err}");
        assert_eq!(s.get("acme").unwrap(), cfg);
    }
}
