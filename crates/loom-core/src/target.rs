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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FindingView {
    pub claim: String,
    pub text: String,
    pub status: String,
    pub mission: String,
    pub evidence: Vec<String>,
}

/// The targets under `~/.loom/targets`.
pub struct TargetStore {
    pub root: std::path::PathBuf,
}

impl TargetStore {
    pub fn new(root: std::path::PathBuf) -> TargetStore {
        TargetStore { root }
    }
    pub fn list(&self) -> Result<Vec<(String, TargetCfg)>, String> {
        todo!("CONTRACTS-TRAFFIC-TARGETS T1")
    }
    pub fn get(&self, _name: &str) -> Result<TargetCfg, String> {
        todo!("CONTRACTS-TRAFFIC-TARGETS T1")
    }
    /// Creates or replaces the settings; the scope is checked with [`Scope::parse`] first.
    pub fn put(&self, _name: &str, _cfg: &TargetCfg) -> Result<(), String> {
        todo!("CONTRACTS-TRAFFIC-TARGETS T1")
    }
    /// Appends lines to `graph.jsonl`, chaining `prev`; lines about out-of-scope locators are dropped (T4).
    pub fn append(&self, _name: &str, _lines: Vec<GraphLine>) -> Result<(), String> {
        todo!("CONTRACTS-TRAFFIC-TARGETS T3, T4")
    }
    /// Every node with its status (T6), plus `NotSeen` entries for scope entries with no node.
    pub fn nodes(&self, _name: &str) -> Result<Vec<NodeView>, String> {
        todo!("CONTRACTS-TRAFFIC-TARGETS T6")
    }
}

/// The text that goes under "# Target {name}" in a lead's system prompt (T5), at most 8 KiB.
pub fn summary(_name: &str, _cfg: &TargetCfg, _nodes: &[NodeView]) -> String {
    todo!("CONTRACTS-TRAFFIC-TARGETS T5")
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
}
