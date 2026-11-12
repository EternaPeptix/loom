//! The network policy as a pure function.
//!
//! CONTRACT (bodies are placeholders for the implementer; signatures and types are fixed).
//!
//! ## Patterns (`allow`, `deny`, and the name form of `allow_private`)
//! `host`, `*.suffix`, either optionally followed by `:port`. Matching is on the lower-cased host
//! with a trailing dot removed. `example.test` matches only that name; `*.example.test` matches any
//! name that ends in `.example.test` (one or more labels before it) and not `example.test` itself.
//! `*` alone matches every host. Without a port the pattern matches every port. An IP literal is a
//! host like any other (IPv6 written in brackets when a port follows: `[::1]:8080`).
//! `allow_private` entries may also be CIDR blocks (`10.0.0.0/8`, `fd00::/8`) or bare addresses,
//! which match resolved addresses rather than names.
//! `Policy::new` rejects an entry it cannot parse, with a sentence naming the entry and the list.
//!
//! ## Decision — `check_name(host, port)` runs before resolving, `check_addr` after
//! `check_name`, first match wins:
//!   1. `deny` pattern matches → refused, rule `deny {pattern}`;
//!   2. mode `deny_all` → refused, rule `mode deny_all`;
//!   3. mode `allowlist` and no `allow` pattern matches → refused, rule `not in allow list`;
//!   4. otherwise allowed so far: rule `allow {pattern}` (allowlist) or `mode open`.
//! `check_addr(host, port, addr, name_rule)` — for the address the proxy is about to connect to:
//!   - if `addr` is special (see below): allowed only when an `allow_private` entry matches the
//!     host name pattern (with port), or a CIDR/address entry contains `addr`; rule
//!     `allow_private {entry}`; otherwise refused with rule `deny private-address {addr}`;
//!   - otherwise allowed with `name_rule`.
//! Special addresses: IPv4 0.0.0.0/8, 10/8, 100.64/10, 127/8, 169.254/16, 172.16/12, 192.0.0.0/24,
//! 192.168/16, 198.18/15, 224/4 and above; IPv6 `::`, `::1`, fc00::/7, fe80::/10, ff00::/8, and
//! IPv4-mapped/compatible forms of any special IPv4 address (check the embedded address).
//!
//! `Verdict::allowed` + `rule` are what the proxy reports. Everything here is deterministic and does
//! no I/O.
//!
//! Tests required: pattern parsing (good and bad entries); wildcard semantics incl. the apex not
//! matching; port-specific patterns; case and trailing dot; each numbered rule and their order (deny
//! beats allow); every special range at its edges (first/last address in, neighbours out); mapped
//! IPv6; `allow_private` by name, by CIDR and by address; open mode still refuses private addresses.

#![allow(clippy::doc_lazy_continuation)]

use loom_core::config::{NetworkCfg, NetworkMode};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    pub allowed: bool,
    pub rule: String,
}

impl Verdict {
    fn yes(rule: impl Into<String>) -> Verdict {
        Verdict { allowed: true, rule: rule.into() }
    }
    fn no(rule: impl Into<String>) -> Verdict {
        Verdict { allowed: false, rule: rule.into() }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Kind {
    Any,
    Exact(String),
    /// Stored with its leading dot (`.example.test`).
    Suffix(String),
}

/// One host pattern, as written in the config.
#[derive(Clone, Debug)]
struct Pattern {
    text: String,
    kind: Kind,
    port: Option<u16>,
}

impl Pattern {
    fn parse(entry: &str) -> Result<Pattern, String> {
        let text = entry.trim();
        if text.is_empty() {
            return Err("it is empty".into());
        }
        let (host, port) = split_host_port(text)?;
        let kind = if host == "*" {
            Kind::Any
        } else if let Some(suffix) = host.strip_prefix("*.") {
            let s = normalize_host(suffix);
            if !valid_name(&s) {
                return Err("the part after `*.` is not a host name".into());
            }
            Kind::Suffix(format!(".{s}"))
        } else {
            let h = normalize_host(host);
            if !valid_name(&h) && h.parse::<IpAddr>().is_err() {
                return Err("the host is not a valid name or address (`*` may only appear as `*` or a leading `*.`)".into());
            }
            Kind::Exact(h)
        };
        Ok(Pattern { text: text.to_string(), kind, port })
    }

    /// `host` must already be normalized.
    fn matches(&self, host: &str, port: u16) -> bool {
        if self.port.is_some_and(|p| p != port) {
            return false;
        }
        match &self.kind {
            Kind::Any => true,
            Kind::Exact(h) => h == host,
            Kind::Suffix(s) => host.len() > s.len() && host.ends_with(s.as_str()),
        }
    }
}

/// Splits `host[:port]`, `[v6]` and `[v6]:port`; a bare IPv6 literal has no port.
fn split_host_port(text: &str) -> Result<(&str, Option<u16>), String> {
    let parse_port = |p: &str| p.parse::<u16>().map_err(|_| format!("`{p}` is not a port number"));
    if let Some(rest) = text.strip_prefix('[') {
        let (inner, after) = rest.split_once(']').ok_or("the `[` has no closing `]`")?;
        if inner.parse::<Ipv6Addr>().is_err() {
            return Err("the text in brackets is not an IPv6 address".into());
        }
        return match after {
            "" => Ok((inner, None)),
            _ => match after.strip_prefix(':') {
                Some(p) => Ok((inner, Some(parse_port(p)?))),
                None => Err("only `:port` may follow the closing `]`".into()),
            },
        };
    }
    match text.matches(':').count() {
        0 => Ok((text, None)),
        1 => {
            let (h, p) = text.split_once(':').ok_or("malformed host:port")?;
            Ok((h, Some(parse_port(p)?)))
        }
        _ if text.parse::<Ipv6Addr>().is_ok() => Ok((text, None)),
        _ => Err("an IPv6 address with a port must be written in brackets, like `[::1]:8080`".into()),
    }
}

fn valid_name(h: &str) -> bool {
    !h.is_empty() && h.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
}

/// Lower-case, without brackets or trailing dots; IP literals in canonical form.
pub(crate) fn normalize_host(host: &str) -> String {
    let h = host.trim();
    let h = h.strip_prefix('[').and_then(|r| r.strip_suffix(']')).unwrap_or(h);
    let h = h.trim_end_matches('.').to_ascii_lowercase();
    match h.parse::<IpAddr>() {
        Ok(ip) => ip.to_string(),
        Err(_) => h,
    }
}

#[derive(Clone, Debug)]
enum IpNet {
    V4 { base: u32, mask: u32 },
    V6 { base: u128, mask: u128 },
}

impl IpNet {
    fn new(ip: IpAddr, prefix: u8) -> IpNet {
        match ip {
            IpAddr::V4(a) => {
                let mask = u32::MAX.checked_shl(32u32.saturating_sub(u32::from(prefix))).unwrap_or(0);
                IpNet::V4 { base: u32::from(a) & mask, mask }
            }
            IpAddr::V6(a) => {
                let mask = u128::MAX.checked_shl(128u32.saturating_sub(u32::from(prefix))).unwrap_or(0);
                IpNet::V6 { base: u128::from(a) & mask, mask }
            }
        }
    }

    fn contains(&self, addr: IpAddr) -> bool {
        match (self, addr) {
            (IpNet::V4 { base, mask }, IpAddr::V4(a)) => u32::from(a) & mask == *base,
            (IpNet::V6 { base, mask }, IpAddr::V6(a)) => u128::from(a) & mask == *base,
            (IpNet::V4 { .. }, IpAddr::V6(a)) => embedded_v4(a).is_some_and(|v| self.contains(IpAddr::V4(v))),
            (IpNet::V6 { .. }, IpAddr::V4(_)) => false,
        }
    }
}

#[derive(Clone, Debug)]
enum PrivEntry {
    Name(Pattern),
    Net { text: String, net: IpNet },
}

impl PrivEntry {
    fn parse(entry: &str) -> Result<PrivEntry, String> {
        let text = entry.trim();
        if let Some((a, p)) = text.split_once('/') {
            let ip = a.parse::<IpAddr>().map_err(|_| format!("`{a}` is not an IP address"))?;
            let max = if ip.is_ipv4() { 32 } else { 128 };
            let prefix = p
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= max)
                .ok_or_else(|| format!("`{p}` is not a prefix length from 0 to {max}"))?;
            return Ok(PrivEntry::Net { text: text.to_string(), net: IpNet::new(ip, prefix) });
        }
        if let Ok(ip) = text.parse::<IpAddr>() {
            let full = if ip.is_ipv4() { 32 } else { 128 };
            return Ok(PrivEntry::Net { text: text.to_string(), net: IpNet::new(ip, full) });
        }
        Pattern::parse(text).map(PrivEntry::Name)
    }
}

/// A parsed, validated network policy.
#[derive(Clone, Debug)]
pub struct Policy {
    mode: NetworkMode,
    allow: Vec<Pattern>,
    /// Host patterns, plus address entries (literals and CIDR blocks) that also match resolved addresses.
    deny: Vec<PrivEntry>,
    allow_private: Vec<PrivEntry>,
}

fn parse_list<T>(list: &str, entries: &[String], parse: fn(&str) -> Result<T, String>) -> Result<Vec<T>, String> {
    entries
        .iter()
        .map(|e| {
            parse(e).map_err(|why| {
                format!(
                    "network.{list} entry \"{e}\" is not valid: {why}. Write a host (`example.test`), a wildcard (`*.example.test`) or `*`, optionally followed by `:port`{}, then reload the config.",
                    if list != "allow" { ", or a CIDR block such as `10.0.0.0/8`" } else { "" }
                )
            })
        })
        .collect()
}

impl Policy {
    pub fn new(cfg: &NetworkCfg) -> Result<Policy, String> {
        Ok(Policy {
            mode: cfg.mode,
            allow: parse_list("allow", &cfg.allow, Pattern::parse)?,
            deny: parse_list("deny", &cfg.deny, PrivEntry::parse)?,
            allow_private: parse_list("allow_private", &cfg.allow_private, PrivEntry::parse)?,
        })
    }

    pub fn check_name(&self, host: &str, port: u16) -> Verdict {
        let h = normalize_host(host);
        if let Some(rule) = self.deny_hit(&h, port, h.parse::<IpAddr>().ok()) {
            return Verdict::no(rule);
        }
        match self.mode {
            NetworkMode::DenyAll => Verdict::no("mode deny_all"),
            NetworkMode::Allowlist => match self.allow.iter().find(|p| p.matches(&h, port)) {
                Some(p) => Verdict::yes(format!("allow {}", p.text)),
                None => Verdict::no("not in allow list"),
            },
            NetworkMode::Open => Verdict::yes("mode open"),
        }
    }

    /// The `deny ...` rule that matches the name, or the address when there is one. Address entries
    /// are compared on the canonical form, so `::ffff:10.0.0.5` is `10.0.0.5`.
    fn deny_hit(&self, host: &str, port: u16, addr: Option<IpAddr>) -> Option<String> {
        for e in &self.deny {
            match e {
                PrivEntry::Name(p) => {
                    let literal = match (&p.kind, addr) {
                        (Kind::Exact(x), Some(a)) => {
                            p.port.is_none_or(|pp| pp == port)
                                && x.parse::<IpAddr>().is_ok_and(|x| canonical_ip(x) == canonical_ip(a))
                        }
                        _ => false,
                    };
                    if literal || p.matches(host, port) {
                        return Some(format!("deny {}", p.text));
                    }
                }
                PrivEntry::Net { text, net } => {
                    if addr.is_some_and(|a| net.contains(a) || net.contains(canonical_ip(a))) {
                        return Some(format!("deny {text}"));
                    }
                }
            }
        }
        None
    }

    /// Like the module contract, with one addition: before anything else, a `deny` entry that is an IP
    /// literal or a CIDR block refuses a resolved address it contains, whatever name led to it.
    pub fn check_addr(&self, host: &str, port: u16, addr: IpAddr, name_rule: &str) -> Verdict {
        let h = normalize_host(host);
        if let Some(rule) = self.deny_hit(&h, port, Some(addr)) {
            return Verdict::no(rule);
        }
        if !is_special(addr) {
            return Verdict::yes(name_rule);
        }
        for e in &self.allow_private {
            match e {
                PrivEntry::Name(p) if p.matches(&h, port) => return Verdict::yes(format!("allow_private {}", p.text)),
                PrivEntry::Net { text, net } if net.contains(addr) => {
                    return Verdict::yes(format!("allow_private {text}"));
                }
                _ => {}
            }
        }
        Verdict::no(format!("deny private-address {addr}"))
    }
}

/// The IPv4 address inside an IPv4-mapped (`::ffff:a.b.c.d`) or IPv4-compatible (`::a.b.c.d`) address.
fn embedded_v4(a: Ipv6Addr) -> Option<Ipv4Addr> {
    let [s0, s1, s2, s3, s4, s5, s6, s7] = a.segments();
    let head_zero = s0 == 0 && s1 == 0 && s2 == 0 && s3 == 0 && s4 == 0;
    if !head_zero || (s5 != 0xffff && s5 != 0) {
        return None;
    }
    let [a0, a1] = s6.to_be_bytes();
    let [a2, a3] = s7.to_be_bytes();
    Some(Ipv4Addr::new(a0, a1, a2, a3))
}

/// IPv4-mapped and IPv4-compatible IPv6 addresses as the IPv4 address they carry (`::` and `::1` stay).
fn canonical_ip(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(a) => match embedded_v4(a) {
            Some(v4) if v4.octets().first().is_some_and(|o| *o != 0) || a.segments().get(5) == Some(&0xffff) => {
                IpAddr::V4(v4)
            }
            _ => addr,
        },
        IpAddr::V4(_) => addr,
    }
}

fn special_v4(a: Ipv4Addr) -> bool {
    let [o0, o1, o2, _] = a.octets();
    o0 == 0
        || o0 == 10
        || (o0 == 100 && (64..=127).contains(&o1))
        || o0 == 127
        || (o0 == 169 && o1 == 254)
        || (o0 == 172 && (16..=31).contains(&o1))
        || (o0 == 192 && o1 == 0 && o2 == 0)
        || (o0 == 192 && o1 == 168)
        || (o0 == 198 && (o1 == 18 || o1 == 19))
        || o0 >= 224
}

/// Whether `addr` is loopback, private, link-local, multicast, or otherwise not a public unicast
/// address (the list is in the module contract).
pub fn is_special(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => special_v4(a),
        IpAddr::V6(a) => {
            // `::` and `::1` fall out of the compatible form (0.0.0.0 and 0.0.0.1).
            if let Some(v4) = embedded_v4(a) {
                return special_v4(v4);
            }
            let [s0, ..] = a.segments();
            (s0 & 0xfe00) == 0xfc00 || (s0 & 0xffc0) == 0xfe80 || (s0 & 0xff00) == 0xff00
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(mode: NetworkMode, allow: &[&str], deny: &[&str], private: &[&str]) -> NetworkCfg {
        let v = |x: &[&str]| x.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        NetworkCfg { mode, allow: v(allow), deny: v(deny), allow_private: v(private) }
    }
    fn pol(mode: NetworkMode, allow: &[&str], deny: &[&str], private: &[&str]) -> Policy {
        Policy::new(&cfg(mode, allow, deny, private)).unwrap()
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn good_entries_parse() {
        for e in ["example.test", "*.example.test", "example.test:443", "*", "*:80", "[::1]:8080", "::1", "10.0.0.1", "*.a-b.c_d"] {
            assert!(Policy::new(&cfg(NetworkMode::Open, &[e], &[e], &[])).is_ok(), "{e}");
        }
        for e in ["10.0.0.0/8", "fd00::/8", "1.2.3.4", "0.0.0.0/0", "::/0", "::1/128"] {
            assert!(Policy::new(&cfg(NetworkMode::Open, &[], &[], &[e])).is_ok(), "{e}");
        }
    }

    #[test]
    fn bad_entries_name_entry_and_list() {
        let e = Policy::new(&cfg(NetworkMode::Open, &["bad host"], &[], &[])).unwrap_err();
        assert!(e.contains("network.allow"), "{e}");
        let e = Policy::new(&cfg(NetworkMode::Open, &[], &["example.test:99999"], &[])).unwrap_err();
        assert!(e.contains("network.deny"), "{e}");
        let e = Policy::new(&cfg(NetworkMode::Open, &[], &[], &["10.0.0.0/33"])).unwrap_err();
        assert!(e.contains("network.allow_private"), "{e}");
        for e in ["", "  ", "a*b.test", "*.", "*.*.test", "ex.test:", "ex.test:x", "[::1", "[::1]x", "[abc]:1", "a/b", "1.2.3.4/x", "fd00::/129", "x/8"] {
            let r = Policy::new(&cfg(NetworkMode::Open, &[], &[], &[e]));
            assert!(r.is_err(), "{e:?} should be rejected");
        }
        assert!(Policy::new(&cfg(NetworkMode::Open, &["10.0.0.0/8"], &[], &[])).is_err());
        let msg = Policy::new(&cfg(NetworkMode::Open, &["a b"], &[], &[])).unwrap_err();
        assert!(msg.contains("\"a b\""), "{msg}");
    }

    #[test]
    fn wildcard_semantics() {
        let p = pol(NetworkMode::Allowlist, &["*.example.test"], &[], &[]);
        assert!(p.check_name("a.example.test", 443).allowed);
        assert!(p.check_name("a.b.example.test", 443).allowed);
        assert!(!p.check_name("example.test", 443).allowed);
        assert!(!p.check_name("badexample.test", 443).allowed);
        assert!(!p.check_name("a.example.test.evil", 443).allowed);
        let all = pol(NetworkMode::Allowlist, &["*"], &[], &[]);
        assert_eq!(all.check_name("anything.test", 1).rule, "allow *");
        let exact = pol(NetworkMode::Allowlist, &["example.test"], &[], &[]);
        assert!(exact.check_name("example.test", 1).allowed);
        assert!(!exact.check_name("www.example.test", 1).allowed);
    }

    #[test]
    fn port_specific_patterns() {
        let p = pol(NetworkMode::Allowlist, &["example.test:443", "[::1]:8080"], &[], &[]);
        assert!(p.check_name("example.test", 443).allowed);
        assert!(!p.check_name("example.test", 80).allowed);
        assert!(p.check_name("::1", 8080).allowed);
        assert!(!p.check_name("::1", 8081).allowed);
        let d = pol(NetworkMode::Open, &[], &["*.example.test:25"], &[]);
        assert!(!d.check_name("mail.example.test", 25).allowed);
        assert!(d.check_name("mail.example.test", 587).allowed);
    }

    #[test]
    fn case_and_trailing_dot() {
        let p = pol(NetworkMode::Allowlist, &["Example.TEST"], &["EVIL.test."], &[]);
        assert!(p.check_name("EXAMPLE.test.", 80).allowed);
        assert!(!p.check_name("evil.TEST", 80).allowed);
        assert!(!p.check_name("[::1]", 80).allowed);
        assert_eq!(normalize_host("[::FFFF:1.2.3.4]"), "::ffff:1.2.3.4");
    }

    #[test]
    fn rules_and_order() {
        let open = pol(NetworkMode::Open, &[], &[], &[]);
        assert_eq!(open.check_name("a.test", 1), Verdict { allowed: true, rule: "mode open".into() });
        let deny_all = pol(NetworkMode::DenyAll, &["a.test"], &[], &[]);
        assert_eq!(deny_all.check_name("a.test", 1), Verdict { allowed: false, rule: "mode deny_all".into() });
        let al = pol(NetworkMode::Allowlist, &["*.a.test"], &[], &[]);
        assert_eq!(al.check_name("x.a.test", 1).rule, "allow *.a.test");
        assert_eq!(al.check_name("b.test", 1), Verdict { allowed: false, rule: "not in allow list".into() });
        for mode in [NetworkMode::Open, NetworkMode::Allowlist, NetworkMode::DenyAll] {
            let p = pol(mode, &["*.a.test", "*"], &["bad.a.test"], &[]);
            assert_eq!(p.check_name("bad.a.test", 1), Verdict { allowed: false, rule: "deny bad.a.test".into() });
        }
    }

    #[test]
    fn deny_wins_on_the_resolved_address() {
        // A denied literal beats allow_private, whatever name resolved to it and in whatever spelling.
        let p = pol(NetworkMode::Open, &[], &["10.0.0.5"], &["10.0.0.0/8"]);
        let a = |h: &str, port: u16, addr: &str| p.check_addr(h, port, ip(addr), "mode open");
        assert_eq!(a("lab.test", 80, "10.0.0.5"), Verdict { allowed: false, rule: "deny 10.0.0.5".into() });
        assert!(!a("lab.test", 80, "::ffff:10.0.0.5").allowed);
        assert!(!a("lab.test", 80, "::10.0.0.5").allowed);
        assert!(a("lab.test", 80, "10.0.0.6").allowed);
        // A mapped deny entry covers the plain form.
        let p = pol(NetworkMode::Open, &[], &["[::ffff:10.0.0.5]"], &["10.0.0.0/8"]);
        assert!(!p.check_addr("x.test", 80, ip("10.0.0.5"), "mode open").allowed);
        // CIDR deny entries, public addresses included; the port form only matches its port.
        let p = pol(NetworkMode::Open, &[], &["10.1.0.0/16", "203.0.113.0/24", "8.8.8.8:53", "fd00::/8"], &["10.0.0.0/8", "fd00::/8"]);
        assert_eq!(p.check_addr("x.test", 80, ip("10.1.2.3"), "r").rule, "deny 10.1.0.0/16");
        assert!(!p.check_addr("x.test", 80, ip("203.0.113.9"), "r").allowed);
        assert!(!p.check_addr("x.test", 80, ip("::ffff:203.0.113.9"), "r").allowed);
        assert!(!p.check_addr("x.test", 80, ip("fd12::1"), "r").allowed);
        assert!(!p.check_addr("x.test", 53, ip("8.8.8.8"), "r").allowed);
        assert!(p.check_addr("x.test", 443, ip("8.8.8.8"), "r").allowed);
        assert!(p.check_addr("x.test", 80, ip("10.2.0.1"), "r").allowed);
        // A literal host is refused before resolving; names keep matching names.
        assert_eq!(p.check_name("10.1.2.3", 80).rule, "deny 10.1.0.0/16");
        assert!(p.check_name("10.2.0.1", 80).allowed);
        assert!(Policy::new(&cfg(NetworkMode::Open, &[], &["10.0.0.0/33"], &[])).is_err());
    }

    #[test]
    fn special_ranges_at_edges() {
        let yes = [
            "0.0.0.0", "0.255.255.255", "10.0.0.0", "10.255.255.255", "100.64.0.0", "100.127.255.255", "127.0.0.0",
            "127.255.255.255", "169.254.0.0", "169.254.255.255", "172.16.0.0", "172.31.255.255", "192.0.0.0", "192.0.0.255",
            "192.168.0.0", "192.168.255.255", "198.18.0.0", "198.19.255.255", "224.0.0.0", "239.255.255.255", "240.0.0.0",
            "255.255.255.255", "::", "::1", "fc00::", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "fe80::", "febf:ffff::1",
            "ff00::", "ffff::1", "::ffff:127.0.0.1", "::ffff:10.1.2.3", "::ffff:a9fe:1", "::127.0.0.1", "::ffff:224.0.0.1",
        ];
        for a in yes {
            assert!(is_special(ip(a)), "{a} should be special");
        }
        let no = [
            "1.0.0.0", "9.255.255.255", "11.0.0.0", "100.63.255.255", "100.128.0.0", "126.255.255.255", "128.0.0.0",
            "169.253.255.255", "169.255.0.0", "172.15.255.255", "172.32.0.0", "192.0.1.0", "192.167.255.255", "192.169.0.0",
            "198.17.255.255", "198.20.0.0", "223.255.255.255", "8.8.8.8", "2001:db8::1", "2606:4700::1", "fbff::1", "fec0::1",
            "feff::1", "::ffff:8.8.8.8", "::8.8.8.8", "fe00::1",
        ];
        for a in no {
            assert!(!is_special(ip(a)), "{a} should not be special");
        }
    }

    #[test]
    fn open_mode_refuses_private_addresses() {
        let p = pol(NetworkMode::Open, &[], &[], &[]);
        let v = p.check_addr("localhost", 80, ip("127.0.0.1"), "mode open");
        assert_eq!(v, Verdict { allowed: false, rule: "deny private-address 127.0.0.1".into() });
        let v = p.check_addr("x.test", 80, ip("::ffff:10.0.0.1"), "mode open");
        assert!(!v.allowed);
        let v = p.check_addr("x.test", 80, ip("8.8.8.8"), "mode open");
        assert_eq!(v, Verdict { allowed: true, rule: "mode open".into() });
    }

    #[test]
    fn allow_private_by_name_cidr_and_address() {
        let p = pol(NetworkMode::Open, &[], &[], &["lab.test:8080", "*.corp.test", "10.0.0.0/8", "fd00::/8", "127.0.0.1"]);
        let r = |h: &str, port: u16, a: &str| p.check_addr(h, port, ip(a), "mode open");
        assert_eq!(r("lab.test", 8080, "192.168.1.1").rule, "allow_private lab.test:8080");
        assert!(!r("lab.test", 80, "192.168.1.1").allowed);
        assert_eq!(r("a.corp.test", 1, "172.16.0.1").rule, "allow_private *.corp.test");
        assert!(!r("corp.test", 1, "172.16.0.1").allowed);
        assert_eq!(r("x.test", 1, "10.9.8.7").rule, "allow_private 10.0.0.0/8");
        assert!(!r("x.test", 1, "192.168.9.9").allowed);
        assert_eq!(r("x.test", 1, "fd12::1").rule, "allow_private fd00::/8");
        assert!(!r("x.test", 1, "fe80::1").allowed);
        assert_eq!(r("127.0.0.1", 9, "127.0.0.1").rule, "allow_private 127.0.0.1");
        assert!(!r("x.test", 9, "127.0.0.2").allowed);
        // A mapped form of a listed IPv4 range is covered by the IPv4 entry.
        assert!(r("x.test", 1, "::ffff:10.1.1.1").allowed);
        // Public addresses never need an entry and keep the name rule.
        assert_eq!(r("x.test", 1, "1.1.1.1").rule, "mode open");
    }

    #[test]
    fn cidr_extremes() {
        let p = pol(NetworkMode::Open, &[], &[], &["0.0.0.0/0"]);
        assert!(p.check_addr("x", 1, ip("127.0.0.1"), "r").allowed);
        assert!(!p.check_addr("x", 1, ip("fe80::1"), "r").allowed);
        let p = pol(NetworkMode::Open, &[], &[], &["::/0"]);
        assert!(p.check_addr("x", 1, ip("::1"), "r").allowed);
        let p = pol(NetworkMode::Open, &[], &[], &["192.168.1.7/32"]);
        assert!(p.check_addr("x", 1, ip("192.168.1.7"), "r").allowed);
        assert!(!p.check_addr("x", 1, ip("192.168.1.8"), "r").allowed);
    }
}
