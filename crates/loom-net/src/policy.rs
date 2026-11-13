//! The network policy as a pure function.
//!
//! CONTRACT.
//!
//! ## Patterns (`allow`, `reference_hosts`, `deny`, and the name form of `allow_private`)
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
//!   2. `reference_hosts` matches → refused on the raw command policy, regardless of mode/grants;
//!   3. mode `deny_all` → refused, rule `mode deny_all`;
//!   4. mode `allowlist` and no `allow` pattern matches → refused, rule `not in allow list`;
//!   5. otherwise allowed so far: rule `allow {pattern}` (allowlist) or `mode open`.
//! `check_addr(host, port, addr, name_rule)` — for the address the proxy is about to connect to:
//!   - if `addr` is special (see below): allowed only when an `allow_private` entry matches the
//!     host name pattern (with port), or a CIDR/address entry contains `addr`; rule
//!     `allow_private {entry}`; otherwise refused with rule `deny private-address {addr}`;
//!   - otherwise allowed with `name_rule`.
//! Special addresses: IPv4 0.0.0.0/8, 10/8, 100.64/10, 127/8, 169.254/16, 172.16/12, 192.0.0.0/24,
//! 192.168/16, 198.18/15, 224/4 and above; IPv6 `::`, `::1`, fc00::/7, fe80::/10, ff00::/8, and
//! IPv4-mapped/compatible forms of any special IPv4 address (check the embedded address).
//! IPv6 forms that carry an IPv4 address are judged by that address, and the deny list and
//! `allow_private` see it too: IPv4-mapped, IPv4-compatible, NAT64 (`64:ff9b::/96`, and the local-use
//! `64:ff9b:1::/48` in its /96 form `64:ff9b:1::a.b.c.d`) and 6to4 (`2002:aabb:ccdd::/48` carries
//! `aa.bb.cc.dd`). Also special: the rest of `64:ff9b::/32` (a translator could read an IPv4 address
//! from it in another layout), discard-only `100::/64` and the dummy prefix `100:0:0:1::/64`, the IETF
//! protocol assignments `2001::/23` (Teredo `2001::/32`, benchmarking, ORCHID, ORCHIDv2, DETs) except
//! the globally reachable anycast addresses `2001:1::1`..`2001:1::3`, AMT `2001:3::/32` and AS112
//! `2001:4:112::/48`; documentation `2001:db8::/32` and `3fff::/20`; SRv6 SIDs `5f00::/16`.
//! `deny` and `allow_private` entries written in the mapped, compatible or NAT64 /96 form stand for
//! the IPv4 block they carry, so they cover the plain IPv4 addresses too (a `deny` entry
//! `64:ff9b::/96` is `0.0.0.0/0` and refuses every IPv4 destination); `Policy::new` refuses such an
//! `allow_private` entry wider than /8, which would open most private IPv4 addresses. Entries written
//! in 6to4 form are IPv6 blocks and match 6to4 addresses only (an IPv4 entry covers the 6to4 form).
//! The other /96 subnets and the /48, /56 and /64 layouts of the local-use prefix `64:ff9b:1::/48` are
//! not unwrapped, and a network-specific NAT64 prefix (RFC 6052) is an ordinary IPv6 prefix here: the
//! IPv4 address behind such a prefix is not seen. Listing one in `allow_private` admits every IPv4
//! address behind it, private ones included, and IPv4 `deny` entries do not cover addresses inside it.
//!
//! ## Reference clients — `Policy::reference(cfg)`
//! Allows only `reference_hosts`, retaining deny and resolved-address restrictions. This is separate
//! from command grants: raw `new`/`with_hosts` refuse these names even in open mode. These are name
//! reservations, not data-flow isolation or alias/IP blocking; GET URLs can still carry secrets.
//! `matches_reference` is pattern routing only and does not authorize an address or override deny.
//!
//! ## Per-session grants — `Policy::with_hosts(cfg, hosts)`, `check_hosts(hosts)`
//! `with_hosts` is `Policy::new(cfg)` plus the operator-granted `hosts` (same pattern syntax as `allow`).
//! Mode `deny_all` with at least one host becomes `allowlist` allowing exactly the granted hosts; mode
//! `allowlist` gets them appended to `allow`; mode `open` is unchanged. `deny` and `allow_private` are
//! the config's, so a granted host that is denied, or resolves to a private address, is still refused.
//! An entry that is not a valid pattern is an error sentence naming it. `check_hosts` trims and
//! validates a list of hosts to grant (non-empty, no blank entry, no whitespace or comma inside an
//! entry, each a valid pattern) and returns them as written, trimmed.
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
                return Err(
                    "the host is not a valid name or address (`*` may only appear as `*` or a leading `*.`)".into()
                );
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

    /// An IPv6 address is compared with an IPv4 block in its canonical form (see [`canonical_ip`]), so
    /// `::ffff:10.0.0.5` is in `10.0.0.0/8` and `::1` is not in `0.0.0.0/8`.
    fn contains(&self, addr: IpAddr) -> bool {
        match (self, addr) {
            (IpNet::V4 { base, mask }, IpAddr::V4(a)) => u32::from(a) & mask == *base,
            (IpNet::V6 { base, mask }, IpAddr::V6(a)) => u128::from(a) & mask == *base,
            (IpNet::V4 { .. }, IpAddr::V6(_)) => match canonical_ip(addr) {
                v4 @ IpAddr::V4(_) => self.contains(v4),
                IpAddr::V6(_) => false,
            },
            (IpNet::V6 { .. }, IpAddr::V4(_)) => false,
        }
    }

    /// A block inside the IPv4-mapped range (`::ffff:0:0/96`), inside the IPv4-compatible range with a
    /// non-zero first octet, or inside a NAT64 /96 (`64:ff9b::/96`, `64:ff9b:1::/96`), as the IPv4 block
    /// it stands for; any other block as it is.
    fn canonical(self) -> IpNet {
        let IpNet::V6 { base, mask } = self else { return self };
        let Some(v4_prefix) = mask.count_ones().checked_sub(96) else { return self };
        let v4 = Ipv4Addr::from(u32::try_from(base & u128::from(u32::MAX)).unwrap_or(0));
        let high = base >> 32;
        let mapped = high == 0xffff || high == NAT64_WKP || high == NAT64_LOCAL;
        let compatible = high == 0 && v4_prefix >= 8 && v4.octets().first().is_some_and(|o| *o != 0);
        match u8::try_from(v4_prefix) {
            Ok(p) if mapped || compatible => IpNet::new(IpAddr::V4(v4), p),
            _ => self,
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
            return Ok(PrivEntry::Net { text: text.to_string(), net: IpNet::new(ip, prefix).canonical() });
        }
        if let Ok(ip) = text.parse::<IpAddr>() {
            let full = if ip.is_ipv4() { 32 } else { 128 };
            return Ok(PrivEntry::Net { text: text.to_string(), net: IpNet::new(ip, full).canonical() });
        }
        Pattern::parse(text).map(PrivEntry::Name)
    }

    /// An `allow_private` entry: as [`PrivEntry::parse`], but a block written in an IPv6 form that
    /// stands for an IPv4 block wider than /8 is refused.
    fn parse_private(entry: &str) -> Result<PrivEntry, String> {
        let e = PrivEntry::parse(entry)?;
        if let PrivEntry::Net { text, net: IpNet::V4 { base, mask } } = &e {
            let prefix = mask.count_ones();
            if prefix < 8 && text.contains(':') {
                return Err(format!(
                    "it stands for the IPv4 block {}/{prefix} (an IPv6 address in this form is judged by the IPv4 address it carries), so it would allow most private IPv4 addresses; list the IPv4 blocks that are meant instead",
                    Ipv4Addr::from(*base)
                ));
            }
        }
        Ok(e)
    }
}

/// A parsed, validated network policy.
#[derive(Clone, Debug)]
pub struct Policy {
    mode: NetworkMode,
    allow: Vec<Pattern>,
    reference_hosts: Vec<Pattern>,
    /// Host patterns, plus address entries (literals and CIDR blocks) that also match resolved addresses.
    deny: Vec<PrivEntry>,
    allow_private: Vec<PrivEntry>,
}

fn grant_pattern(host: &str) -> Result<Pattern, String> {
    Pattern::parse(host).map_err(|why| {
        format!(
            "The host \"{host}\" cannot be authorized: {why}. Write a host (`example.test`) or a wildcard (`*.example.test`), optionally followed by `:port`."
        )
    })
}

/// Validate hosts to be granted to a session: at least one, none blank, one host per entry, each a valid
/// pattern. Returned trimmed. The errors are sentences for the operator or the model.
pub fn check_hosts(hosts: &[String]) -> Result<Vec<String>, String> {
    if hosts.is_empty() {
        return Err(
            "Name at least one host, one per entry, such as `api.example.test` or `*.example.test`.".to_string()
        );
    }
    let mut out = Vec::new();
    for h in hosts {
        let h = h.trim();
        if h.is_empty() {
            return Err("A host is blank. Give one host per entry, such as `api.example.test`, and no empty entries."
                .to_string());
        }
        if h.chars().any(|c| c.is_whitespace() || c == ',') {
            return Err(format!("The host entry \"{h}\" contains whitespace or a comma. Give one host per entry."));
        }
        grant_pattern(h)?;
        out.push(h.to_string());
    }
    Ok(out)
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
            reference_hosts: parse_list("reference_hosts", &cfg.reference_hosts, Pattern::parse)?,
            deny: parse_list("deny", &cfg.deny, PrivEntry::parse)?,
            allow_private: parse_list("allow_private", &cfg.allow_private, PrivEntry::parse_private)?,
        })
    }

    /// Reference-only policy for trusted in-process GET clients. Deny/address checks still apply.
    pub fn reference(cfg: &NetworkCfg) -> Result<Policy, String> {
        let mut policy = Self::new(cfg)?;
        policy.mode = NetworkMode::Allowlist;
        policy.allow = std::mem::take(&mut policy.reference_hosts);
        Ok(policy)
    }

    /// Whether the configuration reserves this destination for the in-process reference client.
    pub fn matches_reference(&self, host: &str, port: u16) -> bool {
        let h = normalize_host(host);
        self.reference_hosts.iter().any(|p| p.matches(&h, port))
    }

    /// The policy of `cfg` with `hosts` granted on top (see the module contract). The hosts are not
    /// trimmed here: pass them through [`check_hosts`] first.
    pub fn with_hosts(cfg: &NetworkCfg, hosts: &[String]) -> Result<Policy, String> {
        let mut policy = Policy::new(cfg)?;
        if hosts.is_empty() || policy.mode == NetworkMode::Open {
            return Ok(policy);
        }
        for h in hosts {
            policy.allow.push(grant_pattern(h)?);
        }
        policy.mode = NetworkMode::Allowlist;
        Ok(policy)
    }

    pub fn check_name(&self, host: &str, port: u16) -> Verdict {
        let h = normalize_host(host);
        if let Some(rule) = self.deny_hit(&h, port, h.parse::<IpAddr>().ok()) {
            return Verdict::no(rule);
        }
        if self.matches_reference(&h, port) {
            return Verdict::no("reference host requires the in-process GET client");
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

    /// The `deny ...` rule that matches the name, or the address when there is one. Addresses and
    /// address entries are compared in canonical form, so `::ffff:10.0.0.5` is `10.0.0.5`.
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
                    if addr.is_some_and(|a| net.contains(a)) {
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

/// The first 96 bits of the NAT64 well-known prefix `64:ff9b::/96`.
const NAT64_WKP: u128 = 0x0064_ff9b_0000_0000_0000_0000;
/// The first 96 bits of `64:ff9b:1::/96`, the /96 form of the local-use NAT64 prefix `64:ff9b:1::/48`.
const NAT64_LOCAL: u128 = 0x0064_ff9b_0001_0000_0000_0000;

/// The IPv4 address an IPv6 address carries: IPv4-mapped (`::ffff:a.b.c.d`), IPv4-compatible
/// (`::a.b.c.d`), NAT64 (`64:ff9b::a.b.c.d`, `64:ff9b:1::a.b.c.d`) or 6to4 (`2002:aabb:ccdd::/48`).
fn embedded_v4(a: Ipv6Addr) -> Option<Ipv4Addr> {
    let v4 = |hi: u16, lo: u16| {
        let ([a0, a1], [a2, a3]) = (hi.to_be_bytes(), lo.to_be_bytes());
        Ipv4Addr::new(a0, a1, a2, a3)
    };
    match a.segments() {
        [0, 0, 0, 0, 0, 0 | 0xffff, hi, lo] | [0x64, 0xff9b, 0 | 1, 0, 0, 0, hi, lo] | [0x2002, hi, lo, ..] => {
            Some(v4(hi, lo))
        }
        _ => None,
    }
}

/// IPv6 addresses that carry an IPv4 address (see [`embedded_v4`]) as that address; `::`, `::1` and the
/// other IPv4-compatible addresses in `::/104` stay IPv6 addresses.
fn canonical_ip(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(a) => match (embedded_v4(a), a.segments()) {
            (Some(v4), [0, 0, 0, 0, 0, 0, ..]) if v4.octets().first() == Some(&0) => addr,
            (Some(v4), _) => IpAddr::V4(v4),
            (None, _) => addr,
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
            special_v6(a)
        }
    }
}

/// The IPv6 ranges of the module contract that carry no IPv4 address [`embedded_v4`] can read.
fn special_v6(a: Ipv6Addr) -> bool {
    let [s0, s1, s2, s3, s4, s5, s6, s7] = a.segments();
    // The globally reachable parts of 2001::/23: the PCP, TURN and DNS-SD SRP anycast addresses
    // (2001:1::1 to 2001:1::3), AMT (2001:3::/32) and AS112-v6 (2001:4:112::/48).
    let anycast = s1 == 1 && s2 == 0 && s3 == 0 && s4 == 0 && s5 == 0 && s6 == 0 && (1..=3).contains(&s7);
    let global_ietf = anycast || s1 == 3 || (s1 == 4 && s2 == 0x112);
    (s0 & 0xfe00) == 0xfc00
        || (s0 & 0xffc0) == 0xfe80
        || (s0 & 0xff00) == 0xff00
        || (s0 == 0x64 && s1 == 0xff9b)
        || (s0 == 0x100 && s1 == 0 && s2 == 0 && s3 <= 1)
        || (s0 == 0x2001 && s1 < 0x200 && !global_ietf)
        || (s0 == 0x2001 && s1 == 0xdb8)
        || (s0 == 0x3fff && s1 < 0x1000)
        || s0 == 0x5f00
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(mode: NetworkMode, allow: &[&str], deny: &[&str], private: &[&str]) -> NetworkCfg {
        let v = |x: &[&str]| x.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        NetworkCfg { mode, allow: v(allow), deny: v(deny), allow_private: v(private), ..NetworkCfg::default() }
    }
    fn pol(mode: NetworkMode, allow: &[&str], deny: &[&str], private: &[&str]) -> Policy {
        Policy::new(&cfg(mode, allow, deny, private)).unwrap()
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn reference_hosts_are_separate_even_with_open_mode_and_session_grants() {
        let mut cfg = cfg(NetworkMode::Open, &["*"], &["blocked.reference.test"], &[]);
        cfg.reference_hosts = vec!["*.reference.test:443".into()];
        for raw in [Policy::new(&cfg).unwrap(), Policy::with_hosts(&cfg, &["api.reference.test:443".into()]).unwrap()] {
            assert!(!raw.check_name("API.Reference.Test.", 443).allowed);
            assert!(raw.check_name("api.reference.test", 80).allowed);
            assert!(raw.check_name("active.test", 443).allowed);
        }
        let reference = Policy::reference(&cfg).unwrap();
        assert!(reference.check_name("api.reference.test", 443).allowed);
        assert!(!reference.check_name("api.reference.test", 80).allowed);
        assert!(!reference.check_name("blocked.reference.test", 443).allowed);
        assert!(!reference.check_name("active.test", 443).allowed);
        assert!(!reference.check_addr("api.reference.test", 443, "127.0.0.1".parse().unwrap(), "allowed").allowed);
        cfg.mode = NetworkMode::DenyAll;
        assert!(Policy::reference(&cfg).unwrap().check_name("api.reference.test", 443).allowed);
        cfg.reference_hosts = vec!["bad host".into()];
        assert!(Policy::new(&cfg).is_err());
    }

    #[test]
    fn granted_hosts_widen_deny_all_and_allowlist_but_not_open_and_not_past_deny_or_private() {
        let c = cfg(NetworkMode::DenyAll, &[], &["bad.test"], &[]);
        let hosts = |h: &[&str]| h.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let p = Policy::with_hosts(&c, &hosts(&["a.test", "*.b.test:443"])).unwrap();
        assert!(p.check_name("a.test", 80).allowed);
        assert!(p.check_name("x.b.test", 443).allowed);
        assert!(!p.check_name("x.b.test", 80).allowed);
        assert_eq!(p.check_name("other.test", 80).rule, "not in allow list");
        // Nothing granted: still deny_all.
        assert_eq!(Policy::with_hosts(&c, &[]).unwrap().check_name("a.test", 80).rule, "mode deny_all");

        let base = cfg(NetworkMode::Allowlist, &["base.test"], &["bad.test"], &[]);
        let p = Policy::with_hosts(&base, &hosts(&["a.test", "bad.test"])).unwrap();
        assert!(p.check_name("base.test", 80).allowed && p.check_name("a.test", 80).allowed);
        assert!(!p.check_name("other.test", 80).allowed);
        // The deny list beats a grant.
        assert_eq!(p.check_name("bad.test", 80).rule, "deny bad.test");
        // A granted name that resolves to a private address is still refused.
        let v = p.check_addr("a.test", 80, ip("10.1.2.3"), "allow a.test");
        assert!(!v.allowed && v.rule.starts_with("deny private-address"), "{v:?}");
        assert!(p.check_addr("a.test", 80, ip("93.184.216.34"), "allow a.test").allowed);

        let open = Policy::with_hosts(&cfg(NetworkMode::Open, &[], &[], &[]), &hosts(&["a.test"])).unwrap();
        assert_eq!(open.check_name("anything.test", 80).rule, "mode open");
    }

    #[test]
    fn granted_hosts_are_validated() {
        let c = cfg(NetworkMode::DenyAll, &[], &[], &[]);
        let bad = |h: &str| Policy::with_hosts(&c, &[h.to_string()]).unwrap_err();
        assert!(bad("bad host").contains("\"bad host\" cannot be authorized"));
        assert!(bad("a*b.test").contains("cannot be authorized"));
        assert!(bad("x.test:99999").contains("cannot be authorized"));
        let s = |h: &[&str]| check_hosts(&h.iter().map(|x| x.to_string()).collect::<Vec<_>>());
        assert_eq!(s(&[" a.test ", "*.b.test"]).unwrap(), ["a.test", "*.b.test"]);
        assert!(s(&[]).unwrap_err().contains("at least one host"));
        assert!(s(&["a.test", "  "]).unwrap_err().contains("blank"));
        assert!(s(&["a.test,b.test"]).unwrap_err().contains("one host per entry"));
        assert!(s(&["a b"]).unwrap_err().contains("one host per entry"));
        assert!(s(&["a*b"]).unwrap_err().contains("cannot be authorized"));
    }

    #[test]
    fn good_entries_parse() {
        for e in [
            "example.test",
            "*.example.test",
            "example.test:443",
            "*",
            "*:80",
            "[::1]:8080",
            "::1",
            "10.0.0.1",
            "*.a-b.c_d",
        ] {
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
        for e in [
            "",
            "  ",
            "a*b.test",
            "*.",
            "*.*.test",
            "ex.test:",
            "ex.test:x",
            "[::1",
            "[::1]x",
            "[abc]:1",
            "a/b",
            "1.2.3.4/x",
            "fd00::/129",
            "x/8",
        ] {
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
        // A mapped deny entry covers the plain form, bracketed, bare, or as a mapped block.
        for entry in ["[::ffff:10.0.0.5]", "::ffff:10.0.0.5", "::ffff:10.0.0.0/104", "::10.0.0.5"] {
            let p = pol(NetworkMode::Open, &[], &[entry], &["10.0.0.0/8"]);
            for addr in ["10.0.0.5", "::ffff:10.0.0.5"] {
                let v = p.check_addr("x.test", 80, ip(addr), "mode open");
                assert_eq!(v.rule, format!("deny {entry}"), "{entry} {addr}");
            }
            assert!(p.check_addr("x.test", 80, ip("11.0.0.5"), "mode open").allowed, "{entry}");
        }
        // `::1` and `::` are IPv6 addresses, not members of an IPv4 block that holds 0.0.0.1 or 0.0.0.0.
        let p = pol(NetworkMode::Open, &[], &["0.0.0.0/8"], &["::1", "::"]);
        assert_eq!(p.check_addr("x.test", 80, ip("::1"), "r").rule, "allow_private ::1");
        assert_eq!(p.check_addr("x.test", 80, ip("::"), "r").rule, "allow_private ::");
        assert_eq!(p.check_addr("x.test", 80, ip("0.0.0.1"), "r").rule, "deny 0.0.0.0/8");
        let p = pol(NetworkMode::Open, &[], &[], &["0.0.0.0/0"]);
        assert!(!p.check_addr("x.test", 80, ip("::1"), "r").allowed);
        assert!(p.check_addr("x.test", 80, ip("::ffff:127.0.0.1"), "r").allowed);
        // CIDR deny entries, public addresses included; the port form only matches its port.
        let p = pol(
            NetworkMode::Open,
            &[],
            &["10.1.0.0/16", "203.0.113.0/24", "8.8.8.8:53", "fd00::/8"],
            &["10.0.0.0/8", "fd00::/8"],
        );
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
            "0.0.0.0",
            "0.255.255.255",
            "10.0.0.0",
            "10.255.255.255",
            "100.64.0.0",
            "100.127.255.255",
            "127.0.0.0",
            "127.255.255.255",
            "169.254.0.0",
            "169.254.255.255",
            "172.16.0.0",
            "172.31.255.255",
            "192.0.0.0",
            "192.0.0.255",
            "192.168.0.0",
            "192.168.255.255",
            "198.18.0.0",
            "198.19.255.255",
            "224.0.0.0",
            "239.255.255.255",
            "240.0.0.0",
            "255.255.255.255",
            "::",
            "::1",
            "fc00::",
            "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "fe80::",
            "febf:ffff::1",
            "ff00::",
            "ffff::1",
            "::ffff:127.0.0.1",
            "::ffff:10.1.2.3",
            "::ffff:a9fe:1",
            "::127.0.0.1",
            "::ffff:224.0.0.1",
        ];
        for a in yes {
            assert!(is_special(ip(a)), "{a} should be special");
        }
        let no = [
            "1.0.0.0",
            "9.255.255.255",
            "11.0.0.0",
            "100.63.255.255",
            "100.128.0.0",
            "126.255.255.255",
            "128.0.0.0",
            "169.253.255.255",
            "169.255.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "192.0.1.0",
            "192.167.255.255",
            "192.169.0.0",
            "198.17.255.255",
            "198.20.0.0",
            "223.255.255.255",
            "8.8.8.8",
            "2606:4700::1",
            "fbff::1",
            "fec0::1",
            "feff::1",
            "::ffff:8.8.8.8",
            "::8.8.8.8",
            "fe00::1",
        ];
        for a in no {
            assert!(!is_special(ip(a)), "{a} should not be special");
        }
    }

    /// `v4` as NAT64 (well-known and local-use prefix) and 6to4 addresses.
    fn carried(v4: &str) -> [String; 3] {
        let n = u32::from(v4.parse::<Ipv4Addr>().unwrap());
        [format!("64:ff9b::{v4}"), format!("64:ff9b:1::{v4}"), format!("2002:{:x}:{:x}::1", n >> 16, n & 0xffff)]
    }

    #[test]
    fn ipv6_forms_that_carry_an_ipv4_address_are_judged_by_it() {
        let open = pol(NetworkMode::Open, &[], &[], &[]);
        let al = pol(NetworkMode::Allowlist, &["x.test"], &[], &[]);
        for v4 in ["10.0.0.5", "127.0.0.1", "169.254.169.254"] {
            let listed = pol(NetworkMode::Allowlist, &["x.test"], &[], &[v4]);
            for a in carried(v4) {
                assert!(is_special(ip(&a)), "{a}");
                assert_eq!(canonical_ip(ip(&a)), ip(v4), "{a}");
                let v = open.check_addr("x.test", 443, ip(&a), "mode open");
                assert_eq!(v, Verdict { allowed: false, rule: format!("deny private-address {}", ip(&a)) }, "{a}");
                assert!(!al.check_addr("x.test", 443, ip(&a), &al.check_name("x.test", 443).rule).allowed, "{a}");
                assert_eq!(
                    listed.check_addr("x.test", 443, ip(&a), "allow x.test").rule,
                    format!("allow_private {v4}")
                );
            }
        }
        // A public address inside them keeps the name rule.
        for a in carried("8.8.8.8") {
            assert!(!is_special(ip(&a)), "{a}");
            assert_eq!(open.check_addr("x.test", 443, ip(&a), "mode open"), Verdict::yes("mode open"), "{a}");
            assert_eq!(al.check_addr("x.test", 443, ip(&a), "allow x.test"), Verdict::yes("allow x.test"), "{a}");
        }
        // A deny entry on the carried address wins, also over allow_private and before resolving a literal.
        let p = pol(NetworkMode::Open, &[], &["10.0.0.5", "8.8.8.0/24"], &["10.0.0.0/8"]);
        for a in carried("10.0.0.5") {
            assert_eq!(p.check_addr("x.test", 80, ip(&a), "mode open").rule, "deny 10.0.0.5", "{a}");
            assert_eq!(p.check_name(&format!("[{a}]"), 80).rule, "deny 10.0.0.5", "{a}");
        }
        for a in carried("8.8.8.8") {
            assert_eq!(p.check_addr("x.test", 80, ip(&a), "mode open").rule, "deny 8.8.8.0/24", "{a}");
        }
        assert!(p.check_addr("x.test", 80, ip("64:ff9b::10.0.0.6"), "mode open").allowed);
        // Entries written in these forms cover the plain IPv4 address.
        let p = pol(NetworkMode::Open, &[], &["64:ff9b::10.0.0.5", "64:ff9b::a01:0/112"], &[]);
        assert_eq!(p.check_addr("x.test", 80, ip("10.0.0.5"), "r").rule, "deny 64:ff9b::10.0.0.5");
        assert_eq!(p.check_addr("x.test", 80, ip("2002:a01:203::1"), "r").rule, "deny 64:ff9b::a01:0/112");
        // So a NAT64 or mapped /96 is all of IPv4: refused in allow_private, every IPv4 address in deny.
        for entry in ["64:ff9b::/96", "64:ff9b:1::/96", "::ffff:0:0/96", "64:ff9b::/100"] {
            let e = Policy::new(&cfg(NetworkMode::Open, &[], &[], &[entry])).unwrap_err();
            assert!(e.contains("network.allow_private") && e.contains("stands for the IPv4 block 0.0.0.0/"), "{e}");
        }
        let p = pol(NetworkMode::Open, &[], &["64:ff9b::/96"], &[]);
        assert_eq!(p.check_addr("x.test", 80, ip("8.8.8.8"), "r").rule, "deny 64:ff9b::/96");
        let p = pol(NetworkMode::Open, &[], &[], &["64:ff9b::a00:0/104"]);
        assert_eq!(p.check_addr("x.test", 80, ip("10.1.2.3"), "r").rule, "allow_private 64:ff9b::a00:0/104");
        assert!(!p.check_addr("x.test", 80, ip("127.0.0.1"), "r").allowed);
        // An entry in 6to4 form is an IPv6 block: it matches 6to4 addresses only.
        let p = pol(NetworkMode::Open, &[], &["2002:a00:5::/48"], &["10.0.0.0/8"]);
        assert_eq!(p.check_addr("x.test", 80, ip("2002:a00:5::1"), "r").rule, "deny 2002:a00:5::/48");
        assert_eq!(p.check_addr("x.test", 80, ip("10.0.0.5"), "r").rule, "allow_private 10.0.0.0/8");
        // Teredo, and local-use NAT64 addresses outside the /96 form, carry nothing the policy reads.
        let teredo = "2001:0:4136:e378:8000:63bf:3fff:fdd2";
        for a in [teredo, "64:ff9b:1:1::808:808", "64:ff9b:2::808:808"] {
            assert!(!open.check_addr("x.test", 443, ip(a), "mode open").allowed, "{a}");
        }
        let listed = pol(NetworkMode::Open, &[], &[], &["2001::/32"]);
        assert_eq!(listed.check_addr("x.test", 443, ip(teredo), "mode open").rule, "allow_private 2001::/32");
    }

    #[test]
    fn other_special_ipv6_ranges_at_edges() {
        let yes = [
            "100::",
            "100::1:0:0:0",
            "100:0:0:1:ffff:ffff:ffff:ffff",
            "2001::",
            "2001:0:ffff::1",
            "2001:1::4",
            "2001:2::1",
            "2001:10::1",
            "2001:20::1",
            "2001:3f::1",
            "2001:1ff:ffff::1",
            "2001:db8::",
            "2001:db8:ffff::1",
            "3fff::",
            "3fff:fff:ffff::1",
            "5f00::",
            "5f00:ffff::1",
            "64:ff9b:1:1::1",
            "64:ff9b:2::1",
            "64:ff9b:ffff::1",
        ];
        for a in yes {
            assert!(is_special(ip(a)), "{a} should be special");
        }
        let no = [
            "100:0:0:2::",
            "ff::1",
            "101::1",
            "2001:1::1",
            "2001:1::2",
            "2001:1::3",
            "2001:3::1",
            "2001:4:112::1",
            "2001:200::",
            "2001:db7:ffff::1",
            "2001:db9::",
            "3ffe:ffff::1",
            "3fff:1000::",
            "5eff:ffff::1",
            "5f01::",
            "64:ff9a::1",
            "64:ff9c::1",
            "2620:4f:8000::1",
            "2003::1",
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
        let p =
            pol(NetworkMode::Open, &[], &[], &["lab.test:8080", "*.corp.test", "10.0.0.0/8", "fd00::/8", "127.0.0.1"]);
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
