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
//! ## Implicit infrastructure deny (E1) — `Policy::new`, `Policy::with_infrastructure(spec)`
//! Every policy refuses a fixed list of infrastructure **before anything else, grants included** (a
//! granted host, a literal grant, `allow_private` and `mode open` do not lift it), in `check_name` and in
//! `check_addr` (so a name that resolves to one of them is refused, and an address written in any form):
//! rule `deny infrastructure: {what}`. `Policy::new` always has: cloud metadata (169.254.0.0/16,
//! `fd00:ec2::254`, `100.100.100.200`, `192.0.0.192`, and the cloud metadata names below, on every port) and, on this machine (`127.0.0.0/8`, `::1`, the unspecified
//! addresses and their IPv6 forms, `localhost`, `*.localhost`), the DevTools and inspector ports 9222 and
//! 9229 and the Docker API ports 2375 and 2376. `with_infrastructure` adds what the daemon knows:
//! `InfraSpec.daemon_port` (this machine's loopback, that port), `model_endpoints` (`host:port` of each
//! profile's `base_url`), `docker_hosts` (the box's Docker host: its ssh target's host name, and the
//! `hostname` ssh resolves it to; every port), `services` (what the daemon itself talks to for the operator, as
//! `(config key, host:port)`: the Signal bridge's `signal.http_url` and the mail inbox's `mail.host`, each on its
//! port as a model endpoint is, rule `deny infrastructure: {key} {host:port}`) and `extra`
//! (`network.infrastructure`, same grammar as `deny`, CIDR blocks too). An entry naming this machine
//! (`localhost`, a loopback or unspecified literal) is a rule for the machine, so the name and every
//! address spelling are one thing; any other IP literal is its exact address (and port). A name entry
//! matches the name only, so the daemon also passes `InfraSpec.resolved`: the addresses it resolved for
//! those names (each an exact-address rule on the entry's port, every port for a Docker host), which
//! refuse the same host reached by an IP literal (granted or not), a short name or an alias, and
//! `InfraSpec.local_addrs`: this machine's own interface addresses, which are this machine for every
//! loopback rule (a listener on `0.0.0.0` or `[::]` answers on its LAN, tailnet and global addresses).
//! A name that resolved to nothing, or addresses that changed since, are covered only as the daemon last
//! resolved them. `Policy::infrastructure_refusal(entry)` names the rule that refuses a grant entry
//! (its IP literal, with its port, or every port when it has none), for the early sentence;
//! `Policy::infrastructure_on_some_port(host)` names a rule that refuses a host (no port) on any port at all, such as
//! a service on its own port (what a grant of the host without a port leaves refused). Cloud
//! metadata names are `metadata`, `instance-data`, `metadata.goog` and `metadata.*` / `instance-data.*`
//! under `.internal` (not `metadata.target.example`, an ordinary host). The ferret proxy's own listeners (every other
//! session's port) are refused by the proxy itself (`deny the egress proxy's own port`), not here. An
//! entry that cannot be parsed is an error sentence naming the entry and its list.
//!
//! ## Revoked hosts — `Policy::with_revoked(hosts)`
//! The operator's revokes of a mission's grants (`Runtime::revoke_scope`): each entry (as granted, a host,
//! `*.suffix`, an IP literal, optionally with a port) is refused in `check_name` and `check_addr`, rule
//! `deny revoked {entry}`, right after infrastructure and before `deny`, so a wildcard grant that also
//! covers the host, `allow`, `mode open` and `allow_private` do not let it through. An entry that cannot
//! be read is an error sentence naming it.
//!
//! ## Decision — `check_name(host, port)` runs before resolving, `check_addr` after
//! `check_name`, first match wins:
//!   0. an infrastructure rule matches → refused, rule `deny infrastructure: {what}` (above);
//!   0b. a revoked entry matches → refused, rule `deny revoked {entry}`;
//!   1. `deny` pattern matches → refused, rule `deny {pattern}`;
//!   2. `reference_hosts` matches → refused on the raw command policy, regardless of mode/grants;
//!   3. mode `deny_all` → refused, rule `mode deny_all`;
//!   4. mode `allowlist` and no `allow` pattern matches → refused, rule `not in allow list`;
//!   5. otherwise allowed so far: rule `allow {pattern}` (allowlist) or `mode open`.
//! `check_addr(host, port, addr, name_rule)` — for the address the proxy is about to connect to:
//!   - an infrastructure rule matching the name or the address refuses it first;
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
//! Mode `deny_all` with at least one host becomes `allowlist` allowing exactly the granted hosts: the
//! configured `allow` list is not in force under `deny_all`, so it is emptied first and a grant never
//! switches it on. Mode `allowlist` gets them appended to `allow`; mode `open` is unchanged. `deny` and
//! `allow_private` are the config's, so a granted host that is denied, or resolves to a private address,
//! is still refused. An entry that is not a valid pattern is an error sentence naming it. `with_hosts`
//! does not apply the refusals of `check_hosts` below: hosts restored from a ledger written before them
//! are honoured as they were granted.
//!
//! `check_hosts` trims and validates a list of hosts to grant (non-empty, no blank entry, no whitespace
//! or comma inside an entry, each a valid pattern) and returns them as written, trimmed. It is the check
//! of both a model's `request_scope` and the operator's grant (`Runtime::grant_scope`, which the approve
//! action of a scope request calls with the hosts the model wrote), and it also refuses, each with a
//! sentence that names the entry, says why and what to write instead, and grants nothing of the list:
//! - `*` with or without a port: it would authorize every host;
//! - a wildcard over a single label, `*.{label}` with or without a port (`*.com`, `*.io`, `*.htb`): it
//!   would authorize a whole top-level domain; a wildcard under a domain (`*.example.test`) is kept. A
//!   public suffix of more than one label (`*.co.uk`) is not recognised, nor is a domain whose names
//!   resolve to whatever address the name spells (wildcard DNS such as `*.nip.io`);
//! - a wildcard whose last label is a number as the system's address parser reads one: all digits
//!   (`*.0.1`, `*.1.168.192:80`, octal `*.8.010`) or `0x`/`0X` and hex digits (`*.8.0x8`): no top-level
//!   domain is numeric, and the resolver reads `a.b.8.0x8` as the address `a.b.8.8`, so it can only match
//!   addresses written as host names, a whole range of them;
//! - an IP literal that is unspecified or in `0.0.0.0/8` (`0.0.0.0`, `0.0.0.0:8080`, `0.1.2.3`, `::`,
//!   `[::]:80`), also in an IPv6 form that carries such an IPv4 address (`[::ffff:0.0.0.0]`): a literal
//!   grant unlocks its exact address against the private-address rule (below), and a connection to the
//!   unspecified address reaches this machine's own services;
//! - a loopback IP literal without a port (`127.0.0.1`, `127.1.2.3`, `[::1]`, `[::ffff:127.0.0.1]`): it would
//!   unlock every service listening on this machine's loopback; the sentence asks for the port
//!   (`127.0.0.1:8080`). With a port it is kept. A grant of one of this machine's own non-loopback
//!   addresses (its LAN address, say) is not recognised as this machine.
//!
//! **Loopback/private literals granted to a session unlock that exact address**: a granted host that is
//! an IP literal (`127.0.0.1`, `[::1]:8080`, `10.0.0.5:443`) additionally authorizes connections to that
//! exact address (and port, when written) even though the address is private/loopback — an operator
//! typing a lab target's literal address into a mission grant means exactly that address and nothing
//! else. Names granted are not unlocked this way even when they resolve to a private address: opting into
//! name resolution for private destinations stays with `allow_private`. `deny` still wins over a literal
//! grant.
//!
//! `Verdict::allowed` + `rule` are what the proxy reports. Everything here is deterministic and does
//! no I/O.
//!
//! Tests required: pattern parsing (good and bad entries); wildcard semantics incl. the apex not
//! matching; port-specific patterns; case and trailing dot; each numbered rule and their order (deny
//! beats allow); every special range at its edges (first/last address in, neighbours out); mapped
//! IPv6; `allow_private` by name, by CIDR and by address; open mode still refuses private addresses.
//! `with_hosts` under `deny_all` with a non-empty configured `allow` and one granted host: the granted
//! host is allowed and every `allow` entry is refused (`not in allow list`); under `allowlist` both are
//! allowed. `check_hosts` refuses `*`, `*:443`, `*.com`, `*.com:443`, `*.0.1`, `*.1.168.192:80`, `*.8.0x8`,
//! `*.8.0XfF`, `*.8.010`, `0.0.0.0`,
//! `0.0.0.0:8080`, `0.1.2.3`, `::`, `[::]`, `[::]:80`, `[::ffff:0.0.0.0]`, `127.0.0.1`, `127.1.2.3`, `[::1]`,
//! `::1` and `[::ffff:127.0.0.1]` with a sentence naming the entry, refuses a list holding one of them
//! besides valid hosts, and accepts `*.example.test`, `*.a1.example.test`, `*.0xide.example.test`, `api.example.test:443`,
//! `127.0.0.1:19201`, `10.0.0.5` and `[::1]:8080`. Infrastructure: with `mode open`, a literal grant of
//! `169.254.169.254`, `127.0.0.1:9222`, `127.0.0.1:2375`, `[::1]:9229`, `metadata.google.internal`,
//! `127.0.0.1:{daemon_port}` and a model endpoint, and `allow_private` covering them, each refused with
//! the infrastructure rule, by name and by resolved address (`localhost` resolving to 127.0.0.1,
//! `::ffff:127.0.0.1`, `0.0.0.0`) and with the rule's port respected (another loopback port is allowed);
//! `network.infrastructure` entries (name, `host:port`, CIDR) refuse and a bad entry is a sentence;
//! `docker_hosts` refuse every port; the infrastructure rule comes before `deny`; resolved addresses of a
//! model endpoint and a Docker host refuse a literal grant of that address (`infrastructure_refusal`
//! names it too); this machine's own addresses refuse the loopback rules' ports; `metadata.target.test`
//! is an ordinary host; a revoked host is refused (`deny revoked`) in open mode, under a covering wildcard
//! grant and by address, and its sibling hosts are not.

#![allow(clippy::doc_lazy_continuation)]

use ferret_core::config::{NetworkCfg, NetworkMode};
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

/// True when the host pattern `pattern` (the grammar of `allow` and of operator grants: `host`, `*.suffix`,
/// optionally `:port`) covers `host`. With `port` of `None` a port written in the pattern is ignored, so the answer is
/// "does this grant cover the host on some port". A wildcard covers its subdomains, never the apex. An invalid
/// pattern covers nothing.
pub fn pattern_covers(pattern: &str, host: &str, port: Option<u16>) -> bool {
    let Ok(p) = Pattern::parse(pattern) else { return false };
    let h = normalize_host(host);
    match port {
        Some(port) => p.matches(&h, port),
        None => {
            let any_port = Pattern { port: None, ..p };
            any_port.matches(&h, 0)
        }
    }
}

/// True when an entry of a mission target's `scope` or `exclude` (the grammar of [`Policy::with_target`]: a host
/// pattern as [`pattern_covers`] reads it, an IP literal, or a CIDR block) covers `host` (a name, or an address that a
/// literal or a block holds). `port` is as in [`pattern_covers`]. An invalid entry covers nothing.
pub fn scope_entry_covers(entry: &str, host: &str, port: Option<u16>) -> bool {
    match PrivEntry::parse(entry) {
        Ok(PrivEntry::Net { net, .. }) => normalize_host(host).parse::<IpAddr>().is_ok_and(|a| net.contains(a)),
        Ok(PrivEntry::Name(_)) => pattern_covers(entry, host, port),
        Err(_) => false,
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
    /// IP literals granted to this session (with optional port): exact addresses that may be reached
    /// even though they are private/loopback/link-local. See the module contract.
    granted_private: Vec<(IpAddr, Option<u16>)>,
    /// Address blocks of a mission target's scope (`with_target`): reachable by address, private or not.
    target_nets: Vec<(String, IpNet)>,
    /// The implicit infrastructure deny list (E1): checked before everything else, beating grants.
    infra: Vec<InfraRule>,
    /// Hosts the operator revoked from the session's grants: refused right after infrastructure, whatever
    /// else allows them (a wildcard grant, `allow`, `mode open`).
    revoked: Vec<PrivEntry>,
    /// This machine's own interface addresses (canonical), for the loopback infrastructure rules.
    local_addrs: Vec<IpAddr>,
}

/// What the daemon knows about its own infrastructure, for [`Policy::with_infrastructure`]. Every field
/// is a list of entries in the grammar of `network.deny` (a host, `*.suffix` or `host:port`; the
/// `infrastructure` and `docker_hosts` lists also take CIDR blocks), or a port.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InfraSpec {
    /// The port the ferret daemon listens on (loopback). Denied on every loopback and unspecified address
    /// and on `localhost`, whatever name led there.
    pub daemon_port: Option<u16>,
    /// The `host:port` of every model endpoint of the configuration (`base_url` without scheme and path).
    pub model_endpoints: Vec<String>,
    /// The Docker hosts of the box (its `ssh_host`), refused on every port.
    pub docker_hosts: Vec<String>,
    /// `network.infrastructure`: anything else the operator wants refused to every command (tailnet
    /// infrastructure, desktop-app ports). Written like `network.deny`.
    pub extra: Vec<String>,
    /// The services the daemon talks to for the operator, as `(config key, host:port)`: the Signal bridge's
    /// signal-cli (`signal.http_url`) and the mail inbox's IMAP server (`mail.host`). Refused on their port, as a
    /// model endpoint is: a command that reached signal-cli could read the operator's replies or send as the bridge.
    pub services: Vec<(String, String)>,
    /// Addresses the daemon resolved for the name entries above (the box's Docker host and its ssh
    /// alias, model endpoints, `network.infrastructure` names): each is refused as an address, so a literal
    /// grant, a short name or an IP alias of the same host is refused too.
    pub resolved: Vec<InfraAddr>,
    /// This machine's own interface addresses (LAN, tailnet, global IPv6): they count as this machine
    /// for every loopback rule, since a listener bound to `0.0.0.0` or `[::]` answers on them.
    pub local_addrs: Vec<IpAddr>,
}

/// One address that is infrastructure, with the port it is refused on (`None`: every port).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InfraAddr {
    /// What the address is (`Docker host ferret-box`), for the refusal's rule text.
    pub label: String,
    pub addr: IpAddr,
    pub port: Option<u16>,
}

#[derive(Clone, Debug)]
struct InfraRule {
    label: String,
    kind: InfraKind,
}

#[derive(Clone, Debug)]
enum InfraKind {
    /// A host pattern, with its optional port; an IP literal also matches the resolved address.
    Name(Pattern),
    /// An address block, optionally on one port.
    Net { net: IpNet, port: Option<u16> },
    /// This machine: `127.0.0.0/8`, `::1`, the unspecified addresses (and IPv6 forms carrying them) and
    /// the names `localhost` and `*.localhost`, on the listed ports (`None`: every port).
    Loopback { ports: Option<Vec<u16>> },
    /// The names of cloud metadata services (see [`is_metadata_name`]), on every port.
    MetadataNames,
}

/// Whether `host` (lower case, no trailing dot) is the name of a cloud metadata service: `metadata`,
/// `instance-data`, `metadata.goog`, and any `metadata.*` or `instance-data.*` name under `.internal`
/// (`metadata.google.internal`, `instance-data.ec2.internal`). `metadata.example.com` is an ordinary
/// host: a public domain's own `metadata` label is not a metadata service.
fn is_metadata_name(host: &str) -> bool {
    let first = host.split('.').next().unwrap_or("");
    let single = !host.contains('.');
    (single && (first == "metadata" || first == "instance-data"))
        || host == "metadata.goog"
        || (host.ends_with(".internal") && (first == "metadata" || first == "instance-data"))
}

impl InfraRule {
    fn new(label: impl Into<String>, kind: InfraKind) -> InfraRule {
        InfraRule { label: label.into(), kind }
    }

    fn net(label: &str, cidr: &str, port: Option<u16>) -> Option<InfraRule> {
        let (a, p) = cidr.split_once('/')?;
        let net = IpNet::new(a.parse().ok()?, p.parse().ok()?);
        Some(InfraRule::new(label, InfraKind::Net { net, port }))
    }

    /// The rules every policy has, whatever the configuration says.
    fn builtin() -> Vec<InfraRule> {
        let mut rules = vec![InfraRule::new(
            "cloud metadata names (metadata, instance-data, metadata.goog, metadata.*.internal)",
            InfraKind::MetadataNames,
        )];
        for (label, cidr) in [
            ("cloud metadata addresses 169.254.0.0/16", "169.254.0.0/16"),
            ("cloud metadata address fd00:ec2::254", "fd00:ec2::254/128"),
            ("cloud metadata address 100.100.100.200", "100.100.100.200/32"),
            ("cloud metadata address 192.0.0.192", "192.0.0.192/32"),
        ] {
            rules.extend(InfraRule::net(label, cidr, None));
        }
        rules.push(InfraRule::new(
            "DevTools and inspector ports 9222 and 9229 on this machine",
            InfraKind::Loopback { ports: Some(vec![9222, 9229]) },
        ));
        rules.push(InfraRule::new(
            "Docker API ports 2375 and 2376 on this machine",
            InfraKind::Loopback { ports: Some(vec![2375, 2376]) },
        ));
        rules
    }

    /// One configured entry: a CIDR block (every port), or a pattern as in `network.deny`. A pattern
    /// naming this machine (`localhost`, a loopback or unspecified literal) becomes a loopback rule, so a
    /// name and the address it resolves to are one thing; any other IP literal is its exact address.
    fn parse(label: String, entry: &str) -> Result<InfraRule, String> {
        let text = entry.trim();
        if let Some((a, p)) = text.split_once('/') {
            let ip = a.parse::<IpAddr>().map_err(|_| format!("`{a}` is not an IP address"))?;
            let max = if ip.is_ipv4() { 32 } else { 128 };
            let prefix = p
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= max)
                .ok_or_else(|| format!("`{p}` is not a prefix length from 0 to {max}"))?;
            return Ok(InfraRule::new(label, InfraKind::Net { net: IpNet::new(ip, prefix).canonical(), port: None }));
        }
        let pattern = Pattern::parse(text)?;
        let kind = match &pattern.kind {
            Kind::Exact(h) if h == "localhost" => InfraKind::Loopback { ports: pattern.port.map(|p| vec![p]) },
            Kind::Exact(h) => match h.parse::<IpAddr>() {
                Ok(a) if is_local_literal(a) => InfraKind::Loopback { ports: pattern.port.map(|p| vec![p]) },
                Ok(a) => {
                    let full = if a.is_ipv4() { 32 } else { 128 };
                    InfraKind::Net { net: IpNet::new(canonical_ip(a), full).canonical(), port: pattern.port }
                }
                Err(_) => InfraKind::Name(pattern),
            },
            _ => InfraKind::Name(pattern),
        };
        Ok(InfraRule::new(label, kind))
    }

    fn hits(&self, host: &str, port: u16, addr: Option<IpAddr>, locals: &[IpAddr]) -> bool {
        match &self.kind {
            InfraKind::Name(p) => p.matches(host, port),
            InfraKind::Net { net, port: want } => {
                want.is_none_or(|w| w == port) && addr.is_some_and(|a| net.contains(a))
            }
            InfraKind::Loopback { ports } => {
                ports.as_ref().is_none_or(|ps| ps.contains(&port))
                    && (addr.is_some_and(|a| is_local_literal(a) || locals.contains(&canonical_ip(a)))
                        || host == "localhost"
                        || host.ends_with(".localhost"))
            }
            InfraKind::MetadataNames => is_metadata_name(host),
        }
    }
}

fn grant_pattern(host: &str) -> Result<Pattern, String> {
    Pattern::parse(host).map_err(|why| {
        format!(
            "The host \"{host}\" cannot be authorized: {why}. Write a host (`example.test`) or a wildcard (`*.example.test`), optionally followed by `:port`."
        )
    })
}

/// Extract an IP-literal grant from a granted host: `1.2.3.4`, `[::1]:8080`, `10.0.0.5:443`.
/// A granted name is never a private grant, even if it resolves to one.
fn literal_grant(host: &str) -> Option<(IpAddr, Option<u16>)> {
    let (h, port) = split_host_port(host).ok()?;
    let ip = h.parse::<IpAddr>().ok()?;
    Some((canonical_ip(ip), port))
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
        refuse_too_broad(h)?;
        out.push(h.to_string());
    }
    Ok(out)
}

/// Whether an IP literal is unspecified or in `0.0.0.0/8`, also when an IPv6 form carries such an address.
fn is_unspecified_literal(ip: IpAddr) -> bool {
    match canonical_ip(ip) {
        IpAddr::V4(v4) => v4.octets().first() == Some(&0),
        IpAddr::V6(v6) => v6.is_unspecified(),
    }
}

/// Whether an IP is loopback (`127.0.0.0/8`, `::1`), also when an IPv6 form carries a `127.x` address.
pub(crate) fn is_loopback_literal(ip: IpAddr) -> bool {
    match canonical_ip(ip) {
        IpAddr::V4(v4) => v4.octets().first() == Some(&127),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// Whether an IP is loopback or unspecified (the addresses that reach this machine's own listeners).
pub(crate) fn is_local_literal(ip: IpAddr) -> bool {
    is_loopback_literal(ip) || is_unspecified_literal(ip)
}

/// The refusals of [`check_hosts`] beyond pattern validity: `*`, a wildcard over a single label and an
/// unspecified address. `host` is a trimmed, valid pattern.
fn refuse_too_broad(host: &str) -> Result<(), String> {
    let (name, port) = split_host_port(host)?;
    if name == "*" {
        return Err(format!(
            "The host \"{host}\" would authorize every host. Name the hosts you need, such as `api.example.test` or `*.example.test`."
        ));
    }
    if let Some(rest) = name.strip_prefix("*.") {
        let label = normalize_host(rest);
        if !label.contains('.') {
            return Err(format!(
                "The host \"{host}\" would authorize a whole top-level domain. Name the hosts you need, such as `api.example.{label}` or `*.example.{label}`."
            ));
        }
    }
    if let Some(rest) = name.strip_prefix("*.") {
        let last = normalize_host(rest);
        let last = last.rsplit('.').next().unwrap_or("");
        let hex = last.strip_prefix("0x").or_else(|| last.strip_prefix("0X"));
        let numeric = !last.is_empty()
            && (last.chars().all(|c| c.is_ascii_digit())
                || hex.is_some_and(|h| !h.is_empty() && h.chars().all(|c| c.is_ascii_hexdigit())));
        if numeric {
            return Err(format!(
                "The host \"{host}\" ends in a number, which no top-level domain does, so it would authorize a whole range of IP addresses written as host names. Name the hosts you need."
            ));
        }
    }
    if let Ok(ip) = normalize_host(name).parse::<IpAddr>() {
        if is_loopback_literal(ip) && port.is_none() {
            return Err(format!(
                "The host \"{host}\" is a loopback address without a port, which would unlock every service on this machine. Write the port of the service you need, such as `127.0.0.1:8080`."
            ));
        }
        if is_unspecified_literal(ip) {
            return Err(format!(
                "The host \"{host}\" is an unspecified address, and a connection to it reaches this machine's own services. Write the address of the host you need, or `127.0.0.1` with a port for a service on this machine."
            ));
        }
    }
    Ok(())
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
            granted_private: Vec::new(),
            target_nets: Vec::new(),
            infra: InfraRule::builtin(),
            revoked: Vec::new(),
            local_addrs: Vec::new(),
        })
    }

    /// This policy with the infrastructure of `spec` refused as well (see the module contract, *Implicit
    /// infrastructure deny*). An entry that cannot be parsed is an error sentence naming the entry and
    /// the list, which says what to write instead.
    pub fn with_infrastructure(mut self, spec: &InfraSpec) -> Result<Policy, String> {
        let bad = |list: &str, e: &str, why: String| {
            format!(
                "{list} entry \"{e}\" is not valid: {why}. Write a host (`example.test`), a wildcard (`*.example.test`) or an address, optionally followed by `:port`, then reload the config."
            )
        };
        if let Some(port) = spec.daemon_port {
            let label = format!("the ferret daemon's port {port} on this machine");
            self.infra.push(InfraRule::new(label, InfraKind::Loopback { ports: Some(vec![port]) }));
        }
        for e in &spec.model_endpoints {
            let rule = InfraRule::parse(format!("model endpoint {e}"), e).map_err(|w| bad("a model endpoint", e, w))?;
            self.infra.push(rule);
        }
        for e in &spec.docker_hosts {
            let rule = InfraRule::parse(format!("Docker host {e}"), e).map_err(|w| bad("box.ssh_host", e, w))?;
            self.infra.push(rule);
        }
        for (key, e) in &spec.services {
            let rule = InfraRule::parse(format!("{key} {e}"), e).map_err(|w| bad(key, e, w))?;
            self.infra.push(rule);
        }
        for e in &spec.extra {
            let rule = InfraRule::parse(format!("network.infrastructure {e}"), e)
                .map_err(|w| bad("network.infrastructure", e, w))?;
            self.infra.push(rule);
        }
        for a in &spec.resolved {
            let full = if a.addr.is_ipv4() { 32 } else { 128 };
            let net = IpNet::new(canonical_ip(a.addr), full).canonical();
            self.infra.push(InfraRule::new(a.label.clone(), InfraKind::Net { net, port: a.port }));
        }
        for a in &spec.local_addrs {
            let a = canonical_ip(*a);
            if !self.local_addrs.contains(&a) {
                self.local_addrs.push(a);
            }
        }
        Ok(self)
    }

    /// This policy with `hosts` (entries as granted) refused as revoked, in the rule `deny revoked {entry}`:
    /// after infrastructure and before every other rule, so a wildcard grant, `allow` and `mode open` do
    /// not reach them. An entry that cannot be read is an error sentence naming it.
    pub fn with_revoked(mut self, hosts: &[String]) -> Result<Policy, String> {
        for h in hosts {
            let e = PrivEntry::parse(h).map_err(|why| format!("The revoked host \"{h}\" is not valid: {why}."))?;
            self.revoked.push(e);
        }
        Ok(self)
    }

    /// The infrastructure rule that refuses an entry written for a grant (`host`, `host:port`, an IP
    /// literal), if any: the entry's own port (every port when it has none) and, for an IP literal, its
    /// address. Names are judged by name only; a grant that infrastructure refuses is refused at
    /// connection time whatever is granted, so this is the early, clear sentence.
    pub fn infrastructure_refusal(&self, entry: &str) -> Option<String> {
        let (h, port) = split_host_port(entry.trim()).ok()?;
        let h = normalize_host(h);
        let literal = h.parse::<IpAddr>().ok();
        self.infra_hit(&h, port.unwrap_or(0), literal)
    }

    /// The infrastructure rule that refuses `host` (a name or an IP literal, no port) on some port, if any: what a
    /// grant of the host without a port leaves refused, such as the IMAP server of `[mail]` on its port. Names are
    /// judged by name only, as in `infrastructure_refusal`. The monitor asks it of a scope request without a port.
    pub fn infrastructure_on_some_port(&self, host: &str) -> Option<String> {
        let h = normalize_host(host.trim().trim_start_matches('[').trim_end_matches(']'));
        let literal = h.parse::<IpAddr>().ok();
        self.infra
            .iter()
            .find(|r| match &r.kind {
                InfraKind::Name(p) => Pattern { port: None, ..p.clone() }.matches(&h, 0),
                InfraKind::Net { net, .. } => literal.is_some_and(|a| net.contains(a)),
                InfraKind::Loopback { .. } => {
                    InfraRule { label: String::new(), kind: InfraKind::Loopback { ports: None } }.hits(
                        &h,
                        0,
                        literal,
                        &self.local_addrs,
                    )
                }
                InfraKind::MetadataNames => is_metadata_name(&h),
            })
            .map(|r| format!("deny infrastructure: {}", r.label))
    }

    /// The `deny infrastructure ...` rule that matches the name or the address, if any.
    fn infra_hit(&self, host: &str, port: u16, addr: Option<IpAddr>) -> Option<String> {
        self.infra
            .iter()
            .find(|r| r.hits(host, port, addr, &self.local_addrs))
            .map(|r| format!("deny infrastructure: {}", r.label))
    }

    /// The policy with a target's scope added (CONTRACTS-TRAFFIC-TARGETS T2): scope hosts, IPs and CIDR
    /// blocks are reachable in every mode but `open` (where they change nothing), also under `deny_all`,
    /// and the `exclude` entries are refused whatever else would allow them, `open` included. The entries
    /// are those of a validated `Scope`.
    pub fn with_target(mut self, scope: &[String], exclude: &[String]) -> Result<Policy, String> {
        for e in exclude {
            let entry =
                PrivEntry::parse(e).map_err(|why| format!("The excluded entry \"{e}\" cannot be used: {why}."))?;
            self.deny.push(entry);
        }
        if self.mode == NetworkMode::Open || scope.is_empty() {
            return Ok(self);
        }
        if self.mode == NetworkMode::DenyAll {
            self.allow.clear();
            self.mode = NetworkMode::Allowlist;
        }
        for e in scope {
            match PrivEntry::parse(e).map_err(|why| format!("The scope entry \"{e}\" cannot be used: {why}."))? {
                PrivEntry::Name(p) => {
                    if let Some((ip, port)) = literal_grant(e) {
                        self.granted_private.push((ip, port));
                    }
                    self.allow.push(p);
                }
                PrivEntry::Net { text, net } => self.target_nets.push((text, net)),
            }
        }
        Ok(self)
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
        if policy.mode == NetworkMode::DenyAll {
            // The configured `allow` list is not in force under deny_all; a grant must not switch it on.
            policy.allow.clear();
        }
        for h in hosts {
            let p = grant_pattern(h)?;
            if let Some((ip, port)) = literal_grant(h) {
                policy.granted_private.push((ip, port));
            }
            policy.allow.push(p);
        }
        policy.mode = NetworkMode::Allowlist;
        Ok(policy)
    }

    pub fn check_name(&self, host: &str, port: u16) -> Verdict {
        let h = normalize_host(host);
        let literal = h.parse::<IpAddr>().ok();
        if let Some(rule) = self.infra_hit(&h, port, literal) {
            return Verdict::no(rule);
        }
        if let Some(rule) = self.revoked_hit(&h, port, literal) {
            return Verdict::no(rule);
        }
        if let Some(rule) = self.deny_hit(&h, port, literal) {
            return Verdict::no(rule);
        }
        if self.matches_reference(&h, port) {
            return Verdict::no("reference host requires the in-process GET client");
        }
        match self.mode {
            NetworkMode::DenyAll => Verdict::no("mode deny_all"),
            NetworkMode::Allowlist => match self.allow.iter().find(|p| p.matches(&h, port)) {
                Some(p) => Verdict::yes(format!("allow {}", p.text)),
                None => {
                    match h.parse::<IpAddr>().ok().and_then(|a| self.target_nets.iter().find(|(_, n)| n.contains(a))) {
                        Some((text, _)) => Verdict::yes(format!("target scope {text}")),
                        None => Verdict::no("not in allow list"),
                    }
                }
            },
            NetworkMode::Open => Verdict::yes("mode open"),
        }
    }

    /// The `deny ...` rule that matches the name, or the address when there is one. Addresses and
    /// address entries are compared in canonical form, so `::ffff:10.0.0.5` is `10.0.0.5`.
    fn deny_hit(&self, host: &str, port: u16, addr: Option<IpAddr>) -> Option<String> {
        Self::list_hit(&self.deny, "deny", host, port, addr)
    }

    /// The `revoked ...` rule that matches the name, or the address when there is one.
    fn revoked_hit(&self, host: &str, port: u16, addr: Option<IpAddr>) -> Option<String> {
        Self::list_hit(&self.revoked, "deny revoked", host, port, addr)
    }

    fn list_hit(list: &[PrivEntry], prefix: &str, host: &str, port: u16, addr: Option<IpAddr>) -> Option<String> {
        for e in list {
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
                        return Some(format!("{prefix} {}", p.text));
                    }
                }
                PrivEntry::Net { text, net } => {
                    if addr.is_some_and(|a| net.contains(a)) {
                        return Some(format!("{prefix} {text}"));
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
        if let Some(rule) = self.infra_hit(&h, port, Some(addr)) {
            return Verdict::no(rule);
        }
        if let Some(rule) = self.revoked_hit(&h, port, Some(addr)) {
            return Verdict::no(rule);
        }
        if let Some(rule) = self.deny_hit(&h, port, Some(addr)) {
            return Verdict::no(rule);
        }
        if !is_special(addr) {
            return Verdict::yes(name_rule);
        }
        let grant_port = port;
        let can = canonical_ip(addr);
        for (ip, gp) in &self.granted_private {
            if *ip == can && gp.as_ref().is_none_or(|p| *p == grant_port) {
                return Verdict::yes(format!("grant private-address {can}"));
            }
        }
        if let Some((text, _)) = self.target_nets.iter().find(|(_, n)| n.contains(addr)) {
            return Verdict::yes(format!("target scope {text}"));
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
pub(crate) fn canonical_ip(addr: IpAddr) -> IpAddr {
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
    fn pattern_covers_follows_the_grant_grammar() {
        assert!(pattern_covers("*.lab.example", "X1.Lab.Example", None));
        assert!(!pattern_covers("*.lab.example", "lab.example", None), "a wildcard does not cover the apex");
        assert!(pattern_covers("lab.example:8443", "lab.example", None));
        assert!(pattern_covers("lab.example:8443", "lab.example", Some(8443)));
        assert!(!pattern_covers("lab.example:8443", "lab.example", Some(443)));
        assert!(!pattern_covers("not a host", "lab.example", None));
    }

    #[test]
    fn a_scope_entry_covers_names_by_pattern_and_addresses_by_block() {
        assert!(scope_entry_covers("*.acme.test", "www.ACME.test", None));
        assert!(!scope_entry_covers("*.acme.test", "acme.test", None));
        assert!(scope_entry_covers("10.20.0.0/24", "10.20.0.5", Some(80)));
        assert!(!scope_entry_covers("10.20.0.0/24", "10.30.0.5", None));
        assert!(scope_entry_covers("10.20.0.9", "10.20.0.9", None));
        assert!(scope_entry_covers("fd00::/8", "[fd00::1]", None));
        assert!(!scope_entry_covers("10.20.0.0/24", "www.acme.test", None), "a block never covers a name");
        assert!(!scope_entry_covers("10.20.0.0/99", "10.20.0.5", None), "an invalid entry covers nothing");
    }

    #[test]
    fn a_target_scope_is_reachable_in_deny_all_and_its_exclusions_never_are() {
        let s = |x: &[&str]| x.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let scope = s(&["*.acme.test", "10.20.0.0/24"]);
        let exclude = s(&["vpn.acme.test", "10.20.0.9"]);
        for mode in [NetworkMode::DenyAll, NetworkMode::Allowlist] {
            let p = pol(mode, &["ok.test"], &[], &[]).with_target(&scope, &exclude).unwrap();
            assert!(p.check_name("www.acme.test", 443).allowed, "{mode:?}");
            assert!(!p.check_name("vpn.acme.test", 443).allowed, "{mode:?}");
            assert!(!p.check_name("other.test", 443).allowed, "{mode:?}");
            assert!(p.check_name("10.20.0.5", 80).allowed, "{mode:?}");
            assert!(!p.check_name("10.20.0.9", 80).allowed, "{mode:?}");
            assert!(!p.check_name("10.30.0.5", 80).allowed, "{mode:?}");
            assert!(p.check_addr("10.20.0.5", 80, ip("10.20.0.5"), "x").allowed, "private address in scope");
            assert!(!p.check_addr("10.30.0.5", 80, ip("10.30.0.5"), "x").allowed);
        }
        // `open` changes nothing but the exclusions still hold.
        let p = pol(NetworkMode::Open, &["*"], &[], &[]).with_target(&scope, &exclude).unwrap();
        assert!(p.check_name("other.test", 443).allowed);
        assert!(!p.check_name("vpn.acme.test", 443).allowed);
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
    fn granted_private_literals_authorize_exactly_themselves() {
        let c = cfg(NetworkMode::DenyAll, &[], &[], &[]);
        let hosts = |h: &[&str]| h.iter().map(|s| s.to_string()).collect::<Vec<_>>();

        // A granted literal with a port authorizes that literal:port only.
        let p = Policy::with_hosts(&c, &hosts(&["127.0.0.1:19201"])).unwrap();
        assert!(p.check_addr("127.0.0.1", 19201, ip("127.0.0.1"), "allow 127.0.0.1:19201").allowed);
        assert!(!p.check_addr("127.0.0.1", 7878, ip("127.0.0.1"), "allow 127.0.0.1:19201").allowed);
        // A different loopback address is still refused — the grant is exact.
        assert!(!p.check_addr("127.0.0.2", 19201, ip("127.0.0.2"), "allow 127.0.0.1:19201").allowed);
        // Port-less literal grants cover every port on that address — but nothing else.
        let p = Policy::with_hosts(&c, &hosts(&["127.0.0.1"])).unwrap();
        assert!(p.check_addr("127.0.0.1", 7878, ip("127.0.0.1"), "allow 127.0.0.1").allowed);
        assert!(!p.check_addr("127.0.0.2", 7878, ip("127.0.0.2"), "allow 127.0.0.1").allowed);
        // IPv6 brackets, canonical-form compare (an IPv4-mapped form stands for the same address).
        let p = Policy::with_hosts(&c, &hosts(&["[::1]:8080"])).unwrap();
        assert!(p.check_addr("::1", 8080, ip("::1"), "allow [::1]:8080").allowed);
        assert!(!p.check_addr("::1", 9090, ip("::1"), "allow ::1:8080").allowed);
        let p = Policy::with_hosts(&c, &hosts(&["10.0.0.5:443"])).unwrap();
        assert!(p.check_addr("::ffff:10.0.0.5", 443, ip("::ffff:10.0.0.5"), "allow ::ffff:10.0.0.5").allowed);
        // A name grant does NOT unlock its private resolution (SSRF amplifier stays closed).
        let p = Policy::with_hosts(&c, &hosts(&["lab.test:19201"])).unwrap();
        assert!(!p.check_addr("lab.test", 19201, ip("10.1.2.3"), "allow lab.test:19201").allowed);
        // But granting the literal IP unlocks it.
        let p = Policy::with_hosts(&c, &hosts(&["10.1.2.3:19201"])).unwrap();
        assert!(p.check_addr("lab.test", 19201, ip("10.1.2.3"), "allow lab.test:19201").allowed);
        // The config's deny list still beats the literal grant.
        let c2 = cfg(NetworkMode::DenyAll, &[], &["10.1.2.3:19201"], &[]);
        let p = Policy::with_hosts(&c2, &hosts(&["10.1.2.3:19201"])).unwrap();
        assert_eq!(p.check_addr("lab.test", 19201, ip("10.1.2.3"), "allow 10.1.2.3:19201").rule, "deny 10.1.2.3:19201");
        // Mode open unchanged: private addresses stay refused there (module contract), grants
        // don't need to work in an open mode.
        let open = Policy::with_hosts(&cfg(NetworkMode::Open, &[], &[], &[]), &hosts(&["127.0.0.1"])).unwrap();
        assert_eq!(open.check_addr("x.test", 80, ip("127.0.0.1"), "mode open").rule, "deny private-address 127.0.0.1");
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
    fn grant_under_deny_all_does_not_switch_on_the_configured_allow_list() {
        let hosts = |h: &[&str]| h.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let c = cfg(NetworkMode::DenyAll, &["cfg.test", "*.cfg.test:443"], &[], &[]);
        let p = Policy::with_hosts(&c, &hosts(&["granted.test"])).unwrap();
        assert!(p.check_name("granted.test", 80).allowed);
        for (h, port) in [("cfg.test", 80), ("api.cfg.test", 443)] {
            let v = p.check_name(h, port);
            assert!(!v.allowed, "{h}");
            assert_eq!(v.rule, "not in allow list", "{h}");
        }
        let c = cfg(NetworkMode::Allowlist, &["cfg.test"], &[], &[]);
        let p = Policy::with_hosts(&c, &hosts(&["granted.test"])).unwrap();
        assert!(p.check_name("granted.test", 80).allowed);
        assert!(p.check_name("cfg.test", 80).allowed);
    }

    #[test]
    fn check_hosts_refuses_everything_hosts_and_unspecified_addresses() {
        let s = |h: &[&str]| check_hosts(&h.iter().map(|x| x.to_string()).collect::<Vec<_>>());
        for e in [
            "*",
            "*:443",
            "*.com",
            "*.com:443",
            "*.0.1",
            "*.8.0x8",
            "*.8.0XfF",
            "*.8.010",
            "*.1.168.192:80",
            "0.0.0.0",
            "0.0.0.0:8080",
            "0.1.2.3",
            "::",
            "[::]",
            "[::]:80",
            "[::ffff:0.0.0.0]",
            "127.0.0.1",
            "127.1.2.3",
            "[::1]",
            "::1",
            "[::ffff:127.0.0.1]",
        ] {
            let err = s(&[e]).unwrap_err();
            assert!(err.contains(&format!("\"{e}\"")), "{e}: {err}");
            let err = s(&["a.test", e]).unwrap_err();
            assert!(err.contains(&format!("\"{e}\"")), "{e}: {err}");
        }
        for e in [
            "*.example.test",
            "*.a1.example.test",
            "*.0xide.example.test",
            "api.example.test:443",
            "127.0.0.1:19201",
            "10.0.0.5",
            "[::1]:8080",
        ] {
            assert_eq!(s(&[e]).unwrap(), [e], "{e}");
        }
        // with_hosts honours what a ledger restored.
        let c = cfg(NetworkMode::DenyAll, &[], &[], &[]);
        assert!(Policy::with_hosts(&c, &["*.com".to_string()]).is_ok());
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
        for v4 in ["10.0.0.5", "127.0.0.1", "192.168.1.5"] {
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

    // ---- E1: the implicit infrastructure deny ----------------------------------------------------

    fn hosts(list: &[&str]) -> Vec<String> {
        list.iter().map(|h| h.to_string()).collect()
    }

    fn infra_rule(v: &Verdict) -> bool {
        !v.allowed && v.rule.starts_with("deny infrastructure: ")
    }

    /// A policy as lax as the configuration can make one: open, everything private allowed, every
    /// infrastructure literal granted. None of it may lift the infrastructure deny.
    fn lax(spec: &InfraSpec) -> Policy {
        let c = cfg(
            NetworkMode::Open,
            &[],
            &[],
            &["0.0.0.0/0", "::/0", "localhost", "*.localhost", "metadata.google.internal"],
        );
        let grants = hosts(&[
            "169.254.169.254",
            "127.0.0.1:9222",
            "127.0.0.1:9229",
            "127.0.0.1:2375",
            "[::1]:9229",
            "127.0.0.1:7878",
            "metadata.google.internal",
        ]);
        Policy::with_hosts(&c, &grants).unwrap().with_infrastructure(spec).unwrap()
    }

    #[test]
    fn infrastructure_beats_grants_allow_private_and_open_mode_by_name_and_address() {
        let spec = InfraSpec { daemon_port: Some(7878), ..InfraSpec::default() };
        let p = lax(&spec);
        for (host, port) in [
            ("169.254.169.254", 80),
            ("169.254.0.1", 1),
            ("fd00:ec2::254", 80),
            ("100.100.100.200", 80),
            ("192.0.0.192", 80),
            ("metadata.google.internal", 80),
            ("metadata", 80),
            ("instance-data.ec2.internal", 80),
            ("metadata.goog", 443),
            ("127.0.0.1", 9222),
            ("[::1]", 9229),
            ("localhost", 9222),
            ("x.localhost", 9229),
            ("127.0.0.1", 2375),
            ("127.0.0.1", 2376),
            ("127.0.0.1", 7878),
            ("localhost", 7878),
            ("::ffff:127.0.0.1", 7878),
            ("0.0.0.0", 9222),
        ] {
            let v = p.check_name(host, port);
            assert!(infra_rule(&v), "{host}:{port} {v:?}");
        }
        // After resolving: a name that leads to an infrastructure address is refused too.
        for (name, port, addr) in [
            ("alias.example.test", 80, "169.254.169.254"),
            ("alias.example.test", 9222, "127.0.0.1"),
            ("alias.example.test", 9229, "::1"),
            ("alias.example.test", 7878, "::ffff:127.0.0.1"),
            ("alias.example.test", 2375, "0.0.0.0"),
            ("alias.example.test", 80, "fd00:ec2::254"),
        ] {
            let v = p.check_addr(name, port, ip(addr), "mode open");
            assert!(infra_rule(&v), "{name}:{port} -> {addr} {v:?}");
        }
        // Other loopback ports and other hosts on those ports are not infrastructure.
        assert!(p.check_name("127.0.0.1", 8080).allowed);
        assert!(p.check_addr("lab.test", 8080, ip("127.0.0.1"), "x").allowed);
        assert!(p.check_name("203.0.113.5", 9222).allowed);
        assert!(p.check_name("example.test", 2375).allowed);
        assert!(p.check_addr("example.test", 2375, ip("203.0.113.5"), "r").allowed);
        assert!(p.check_name("metadata-service.example.test", 80).allowed, "only the first label counts, whole");
    }

    #[test]
    fn infrastructure_is_in_every_plain_policy_and_comes_before_deny() {
        for p in [
            pol(NetworkMode::Open, &[], &[], &[]),
            pol(NetworkMode::Allowlist, &["169.254.169.254", "*.localhost"], &[], &[]),
            pol(NetworkMode::DenyAll, &[], &[], &[]),
        ] {
            assert!(infra_rule(&p.check_name("169.254.169.254", 80)));
            assert!(infra_rule(&p.check_name("localhost", 9222)));
        }
        let p = pol(NetworkMode::Open, &[], &["169.254.0.0/16", "metadata.google.internal"], &[]);
        assert!(
            infra_rule(&p.check_name("metadata.google.internal", 80)),
            "the infrastructure rule is named, not `deny {{pattern}}`"
        );
        assert!(infra_rule(&p.check_addr("x.test", 80, ip("169.254.1.1"), "r")));
    }

    #[test]
    fn infrastructure_entries_of_the_configuration_refuse_by_name_address_and_cidr() {
        let spec = InfraSpec {
            daemon_port: None,
            model_endpoints: vec![
                "spark-one.tail1234.ts.net:8000".into(),
                "127.0.0.1:9920".into(),
                "10.0.0.5:8000".into(),
            ],
            docker_hosts: vec!["ferret-box".into()],
            extra: vec!["*.tailnet.test".into(), "100.64.1.0/24".into(), "localhost:5555".into()],
            ..InfraSpec::default()
        };
        let p =
            Policy::new(&cfg(NetworkMode::Open, &[], &[], &["0.0.0.0/0"])).unwrap().with_infrastructure(&spec).unwrap();
        for (host, port) in [
            ("spark-one.tail1234.ts.net", 8000),
            ("SPARK-ONE.tail1234.ts.net.", 8000),
            ("127.0.0.1", 9920),
            ("localhost", 9920),
            ("10.0.0.5", 8000),
            ("ferret-box", 22),
            ("ferret-box", 2375),
            ("a.tailnet.test", 1),
            ("100.64.1.9", 443),
            ("localhost", 5555),
            ("127.0.0.1", 5555),
        ] {
            assert!(infra_rule(&p.check_name(host, port)), "{host}:{port}");
        }
        assert!(infra_rule(&p.check_addr("x.test", 8000, ip("10.0.0.5"), "r")));
        assert!(infra_rule(&p.check_addr("x.test", 1, ip("100.64.1.200"), "r")));
        // Port-exact: the same hosts on other ports, and the apex of a wildcard, are not listed.
        assert!(p.check_name("spark-one.tail1234.ts.net", 22).allowed);
        assert!(p.check_name("127.0.0.1", 9921).allowed);
        assert!(p.check_name("10.0.0.5", 22).allowed);
        assert!(p.check_name("tailnet.test", 1).allowed);
        assert!(p.check_addr("x.test", 1, ip("100.64.2.1"), "r").allowed);
        assert!(p.check_name("other-box", 22).allowed);
    }

    /// The services the daemon talks to for the operator (the Signal bridge, the mail inbox) are refused on their port
    /// whatever is granted, by name and by address, with their configuration key in the rule.
    #[test]
    fn the_services_of_the_daemon_are_infrastructure_on_their_port() {
        let spec = InfraSpec {
            services: vec![
                ("signal.http_url".into(), "127.0.0.1:1337".into()),
                ("mail.host".into(), "imap.example.test:993".into()),
            ],
            ..InfraSpec::default()
        };
        let grants = hosts(&["127.0.0.1:1337", "imap.example.test:993", "imap.example.test:443"]);
        let c = cfg(NetworkMode::Open, &[], &[], &["127.0.0.0/8"]);
        let p = Policy::with_hosts(&c, &grants).unwrap().with_infrastructure(&spec).unwrap();
        for (host, port, rule) in [
            ("127.0.0.1", 1337, "deny infrastructure: signal.http_url 127.0.0.1:1337"),
            ("localhost", 1337, "deny infrastructure: signal.http_url 127.0.0.1:1337"),
            ("imap.example.test", 993, "deny infrastructure: mail.host imap.example.test:993"),
        ] {
            assert_eq!(p.check_name(host, port).rule, rule, "{host}:{port}");
        }
        assert!(infra_rule(&p.check_addr("x.test", 1337, ip("127.0.0.1"), "r")));
        assert!(p.infrastructure_refusal("127.0.0.1:1337").is_some());
        // A host without a port is infrastructure on some port: what the monitor asks of a scope request without one.
        assert_eq!(
            p.infrastructure_on_some_port("imap.example.test").as_deref(),
            Some("deny infrastructure: mail.host imap.example.test:993")
        );
        assert!(
            p.infrastructure_on_some_port("localhost").is_some() && p.infrastructure_on_some_port("[::1]").is_some()
        );
        assert!(p.infrastructure_on_some_port("metadata.google.internal").is_some());
        assert!(p.infrastructure_on_some_port("other.example.test").is_none());
        // Port-exact, as a model endpoint.
        assert!(p.check_name("imap.example.test", 443).allowed);
        assert!(p.check_name("127.0.0.1", 1338).allowed);
        let e = Policy::new(&c)
            .unwrap()
            .with_infrastructure(&InfraSpec {
                services: vec![("mail.host".into(), "bad host:993".into())],
                ..InfraSpec::default()
            })
            .unwrap_err();
        assert!(e.contains("mail.host entry \"bad host:993\" is not valid"), "{e}");
    }

    #[test]
    fn infrastructure_entries_that_cannot_be_parsed_say_which_and_what_to_write() {
        let spec = |extra: &str| InfraSpec { extra: vec![extra.into()], ..InfraSpec::default() };
        let base = Policy::new(&cfg(NetworkMode::Open, &[], &[], &[])).unwrap();
        for bad in ["", "a b", "10.0.0.0/99", "foo/8", "[::1", "x:notaport"] {
            let e = base.clone().with_infrastructure(&spec(bad)).unwrap_err();
            assert!(
                e.contains("network.infrastructure") && e.contains("is not valid") && e.contains("Write a host"),
                "{bad}: {e}"
            );
        }
        let e = base
            .clone()
            .with_infrastructure(&InfraSpec { model_endpoints: vec!["bad host".into()], ..InfraSpec::default() })
            .unwrap_err();
        assert!(e.contains("a model endpoint") && e.contains("\"bad host\""), "{e}");
        let e = base
            .with_infrastructure(&InfraSpec { docker_hosts: vec!["x/99".into()], ..InfraSpec::default() })
            .unwrap_err();
        assert!(e.contains("box.ssh_host"), "{e}");
    }

    /// The tailnet case: the model host is a name in the configuration, an IP alias of it is what an
    /// agent asks for, and the operator approves that literal.
    #[test]
    fn a_named_infrastructure_host_is_refused_by_the_addresses_it_resolves_to_whatever_is_granted() {
        let spec = InfraSpec {
            model_endpoints: vec!["spark-one.tail1234.ts.net:8000".into()],
            docker_hosts: vec!["h510".into()],
            resolved: vec![
                InfraAddr {
                    label: "model endpoint spark-one.tail1234.ts.net:8000".into(),
                    addr: ip("100.101.102.103"),
                    port: Some(8000),
                },
                InfraAddr { label: "Docker host h510".into(), addr: ip("192.168.1.50"), port: None },
            ],
            ..InfraSpec::default()
        };
        let grants = hosts(&["100.101.102.103:8000", "192.168.1.50:2375", "h510.lan:2375"]);
        let c = cfg(NetworkMode::Open, &[], &[], &["100.64.0.0/10", "192.168.0.0/16"]);
        let p = Policy::with_hosts(&c, &grants).unwrap().with_infrastructure(&spec).unwrap();
        assert!(infra_rule(&p.check_name("100.101.102.103", 8000)));
        assert!(infra_rule(&p.check_addr("spark-one", 8000, ip("100.101.102.103"), "r")));
        assert!(infra_rule(&p.check_name("192.168.1.50", 2375)));
        assert!(infra_rule(&p.check_name("192.168.1.50", 22)));
        assert!(infra_rule(&p.check_addr("h510.lan", 22, ip("192.168.1.50"), "r")));
        // Other ports of the model host and other hosts of the tailnet are not infrastructure.
        assert!(p.check_name("100.101.102.103", 22).allowed);
        assert!(p.check_addr("lab.test", 8000, ip("100.101.102.104"), "r").allowed);
        // The early sentence for a grant: the literal with its port.
        assert!(p.infrastructure_refusal("100.101.102.103:8000").is_some());
        assert!(p.infrastructure_refusal("192.168.1.50").is_some());
        assert!(p.infrastructure_refusal("lab.test:8000").is_none());
        assert!(p.infrastructure_refusal("100.101.102.103:22").is_none());
    }

    #[test]
    fn this_machines_own_addresses_are_this_machine_for_the_loopback_rules() {
        let spec = InfraSpec {
            daemon_port: Some(9920),
            local_addrs: vec![ip("192.168.1.10"), ip("2601:db8:abcd::1234")],
            ..InfraSpec::default()
        };
        let c = cfg(NetworkMode::Open, &[], &[], &["192.168.1.0/24"]);
        let p = Policy::new(&c).unwrap().with_infrastructure(&spec).unwrap();
        assert!(infra_rule(&p.check_name("192.168.1.10", 9920)));
        assert!(infra_rule(&p.check_name("192.168.1.10", 2375)));
        assert!(infra_rule(&p.check_addr("x.test", 9920, ip("2601:db8:abcd::1234"), "r")));
        assert!(p.check_name("192.168.1.10", 8080).allowed, "only the listed ports");
        assert!(p.check_name("192.168.1.11", 9920).allowed, "another host of the LAN");
    }

    #[test]
    fn only_the_cloud_metadata_names_are_metadata_names() {
        let p = pol(NetworkMode::Open, &[], &[], &[]);
        for h in
            ["metadata", "instance-data", "metadata.goog", "metadata.google.internal", "instance-data.ec2.internal"]
        {
            assert!(infra_rule(&p.check_name(h, 80)), "{h}");
        }
        for h in ["metadata.target-company.com", "instance-data.example.test", "metadata.goog.example.test"] {
            assert!(p.check_name(h, 443).allowed, "{h} is an ordinary host");
        }
    }

    #[test]
    fn a_revoked_host_is_refused_whatever_else_allows_it() {
        let revoked = hosts(&["api.lab.test", "10.0.0.5:8080", "other.test"]);
        // Open mode, a wildcard grant covering the host, and an `allow` entry for it.
        for c in [
            cfg(NetworkMode::Open, &[], &[], &["10.0.0.0/8"]),
            cfg(NetworkMode::Allowlist, &["api.lab.test", "other.test"], &[], &["10.0.0.0/8"]),
        ] {
            let p = Policy::with_hosts(&c, &hosts(&["*.lab.test"])).unwrap().with_revoked(&revoked).unwrap();
            let v = p.check_name("API.lab.test.", 443);
            assert!(!v.allowed && v.rule == "deny revoked api.lab.test", "{v:?}");
            assert!(!p.check_name("10.0.0.5", 8080).allowed);
            assert!(!p.check_addr("alias.test", 8080, ip("10.0.0.5"), "r").allowed);
        }
        let c = cfg(NetworkMode::DenyAll, &[], &[], &[]);
        let p = Policy::with_hosts(&c, &hosts(&["*.lab.test"])).unwrap().with_revoked(&revoked).unwrap();
        assert!(p.check_name("web.lab.test", 443).allowed, "a sibling under the wildcard stays granted");
        assert!(infra_rule(&p.with_revoked(&[]).unwrap().check_name("169.254.169.254", 80)));
        assert!(Policy::new(&c).unwrap().with_revoked(&hosts(&["a b"])).unwrap_err().contains("a b"));
    }

    #[test]
    fn a_checked_host_list_may_still_name_infrastructure_but_the_policy_refuses_it() {
        // `check_hosts` accepts these (they are valid grants in grammar); E1 is what makes them inert.
        assert!(check_hosts(&hosts(&["169.254.169.254", "127.0.0.1:9222", "metadata.google.internal"])).is_ok());
        let p = Policy::with_hosts(
            &cfg(NetworkMode::DenyAll, &[], &[], &[]),
            &hosts(&["169.254.169.254", "127.0.0.1:9222", "metadata.google.internal", "lab.test"]),
        )
        .unwrap();
        assert!(infra_rule(&p.check_name("169.254.169.254", 80)));
        assert!(infra_rule(&p.check_name("127.0.0.1", 9222)));
        assert!(infra_rule(&p.check_name("metadata.google.internal", 80)));
        assert!(p.check_name("lab.test", 80).allowed);
    }
}
