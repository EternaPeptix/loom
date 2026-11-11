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

use loom_core::config::NetworkCfg;
use std::net::IpAddr;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    pub allowed: bool,
    pub rule: String,
}

/// A parsed, validated network policy.
#[derive(Clone, Debug)]
pub struct Policy {
    #[allow(dead_code)]
    cfg: NetworkCfg,
}

impl Policy {
    pub fn new(cfg: &NetworkCfg) -> Result<Policy, String> {
        let _ = cfg;
        todo!("implement per module contract")
    }

    pub fn check_name(&self, host: &str, port: u16) -> Verdict {
        let _ = (host, port);
        todo!("implement per module contract")
    }

    pub fn check_addr(&self, host: &str, port: u16, addr: IpAddr, name_rule: &str) -> Verdict {
        let _ = (host, port, addr, name_rule);
        todo!("implement per module contract")
    }
}

/// Whether `addr` is loopback, private, link-local, multicast, or otherwise not a public unicast
/// address (the list is in the module contract).
pub fn is_special(addr: IpAddr) -> bool {
    let _ = addr;
    todo!("implement per module contract")
}
