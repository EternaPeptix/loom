//! What the daemon resolves about its own infrastructure, for the implicit deny of every command policy
//! (E1, `ferret_net::policy`).
//!
//! CONTRACT.
//!
//! `ferret_net::policy` matches a named infrastructure entry (a model endpoint's host, a service the daemon talks to
//! for the operator, a `network.infrastructure` name, the box's Docker host) by name only. This module finds the addresses
//! those names stand for and this machine's own interface addresses, so the policy can refuse the same
//! host reached by an IP literal, a short name or an alias:
//!
//! - `docker_host_of(target)`: the host of an ssh destination, as the policy reads a host: a leading
//!   `ssh://`, a `user@` and a trailing `:port` (or `/path`) are removed, an IPv6 address is bracketed;
//!   `None` for an empty or unusable target. `jeweled@ferret-box`, `ssh://jeweled@ferret-box:2222` and
//!   `ferret-box` are all `ferret-box`.
//! - `ssh_hostname(output)`: the `hostname` line of `ssh -G <target>` output (its resolved `HostName`),
//!   `None` when there is none.
//! - `resolve(config, ssh_g, lookup, local)` (pure over its three injected inputs): with the box enabled,
//!   the Docker host named by `[box] ssh_host` and the `hostname` that `ssh -G` resolves it to, every port;
//!   the host of each model endpoint (on its port); the host of each service the daemon talks to for the operator
//!   (`runtime::service_endpoints`: the Signal bridge's signal-cli, the mail inbox's IMAP server, the OAST broker's
//!   endpoints, on its port; a `*.domain` entry of the broker's is a wildcard and is not looked up); each
//!   `network.infrastructure` entry that is a plain name, with its port. Each name is looked up, and every address found is a `Resolution::addrs` entry
//!   whose label is the entry's. IP literals, `localhost` names, wildcards and CIDR blocks are not looked
//!   up (the policy reads them as written). A Docker host's loopback or unspecified address is dropped (an
//!   ssh alias to `127.0.0.1` with a forwarded port is not the machine's every port). `Resolution::
//!   docker_hosts` are the extra names (the `hostname` from `ssh -G`) for the policy's name rule.
//! - `resolve_system(config)`: `resolve` with the real `ssh -G` (no network, five second limit), the
//!   system resolver and `local_addresses()`. It blocks: call it off the async threads.
//! - `local_addresses()`: this machine's interface addresses from `getifaddrs`, empty when the call fails.
//!
//! The runtime resolves once at start and again every `RESOLVE_EVERY`; a session's policy carries the
//! last resolution at the time it is built (a spawn, a grant, a revoke), so an address that changed
//! since is refused to a running session only after its next rebuild. A failed lookup keeps what the
//! previous resolution found for nothing: names that do not resolve add no address.
//!
//! Tests required: `docker_host_of` for a bare host, `user@host`, `ssh://user@host:2222`, `host:22`,
//! `[::1]:22`, `user@10.0.0.5` and empty; `ssh_hostname` for the usual output; `resolve` for an alias
//! whose HostName is an address, a model endpoint name, an `extra` name with a port, and the entries not
//! looked up; `local_addresses` includes the loopback address.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::process::{Command, Stdio};
use std::time::Duration;

use ferret_core::config::Config;
use ferret_net::InfraAddr;

/// How often the runtime resolves again.
pub const RESOLVE_EVERY: Duration = Duration::from_secs(300);

/// How long `ssh -G` may take.
const SSH_G_LIMIT: Duration = Duration::from_secs(5);

/// What `resolve` found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Resolution {
    /// Docker host names beyond the written `ssh_host` (the `hostname` of `ssh -G`).
    pub docker_hosts: Vec<String>,
    /// Addresses of the named entries.
    pub addrs: Vec<InfraAddr>,
    /// This machine's interface addresses.
    pub local: Vec<IpAddr>,
}

/// The host of an ssh destination (`user@host`, `ssh://user@host:2222`, `host`), as a policy reads a host.
pub fn docker_host_of(target: &str) -> Option<String> {
    let t = target.trim();
    let t = t.strip_prefix("ssh://").unwrap_or(t);
    let t = t.split('/').next().unwrap_or("");
    let t = t.rsplit_once('@').map_or(t, |(_, h)| h);
    let host = if let Some(rest) = t.strip_prefix('[') {
        let (inner, _) = rest.split_once(']')?;
        format!("[{inner}]")
    } else if t.matches(':').count() == 1 {
        t.split(':').next().unwrap_or("").to_string()
    } else if t.contains(':') {
        format!("[{t}]")
    } else {
        t.to_string()
    };
    let ok = !host.is_empty() && host != "[]";
    (ok && !host.starts_with('-') && !host.chars().any(|c| c.is_whitespace() || c == '@')).then_some(host)
}

/// The `hostname` line of `ssh -G` output.
pub fn ssh_hostname(output: &str) -> Option<String> {
    output.lines().find_map(|l| {
        let (key, value) = l.trim().split_once(char::is_whitespace)?;
        (key.eq_ignore_ascii_case("hostname") && !value.trim().is_empty()).then(|| value.trim().to_string())
    })
}

/// A `host` and its optional port from an entry (`host`, `host:8000`, `[::1]:80`); `None` for a CIDR
/// block, a wildcard or an entry that is not a plain name.
fn plain_name(entry: &str) -> Option<(String, Option<u16>)> {
    let e = entry.trim();
    if e.is_empty() || e.contains('/') || e.starts_with('*') || e.starts_with('[') {
        return None;
    }
    let (host, port) = match e.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (h, Some(p.parse::<u16>().ok()?)),
        Some(_) => return None,
        None => (e, None),
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let local = host == "localhost" || host.ends_with(".localhost");
    (!host.is_empty() && !local && host.parse::<IpAddr>().is_err()).then_some((host, port))
}

fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_loopback() || a.is_unspecified(),
        IpAddr::V6(a) => {
            a.is_loopback() || a.is_unspecified() || a.to_ipv4_mapped().is_some_and(|m| is_local(m.into()))
        }
    }
}

/// The ports of the infrastructure entries that name this machine (`localhost`, a loopback or unspecified
/// address) with a port: a model endpoint's, a service's (the Signal bridge's signal-cli, usually
/// `127.0.0.1:1337`; the OAST broker's listeners on the ports they were bound to) and a `network.infrastructure`
/// entry's. The sandbox refuses them to every command whatever
/// loopback it allows (`SandboxCfg::infra_ports`).
pub fn loopback_ports(config: &Config) -> Vec<u16> {
    let entries = config
        .models
        .values()
        .filter_map(|m| crate::runtime::endpoint_of(&m.base_url))
        .chain(crate::runtime::service_endpoints(config).into_iter().map(|(_, e)| e))
        .chain(config.network.infrastructure.iter().cloned());
    endpoint_loopback_ports(entries)
}

/// The ports of the `host:port` entries that name this machine, as [`loopback_ports`] reads them, sorted.
pub fn endpoint_loopback_ports(entries: impl IntoIterator<Item = String>) -> Vec<u16> {
    let mut out: Vec<u16> = Vec::new();
    for e in entries {
        let e = e.trim();
        let (host, port) = match e.strip_prefix('[') {
            Some(rest) => match rest.split_once("]:") {
                Some((h, p)) => (h, p),
                None => continue,
            },
            None => match e.rsplit_once(':') {
                Some((h, p)) if !h.contains(':') => (h, p),
                _ => continue,
            },
        };
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let on_this_machine =
            host == "localhost" || host.ends_with(".localhost") || host.parse::<IpAddr>().is_ok_and(is_local);
        if let (true, Ok(p)) = (on_this_machine, port.parse::<u16>()) {
            if !out.contains(&p) {
                out.push(p);
            }
        }
    }
    out.sort_unstable();
    out
}

/// Resolve the named infrastructure of `config` (see the module contract).
pub fn resolve(
    config: &Config,
    ssh_g: &dyn Fn(&str) -> Option<String>,
    lookup: &dyn Fn(&str) -> Vec<IpAddr>,
    local: Vec<IpAddr>,
) -> Resolution {
    let mut out = Resolution { local, ..Resolution::default() };
    let add = |out: &mut Resolution, label: String, host: &str, port: Option<u16>, drop_local: bool| {
        for addr in lookup(host) {
            if drop_local && is_local(addr) {
                continue;
            }
            let entry = InfraAddr { label: label.clone(), addr, port };
            if !out.addrs.contains(&entry) {
                out.addrs.push(entry);
            }
        }
    };
    let ssh = config.boxed.ssh_host.trim();
    if config.boxed.enabled && !ssh.is_empty() {
        let direct = docker_host_of(ssh);
        let via = ssh_g(ssh).and_then(|o| ssh_hostname(&o)).and_then(|h| docker_host_of(&h));
        for (i, host) in [direct.clone(), via].into_iter().flatten().enumerate() {
            if i > 0 && direct.as_deref() == Some(host.as_str()) {
                continue;
            }
            if i > 0 {
                out.docker_hosts.push(host.clone());
            }
            let bare = host.trim_start_matches('[').trim_end_matches(']');
            match bare.parse::<IpAddr>() {
                Ok(a) if !is_local(a) => {
                    let entry = InfraAddr { label: format!("Docker host {host}"), addr: a, port: None };
                    if !out.addrs.contains(&entry) {
                        out.addrs.push(entry);
                    }
                }
                Ok(_) => {}
                Err(_) => add(&mut out, format!("Docker host {host}"), bare, None, true),
            }
        }
    }
    for e in config.models.values().filter_map(|m| crate::runtime::endpoint_of(&m.base_url)) {
        if let Some((host, port)) = plain_name(&e) {
            add(&mut out, format!("model endpoint {e}"), &host, port, false);
        }
    }
    for (key, e) in crate::runtime::service_endpoints(config) {
        if let Some((host, port)) = plain_name(&e) {
            add(&mut out, format!("{key} {e}"), &host, port, false);
        }
    }
    for e in &config.network.infrastructure {
        if let Some((host, port)) = plain_name(e) {
            add(&mut out, format!("network.infrastructure {e}"), &host, port, false);
        }
    }
    out
}

/// `resolve` with the real `ssh -G`, resolver and interfaces. Blocks.
pub fn resolve_system(config: &Config) -> Resolution {
    resolve(config, &ssh_g, &system_lookup, local_addresses())
}

fn system_lookup(host: &str) -> Vec<IpAddr> {
    match (host, 0u16).to_socket_addrs() {
        Ok(it) => it.map(|a| a.ip()).collect(),
        Err(_) => Vec::new(),
    }
}

/// The output of `ssh -G <target>`: the configuration ssh would use, without connecting.
fn ssh_g(target: &str) -> Option<String> {
    let mut child = Command::new("ssh")
        .args(["-G", "--", target])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let started = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(_)) | Err(_) => return None,
            Ok(None) if started.elapsed() > SSH_G_LIMIT => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    let mut text = String::new();
    std::io::Read::read_to_string(&mut child.stdout.take()?, &mut text).ok()?;
    Some(text)
}

/// This machine's interface addresses.
pub fn local_addresses() -> Vec<IpAddr> {
    let mut out = Vec::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `getifaddrs` fills `head` with a list it owns; the list is only read until `freeifaddrs`.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return out;
    }
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is a node of the list `getifaddrs` returned, valid until `freeifaddrs`.
        let ifa = unsafe { &*cur };
        let sa = ifa.ifa_addr;
        if !sa.is_null() {
            // SAFETY: a non-null `ifa_addr` points at a socket address whose family says its layout.
            let family = i32::from(unsafe { (*sa).sa_family });
            let addr = if family == libc::AF_INET {
                // SAFETY: the family is AF_INET, so the address is a `sockaddr_in`.
                let sin = unsafe { &*(sa as *const libc::sockaddr_in) };
                Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr))))
            } else if family == libc::AF_INET6 {
                // SAFETY: the family is AF_INET6, so the address is a `sockaddr_in6`.
                let sin6 = unsafe { &*(sa as *const libc::sockaddr_in6) };
                Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
            } else {
                None
            };
            if let Some(a) = addr {
                if !out.contains(&a) {
                    out.push(a);
                }
            }
        }
        cur = ifa.ifa_next;
    }
    // SAFETY: `head` came from `getifaddrs` and nothing points into the list any more.
    unsafe { libc::freeifaddrs(head) };
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferret_core::config::ModelProfile;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn an_ssh_destination_is_reduced_to_its_host() {
        for (target, want) in [
            ("ferret-box", Some("ferret-box")),
            ("jeweled@ferret-box", Some("ferret-box")),
            ("ssh://jeweled@ferret-box:2222", Some("ferret-box")),
            ("ferret-box:22", Some("ferret-box")),
            ("[::1]:22", Some("[::1]")),
            ("user@10.0.0.5", Some("10.0.0.5")),
            ("fe80::1", Some("[fe80::1]")),
            ("  ", None),
            ("user@", None),
            ("ssh://", None),
        ] {
            assert_eq!(docker_host_of(target).as_deref(), want, "{target}");
        }
    }

    #[test]
    fn ssh_g_output_gives_its_hostname() {
        let out = "user jeweled\nhostname h510.tail1234.ts.net\nport 22\n";
        assert_eq!(ssh_hostname(out).as_deref(), Some("h510.tail1234.ts.net"));
        assert_eq!(ssh_hostname("user x\nport 22\n"), None);
    }

    fn boxed(ssh: &str) -> Config {
        let mut c = Config::default();
        c.models.clear();
        c.boxed.enabled = true;
        c.boxed.ssh_host = ssh.into();
        c
    }

    #[test]
    fn an_ssh_alias_is_resolved_to_the_host_it_names_and_the_addresses_of_that() {
        let c = boxed("jeweled@ferret-box");
        let ssh_g = |t: &str| (t == "jeweled@ferret-box").then(|| "hostname h510.tail1234.ts.net\n".to_string());
        let lookup = |h: &str| match h {
            "h510.tail1234.ts.net" => vec![ip("100.101.102.103")],
            "ferret-box" => vec![],
            _ => vec![ip("203.0.113.9")],
        };
        let r = resolve(&c, &ssh_g, &lookup, vec![]);
        assert_eq!(r.docker_hosts, ["h510.tail1234.ts.net"]);
        assert_eq!(
            r.addrs,
            [InfraAddr { label: "Docker host h510.tail1234.ts.net".into(), addr: ip("100.101.102.103"), port: None }]
        );
        // The alias's HostName is an address: it is the address, and a forward to loopback is dropped.
        let via_ip = |_: &str| Some("hostname 192.168.64.5\n".to_string());
        let r = resolve(&c, &via_ip, &|_| vec![], vec![]);
        assert_eq!(r.addrs.len(), 1);
        assert_eq!(r.addrs[0].addr, ip("192.168.64.5"));
        let via_lo = |_: &str| Some("hostname 127.0.0.1\n".to_string());
        assert!(resolve(&c, &via_lo, &|_| vec![ip("127.0.0.1")], vec![]).addrs.is_empty());
    }

    #[test]
    fn model_endpoints_and_infrastructure_names_are_resolved_with_their_ports() {
        let mut c = Config::default();
        c.models.clear();
        for (n, u) in [
            ("a", "http://spark-one.tail1234.ts.net:8000/v1"),
            ("b", "http://127.0.0.1:9920/v1"),
            ("c", "http://10.0.0.5:8000/v1"),
        ] {
            c.models.insert(n.into(), ModelProfile { base_url: u.into(), ..ModelProfile::default() });
        }
        c.network.infrastructure =
            vec!["lab-gw:5555".into(), "*.x.test".into(), "10.1.0.0/16".into(), "localhost".into()];
        let looked = std::cell::RefCell::new(Vec::new());
        let lookup = |h: &str| {
            looked.borrow_mut().push(h.to_string());
            vec![ip("100.101.102.103")]
        };
        let r = resolve(&c, &|_| None, &lookup, vec![ip("192.168.1.10")]);
        assert_eq!(*looked.borrow(), ["spark-one.tail1234.ts.net", "lab-gw"], "only plain names are looked up");
        assert_eq!(r.addrs.len(), 2);
        assert_eq!(r.addrs[0].port, Some(8000));
        assert_eq!(r.addrs[1].port, Some(5555));
        assert_eq!(r.local, [ip("192.168.1.10")]);
    }

    #[test]
    fn the_loopback_ports_of_infrastructure_are_listed_for_the_sandbox() {
        let mut c = Config::default();
        c.models.clear();
        for (n, u) in [
            ("a", "http://127.0.0.1:9920/v1"),
            ("b", "http://localhost:8000/v1"),
            ("c", "http://spark.test:7000/v1"),
            ("d", "http://[::1]:8100/v1"),
        ] {
            c.models.insert(n.into(), ModelProfile { base_url: u.into(), ..ModelProfile::default() });
        }
        c.network.infrastructure = vec!["127.0.0.1:5555".into(), "localhost".into(), "10.0.0.1:81".into()];
        assert_eq!(loopback_ports(&c), [5555, 8000, 8100, 9920]);
        // The Signal bridge's signal-cli on this machine, once the bridge is enabled.
        c.signal.enabled = true;
        assert_eq!(loopback_ports(&c), [1337, 5555, 8000, 8100, 9920]);
    }

    #[test]
    fn the_mail_server_is_resolved_with_its_port() {
        let mut c = Config::default();
        c.models.clear();
        c.mail.enabled = true;
        c.mail.host = "imap.example.test".into();
        let r = resolve(&c, &|_| None, &|_| vec![ip("203.0.113.25")], vec![]);
        assert_eq!(
            r.addrs,
            [InfraAddr { label: "mail.host imap.example.test:993".into(), addr: ip("203.0.113.25"), port: Some(993) }]
        );
    }

    #[test]
    fn the_interfaces_include_loopback() {
        assert!(local_addresses().iter().any(|a| a.is_loopback()));
    }
}
