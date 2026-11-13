//! The box: one container per mission, on a Docker host, that the agent's commands run in.
//!
//! CONTRACT.
//!
//! The agent never reaches Docker. This module is used by the daemon and by the three box tools
//! (`box_exec`, `box_get`, `box_reset`), which are the only things a session can do with a box. The
//! agent's text is never a docker argument, an ssh argument, an iptables argument or shell text on this
//! machine: the docker command line client is run by the daemon, outside every sandbox, with an argv that
//! loom builds (the pure `*_args` functions below), a minimal environment (`PATH`, `HOME`), and
//! `--host unix://<socket>`. A command of the agent is the single last argument of
//! `/bin/bash -c <fixed text> _ <pid file> <script>` inside the container.
//!
//! ## Reaching Docker (`DockerHost`)
//! `DockerHost::new(cfg, loom_home)` resolves `docker_cli` on the daemon's `PATH` (a name with a `/` is
//! taken as a path) and fixes the socket: `docker_socket`, or with `ssh_host` the forwarded socket
//! `<loom home>/keys/box.sock`. That directory is private to the daemon and unreadable to commands
//! (`Sandbox` makes `<loom home>/keys` unreadable), and the socket is never added to
//! `sandbox.unix_sockets`. A socket path longer than 100 bytes is refused with a sentence.
//! The forward is started lazily by the first use (`ensure_forward`) as
//! `ssh -o BatchMode=yes -o ExitOnForwardFailure=yes -o ControlPath=none -o ForwardAgent=no
//! -o ServerAliveInterval=15 -N -L <socket>:<remote_socket> -- <ssh_host>` ([`ssh_args`]), supervised: a stale
//! socket file is removed before each start, an exit restarts it after a backoff of 1 s doubling to 30 s
//! (reset after a minute of uptime), and `shutdown` stops it and removes the socket. It reads the
//! operator's own ssh configuration, which is where an alias such as `loom-box` (with its ProxyJump) is defined.
//! `DockerHost::docker(args, stdin)` runs one docker command and returns its status, output (at most
//! `max_out` bytes) and error text; it never returns before the process has ended or a 10-minute limit.
//!
//! ## Names and labels
//! For a mission id `m`: container and network `loom-<m>` (when `m` is not a plain Docker name,
//! `loom-<short>`), `short` being the first 12 hex digits of the SHA-256 of `m`; iptables chain
//! `LOOM-<short>`; bridge interface `lb-<short>` (set with the network's bridge-name option, so the rule
//! can name it). Every container and network carries `loom.home=<hash of the loom home>` and
//! `loom.mission=<m>`.
//!
//! ## The container (I2)
//! [`run_args`] builds the one `docker run`. Fixed by loom, nothing in the config can undo it: all
//! capabilities dropped and only `cap_add` added back (config load refuses the dangerous ones),
//! `no-new-privileges`, pids/memory/cpus limits (memory-swap equal to memory), a read-only root with
//! tmpfs on `/tmp` and `/work` (`nosuid,nodev`, owned by 1000:1000, sizes from the config), user
//! 1000:1000, its own network (below), a private IPC namespace, no bind mount or volume, no device, no
//! privileged mode, and no host network, pid, ipc or uts namespace. The entry point is replaced by
//! `/bin/sleep 2147483647`.
//!
//! ## Egress (I4)
//! The mission's network `loom-<m>` is a bridge with IPv6 off. The container's DNS is `192.0.2.1`, which is
//! not routable, so Docker's resolver cannot answer and nothing can be sent out through DNS. The
//! destinations the box may reach are the mission's granted hosts that are exact names or IP literals
//! (with an optional `:port`; none means every port). A wildcard (`*.x`, `*`) is not applied; the first
//! `box_exec` result of a session says so once ([`MissionBox::take_notice`]). The daemon resolves names
//! ([`resolve_names`]); [`plan_egress`] then passes each resolved address through
//! `loom_net::policy::Policy::check_addr` with the session's effective policy (private and special
//! addresses need `allow_private`, `deny` entries apply, and an entry that denies some ports refuses a
//! grant of all ports), and keeps IPv4 addresses only (the network has no IPv6). The names that were
//! resolved, with the addresses that passed, are written to the container's `/etc/hosts` by the daemon
//! (`docker exec -u 0 -i`, the text on stdin). The rules are the chain `LOOM-<short>`
//! ([`rules_text`]): ACCEPT established and related, ACCEPT each allowed `ip/32` per protocol (tcp and
//! udp, with `--dport` when a port was granted), DROP the rest. The chain is jumped to from `DOCKER-USER`
//! (forwarded packets) and from `INPUT` (packets to the Docker host itself) for packets that enter on the
//! bridge interface. It is installed or replaced atomically (`iptables-restore --noflush`) by the operator's
//! `helper_image`, run as `--rm --network host --cap-drop ALL --cap-add NET_ADMIN` with a fixed script;
//! the only variable parts are validated addresses and ports that loom formats itself, and chain and
//! interface names that are derived from a hash.
//! The container is started only after its rules are in place. When rules cannot be brought up to date
//! while a container exists, the container is removed (fail closed).
//!
//! ## Life of a box (`MissionBox`, I5)
//! One per mission, created by the runtime with a source of the mission's grants and effective policy.
//! `ready` creates the network, the rules and the container when there is no running container (it
//! adopts one that is running, re-applying the rules). `reset` removes the container and makes a new one.
//! `resync` re-applies the rules to the current grants when the box exists. `teardown` removes the
//! container, then the network, then the chain (in that order, so that a container is never left without
//! its filter), best effort. [`reconcile`] removes the containers, networks and chains labelled with this
//! loom home whose mission is not in the set it is given.
//!
//! ## Commands (`launcher`, I1)
//! `launcher(call, cwd, script)` returns the `proc::Launcher` that `bash::run_launched` runs:
//! `docker exec -u 1000:1000 -w /work[/cwd] -e HOME=/tmp -e TERM=dumb <container> /bin/bash -c
//! 'exec setsid /bin/bash -c '\''echo $$ > "$0"; exec /bin/bash -c "$1"'\'' "$1" "$2"' _ <pid file> <script>`.
//! The command runs in its own session, and the pid file `/tmp/.loom-<call>.pid` holds the process group
//! id. The launcher's `remote_stop` runs `docker exec ... /bin/sh -c 'kill -<SIG> -- -$(cat "$0")'
//! <pid file>` (TERM, then KILL) whenever the job's group is signalled: stopping the local docker client
//! alone would leave the command running in the container.
//!
//! ## Files (`boxfs`)
//! `push` copies changed workspace files to `/work` as a tar stream (`docker cp -a - <ctr>:/work`),
//! `get_tar` reads a path out of the container as a tar stream; what may be sent and how a stream is
//! unpacked is in `boxfs` (I6, I7).
//!
//! Tests required: exact argv of `run`, `exec`, `cp`, `network create`, `rm`, the helper run and the
//! kill (I1, I2, I4); a hostile script reaches the launcher as one argv element; the egress plan for a grant
//! set (private address refused without `allow_private`, wildcard skipped and noticed once, IPv6 skipped,
//! ports kept); the rules text; names and labels; the ssh argv and the forward supervisor with a fake
//! `ssh` (stale socket removed, restarted after an exit); container life with a fake `docker` (created
//! after its rules, reset, resync fail-closed, teardown order, reconcile); a box job's kill reaches the
//! command in the "container" (fake `docker exec` runs it), TERM then KILL.

use crate::boxfs::{self, Manifest};
use crate::proc::{Launcher, RemoteStop};
use crate::sandbox::Sandbox;
use loom_core::config::BoxCfg;
use loom_net::policy::Policy;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

/// The user the box runs commands as.
pub const BOX_USER: &str = "1000:1000";
/// Where the workspace is copied to and commands start.
pub const WORK: &str = "/work";
/// Docker's DNS is pointed here: a documentation address (RFC 5737) that is never routed.
pub const DNS_SINKHOLE: &str = "192.0.2.1";
/// Longest socket path a unix socket can take, with room to spare.
const SOCKET_PATH_MAX: usize = 100;
/// The time one docker command may take.
const DOCKER_LIMIT: Duration = Duration::from_secs(600);
/// What a docker command that only answers a question may print.
const SMALL_OUT: usize = 1 << 20;
/// Resolving one name may take this long.
const RESOLVE_LIMIT: Duration = Duration::from_secs(10);
/// How long the first use waits for the forwarded socket to appear.
const FORWARD_WAIT: Duration = Duration::from_secs(20);

// ---- names ---------------------------------------------------------------------------------------

/// The names of everything that belongs to one mission's box.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Names {
    pub mission: String,
    pub short: String,
    pub container: String,
    pub network: String,
    pub chain: String,
    pub iface: String,
}

/// The names for `mission` (see the module contract).
pub fn names(mission: &str) -> Names {
    let short: String = loom_core::sha256_hex(mission.as_bytes()).chars().take(12).collect();
    let plain = !mission.is_empty()
        && mission.len() <= 64
        && mission.starts_with(|c: char| c.is_ascii_alphanumeric())
        && mission.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
    let base = if plain { format!("loom-{mission}") } else { format!("loom-{short}") };
    Names {
        mission: mission.to_string(),
        container: base.clone(),
        network: base,
        chain: format!("LOOM-{short}"),
        iface: format!("lb-{short}"),
        short,
    }
}

/// The label value that ties a container or network to this loom home.
pub fn home_hash(home: &Path) -> String {
    loom_core::sha256_hex(home.to_string_lossy().as_bytes()).chars().take(16).collect()
}

fn strings<const N: usize>(a: [&str; N]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

fn labels(mission: &str, home: &str) -> Vec<String> {
    vec!["--label".into(), format!("loom.home={home}"), "--label".into(), format!("loom.mission={mission}")]
}

// ---- argv builders (pure) ------------------------------------------------------------------------

/// `docker network create` for the mission's network: a bridge without IPv6, named interface.
pub fn network_args(n: &Names, home: &str) -> Vec<String> {
    let mut a = strings(["network", "create", "--driver", "bridge", "--ipv6=false", "--opt"]);
    a.push(format!("com.docker.network.bridge.name={}", n.iface));
    a.extend(labels(&n.mission, home));
    a.push(n.network.clone());
    a
}

pub fn network_rm_args(n: &Names) -> Vec<String> {
    vec!["network".into(), "rm".into(), n.network.clone()]
}

pub fn rm_args(n: &Names) -> Vec<String> {
    vec!["rm".into(), "--force".into(), "--volumes".into(), n.container.clone()]
}

pub fn running_args(n: &Names) -> Vec<String> {
    vec!["inspect".into(), "--type".into(), "container".into(), "--format".into(), "{{.State.Running}}".into(), n.container.clone()]
}

/// `docker run` of the box (I2). `cfg.cap_add` has passed `BoxCfg::check`.
pub fn run_args(cfg: &BoxCfg, n: &Names, home: &str) -> Vec<String> {
    let mut a = strings(["run", "--detach", "--name"]);
    a.push(n.container.clone());
    a.extend(labels(&n.mission, home));
    a.extend(strings(["--network"]));
    a.push(n.network.clone());
    a.extend(strings(["--dns", DNS_SINKHOLE, "--cap-drop", "ALL"]));
    for cap in cfg.caps() {
        a.push("--cap-add".into());
        a.push(cap);
    }
    a.extend(strings(["--security-opt", "no-new-privileges"]));
    a.push("--pids-limit".into());
    a.push(cfg.pids.to_string());
    a.push("--memory".into());
    a.push(format!("{}m", cfg.memory_mb));
    a.push("--memory-swap".into());
    a.push(format!("{}m", cfg.memory_mb));
    a.push("--cpus".into());
    a.push(cfg.cpus.to_string());
    a.push("--read-only".into());
    a.push("--tmpfs".into());
    a.push(format!("/tmp:rw,nosuid,nodev,size={}m,uid=1000,gid=1000,mode=1777", cfg.tmp_mb));
    a.push("--tmpfs".into());
    a.push(format!("{WORK}:rw,nosuid,nodev,size={}m,uid=1000,gid=1000,mode=0755", cfg.work_mb));
    a.extend(strings(["--user", BOX_USER, "--workdir", WORK, "--ipc", "private", "--restart", "no"]));
    a.extend(strings(["--entrypoint", "/bin/sleep", &cfg.image, "2147483647"]));
    a
}

/// The pid file of a command: `/tmp/.loom-<call id with anything unusual replaced>.pid`.
pub fn pid_file(call_id: &str) -> String {
    let clean: String = call_id
        .chars()
        .take(64)
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    format!("/tmp/.loom-{clean}.pid")
}

/// The fixed text the container's outer bash runs. `$1` is the pid file and `$2` the agent's script.
const EXEC_WRAP: &str = r#"exec setsid /bin/bash -c 'echo $$ > "$0"; exec /bin/bash -c "$1"' "$1" "$2""#;

/// A directory under `/work`: relative, plain components only.
pub fn work_dir(cwd: Option<&str>) -> Result<String, String> {
    let Some(cwd) = cwd.map(str::trim).filter(|c| !c.is_empty() && *c != ".") else { return Ok(WORK.to_string()) };
    let mut out = WORK.to_string();
    for part in cwd.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." || part.chars().any(char::is_control) {
            return Err(format!(
                "The directory `{cwd}` is not usable: `cwd` is relative to {WORK} and cannot contain `..`. Give a path below {WORK}, or leave `cwd` out."
            ));
        }
        out.push('/');
        out.push_str(part);
    }
    Ok(out)
}

/// `docker exec` of one command (I1): `script` is the last argument and is never read by anything but the
/// inner `bash -c` in the container.
pub fn exec_args(n: &Names, call_id: &str, cwd: &str, script: &str) -> Vec<String> {
    let mut a = strings(["exec", "--user", BOX_USER, "--workdir"]);
    a.push(cwd.to_string());
    a.extend(strings(["--env", "HOME=/tmp", "--env", "TERM=dumb"]));
    a.push(n.container.clone());
    a.extend(strings(["/bin/bash", "-c", EXEC_WRAP, "_"]));
    a.push(pid_file(call_id));
    a.push(script.to_string());
    a
}

/// `docker exec` that signals the command's process group in the container (`signal`: `TERM` or `KILL`).
pub fn kill_args(n: &Names, pid_file: &str, signal: &str) -> Vec<String> {
    let sig = if signal == "KILL" { "KILL" } else { "TERM" };
    let mut a = strings(["exec", "--user", BOX_USER]);
    a.push(n.container.clone());
    a.extend(strings(["/bin/sh", "-c"]));
    a.push(format!("kill -{sig} -- -$(cat \"$0\")"));
    a.push(pid_file.to_string());
    a
}

/// `docker exec` that replaces `/etc/hosts` with what arrives on stdin.
pub fn hosts_args(n: &Names) -> Vec<String> {
    let mut a = strings(["exec", "--interactive", "--user", "0"]);
    a.push(n.container.clone());
    a.extend(strings(["/bin/sh", "-c", "cat > /etc/hosts"]));
    a
}

/// `docker cp` of a tar stream on stdin into `/work` (ownership taken from the stream).
pub fn cp_in_args(n: &Names) -> Vec<String> {
    vec!["cp".into(), "--archive".into(), "-".into(), format!("{}:{WORK}", n.container)]
}

/// `docker cp` of `path` (absolute, in the container) to a tar stream on stdout.
pub fn cp_out_args(n: &Names, path: &str) -> Vec<String> {
    vec!["cp".into(), format!("{}:{path}", n.container), "-".into()]
}

pub fn ps_args(home: &str) -> Vec<String> {
    vec![
        "ps".into(),
        "--all".into(),
        "--filter".into(),
        format!("label=loom.home={home}"),
        "--format".into(),
        "{{.Label \"loom.mission\"}}".into(),
    ]
}

pub fn network_ls_args(home: &str) -> Vec<String> {
    vec![
        "network".into(),
        "ls".into(),
        "--filter".into(),
        format!("label=loom.home={home}"),
        "--format".into(),
        "{{.Label \"loom.mission\"}}".into(),
    ]
}

/// The script of the helper run that installs or replaces the chain. `$1` is the chain, `$2` the interface.
const RULES_APPLY: &str = "iptables-restore -w 5 --noflush || exit 1; \
for c in DOCKER-USER INPUT; do iptables -w 5 -C \"$c\" -i \"$2\" -j \"$1\" 2>/dev/null || iptables -w 5 -I \"$c\" 1 -i \"$2\" -j \"$1\" || exit 1; done";
/// The script that removes the jumps, then the chain.
const RULES_REMOVE: &str = "for c in DOCKER-USER INPUT; do while iptables -w 5 -D \"$c\" -i \"$2\" -j \"$1\" 2>/dev/null; do :; done; done; \
iptables -w 5 -F \"$1\" 2>/dev/null; iptables -w 5 -X \"$1\" 2>/dev/null; exit 0";

fn helper_args(cfg: &BoxCfg, interactive: bool, script: &str, n: &Names) -> Vec<String> {
    let mut a = strings(["run", "--rm"]);
    if interactive {
        a.push("--interactive".into());
    }
    a.extend(strings([
        "--network",
        "host",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "NET_ADMIN",
        "--security-opt",
        "no-new-privileges",
        "--read-only",
        "--entrypoint",
        "/bin/sh",
    ]));
    a.push(cfg.helper_image.clone());
    a.extend(strings(["-c"]));
    a.push(script.to_string());
    a.push("_".into());
    a.push(n.chain.clone());
    a.push(n.iface.clone());
    a
}

/// The helper run that installs the chain (its stdin is [`rules_text`]).
pub fn rules_args(cfg: &BoxCfg, n: &Names) -> Vec<String> {
    helper_args(cfg, true, RULES_APPLY, n)
}

/// The helper run that removes the jumps and the chain.
pub fn rules_remove_args(cfg: &BoxCfg, n: &Names) -> Vec<String> {
    helper_args(cfg, false, RULES_REMOVE, n)
}

/// The `iptables-restore` input for the chain: established and related traffic, each allowed address, drop.
pub fn rules_text(n: &Names, allowed: &BTreeSet<Allowed>) -> String {
    let mut t = format!("*filter\n:{} - [0:0]\n", n.chain);
    t.push_str(&format!("-A {} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n", n.chain));
    for a in allowed {
        for proto in ["tcp", "udp"] {
            match a.port {
                Some(p) => t.push_str(&format!("-A {} -d {}/32 -p {proto} -m {proto} --dport {p} -j ACCEPT\n", n.chain, a.ip)),
                None => t.push_str(&format!("-A {} -d {}/32 -p {proto} -j ACCEPT\n", n.chain, a.ip)),
            }
        }
    }
    t.push_str(&format!("-A {} -j DROP\nCOMMIT\n", n.chain));
    t
}

/// The ssh command that forwards the remote Docker socket to the local one.
pub fn ssh_args(cfg: &BoxCfg, socket: &Path) -> Vec<String> {
    let mut a = strings([
        "-o",
        "BatchMode=yes",
        "-o",
        "ExitOnForwardFailure=yes",
        "-o",
        "ControlPath=none",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ServerAliveInterval=15",
        "-N",
        "-L",
    ]);
    a.push(format!("{}:{}", socket.display(), cfg.remote_socket));
    a.push("--".into());
    a.push(cfg.ssh_host.clone());
    a
}

// ---- egress --------------------------------------------------------------------------------------

/// One destination the box may reach.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Allowed {
    pub ip: Ipv4Addr,
    pub port: Option<u16>,
}

/// What the grants and the policy allow the box (see the module contract).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Egress {
    pub allowed: BTreeSet<Allowed>,
    /// The resolved names with the addresses that passed the policy, for `/etc/hosts`.
    pub hosts: BTreeMap<String, BTreeSet<Ipv4Addr>>,
    /// Wildcard grants, which are not applied to the box.
    pub wildcards: Vec<String>,
    /// Entries left out for another reason, each with the reason (logged).
    pub skipped: Vec<String>,
}

/// A grant as `host`, `host:port`, `ip`, `ip:port` or `[v6]:port`: the lower-cased host and the port.
fn split_grant(grant: &str) -> Option<(String, Option<u16>)> {
    let g = grant.trim();
    if let Some(rest) = g.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(p) => Some(p.parse::<u16>().ok()?),
            None if tail.is_empty() => None,
            None => return None,
        };
        return Some((host.to_ascii_lowercase(), port));
    }
    if g.parse::<IpAddr>().is_ok() {
        return Some((g.to_ascii_lowercase(), None));
    }
    match g.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => Some((host.trim_end_matches('.').to_ascii_lowercase(), Some(port.parse::<u16>().ok()?))),
        Some(_) => None,
        None => Some((g.trim_end_matches('.').to_ascii_lowercase(), None)),
    }
}

/// The names in `grants` that have to be resolved (exact names, not IP literals or wildcards).
pub fn grant_names(grants: &[String]) -> Vec<String> {
    let mut out = BTreeSet::new();
    for g in grants {
        if let Some((host, _)) = split_grant(g) {
            if !host.contains('*') && host.parse::<IpAddr>().is_err() && valid_name(&host) {
                out.insert(host);
            }
        }
    }
    out.into_iter().collect()
}

/// A host name that can be written to `/etc/hosts`.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        && !name.starts_with(['-', '.'])
}

/// Resolve `names` on this machine. A name that does not resolve is left out.
pub async fn resolve_names(names: &[String]) -> BTreeMap<String, Vec<IpAddr>> {
    let mut out = BTreeMap::new();
    for name in names {
        let looked = tokio::time::timeout(RESOLVE_LIMIT, tokio::net::lookup_host((name.as_str(), 0))).await;
        if let Ok(Ok(addrs)) = looked {
            let ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
            if !ips.is_empty() {
                out.insert(name.clone(), ips);
            }
        }
    }
    out
}

/// Whether the policy lets `addr` be reached on every port.
fn every_port_ok(policy: &Policy, host: &str, addr: IpAddr) -> bool {
    (0..=u16::MAX).all(|p| policy.check_addr(host, p, addr, "granted").allowed)
}

/// What `grants` allow the box, under `policy`, with names resolved to `resolved` (I4).
pub fn plan_egress(grants: &[String], policy: &Policy, resolved: &BTreeMap<String, Vec<IpAddr>>) -> Egress {
    let mut plan = Egress::default();
    for grant in grants {
        let Some((host, port)) = split_grant(grant) else {
            plan.skipped.push(format!("{grant}: not a host the box can use"));
            continue;
        };
        if host.contains('*') {
            plan.wildcards.push(grant.trim().to_string());
            continue;
        }
        let literal = host.parse::<IpAddr>().ok();
        let addrs: Vec<IpAddr> = match literal {
            Some(ip) => vec![ip],
            None if valid_name(&host) => resolved.get(&host).cloned().unwrap_or_default(),
            None => {
                plan.skipped.push(format!("{grant}: not a host name the box can use"));
                continue;
            }
        };
        if addrs.is_empty() {
            plan.skipped.push(format!("{grant}: the name did not resolve"));
            continue;
        }
        for addr in addrs {
            let IpAddr::V4(v4) = addr else {
                plan.skipped.push(format!("{grant}: {addr} is IPv6, and the box network has none"));
                continue;
            };
            let ok = match port {
                Some(p) => policy.check_addr(&host, p, addr, "granted").allowed,
                None => every_port_ok(policy, &host, addr),
            };
            if !ok {
                let why = policy.check_addr(&host, port.unwrap_or(0), addr, "granted").rule;
                plan.skipped.push(format!("{grant}: {addr} is refused by the network policy ({why})"));
                continue;
            }
            plan.allowed.insert(Allowed { ip: v4, port });
            if literal.is_none() {
                plan.hosts.entry(host.clone()).or_default().insert(v4);
            }
        }
    }
    plan.wildcards.sort();
    plan.wildcards.dedup();
    plan
}

/// The container's `/etc/hosts`.
pub fn hosts_text(hosts: &BTreeMap<String, BTreeSet<Ipv4Addr>>) -> String {
    let mut t = String::from("127.0.0.1 localhost\n::1 localhost ip6-localhost\n");
    for (name, ips) in hosts {
        for ip in ips {
            t.push_str(&format!("{ip} {name}\n"));
        }
    }
    t
}

// ---- the Docker host -----------------------------------------------------------------------------

/// What a docker command printed.
#[derive(Debug)]
pub struct DockerOut {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: String,
}

impl DockerOut {
    pub fn ok(&self) -> bool {
        self.code == 0
    }
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).trim().to_string()
    }
    /// The error text, or the status when there is none.
    pub fn why(&self) -> String {
        let e = self.stderr.trim();
        if e.is_empty() {
            format!("docker exited with status {}", self.code)
        } else {
            crate::preview(e, 600)
        }
    }
}

struct Forward {
    task: tokio::task::JoinHandle<()>,
    stop: Arc<tokio::sync::Notify>,
}

/// The connection to one Docker host. Shared by the whole daemon.
pub struct DockerHost {
    pub cfg: BoxCfg,
    home: PathBuf,
    cli: PathBuf,
    socket: PathBuf,
    ssh_program: String,
    forward: Mutex<Option<Forward>>,
    last_ssh_error: Arc<StdMutex<String>>,
}

fn resolve_cli(name: &str) -> Result<PathBuf, String> {
    let executable = |p: &Path| {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    };
    if name.contains('/') {
        let p = PathBuf::from(name);
        return if executable(&p) {
            Ok(p)
        } else {
            Err(format!("box.docker_cli {name} is not an executable file. Install the docker command line client or give its full path."))
        };
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .map(|d| d.join(name))
        .find(|p| executable(p))
        .ok_or_else(|| format!("box.docker_cli `{name}` was not found on the daemon's PATH. Install the docker command line client or give its full path."))
}

impl DockerHost {
    /// Prepare the connection (nothing is started yet). `loom_home` is where `keys/box.sock` lives.
    pub fn new(cfg: &BoxCfg, loom_home: &Path) -> Result<Arc<DockerHost>, String> {
        let cli = resolve_cli(&cfg.docker_cli)?;
        let socket = if cfg.docker_socket.is_empty() {
            loom_home.join("keys").join("box.sock")
        } else {
            PathBuf::from(&cfg.docker_socket)
        };
        if socket.as_os_str().len() > SOCKET_PATH_MAX {
            return Err(format!(
                "The Docker socket path {} is longer than {SOCKET_PATH_MAX} bytes, which a unix socket cannot have. Use a shorter loom home.",
                socket.display()
            ));
        }
        Ok(Arc::new(DockerHost {
            cfg: cfg.clone(),
            home: loom_home.to_path_buf(),
            cli,
            socket,
            ssh_program: "ssh".to_string(),
            forward: Mutex::new(None),
            last_ssh_error: Arc::new(StdMutex::new(String::new())),
        }))
    }

    /// Run `program` instead of `ssh` for the forward (tests).
    #[cfg(any(test, feature = "testutil"))]
    pub fn with_ssh_program(self: Arc<Self>, program: &str) -> Arc<DockerHost> {
        match Arc::try_unwrap(self) {
            Ok(mut h) => {
                h.ssh_program = program.to_string();
                Arc::new(h)
            }
            Err(shared) => shared,
        }
    }

    pub fn home_hash(&self) -> String {
        home_hash(&self.home)
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    pub fn cli(&self) -> &Path {
        &self.cli
    }

    /// The program and the whole argv (host option first) of one docker command.
    pub fn argv(&self, args: &[String]) -> (String, Vec<String>) {
        let mut full = vec!["--host".to_string(), format!("unix://{}", self.socket.display())];
        full.extend(args.iter().cloned());
        (self.cli.display().to_string(), full)
    }

    /// The environment of every process this module starts: `PATH` and `HOME`, nothing of the agent's.
    fn base_env() -> Vec<(&'static str, String)> {
        ["PATH", "HOME"].iter().filter_map(|k| Some((*k, std::env::var(k).ok()?))).collect()
    }

    /// Make sure the socket can be used: start the ssh forward when one is configured.
    pub async fn ensure_forward(&self) -> Result<(), String> {
        if self.cfg.docker_socket.is_empty() {
            let mut guard = self.forward.lock().await;
            if guard.is_none() {
                *guard = Some(self.start_forward());
            }
            drop(guard);
        }
        let until = Instant::now() + FORWARD_WAIT;
        loop {
            if std::fs::symlink_metadata(&self.socket).is_ok() {
                return Ok(());
            }
            if !self.cfg.docker_socket.is_empty() {
                return Err(format!(
                    "The Docker socket {} does not exist. Start Docker there, or fix box.docker_socket.",
                    self.socket.display()
                ));
            }
            if Instant::now() >= until {
                let why = self.last_ssh_error.lock().map(|e| e.clone()).unwrap_or_default();
                let why = if why.is_empty() { "it did not come up in time".to_string() } else { why };
                return Err(format!(
                    "The ssh forward to {} did not come up ({why}). The daemon runs `ssh` in batch mode: check that `ssh {}` works without a prompt from the daemon's account.",
                    self.cfg.ssh_host, self.cfg.ssh_host
                ));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn start_forward(&self) -> Forward {
        let stop = Arc::new(tokio::sync::Notify::new());
        let (program, args, socket) = (self.ssh_program.clone(), ssh_args(&self.cfg, &self.socket), self.socket.clone());
        let (stop2, errors) = (stop.clone(), self.last_ssh_error.clone());
        let task = tokio::spawn(async move {
            let mut backoff = Duration::from_secs(1);
            loop {
                let _ = std::fs::remove_file(&socket);
                let started = Instant::now();
                let mut cmd = tokio::process::Command::new(&program);
                cmd.args(&args)
                    .env_clear()
                    .envs(DockerHost::base_env())
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::piped())
                    .kill_on_drop(true);
                match cmd.spawn() {
                    Ok(mut child) => {
                        let stopped = tokio::select! {
                            _ = child.wait() => false,
                            () = stop2.notified() => { let _ = child.kill().await; true }
                        };
                        let mut text = String::new();
                        if let Some(mut e) = child.stderr.take() {
                            let _ = tokio::time::timeout(Duration::from_millis(200), (&mut e).take(4096).read_to_string(&mut text)).await;
                        }
                        if let Ok(mut last) = errors.lock() {
                            *last = text.trim().to_string();
                        }
                        if stopped {
                            break;
                        }
                        tracing::warn!("box: the ssh forward ended: {}", text.trim());
                    }
                    Err(e) => {
                        if let Ok(mut last) = errors.lock() {
                            *last = format!("{program} could not be started: {e}");
                        }
                    }
                }
                let _ = std::fs::remove_file(&socket);
                if started.elapsed() > Duration::from_secs(60) {
                    backoff = Duration::from_secs(1);
                }
                tokio::select! {
                    () = tokio::time::sleep(backoff) => {}
                    () = stop2.notified() => break,
                }
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
            let _ = std::fs::remove_file(&socket);
        });
        Forward { task, stop }
    }

    /// Stop the forward and remove its socket.
    pub async fn shutdown(&self) {
        let forward = self.forward.lock().await.take();
        if let Some(f) = forward {
            f.stop.notify_waiters();
            f.stop.notify_one();
            if tokio::time::timeout(Duration::from_secs(5), f.task).await.is_err() {
                tracing::warn!("box: the ssh forward did not stop in time");
            }
        }
        if self.cfg.docker_socket.is_empty() {
            let _ = std::fs::remove_file(&self.socket);
        }
    }

    /// Run one docker command (the forward is started first).
    pub async fn docker(&self, args: &[String], stdin: Option<Vec<u8>>, max_out: usize) -> Result<DockerOut, String> {
        self.ensure_forward().await?;
        let (program, full) = self.argv(args);
        let mut cmd = tokio::process::Command::new(program);
        cmd.args(full)
            .env_clear()
            .envs(Self::base_env())
            .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = cmd.spawn().map_err(|e| format!("The docker command line client could not be run ({e})."))?;
        let mut sin = child.stdin.take();
        let mut sout = child.stdout.take().ok_or("docker gave no output pipe")?;
        let mut serr = child.stderr.take().ok_or("docker gave no error pipe")?;
        let (big_tx, mut big_rx) = tokio::sync::oneshot::channel::<()>();
        let out_task = tokio::spawn(async move {
            let mut buf = Vec::new();
            let r = (&mut sout).take(max_out as u64 + 1).read_to_end(&mut buf).await;
            if buf.len() > max_out {
                let _ = big_tx.send(());
            }
            r.map(|_| buf)
        });
        let err_task = tokio::spawn(async move {
            let mut buf = Vec::new();
            let _ = (&mut serr).take(64 * 1024).read_to_end(&mut buf).await;
            String::from_utf8_lossy(&buf).to_string()
        });
        let in_task = tokio::spawn(async move {
            if let (Some(mut pipe), Some(bytes)) = (sin.take(), stdin) {
                let _ = pipe.write_all(&bytes).await;
                let _ = pipe.shutdown().await;
            }
        });
        let waited = tokio::time::timeout(DOCKER_LIMIT, async {
            tokio::select! {
                status = child.wait() => Ok(status),
                Ok(()) = &mut big_rx => {
                    let _ = child.kill().await;
                    Err(format!("docker printed more than {max_out} bytes, which is more than allowed here"))
                }
            }
        })
        .await;
        let status = match waited {
            Ok(Ok(status)) => status.map_err(|e| format!("docker could not be waited for ({e})"))?,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                let _ = child.kill().await;
                return Err("The docker command took longer than ten minutes and was stopped.".to_string());
            }
        };
        let _ = in_task.await;
        let stdout = out_task
            .await
            .map_err(|e| format!("docker's output could not be read ({e})"))?
            .map_err(|e| format!("docker's output could not be read ({e})"))?;
        if stdout.len() > max_out {
            return Err(format!("docker printed more than {max_out} bytes, which is more than allowed here"));
        }
        let stderr = err_task.await.unwrap_or_default();
        Ok(DockerOut { code: status.code().unwrap_or(-1), stdout, stderr })
    }

    /// `docker` with a short answer; a failure is an error with docker's own text.
    async fn run_ok(&self, what: &str, args: &[String], stdin: Option<Vec<u8>>) -> Result<DockerOut, String> {
        let out = self.docker(args, stdin, SMALL_OUT).await?;
        if out.ok() {
            Ok(out)
        } else {
            Err(format!("{what} failed on the Docker host: {}", out.why()))
        }
    }
}

// ---- one mission's box ---------------------------------------------------------------------------

/// The mission's granted hosts and the effective network policy of its sessions, now.
pub type EgressSource = Arc<dyn Fn() -> Result<(Vec<String>, Policy), String> + Send + Sync>;

#[derive(Default)]
struct State {
    up: bool,
    pushed: Manifest,
}

/// What a push did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PushReport {
    pub files: usize,
    pub bytes: u64,
    pub notes: Vec<String>,
}

/// One mission's container, network and rules. All changes are made one at a time.
pub struct MissionBox {
    host: Arc<DockerHost>,
    names: Names,
    home: String,
    source: EgressSource,
    state: Mutex<State>,
    wildcards: StdMutex<Vec<String>>,
    told: StdMutex<HashSet<String>>,
}

impl MissionBox {
    pub fn new(host: Arc<DockerHost>, mission: &str, source: EgressSource) -> Arc<MissionBox> {
        let home = host.home_hash();
        Arc::new(MissionBox {
            names: names(mission),
            home,
            host,
            source,
            state: Mutex::new(State::default()),
            wildcards: StdMutex::new(Vec::new()),
            told: StdMutex::new(HashSet::new()),
        })
    }

    pub fn names(&self) -> &Names {
        &self.names
    }

    pub fn cfg(&self) -> &BoxCfg {
        &self.host.cfg
    }

    async fn run_ok(&self, what: &str, args: Vec<String>) -> Result<DockerOut, String> {
        self.host.run_ok(what, &args, None).await
    }

    /// Whether the container exists and is running now.
    pub async fn running(&self) -> bool {
        self.is_running().await
    }

    async fn is_running(&self) -> bool {
        match self.host.docker(&running_args(&self.names), None, SMALL_OUT).await {
            Ok(o) => o.ok() && o.text() == "true",
            Err(_) => false,
        }
    }

    /// The plan for the grants of this moment.
    async fn plan(&self) -> Result<Egress, String> {
        let (grants, policy) = (self.source)()?;
        let resolved = resolve_names(&grant_names(&grants)).await;
        let plan = plan_egress(&grants, &policy, &resolved);
        if let Ok(mut w) = self.wildcards.lock() {
            w.clone_from(&plan.wildcards);
        }
        for s in &plan.skipped {
            tracing::info!(mission = %self.names.mission, "box egress: {s}");
        }
        Ok(plan)
    }

    async fn install_rules(&self, plan: &Egress) -> Result<(), String> {
        let text = rules_text(&self.names, &plan.allowed).into_bytes();
        self.host.run_ok("Installing the egress rules", &rules_args(&self.host.cfg, &self.names), Some(text)).await.map(|_| ())
    }

    async fn write_hosts(&self, plan: &Egress) -> Result<(), String> {
        let text = hosts_text(&plan.hosts).into_bytes();
        self.host.run_ok("Writing the container's /etc/hosts", &hosts_args(&self.names), Some(text)).await.map(|_| ())
    }

    async fn ensure_locked(&self, st: &mut State) -> Result<(), String> {
        self.host.ensure_forward().await?;
        if st.up {
            if self.is_running().await {
                return Ok(());
            }
            st.up = false;
            st.pushed.clear();
        }
        let plan = self.plan().await?;
        if self.is_running().await {
            // A box from before a restart of the daemon: bring its rules to the grants of now.
            self.install_rules(&plan).await?;
            self.write_hosts(&plan).await?;
            st.up = true;
            st.pushed.clear();
            return Ok(());
        }
        // Leftovers of an earlier box of this mission (stopped container, network).
        let _ = self.host.docker(&rm_args(&self.names), None, SMALL_OUT).await;
        let made = self.host.docker(&network_args(&self.names, &self.home), None, SMALL_OUT).await?;
        if !made.ok() && !made.stderr.contains("already exists") {
            return Err(format!("Creating the box network failed on the Docker host: {}", made.why()));
        }
        // The container starts only once the rules that confine it are in place.
        self.install_rules(&plan).await?;
        self.run_ok("Starting the box", run_args(&self.host.cfg, &self.names, &self.home)).await?;
        if let Err(e) = self.write_hosts(&plan).await {
            let _ = self.host.docker(&rm_args(&self.names), None, SMALL_OUT).await;
            return Err(e);
        }
        st.up = true;
        st.pushed.clear();
        Ok(())
    }

    /// Make sure the container is running, creating it (network, rules, container) when it is not.
    pub async fn ready(&self) -> Result<(), String> {
        let mut st = self.state.lock().await;
        self.ensure_locked(&mut st).await
    }

    /// Remove the container and make a new one. What was in `/work` is gone.
    pub async fn reset(&self) -> Result<(), String> {
        let mut st = self.state.lock().await;
        self.host.ensure_forward().await?;
        self.run_ok("Removing the box", rm_args(&self.names)).await?;
        st.up = false;
        st.pushed.clear();
        self.ensure_locked(&mut st).await
    }

    /// Bring the rules to the mission's grants as they are now, if the box exists. When that cannot be
    /// done the container is removed, so that it never has more than the grants allow.
    pub async fn resync(&self) {
        let mut st = self.state.lock().await;
        if self.host.ensure_forward().await.is_err() || !self.is_running().await {
            return;
        }
        let applied = async {
            let plan = self.plan().await?;
            self.install_rules(&plan).await?;
            self.write_hosts(&plan).await
        }
        .await;
        if let Err(e) = applied {
            tracing::warn!(mission = %self.names.mission, "box: the egress rules could not be updated, so the box is removed: {e}");
            let _ = self.host.docker(&rm_args(&self.names), None, SMALL_OUT).await;
            st.up = false;
            st.pushed.clear();
        }
    }

    /// Remove the container, the network and the chain, in that order (best effort, logged).
    pub async fn teardown(&self) {
        let mut st = self.state.lock().await;
        st.up = false;
        st.pushed.clear();
        teardown_names(&self.host, &self.names).await;
    }

    /// The one-time note about grants the box does not apply, for the first call of `session`.
    pub fn take_notice(&self, session: &str) -> Option<String> {
        let wildcards = self.wildcards.lock().ok()?.clone();
        if wildcards.is_empty() {
            return None;
        }
        let mut told = self.told.lock().ok()?;
        if !told.insert(session.to_string()) {
            return None;
        }
        Some(format!(
            "the box reaches only exact hosts and IP addresses that were granted, and these wildcard grants are not applied to it: {}. Ask for the exact host with request_scope if the box needs it.",
            wildcards.join(", ")
        ))
    }

    /// Copy the files of the workspace that changed since the last push into `/work` (I6).
    pub async fn push(&self, sandbox: Arc<Sandbox>, workspace: PathBuf) -> Result<PushReport, String> {
        let mut st = self.state.lock().await;
        let cfg = &self.host.cfg;
        let limits = boxfs::PushLimits { total: cfg.sync_max_mb.saturating_mul(1 << 20), file: cfg.sync_file_max_mb.saturating_mul(1 << 20) };
        let prev = std::mem::take(&mut st.pushed);
        let built = {
            let prev = prev.clone();
            tokio::task::spawn_blocking(move || boxfs::build_push(&sandbox, &workspace, &prev, limits)).await
        };
        let push = match built {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => {
                st.pushed = prev;
                return Err(e);
            }
            Err(e) => {
                st.pushed = prev;
                return Err(format!("The workspace could not be read for copying ({e})."));
            }
        };
        let report = PushReport { files: push.sent, bytes: push.bytes, notes: push.notes };
        if push.sent == 0 {
            st.pushed = push.manifest;
            return Ok(report);
        }
        match self.host.docker(&cp_in_args(&self.names), Some(push.tar), SMALL_OUT).await {
            Ok(o) if o.ok() => {
                st.pushed = push.manifest;
                Ok(report)
            }
            Ok(o) => {
                st.pushed = prev;
                Err(format!("Copying the workspace files into the box failed on the Docker host: {}", o.why()))
            }
            Err(e) => {
                st.pushed = prev;
                Err(e)
            }
        }
    }

    /// `docker cp <container>:<path> -`: the tar stream, at most `max` bytes (I7 reads it).
    pub async fn get_tar(&self, path: &str, max: usize) -> Result<Vec<u8>, String> {
        let _st = self.state.lock().await;
        if !path.starts_with('/') || path.contains('\0') {
            return Err(format!("The path `{path}` is not absolute in the box."));
        }
        let out = self.host.docker(&cp_out_args(&self.names, path), None, max).await?;
        if !out.ok() {
            return Err(format!("Reading {path} from the box failed: {}", out.why()));
        }
        Ok(out.stdout)
    }

    /// The program that runs one command in the box (I1). `cwd` is relative to `/work`.
    pub fn launcher(&self, call_id: &str, cwd: Option<&str>, script: &str) -> Result<Launcher, String> {
        let dir = work_dir(cwd)?;
        let (program, args) = self.host.argv(&exec_args(&self.names, call_id, &dir, script));
        let pid = pid_file(call_id);
        let (host, n) = (self.host.clone(), self.names.clone());
        let stop = move |sig: i32| {
            let name = if sig == libc::SIGKILL { "KILL" } else { "TERM" };
            let (program, args) = host.argv(&kill_args(&n, &pid, name));
            // Detached: the signal path of a job must not wait for docker.
            if let Ok(mut child) = std::process::Command::new(program)
                .args(args)
                .env_clear()
                .envs(DockerHost::base_env())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
            {
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
            }
        };
        Ok(Launcher { program, args, remote_stop: Some(RemoteStop(Arc::new(stop))) })
    }
}

/// Remove one mission's container, network and chain.
async fn teardown_names(host: &DockerHost, n: &Names) {
    let container = host.docker(&rm_args(n), None, SMALL_OUT).await;
    match container {
        Ok(o) if o.ok() || o.stderr.contains("No such container") => {}
        Ok(o) => {
            tracing::warn!(mission = %n.mission, "box: the container was not removed, so its rules stay: {}", o.why());
            return;
        }
        Err(e) => {
            tracing::warn!(mission = %n.mission, "box: the container was not removed, so its rules stay: {e}");
            return;
        }
    }
    if let Ok(o) = host.docker(&network_rm_args(n), None, SMALL_OUT).await {
        if !o.ok() && !o.stderr.contains("not found") {
            tracing::warn!(mission = %n.mission, "box: the network was not removed: {}", o.why());
        }
    }
    match host.docker(&rules_remove_args(&host.cfg, n), None, SMALL_OUT).await {
        Ok(o) if o.ok() => {}
        Ok(o) => tracing::warn!(mission = %n.mission, "box: the egress chain was not removed: {}", o.why()),
        Err(e) => tracing::warn!(mission = %n.mission, "box: the egress chain was not removed: {e}"),
    }
}

/// Remove the container, network and chain of one mission by name (best effort, logged).
pub async fn teardown_mission(host: &DockerHost, mission: &str) {
    teardown_names(host, &names(mission)).await;
}

/// Remove what boxes of this loom home leave on the Docker host for missions that are not in `running`
/// (I5): containers, networks and chains. Best effort; returns the missions that were cleaned.
pub async fn reconcile(host: &DockerHost, running: &HashSet<String>) -> Vec<String> {
    let home = host.home_hash();
    let mut found: BTreeSet<String> = BTreeSet::new();
    for args in [ps_args(&home), network_ls_args(&home)] {
        match host.docker(&args, None, SMALL_OUT).await {
            Ok(o) if o.ok() => {
                found.extend(o.text().lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()));
            }
            Ok(o) => tracing::warn!("box: listing leftovers failed: {}", o.why()),
            Err(e) => tracing::warn!("box: listing leftovers failed: {e}"),
        }
    }
    let mut cleaned = Vec::new();
    for mission in found {
        let plain = mission.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
        if !plain || running.contains(&mission) {
            continue;
        }
        teardown_names(host, &names(&mission)).await;
        cleaned.push(mission);
    }
    cleaned
}

// ---- test support --------------------------------------------------------------------------------

/// A fake `docker` command line client for tests, in a directory of its own: it appends its argv to a
/// log and emulates `run`, `rm`, `inspect`, `network`, `cp`, `ps` and `exec` just enough (an `exec` of a
/// command runs the command on this machine, as the container would, in `<dir>/work`). Nothing here
/// reaches a real Docker daemon.
#[cfg(any(test, feature = "testutil"))]
pub mod fake {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    pub struct FakeDocker {
        pub dir: PathBuf,
        pub cli: PathBuf,
        pub socket: PathBuf,
    }

    const SCRIPT: &str = r##"#!/bin/sh
D="@DIR@"
entry=$(for a in "$@"; do printf '%s\n' "$a"; done; echo '----'); until mkdir "$D/log.lock" 2>/dev/null; do :; done; printf '%s\n' "$entry" >> "$D/docker.log"; rmdir "$D/log.lock"
[ -f "$D/fail.$3" ] && { echo "boom: $3 failed" >&2; exit 1; }
shift 2
sub=$1; shift
case "$sub" in
  run)
    case " $* " in
      *" --entrypoint /bin/sh "*)
        [ -f "$D/rules.fail" ] && { echo "iptables: failed" >&2; exit 1; }
        case " $* " in *" --interactive "*) cat > "$D/rules.in.$$"; mv "$D/rules.in.$$" "$D/rules.in";; esac
        exit 0;;
    esac
    name=""; prev=""; for a in "$@"; do [ "$prev" = "--name" ] && name="$a"; prev="$a"; done
    touch "$D/ctr-$name"; echo "fakeid"; exit 0;;
  rm) for a in "$@"; do last="$a"; done
      if [ -f "$D/ctr-$last" ]; then rm -f "$D/ctr-$last"; exit 0; fi
      echo "Error: No such container: $last" >&2; exit 1;;
  inspect) for a in "$@"; do last="$a"; done
      if [ -f "$D/ctr-$last" ]; then echo true; exit 0; fi
      echo "Error: No such object: $last" >&2; exit 1;;
  network)
    case "$1" in
      create) for a in "$@"; do last="$a"; done
              if [ -f "$D/net-$last" ]; then echo "network with name $last already exists" >&2; exit 1; fi
              touch "$D/net-$last"; echo netid; exit 0;;
      rm) rm -f "$D/net-$2"; exit 0;;
      ls) [ -f "$D/net.txt" ] && cat "$D/net.txt"; exit 0;;
    esac;;
  ps) [ -f "$D/ps.txt" ] && cat "$D/ps.txt"; exit 0;;
  cp)
    if [ "$1" = "--archive" ]; then n=1; while [ -e "$D/cp-in.$n.tar" ]; do n=$((n+1)); done; cat > "$D/cp-in.$n.tar"; exit 0; fi
    [ -f "$D/cp-out.tar" ] && { cat "$D/cp-out.tar"; exit 0; }
    echo "Error: No such container:path" >&2; exit 1;;
  exec)
    stdin=0
    while [ $# -gt 0 ]; do
      case "$1" in --interactive) stdin=1; shift;; --user|--workdir|--env) shift 2;; *) break;; esac
    done
    ctr=$1; shift
    if [ ! -f "$D/ctr-$ctr" ]; then echo "Error: No such container: $ctr" >&2; exit 1; fi
    if [ "$*" = "/bin/sh -c cat > /etc/hosts" ]; then cat > "$D/etc-hosts"; exit 0; fi
    mkdir -p "$D/work"; cd "$D/work" || exit 1
    command -v setsid >/dev/null 2>&1 || PATH="$D/bin:$PATH"
    export PATH
    exec "$@";;
esac
exit 0
"##;

    impl FakeDocker {
        pub fn new(dir: &Path) -> FakeDocker {
            let dir = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
            std::fs::create_dir_all(&dir).expect("fake docker dir");
            let cli = dir.join("docker");
            std::fs::write(&cli, SCRIPT.replace("@DIR@", &dir.display().to_string())).expect("write fake docker");
            std::fs::set_permissions(&cli, std::fs::Permissions::from_mode(0o755)).expect("chmod fake docker");
            let socket = dir.join("docker.sock");
            std::fs::write(&socket, b"").expect("socket placeholder");
            // Hosts without a `setsid` command (macOS) get one that behaves the same for the box's wrapper.
            std::fs::create_dir_all(dir.join("bin")).expect("fake bin");
            let setsid = dir.join("bin/setsid");
            std::fs::write(&setsid, "#!/usr/bin/perl\nuse POSIX;\nPOSIX::setsid();\nexec { $ARGV[0] } @ARGV;\n").expect("write setsid");
            std::fs::set_permissions(&setsid, std::fs::Permissions::from_mode(0o755)).expect("chmod setsid");
            FakeDocker { dir, cli, socket }
        }

        /// A box config that uses this fake.
        pub fn cfg(&self) -> BoxCfg {
            let digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
            BoxCfg {
                enabled: true,
                docker_socket: self.socket.display().to_string(),
                docker_cli: self.cli.display().to_string(),
                image: digest.to_string(),
                helper_image: format!("helper@{digest}"),
                ..BoxCfg::default()
            }
        }

        /// Every call so far, each as its argv (the host option included).
        pub fn calls(&self) -> Vec<Vec<String>> {
            let text = std::fs::read_to_string(self.dir.join("docker.log")).unwrap_or_default();
            let mut calls = Vec::new();
            let mut cur = Vec::new();
            for line in text.lines() {
                if line == "----" {
                    calls.push(std::mem::take(&mut cur));
                } else {
                    cur.push(line.to_string());
                }
            }
            calls
        }

        /// The calls of one docker subcommand (the argv after `--host <x>`).
        pub fn sub(&self, name: &str) -> Vec<Vec<String>> {
            self.calls().into_iter().filter_map(|c| c.get(2..).map(<[String]>::to_vec)).filter(|c| c.first().is_some_and(|s| s == name)).collect()
        }

        pub fn running(&self, container: &str) -> bool {
            self.dir.join(format!("ctr-{container}")).exists()
        }

        pub fn host(&self) -> Arc<DockerHost> {
            DockerHost::new(&self.cfg(), &self.dir).expect("fake host")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeDocker;
    use super::*;
    use loom_core::config::{NetworkCfg, NetworkMode};

    const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn sample_cfg() -> BoxCfg {
        BoxCfg {
            enabled: true,
            ssh_host: "loom-box".into(),
            remote_socket: "/var/run/docker.sock".into(),
            image: DIGEST.into(),
            helper_image: format!("helper@{DIGEST}"),
            cap_add: vec!["SYS_PTRACE".into(), "cap_net_raw".into()],
            ..BoxCfg::default()
        }
    }

    fn policy(allow_private: &[&str], deny: &[&str]) -> Policy {
        Policy::new(&NetworkCfg {
            mode: NetworkMode::DenyAll,
            allow_private: allow_private.iter().map(|s| s.to_string()).collect(),
            deny: deny.iter().map(|s| s.to_string()).collect(),
            ..NetworkCfg::default()
        })
        .unwrap()
    }

    fn grants(g: &[&str]) -> Vec<String> {
        g.iter().map(|s| s.to_string()).collect()
    }

    fn resolved(pairs: &[(&str, &[&str])]) -> BTreeMap<String, Vec<IpAddr>> {
        pairs.iter().map(|(n, ips)| (n.to_string(), ips.iter().map(|i| i.parse().unwrap()).collect())).collect()
    }

    #[test]
    fn names_are_derived_from_the_mission_and_are_safe() {
        let n = names("m-0123abc");
        assert_eq!(n.container, "loom-m-0123abc");
        assert_eq!(n.network, "loom-m-0123abc");
        assert_eq!(n.short.len(), 12);
        assert_eq!(n.chain, format!("LOOM-{}", n.short));
        assert_eq!(n.iface, format!("lb-{}", n.short));
        assert!(n.iface.len() <= 15 && n.chain.len() <= 28);
        // An id that is not a plain Docker name is not used in one.
        let odd = names("m-x; docker ps");
        assert_eq!(odd.container, format!("loom-{}", odd.short));
        assert_eq!(names("").container, format!("loom-{}", names("").short));
        assert_ne!(names("m-1").short, names("m-2").short);
        assert_eq!(home_hash(Path::new("/h")), home_hash(Path::new("/h")));
        assert_ne!(home_hash(Path::new("/h")), home_hash(Path::new("/h2")));
    }

    #[test]
    fn i2_the_docker_run_argv_is_exactly_this() {
        let n = names("m-1");
        let args = run_args(&sample_cfg(), &n, "HOMEHASH");
        let expected: Vec<String> = [
            "run", "--detach", "--name", "loom-m-1", "--label", "loom.home=HOMEHASH", "--label", "loom.mission=m-1",
            "--network", "loom-m-1", "--dns", "192.0.2.1", "--cap-drop", "ALL", "--cap-add", "SYS_PTRACE", "--cap-add",
            "NET_RAW", "--security-opt", "no-new-privileges", "--pids-limit", "512", "--memory", "8192m", "--memory-swap",
            "8192m", "--cpus", "4", "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=1024m,uid=1000,gid=1000,mode=1777",
            "--tmpfs", "/work:rw,nosuid,nodev,size=4096m,uid=1000,gid=1000,mode=0755", "--user", "1000:1000", "--workdir",
            "/work", "--ipc", "private", "--restart", "no", "--entrypoint", "/bin/sleep", DIGEST, "2147483647",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(args, expected);
        // What must never appear, whatever the configuration.
        for forbidden in ["--privileged", "-v", "--volume", "--mount", "--device", "--pid", "--uts", "--userns", "--cap-add=ALL"] {
            assert!(!args.iter().any(|a| a == forbidden), "{forbidden}");
        }
        for (i, a) in args.iter().enumerate() {
            if matches!(a.as_str(), "--network" | "--ipc") {
                assert!(!matches!(args[i + 1].as_str(), "host" | "none"), "{a} {}", args[i + 1]);
            }
            assert!(!a.starts_with("container:") && !a.contains("docker.sock"), "{a}");
        }
        // No cap_add: nothing is added back.
        let plain = run_args(&BoxCfg { cap_add: vec![], ..sample_cfg() }, &n, "H");
        assert!(!plain.iter().any(|a| a == "--cap-add"));
        assert!(plain.windows(2).any(|w| w == ["--cap-drop", "ALL"]));
    }

    #[test]
    fn i1_a_hostile_script_is_one_argv_element_and_nothing_else_changes() {
        let n = names("m-1");
        let plain = exec_args(&n, "call-1", "/work", "echo hi");
        let hostile = [
            "'; docker ps; '",
            "--privileged",
            "$(docker run --privileged x)",
            "line one\nline two\n; docker rm -f everything",
            "`id`; -- --user 0 /bin/sh",
            "",
        ];
        for script in hostile {
            let a = exec_args(&n, "call-1", "/work", script);
            assert_eq!(a.len(), plain.len(), "{script:?} changed the number of arguments");
            assert_eq!(a.last().map(String::as_str), Some(script), "the script is the last argument, verbatim");
            assert_eq!(a[..a.len() - 1], plain[..plain.len() - 1], "{script:?} changed an argument that is not its own");
        }
        let expected: Vec<String> = [
            "exec", "--user", "1000:1000", "--workdir", "/work", "--env", "HOME=/tmp", "--env", "TERM=dumb", "loom-m-1", "/bin/bash",
            "-c", EXEC_WRAP, "_", "/tmp/.loom-call-1.pid", "echo hi",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(plain, expected);
        // The call id cannot change the shape of the argument it ends up in.
        assert_eq!(pid_file("a/../b c;`x`"), "/tmp/.loom-a____b_c__x_.pid");
        // The directory is relative to /work and never leaves it.
        assert_eq!(work_dir(None).unwrap(), "/work");
        assert_eq!(work_dir(Some("sub/dir")).unwrap(), "/work/sub/dir");
        assert_eq!(work_dir(Some("./a//b/")).unwrap(), "/work/a/b");
        assert!(work_dir(Some("../etc")).is_err());
        assert!(work_dir(Some("a/../../b")).is_err());
    }

    #[test]
    fn the_kill_cp_hosts_network_and_rm_argv_are_exactly_this() {
        let n = names("m-1");
        let kill = kill_args(&n, "/tmp/.loom-c.pid", "TERM");
        assert_eq!(
            kill,
            ["exec", "--user", "1000:1000", "loom-m-1", "/bin/sh", "-c", "kill -TERM -- -$(cat \"$0\")", "/tmp/.loom-c.pid"]
        );
        assert_eq!(kill_args(&n, "/p", "KILL")[6], "kill -KILL -- -$(cat \"$0\")");
        assert_eq!(kill_args(&n, "/p", "x; rm")[6], "kill -TERM -- -$(cat \"$0\")", "the signal is one of two fixed words");
        assert_eq!(hosts_args(&n), ["exec", "--interactive", "--user", "0", "loom-m-1", "/bin/sh", "-c", "cat > /etc/hosts"]);
        assert_eq!(cp_in_args(&n), ["cp", "--archive", "-", "loom-m-1:/work"]);
        assert_eq!(cp_out_args(&n, "/work/out"), ["cp", "loom-m-1:/work/out", "-"]);
        assert_eq!(rm_args(&n), ["rm", "--force", "--volumes", "loom-m-1"]);
        assert_eq!(network_rm_args(&n), ["network", "rm", "loom-m-1"]);
        assert_eq!(
            network_args(&n, "H"),
            [
                "network", "create", "--driver", "bridge", "--ipv6=false", "--opt",
                &format!("com.docker.network.bridge.name={}", n.iface), "--label", "loom.home=H", "--label", "loom.mission=m-1",
                "loom-m-1"
            ]
        );
    }

    #[test]
    fn i4_the_plan_applies_exact_hosts_and_ips_under_the_policy() {
        let g = grants(&[
            "203.0.113.7",          // public IP literal, all ports
            "198.51.100.9:443",     // public IP literal with a port
            "target.test:8080",     // a name with a port
            "both.test",            // a name that resolves to a v4 and a v6 address
            "10.1.2.3",             // private literal: refused
            "internal.test",        // resolves to a private address: refused
            "*.wild.test",          // wildcard: not applied
            "*",                    // wildcard: not applied
            "[2001:db8::1]:80",     // IPv6 literal: skipped
            "gone.test",            // does not resolve
        ]);
        let res = resolved(&[
            ("target.test", &["203.0.113.50"]),
            ("both.test", &["203.0.113.60", "2001:db8::60"]),
            ("internal.test", &["10.9.9.9"]),
        ]);
        let plan = plan_egress(&g, &policy(&[], &[]), &res);
        let a = |ip: &str, port: Option<u16>| Allowed { ip: ip.parse().unwrap(), port };
        let want: BTreeSet<Allowed> = [
            a("203.0.113.7", None),
            a("198.51.100.9", Some(443)),
            a("203.0.113.50", Some(8080)),
            a("203.0.113.60", None),
        ]
        .into_iter()
        .collect();
        assert_eq!(plan.allowed, want);
        assert_eq!(plan.wildcards, ["*", "*.wild.test"]);
        let skipped = plan.skipped.join("\n");
        assert!(skipped.contains("10.1.2.3") && skipped.contains("refused by the network policy"), "{skipped}");
        assert!(skipped.contains("internal.test") && skipped.contains("10.9.9.9"), "{skipped}");
        assert!(skipped.contains("2001:db8::1") && skipped.contains("IPv6"), "{skipped}");
        assert!(skipped.contains("2001:db8::60") && skipped.contains("IPv6"), "{skipped}");
        assert!(skipped.contains("gone.test") && skipped.contains("did not resolve"), "{skipped}");
        // Only names appear in /etc/hosts, with the addresses that passed.
        assert_eq!(plan.hosts.keys().map(String::as_str).collect::<Vec<_>>(), ["both.test", "target.test"]);
        assert_eq!(hosts_text(&plan.hosts), "127.0.0.1 localhost\n::1 localhost ip6-localhost\n203.0.113.60 both.test\n203.0.113.50 target.test\n");
        // The names to resolve: exact names only.
        assert_eq!(grant_names(&g), ["both.test", "gone.test", "internal.test", "target.test"]);
    }

    #[test]
    fn i4_private_addresses_need_allow_private_exactly_as_for_the_proxy() {
        let g = grants(&["10.1.2.3", "internal.test:22", "172.16.0.5"]);
        let res = resolved(&[("internal.test", &["10.9.9.9"])]);
        assert!(plan_egress(&g, &policy(&[], &[]), &res).allowed.is_empty());
        // A CIDR block allows the literal and (on its ports) the name's address.
        let plan = plan_egress(&g, &policy(&["10.0.0.0/8"], &[]), &res);
        let ips: Vec<String> = plan.allowed.iter().map(|a| format!("{}:{:?}", a.ip, a.port)).collect();
        assert_eq!(ips, ["10.1.2.3:None", "10.9.9.9:Some(22)"]);
        // A deny entry still wins over a grant, and one that names ports refuses a grant of all ports.
        let plan = plan_egress(&grants(&["203.0.113.7", "203.0.113.8:22"]), &policy(&[], &["203.0.113.7"]), &BTreeMap::new());
        assert_eq!(plan.allowed.iter().map(|a| a.ip.to_string()).collect::<Vec<_>>(), ["203.0.113.8"]);
        let plan = plan_egress(&grants(&["203.0.113.7", "203.0.113.7:80"]), &policy(&[], &["203.0.113.7:22"]), &BTreeMap::new());
        assert_eq!(plan.allowed.iter().map(|a| a.port).collect::<Vec<_>>(), [Some(80)], "all ports are refused when one is denied");
    }

    #[test]
    fn i4_the_rules_text_and_the_helper_run_are_exactly_this() {
        let n = names("m-1");
        let allowed: BTreeSet<Allowed> = [
            Allowed { ip: "203.0.113.7".parse().unwrap(), port: None },
            Allowed { ip: "203.0.113.50".parse().unwrap(), port: Some(8080) },
        ]
        .into_iter()
        .collect();
        let c = &n.chain;
        assert_eq!(
            rules_text(&n, &allowed),
            format!(
                "*filter\n:{c} - [0:0]\n-A {c} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n\
                 -A {c} -d 203.0.113.7/32 -p tcp -j ACCEPT\n-A {c} -d 203.0.113.7/32 -p udp -j ACCEPT\n\
                 -A {c} -d 203.0.113.50/32 -p tcp -m tcp --dport 8080 -j ACCEPT\n\
                 -A {c} -d 203.0.113.50/32 -p udp -m udp --dport 8080 -j ACCEPT\n-A {c} -j DROP\nCOMMIT\n"
            )
        );
        // Nothing allowed: only the DROP.
        let none = rules_text(&n, &BTreeSet::new());
        assert!(none.ends_with(&format!("-A {c} -j DROP\nCOMMIT\n")) && !none.contains(" -d "), "{none}");
        let cfg = sample_cfg();
        let run = rules_args(&cfg, &n);
        assert_eq!(
            run[..run.len() - 3],
            [
                "run", "--rm", "--interactive", "--network", "host", "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--security-opt",
                "no-new-privileges", "--read-only", "--entrypoint", "/bin/sh", &cfg.helper_image, "-c", RULES_APPLY
            ]
        );
        assert_eq!(run[run.len() - 3..], ["_".to_string(), n.chain.clone(), n.iface.clone()]);
        let rm = rules_remove_args(&cfg, &n);
        assert!(!rm.iter().any(|a| a == "--interactive") && rm.iter().any(|a| a == RULES_REMOVE));
        // The only mission-dependent words are derived from a hash.
        assert!(n.chain.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') && n.iface.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
    }

    #[test]
    fn the_ssh_forward_argv_is_exactly_this() {
        let cfg = sample_cfg();
        let a = ssh_args(&cfg, Path::new("/h/keys/box.sock"));
        assert_eq!(
            a,
            [
                "-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes", "-o", "ControlPath=none", "-o", "ForwardAgent=no", "-o",
                "ServerAliveInterval=15", "-N", "-L", "/h/keys/box.sock:/var/run/docker.sock", "--", "loom-box"
            ]
        );
    }

    #[test]
    fn i1_the_socket_lives_under_keys_and_a_long_path_is_refused() {
        let cfg = sample_cfg();
        let host = DockerHost::new(&BoxCfg { docker_cli: "/bin/sh".into(), ..cfg.clone() }, Path::new("/home/x/.loom")).unwrap();
        assert_eq!(host.socket(), Path::new("/home/x/.loom/keys/box.sock"));
        let (program, argv) = host.argv(&["ps".into()]);
        assert_eq!(program, "/bin/sh");
        assert_eq!(argv, ["--host", "unix:///home/x/.loom/keys/box.sock", "ps"]);
        let long = format!("/{}", "a".repeat(120));
        let err = DockerHost::new(&BoxCfg { docker_cli: "/bin/sh".into(), ..cfg.clone() }, Path::new(&long)).err().unwrap();
        assert!(err.contains("longer than"), "{err}");
        let err = DockerHost::new(&BoxCfg { docker_cli: "no-such-docker-cli".into(), ..cfg }, Path::new("/h")).err().unwrap();
        assert!(err.contains("not found on the daemon's PATH"), "{err}");
    }

    fn source(g: &[&str]) -> EgressSource {
        let g = grants(g);
        Arc::new(move || Ok((g.clone(), policy(&[], &[]))))
    }

    fn subs(f: &FakeDocker) -> Vec<String> {
        f.calls().iter().filter_map(|c| c.get(2).cloned()).collect()
    }

    #[tokio::test]
    async fn a_box_is_created_lazily_with_its_rules_in_place_before_the_container() {
        let dir = tempfile::tempdir().unwrap();
        let f = FakeDocker::new(dir.path());
        let b = MissionBox::new(f.host(), "m-1", source(&["203.0.113.7", "*.wild.test"]));
        assert!(f.calls().is_empty(), "nothing is done before the first use");
        b.ready().await.unwrap();
        // inspect (is one there?) -> rm leftovers -> network -> rules (helper) -> container -> /etc/hosts
        assert_eq!(subs(&f), ["inspect", "rm", "network", "run", "run", "exec"]);
        let runs = f.sub("run");
        assert!(runs[0].iter().any(|a| a == "--entrypoint") && runs[0].iter().any(|a| a == "/bin/sh"), "the helper comes first");
        assert!(runs[1].iter().any(|a| a == "--name"), "then the container");
        let rules = std::fs::read_to_string(f.dir.join("rules.in")).unwrap();
        assert!(rules.contains("-d 203.0.113.7/32 -p tcp -j ACCEPT") && rules.contains("-j DROP"), "{rules}");
        assert!(f.dir.join("etc-hosts").exists());
        // A second call finds it running and does nothing more.
        let before = f.calls().len();
        b.ready().await.unwrap();
        assert_eq!(f.calls().len(), before + 1, "one inspect");
        // The wildcard is told once per session.
        let notice = b.take_notice("s-1").unwrap();
        assert!(notice.contains("*.wild.test") && notice.contains("request_scope"), "{notice}");
        assert!(b.take_notice("s-1").is_none());
        assert!(b.take_notice("s-2").is_some());
        // Every docker call went through the one socket, and none carries an agent word.
        for c in f.calls() {
            assert_eq!(&c[..2], ["--host".to_string(), format!("unix://{}", f.socket.display())]);
        }
    }

    #[tokio::test]
    async fn a_failed_rules_install_leaves_no_container() {
        let dir = tempfile::tempdir().unwrap();
        let f = FakeDocker::new(dir.path());
        std::fs::write(f.dir.join("rules.fail"), "").unwrap();
        let b = MissionBox::new(f.host(), "m-1", source(&["203.0.113.7"]));
        let err = b.ready().await.unwrap_err();
        assert!(err.contains("egress rules") && err.contains("iptables: failed"), "{err}");
        assert!(!f.running("loom-m-1"), "the container is never started without its rules");
    }

    #[tokio::test]
    async fn reset_replaces_the_container_and_resync_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let f = FakeDocker::new(dir.path());
        let b = MissionBox::new(f.host(), "m-1", source(&["203.0.113.7"]));
        b.ready().await.unwrap();
        let runs_before = f.sub("run").len();
        b.reset().await.unwrap();
        assert_eq!(f.sub("run").len(), runs_before + 2, "rules and container again");
        assert!(f.running("loom-m-1"));
        // Resync applies the current grants to a box that exists.
        let helper_runs = f.sub("run").len();
        b.resync().await;
        assert_eq!(f.sub("run").len(), helper_runs + 1);
        // When the rules cannot be updated the box is removed rather than left with old rules.
        std::fs::write(f.dir.join("rules.fail"), "").unwrap();
        b.resync().await;
        assert!(!f.running("loom-m-1"));
        // Resync of a box that does not exist does nothing.
        let n = f.calls().len();
        std::fs::remove_file(f.dir.join("rules.fail")).unwrap();
        b.resync().await;
        assert!(f.sub("run").iter().all(|r| r.iter().any(|a| a == "--entrypoint" || a == "--name")));
        assert!(f.calls().len() <= n + 2);
    }

    #[tokio::test]
    async fn i5_teardown_removes_the_container_then_the_network_then_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let f = FakeDocker::new(dir.path());
        let b = MissionBox::new(f.host(), "m-1", source(&[]));
        b.ready().await.unwrap();
        let mark = f.calls().len();
        b.teardown().await;
        let after: Vec<Vec<String>> = f.calls()[mark..].iter().map(|c| c[2..].to_vec()).collect();
        assert_eq!(after[0], rm_args(b.names()));
        assert_eq!(after[1], network_rm_args(b.names()));
        assert_eq!(after[2], rules_remove_args(&f.cfg(), b.names()));
        assert_eq!(after.len(), 3);
        assert!(!f.running("loom-m-1"));
        // A container that cannot be removed keeps its chain.
        let b2 = MissionBox::new(f.host(), "m-2", source(&[]));
        b2.ready().await.unwrap();
        std::fs::write(f.dir.join("fail.rm"), "").unwrap();
        let mark = f.calls().len();
        b2.teardown().await;
        let after: Vec<String> = f.calls()[mark..].iter().map(|c| c[2].clone()).collect();
        assert_eq!(after, ["rm"], "the network and chain stay while the container is there");
    }

    #[tokio::test]
    async fn i5_reconcile_removes_boxes_of_missions_that_are_not_running() {
        let dir = tempfile::tempdir().unwrap();
        let f = FakeDocker::new(dir.path());
        let host = f.host();
        for m in ["m-live", "m-dead", "m-orphan-net"] {
            std::fs::write(f.dir.join(format!("ctr-{}", names(m).container)), "").unwrap();
        }
        std::fs::write(f.dir.join("ps.txt"), "m-live\nm-dead\nm-bad; x\n").unwrap();
        std::fs::write(f.dir.join("net.txt"), "m-live\nm-dead\nm-orphan-net\n").unwrap();
        let running: HashSet<String> = ["m-live".to_string()].into_iter().collect();
        let cleaned = reconcile(&host, &running).await;
        assert_eq!(cleaned, ["m-dead", "m-orphan-net"]);
        assert!(f.running("loom-m-live"), "a running mission keeps its box");
        assert!(!f.running("loom-m-dead") && !f.running("loom-m-orphan-net"));
        // The lists are asked for this loom home only.
        let listing = f.sub("ps");
        assert!(listing[0].iter().any(|a| a == &format!("label=loom.home={}", host.home_hash())), "{listing:?}");
        // A chain was removed for each cleaned mission.
        let helper = f.sub("run");
        assert_eq!(helper.len(), 2);
        assert!(helper.iter().all(|r| !r.iter().any(|a| a == "--interactive")));
    }

    #[tokio::test]
    async fn the_ssh_forward_is_started_lazily_replaced_after_an_exit_and_stopped() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("keys")).unwrap();
        // A fake ssh: records its argv, makes the socket file, and exits on the first run only.
        let ssh = root.join("ssh");
        let script = format!(
            "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done >> '{r}/ssh.log'\necho -- >> '{r}/ssh.log'\n\
             sock=''; prev=''; for a in \"$@\"; do [ \"$prev\" = '-L' ] && sock=\"${{a%%:*}}\"; prev=\"$a\"; done\n\
             : > \"$sock\"\nn=$(wc -l < '{r}/starts' 2>/dev/null || echo 0); echo x >> '{r}/starts'\n\
             if [ \"$n\" -lt 1 ]; then echo 'first run dies' >&2; exit 3; fi\nexec sleep 300\n",
            r = root.display()
        );
        std::fs::write(&ssh, script).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let cfg = BoxCfg { docker_cli: "/bin/sh".into(), ..sample_cfg() };
        let host = DockerHost::new(&cfg, &root).unwrap().with_ssh_program(&ssh.display().to_string());
        assert!(std::fs::read_to_string(root.join("ssh.log")).is_err(), "nothing runs before the first use");
        // A stale socket from an earlier daemon is removed before ssh starts (the fake recreates it).
        std::fs::write(root.join("keys/box.sock"), "stale").unwrap();
        host.ensure_forward().await.unwrap();
        // The first run exits at once; the supervisor starts it again after a backoff.
        let mut starts = 0;
        for _ in 0..80 {
            starts = std::fs::read_to_string(root.join("starts")).map(|s| s.lines().count()).unwrap_or(0);
            if starts >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(starts >= 2, "restarted after an exit: {starts}");
        let log = std::fs::read_to_string(root.join("ssh.log")).unwrap();
        let want = ssh_args(&cfg, host.socket());
        let got: Vec<&str> = log.lines().take(want.len()).collect();
        assert_eq!(got, want.iter().map(String::as_str).collect::<Vec<_>>());
        host.shutdown().await;
        assert!(!host.socket().exists(), "the socket is removed at shutdown");
    }

    // ---- a command in the box, through the job machinery ----------------------------------------

    use crate::bash::{run_launched, Launch};
    use crate::testutil::env_with;
    use loom_core::config::{SandboxCfg, SandboxMode, ToolsCfg};
    use loom_core::event::{ToolStatus, META_JOB};
    use serde_json::{json, Map, Value};

    fn args(v: Value) -> Map<String, Value> {
        v.as_object().cloned().unwrap_or_default()
    }

    fn pid_alive(pid: i32) -> bool {
        // SAFETY: signal 0 only tests for existence.
        unsafe { libc::kill(pid, 0) == 0 }
    }

    async fn read_pid(path: &str) -> i32 {
        for _ in 0..200 {
            if let Some(p) = std::fs::read_to_string(path).ok().and_then(|t| t.trim().parse().ok()) {
                return p;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("no pid in {path}");
    }

    async fn gone(pid: i32) -> bool {
        for _ in 0..100 {
            if !pid_alive(pid) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    #[tokio::test]
    async fn a_box_command_runs_as_a_job_and_the_script_arrives_verbatim() {
        let dir = tempfile::tempdir().unwrap();
        let f = FakeDocker::new(dir.path());
        let b = MissionBox::new(f.host(), "m-1", source(&[]));
        b.ready().await.unwrap();
        let e = env_with(ToolsCfg::default(), SandboxCfg { mode: SandboxMode::None, ..SandboxCfg::default() });
        let script = "echo \"hello $((1+2))\"; echo '; docker ps; '; echo --privileged";
        let launch = Launch { launcher: b.launcher("call-run", None, script).unwrap(), cwd: e.ctx.tmp_dir.clone() };
        let out = run_launched(&e.ctx, &args(json!({"command": script})), &launch).await;
        assert_eq!(out.status, ToolStatus::Ok, "{out:?}");
        assert_eq!(out.outcome, "exit 0");
        let body = match &out.body {
            crate::Body::Raw(b) => String::from_utf8_lossy(b).to_string(),
            other => panic!("{other:?}"),
        };
        assert_eq!(body, "hello 3\n; docker ps; \n--privileged\n");
        // The docker call the daemon made for it has the script as its last argument, and no other call has it.
        let exec = f.sub("exec").into_iter().find(|c| c.last().is_some_and(|l| l == script)).expect("the exec call");
        assert_eq!(exec[..exec.len() - 1], exec_args(b.names(), "call-run", "/work", script)[..exec_args(b.names(), "call-run", "/work", script).len() - 1]);
        assert_eq!(f.calls().iter().filter(|c| c.iter().any(|a| a == script)).count(), 1);
        // The exit status of the command in the box is the job's.
        let launch = Launch { launcher: b.launcher("call-exit", None, "exit 7").unwrap(), cwd: e.ctx.tmp_dir.clone() };
        let out = run_launched(&e.ctx, &args(json!({"command": "exit 7"})), &launch).await;
        assert_eq!((out.status, out.outcome.as_str()), (ToolStatus::Error, "exit 7"));
    }

    #[tokio::test]
    async fn killing_a_box_job_stops_the_command_in_the_container_term_then_kill() {
        let dir = tempfile::tempdir().unwrap();
        let f = FakeDocker::new(dir.path());
        let b = MissionBox::new(f.host(), "m-1", source(&[]));
        b.ready().await.unwrap();
        let e = env_with(ToolsCfg { kill_grace_s: 1, ..ToolsCfg::default() }, SandboxCfg { mode: SandboxMode::None, ..SandboxCfg::default() });
        let tag = std::process::id();
        for (call, script, expect_sigs) in [
            (format!("killtest-term-{tag}"), "sleep 300 & wait", vec!["TERM"]),
            (format!("killtest-kill-{tag}"), "trap '' TERM; (trap '' TERM; sleep 300) & wait", vec!["TERM", "KILL"]),
        ] {
            let call = call.as_str();
            let _ = std::fs::remove_file(pid_file(call));
            let launch = Launch { launcher: b.launcher(call, None, script).unwrap(), cwd: e.ctx.tmp_dir.clone() };
            let started = run_launched(&e.ctx, &args(json!({"command": script, "background": true})), &launch).await;
            let job = started.meta.get(META_JOB).and_then(Value::as_str).unwrap().to_string();
            let pgid = read_pid(&pid_file(call)).await;
            assert!(pid_alive(pgid), "the command runs in the container (the fake)");
            let killed = crate::Tool::run(&crate::bash::JobKill, &e.ctx, &args(json!({"job": job}))).await;
            assert!(killed.outcome.contains("killed") || killed.outcome.contains("stopped"), "{killed:?}");
            assert!(gone(pgid).await, "{call}: the process group in the container is gone");
            // Which signals reached the container, in order.
            let sigs: Vec<String> = f
                .sub("exec")
                .into_iter()
                .filter(|c| c.iter().any(|a| a == &pid_file(call)) && c.iter().any(|a| a.starts_with("kill -")))
                .map(|c| c.iter().find(|a| a.starts_with("kill -")).map(|a| a[6..].split(' ').next().unwrap_or("").to_string()).unwrap_or_default())
                .collect();
            let mut seen = sigs.clone();
            seen.dedup();
            assert_eq!(seen, expect_sigs, "{call}: {sigs:?}");
        }
    }

    #[tokio::test]
    async fn a_timeout_in_the_foreground_stops_the_command_in_the_container() {
        let dir = tempfile::tempdir().unwrap();
        let f = FakeDocker::new(dir.path());
        let b = MissionBox::new(f.host(), "m-1", source(&[]));
        b.ready().await.unwrap();
        let e = env_with(ToolsCfg { kill_grace_s: 1, ..ToolsCfg::default() }, SandboxCfg { mode: SandboxMode::None, ..SandboxCfg::default() });
        let script = "sleep 300";
        let call = format!("timeout-test-{}", std::process::id());
        let _ = std::fs::remove_file(pid_file(&call));
        let launch = Launch { launcher: b.launcher(&call, None, script).unwrap(), cwd: e.ctx.tmp_dir.clone() };
        let out = run_launched(&e.ctx, &args(json!({"command": script, "timeout_s": 1})), &launch).await;
        assert_eq!(out.status, ToolStatus::Timeout, "{out:?}");
        let pgid = read_pid(&pid_file(&call)).await;
        assert!(gone(pgid).await, "the command in the container was stopped with the call");
    }
}
