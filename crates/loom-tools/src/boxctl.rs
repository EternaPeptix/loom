//! The box: one container per mission, on a Docker host, that the agent's commands run in.
//!
//! CONTRACT.
//!
//! The agent never reaches Docker. This module is used by the daemon and by the three box tools
//! (`box_exec`, `box_get`, `box_reset`), which are the only things a session can do with a box. The
//! agent's text is never a docker argument, an ssh argument, an iptables argument or shell text on this
//! machine: the docker command line client is run by the daemon, outside every sandbox, with an argv that
//! loom builds (the pure `*_args` functions below), a fixed environment ([`DockerHost::docker_env`]), and
//! `--host unix://<socket>`. A command of the agent is the single last argument of
//! `/bin/bash -c <fixed text> _ <pid file> <script>` inside the container.
//!
//! ## Reaching Docker (`DockerHost`)
//! `DockerHost::new(cfg, loom_home)` resolves `docker_cli` and, when the socket is forwarded, `ssh` to absolute
//! paths once, at start (a bare name is looked for on the daemon's `PATH` then and never again; a relative path
//! or a program that is not found refuses the start of the box), makes the private directories
//! `<loom home>/keys/box-docker` (empty; `HOME` and `DOCKER_CONFIG` of the docker client, so no operator
//! configuration or credential helper is read) and `<loom home>/keys/box-run` (where every process of this
//! module starts, never the session's scratch directory), and fixes the socket: `docker_socket`, or with `ssh_host` the forwarded socket
//! `<loom home>/keys/box.sock`. That directory is private to the daemon and unreadable to commands
//! (`Sandbox` makes `<loom home>/keys` unreadable), and the socket is never added to
//! `sandbox.unix_sockets`. A socket path longer than 100 bytes is refused with a sentence.
//! The forward is started lazily by the first use (`ensure_forward`) as
//! `<absolute ssh> -o BatchMode=yes -o ExitOnForwardFailure=yes -o ControlPath=none -o ForwardAgent=no
//! -o ServerAliveInterval=15 -N -L <socket>:<remote_socket> -- <ssh_host>` ([`ssh_args`]), with `PATH` fixed to
//! [`SYSTEM_PATH`] and the operator's own `HOME`, supervised: a stale
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
//! 1000:1000, IPv6 off in its own network namespace (`--sysctl net.ipv6.conf.{all,default}.disable_ipv6=1`),
//! its own network (below), a private IPC namespace, no bind mount or volume, no device, no
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
//! resolved, with the addresses that passed, are given to `docker run` as one `--add-host <name>:<ipv4>`
//! each, sorted by name then address, built from validated names and `Ipv4Addr` only; Docker writes the
//! container's `/etc/hosts` from them (the root is read-only, so `/etc/hosts` is read-only too, and no
//! root `docker exec` exists). A name granted after the container was made gets its rules at once, so
//! its addresses are reachable, but it resolves inside the box only after `box_reset`; until then
//! [`MissionBox::pending_hosts`] lists it and every `box_exec` result says so. The rules are the chain `LOOM-<short>` ([`rules_text`]): flushed first, then ACCEPT each allowed
//! `ip/32` per protocol (tcp and udp, with `--dport` when a port was granted), DROP the rest. Behind it is a
//! static chain `LOOM-ALL` that ends with `DROP` and holds one jump `-i lb-<short> -j LOOM-<short>` per
//! mission, above that `DROP`; `DOCKER-USER` (forwarded packets) and `INPUT` (packets to the Docker host
//! itself) send everything that enters on any `lb-+` interface to `LOOM-ALL`. So a bridge whose mission has
//! no chain or no jump is dropped, never routed or translated. IPv6 on the interface is dropped in `INPUT`
//! and `FORWARD` (`ip6tables`; the helper image must have it). The mission's chain is installed or replaced
//! atomically (`iptables-restore --noflush`) by the operator's `helper_image`, run as `--rm --network host
//! --cap-drop ALL --cap-add NET_ADMIN` with a fixed script ([`rules_args`]); removing a mission
//! ([`rules_remove_args`]) takes away only its own jump, chain and IPv6 drops, never `LOOM-ALL` or its `DROP`.
//! The container is started only after its rules are in place. When rules cannot be brought up to date
//! while a container exists, the container is removed (fail closed). The rules of a running box are checked
//! again by `ready` when [`RULES_RECHECK`] has passed since they were last known to be there
//! ([`rules_check_args`]); a missing chain or jump is installed again before the command runs, and when that
//! fails the container is removed and the command is refused.
//!
//! ## Life of a box (`MissionBox`, I5)
//! One per mission, created by the runtime with a source of the mission's grants and effective policy.
//! Everything that creates, changes or removes a mission's box (`ready`, `reset`, `resync`, `teardown`,
//! `push`, `get_tar`, [`teardown_mission`] and each mission [`reconcile`] sweeps) holds the host's lock
//! for that mission, shared by every handle, so a teardown and a re-creation never overlap (R1).
//! `ready` creates the network, the rules and the container when there is no running container (it
//! adopts one that is running, re-applying the rules). An existing network of the mission's name is adopted
//! only when its labels, driver, IPv6 setting and bridge name are the box's own; any other is removed and
//! made again, or, when containers are attached to it, left alone and the call fails. `reset` removes the
//! container and makes a new one. `resync` re-applies the rules to the current grants when the box exists.
//! `teardown` removes the container, then the network, then the chain, in that order and each only if the
//! one before succeeded (a network that was not found counts as removed), so that a container or network is
//! never left without its filter; best effort. [`reconcile`] removes the containers, networks and chains
//! labelled with this loom home whose mission `keep` does not name, asking `keep` after the lock is taken.
//!
//! ## Commands (`launcher`, I1)
//! `launch(call, cwd, script)` returns the `bash::Launch` that `bash::run_launched` runs: the launcher
//! below, the box's private run directory and the docker client's environment. The launcher is:
//! `docker exec -u 1000:1000 -w /work[/cwd] -e HOME=/tmp -e TERM=dumb <container> /bin/bash -c
//! 'exec setsid /bin/bash -c '\''echo $$ > "$0"; exec /bin/bash -c "$1"'\'' "$1" "$2"' _ <pid file> <script>`.
//! The command runs in its own session, and the pid file `/tmp/.loom-<call>.pid` holds the process group
//! id. The launcher's `remote_stop` runs `docker exec ... /bin/sh -c 'kill -<SIG> -$(cat "$0")'
//! <pid file>` (TERM, then KILL) whenever the job's group is signalled: stopping the local docker client
//! alone would leave the command running in the container.
//!
//! ## Files (`boxfs`)
//! `push` copies changed workspace files to `/work` as a tar stream (`docker cp -a - <ctr>:/work`),
//! `get_tar` reads a path out of the container as a tar stream; what may be sent and how a stream is
//! unpacked is in `boxfs` (I6, I7).
//!
//! Tests required: exact argv of `run`, `exec`, `cp`, `network create`, `rm`, the helper run and the
//! kill (I1, I2, I4); the three helper scripts run against stand-ins for `iptables` (R1, R2); a hostile script reaches the launcher as one argv element; the egress plan for a grant
//! set (private address refused without `allow_private`, wildcard skipped and noticed once, IPv6 skipped,
//! ports kept); the rules text; names and labels; the ssh argv and the forward supervisor with a fake
//! `ssh` (stale socket removed, restarted after an exit); container life with a fake `docker` (created
//! after its rules, reset, resync fail-closed, teardown order, reconcile); a box job's kill reaches the
//! command in the "container" (fake `docker exec` runs it), TERM then KILL.

use crate::bash::Launch;
use crate::boxfs::{self, Manifest};
use crate::proc::{Launcher, RemoteStop};
use crate::sandbox::Sandbox;
use loom_core::config::BoxCfg;
use loom_net::policy::Policy;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ffi::OsStr;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
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
/// A running box has its egress rules looked at again by `ready` when this long has passed since the last time.
pub const RULES_RECHECK: Duration = Duration::from_secs(60);
/// When the rules of a running box are not there and cannot be put back, the try is made once more after this.
pub const RULES_RETRY_DELAY: Duration = Duration::from_secs(2);
/// What the box tools answer after the mission was stopped, ended or archived, until it is resumed.
pub const BOX_CLOSED: &str = "The box of this mission was removed when the mission was stopped. It comes back when the operator resumes the mission.";
/// The `PATH` of every process this module starts on this machine: fixed system directories, all absolute.
pub const SYSTEM_PATH: &str = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";
/// The static chain that every box bridge (`lb-+`) is sent to first; it ends with `DROP`.
pub const ALL_CHAIN: &str = "LOOM-ALL";
/// The directory (under `<loom home>/keys`) that is `HOME` and `DOCKER_CONFIG` of the docker client: empty.
const DOCKER_DIR: &str = "box-docker";
/// The directory (under `<loom home>/keys`) the launcher processes start in.
const RUN_DIR: &str = "box-run";

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

/// `docker network inspect` of the mission's network as one JSON object.
pub fn network_inspect_args(n: &Names) -> Vec<String> {
    vec!["network".into(), "inspect".into(), "--format".into(), "{{json .}}".into(), n.network.clone()]
}

pub fn pause_args(n: &Names) -> Vec<String> {
    vec!["pause".into(), n.container.clone()]
}

pub fn unpause_args(n: &Names) -> Vec<String> {
    vec!["unpause".into(), n.container.clone()]
}

pub fn rm_args(n: &Names) -> Vec<String> {
    vec!["rm".into(), "--force".into(), "--volumes".into(), n.container.clone()]
}

pub fn running_args(n: &Names) -> Vec<String> {
    vec![
        "inspect".into(),
        "--type".into(),
        "container".into(),
        "--format".into(),
        "{{.State.Running}}".into(),
        n.container.clone(),
    ]
}

/// `docker run` of the box (I2). `cfg.cap_add` has passed `BoxCfg::check`. `hosts` are the granted names with the
/// addresses that passed the policy: each becomes one `--add-host name:ip`, from a validated name and an
/// `Ipv4Addr`, so nothing in a grant can become a flag or a second value.
pub fn run_args(cfg: &BoxCfg, n: &Names, home: &str, hosts: &Hosts) -> Vec<String> {
    // `--init`: an init as PID 1 reaps the processes a stopped command leaves behind; without it they stay
    // zombies under `sleep` and count against `--pids-limit`.
    let mut a = strings(["run", "--detach", "--init", "--name"]);
    a.push(n.container.clone());
    a.extend(labels(&n.mission, home));
    a.extend(strings(["--network"]));
    a.push(n.network.clone());
    a.extend(strings(["--dns", DNS_SINKHOLE]));
    for (name, ips) in hosts.iter().filter(|(name, _)| valid_name(name)) {
        for ip in ips {
            a.push("--add-host".into());
            a.push(format!("{name}:{ip}"));
        }
    }
    a.extend(strings(["--cap-drop", "ALL"]));
    for cap in cfg.caps() {
        a.push("--cap-add".into());
        a.push(cap);
    }
    a.extend(strings(["--security-opt", "no-new-privileges"]));
    a.extend(strings([
        "--sysctl",
        "net.ipv6.conf.all.disable_ipv6=1",
        "--sysctl",
        "net.ipv6.conf.default.disable_ipv6=1",
    ]));
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
    // `exec`: Docker mounts a tmpfs `noexec` unless told otherwise, and the box exists to run what is built in it.
    a.push(format!("/tmp:rw,exec,nosuid,nodev,size={}m,uid=1000,gid=1000,mode=1777", cfg.tmp_mb));
    a.push("--tmpfs".into());
    a.push(format!("{WORK}:rw,exec,nosuid,nodev,size={}m,uid=1000,gid=1000,mode=0755", cfg.work_mb));
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
    // No `--`: dash (Debian/Ubuntu `/bin/sh`) refuses `kill -SIG -- -PGID` ("Illegal number"), and bash and dash
    // both read `kill -SIG -PGID` as a signal to the process group.
    a.push(format!("kill -{sig} -$(cat \"$0\")"));
    a.push(pid_file.to_string());
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

/// The script of the helper run that installs or replaces the mission's rules. `$1` is the mission's chain
/// and `$2` its bridge interface; the chain's rules arrive on stdin ([`rules_text`]).
///
/// The static chain `LOOM-ALL` is made first and ends with `DROP`; `DOCKER-USER` (forwarded packets) and
/// `INPUT` (packets to the Docker host) send everything that enters on any `lb-` interface to it. The
/// mission's own chain is installed by `iptables-restore --noflush` (a declared chain is replaced as one
/// step), and only then does `LOOM-ALL` get the mission's jump, inserted above its final `DROP`. A bridge
/// without a jump of its own is therefore dropped, never routed or translated. IPv6 is dropped for the
/// interface in `INPUT` and `FORWARD`. Every step can be repeated.
const RULES_APPLY: &str = ": loom-rules-apply; \
iptables -w 5 -N LOOM-ALL 2>/dev/null; \
iptables -w 5 -C LOOM-ALL -j DROP 2>/dev/null || iptables -w 5 -A LOOM-ALL -j DROP || exit 1; \
for c in DOCKER-USER INPUT; do iptables -w 5 -C \"$c\" -i 'lb-+' -j LOOM-ALL 2>/dev/null || iptables -w 5 -I \"$c\" 1 -i 'lb-+' -j LOOM-ALL || exit 1; done; \
iptables-restore -w 5 --noflush || exit 1; \
iptables -w 5 -C LOOM-ALL -i \"$2\" -j \"$1\" 2>/dev/null || iptables -w 5 -I LOOM-ALL 1 -i \"$2\" -j \"$1\" || exit 1; \
for c in INPUT FORWARD; do ip6tables -w 5 -C \"$c\" -i \"$2\" -j DROP 2>/dev/null || ip6tables -w 5 -I \"$c\" 1 -i \"$2\" -j DROP || exit 1; done";
/// The script that tells whether everything [`RULES_APPLY`] makes is still there (exit status 0).
const RULES_CHECK: &str = ": loom-rules-check; \
iptables -w 5 -C LOOM-ALL -j DROP && \
iptables -w 5 -C DOCKER-USER -i 'lb-+' -j LOOM-ALL && iptables -w 5 -C INPUT -i 'lb-+' -j LOOM-ALL && \
iptables -w 5 -C LOOM-ALL -i \"$2\" -j \"$1\" && iptables -w 5 -C \"$1\" -j DROP && \
ip6tables -w 5 -C INPUT -i \"$2\" -j DROP && ip6tables -w 5 -C FORWARD -i \"$2\" -j DROP";
/// The script that removes the mission's jump from `LOOM-ALL`, its chain and its IPv6 drops. Nothing else:
/// `LOOM-ALL` and its final `DROP` stay.
const RULES_REMOVE: &str = ": loom-rules-remove; \
while iptables -w 5 -D LOOM-ALL -i \"$2\" -j \"$1\" 2>/dev/null; do :; done; \
iptables -w 5 -F \"$1\" 2>/dev/null; iptables -w 5 -X \"$1\" 2>/dev/null; \
for c in INPUT FORWARD; do while ip6tables -w 5 -D \"$c\" -i \"$2\" -j DROP 2>/dev/null; do :; done; done; exit 0";

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

/// The helper run that removes the mission's jump, chain and IPv6 drops.
pub fn rules_remove_args(cfg: &BoxCfg, n: &Names) -> Vec<String> {
    helper_args(cfg, false, RULES_REMOVE, n)
}

/// The helper run that checks that the mission's rules are all in place (its status says).
pub fn rules_check_args(cfg: &BoxCfg, n: &Names) -> Vec<String> {
    helper_args(cfg, false, RULES_CHECK, n)
}

/// The `iptables-restore` input for the chain: an explicit flush, each allowed address, drop. There is no
/// rule for established traffic: the chain sees only packets that leave the `lb-` bridge, and those of an
/// allowed flow match the `-d` rules anyway, so a revoked address stops at once, with its open flows (the
/// replies arrive on the uplink, never through this chain). Container-to-host packets end at the `DROP`.
pub fn rules_text(n: &Names, allowed: &BTreeSet<Allowed>) -> String {
    // The `-F` is explicit so that a revoke never depends on a declared chain being flushed by itself.
    let mut t = format!("*filter\n:{} - [0:0]\n-F {}\n", n.chain, n.chain);
    for a in allowed {
        for proto in ["tcp", "udp"] {
            match a.port {
                Some(p) => {
                    t.push_str(&format!("-A {} -d {}/32 -p {proto} -m {proto} --dport {p} -j ACCEPT\n", n.chain, a.ip))
                }
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

/// Granted names with the addresses that passed the policy.
pub type Hosts = BTreeMap<String, BTreeSet<Ipv4Addr>>;

/// What the grants and the policy allow the box (see the module contract).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Egress {
    pub allowed: BTreeSet<Allowed>,
    /// The resolved names with the addresses that passed the policy, for `--add-host`.
    pub hosts: Hosts,
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
        Some((host, port)) if !host.contains(':') => {
            Some((host.trim_end_matches('.').to_ascii_lowercase(), Some(port.parse::<u16>().ok()?)))
        }
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

/// A host name that can be given to `--add-host`.
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
    /// The absolute path of `ssh` (resolved once, at start), when the socket is forwarded.
    ssh_program: String,
    /// `HOME` and `DOCKER_CONFIG` of the docker client: an empty directory of the daemon's own.
    docker_dir: PathBuf,
    /// Where the launcher processes start: a directory of the daemon's own.
    run_dir: PathBuf,
    forward: Mutex<Option<Forward>>,
    last_ssh_error: Arc<StdMutex<String>>,
    /// One lock per mission (by `Names::short`) that every change of its box takes (R1).
    locks: StdMutex<HashMap<String, Arc<Mutex<()>>>>,
    /// Milliseconds between two looks at the rules of a running box.
    recheck_ms: AtomicU64,
    /// Milliseconds before the second try of a failed rules check.
    retry_ms: AtomicU64,
}

/// `name` as an absolute path to an executable file. A name with a `/` is taken as it is; a bare name is
/// looked for in `search` (a `PATH` value) now, and the answer is what is used from then on.
fn resolve_program(name: &str, what: &str, search: &OsStr) -> Result<PathBuf, String> {
    let executable = |p: &Path| {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    };
    if name.contains('/') {
        let p = PathBuf::from(name);
        return if !p.is_absolute() {
            Err(format!(
                "{what} {name} is a relative path. Give a bare name to look for on the daemon's PATH, or a full path."
            ))
        } else if executable(&p) {
            Ok(p)
        } else {
            Err(format!("{what} {name} is not an executable file. Install it or give its full path."))
        };
    }
    std::env::split_paths(search)
        .filter(|d| d.is_absolute())
        .map(|d| d.join(name))
        .find(|p| executable(p))
        .ok_or_else(|| format!("{what} `{name}` was not found on the daemon's PATH. Install it or give its full path."))
}

impl DockerHost {
    /// Prepare the connection (nothing is started yet). `loom_home` is where `keys/box.sock` lives.
    pub fn new(cfg: &BoxCfg, loom_home: &Path) -> Result<Arc<DockerHost>, String> {
        let search = std::env::var_os("PATH").unwrap_or_default();
        Self::new_in(cfg, loom_home, &search)
    }

    /// [`DockerHost::new`] looking for `docker_cli` and `ssh` in `search` (a `PATH` value) instead of the
    /// daemon's. Both are resolved here, once; nothing is looked up by name later. A program that is not
    /// found refuses the start of the box with a sentence.
    pub fn new_in(cfg: &BoxCfg, loom_home: &Path, search: &OsStr) -> Result<Arc<DockerHost>, String> {
        let cli = resolve_program(&cfg.docker_cli, "box.docker_cli", search)?;
        let ssh_program = if cfg.docker_socket.is_empty() {
            resolve_program("ssh", "The ssh program (box.ssh_host needs it)", search)?.display().to_string()
        } else {
            String::new()
        };
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
        let keys = loom_home.join("keys");
        let (docker_dir, run_dir) = (keys.join(DOCKER_DIR), keys.join(RUN_DIR));
        for dir in [&docker_dir, &run_dir] {
            loom_core::config::ensure_private_dir(dir)
                .map_err(|e| format!("The box's private directory {} cannot be made: {e}", dir.display()))?;
        }
        Ok(Arc::new(DockerHost {
            cfg: cfg.clone(),
            home: loom_home.to_path_buf(),
            cli,
            socket,
            ssh_program,
            docker_dir,
            run_dir,
            forward: Mutex::new(None),
            last_ssh_error: Arc::new(StdMutex::new(String::new())),
            locks: StdMutex::new(HashMap::new()),
            recheck_ms: AtomicU64::new(u64::try_from(RULES_RECHECK.as_millis()).unwrap_or(u64::MAX)),
            retry_ms: AtomicU64::new(u64::try_from(RULES_RETRY_DELAY.as_millis()).unwrap_or(u64::MAX)),
        }))
    }

    /// The lock that serializes everything done to one mission's box: creating, resetting, re-ruling,
    /// removing, and what reconcile removes. It is shared by every handle for the same mission (R1).
    fn mission_lock(&self, short: &str) -> Arc<Mutex<()>> {
        let mut locks = self.locks.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        locks.entry(short.to_string()).or_default().clone()
    }

    /// Look at the rules of a running box this often (tests make it shorter).
    #[cfg(any(test, feature = "testutil"))]
    pub fn set_recheck(&self, every: Duration) {
        self.recheck_ms.store(u64::try_from(every.as_millis()).unwrap_or(u64::MAX), Ordering::SeqCst);
    }

    /// Wait this long before the second try of a failed rules check (tests make it shorter).
    #[cfg(any(test, feature = "testutil"))]
    pub fn set_retry_delay(&self, delay: Duration) {
        self.retry_ms.store(u64::try_from(delay.as_millis()).unwrap_or(u64::MAX), Ordering::SeqCst);
    }

    fn retry_delay(&self) -> Duration {
        Duration::from_millis(self.retry_ms.load(Ordering::SeqCst))
    }

    fn recheck_every(&self) -> Duration {
        Duration::from_millis(self.recheck_ms.load(Ordering::SeqCst))
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

    /// The whole environment of the docker client: a fixed `PATH`, and `HOME` and `DOCKER_CONFIG` in an
    /// empty directory of the daemon's own, so that no configuration, credential helper or plugin of the
    /// operator's account is read, and nothing of the agent's or of this process's environment is passed.
    pub fn docker_env(&self) -> BTreeMap<String, String> {
        let dir = self.docker_dir.display().to_string();
        BTreeMap::from([
            ("PATH".to_string(), SYSTEM_PATH.to_string()),
            ("HOME".to_string(), dir.clone()),
            ("DOCKER_CONFIG".to_string(), dir),
        ])
    }

    /// The environment of `ssh`: a fixed `PATH` and the operator's own `HOME`, where its configuration is.
    fn ssh_env() -> Vec<(&'static str, String)> {
        let mut env = vec![("PATH", SYSTEM_PATH.to_string())];
        env.extend(std::env::var("HOME").ok().map(|h| ("HOME", h)));
        env
    }

    /// The directory the launcher processes start in.
    pub fn run_dir(&self) -> &Path {
        &self.run_dir
    }

    /// The absolute path of the `ssh` program that was resolved at start (empty with a local socket).
    pub fn ssh_program(&self) -> &str {
        &self.ssh_program
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
        let (program, args, socket, run_dir) =
            (self.ssh_program.clone(), ssh_args(&self.cfg, &self.socket), self.socket.clone(), self.run_dir.clone());
        let (stop2, errors) = (stop.clone(), self.last_ssh_error.clone());
        let task = tokio::spawn(async move {
            let mut backoff = Duration::from_secs(1);
            loop {
                let _ = std::fs::remove_file(&socket);
                let started = Instant::now();
                let mut cmd = tokio::process::Command::new(&program);
                cmd.args(&args)
                    .env_clear()
                    .envs(DockerHost::ssh_env())
                    .current_dir(&run_dir)
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
                            let _ = tokio::time::timeout(
                                Duration::from_millis(200),
                                (&mut e).take(4096).read_to_string(&mut text),
                            )
                            .await;
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
            .envs(self.docker_env())
            .current_dir(&self.run_dir)
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
    /// When the rules of the running container were last known to be in place.
    verified: Option<Instant>,
    /// The container is paused because its rules could not be checked or put back (L2).
    paused: bool,
    /// The mission's box was torn down through this handle; it makes nothing again (L1). `forget` keeps it.
    closed: bool,
    /// The names and addresses the running container was created with (its `/etc/hosts`).
    created_hosts: Hosts,
    /// The names and addresses the grants give now, as of the last time the rules were brought to them.
    wanted_hosts: Hosts,
}

impl State {
    fn forget(&mut self) {
        self.paused = false;
        self.up = false;
        self.pushed.clear();
        self.verified = None;
        self.created_hosts.clear();
        self.wanted_hosts.clear();
    }
}

/// What a push did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PushReport {
    pub files: usize,
    pub bytes: u64,
    pub notes: Vec<String>,
}

/// One mission's container, network and rules. All changes are made one at a time, and the lock that
/// orders them is the host's lock of the mission, so it holds across every handle of the same mission
/// and against [`teardown_mission`] and [`reconcile`] (R1).
pub struct MissionBox {
    host: Arc<DockerHost>,
    names: Names,
    home: String,
    source: EgressSource,
    /// The mission's lock on the host: held by everything that creates, changes or removes the box.
    lifecycle: Arc<Mutex<()>>,
    state: Mutex<State>,
    wildcards: StdMutex<Vec<String>>,
    told: StdMutex<HashSet<String>>,
}

impl MissionBox {
    pub fn new(host: Arc<DockerHost>, mission: &str, source: EgressSource) -> Arc<MissionBox> {
        let home = host.home_hash();
        let names = names(mission);
        Arc::new(MissionBox {
            lifecycle: host.mission_lock(&names.short),
            names,
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
        self.host
            .run_ok("Installing the egress rules", &rules_args(&self.host.cfg, &self.names), Some(text))
            .await
            .map(|_| ())
    }

    /// Remove the container so that it never runs with rules that are not the grants' (best effort).
    async fn remove_container(&self, st: &mut State) {
        let _ = self.host.docker(&rm_args(&self.names), None, SMALL_OUT).await;
        st.forget();
    }

    async fn create_network(&self) -> Result<DockerOut, String> {
        let args = network_args(&self.names, &self.home);
        self.host.docker(&args, None, SMALL_OUT).await
    }

    /// Make the mission's network, or adopt the one that is there when it is this mission's own (R5): its
    /// labels name this loom home and mission, it is a bridge without IPv6, and its bridge interface is the
    /// one the rules name. Any other network of that name is removed and made again, unless something is
    /// attached to it, in which case it is left alone and the call fails.
    async fn make_network(&self) -> Result<(), String> {
        let made = self.create_network().await?;
        if made.ok() {
            return Ok(());
        }
        if !made.stderr.contains("already exists") {
            return Err(format!("Creating the box network failed on the Docker host: {}", made.why()));
        }
        let looked = self.host.docker(&network_inspect_args(&self.names), None, SMALL_OUT).await?;
        if !looked.ok() {
            return Err(format!(
                "The existing network {} could not be inspected: {}",
                self.names.network,
                looked.why()
            ));
        }
        let found = inspect_network(&looked.stdout, &self.names, &self.home)?;
        match found {
            Found::Ours => Ok(()),
            Found::Foreign { attached: 0, why } => {
                tracing::warn!(mission = %self.names.mission, "box: replacing the network {}: {why}", self.names.network);
                self.run_ok("Removing a network that is not the box's", network_rm_args(&self.names)).await?;
                let again = self.create_network().await?;
                if again.ok() {
                    Ok(())
                } else {
                    Err(format!("Creating the box network failed on the Docker host: {}", again.why()))
                }
            }
            Found::Foreign { attached, why } => Err(format!(
                "A network named {} already exists on the Docker host and is not this box's ({why}), and {attached} container(s) are attached to it, so it was left alone and no box was made. Remove or rename that network on the Docker host.",
                self.names.network
            )),
        }
    }

    /// Whether the rules of the running container are all there, and if not, put them back, at most once per
    /// `recheck_every` (R4). A try that fails is made once more after `retry_delay` (a helper that failed
    /// once is not a reason to lose `/work`). When the rules still cannot be put back the container is
    /// paused, not removed, and the call fails (L2); a later check or install that works unpauses it.
    async fn verify_rules(&self, st: &mut State) -> Result<(), String> {
        if !st.paused && st.verified.is_some_and(|t| t.elapsed() < self.host.recheck_every()) {
            return Ok(());
        }
        let mut last = String::new();
        for attempt in 0..2 {
            if attempt > 0 {
                tokio::time::sleep(self.host.retry_delay()).await;
            }
            let args = rules_check_args(&self.host.cfg, &self.names);
            if matches!(self.host.docker(&args, None, SMALL_OUT).await, Ok(o) if o.ok()) {
                return self.rules_ok(st).await;
            }
            tracing::warn!(mission = %self.names.mission, "box: its egress rules are not all in place; installing them again");
            let again = async {
                let plan = self.plan().await?;
                self.install_rules(&plan).await?;
                Ok::<_, String>(plan.hosts)
            }
            .await;
            match again {
                Ok(hosts) => {
                    st.wanted_hosts = hosts;
                    return self.rules_ok(st).await;
                }
                Err(e) => last = e,
            }
        }
        // Fail closed without losing the work: a paused container runs nothing and keeps `/work`.
        let paused = matches!(self.host.docker(&pause_args(&self.names), None, SMALL_OUT).await, Ok(o) if o.ok());
        if paused {
            st.paused = true;
            st.verified = None;
            Err(format!(
                "The egress rules of the box were not all in place and could not be put back ({last}), so the box was paused and the command was not run. The next box_exec checks the rules again and continues when they are back."
            ))
        } else {
            self.remove_container(st).await;
            Err(format!(
                "The egress rules of the box were not all in place and could not be put back ({last}), and the box could not be paused, so it was removed and the command was not run. The next box_exec makes a new box."
            ))
        }
    }

    /// The rules are in place: note it, and let a paused container run again.
    async fn rules_ok(&self, st: &mut State) -> Result<(), String> {
        if st.paused {
            match self.host.docker(&unpause_args(&self.names), None, SMALL_OUT).await {
                Ok(o) if o.ok() => st.paused = false,
                Ok(o) => return Err(format!("The box is paused and could not be resumed: {}", o.why())),
                Err(e) => return Err(e),
            }
        }
        st.verified = Some(Instant::now());
        Ok(())
    }

    /// The body of `ready` and `reset`; the mission's lock and the state are held by the caller.
    async fn ensure_locked(&self, st: &mut State) -> Result<(), String> {
        if st.closed {
            return Err(BOX_CLOSED.to_string());
        }
        self.host.ensure_forward().await?;
        if st.up {
            if self.is_running().await {
                return self.verify_rules(st).await;
            }
            st.forget();
        }
        let plan = self.plan().await?;
        if self.is_running().await {
            // A box from before a restart of the daemon: bring its rules to the grants of now.
            self.install_rules(&plan).await?;
            st.forget();
            st.up = true;
            // What it was created with is not known: its names count as pending until `box_reset`.
            st.wanted_hosts = plan.hosts;
            st.verified = Some(Instant::now());
            return Ok(());
        }
        // Leftovers of an earlier box of this mission (stopped container, network).
        let _ = self.host.docker(&rm_args(&self.names), None, SMALL_OUT).await;
        self.make_network().await?;
        // The container starts only once the rules that confine it are in place.
        self.install_rules(&plan).await?;
        self.run_ok("Starting the box", run_args(&self.host.cfg, &self.names, &self.home, &plan.hosts)).await?;
        st.forget();
        st.up = true;
        st.created_hosts.clone_from(&plan.hosts);
        st.wanted_hosts = plan.hosts;
        st.verified = Some(Instant::now());
        Ok(())
    }

    /// Make sure the container is running, creating it (network, rules, container) when it is not.
    pub async fn ready(&self) -> Result<(), String> {
        let _life = self.lifecycle.lock().await;
        let mut st = self.state.lock().await;
        self.ensure_locked(&mut st).await
    }

    /// Remove the container and make a new one. What was in `/work` is gone.
    pub async fn reset(&self) -> Result<(), String> {
        let _life = self.lifecycle.lock().await;
        let mut st = self.state.lock().await;
        if st.closed {
            return Err(BOX_CLOSED.to_string());
        }
        self.host.ensure_forward().await?;
        self.run_ok("Removing the box", rm_args(&self.names)).await?;
        st.forget();
        self.ensure_locked(&mut st).await
    }

    /// Bring the rules to the mission's grants as they are now, if the box exists. When that cannot be
    /// done the container is removed, so that it never has more than the grants allow.
    pub async fn resync(&self) {
        let _life = self.lifecycle.lock().await;
        let mut st = self.state.lock().await;
        if self.host.ensure_forward().await.is_err() || !self.is_running().await {
            return;
        }
        let applied = async {
            let plan = self.plan().await?;
            self.install_rules(&plan).await?;
            Ok::<_, String>(plan.hosts)
        }
        .await;
        match applied {
            Ok(hosts) => {
                st.wanted_hosts = hosts;
                st.verified = Some(Instant::now());
            }
            Err(e) => {
                tracing::warn!(mission = %self.names.mission, "box: the egress rules could not be updated, so the box is removed: {e}");
                self.remove_container(&mut st).await;
            }
        }
    }

    /// Remove the container, the network and the chain, in that order (best effort, logged).
    pub async fn teardown(&self) {
        let _life = self.lifecycle.lock().await;
        let mut st = self.state.lock().await;
        st.forget();
        st.closed = true;
        teardown_names_locked(&self.host, &self.names).await;
    }

    /// The granted names whose addresses differ from what the running container was created with: their rules
    /// are in place, but the container's `/etc/hosts` (written by Docker at creation) lacks them until
    /// `reset`. Name and addresses, sorted.
    pub async fn pending_hosts(&self) -> Vec<(String, Vec<Ipv4Addr>)> {
        let st = self.state.lock().await;
        if !st.up {
            return Vec::new();
        }
        st.wanted_hosts
            .iter()
            .filter(|(name, ips)| st.created_hosts.get(*name) != Some(*ips))
            .map(|(name, ips)| (name.clone(), ips.iter().copied().collect()))
            .collect()
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
        let _life = self.lifecycle.lock().await;
        let mut st = self.state.lock().await;
        if st.closed {
            return Err(BOX_CLOSED.to_string());
        }
        let cfg = &self.host.cfg;
        let limits = boxfs::PushLimits {
            total: cfg.sync_max_mb.saturating_mul(1 << 20),
            file: cfg.sync_file_max_mb.saturating_mul(1 << 20),
        };
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
        let _life = self.lifecycle.lock().await;
        let st = self.state.lock().await;
        if st.closed {
            return Err(BOX_CLOSED.to_string());
        }
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
                .envs(host.docker_env())
                .current_dir(host.run_dir())
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

    /// [`MissionBox::launcher`] with where it starts (a directory of the daemon's own, never the session's
    /// scratch directory) and the whole environment of the docker client (R9).
    pub fn launch(&self, call_id: &str, cwd: Option<&str>, script: &str) -> Result<Launch, String> {
        Ok(Launch {
            launcher: self.launcher(call_id, cwd, script)?,
            cwd: self.host.run_dir().to_path_buf(),
            env: self.host.docker_env(),
        })
    }
}

/// What `docker network inspect` says about a network that is in the way.
#[derive(Debug, PartialEq, Eq)]
enum Found {
    Ours,
    Foreign { attached: usize, why: String },
}

/// Judge the JSON of `docker network inspect --format '{{json .}}'` (R5).
fn inspect_network(json: &[u8], n: &Names, home: &str) -> Result<Found, String> {
    let v: serde_json::Value = serde_json::from_slice(json)
        .map_err(|e| format!("The existing network {} could not be understood ({e}).", n.network))?;
    let text = |obj: &str, key: &str| v.get(obj).and_then(|o| o.get(key)).and_then(|x| x.as_str()).unwrap_or("");
    let attached = v.get("Containers").and_then(|c| c.as_object()).map_or(0, serde_json::Map::len);
    let checks = [
        (v.get("Driver").and_then(|d| d.as_str()) == Some("bridge"), "it is not a bridge network".to_string()),
        (!v.get("EnableIPv6").and_then(serde_json::Value::as_bool).unwrap_or(false), "it has IPv6 on".to_string()),
        (text("Labels", "loom.home") == home, "it is not labelled with this loom home".to_string()),
        (text("Labels", "loom.mission") == n.mission, "it is not labelled with this mission".to_string()),
        (
            text("Options", "com.docker.network.bridge.name") == n.iface,
            format!("its bridge interface is not {}", n.iface),
        ),
    ];
    match checks.into_iter().find(|(ok, _)| !ok) {
        None => Ok(Found::Ours),
        Some((_, why)) => Ok(Found::Foreign { attached, why }),
    }
}

/// Remove one mission's container, network and chain. The caller holds the mission's lock. The chain goes
/// last, and only when the container is gone and the network is gone or was not there: while either exists
/// the chain (and `LOOM-ALL` behind it) is what confines the bridge (R1).
async fn teardown_names_locked(host: &DockerHost, n: &Names) {
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
    match host.docker(&network_rm_args(n), None, SMALL_OUT).await {
        Ok(o) if o.ok() || o.stderr.contains("not found") || o.stderr.contains("No such network") => {}
        Ok(o) => {
            tracing::warn!(mission = %n.mission, "box: the network was not removed, so its rules stay: {}", o.why());
            return;
        }
        Err(e) => {
            tracing::warn!(mission = %n.mission, "box: the network was not removed, so its rules stay: {e}");
            return;
        }
    }
    match host.docker(&rules_remove_args(&host.cfg, n), None, SMALL_OUT).await {
        Ok(o) if o.ok() => {}
        Ok(o) => tracing::warn!(mission = %n.mission, "box: the egress chain was not removed: {}", o.why()),
        Err(e) => tracing::warn!(mission = %n.mission, "box: the egress chain was not removed: {e}"),
    }
}

/// Remove the container, network and chain of one mission by name (best effort, logged), once nothing else
/// is changing that mission's box.
pub async fn teardown_mission(host: &DockerHost, mission: &str) {
    let n = names(mission);
    let lock = host.mission_lock(&n.short);
    let _life = lock.lock().await;
    teardown_names_locked(host, &n).await;
}

/// Remove what boxes of this loom home leave on the Docker host for missions that `keep` does not name
/// (I5): containers, networks and chains. Best effort; returns the missions that were cleaned. `keep` is
/// asked for each mission after that mission's lock is taken, so a mission that started in the meantime is
/// not touched.
pub async fn reconcile(host: &DockerHost, keep: &(dyn Fn(&str) -> bool + Sync)) -> Vec<String> {
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
        if !plain {
            continue;
        }
        let n = names(&mission);
        let lock = host.mission_lock(&n.short);
        let _life = lock.lock().await;
        if keep(&mission) {
            continue;
        }
        teardown_names_locked(host, &n).await;
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
env > "$D/docker.env"; pwd -P > "$D/docker.cwd"
entry=$(for a in "$@"; do printf '%s\n' "$a"; done; echo '----'); until mkdir "$D/log.lock" 2>/dev/null; do :; done; printf '%s\n' "$entry" >> "$D/docker.log"; rmdir "$D/log.lock"
[ -f "$D/fail.$3" ] && { echo "boom: $3 failed" >&2; exit 1; }
shift 2
sub=$1; shift
case "$sub" in
  run)
    case " $* " in
      *" --entrypoint /bin/sh "*)
        # The helper: the last two arguments are the chain and the interface. Its three scripts are told apart
        # by their first word; the chain is a file here, so tests can see when it exists.
        chain=""; iface=""; for a in "$@"; do chain="$iface"; iface="$a"; done
        [ -f "$D/rules.fail" ] && { echo "iptables: failed" >&2; exit 1; }
        if [ -f "$D/rules.fail.count" ]; then n=$(cat "$D/rules.fail.count"); if [ "$n" -gt 0 ]; then echo $((n-1)) > "$D/rules.fail.count"; echo "iptables: transient" >&2; exit 1; fi; fi
        case "$*" in
          *": loom-rules-check;"*)
            [ -f "$D/chain-$chain" ] || { echo "iptables: Bad rule (does a matching rule exist in that chain?)" >&2; exit 1; }
            exit 0;;
          *": loom-rules-remove;"*)
            [ -f "$D/slow.remove" ] && sleep 1
            rm -f "$D/chain-$chain"; exit 0;;
        esac
        case " $* " in *" --interactive "*) cat > "$D/rules.in.$$"; mv "$D/rules.in.$$" "$D/rules.in";; esac
        touch "$D/chain-$chain"
        exit 0;;
    esac
    name=""; net=""; prev=""; for a in "$@"; do [ "$prev" = "--name" ] && name="$a"; [ "$prev" = "--network" ] && net="$a"; prev="$a"; done
    # A container that starts while the chain of its bridge is not there is a hole: note it.
    if [ -f "$D/netif-$net" ]; then short=$(sed 's/^lb-//' "$D/netif-$net"); [ -f "$D/chain-LOOM-$short" ] || echo "$name" >> "$D/violations"; fi
    touch "$D/ctr-$name"; echo "fakeid"; exit 0;;
  rm) for a in "$@"; do last="$a"; done
      if [ -f "$D/ctr-$last" ]; then rm -f "$D/ctr-$last" "$D/paused-$last"; exit 0; fi
      echo "Error: No such container: $last" >&2; exit 1;;
  pause) for a in "$@"; do last="$a"; done
      if [ -f "$D/ctr-$last" ]; then touch "$D/paused-$last"; echo "$last"; exit 0; fi
      echo "Error: No such container: $last" >&2; exit 1;;
  unpause) for a in "$@"; do last="$a"; done
      if [ -f "$D/paused-$last" ]; then rm -f "$D/paused-$last"; echo "$last"; exit 0; fi
      echo "Error response from daemon: Container $last is not paused" >&2; exit 1;;
  inspect) for a in "$@"; do last="$a"; done
      if [ -f "$D/ctr-$last" ]; then echo true; exit 0; fi
      echo "Error: No such object: $last" >&2; exit 1;;
  network)
    case "$1" in
      create) h=""; m=""; iface=""; prev=""; last=""
              for a in "$@"; do
                case "$prev" in
                  --label) case "$a" in loom.home=*) h="${a#loom.home=}";; loom.mission=*) m="${a#loom.mission=}";; esac;;
                  --opt) case "$a" in com.docker.network.bridge.name=*) iface="${a#*=}";; esac;;
                esac
                prev="$a"; last="$a"
              done
              if [ -f "$D/net-$last" ]; then echo "Error response from daemon: network with name $last already exists" >&2; exit 1; fi
              touch "$D/net-$last"; echo "$iface" > "$D/netif-$last"
              printf '{"Name":"%s","Driver":"bridge","EnableIPv6":false,"Labels":{"loom.home":"%s","loom.mission":"%s"},"Options":{"com.docker.network.bridge.name":"%s"},"Containers":{}}\n' "$last" "$h" "$m" "$iface" > "$D/netjson-$last"
              echo netid; exit 0;;
      inspect) for a in "$@"; do last="$a"; done
              if [ -f "$D/netjson-$last" ]; then cat "$D/netjson-$last"; exit 0; fi
              if [ -f "$D/net-$last" ]; then echo '{"Driver":"bridge","Labels":null,"Options":{},"Containers":{}}'; exit 0; fi
              echo "Error: No such network: $last" >&2; exit 1;;
      rm) [ -f "$D/netrm.fail" ] && { echo "Error response from daemon: error while removing network: network $2 has active endpoints" >&2; exit 1; }
          if [ -f "$D/net-$2" ]; then rm -f "$D/net-$2" "$D/netif-$2" "$D/netjson-$2"; exit 0; fi
          echo "Error response from daemon: network $2 not found" >&2; exit 1;;
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
    if [ -f "$D/paused-$ctr" ]; then echo "Error response from daemon: Container $ctr is paused, unpause the container before exec" >&2; exit 1; fi
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
            std::fs::write(&setsid, "#!/usr/bin/perl\nuse POSIX;\nPOSIX::setsid();\nexec { $ARGV[0] } @ARGV;\n")
                .expect("write setsid");
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
            self.calls()
                .into_iter()
                .filter_map(|c| c.get(2..).map(<[String]>::to_vec))
                .filter(|c| c.first().is_some_and(|s| s == name))
                .collect()
        }

        pub fn running(&self, container: &str) -> bool {
            self.dir.join(format!("ctr-{container}")).exists()
        }

        pub fn paused(&self, container: &str) -> bool {
            self.dir.join(format!("paused-{container}")).exists()
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

    fn sample_hosts() -> Hosts {
        let mut h = Hosts::new();
        // Inserted out of order: the argv is sorted by name, then address.
        h.entry("b.test".into()).or_default().insert("198.51.100.9".parse().unwrap());
        h.entry("a.test".into()).or_default().insert("203.0.113.60".parse().unwrap());
        h.entry("a.test".into()).or_default().insert("203.0.113.5".parse().unwrap());
        h
    }

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
        let args = run_args(&sample_cfg(), &n, "HOMEHASH", &sample_hosts());
        let expected: Vec<String> = [
            "run",
            "--detach",
            "--init",
            "--name",
            "loom-m-1",
            "--label",
            "loom.home=HOMEHASH",
            "--label",
            "loom.mission=m-1",
            "--network",
            "loom-m-1",
            "--dns",
            "192.0.2.1",
            "--add-host",
            "a.test:203.0.113.5",
            "--add-host",
            "a.test:203.0.113.60",
            "--add-host",
            "b.test:198.51.100.9",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "SYS_PTRACE",
            "--cap-add",
            "NET_RAW",
            "--security-opt",
            "no-new-privileges",
            "--sysctl",
            "net.ipv6.conf.all.disable_ipv6=1",
            "--sysctl",
            "net.ipv6.conf.default.disable_ipv6=1",
            "--pids-limit",
            "512",
            "--memory",
            "8192m",
            "--memory-swap",
            "8192m",
            "--cpus",
            "4",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,exec,nosuid,nodev,size=1024m,uid=1000,gid=1000,mode=1777",
            "--tmpfs",
            "/work:rw,exec,nosuid,nodev,size=4096m,uid=1000,gid=1000,mode=0755",
            "--user",
            "1000:1000",
            "--workdir",
            "/work",
            "--ipc",
            "private",
            "--restart",
            "no",
            "--entrypoint",
            "/bin/sleep",
            DIGEST,
            "2147483647",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(args, expected);
        // What must never appear, whatever the configuration.
        for forbidden in
            ["--privileged", "-v", "--volume", "--mount", "--device", "--pid", "--uts", "--userns", "--cap-add=ALL"]
        {
            assert!(!args.iter().any(|a| a == forbidden), "{forbidden}");
        }
        for (i, a) in args.iter().enumerate() {
            if matches!(a.as_str(), "--network" | "--ipc") {
                assert!(!matches!(args[i + 1].as_str(), "host" | "none"), "{a} {}", args[i + 1]);
            }
            assert!(!a.starts_with("container:") && !a.contains("docker.sock"), "{a}");
        }
        // No cap_add: nothing is added back.
        let plain = run_args(&BoxCfg { cap_add: vec![], ..sample_cfg() }, &n, "H", &Hosts::new());
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
            assert_eq!(
                a[..a.len() - 1],
                plain[..plain.len() - 1],
                "{script:?} changed an argument that is not its own"
            );
        }
        let expected: Vec<String> = [
            "exec",
            "--user",
            "1000:1000",
            "--workdir",
            "/work",
            "--env",
            "HOME=/tmp",
            "--env",
            "TERM=dumb",
            "loom-m-1",
            "/bin/bash",
            "-c",
            EXEC_WRAP,
            "_",
            "/tmp/.loom-call-1.pid",
            "echo hi",
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
    fn the_kill_cp_network_and_rm_argv_are_exactly_this() {
        let n = names("m-1");
        let kill = kill_args(&n, "/tmp/.loom-c.pid", "TERM");
        assert_eq!(
            kill,
            [
                "exec",
                "--user",
                "1000:1000",
                "loom-m-1",
                "/bin/sh",
                "-c",
                "kill -TERM -$(cat \"$0\")",
                "/tmp/.loom-c.pid"
            ]
        );
        assert_eq!(kill_args(&n, "/p", "KILL")[6], "kill -KILL -$(cat \"$0\")");
        assert_eq!(
            kill_args(&n, "/p", "x; rm")[6],
            "kill -TERM -$(cat \"$0\")",
            "the signal is one of two fixed words"
        );
        assert_eq!(network_inspect_args(&n), ["network", "inspect", "--format", "{{json .}}", "loom-m-1"]);
        assert_eq!(cp_in_args(&n), ["cp", "--archive", "-", "loom-m-1:/work"]);
        assert_eq!(cp_out_args(&n, "/work/out"), ["cp", "loom-m-1:/work/out", "-"]);
        assert_eq!(rm_args(&n), ["rm", "--force", "--volumes", "loom-m-1"]);
        assert_eq!(network_rm_args(&n), ["network", "rm", "loom-m-1"]);
        assert_eq!(
            network_args(&n, "H"),
            [
                "network",
                "create",
                "--driver",
                "bridge",
                "--ipv6=false",
                "--opt",
                &format!("com.docker.network.bridge.name={}", n.iface),
                "--label",
                "loom.home=H",
                "--label",
                "loom.mission=m-1",
                "loom-m-1"
            ]
        );
    }

    #[test]
    fn i4_the_plan_applies_exact_hosts_and_ips_under_the_policy() {
        let g = grants(&[
            "203.0.113.7",      // public IP literal, all ports
            "198.51.100.9:443", // public IP literal with a port
            "target.test:8080", // a name with a port
            "both.test",        // a name that resolves to a v4 and a v6 address
            "10.1.2.3",         // private literal: refused
            "internal.test",    // resolves to a private address: refused
            "*.wild.test",      // wildcard: not applied
            "*",                // wildcard: not applied
            "[2001:db8::1]:80", // IPv6 literal: skipped
            "gone.test",        // does not resolve
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
        // Only names are given to the container, with the addresses that passed.
        assert_eq!(plan.hosts.keys().map(String::as_str).collect::<Vec<_>>(), ["both.test", "target.test"]);
        assert_eq!(plan.hosts["both.test"].iter().map(ToString::to_string).collect::<Vec<_>>(), ["203.0.113.60"]);
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
        let plan =
            plan_egress(&grants(&["203.0.113.7", "203.0.113.8:22"]), &policy(&[], &["203.0.113.7"]), &BTreeMap::new());
        assert_eq!(plan.allowed.iter().map(|a| a.ip.to_string()).collect::<Vec<_>>(), ["203.0.113.8"]);
        let plan = plan_egress(
            &grants(&["203.0.113.7", "203.0.113.7:80"]),
            &policy(&[], &["203.0.113.7:22"]),
            &BTreeMap::new(),
        );
        assert_eq!(
            plan.allowed.iter().map(|a| a.port).collect::<Vec<_>>(),
            [Some(80)],
            "all ports are refused when one is denied"
        );
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
                "*filter\n:{c} - [0:0]\n-F {c}\n\
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
                "run",
                "--rm",
                "--interactive",
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
                &cfg.helper_image,
                "-c",
                RULES_APPLY
            ]
        );
        assert_eq!(run[run.len() - 3..], ["_".to_string(), n.chain.clone(), n.iface.clone()]);
        let rm = rules_remove_args(&cfg, &n);
        assert!(!rm.iter().any(|a| a == "--interactive") && rm.iter().any(|a| a == RULES_REMOVE));
        // The only mission-dependent words are derived from a hash.
        assert!(
            n.chain.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && n.iface.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        );
    }

    #[test]
    fn the_ssh_forward_argv_is_exactly_this() {
        let cfg = sample_cfg();
        let a = ssh_args(&cfg, Path::new("/h/keys/box.sock"));
        assert_eq!(
            a,
            [
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
                "/h/keys/box.sock:/var/run/docker.sock",
                "--",
                "loom-box"
            ]
        );
    }

    #[test]
    fn i1_the_socket_lives_under_keys_and_a_long_path_is_refused() {
        let cfg = sample_cfg();
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().canonicalize().unwrap().join(".loom");
        let (search, _ssh) = fake_ssh_dir(dir.path());
        let host = DockerHost::new_in(&BoxCfg { docker_cli: "/bin/sh".into(), ..cfg.clone() }, &home, &search).unwrap();
        assert_eq!(host.socket(), home.join("keys/box.sock"));
        let (program, argv) = host.argv(&["ps".into()]);
        assert_eq!(program, "/bin/sh");
        assert_eq!(
            argv,
            ["--host".to_string(), format!("unix://{}", home.join("keys/box.sock").display()), "ps".to_string()]
        );
        let long = format!("/{}", "a".repeat(120));
        let err =
            DockerHost::new_in(&BoxCfg { docker_cli: "/bin/sh".into(), ..cfg.clone() }, Path::new(&long), &search)
                .err()
                .unwrap();
        assert!(err.contains("longer than"), "{err}");
        let err = DockerHost::new_in(&BoxCfg { docker_cli: "no-such-docker-cli".into(), ..cfg }, &home, &search)
            .err()
            .unwrap();
        assert!(err.contains("not found on the daemon's PATH"), "{err}");
    }

    /// A directory with an executable `ssh` in it (that does nothing), as a `PATH` value, and its path.
    fn fake_ssh_dir(base: &Path) -> (std::ffi::OsString, PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let bin = base.canonicalize().unwrap().join("ssh-bin");
        std::fs::create_dir_all(&bin).unwrap();
        let ssh = bin.join("ssh");
        std::fs::write(&ssh, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o755)).unwrap();
        (bin.into_os_string(), ssh)
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
        // inspect (is one there?) -> rm leftovers -> network -> rules (helper) -> container; no exec at all
        assert_eq!(subs(&f), ["inspect", "rm", "network", "run", "run"]);
        let runs = f.sub("run");
        assert!(
            runs[0].iter().any(|a| a == "--entrypoint") && runs[0].iter().any(|a| a == "/bin/sh"),
            "the helper comes first"
        );
        assert!(runs[1].iter().any(|a| a == "--name"), "then the container");
        let rules = std::fs::read_to_string(f.dir.join("rules.in")).unwrap();
        assert!(rules.contains("-d 203.0.113.7/32 -p tcp -j ACCEPT") && rules.contains("-j DROP"), "{rules}");
        assert!(!f.calls().iter().any(|c| c.iter().any(|a| a.contains("/etc/hosts"))), "no root writer remains");
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

    /// Grants that can be changed while a box exists.
    fn live_source(g: &Arc<StdMutex<Vec<String>>>) -> EgressSource {
        let g = g.clone();
        Arc::new(move || Ok((g.lock().unwrap().clone(), policy(&["127.0.0.0/8"], &[]))))
    }

    #[tokio::test]
    async fn a_name_granted_after_creation_is_pending_until_reset_and_its_address_works_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let f = FakeDocker::new(dir.path());
        let grants = Arc::new(StdMutex::new(vec!["203.0.113.7".to_string()]));
        let b = MissionBox::new(f.host(), "m-1", live_source(&grants));
        b.ready().await.unwrap();
        assert!(b.pending_hosts().await.is_empty());
        // A grant after creation: the rules follow at once, the name resolves only after a reset.
        grants.lock().unwrap().push("localhost".to_string());
        b.resync().await;
        let rules = std::fs::read_to_string(f.dir.join("rules.in")).unwrap();
        assert!(rules.contains("-d 127.0.0.1/32 -p tcp -j ACCEPT"), "{rules}");
        let pending = b.pending_hosts().await;
        assert_eq!(pending, [("localhost".to_string(), vec!["127.0.0.1".parse::<Ipv4Addr>().unwrap()])]);
        // A second resync does not change that.
        b.resync().await;
        assert_eq!(b.pending_hosts().await, pending);
        // The reset makes the container with every current name.
        b.reset().await.unwrap();
        assert!(b.pending_hosts().await.is_empty());
        let runs = f.sub("run");
        let container = runs.last().unwrap();
        assert!(container.windows(2).any(|w| w == ["--add-host", "localhost:127.0.0.1"]), "{container:?}");
        // No call is ever a root exec or touches /etc/hosts.
        for c in f.calls() {
            assert!(!c.iter().any(|a| a.contains("/etc/hosts")), "{c:?}");
            assert!(!(c.get(2).map(String::as_str) == Some("exec") && c.iter().any(|a| a == "0")), "{c:?}");
        }
        assert!(!subs(&f).iter().any(|s| s == "exec"));
    }

    #[test]
    fn a_hostile_grant_cannot_become_a_flag() {
        let n = names("m-1");
        let g = grants(&[
            "--privileged",
            "-v",
            "evil.test --privileged",
            "x.test:--cap-add=ALL",
            "a.test,--network=host",
            "ok.test",
        ]);
        let res = resolved(&[
            ("--privileged", &["203.0.113.1"]),
            ("-v", &["203.0.113.2"]),
            ("evil.test --privileged", &["203.0.113.3"]),
            ("x.test", &["203.0.113.4"]),
            ("ok.test", &["203.0.113.5"]),
        ]);
        let plan = plan_egress(&g, &policy(&[], &[]), &res);
        let plain = run_args(&sample_cfg(), &n, "H", &Hosts::new());
        let args = run_args(&sample_cfg(), &n, "H", &plan.hosts);
        let adds: Vec<&str> = args.windows(2).filter(|w| w[0] == "--add-host").map(|w| w[1].as_str()).collect();
        assert_eq!(adds, ["ok.test:203.0.113.5"], "only the valid name, as one `name:ip` value");
        assert_eq!(args.len(), plain.len() + 2, "nothing else was added: no flag came from a grant");
        // A hostile map that bypassed the plan is still filtered by the name check.
        let mut bad = Hosts::new();
        bad.entry("--privileged".into()).or_default().insert("203.0.113.1".parse().unwrap());
        bad.entry("a b".into()).or_default().insert("203.0.113.2".parse().unwrap());
        assert_eq!(run_args(&sample_cfg(), &n, "H", &bad), plain);
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
        let cleaned = reconcile(&host, &|m| m == "m-live").await;
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
        let host = DockerHost::new_in(&cfg, &root, root.as_os_str()).unwrap();
        assert_eq!(host.ssh_program(), ssh.display().to_string(), "ssh is resolved to an absolute path at start");
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

    use crate::bash::run_launched;
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
        let launch = b.launch("call-run", None, script).unwrap();
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
        assert_eq!(
            exec[..exec.len() - 1],
            exec_args(b.names(), "call-run", "/work", script)
                [..exec_args(b.names(), "call-run", "/work", script).len() - 1]
        );
        assert_eq!(f.calls().iter().filter(|c| c.iter().any(|a| a == script)).count(), 1);
        // The exit status of the command in the box is the job's.
        let launch = b.launch("call-exit", None, "exit 7").unwrap();
        let out = run_launched(&e.ctx, &args(json!({"command": "exit 7"})), &launch).await;
        assert_eq!((out.status, out.outcome.as_str()), (ToolStatus::Error, "exit 7"));
    }

    #[tokio::test]
    async fn killing_a_box_job_stops_the_command_in_the_container_term_then_kill() {
        let dir = tempfile::tempdir().unwrap();
        let f = FakeDocker::new(dir.path());
        let b = MissionBox::new(f.host(), "m-1", source(&[]));
        b.ready().await.unwrap();
        let e = env_with(
            ToolsCfg { kill_grace_s: 1, ..ToolsCfg::default() },
            SandboxCfg { mode: SandboxMode::None, ..SandboxCfg::default() },
        );
        let tag = std::process::id();
        for (call, script, expect_sigs) in [
            (format!("killtest-term-{tag}"), "sleep 300 & wait", vec!["TERM"]),
            (format!("killtest-kill-{tag}"), "trap '' TERM; (trap '' TERM; sleep 300) & wait", vec!["TERM", "KILL"]),
        ] {
            let call = call.as_str();
            let _ = std::fs::remove_file(pid_file(call));
            let launch = b.launch(call, None, script).unwrap();
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
                .map(|c| {
                    c.iter()
                        .find(|a| a.starts_with("kill -"))
                        .map(|a| a[6..].split(' ').next().unwrap_or("").to_string())
                        .unwrap_or_default()
                })
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
        let e = env_with(
            ToolsCfg { kill_grace_s: 1, ..ToolsCfg::default() },
            SandboxCfg { mode: SandboxMode::None, ..SandboxCfg::default() },
        );
        let script = "sleep 300";
        let call = format!("timeout-test-{}", std::process::id());
        let _ = std::fs::remove_file(pid_file(&call));
        let launch = b.launch(&call, None, script).unwrap();
        let out = run_launched(&e.ctx, &args(json!({"command": script, "timeout_s": 1})), &launch).await;
        assert_eq!(out.status, ToolStatus::Timeout, "{out:?}");
        let pgid = read_pid(&pid_file(&call)).await;
        assert!(gone(pgid).await, "the command in the container was stopped with the call");
    }

    // ---- R1 to R5, R9: the lifecycle lock, the static chain, the checks, the environment ----------

    /// What one logged docker call was: `apply`, `check` or `remove` for the helper, `container` for the
    /// box's own `docker run`, otherwise the subcommand.
    fn kind(call: &[String]) -> String {
        if let Some(script) = call.iter().find(|a| a.starts_with(": loom-rules-")) {
            return script.trim_start_matches(": loom-rules-").split(';').next().unwrap_or_default().to_string();
        }
        match call.get(2).map(String::as_str) {
            Some("run") => "container".to_string(),
            other => other.unwrap_or_default().to_string(),
        }
    }

    fn kinds_since(f: &FakeDocker, mark: usize) -> Vec<String> {
        f.calls()[mark..].iter().map(|c| kind(c)).collect()
    }

    fn net_ops(f: &FakeDocker) -> Vec<String> {
        f.calls()
            .iter()
            .filter(|c| c.get(2).is_some_and(|s| s == "network"))
            .filter_map(|c| c.get(3).cloned())
            .collect()
    }

    #[tokio::test]
    async fn r1_a_teardown_racing_a_recreate_never_runs_the_container_without_its_chain() {
        let dir = tempfile::tempdir().unwrap();
        let f = FakeDocker::new(dir.path());
        let host = f.host();
        let old = MissionBox::new(host.clone(), "m-1", source(&["203.0.113.7"]));
        old.ready().await.unwrap();
        let chain_file = f.dir.join(format!("chain-{}", old.names().chain));
        assert!(chain_file.exists());
        // Removing the chain takes a second on the Docker host.
        std::fs::write(f.dir.join("slow.remove"), "").unwrap();
        let mark = f.calls().len();
        let teardown = tokio::spawn({
            let old = old.clone();
            async move { old.teardown().await }
        });
        for _ in 0..300 {
            if !f.running("loom-m-1") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(!f.running("loom-m-1"), "the teardown has removed the container and is on its way to the chain");
        // Another handle for the same mission (the runtime makes one after a stop) wants the box now.
        let fresh = MissionBox::new(host.clone(), "m-1", source(&["203.0.113.7"]));
        fresh.ready().await.unwrap();
        teardown.await.unwrap();
        assert!(f.running("loom-m-1"), "the box that was asked for is there");
        assert!(chain_file.exists(), "and its chain is: the teardown's late removal did not take it away");
        assert!(!f.dir.join("violations").exists(), "the container never started without its chain");
        let kinds = kinds_since(&f, mark);
        let at = |k: &str| kinds.iter().position(|x| x == k).unwrap_or(usize::MAX);
        assert!(at("remove") < at("apply") && at("apply") < at("container"), "{kinds:?}");
    }

    #[tokio::test]
    async fn r1_reconcile_and_teardown_by_name_take_the_missions_lock_too() {
        let dir = tempfile::tempdir().unwrap();
        let f = FakeDocker::new(dir.path());
        let host = f.host();
        let b = MissionBox::new(host.clone(), "m-1", source(&[]));
        b.ready().await.unwrap();
        std::fs::write(f.dir.join("ps.txt"), "m-1\n").unwrap();
        // While the mission's lock is held (here by a stand-in for a creation), neither one gets to touch it.
        let lock = host.mission_lock(&b.names().short);
        let guard = lock.lock().await;
        let by_name = tokio::spawn({
            let host = host.clone();
            async move { teardown_mission(&host, "m-1").await }
        });
        let swept = tokio::spawn({
            let host = host.clone();
            async move { reconcile(&host, &|_| false).await }
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(f.running("loom-m-1"), "nothing was removed while the lock was held");
        assert!(!by_name.is_finished() && !swept.is_finished());
        drop(guard);
        by_name.await.unwrap();
        let cleaned = swept.await.unwrap();
        assert!(!f.running("loom-m-1"));
        // The sweep asked the keep rule only after it had the lock, and a mission it keeps is left alone.
        assert_eq!(cleaned, ["m-1"]);
        let b2 = MissionBox::new(host.clone(), "m-1", source(&[]));
        b2.ready().await.unwrap();
        assert!(reconcile(&host, &|m| m == "m-1").await.is_empty());
        assert!(f.running("loom-m-1"));
    }

    #[tokio::test]
    async fn r1_the_chain_stays_until_the_container_and_the_network_are_gone() {
        let dir = tempfile::tempdir().unwrap();
        let f = FakeDocker::new(dir.path());
        let host = f.host();
        let b = MissionBox::new(host.clone(), "m-1", source(&[]));
        b.ready().await.unwrap();
        let chain_file = f.dir.join(format!("chain-{}", b.names().chain));
        // The network cannot be removed: the container is gone but the chain stays, with its jump.
        std::fs::write(f.dir.join("netrm.fail"), "").unwrap();
        let mark = f.calls().len();
        b.teardown().await;
        assert_eq!(kinds_since(&f, mark), ["rm", "network"], "no helper run that removes the chain");
        assert!(chain_file.exists() && !f.running("loom-m-1"));
        // The network is gone by the time the next try is made ("not found" counts as gone): now the chain goes.
        std::fs::remove_file(f.dir.join("netrm.fail")).unwrap();
        std::fs::remove_file(f.dir.join("net-loom-m-1")).unwrap();
        let mark = f.calls().len();
        teardown_mission(&host, "m-1").await;
        assert_eq!(kinds_since(&f, mark), ["rm", "network", "remove"]);
        assert!(!chain_file.exists());
    }

    /// Stands in for `iptables`, `ip6tables` and `iptables-restore`: rules and chains are lines in files.
    const IPTABLES_STUB: &str = r##"#!/bin/sh
S="@S@"
T=$(basename "$0")
if [ "$T" = iptables-restore ]; then
  while IFS= read -r line; do
    case "$line" in
      :*) c=${line#:}; c=${c%% *}
          # --noflush: a declared chain that exists is kept as it is (only an explicit -F empties it).
          grep -qxF "$c" "$S/iptables.chains" || echo "$c" >> "$S/iptables.chains";;
      -F*) set -- $line; c=$2; grep -v "^$c|" "$S/iptables.rules" > "$S/t"; mv "$S/t" "$S/iptables.rules";;
      -A*) set -- $line; shift; c=$1; shift; echo "$c|$*" >> "$S/iptables.rules";;
    esac
  done
  exit 0
fi
F="$S/$T.rules"; C="$S/$T.chains"
[ "$1" = "-w" ] && shift 2
op=$1; c=$2; shift 2
has() { grep -qxF "$1" "$C"; }
case "$op" in
  -N) has "$c" && exit 1; echo "$c" >> "$C"; exit 0;;
  -C) grep -qxF "$c|$*" "$F"; exit $?;;
  -A) has "$c" || exit 1; echo "$c|$*" >> "$F"; exit 0;;
  -I) case "$1" in [0-9]*) shift;; esac; has "$c" || exit 1; { echo "$c|$*"; cat "$F"; } > "$S/t"; mv "$S/t" "$F"; exit 0;;
  -D) grep -qxF "$c|$*" "$F" || exit 1; grep -vxF "$c|$*" "$F" > "$S/t"; mv "$S/t" "$F"; exit 0;;
  -F) has "$c" || exit 1; grep -v "^$c|" "$F" > "$S/t"; mv "$S/t" "$F"; exit 0;;
  -X) has "$c" || exit 1; grep -q "^$c|" "$F" && exit 1; grep -vxF "$c" "$C" > "$S/t"; mv "$S/t" "$C"; exit 0;;
esac
exit 2
"##;

    struct Tables {
        dir: PathBuf,
        _keep: tempfile::TempDir,
    }

    impl Tables {
        fn new() -> Tables {
            use std::os::unix::fs::PermissionsExt;
            let keep = tempfile::tempdir().unwrap();
            let dir = keep.path().canonicalize().unwrap();
            for name in ["iptables", "ip6tables", "iptables-restore"] {
                let path = dir.join(name);
                std::fs::write(&path, IPTABLES_STUB.replace("@S@", &dir.display().to_string())).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            std::fs::write(dir.join("iptables.chains"), "DOCKER-USER\nINPUT\nFORWARD\n").unwrap();
            std::fs::write(dir.join("ip6tables.chains"), "INPUT\nFORWARD\n").unwrap();
            std::fs::write(dir.join("iptables.rules"), "").unwrap();
            std::fs::write(dir.join("ip6tables.rules"), "").unwrap();
            Tables { dir, _keep: keep }
        }

        /// Run one of the helper's scripts the way the helper container does, with the stub tools.
        fn run(&self, script: &str, n: &Names, stdin: &str) -> bool {
            use std::io::Write;
            let mut child = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(script)
                .arg("_")
                .arg(&n.chain)
                .arg(&n.iface)
                .env_clear()
                .env("PATH", format!("{}:/usr/bin:/bin", self.dir.display()))
                .stdin(Stdio::piped())
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
            child.wait().unwrap().success()
        }

        /// The rules of one chain of one table, top first.
        fn chain(&self, table: &str, chain: &str) -> Vec<String> {
            let text = std::fs::read_to_string(self.dir.join(format!("{table}.rules"))).unwrap();
            let prefix = format!("{chain}|");
            text.lines().filter_map(|l| l.strip_prefix(&prefix)).map(str::to_string).collect()
        }
    }

    #[test]
    fn r1_r2_the_scripts_keep_loom_all_with_its_final_drop_and_drop_ipv6() {
        let t = Tables::new();
        let (m1, m2) = (names("m-1"), names("m-2"));
        let allowed: BTreeSet<Allowed> =
            [Allowed { ip: "203.0.113.7".parse().unwrap(), port: None }].into_iter().collect();
        let to_all = |n: &Names| format!("-i {} -j {}", n.iface, n.chain);
        // One mission: its chain, its jump above LOOM-ALL's DROP, the static jumps, the IPv6 drops.
        assert!(t.run(RULES_APPLY, &m1, &rules_text(&m1, &allowed)));
        assert_eq!(t.chain("iptables", ALL_CHAIN), [to_all(&m1), "-j DROP".to_string()]);
        assert_eq!(t.chain("iptables", "DOCKER-USER"), ["-i lb-+ -j LOOM-ALL"]);
        assert_eq!(t.chain("iptables", "INPUT"), ["-i lb-+ -j LOOM-ALL"]);
        let own = t.chain("iptables", &m1.chain);
        assert!(!own.iter().any(|l| l.contains("ESTABLISHED") || l.contains("conntrack")), "{own:?}");
        assert!(own.first().unwrap().contains("-d 203.0.113.7/32") && own.last().unwrap() == "-j DROP", "{own:?}");
        assert!(own.iter().any(|l| l.contains("-d 203.0.113.7/32 -p tcp -j ACCEPT")), "{own:?}");
        for c in ["INPUT", "FORWARD"] {
            assert_eq!(t.chain("ip6tables", c), [format!("-i {} -j DROP", m1.iface)], "{c}");
        }
        // Again: nothing doubles. A second mission goes above the DROP, not below it.
        assert!(t.run(RULES_APPLY, &m1, &rules_text(&m1, &allowed)));
        assert_eq!(t.chain("iptables", ALL_CHAIN), [to_all(&m1), "-j DROP".to_string()]);
        assert_eq!(t.chain("iptables", "DOCKER-USER").len(), 1);
        assert!(t.run(RULES_APPLY, &m2, &rules_text(&m2, &BTreeSet::new())));
        assert_eq!(t.chain("iptables", ALL_CHAIN), [to_all(&m2), to_all(&m1), "-j DROP".to_string()]);
        assert_eq!(t.chain("iptables", "INPUT").len(), 1);
        assert_eq!(t.chain("ip6tables", "FORWARD").len(), 2);
        // The check passes while everything is there, and fails when the jump or an IPv6 drop is gone.
        assert!(t.run(RULES_CHECK, &m1, ""));
        let rules = std::fs::read_to_string(t.dir.join("ip6tables.rules")).unwrap();
        let without = rules.lines().filter(|l| *l != format!("FORWARD|-i {} -j DROP", m1.iface)).collect::<Vec<_>>();
        std::fs::write(t.dir.join("ip6tables.rules"), without.join("\n") + "\n").unwrap();
        assert!(!t.run(RULES_CHECK, &m1, ""), "an IPv6 drop is missing");
        assert!(t.run(RULES_APPLY, &m1, &rules_text(&m1, &allowed)) && t.run(RULES_CHECK, &m1, ""));
        // Removing one mission removes its own jump, chain and IPv6 drops, and nothing of LOOM-ALL's.
        assert!(t.run(RULES_REMOVE, &m1, ""));
        assert_eq!(t.chain("iptables", ALL_CHAIN), [to_all(&m2), "-j DROP".to_string()]);
        assert!(t.chain("iptables", &m1.chain).is_empty());
        assert!(!std::fs::read_to_string(t.dir.join("iptables.chains")).unwrap().contains(&m1.chain));
        assert_eq!(t.chain("ip6tables", "INPUT"), [format!("-i {} -j DROP", m2.iface)]);
        assert_eq!(t.chain("iptables", "DOCKER-USER"), ["-i lb-+ -j LOOM-ALL"], "the static jumps stay");
        assert!(!t.run(RULES_CHECK, &m1, ""));
        // The last mission leaves LOOM-ALL with its DROP alone: a bridge with no chain is dropped.
        assert!(t.run(RULES_REMOVE, &m2, ""));
        assert_eq!(t.chain("iptables", ALL_CHAIN), ["-j DROP"]);
        assert_eq!(t.chain("iptables", "INPUT"), ["-i lb-+ -j LOOM-ALL"]);
        assert!(t.chain("ip6tables", "INPUT").is_empty() && t.chain("ip6tables", "FORWARD").is_empty());
        // The scripts say nothing that touches the static chain's end: no flush, no delete of LOOM-ALL.
        for script in [RULES_APPLY, RULES_REMOVE] {
            assert!(
                !script.contains("-F LOOM-ALL")
                    && !script.contains("-X LOOM-ALL")
                    && !script.contains("-D LOOM-ALL -j")
            );
        }
    }

    #[test]
    fn m1_a_revoked_destination_is_gone_from_the_chain_and_its_open_flows_are_cut() {
        let t = Tables::new();
        let m = names("m-1");
        let both: BTreeSet<Allowed> = [
            Allowed { ip: "203.0.113.7".parse().unwrap(), port: None },
            Allowed { ip: "203.0.113.9".parse().unwrap(), port: None },
        ]
        .into_iter()
        .collect();
        let only: BTreeSet<Allowed> =
            [Allowed { ip: "203.0.113.7".parse().unwrap(), port: None }].into_iter().collect();
        // The text itself: an explicit flush after the declaration, and no rule for established traffic.
        let text = rules_text(&m, &both);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[..3], ["*filter".to_string(), format!(":{} - [0:0]", m.chain), format!("-F {}", m.chain)]);
        assert!(!text.contains("ESTABLISHED") && !text.contains("conntrack"), "{text}");
        // Applied twice with a grant revoked in between (the stub does not flush a declared chain by itself):
        // the revoked address no longer has a rule, so nothing of its open flows is accepted.
        assert!(t.run(RULES_APPLY, &m, &text));
        assert!(t.chain("iptables", &m.chain).iter().any(|l| l.contains("203.0.113.9/32")));
        assert!(t.run(RULES_APPLY, &m, &rules_text(&m, &only)));
        let own = t.chain("iptables", &m.chain);
        assert!(!own.iter().any(|l| l.contains("203.0.113.9")), "{own:?}");
        assert!(own.iter().any(|l| l.contains("203.0.113.7/32")) && own.last().unwrap() == "-j DROP", "{own:?}");
        assert!(!own.iter().any(|l| l.contains("ESTABLISHED")), "{own:?}");
    }

    #[tokio::test]
    async fn r4_a_running_box_has_its_rules_checked_again_and_put_back_or_the_command_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let f = FakeDocker::new(dir.path());
        let host = f.host();
        let b = MissionBox::new(host.clone(), "m-1", source(&["203.0.113.7"]));
        b.ready().await.unwrap();
        let chain_file = f.dir.join(format!("chain-{}", b.names().chain));
        // Inside the interval nothing is looked at.
        let mark = f.calls().len();
        b.ready().await.unwrap();
        assert_eq!(kinds_since(&f, mark), ["inspect"]);
        // Once the interval is over the rules are checked; present, nothing else happens.
        host.set_recheck(Duration::ZERO);
        let mark = f.calls().len();
        b.ready().await.unwrap();
        assert_eq!(kinds_since(&f, mark), ["inspect", "check"]);
        // The chain went missing: it is installed again before the command may run.
        std::fs::remove_file(&chain_file).unwrap();
        let mark = f.calls().len();
        b.ready().await.unwrap();
        assert_eq!(kinds_since(&f, mark), ["inspect", "check", "apply"]);
        assert!(chain_file.exists() && f.running("loom-m-1"));
        assert!(std::fs::read_to_string(f.dir.join("rules.in")).unwrap().contains("-d 203.0.113.7/32"));
        // Missing and not to be put back (L2): the command is refused, the box is paused, not removed, and
        // `/work` stays; both tries (check, install) are made twice.
        host.set_retry_delay(Duration::ZERO);
        std::fs::remove_file(&chain_file).unwrap();
        std::fs::write(f.dir.join("rules.fail"), "").unwrap();
        let mark = f.calls().len();
        let err = b.ready().await.unwrap_err();
        assert!(
            err.contains("not all in place") && err.contains("command was not run") && err.contains("paused"),
            "{err}"
        );
        assert_eq!(kinds_since(&f, mark), ["inspect", "check", "apply", "check", "apply", "pause"]);
        assert!(f.running("loom-m-1") && f.paused("loom-m-1"), "paused, not removed");
        // Still failing: still refused (even inside the recheck interval), still paused.
        host.set_recheck(Duration::from_secs(3600));
        assert!(b.ready().await.is_err() && f.paused("loom-m-1"));
        // The helper works again: the rules are put back and the box runs again (L2).
        std::fs::remove_file(f.dir.join("rules.fail")).unwrap();
        let mark = f.calls().len();
        b.ready().await.unwrap();
        assert_eq!(kinds_since(&f, mark), ["inspect", "check", "apply", "unpause"]);
        assert!(f.running("loom-m-1") && !f.paused("loom-m-1") && chain_file.exists());
        // A check that passes also unpauses.
        host.set_recheck(Duration::ZERO);
        std::fs::write(f.dir.join("rules.fail.count"), "4").unwrap();
        std::fs::remove_file(&chain_file).unwrap();
        assert!(b.ready().await.is_err() && f.paused("loom-m-1"));
        std::fs::write(&chain_file, "").unwrap();
        let mark = f.calls().len();
        b.ready().await.unwrap();
        assert_eq!(kinds_since(&f, mark), ["inspect", "check", "unpause"]);
        assert!(!f.paused("loom-m-1"));
    }

    #[tokio::test]
    async fn l2_a_helper_that_fails_once_does_not_cost_the_box_and_a_paused_box_can_be_torn_down() {
        let dir = tempfile::tempdir().unwrap();
        let f = FakeDocker::new(dir.path());
        let host = f.host();
        host.set_recheck(Duration::ZERO);
        host.set_retry_delay(Duration::ZERO);
        let b = MissionBox::new(host.clone(), "m-1", source(&["203.0.113.7"]));
        b.ready().await.unwrap();
        // The chain is gone and the helper fails twice (the check and the install of the first try): the
        // second try puts the rules back, and nothing is paused or removed.
        std::fs::remove_file(f.dir.join(format!("chain-{}", b.names().chain))).unwrap();
        std::fs::write(f.dir.join("rules.fail.count"), "2").unwrap();
        let mark = f.calls().len();
        b.ready().await.unwrap();
        assert_eq!(kinds_since(&f, mark), ["inspect", "check", "apply", "check", "apply"]);
        assert!(f.running("loom-m-1") && !f.paused("loom-m-1"));
        assert!(!subs(&f).iter().any(|s| s == "pause"));
        // A paused box goes away with the mission: `docker rm --force` removes a paused container.
        std::fs::remove_file(f.dir.join(format!("chain-{}", b.names().chain))).unwrap();
        std::fs::write(f.dir.join("rules.fail"), "").unwrap();
        assert!(b.ready().await.is_err());
        assert!(f.paused("loom-m-1"));
        std::fs::remove_file(f.dir.join("rules.fail")).unwrap();
        b.teardown().await;
        assert!(!f.running("loom-m-1") && !f.paused("loom-m-1"));
        assert_eq!(rm_args(b.names())[..2], ["rm", "--force"]);
    }

    #[tokio::test]
    async fn l1_a_handle_of_a_torn_down_box_makes_nothing_again() {
        let dir = tempfile::tempdir().unwrap();
        let f = FakeDocker::new(dir.path());
        let host = f.host();
        let b = MissionBox::new(host.clone(), "m-1", source(&[]));
        b.ready().await.unwrap();
        b.teardown().await;
        assert!(!f.running("loom-m-1"));
        let runs = f.sub("run").len();
        let e = env_with(ToolsCfg::default(), SandboxCfg { mode: SandboxMode::None, ..SandboxCfg::default() });
        assert_eq!(b.ready().await.unwrap_err(), BOX_CLOSED);
        assert_eq!(b.reset().await.unwrap_err(), BOX_CLOSED);
        assert_eq!(b.push(e.ctx.sandbox.clone(), e.ctx.workspace.clone()).await.unwrap_err(), BOX_CLOSED);
        assert_eq!(b.get_tar("/work", 1024).await.unwrap_err(), BOX_CLOSED);
        assert_eq!(f.sub("run").len(), runs, "no docker run: nothing was made");
        assert!(!f.running("loom-m-1"));
        // A new handle (the mission was resumed) is a new box.
        let again = MissionBox::new(host, "m-1", source(&[]));
        again.ready().await.unwrap();
        assert!(f.running("loom-m-1"));
    }

    #[tokio::test]
    async fn r5_an_existing_network_is_adopted_only_when_it_is_the_missions_own() {
        let dir = tempfile::tempdir().unwrap();
        let f = FakeDocker::new(dir.path());
        let host = f.host();
        // Our own network left by an earlier box: adopted after an inspect, not removed.
        let b = MissionBox::new(host.clone(), "m-1", source(&[]));
        b.ready().await.unwrap();
        b.reset().await.unwrap();
        assert_eq!(net_ops(&f), ["create", "create", "inspect"], "{:?}", net_ops(&f));
        assert!(f.running("loom-m-1"));
        // A foreign network of that name (no labels), or one with the labels but another bridge: replaced.
        let home = host.home_hash();
        let foreign = [
            r#"{"Driver":"bridge","EnableIPv6":false,"Labels":{"x":"y"},"Options":{},"Containers":{}}"#.to_string(),
            format!(
                r#"{{"Driver":"bridge","EnableIPv6":false,"Labels":{{"loom.home":"{home}","loom.mission":"m-2"}},"Options":{{"com.docker.network.bridge.name":"docker0"}},"Containers":{{}}}}"#
            ),
        ];
        for (i, json) in foreign.iter().enumerate() {
            let mission = format!("m-{}", i + 2);
            let n = names(&mission);
            std::fs::write(f.dir.join(format!("net-{}", n.network)), "").unwrap();
            std::fs::write(f.dir.join(format!("netjson-{}", n.network)), json).unwrap();
            let mark = net_ops(&f).len();
            let b = MissionBox::new(host.clone(), &mission, source(&[]));
            b.ready().await.unwrap();
            assert_eq!(net_ops(&f)[mark..], ["create", "inspect", "rm", "create"], "{mission}");
            let made = std::fs::read_to_string(f.dir.join(format!("netjson-{}", n.network))).unwrap();
            assert!(made.contains(&format!("\"loom.mission\":\"{mission}\"")) && made.contains(&n.iface), "{made}");
        }
        // A foreign network with a container attached is left alone, and no box is made.
        let n = names("m-9");
        std::fs::write(f.dir.join(format!("net-{}", n.network)), "").unwrap();
        std::fs::write(
            f.dir.join(format!("netjson-{}", n.network)),
            r#"{"Driver":"bridge","EnableIPv6":false,"Labels":null,"Options":{},"Containers":{"abc":{}}}"#,
        )
        .unwrap();
        let mark = net_ops(&f).len();
        let b = MissionBox::new(host.clone(), "m-9", source(&[]));
        let err = b.ready().await.unwrap_err();
        assert!(err.contains("left alone") && err.contains("1 container"), "{err}");
        assert_eq!(net_ops(&f)[mark..], ["create", "inspect"]);
        assert!(!f.running(&n.container));
    }

    #[test]
    fn r5_inspect_judges_driver_ipv6_labels_and_the_bridge_name() {
        let n = names("m-1");
        let json = |driver: &str, v6: bool, home: &str, mission: &str, bridge: &str, containers: &str| {
            format!(
                r#"{{"Driver":"{driver}","EnableIPv6":{v6},"Labels":{{"loom.home":"{home}","loom.mission":"{mission}"}},"Options":{{"com.docker.network.bridge.name":"{bridge}"}},"Containers":{containers}}}"#
            )
        };
        let ours = json("bridge", false, "H", "m-1", &n.iface, "{}");
        assert_eq!(inspect_network(ours.as_bytes(), &n, "H").unwrap(), Found::Ours);
        for (bad, why) in [
            (json("overlay", false, "H", "m-1", &n.iface, "{}"), "not a bridge"),
            (json("bridge", true, "H", "m-1", &n.iface, "{}"), "IPv6"),
            (json("bridge", false, "other", "m-1", &n.iface, "{}"), "loom home"),
            (json("bridge", false, "H", "m-2", &n.iface, "{}"), "this mission"),
            (json("bridge", false, "H", "m-1", "br-x", r#"{"a":{},"b":{}}"#), "bridge interface"),
        ] {
            match inspect_network(bad.as_bytes(), &n, "H").unwrap() {
                Found::Foreign { why: w, .. } => assert!(w.contains(why), "{w}"),
                Found::Ours => panic!("{bad} was taken as ours"),
            }
        }
        assert!(inspect_network(b"not json", &n, "H").is_err());
    }

    #[test]
    fn r9_programs_are_absolute_from_the_start_and_the_private_directories_exist() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().canonicalize().unwrap().join("home");
        let (search, ssh) = fake_ssh_dir(dir.path());
        let cfg = BoxCfg { docker_cli: "/bin/sh".into(), ..sample_cfg() };
        let host = DockerHost::new_in(&cfg, &home, &search).unwrap();
        assert_eq!(host.ssh_program(), ssh.display().to_string());
        assert_eq!(host.cli(), Path::new("/bin/sh"));
        for sub in ["box-docker", "box-run"] {
            let mode = std::fs::metadata(home.join("keys").join(sub)).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{sub}");
            assert_eq!(std::fs::read_dir(home.join("keys").join(sub)).unwrap().count(), 0, "{sub} is empty");
        }
        // A bare name is looked for once, in the search path; a relative path is never taken.
        let empty = tempfile::tempdir().unwrap();
        let err = DockerHost::new_in(&cfg, &home, empty.path().as_os_str()).err().unwrap();
        assert!(err.contains("ssh") && err.contains("not found on the daemon's PATH"), "{err}");
        let err = DockerHost::new_in(&BoxCfg { docker_cli: "bin/docker".into(), ..cfg.clone() }, &home, &search)
            .err()
            .unwrap();
        assert!(err.contains("relative path"), "{err}");
        let relative_dir = DockerHost::new_in(&cfg, &home, std::ffi::OsStr::new("relative/dir")).err().unwrap();
        assert!(relative_dir.contains("not found"), "a relative PATH entry is not searched: {relative_dir}");
        // A local socket needs no ssh at all.
        let local = BoxCfg { docker_cli: "/bin/sh".into(), docker_socket: "/s.sock".into(), ..BoxCfg::default() };
        assert!(DockerHost::new_in(&local, &home, empty.path().as_os_str()).is_ok());
    }

    #[tokio::test]
    async fn r9_the_docker_client_gets_exactly_a_fixed_environment_and_a_private_directory() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let f = FakeDocker::new(dir.path());
        let b = MissionBox::new(f.host(), "m-1", source(&[]));
        b.ready().await.unwrap();
        let e = env_with(ToolsCfg::default(), SandboxCfg { mode: SandboxMode::None, ..SandboxCfg::default() });
        // A command through the job machinery: the launcher process and the docker client under it.
        let launch = b.launch("call-env", None, "true").unwrap();
        assert_eq!(launch.cwd, f.dir.join("keys/box-run"), "not the session's scratch directory");
        assert_ne!(launch.cwd, e.ctx.tmp_dir);
        assert_eq!(launch.env, f.host().docker_env());
        let out = run_launched(&e.ctx, &args(json!({"command": "true"})), &launch).await;
        assert_eq!(out.status, ToolStatus::Ok, "{out:?}");
        let text = std::fs::read_to_string(f.dir.join("docker.env")).unwrap();
        let seen: BTreeMap<String, String> = text
            .lines()
            .filter_map(|l| l.split_once('='))
            .filter(|(k, _)| !matches!(*k, "PWD" | "OLDPWD" | "SHLVL" | "_"))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let keys = f.dir.join("keys");
        let expected: BTreeMap<String, String> = [
            ("PATH", SYSTEM_PATH.to_string()),
            ("HOME", keys.join("box-docker").display().to_string()),
            ("DOCKER_CONFIG", keys.join("box-docker").display().to_string()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        assert_eq!(seen, expected, "the environment of the docker client");
        assert!(SYSTEM_PATH.split(':').all(|d| d.starts_with('/')), "only absolute directories");
        assert_eq!(
            std::fs::read_to_string(f.dir.join("docker.cwd")).unwrap().trim(),
            keys.join("box-run").display().to_string()
        );
        assert_eq!(std::fs::metadata(keys.join("box-docker")).unwrap().permissions().mode() & 0o777, 0o700);
        // The docker calls the daemon makes itself (not through a job) have the same environment.
        b.teardown().await;
        let text = std::fs::read_to_string(f.dir.join("docker.env")).unwrap();
        assert!(text.lines().any(|l| l == format!("DOCKER_CONFIG={}", keys.join("box-docker").display())), "{text}");
        assert!(
            !text.lines().any(|l| l.starts_with("LOOM") || l.starts_with("RUST") || l.starts_with("CARGO")),
            "{text}"
        );
    }
}
