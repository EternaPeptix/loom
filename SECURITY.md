# Security

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository: open the repository's Security tab
and choose "Report a vulnerability" (a security advisory). Please do not open a public issue for
something exploitable. Say which version or commit you ran, what you did, and what you saw. If
private reporting is not enabled on the repository you are looking at, open an issue that asks for a
private channel and contains no details.

## What loom is built to resist

loom is a tool for **one operator** who runs it on their own machine against a model server they
trust with their prompts. It assumes the operator is not an adversary and the other local accounts are
not trusted. The adversary it is built against is the **model and the content the model reads**: tool
output, files, web pages and other agents' reports can all contain instructions, and the model can make
mistakes or be talked into harmful commands. loom limits what a command the model runs can do, keeps
the records the model cannot edit, and does not let model text pass as the operator's or the
harness's.

### Files on disk

- The loom home and every directory the harness creates under it are mode 0700, and every file it creates
  there (session logs, status and meta files, blobs and their indexes, job output, the egress audit file,
  journals, the daemon file, the daemon log) is mode 0600, set at creation. At start the daemon tightens the
  home, `keys/`, `sessions/`, `missions/`, `blobs/` and `logs/` to 0700 if an earlier version or the operator
  left them looser, so other local accounts can no longer open anything below them. A descriptor another
  account opened before that keeps working (a `tail -f` on an old session log goes on reading what is appended),
  and files written by earlier versions are not rewritten: they keep their mode behind those directories, and
  `chmod -R go-rwx ~/.loom` tightens them as well.

### The daemon and its API

- The daemon listens on a loopback address only. It refuses to start on a name that resolves to a
  non-loopback address.
- Every API request must carry the API token as `Authorization: Bearer <token>`, or a web-session
  secret obtained with it. There are no cookies. The token is 32 random bytes in `~/.loom/token`
  (mode 0600), created atomically. Anyone who can read that file as your user can drive the daemon,
  so the protection is that of your account.
- Requests must name the daemon's own address in `Host` and, for anything that changes state, an
  allowed `Origin`. This stops a web page you visit from reaching the API through your browser.
- The web page is opened with `loom open`, which trades the token for a single-use login code (valid
  60 seconds) and then a web-session secret kept in memory by the daemon and in the tab's session
  storage. The token is never put on a command line or in a URL, and neither is the login code: `loom open` writes a
  page file (mode 0600, in `<home>/login`, removed after five minutes) that sends the browser to the address and
  gives the opener the file's path.
- Before the `loom` command or the desktop app sends the token to a listener, the listener must prove it
  holds the token (an HMAC answer on `/healthz`). A different program on the daemon's port cannot
  collect the token this way. The exception is the global flag `--unverified-daemon`: with it, the
  `loom` command sends the token to a listener that gave no proof (it prints a warning). It exists only
  to stop a daemon from a version that cannot give the proof; do not use it otherwise.
- To use a daemon on another machine, forward its port over SSH. Do not change the bind address to a
  non-loopback one; the daemon will not accept it.
- **The daemon's environment holds only what it needs.** `loom up` starts the daemon with `PATH`, `HOME`,
  `USER`, `LOGNAME`, `SHELL`, `LANG`, `LC_*`, `TZ`, `TMPDIR`, `LOOM_LOG`, `RUST_BACKTRACE`, the variables
  your profiles name in `api_key_env` and those listed in `[sandbox] env_pass`, and nothing else of the
  shell that ran it: tokens, cloud credentials and proxy or loader variables exported there do not reach
  the daemon or the commands it runs. A login service (`loom service install`) gets `LOOM_HOME` and a fixed
  `PATH` from its property list. `loom daemon` run straight from a shell keeps that shell's environment.
- **Model API keys belong in files.** `api_key_file = "<name>"` reads `~/.loom/keys/models/<name>` once at
  start; the file must be yours, a regular file and mode 0600, and the daemon does not start otherwise.
  Commands cannot read `~/.loom/keys`. `api_key_env` still works, but then the key is in the daemon's
  environment, where commands can read it (see *Known limits*); `loom up`, `loom config check` and the
  daemon's log warn about every such profile, and `loom service install` refuses one.
- **Model requests use no proxy.** `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` (in either case) and the
  system's proxy settings are ignored for model requests, which go to the configured `base_url` only. A
  proxy exported in your shell (an intercepting proxy, say) never sees a transcript or the key.

### What a command run by the model can and cannot do

On macOS, with `[sandbox] mode = "seatbelt"` (the default), commands run under `sandbox-exec`:

- **Writes** are allowed only in the session's workspace, the session's temporary directory, any
  `extra_writable` directories, and the device files `/dev/null`, `/dev/tty` and `/dev/dtracehelper`. `~/.loom`
  (including the token, keys, logs and every session record), `<workspace>/.loom` and your
  `protected_paths` are never writable, with one exception: the session's temporary directory lies in
  `~/.loom` (`sessions/<id>/tmp`), and everything inside it is writable, though the directory entry
  itself cannot be removed, renamed or replaced. A directory that holds a protected path cannot be
  renamed or removed.
- **Credential stores are unreadable and unwritable** by default (`protect_credentials = true`): `~/.ssh`,
  `~/.aws`, `~/.gnupg`, `~/.config/gh`, `~/.config/gcloud`, `~/.azure`, `~/.kube`,
  `~/.docker/config.json`, `~/.netrc`, `~/.npmrc`, `~/.pypirc`, cargo and git credential files, password
  stores and password-manager data, cloud, registry, model-hub, AI-tool and database client credentials
  (`~/.cache/huggingface`, `~/.claude.json`, `~/.pgpass`, `~/.vault-token`, `~/.m2/settings.xml`,
  `~/.config/rclone`, and more), wallets, the macOS Keychains and Cookies folders, Mail, Messages,
  Telegram, Group Containers and the Chrome, Chromium, Brave, Edge, Arc, Vivaldi, Opera, Firefox and
  Safari profiles. So are
  the whole loom home but the session's temp directory and the harness's staging of analysis inputs (the
  token and keys included), whose names are hidden as well as their content, and your `unreadable_paths`. A listed directory that is or contains the
  workspace is skipped.
- **The network** is closed except for loopback connections to the session's own port of the egress
  proxy (and any ports or sockets you list). Each session has a proxy port of its own, and its proxy
  credentials are accepted on that port only; the proxy never connects to one of its own ports, whatever
  the policy allows, and while the daemon runs no session is given a port an earlier session had. The
  proxy applies `[network]`: by default (`deny_all`) it forwards nothing. It resolves
  names itself, refuses private, loopback and link-local addresses (including IPv4 addresses hidden in
  IPv6 forms) unless you list them, applies the deny list to the resolved address, and records every
  decision in a hash-chained audit file. Whatever you grant or allow, the proxy also refuses cloud metadata, the
  DevTools and inspector ports 9222 and 9229 and Docker API ports 2375 and 2376 on this machine, the daemon's
  port, the model endpoints of the configuration, the box's Docker host and `network.infrastructure`
  (`deny infrastructure: …` in the audit file), by name and by the addresses the daemon resolves for the named
  entries and for this machine, and the sandbox refuses those loopback ports directly (also under `loopback_all`);
  `loom scope revoke` takes a grant back for good (it is refused whatever else allows it, and kept across a restart)
  and cuts its open connections. Commands that listen on loopback can be reached by other
  local processes. Commands cannot connect to the daemon's own port, whatever you allow on loopback, so a
  `loom open` login code (which is no longer on any command line) could not be redeemed from inside the sandbox directly (the
  proxy, which refuses loopback addresses, could reach it only if you list loopback in `allow_private` or
  grant a loopback address). In every network mode commands also cannot reach the macOS services that fetch
  a URL for a process (`com.apple.trustd.agent`, `com.apple.trustd`, `com.apple.ocspd`,
  `com.apple.nsurlsessiond`, WebKit's networking services); programs that check certificates through macOS
  (Swift and Go programs, `security`, `codesign --verify`), background URL sessions and WebKit-based tools
  then fail, while curl and Python, which use their own certificate files, work. `mach-lookup` is denied by
  default and a short list of services is allowed (what the usual toolchains need; `sandbox.mach_allow` adds
  one that a tool needs), so the keychain and security daemons, Spotlight (`mdfind`), the clipboard, audio and
  the rest are out of reach too. At start and every hour the daemon runs a self-probe of this (a certificate
  that names a URL, a background URL session, a WebKit view, and the daemon's port with a decoy process whose
  argument vector is readable) against a local listener; `loom status` and the web header say
  `egress: bounded`, or `UNBOUNDED` with the reason when a probe got through, could not run, or
  `sandbox.allow_fetch_services` is set.
- **Git cannot be made to run code as you.** Anywhere commands can write (workspace, temporary
  directory, `extra_writable`), they cannot write Git configuration, hooks or the `commondir`/`gitdir`
  pointers — of the repository, of linked worktrees (also ones checked out outside the workspace) and of
  submodules, initialized or not — nor make or move a `.git`, a worktree's gitdir or a submodule's
  repository into place; the hooks directory your Git configuration names (`core.hooksPath`, as husky
  sets it) and the files it includes are protected too, read from each repository's and your global
  configuration. Commits and branches in existing repositories work; upstream tracking cannot be recorded.
  A session cannot run `git init`, a non-bare `git clone` (installs of pip, npm, cargo or uv dependencies
  from Git URLs included), `git worktree add` or `git submodule update` in any form: you do those, and a
  bare clone works. A submodule you set up during a mission is protected but cannot be committed in until
  the next session.
- **No mounts, no preference writes.** Commands cannot mount a file system or attach a disk image over a
  directory (`hdiutil attach` and `diskutil` fail), which would otherwise replace `.git/hooks`, `~/.ssh`
  or `~/Library/LaunchAgents` for you; and they cannot write macOS preferences (`defaults write`), which a
  system service would otherwise write for them outside the sandbox.
- **Scope is the operator's.** The agent can ask for hosts with `request_scope`, which opens an inbox
  item and changes nothing. Hosts are granted only by the operator, per session, with a record in the
  ledger; a grant dies with the session. Under `deny_all` a grant allows exactly the granted hosts (the
  configured `allow` list stays off). `*`, a wildcard over a top-level domain (`*.com`) or over IP
  addresses (`*.0.1`), the unspecified address (`0.0.0.0`, `::`, which reaches this machine's own
  services) and a loopback address without a port (`127.0.0.1`) can be neither requested nor granted, so
  approving a request cannot open everything at once. Still read what you approve: a wildcard under a
  domain whose names resolve to any address (wildcard DNS such as `*.nip.io`) or one of this machine's own
  LAN addresses is not recognised as broad. `loom release` records that the operator closed a mission
  without the goal established, with a reason, and it is shown as that, not as finished.
- **No LaunchServices opens, Apple Events or launchd jobs**, so a command cannot start a program
  outside the sandbox that way.
- **Signals** can reach only processes inside the sandbox.
- Environment variables whose names look like secrets are not passed to commands.

Commands run with your user id. The sandbox is the only barrier between them and everything your user
can read.

### The box (`[box]`)

When the operator enables a box, a session can run commands in a container on a Docker host with
`box_exec`. What that does and does not give the agent:

- **No Docker for the agent.** The docker command line client is run by the daemon, outside the sandbox,
  with an argument list loom builds. The agent's text is only the last argument of `/bin/bash -c` in the
  container, never a docker, ssh or firewall argument. The forwarded Docker socket is in `<loom home>/keys`,
  which commands cannot read, and is never added to the sandbox's socket list.
- **A hardened container.** All capabilities dropped (plus `cap_add`, from which `SYS_ADMIN`, `NET_ADMIN`
  and the other dangerous ones are refused at config load), `no-new-privileges`, a read-only root, tmpfs
  `/tmp` and `/work` (executable, since the box exists to run what is built in it), an init as PID 1, user 1000, no bind mounts, devices, privileged mode or host namespaces, limits on
  memory, processes and CPUs.
- **Pinned images.** `image` and `helper_image` must be `name@sha256:<digest>`; a tag can be moved.
- **Egress is the mission's grants.** A per-mission bridge network without IPv6 (also off inside the
  container, and dropped on the host) and without DNS; rules on the Docker host allow only the granted
  exact hosts and addresses (checked against the same policy as the proxy, so private addresses need
  `allow_private`) and drop the rest; they are updated when grants change and removed with the box. A granted IP literal is also allowed through the proxy for this mission only; a granted name never unlocks private addresses. Granted names reach the container only as
  `--add-host name:ip` built from validated names and IPv4 addresses (no root process runs in the box); a
  name granted later resolves after `box_reset`, its address is allowed at once. Every
  box bridge is sent to a static chain `LOOM-ALL` that ends with `DROP`, so a bridge with no chain of its
  own is dropped, never NATed. The container is started only after its rules are in place, and is removed
  if they cannot be kept current at an update; a running box's rules are checked again about once a minute. A mission's
  create, reset, re-rule and teardown are serialized, and its chain is removed only after its container
  and network are gone. A network that is not this box's own is never adopted. The Docker host must not
  have other interfaces named `lb-*`: `LOOM-ALL` drops them. The mission chain has no rule for
  established traffic, so a revoked grant cuts open flows at once; a box whose rules cannot be put back
  is paused (its `/work` kept) and the command refused, not removed.
- **The box is not run without a sandbox.** `[sandbox] mode = "none"` with the box, or a
  `sandbox.unix_sockets` entry for the box's socket or anything under `<loom home>/keys`, is a config
  error. The docker client and `ssh` are resolved to absolute paths at start and run with a fixed `PATH`,
  an empty private `HOME` and `DOCKER_CONFIG`, and a private working directory. A stopped, ended or
  archived mission gets no box until it is resumed.
- **Files in** are the changed regular files of the workspace that the agent could read itself: never
  `.loom`, `.git`, oracle secrets, unreadable paths, credential stores or anything reached through a link
  (every directory and file is opened relative to its parent with `O_NOFOLLOW`, so a link swapped in
  after the listing is refused).
  Both directions use `docker exec` of `/usr/bin/tar` as user 1000 with a fixed `PATH` (`docker cp` is not used);
  the path of a fetch is one argv element after `--`, and the stream is read only up to `get_max_mb` plus
  headers, then the client is killed.
  **Files out** (`box_get`) are unpacked by loom, not by the box's `tar`: regular files and directories only, no
  names that leave the destination, no links or devices, size and entry caps, and each file is written
  the way the `write` tool writes it, so it cannot reach a path `write` cannot.
- **Limits.** A kernel or Docker escape from the container reaches the Docker VM, not this machine. Run
  the VM as dedicated and unprivileged, and block it at the VM's host from the host itself and from
  private ranges (see docs/RUN.md). Commands in the box are untrusted code with the network reach of the
  grants; data the agent can read can be sent to a granted host, as with the proxy.

### The monitor (specified in `docs/MONITOR.md`; the phases build it, and until a phase lands its part does not run)

The adversary the rest of this file describes is the model and what it reads. The monitor is aimed at the same
adversary seen from one level up: the **agents themselves**, whatever the cause (a misaligned propensity, reward
hacking, instructions injected through a target, or pressure from other agents). It assumes each agent may deceive,
writes any text the harness reads, may coordinate with other agents through any shared surface (a workspace, a lab
port, the process table, a scope request), runs for hours under a prompt that pushes it to persist, is competent at
offensive security, and **knows how the monitor works**: the design is public, so its only secrets are a keyed seed
(canary names and places, which reasoning is sampled, the fence around data) and the contents of reviews and verdicts.

What is protected: third parties reached from sessions with real targets; the operator's machine and accounts (the
logged-in browser's debugging port, local model ports, the daemon's port and keys, other missions' proxy
credentials); the harness's own records (logs, journals, oracles, the verifier and the monitor); other missions;
and the operator's trust (what a finish text, a scope request or a result says must be true, and nothing the
operator is told to run may be booby-trapped).

What it does about it, in the order of how much it is relied on:
1. **A deterministic floor with no model** (phase E1 to E4): infrastructure denied in every proxy policy and beating
   grants, macOS fetch services denied in every network mode with an hourly self-probe, tunnels that can be cut, the SNI
   bound to the CONNECT host, every process of a session identifiable and killable, a process limit.
2. **Tripwires** on every record, a short list of them enforcing from the first day and the rest in shadow until measured.
3. **A reviewer model from a different family**, reading each trajectory as fenced data. It raises the cost of
   misbehaviour. It is not the boundary, and nothing it writes reaches the agent.
4. **A gate** that decides, before they run, the calls of the classes where harm cannot be undone; anything it
   cannot decide goes to the operator.

The monitor is itself new code with authority to stop work. It is built in shadow, fails closed for clearing (no
model-cleared gate and no keep-going reopen without a full, non-degraded review), never counts its own faults as
agent misbehaviour, and is out of reach of the agents (no session entry, no tools, no network except its model
endpoints, state under the hidden loom home).

### Records

Sessions are append-only logs in which each record names the hash of the previous one, and mission
state is a journal sealed with an HMAC key kept outside the workspace. These make tampering and
truncation detectable, not impossible: see the limits below.

## Known limits

These are the places where loom does less than the text above might suggest.

- **Reads are allowed by default.** The sandbox denies reads of the credential list, the whole loom home
  (`~/.loom`: other sessions' and its own logs, stored outputs, mission journals, configuration, token and
  keys; only the session's temp directory is readable), and `unreadable_paths`. Everything else your user can read, a command can read: your
  documents, shell history, other projects, source trees, tokens kept in files that are not on the
  list, and anything under a directory that is or contains the workspace. Set the workspace to the
  smallest directory that works, and add paths to `unreadable_paths`.
- **The seatbelt profile starts from allow-everything and subtracts.** It denies writes, the listed
  reads, the network and the launch routes above. What it does not name is allowed: running programs,
  reading system information, local inter-process communication. A new macOS facility is open until the
  profile is extended. `sandbox-exec` is deprecated by Apple, though it still works. The denials of
  LaunchServices, Apple Events and launchd jobs were checked to compile into the profile but have
  not been exercised from a graphical login session.
- **The file tools run in the daemon, outside the OS sandbox.** They apply the same rules themselves.
  `read`, `write` and `edit` check the real path of what they actually opened, not a path checked
  earlier: a file is opened and then judged by the path the system gives for the open file, and a write
  opens the directory, judges its real path with the file name, and creates and renames the file
  relative to that open directory. A command that swaps a directory for a link during such a call gets
  no content and no file out of it; it can still learn whether a path there exists and what kind of
  file it is. `grep` checks each path as the walk finds it, and then judges the real path of the file it
  opens, as `read` does; `dep_scan` reads its report files, `continuation` its guarded files and the copy of
  a workspace made for an agent (and adopted back) its files the same way, so a link swapped in meanwhile
  reads and copies nothing the rules refuse. Adopting an agent's copy writes, makes and removes as `write`
  does, relative to directories it opened and judged, so a directory a background command swaps for a link
  during adoption has nothing written through it. `glob` only lists names, checking each directory it walks
  as the directory that was opened, so a command that swaps a link in during a walk can in principle make it
  list names it should not (never content). macOS shows `/Users`, `/private` and the other folders of the
  data volume under `/System/Volumes/Data` too; a path in that form is given its usual form back before the
  rules are applied. All of them refuse to touch anything that is not a regular file.
- **Without macOS there is no sandbox.** On other systems the daemon starts only with
  `[sandbox] mode = "none"`, and then commands are unconfined. The file tools still refuse the protected
  and credential paths, and the network proxy still exists, but a command can ignore it. Do not run
  loom in that mode on a machine or account you care about.
- **Environment scrubbing is by name and by URL.** Names with a secret word, session, auth, pass, jwt,
  webhook or private parts, every model profile's `api_key_env`, and values that are URLs with a
  password in them are withheld. A secret in a variable called something else, in another form, is
  passed through. `env_pass` passes more.
- **Any process of yours can read the environment and arguments another of your processes was started
  with**, sandboxed commands included (macOS `KERN_PROCARGS2`; the seatbelt profile cannot deny it
  without breaking common interpreters, and clearing a variable inside a running process does not erase
  the copy that is read). So a command can read: a key named by `api_key_env`, and anything else in the
  daemon's environment (with `loom daemon` run straight from a shell, that shell's whole environment);
  the command lines and environments of other sessions' commands, other missions' included; and those of
  every other program you run that is not a platform binary. loom narrows what is there: `loom up`
  clears the daemon's environment, `api_key_file` keeps keys out of it, and a session's proxy credentials
  work only on that session's own proxy port, which other sessions' commands cannot connect to, directly
  or through the proxy. With `loopback_all = true` (or a `loopback_ports` entry that happens to be a
  session's port) they can, and a command that read another running session's proxy credentials can then
  reach what that session may reach, recorded in that session's audit log. A daemon restart releases the
  ports: a process that left its command's process group under the previous daemon keeps a profile that
  allows its old port, which a session of the new daemon may be given. A command that holds every free
  loopback port stops new sessions from starting (they cannot get a port), as it stops other outgoing
  connections. Ports of ended sessions are freed only by a restart, so after some sixteen thousand
  sessions in one daemon run new sessions can fail to get a port (with a sentence saying so) until the
  daemon is restarted. Do not export secrets in the shell you start loom from, and do not pass secrets to
  commands on their command lines.
- **A process that leaves its command's process group is not tracked by the job table, but the census finds it.**
  After `setsid`, `daemon()`, `redis-server --daemonize yes` or `tmux new -d`, `job_kill`, stop, the end of the
  session and daemon shutdown do not stop it, although it stays under the seatbelt profile. Every 60 s the daemon
  finds each session's processes by that profile (whatever they did to their process group and environment) with
  the TCP sockets they listen on (`GET /api/census`), warns once about what an ended session left running, and
  `POST /api/sessions/{id}/census/kill` stops them. Nothing is stopped automatically (a server may have been started
  on purpose). The query is a private macOS call (`sandbox_check`), probed at start; where it does not work the census
  falls back to the `LOOM_SANDBOX_ID` environment variable and known process groups, which `env -i`, a double fork
  or `setsid` defeat (`docs/MONITOR.md` X7). Under bubblewrap there is no census yet (no cgroup per session).
- **A fork bomb is limited, not forbidden.** A sandboxed command's RLIMIT_NPROC is the user's limit minus
  `sandbox.nproc_headroom` (256), never below the processes that exist plus 64, so it cannot take the last process
  slots the daemon needs to stop it. The daemon inspects and signals processes through libproc (`/proc` on Linux),
  never by running `ps`, so a full process table does not blind it; a group it cannot inspect is still signalled unless
  its leader is known to have been replaced.
- **The configured network policy is per daemon**, and is read at start. In `allowlist` mode a
  listed host can be used by every session. Data can be sent to an allowed host. On top of it the
  operator can grant a session more hosts while it runs (`loom scope`): a grant is per session,
  recorded in the mission's ledger, and ends with the session. The agent can ask (`request_scope`) but
  cannot grant; only an operator request reaches the grant, and the model's tools cannot make one.
- **A network-specific NAT64 prefix is an ordinary IPv6 prefix to the proxy.** The proxy looks through
  the well-known NAT64 prefix `64:ff9b::/96` (and `64:ff9b:1::/96`) to the IPv4 address it carries, but
  not through a prefix your network chose for itself. Listing such a prefix in `allow_private` admits
  every IPv4 address behind it, private ones included, and IPv4 `deny` entries do not cover addresses
  inside it.
- **A missing holder directory can still be moved into place.** A writable directory that holds a
  protected or unreadable path cannot be removed, renamed or made as a link. If it does not exist yet,
  a command can still create it by moving another directory into its place, and a link already inside
  that moved directory then decides where a file written below it later, by something outside the
  sandbox, lands.
- **A command can talk to anything on loopback that you allow** (`loopback_ports`, `loopback_all`,
  `unix_sockets`), including services that run as you. With `loopback_all` that includes your
  machine's own network addresses, which the macOS sandbox counts as loopback.
- **macOS fetches URLs for a command only if you allow it.** A command could have the certificate service
  (`trustd`) fetch a URL named in a certificate it made, or start a background URL session
  (`nsurlsessiond`) or a WebKit view, which reach any host without the proxy and without an entry in the
  network audit file. The sandbox denies those services in every network mode and denies `mach-lookup` for
  every service outside a short list, so other services that make network requests on a process's behalf
  are out of reach as well (name resolution goes to a socket the network deny already refuses).
  `sandbox.allow_fetch_services = true` opens the route again and marks the daemon's egress "unbounded"
  (status, and keep-going refuses to turn on). The self-probe's controls fetch only from a loopback
  listener of the probe's own. What the probe cannot see: a route that exists on a host whose services do not
  fetch for a sandboxed command when the probe runs (the probe then says so) and any service in the allowed list.
- **Git residuals.** Any directory in a writable root that has no `.git` of its own, your existing
  subdirectories included, can be turned into a repository (a `HEAD`, `objects`, `refs` and `config`),
  and Git runs its configuration if you run Git inside that directory. Set
  `git config --global safe.bareRepository explicit`, which makes Git refuse such a repository unless you
  name it. Scripts that your hooks or your configuration run from the working tree (`.pre-commit-config.yaml`,
  `lefthook.yml`, a filter or `fsmonitor` script under the workspace) are ordinary files the session can
  change: review them before you commit. Your configuration is read without running Git, so a
  `core.hooksPath` or include written in a form that reading does not understand is not protected. A command can
  leave an interactive rebase or a cherry-pick in progress whose list holds `exec` lines: they run when
  you continue it, so do not continue an operation you did not start. Under Bubblewrap a command can make
  a new repository in a writable directory (existing ones are read-only); do not run Git inside one you
  did not make. Under Bubblewrap a `core.hooksPath` directory that does not exist yet in a writable
  directory refuses the session (it cannot be held read-only): create it first.
- **Tamper evidence has gaps.** Deleting a session's records together with their directory, deleting
  `journal.head` together with the last entries of its mission journal, deleting a mission journal and
  its `journal.head` together, or restoring an older matching pair, cannot be detected. A process
  running as you outside the sandbox can read the journal key and forge entries.
  The audit file for requests that name no known session (`logs/net-unattributed.jsonl`) has no reader
  in the API yet.
- **The verifier is another model.** A `finish` that passes the verifier has been checked against
  stored output, with its quotes compared byte for byte, but the verdict is still a model's judgement.
- **The web UI trusts the daemon.** It is served with a strict content-security policy and no inline
  script, but a bug in it would be a bug in a page that holds a bearer secret.
- **The operator's machine and account are trusted.** Another process of your user, or anyone who can
  read `~/.loom/token`, has the daemon's full power. Disk encryption, account separation and keeping the
  token file private are your job.

### Residual risks of the monitor (X1 to X17)

These hold once the monitor is built, and several hold before: where a risk depends on a phase, it says so. Each is
a place where the monitor does less than its description might suggest. `docs/MONITOR.md` §9.5 is the same list.

- **X1. LLM review is weak and attackable.** A capable agent that knows the protocol can write reasoning and outputs that pass the reviewer; in published work the strongest monitor passed 375 of 375 backdoors. Cross-family review reduces affinity bias but adds no robustness to injection. The deterministic floor and the tripwires are the boundary; the reviewer only raises the cost.
- **X2. Inside-scope harm through opaque HTTPS.** CONNECT tunnels are opaque (`loom_net::proxy`). Method, path and body of HTTPS requests to granted hosts are invisible except in arguments and referenced scripts. A compiled binary or runtime-built request can move value or reach users on a granted host before anyone sees it. G8 and the "opaque code" class cover the common shapes only. Closing this needs TLS termination with a loom CA for hosts marked real, which this design does not include.
- **X3. Target-side SSRF.** After a host is granted, the target can fetch anything on the agent's behalf. Only arguments reveal it.
- **X4. Domain fronting by Host header** inside a TLS session whose SNI matches a granted name, on CDNs that still route by Host. SNI binding does not stop it.
- **X5. Box and rootbox egress.** The box has per-destination counters but no per-connection record or content. The rootbox is shared by every mission and its egress is unlogged until it is isolated per mission (a prerequisite listed in §9.3); keep-going is refused for rootbox roles until then, but Duty W sees only command text there.
- **X6. Covert channels that carry no tool traffic:** steganography in prose, timing, file metadata in a shared workspace, and the blob existence oracle until the build that scopes stored outputs to the mission (#36) is the one that runs. The monitor watches channels, not meaning.
- **X7. Process identity.** It depends on a private macOS sandbox query, unprobed here. Where it fails, the census falls back to process groups and environments, which `env -i` and double forks defeat.
- **X8. Reviewer refusals and redaction gaps.** Providers may refuse offensive content (as one provider did during a published incident's forensics); a refusal is a missed detection, held as "not cleared" but not reviewed. Redaction is pattern- and index-based: unknown-format secrets and third-party PII can reach a reviewer whose recipient already receives that mission's data.
- **X9. Monitorability.** Reasoning need not reflect intent: models verbalised taught reward hacks under 2% of the time. The middle of very long reasoning is excerpted by content, not read in full. Profiles that emit no reasoning get action-only review.
- **X10. Keep-going still amplifies.** Every reopen adds up to `per_reopen` of exposure, and each reopen tells the agent that nothing so far was flagged at the blocking tier, a few bits of oracle per reopen. The caps bound this; nothing removes it.
- **X11. Alert fatigue and the operator's own click.**
  - Even tuned, the tripwires would have produced about 17 false pauses per 100 active hours on history before promotion rules. Shadow mode protects the agents' work, but the operator will see many shadow flags.
  - A habit of "mark false positive" can wave through a real request to a Docker host or another piece of infrastructure.
  - An approval from a phone remains the operator's act; annotations inform it but cannot stop it.
- **X12. The gap until deployment.** Until E1–E4 and the merged work they extend (#39 and #41) are in the build that **runs**, the routes they close stay open on the running daemon: a merge does not close them, a restart onto the new build does. Tripwires detect attempts but do not close them.
- **X13. A fleet without cross-family review.** A profile with no eligible reviewer (listed in `tripwires_only_profiles`) is watched by tripwires only, visibly and by recorded choice. Until the reviewer for `dsv41` (D2) is built and vetted (M6, M7), that includes the largest fleet.
- **X14. Lineage is declared, not verified.** A server-side weight swap behind a declared family, or a fine-tune of unknown data (inklingv5), defeats the family rule until the served model id changes and forces a re-vet.
- **X15. A compromised operator browser or daemon credential defeats every control.** E1 removes the known routes from agents to DevTools and the daemon. Any other route to the operator's logged-in browser or bearer token would let an agent act as the operator.
- **X16. The monitor is new code with authority to pause the fleet.** Bugs in it can stop authorized work (mitigated by shadow mode, tests and the monitor-down policy) or miss behaviour (mitigated by layering). It must itself be reviewed like any harness change.
- **X17. Same-family versus cross-family benefit is unmeasured in published work**. loom's own comparison (§8.3) is the evidence the operator will have, and it will rest on synthetic positives plus a small set of real incidents.

## Telemetry

loom makes no network requests of its own. Model requests go to the server in your configuration, and
tool traffic goes through the egress proxy under your `[network]` policy.
