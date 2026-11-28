# Running ferret

## Requirements

- Rust 1.88 or newer (`rust-version` in `Cargo.toml`) to build.
- macOS for the default Seatbelt sandbox, or Linux with `/usr/bin/bwrap` for `mode = "bubblewrap"`.
  Bubblewrap supports x86_64/aarch64 and deny-all command networking only; host proxy bridges and
  loopback/Unix socket exceptions are refused. Explicit `mode = "none"` leaves shell commands
  unconfined, including read-only verifier roles. Missing sandbox support never triggers a fallback.
- An OpenAI-compatible server with `/v1/chat/completions` (streaming) and, ideally, `/v1/models`.

## Build and install

```
cargo build --release -p ferret-daemon
```

The binary is `target/release/ferret`. Put it on your `PATH`, for example
`mkdir -p ~/.local/bin && install -m 755 target/release/ferret ~/.local/bin/ferret` (with `~/.local/bin` on
your `PATH`), or `/usr/local/bin`. `ferret up` starts the daemon by running the same binary again, so do
not move or replace it while the daemon runs without restarting the daemon.

`./x` is optional. It copies the tree to another machine and runs cargo there; the machine is named by
`FERRET_BUILD_HOST` (`FERRET_BUILD_HOST=local ./x ...` runs cargo here) and `FERRET_LANE` picks a separate
source copy on that host. `FERRET_BUILD_HOST` has no default: when it is unset, `./x` stops (exit 2) with
a message saying to set it (or run plain `cargo` directly). `./x --pull-bin` builds a release binary
and copies it to `./bin/ferret`. The desktop app is built with `gui/build.sh`, which also requires
`FERRET_BUILD_HOST` (a host, or `local`) and stops when it is unset.

Tests (the UI test needs Node.js 22.12 or newer: `ui/core.test.js` is an ES module with no
`package.json` beside it, which older releases may not load):

```
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
node --test ui/core.test.js
```

## Configure

The configuration is `~/.ferret/config.toml` (`FERRET_HOME` moves the whole `~/.ferret` directory). The
daemon reads it only when it starts: configure first, then start, and restart after any change —
except `[models]` and `default_model`, which `ferret models reload` applies to the running daemon.

```
ferret config init       # writes a starting file; refuses to overwrite an existing one
ferret config path       # prints the path
ferret config check      # validates syntax, keys, packs, sandbox preflight and box paths: "ok: <path>" (+ warnings), or error and exit 1
```

Edit `base_url` (the server's `/v1` URL) and `model` in the `[models.<name>]` table. If the server
serves one model, that model is used; if it serves several and `model` is not among them, the request
is a configuration error that lists the served ids. `docs/config.example.toml` names every key with its
default. Unknown keys are errors, so a typo does not go unnoticed. The values that matter first:

- `default_model`, and one `[models.<name>]` with `base_url`. `context_window` is discovered from the
  server when left out; if the server is unreachable (or reports none) and the profile sets none, a
  new session is refused with a sentence naming the URL.
- `retry_window_s` (default 300): how long a request keeps retrying an unreachable server. `0` retries
  until the server returns. A failure waiting cannot cure (a reply that is not an event stream, for
  example) ends the request after three attempts in a row whatever this is set to. A request still
  retrying after `[agents] unavailable_notice_s` (default 300; `0` = never) opens a non-blocking inbox
  item and notifies you; the item closes by itself when the request ends. A request whose window ends
  first opens none (it fails at its next failed attempt, and a failed step opens its own item), so
  with both at 300 the notice matters only for a longer window or `retry_window_s = 0`.
- `[context] compact_at_tokens` (default `0`): when a request reaches this many tokens, the session
  compacts the window (the model writes a note, the harness adds a key table for every stored output,
  and older turns leave the window while nothing is deleted). `0` means 40% of the model's context
  window, capped at 400,000 (100,000 when the window is unknown); a session clamps it to a smaller
  model window automatically. The legacy re-weave keys (`target_tokens`, `floor_tokens`,
  `keep_recent_steps`, `stub_tail_lines`) are deprecated and trigger a startup warning if set.
- An API key, when the server wants one: see *Model API keys* below.
- `[network] mode`: `deny_all` (the default), `allowlist` or `open`; see below.
- `[sandbox] protect_credentials` (default `true`): see below.
- `[tools] speculate` (default `true`): the leading read-only calls of a reply (`read`, `glob`, `grep`,
  `out_read`, `out_grep`) may start while the reply is still streaming. Results are recorded in call
  order and used only if the finished reply holds the same call. `false` runs calls only after the
  whole reply has arrived.
- `reasoning_effort` and the other `extra_body` fields are fixed for a session's life (the chat
  template may render them into the prompt head, so changing them mid-session would break the cache).

### Model API keys

Keep a hosted model's key in a file under the ferret home, which commands cannot read:

```
mkdir -p -m 700 ~/.ferret/keys/models
(umask 077; cat > ~/.ferret/keys/models/hosted)   # paste the key, press Return, then Ctrl-D
```

and name the file (not a path) in the profile:

```
[models.hosted]
base_url = "https://api.example.test/v1"
model = "some-model"
api_key_file = "hosted"
```

The file must be yours, a regular file (not a link) and mode 0600; white space around the key is
ignored. The daemon reads it once when it starts, and refuses to start, naming the profile and the file,
when it cannot use it. `ferret config check` reads it too.

`api_key_env = "VAR"` (the key in the variable `VAR` of the daemon's environment) still works, but every
process of yours, sandboxed commands included, can read the environment a process was started with, so
the key is readable by the commands the model runs. `ferret up`, `ferret config check` and the daemon's log
warn about each such profile, and `ferret service install` refuses it (a login service does not have your
shell's variables). To move a key that is exported in your shell, for example from `~/.zshrc`:

```
mkdir -p -m 700 ~/.ferret/keys/models
(umask 077; printenv VAR > ~/.ferret/keys/models/hosted)
```

then replace `api_key_env = "VAR"` with `api_key_file = "hosted"` in `[models.hosted]`, run
`ferret config check`, and restart the daemon (`ferret down`, then `ferret up`). Remove the export from your
shell's start files once no profile names it.

`ferret up` starts the daemon with only `PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`, `LANG`, `LC_*`, `TZ`,
`TMPDIR`, `FERRET_LOG`, `RUST_BACKTRACE`, the `api_key_env` variables of your profiles and the variables
listed in `[sandbox] env_pass`, so the rest of your shell's environment (tokens, cloud credentials,
proxy settings) does not reach the daemon or the commands it runs. List in `env_pass` a variable the
commands need, such as `JAVA_HOME`. Model requests ignore `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and
the system's proxy settings: they go to `base_url` only.

### Network

Commands and `web_fetch` reach hosts only through the daemon's egress proxy, which applies `[network]`:

| mode | reachable |
|---|---|
| `deny_all` (default) | no host. Model requests to your configured endpoint are not affected. |
| `allowlist` | hosts matching `allow` (`example.test`, `*.example.test`, optionally `:port`) |
| `open` | any public host |

`deny` entries (host patterns, IP addresses or CIDR blocks) are refused in every mode, and are matched
against the resolved address too. Private, loopback and link-local destinations are refused unless
listed in `allow_private`. Every decision is recorded in the session's audit log (`ferret net <session>`).
A pack that sets `requires_restricted_network` (`vr` does) is refused while the mode is `open`.

A session can also be given hosts by you while it runs. When it needs one it does not have, the agent
calls `request_scope`; an item naming the hosts and why waits in your inbox, and the session keeps
working. `ferret scope <session> <host>...` grants them (the UI and the app have an Approve button on the
item). `ferret scope revoke <session> <host>... [--note <text>] [--json]` revokes previously granted hosts
and immediately severs any matching live proxy tunnels (and re-syncs `[box]` egress rules). For an immediate
daemon-wide emergency halt, `ferret panic [--reason <text>] [--json]` (or the confirmed Panic button in the
web UI / `/panic` on Signal) severs all live proxy tunnels, disables all proxy rewrite rules, stops all active
sessions, and tears down all active `[box]` containers. The grant is recorded in the mission's ledger, applies
to that mission only, and ends with the session. `ferret net <session>` lists the hosts granted so far. Under `deny_all` a grant allows exactly the
granted hosts; the `allow` list stays off. `*`, a wildcard over a whole top-level domain (`*.com`) or
over IP addresses (`*.0.1`), the unspecified address (`0.0.0.0`, `::`) and a loopback address without a
port (`127.0.0.1`; write `127.0.0.1:8080`) cannot be requested or granted: name the hosts, or a wildcard
under a domain (`*.example.test`), or set the mode in the config.

Each session's commands reach the proxy on a port of that session's own, and the proxy accepts a
session's credentials only on that port and never connects to its own ports, so a command that reads
another session's proxy credentials (from the environment another command was started with) cannot use
them. A session's port is never given to another session while the daemon runs.
`loopback_all = true` lets commands connect to every port, these included: see `SECURITY.md`.

### Sandbox

With `[sandbox] mode = "seatbelt"` (the default) commands run under a macOS sandbox profile:

- they can write only in the workspace, the session's temp directory, `extra_writable`, and
  the device files `/dev/null`, `/dev/tty` and `/dev/dtracehelper`;
- `~/.ferret`, `<workspace>/.ferret` and `protected_paths` are never writable, with one exception: the
  session's temp directory is `~/.ferret/sessions/<id>/tmp`, and everything inside it is writable (the
  directory entry itself cannot be removed, renamed or replaced);
- the whole ferret home (`~/.ferret`: logs, records, stored outputs, missions, configuration, packs, token and keys) is
  not readable by commands (and not by the file tools, in every mode), except the session's temp directory and
  the harness's `analysis` staging directory (a replay: its staged workspace and temp instead); the home and the
  directories down to the temp dir can be looked up (`stat`, `cd`) but not listed, and the names under the home
  are hidden. A command's own output file is in `~/.ferret/sessions/<id>/jobs`: its metadata can be read, nothing
  else, so output works but cannot be read back from a command. A workspace inside `~/.ferret` is refused at
  start. `unreadable_paths` are neither readable nor writable;
- no network except the egress proxy (plus `loopback_ports`, `loopback_all`, `unix_sockets`);
- no LaunchServices opens, Apple Events or launchd jobs.

Git config/hooks and metadata pointers are protected, including existing nested repositories and
linked worktrees. Normal source edits still work. Commands that explicitly write shared `/tmp` or
`/private/var/folders` must use `$TMPDIR` instead; a read-only verifier can write only its own session
temp and device files. Other readable files remain untrusted inputs.

Linux `mode = "bubblewrap"` uses a read-only host tree, private temp/run mounts, hidden credential
stores, and a seccomp socket deny policy. The original user home (when protecting credentials),
Ferret home, and workspace `.ferret` are hidden by private mounts; scoped workspace/temp roots are
restored from pinned descriptors. Create workspace `.ferret` first. Missing explicit unreadable
paths outside hidden parents are refused, and the whole user home cannot be a writable root. Bind sources are pinned by harness descriptors; missing protected paths under writable roots must
exist first (including the reserved workspace `.ferret` directory). Existing Git directories are entirely read-only there;
future repositories must be created by the operator outside the session. It has no shell egress
proxy bridge: use `network.mode = "deny_all"` with no active grants or socket exceptions. In-process
reference GET tools may use `reference_hosts`; the shell cannot use their separate credential.

`network.reference_hosts = ["docs.rs:443"]` enables a separate in-process reference GET capability.
Raw proxy access to those names is refused even under open mode or explicit grants. Do not treat
GET-only requests or stripped auth headers as an exfiltration guarantee: URL paths/queries can carry
secrets, and host-pattern rules do not identify every alias or tenant of a shared service.

Other files are readable.

`protect_credentials = true` (the default) also makes these unreadable and unwritable to commands and
file tools: `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gh`, `~/.config/gcloud`, `~/.azure`, `~/.kube`,
`~/.docker/config.json`, `~/.netrc`, `~/.npmrc`, `~/.pypirc`, `~/.cargo/credentials(.toml)`,
`~/.git-credentials`, `~/.config/git/credentials`, `~/.password-store`, `~/.config/op`,
`~/Library/Keychains`, `~/Library/Cookies`, the profile directories of Chrome, Chromium, Brave, Edge,
Arc, Vivaldi, Opera, Firefox and Safari, and many more: model-hub, AI-tool, database, cloud, registry,
password-manager, wallet and chat stores (`~/.cache/huggingface`, `~/.claude.json`, `~/.pgpass`,
`~/.vault-token`, `~/.m2/settings.xml`, `~/.config/rclone`, `~/Library/Mail`, ...; the list is in
`docs/DESIGN.md`). Add other stores to `unreadable_paths`. A
listed directory that is or contains the workspace is skipped. This needs a home directory: with
`HOME` unset, every session fails to build its sandbox and the message names `HOME` and
`protect_credentials = false`. Set the key to `false` to turn the protection off.

Several of these are whole directories, so what else they hold is off limits too: commands cannot load
models from the Hugging Face cache in `~/.cache/huggingface/hub` (set `HF_HUB_CACHE` to a directory
elsewhere; moving `HF_HOME` moves the token out of protection too), or use Terraform's plugin cache in
`~/.terraform.d`. (`~/.fly` and `~/.pulumi` are protected as their credential files only,
`~/.fly/config.yml` and `~/.pulumi/credentials.json`, so `flyctl` and `pulumi` can run from their `bin`
directories, which installers put on `PATH`: a hidden name on `PATH` makes Node stop its search with EPERM.) The only switch is `protect_credentials = false`, which lifts the protection of every
store.

Environment variables whose names look like secrets (in any case: containing `KEY`, `TOKEN`, `SECRET`,
`PASSWORD`, `PASSWD`, `PASSPHRASE`, `CREDENTIAL` or `COOKIE`, ending in `_PAT`, `_DSN`, `_PWD` or `_PW`,
`DATABASE_URL`, `SSH_AUTH_SOCK`, anything starting `FERRET_`, names with `SESSION`, `AUTH`, `PASS`, `JWT` or
`WEBHOOK` as an `_`-delimited word or with `PRIVATE`, the `api_key_env` of any model profile, and any
variable whose value holds a URL with a password in it) are not passed to commands unless listed in
`env_pass`.

## Using MCP servers

An MCP server gives the model more tools. Each tool shows up as `mcp__{server}__{tool}` and its result is
stored like any other output (you can `read` and `grep` it, quote it as evidence, and the verifier can read it).
Add servers under `[mcp.servers.NAME]` and restart the daemon:

```toml
[mcp]
max_schema_tokens = 20000   # per role: MCP tool definitions beyond this are left out
idle_close_s = 600

# A local program, run inside the session's sandbox.
[mcp.servers.github]
command = ["npx", "-y", "@modelcontextprotocol/server-github"]
env = { GITHUB_PERSONAL_ACCESS_TOKEN = "env:GITHUB_PAT" }   # read from the daemon's environment
hosts = ["api.github.com"]            # the sandbox can reach these while the server is configured
tools = ["search_issues", "get_issue"]

# A remote server, reached through the session's egress proxy.
[mcp.servers.docs]
url = "https://mcp.example.com/mcp"
headers = { Authorization = "file:/home/me/.docs-mcp-token" }
hosts = ["mcp.example.com"]
read_only = true                      # the verifier gets its tools too
```

Prefer `env:NAME` or `file:/path` for secrets: a literal in the file makes the daemon warn at start, `file:`
paths must be regular `0600` files owned by you (no symlinks), and secret values are redacted before wire
capture or logs. HTTP MCP server `hosts` stay isolated to that MCP server's transport rather than widening
the session's general `bash`/`web_fetch` egress scope. Set `pinned_schema_sha256` (64 hex chars) to pin a
server's tool schemas against rug-pulls; `trust_read_only_hints` defaults to `false` so servers cannot
self-declare tools as read-only unless you explicitly opt in.

```
ferret mcp list                                   # the configured servers, transport and roles
ferret mcp check github --workspace ~/work/repo   # start it for that workspace, list its tools, close it
```

`ferret mcp check` prints the tools or the error with the server's last stderr lines. A mission lists its servers
once, when its lead starts; to pick up a changed server, start a new mission. The Session view of the API
(`GET /api/sessions/{id}/mcp`) shows each server's state.

## A box

`[box]` gives the agent a place to run what the local sandbox cannot (raw TCP to a target, heavy
tooling) without giving it Docker. Each mission gets one container on a Docker host that you set up;
the tools `box_exec`, `box_get` and `box_reset` are the whole interface, and the `ctf` solver roles
have them. The daemon, not the agent, talks to Docker.

Set up the host once:

1. Use a **dedicated Linux VM** that runs Docker and nothing you care about (a KVM guest is fine).
   Give it an `ssh_config` alias that works without a prompt from the daemon's account, for example
   `Host ferret-box` with its `HostName`, `User`, `IdentityFile` and, when the VM is behind another
   machine, `ProxyJump`. Test it: `ssh ferret-box docker version`.
2. Set `ssh_host = "ferret-box"` and `remote_socket = "/var/run/docker.sock"` (the socket inside the VM).
   ferret forwards it to `~/.ferret/keys/box.sock`, which commands cannot read. Or set `docker_socket` to a
   socket on this machine instead.
3. Pick two images and pin them by digest (`name@sha256:...`; tags are refused): `image`, the box
   itself (the tools you want, with `bash`; it runs as user 1000), and `helper_image`, a small image
   with `sh`, `iptables`, `iptables-restore` and `ip6tables` (the alpine `iptables` package has all of
   them) that ferret runs with `NET_ADMIN` on the host network to install the per-mission egress rules. The
   Docker VM's kernel must have the iptables and ip6tables filter tables.
4. Set `enabled = true`.

What the box can reach is the mission's grants: exact hosts and IP addresses given with
`request_scope` and approved, with an optional `:port`. Wildcard grants are not applied (the first
`box_exec` of a session says so). The daemon resolves names, applies the `[network]` policy to the
addresses (private addresses need `allow_private`), passes the names that resolved to `docker run` as
`--add-host` (the container's root is read-only, so Docker writes its `/etc/hosts` at creation), and writes the
result into rules on the Docker VM (chain `FERRET-<id>`); everything else, including DNS and IPv6
(`FERRET-ALL6`), is dropped. `INPUT -i fb-+` unconditionally `DROP`s container-to-host traffic while
`DOCKER-USER` sends forwarded traffic from a box bridge (`fb-*`) to `FERRET-ALL`, which holds one jump per
mission and ends with `DROP`: a box bridge without its own chain is dropped, never routed or translated.
The Docker host must not have other interfaces named `fb-*`: they are dropped by `FERRET-ALL`. A revoked
grant cuts open flows at once (the mission chain has no rule for established traffic). A name granted
after the box exists is reachable by address at once but resolves inside the box only after `box_reset`
(which wipes `/work`); until then each `box_exec` result carries a line that says so.
ferret checks a running box's rules about once a minute and puts them back if they are gone; if that fails
twice it pauses the box (keeping `/work`), refuses the command, and resumes the box when a later check
works. A new grant, a revocation, a release, a panic stop, and the end of the mission update or remove the rules.
The box runs with a hardened default-deny seccomp profile, bounded `noexec` `/dev/shm`, no other mounts, no
devices, all capabilities dropped except the tight `cap_add` allowlist (`NET_RAW`, `NET_BIND_SERVICE` only),
a read-only root, and tmpfs `/work`
and `/tmp` (both executable): files in it are lost when the mission ends or on `box_reset`. The image
needs `/bin/sh`, `/bin/bash`, `setsid` (util-linux) and `/usr/bin/tar` (GNU tar, or one that supports
`--format=pax`); Docker supplies the init. Files go in and out through `docker exec ... tar` as user 1000, not
`docker cp`, which cannot write to a read-only root or see the tmpfs `/work`.

Notes. The box needs the OS sandbox: `[sandbox] mode = "none"` and a `sandbox.unix_sockets` entry that
names the box's socket (or anything in `<ferret home>/keys`) are refused. `docker_cli` and `ssh` are looked
up on the daemon's `PATH` once, at start; the docker client runs with a fixed `PATH` and an empty
`HOME`/`DOCKER_CONFIG` of its own (`<ferret home>/keys/box-docker`), so your docker configuration and
credential helpers are not used. Commands in the box run as user 1000 with `no-new-privileges`, so
`cap_add` gives them no capabilities; it matters only for root processes in the image. A mission that is
stopped, ended or archived has its box removed and gets none until its lead is resumed. After a daemon
restart a box job that was running is still listed, but `job_kill` stops only the local client, not the
command in the container (the remote stop is not kept with the job record): `box_reset` stops it.

**Also protect the host from the VM.** ferret's rules cover only the boxes it makes. As a second layer
that does not depend on ferret, configure the VM's *host* (the machine that runs the hypervisor) to block
the VM from reaching the host itself and every private range (RFC 1918, link-local, your management
network), allowing only the addresses the VM needs (its DNS or package mirror if any, and the
targets). A container escape or a bug in the rules should then still end at a VM that cannot see
anything else.

## Signal

`[signal]` connects `ferret daemon` natively to a local `signal-cli daemon --http` instance (outbound
JSON-RPC `/api/v1/rpc`, inbound SSE `/api/v1/events`) so alerts land on your phone and you can answer
or steer missions directly from Signal. It is off by default.

### Setup

1. Install `signal-cli` and register or link an account. You can use either a **dedicated bot number**
   (cleanest separation: alerts arrive in a normal DM from the bot) or your **own number in Note-to-Self
   mode** (single number; set `recipient` equal to `account`).
2. Start `signal-cli` bound to loopback only (never expose its HTTP port on a public interface):

   ```
   signal-cli -a +15550100 daemon --http=127.0.0.1:1337
   ```

3. Add `[signal]` to `~/.ferret/config.toml` (all keys are listed in `docs/config.example.toml`):

   ```toml
   [signal]
   enabled = true
   http_url = "http://127.0.0.1:1337"
   account = "+15550100"           # your registered signal-cli account (E.164)
   recipient = "+15550199"         # your phone E.164, Signal ACI UUID, or "group:<groupId>"
   allow_from = ["+15550199"]      # required, non-empty, "*" refused (E.164 or Signal UUIDs)
   # allow_groups = ["<groupId>"]  # optional; raw id or "group:<id>" (group recipient added automatically)
   # events = ["blocker", "question", "approval", "parked", "finished", "error", "disk"]
   # max_chars = 3500              # 200..=7500
   # inbox_delay_secs = 0          # 0..=86400; e.g. 600 = wait 10 min before buzzing for open inbox items
   ```

   Plaintext `http://` is restricted to loopback addresses (`127.0.0.1`, `localhost`, `[::1]`; remote URLs must
   use `https://`). When `inbox_delay_secs > 0`, outbound alerts for inbox items (`blocker`, `question`,
   `approval`, `parked`) wait until the item has remained open for that many seconds (including across daemon
   restarts); if you answer, approve, or dismiss it at the computer first, no Signal alert is sent. `finished`,
   `error`, `disk`, guest alerts, and direct command replies are always sent immediately.
   For Note-to-Self mode, set `recipient = "+15550100"` and `allow_from = ["+15550100"]`. Unanswered
   blocking reminders follow `[notify] repeat_minutes` (default `0`, off) and open blocking items are
   re-notified after a daemon restart; add `"disk"` to `events` to receive low-disk warnings on Signal.
4. Check the configuration, restart the daemon (`ferret down`, then `ferret up`), and test delivery:

   ```
   ferret config check
   ferret signal check
   ferret signal test
   ```

   `ferret status` also reports live Signal bridge connection state and any recent errors while `[signal]`
   is enabled.

### Phone Number Privacy (UUID / ACI discovery)

When Signal's Phone Number Privacy hides your phone number, inbound messages may carry only your Signal
ACI UUID (`sourceUuid`) without `sourceNumber`. If `allow_from` lists only an E.164 number and
`signal-cli` has not mapped that UUID yet, inbound replies are dropped as unauthorized (logged at `warn`).

To discover your ACI UUID:

1. Send a message from your phone to the `signal-cli` account (or open Note-to-Self).
2. Query `signal-cli` for known contacts and recipients:

   ```
   signal-cli -a +15550100 listContacts --all-recipients
   ```

   Look for the `uuid` / `aci` field (e.g. `00000000-0000-4000-8000-000000000001`).
3. Put that UUID in `recipient` (if needed) and in `allow_from` (plain `<uuid>`, `u:<uuid>`, or
   `PNI:<uuid>` are all accepted). Including both your E.164 number and your ACI UUID in `allow_from`
   ensures replies are accepted whether or not Signal reveals your number.

### Troubleshooting `UNTRUSTED_IDENTITY` (safety numbers)

If you reinstall Signal or switch devices, Signal changes your safety number and `ferret signal test` (or
outbound alerts) will fail with `UNTRUSTED_IDENTITY`. To trust the updated identity:

1. Inspect the pending identity key:

   ```
   signal-cli -a +15550100 listIdentities
   ```

2. Verify the safety number on your phone (Chat settings → View safety number), then trust it:

   ```
   signal-cli -a +15550100 trust -v "<safety-number>" +15550199
   ```

   (Or for your own number when you know you just re-linked, `signal-cli -a +15550100 trust -a +15550199`;
   use your ACI UUID instead of `+15550199` under Phone Number Privacy.)
3. Confirm delivery with `ferret signal test`.

### Replying and slash commands

- **Quote-reply** to an alert to answer that exact inbox item (option numbers `1..N` expand to the option
  text), grant or deny a `request_scope` approval (`approve`/`yes`/`all`, host numbers such as `1 2`, or
  `deny`/`no`/`dismiss`), or send a follow-up message to a finished/errored mission. Sent message mappings
  persist across daemon restarts in `~/.ferret/signal_sent.json` (mode `0600`).
- **Plain reply** (in a direct message, never in a group) answers the sole open blocking item directly.
- **`@<id> <text>`** answers an open inbox item or messages a mission by ID prefix/suffix (or short `#n`
  index shown by `/inbox` and `/status`).
- **Slash commands:** `/inbox`, `/status`, `/tail [id|#n] [count]`, `/scope <id|#n> [host...]`,
  `/scope revoke <id|#n> <host>...`, `/panic [reason]`, `/dismiss [id|#n]`, `/stop [id|#n]`,
  `/resume [id|#n]`, `/approve <id|#n> <text>`, `/rule <id|#n> <text>`, `/release <id|#n> <reason>`,
  `/mute [15m|2h|off]`, `/unmute`, and `/help` (`/start`).
  When `[signal.guests]` is enabled, operators also have `/guests` and `/guest approve|revoke|block|unblock|clear|say`.

### Guest chat and unknown-sender gatekeeper

`[signal.guests]` (off by default) lets non-operator direct messages be handled safely without ever
exposing operator missions, files, tools, or commands:

```toml
[signal.guests]
enabled = true
owner_name = "Jordan"
# allow = ["+15550101", "00000000-0000-4000-8000-000000000001"]  # optional static pre-approved guests
# model = "local"                                                # optional [models.*] profile for guests
# persona = "Keep answers brief and friendly."
# triage_notes = true                                            # zero-tool LLM triage on incoming guest notes
# triage_model = "local"                                         # optional profile override for note triage
# action_workspace = "~/ferret-assistant"                        # workspace outside ~/.ferret for confirmed "do" tasks
# action_pack = "core"                                           # pack used for confirmed note action missions
```

- **Fail-closed & DM-only:** When disabled, non-operator messages are silently dropped. Even when enabled,
  non-operator group messages are always silently dropped.
- **Unknown DM gatekeeper (zero LLM calls):** Blocked senders are silently ignored. First-time unknown DM
  senders receive the fixed `unknown_reply` (rate-limited per sender by `unknown_cooldown_hours`, default
  `24`) and, when `notify_owner_on_unknown = true`, trigger a quote-replyable `[Ferret · NEW CONTACT]`
  alert to `signal.recipient`. Quote-reply `"approve"` (or `"approve <nickname>"`) to allow them and send a
  welcome DM, or `"block"` / `"deny"` to silence future messages.
- **Strict isolation for approved guests:** Approved guests (from static `allow` or owner approval) talk to
  an isolated LLM completion path with an immutable safety preamble, zero host/file/mission/mail/operator
  tools, per-guest rolling history in `~/.ferret/signal_guests.json` (mode `0600`), hourly message limits
  (`rate_limit_per_hour`), and a per-guest single-flight guard so guest replies never block operator commands.
- **Guest commands, note triage & confirm-to-run actions:** Guests may only use `/help`, `/reset` (`/clear`),
  and `/note <message>` (when `allow_notes = true`, capped at 500 characters and 3 notes per 15 minutes; the
  model may also call `leave_note_for_owner` under the same cap). When `triage_notes = true` (default),
  incoming notes are triaged asynchronously by a zero-tool LLM (`triage_model` → `model` → `default_model`)
  with the local date/time and persisted in `~/.ferret/signal_guests.json` (bounded 100-note ring, mode
  `0600`; triage failures gracefully fall back to plain note delivery so notes are never dropped). Nothing
  runs automatically — the owner receives `[Ferret · GUEST NOTE · g-N · n-M from <name>]` and controls what
  happens by quote-replying:
  - `"do"` or `"do <extra>"` — spawns a Ferret mission in `action_workspace` (pack `action_pack`; refused
    if inside `~/.ferret`) with the owner-confirmed task, optional extra instructions, and the verbatim guest
    note framed as untrusted reference context (protected against duplicate execution).
  - `"do + reply"` (or `"do+reply"` / `"do and reply"`) — spawns the mission and sends the suggested reply
    back to the guest.
  - `"reply"` — sends only the suggested reply to the guest without spawning a mission.
  - Any other text (including phrases like `"don't worry, see you then"`) — relayed verbatim directly to the
    guest without invoking an LLM.
- **Owner guest commands:** `/guests` (lists approved, pending, and blocked contacts with `#1..#N` aliases),
  `/guest approve <id|#n|e164|uuid> [name]`, `/guest revoke <id|#n|name>`, `/guest block <id|#n|name>`,
  `/guest unblock <id|#n>`, `/guest clear <id|#n|name>`, and `/guest say <id|#n|name> <message>`.

## Start

```
ferret up                # start the daemon in the background; log: ~/.ferret/logs/ferretd.log
ferret daemon            # or run it in the foreground
ferret status            # the daemon, each model server and whether it answered, what is running, free disk space
ferret down              # stop it; sessions resume when it starts again
```

The first start creates `~/.ferret/token` (the API token, mode 0600). `FERRET_LOG` sets the log level
(default `info`). A second daemon on the same home is refused.

`ferret status` (pass `--json` for raw JSON) lists each configured model profile with ✓ or ✗ (whether it
answered a request for its models just now, placing any failure detail uncut on the next line). The model
and window it prints come from the config until a session of that profile has been created since the
daemon started (`window unknown` when `context_window` is not set); from then on they are the model id
the server serves and the window it reported. When `[signal]` is enabled it also shows live Signal bridge
health (connected/error/muted/pending), and it prints the free space on the volume of the ferret home and
warns when it is under 5 GiB or 5 percent.

On macOS `ferret service install` makes the daemon a login service (a LaunchAgent) and
`ferret service uninstall` removes it; `ferret service status` says whether it is loaded.

If an older ferret's daemon is still running after an upgrade, the new client will not send it the token
(it cannot prove its identity). Run `ferret --unverified-daemon down`, then `ferret up`.

## A mission

```
ferret run -w /path/to/workspace "the task, in plain words"
```

`run` starts a lead session whose workspace is the `-w` / `--workspace` directory (without it, the
current directory; `~` and `~/x` mean your home directory). A workspace that does not exist is refused
with a sentence saying so; add `--create-workspace` to make it (and the folders above it that are missing),
and `run` prints `created workspace <path>` before the session id. A path inside the ferret home (or a
non-absolute path sent directly to the API) is refused either way. By default `run` follows the session's
record on the terminal (pass `-d` / `--detach` to start it and return immediately). Everything after the options is the task;
`-` or no words reads it from standard input. The lead owns a mission ledger (goal, constraints,
plan, claims with evidence), may delegate to workers and have a verifier attack its `finish`, and
stops only through a terminating tool. Ctrl-C stops following, not the session.

A mission that goes back to a target an earlier mission worked on can start from what that mission
recorded: `--prior <mission>` (repeat it, at most 8) names earlier missions for this one to recall. A
mission is its id (`m-…`) or any session of it, written as elsewhere (an id, the beginning of one, or
`last`; `ferret ls` lists them).

```
ferret run -w /path/to/workspace --prior m-0abc… "the task"
```

Before its first model request the new lead gets one note with, per named mission, its title and when its
ledger was last written; the goal, rules and answers you gave it (marked as your words from an earlier
mission); its goal status; where its work stood when it ended (claims, plan, dead ends — marked as written
by the model there and not verified); and its security record as counts and asset locators (no
credentials, no identities by name, no query strings in a locator). Your own words are shown exactly as you
wrote them; what the model wrote is shown with URL queries, fragments and passwords removed, but may still hold
whatever else the model wrote there. The source is each mission's sealed ledger; a ledger that fails
verification or was written by a newer ferret is named as unreadable and nothing from it is shown. Nothing
else carries over: the earlier mission's stored outputs cannot be opened from the new one, and its
approvals and network grants do not apply.

### A target

Missions that work on the same thing can share a scope and what they found:

```
ferret target add acme --scope acme.test --scope '*.acme.test' --scope 10.20.0.0/24 --exclude vpn.acme.test
ferret run -w /path/to/workspace --target acme "map the API and test the login"
ferret target show acme --nodes
```

The scope is reachable from the mission even with `network.mode = "deny_all"`; the excluded entries never
are. The lead starts with a `# Target acme` section (scope, untested services and endpoints, findings) and
the next mission against `acme` sees what the earlier ones tested. `ferret target scope acme --add HOST
--remove HOST --exclude HOST` edits it; the target's files are under `~/.ferret/targets/acme/`.

Exit status of `run` and `send`: 0 after `Finished` or `Yielded`; 2 when you are needed (`Asked`,
`Blocked`, `Parked`: the inbox item was printed); 1 after `Stopped`, `BudgetExhausted` or an error.

## Commands

| command | does |
|---|---|
| `ferret daemon` / `up` / `down` | run the daemon in the foreground / in the background / stop it |
| `ferret status [--json]` | the daemon, each model profile and whether its server answered, live Signal bridge state, counts, free disk space |
| `ferret open [--print]` | open the web UI in the browser (`--print` prints the address instead) |
| `ferret run [options] [--file PATH]... <task...>` | start a session and follow it; `-d` starts it and returns; `--file` attaches files (the workspace must already exist) |
| `ferret chat [options]` | turn-by-turn `chat` session; `--session <id>` continues one (reprinting recent context); `/quit` leaves |
| `ferret ls [-a] [--wide] [--json]` (alias `list`) | list sessions with mission IDs (`-a`: archived too; `--wide`: add pack and workspace columns) |
| `ferret tail <session> [--since <seq> \| -n/--last <N>] [--no-follow] [--no-exchanges] [--json/--jsonl]` | print a session's record and follow it (`-n` shows the last `N` records; `-v` prints `#seq` numbers; `--json` emits JSONL) |
| `ferret send <session> [text...] [--file PATH]... [--after-turn] [-d]` | add a message to a running or idle session (`-d` returns at once; `--after-turn` queues it until the current turn ends); each `--file` is uploaded and attached |
| `ferret queued list\|edit\|send\|rm <session> ...` | inspect (`list`/`ls`, `--json`), edit (`edit <session> <qid> <text...>`), deliver now (`send <session> <qid>`), or remove (`rm`/`remove`/`delete <session> <qid>`) messages queued with `send --after-turn` |
| `ferret stop <session>` / `resume <session>` | stop the turn, its jobs and agents / let a stopped session carry on |
| `ferret compact <session>` (alias `reweave`) | compact the context now: the model writes a note, old output stays readable by key |
| `ferret archive <session> [--undo]` | hide a finished session (or restore with `--undo`); archiving settles the mission's agents |
| `ferret rename <session> <title...>` | rename a mission (its lead's title) |
| `ferret rule <session> <text...>` | set a standing rule (a ledger constraint) for the mission |
| `ferret rule <session> --withdraw <rule-id> [--reason <text>]` | withdraw a rule |
| `ferret approve <session> <text...> [--scope <text>]` | record an approval |
| `ferret scope <session> <host>... [--note <text>] [--json]` | let the mission's tools reach these hosts (one host per argument) |
| `ferret scope revoke <session> <host>... [--note <text>] [--json]` | revoke previously granted hosts and immediately cut matching live proxy tunnels |
| `ferret panic [--reason <text>] [--json]` | emergency kill-switch: sever all proxy tunnels, stop all active sessions, tear down active boxes, and disable all rewrite rules |
| `ferret release <session> <reason...>` | accept a blocked mission as it is and close it: "closed by operator, goal not established" |
| `ferret inbox [--json]` | list questions, approvals, scope requests and blockers waiting for you |
| `ferret answer <item> [text... \| --dismiss]` | answer or dismiss an inbox item (`<item>`: id, prefix, unique 4+ char suffix, `last`, or `.` for the sole waiting item; bare `1..N` selects a numbered option; reads piped stdin when `text` is omitted; `--dismiss` or empty on TTY dismisses non-blocking items) |
| `ferret ledger <session\|mission> [--json]` | print the mission ledger |
| `ferret findings <session\|mission> [-a/--all] [--severity <level>] [--json]` | show a mission's structured security findings and surface coverage (`-a`: include withdrawn; `--severity`: `critical\|high\|medium\|low\|info`) |
| `ferret sarif <session\|mission> [-o <path>] [--include-secrets] [--repo-name ...] [--repo-uri ...] [--commit ...] [--branch ...] [--git-ref ...]` | export active findings and coverage provenance as SARIF 2.1.0 (secrets redacted by default; pass `--include-secrets` to opt out) |
| `ferret traffic <session> [--host <host>] [--after <seq>] [-n <limit>] [--json]` (alias `exchanges`) | inspect captured HTTP exchanges for a session (`--target <name> [--node <node>]` inspects across all missions of a target instead) |
| `ferret har export <session\|mission> [-o <path>] [--host <host>] [--limit <N>] [--include-secrets]` | export captured HTTP exchanges as HAR 1.2 JSON (sanitized by default; pass `--include-secrets` to opt out) |
| `ferret har import <session\|mission> <file.har>` | import a HAR 1.2 file into a mission's traffic log (idempotent) |
| `ferret rewrite list\|add\|enable\|disable\|rm\|example` | manage operator-only proxy rewrite rules (`list`/`ls` supports `--json`; `example` prints a JSON template for `add <file>`; `rm`/`remove`/`delete`) |
| `ferret mail check` | verify `[mail]` configuration, credentials, read-only mailbox access, and sender allowlist |
| `ferret signal check` / `signal test [message...]` | verify `[signal]` config, `signal-cli` health, account registration and daemon bridge status / send a test message |
| `ferret packs [--json]` (alias `pack`) | list installed packs and their roles |
| `ferret score <session\|mission> [--json]` | what the mission's work took: steps, malformed calls, refused finishes and quotes, verifier verdicts, fresh starts, `hand_off` and `ask_for` uses |
| `ferret window <session> [--json]` | what is in the model's context, and what was folded out |
| `ferret net <session> [-n <limit>] [--json]` / `ferret net --noise [--json]` | network decisions and granted hosts for a session, or (`--noise`) live egress noise-governor status |
| `ferret out <handle> [--lines a:b]` | print a stored tool output |
| `ferret target list\|add\|show\|scope` | manage shared target scopes and graphs (`list`/`ls` `--json`; `show <name> [--nodes [--status S] [--kind K] [--under LOC]] [--json]`) |
| `ferret creds list\|show\|record\|set\|rm <target> [--profile <name>]` | manage target credential profiles (accepts positional `<target>` or `--target <name>`; `--json` on `list`/`show`; `list` alias `ls`, `rm` aliases `remove`/`delete`) |
| `ferret ca show` / `ca rotate` | print the HTTPS interception CA certificate path and SHA-256 fingerprint, or rotate the CA |
| `ferret gc [--apply]` | delete stored outputs that nothing refers to (dry run unless `--apply`) |
| `ferret config path` / `check` / `init` | the configuration file |
| `ferret models list [--json]` (alias `ls`) | the model profiles in use (the default marked), each server ✓/✗ |
| `ferret models reload` | read `[models]` and `default_model` from the config again and use them now, without a restart; sessions on a changed profile move to its new settings |
| `ferret models set <session> <profile>` | switch a session (lead or agent) to another model profile from its next step, without a restart; logged as `model_switched` |
| `ferret models show <session> [--json]` | a mission's models: the lead's, the choice for each role of its agents (or what the pack picks), the agents running and their models |
| `ferret models role <session> <role> <profile> [--now]` | start the mission's new agents of `role` (`all`: every role without a choice of its own, not the finish gate's verifier) on `profile`; `--now` also moves its running agents of that role (not forked ones) |
| `ferret models role <session> <role> --clear` | drop that choice: the pack picks again for agents started later |
| `ferret mcp list` (alias `ls`) / `mcp check <server> [--workspace <dir>]` | list configured MCP servers / start one in a scratch sandbox and list its tools |
| `ferret service install` / `uninstall` / `status` | the macOS login service |

Options of `run` and `chat`: `-w/--workspace`, `--create-workspace` (cannot be combined with `--file`),
`--pack`, `--role`, `-m/--model` (a profile name),
`--agent-model ROLE=PROFILE` (repeatable; `all=PROFILE` for every role: the mission's agents start on
it from the first one, as `ferret models role` sets later),
`-t/--title`, `--attended` (do not resume by itself after a restart), `--max-steps`, `--max-minutes`,
`--prior <mission>` (repeatable: earlier missions to recall; not with `chat --session`, which continues a
mission that has already started), `--target <name>`, `--creds <profile>` (requires `--target`),
`--no-intercept` (disable HTTPS interception when `[network] intercept = "pack"`);
and for display `--reasoning`, `--full`, `-v` (includes `#seq` record numbers), `--no-exchanges`.
A `<session>` is an id, a prefix, a unique 4+ character suffix, or `last` (and commands accepting a
`<mission>` also resolve `m-` prefixes/suffixes). `-` as the text reads standard input.
Environment variables: `FERRET_HOME` (default `~/.ferret`), `NO_COLOR`, `COLUMNS` (non-TTY pipes are not
truncated unless set), and `FERRET_LOG` (default `info`). Exit codes: `0` success/finished/yielded, `1`
error/stopped/budget exhausted, `2` waiting on operator (`Asked`/`Blocked`/`Parked`), `130` Ctrl-C while
following (session keeps running).

`rule`, `approve` and `answer` are the ways to steer a running mission. A child's session id reaches
its lead. The command prints `rule sent to <lead>` when the lead records it at once, or `... queued ...`
when the lead is in a turn: it records the input at its next step, not while a tool call is running.
Queued inputs are kept on disk (`queued/` in the session directory) until recorded, and survive a
daemon restart. A mission whose lead keeps no ledger (the `chat` role, for example) takes rules and
approvals only as notes without an id, which cannot be withdrawn by id. Withdrawing an unknown rule id
is refused by the daemon when the mission has a ledger.

### Answering a blocked session

A blocker or a used-up budget waits for you. In the UI and the app the item offers choices, cheapest
first: "Keep working" (the default), "Keep working (more budget)" where a budget ran out, "Provide
what's missing" for a blocker, and "Accept as blocked and close". Closing needs a reason you type and
is recorded as `closed by operator, goal not established`; it is never shown as finished. From the
terminal, `ferret answer <item> <text...>` keeps it working and `ferret release <session> <reason...>`
closes it.

When you answer, point at the next step instead of asking a yes/no question. "Is it blocked?" invites
"yes". "Run the build with the staging config, then read the first failure" gives it something to do.
A verifier that rejects a finish no longer parks the session on you: the agent gets the objection and
continues. By default it continues from a fresh start: the goal is open again and its context is folded,
so that it works from what the verifier found and not from its own account of the attempt (see Packs,
below).

`ferret score <session>` counts what a mission's work took, from its logs: one row per session (the lead,
then its agents and verifiers) and a total. `steps` and `to finish` (steps up to the delivered finish,
`-` when there was none), `calls` and how many were `malformed` (cut short or refused as invalid),
`finish refused` (of how many finish calls), `quote refused` (a finish or an evidence record whose
quote did not check), `verifier` (finishes accepted, of those a verifier judged), `fresh starts`, and how often a session used
`hand_off` and `ask_for`.
`?` marks a count that a log written by an older ferret did not record. `--json` prints the same counts
for a script. They say what the work cost and how often the harness sent it back, not whether the
result is right. To see whether a change to a prompt, a pack or the configuration helped, score the
same tasks before and after it.

`ferret gc` reports the stored outputs that appear in no file under `~/.ferret/sessions` or
`~/.ferret/missions` and are older than one hour; `--apply` deletes them. Deleting a session's directory
is what makes its outputs collectable. The scan does not read session temp directories, follows no link
below a session or mission directory, and never opens FIFOs, sockets or devices. It reads at most
4 GiB of any one file and runs at most 5 minutes; past either limit, or on an entry it cannot read, it
stops with a sentence naming the path and deletes nothing.

## The web UI

`ferret open` asks the daemon for a one-time login code (valid 60 seconds) and opens
`http://127.0.0.1:7878/#code=<code>`. The page exchanges the code for a secret that it keeps in the
tab's session storage and sends as a bearer token on every request; there is no cookie. The page and
its scripts need no login; every `/api` route does. After a daemon restart, or a stale tab, run
`ferret open` again. `ferret open --print` prints the address (with a fresh code) instead of opening a
browser. The API token itself is never printed or put on a command line.

For scripts, `Authorization: Bearer $(cat ~/.ferret/token)` works on every `/api` route.

## A daemon on another machine

The daemon listens on loopback only, and it accepts only its own port number in the `Host` header, so
use the same port number at both ends of the tunnel. The `ferret` client reads the address from
`$FERRET_HOME/daemon.json` (else the config) and the token from `$FERRET_HOME/token`, so give it a small
home of its own that holds the remote token:

```
# on your laptop
mkdir -p ~/.ferret-remote && chmod 700 ~/.ferret-remote
(umask 077; ssh your-host 'cat ~/.ferret/token' > ~/.ferret-remote/token)
ssh -N -L 7878:127.0.0.1:7878 your-host &
FERRET_HOME=~/.ferret-remote ferret status
FERRET_HOME=~/.ferret-remote ferret open
```

If the remote daemon listens on another port, write `[daemon]` / `bind = "127.0.0.1:<port>"` in
`~/.ferret-remote/config.toml` and forward that port on both sides. The port must be free locally (do not
run a local daemon on it at the same time). `ferret-desk` (`gui/`) does the same for you: it opens the
tunnel, fetches the token and keeps it in the Keychain.

## Packs

A pack is a directory with a `pack.toml`. `core` is built into the binary. Others are loaded from
`~/.ferret/packs/<name>/` at daemon start (a directory named `core` replaces the built-in one). A pack
that does not load stops the daemon from starting and the log names the pack and the key. Unknown keys
are errors. Top level: `name`, `description`, `default_role`, `preamble`, `requires_restricted_network`, `solvable` (true: roles are told the mission was built to be solved and `conclude` refuses `unreachable`; off by default).
Per role (`[roles.<name>]`): `description`, `prompt`, `termination` (`explicit` or `free`), `tools`,
`may_spawn`, `verify_finish`, `verifier`, `read_only`. A role with `verify_finish = true` names its
verifier role (`verifier`, default: the pack's role called `verifier`); that role must be in the same
pack, be `read_only`, and have `verdict` and `out_read` or `out_grep`. Copies of a shipped pack in
`~/.ferret/packs` do not update themselves: replace them after upgrading (`rm -rf ~/.ferret/packs/vr && cp -R packs/vr ~/.ferret/packs/vr`,
then restart the daemon).

Start a session of a pack with `ferret run --pack <pack> --role <role> -w <workspace> "..."`. A role that
has `verify_finish` has its `finish` checked by the verifier. A rejected finish is not delivered and
does not stop the session or ask you anything: each objection holds the next finish until a new run of
the target is recorded. With `[agents] fresh_start = true` (the default) the lead also starts afresh at
every rejection. The goal is open again, so it must be concluded anew on a run made after the rejection.
The lead's context is folded: its earlier replies, its reasoning and its finish and conclude calls go
out of view, and it reads what the verifier found in their place. Nothing is deleted: `ferret tail` and
the web UI show the whole record, and the agent can open folded output again. A session that keeps the
rejection in view tends to argue with it or to give up again; `fresh_start = false` keeps it in view
all the same. A lead whose finish is refused again and again before a verifier runs, with nothing new
executed since the last rejection, opens one non-blocking question in your inbox (it pauses nothing). When the verifier cannot be run, the finish is held as unverified, a note says so, and
nothing is delivered as finished. `finish` is also refused while the session has running jobs or
running agents. `[agents] verify_finish = false` in the config turns verification off for every role:
the finish is then delivered at once, marked `not verified`.

## Files

Under the ferret home: `config.toml`, `token`, `daemon.json`, `daemon.lock`, `keys/`, `ca/`, `logs/ferretd.log`,
`packs/`, `targets/`, `blobs/` (stored outputs), `rewrite_rules.json` (0600, operator proxy rewrites),
`signal_sent.json` (0600, Signal quote-reply map), `signal_guests.json` (0600, Signal guest approvals, blocks, and isolated chat histories), `sessions/<id>/` (`log.jsonl`, `meta.json`, `status.json`, `jobs/`,
`tmp/`, `queued/`, `net.jsonl`, and for a child `settlement.json` and, when it works in its own copy
of the workspace, `copy.json`), `missions/<id>/` (`journal.jsonl`, `journal.head`). Session ids made
of anything other than letters, digits, `-`, `_` and `.` never map to a path outside the home.

Beside the ferret home, not in it: `~/.ferret-copies/<mission>/<agent>/` (the home's name with `-copies`
added), the copies of a workspace that agents started with `workspace: "copy"` or by `attempt` work
in. A copy holds everything the workspace holds except `.ferret`, so treat the directory like the
workspaces themselves. On APFS the files are clones and take space only as they change, and only
`agents.copy_max_files` bounds what is copied; elsewhere a copy is a full copy and
`agents.copy_max_mb` bounds it too. Making a copy takes about a second per ten thousand files.
Archiving a mission (`ferret archive`) deletes its copies, including changes the lead never adopted,
and `--undo` does not bring them back. Nothing else deletes them.

## First run checklist

1. `ferret config check` prints `ok: <path>`, then `ferret up`, then `ferret status` shows ✓ beside your server's
   URL (it answered a request for its models).
2. `ferret run -w <a tiny workspace> "how many .rs files are here and how many lines in total?"` (or a
   question about your own files). Confirm: the lead calls `bash`, the result carries the
   `[tool · exit 0 · … · out:…]` header, the lead records a claim with a quote that matches, `finish`
   passes the verifier, and `ferret ledger last` shows the goal and the claim. Now `ferret status` shows
   the model id the server serves and the window it reported (or the `context_window` you set).
3. `ferret window last`: the stable prefix is the system prompt, your message and the turns; the
   `<harness-state>` block is not part of it.

The Bubblewrap host launcher always removes loader/shell startup variables (`LD_*`, `DYLD_*`,
`BASH_FUNC_*`, `BASH_ENV`, `ENV`, `SHELLOPTS`, `BASHOPTS`), even when listed in `env_pass`. Set a
needed library path inside the confined command instead. Its source descriptors are closed by a trusted confined launcher
before target execution; native tests check that they cannot bypass read-only mounts.
