# Running loom

## Requirements

- Rust 1.85 or newer to build.
- macOS for the default Seatbelt sandbox, or Linux with `/usr/bin/bwrap` for `mode = "bubblewrap"`.
  Bubblewrap supports x86_64/aarch64 and deny-all command networking only; host proxy bridges and
  loopback/Unix socket exceptions are refused. Explicit `mode = "none"` leaves shell commands
  unconfined, including read-only verifier roles. Missing sandbox support never triggers a fallback.
- An OpenAI-compatible server with `/v1/chat/completions` (streaming) and, ideally, `/v1/models`.

## Build and install

```
cargo build --release -p loom-daemon
```

The binary is `target/release/loom`. Put it on your `PATH`, for example
`mkdir -p ~/.local/bin && install -m 755 target/release/loom ~/.local/bin/loom` (with `~/.local/bin` on
your `PATH`), or `/usr/local/bin`. `loom up` starts the daemon by running the same binary again, so do
not move or replace it while the daemon runs without restarting the daemon.

`./x` is optional. It copies the tree to another machine and runs cargo there; the machine is named by
`LOOM_BUILD_HOST` (`LOOM_BUILD_HOST=local ./x ...` runs cargo here) and `LOOM_LANE` picks a separate
source copy on that host. Set `LOOM_BUILD_HOST` every time: when it is unset, `./x` does not stop but
falls back to a host name written into the script, which is not a machine of yours. `./x --pull-bin`
builds a release binary there and copies it to `./bin/loom`. The desktop app is built with
`gui/build.sh`, which requires `LOOM_BUILD_HOST` (a host, or `local`) and stops when it is unset.

Tests (the UI test needs Node.js 22.12 or newer: `ui/core.test.js` is an ES module with no
`package.json` beside it, which older releases may not load):

```
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
node --test ui/core.test.js
```

## Configure

The configuration is `~/.loom/config.toml` (`LOOM_HOME` moves the whole `~/.loom` directory). The
daemon reads it only when it starts: configure first, then start, and restart after any change.

```
loom config init       # writes a starting file; refuses to overwrite an existing one
loom config path       # prints the path
loom config check      # loads the file and checks it: prints "ok", or the error and exits 1
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
- `[context] target_tokens` and `floor_tokens`: a re-weave folds old output out of view when the prompt
  passes the target, down to the floor. A session clamps both to a smaller model window automatically.
- `[network] mode`: `deny_all` (the default), `allowlist` or `open`; see below.
- `[sandbox] protect_credentials` (default `true`): see below.
- `[tools] speculate` (default `true`): the leading read-only calls of a reply (`read`, `glob`, `grep`,
  `out_read`, `out_grep`) may start while the reply is still streaming. Results are recorded in call
  order and used only if the finished reply holds the same call. `false` runs calls only after the
  whole reply has arrived.
- `reasoning_effort` and the other `extra_body` fields are fixed for a session's life (the chat
  template may render them into the prompt head, so changing them mid-session would break the cache).

### Network

Commands and `web_fetch` reach hosts only through the daemon's egress proxy, which applies `[network]`:

| mode | reachable |
|---|---|
| `deny_all` (default) | no host. Model requests to your configured endpoint are not affected. |
| `allowlist` | hosts matching `allow` (`example.test`, `*.example.test`, optionally `:port`) |
| `open` | any public host |

`deny` entries (host patterns, IP addresses or CIDR blocks) are refused in every mode, and are matched
against the resolved address too. Private, loopback and link-local destinations are refused unless
listed in `allow_private`. Every decision is recorded in the session's audit log (`loom net <session>`).
A pack that sets `requires_restricted_network` (`vr` does) is refused while the mode is `open`.

A session can also be given hosts by you while it runs. When it needs one it does not have, the agent
calls `request_scope`; an item naming the hosts and why waits in your inbox, and the session keeps
working. `loom scope <session> <host>...` grants them (the UI and the app have an Approve button on the
item). The grant is recorded in the mission's ledger, applies to that mission only, and ends with the
session. `loom net <session>` lists the hosts granted so far.

### Sandbox

With `[sandbox] mode = "seatbelt"` (the default) commands run under a macOS sandbox profile:

- they can write only in the workspace, the session's temp directory, `extra_writable`, and
  the device files `/dev/null`, `/dev/tty` and `/dev/dtracehelper`;
- `~/.loom`, `<workspace>/.loom` and `protected_paths` are never writable, with one exception: the
  session's temp directory is `~/.loom/sessions/<id>/tmp`, and everything inside it is writable (the
  directory entry itself cannot be removed, renamed or replaced);
- the loom token and keys and `unreadable_paths` are neither readable nor writable;
- no network except the egress proxy (plus `loopback_ports`, `loopback_all`, `unix_sockets`);
- no LaunchServices opens, Apple Events or launchd jobs.

Git config/hooks and metadata pointers are protected, including existing nested repositories and
linked worktrees. Normal source edits still work. Commands that explicitly write shared `/tmp` or
`/private/var/folders` must use `$TMPDIR` instead; a read-only verifier can write only its own session
temp and device files. Other readable files remain untrusted inputs.

Linux `mode = "bubblewrap"` uses a read-only host tree, private temp/run mounts, hidden credential
stores, and a seccomp socket deny policy. The original user home (when protecting credentials),
Loom home, and workspace `.loom` are hidden by private mounts; scoped workspace/temp roots are
restored from pinned descriptors. Create workspace `.loom` first. Missing explicit unreadable
paths outside hidden parents are refused, and the whole user home cannot be a writable root. Bind sources are pinned by harness descriptors; missing protected paths under writable roots must
exist first (including the reserved workspace `.loom` directory). Existing Git directories are entirely read-only there;
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
elsewhere; moving `HF_HOME` moves the token out of protection too), run `flyctl` from `~/.fly/bin` or
`pulumi` from `~/.pulumi/bin` (install them elsewhere), or use Terraform's plugin cache in
`~/.terraform.d`. The only switch is `protect_credentials = false`, which lifts the protection of every
store.

Environment variables whose names look like secrets (in any case: containing `KEY`, `TOKEN`, `SECRET`,
`PASSWORD`, `PASSWD`, `PASSPHRASE`, `CREDENTIAL` or `COOKIE`, ending in `_PAT`, `_DSN`, `_PWD` or `_PW`,
`DATABASE_URL`, `SSH_AUTH_SOCK`, anything starting `LOOM_`, names with `SESSION`, `AUTH`, `PASS`, `JWT` or
`WEBHOOK` as an `_`-delimited word or with `PRIVATE`, the `api_key_env` of any model profile, and any
variable whose value holds a URL with a password in it) are not passed to commands unless listed in
`env_pass`.

## A box

`[box]` gives the agent a place to run what the local sandbox cannot (raw TCP to a target, heavy
tooling) without giving it Docker. Each mission gets one container on a Docker host that you set up;
the tools `box_exec`, `box_get` and `box_reset` are the whole interface, and the `ctf` solver roles
have them. The daemon, not the agent, talks to Docker.

Set up the host once:

1. Use a **dedicated Linux VM** that runs Docker and nothing you care about (a KVM guest is fine).
   Give it an `ssh_config` alias that works without a prompt from the daemon's account, for example
   `Host loom-box` with its `HostName`, `User`, `IdentityFile` and, when the VM is behind another
   machine, `ProxyJump`. Test it: `ssh loom-box docker version`.
2. Set `ssh_host = "loom-box"` and `remote_socket = "/var/run/docker.sock"` (the socket inside the VM).
   loom forwards it to `~/.loom/keys/box.sock`, which commands cannot read. Or set `docker_socket` to a
   socket on this machine instead.
3. Pick two images and pin them by digest (`name@sha256:...`; tags are refused): `image`, the box
   itself (the tools you want, with `bash`; it runs as user 1000), and `helper_image`, a small image
   with `sh`, `iptables`, `iptables-restore` and `ip6tables` (the alpine `iptables` package has all of
   them) that loom runs with `NET_ADMIN` on the host network to install the per-mission egress rules. The
   Docker VM's kernel must have the iptables and ip6tables filter tables.
4. Set `enabled = true`.

What the box can reach is the mission's grants: exact hosts and IP addresses given with
`request_scope` and approved, with an optional `:port`. Wildcard grants are not applied (the first
`box_exec` of a session says so). The daemon resolves names, applies the `[network]` policy to the
addresses (private addresses need `allow_private`), and writes the result into rules on the Docker VM
(chain `LOOM-<id>`); everything else, including DNS and IPv6, is dropped. `DOCKER-USER` and `INPUT` send
everything that enters on a box bridge (`lb-*`) to a static chain `LOOM-ALL`, which holds one jump per
mission and ends with `DROP`: a box bridge without its own chain is dropped, never routed or translated.
The Docker host must not have other interfaces named `lb-*`: they are dropped by `LOOM-ALL`. A revoked
grant cuts open flows at once (the mission chain has no rule for established traffic).
loom checks a running box's rules about once a minute and puts them back if they are gone; if that fails
twice it pauses the box (keeping `/work`), refuses the command, and resumes the box when a later check
works. A new grant, a release and the end of the mission update or remove the rules. The box has no
other mounts, no devices, all capabilities dropped except `cap_add`, a read-only root, and tmpfs `/work`
and `/tmp` (both executable): files in it are lost when the mission ends or on `box_reset`. The image
needs `/bin/sh`, `/bin/bash` and `setsid` (util-linux); Docker supplies the init.

Notes. The box needs the OS sandbox: `[sandbox] mode = "none"` and a `sandbox.unix_sockets` entry that
names the box's socket (or anything in `<loom home>/keys`) are refused. `docker_cli` and `ssh` are looked
up on the daemon's `PATH` once, at start; the docker client runs with a fixed `PATH` and an empty
`HOME`/`DOCKER_CONFIG` of its own (`<loom home>/keys/box-docker`), so your docker configuration and
credential helpers are not used. Commands in the box run as user 1000 with `no-new-privileges`, so
`cap_add` gives them no capabilities; it matters only for root processes in the image. A mission that is
stopped, ended or archived has its box removed and gets none until its lead is resumed. After a daemon
restart a box job that was running is still listed, but `job_kill` stops only the local client, not the
command in the container (the remote stop is not kept with the job record): `box_reset` stops it.

**Also protect the host from the VM.** loom's rules cover only the boxes it makes. As a second layer
that does not depend on loom, configure the VM's *host* (the machine that runs the hypervisor) to block
the VM from reaching the host itself and every private range (RFC 1918, link-local, your management
network), allowing only the addresses the VM needs (its DNS or package mirror if any, and the
targets). A container escape or a bug in the rules should then still end at a VM that cannot see
anything else.

## Start

```
loom up                # start the daemon in the background; log: ~/.loom/logs/loomd.log
loom daemon            # or run it in the foreground
loom status            # the daemon, each model server and whether it answered, what is running, free disk space
loom down              # stop it; sessions resume when it starts again
```

The first start creates `~/.loom/token` (the API token, mode 0600). `LOOM_LOG` sets the log level
(default `info`). A second daemon on the same home is refused.

`loom status` marks each model server with ✓ or ✗ (whether it answered a request for its models just
now). The model and window it prints come from the config until a session of that profile has been
created since the daemon started (`window unknown` when `context_window` is not set); from then on
they are the model id the server serves and the window it reported. It also prints the free space on
the volume of the loom home and warns when it is under 5 GiB or 5 percent.

On macOS `loom service install` makes the daemon a login service (a LaunchAgent) and
`loom service uninstall` removes it; `loom service status` says whether it is loaded.

If an older loom's daemon is still running after an upgrade, the new client will not send it the token
(it cannot prove its identity). Run `loom --unverified-daemon down`, then `loom up`.

## A mission

```
loom run -w /path/to/workspace "the task, in plain words"
```

`run` starts a lead session whose workspace is the `-w` / `--workspace` directory (without it, the
current directory) and follows its record on the terminal. Everything after the options is the task;
`-` or no words reads it from standard input. The lead owns a mission ledger (goal, constraints,
plan, claims with evidence), may delegate to workers and have a verifier attack its `finish`, and
stops only through a terminating tool. Ctrl-C stops following, not the session.

Exit status of `run` and `send`: 0 after `Finished` or `Yielded`; 2 when you are needed (`Asked`,
`Blocked`, `Parked`: the inbox item was printed); 1 after `Stopped`, `BudgetExhausted` or an error.

## Commands

| command | does |
|---|---|
| `loom daemon` / `up` / `down` | run the daemon in the foreground / in the background / stop it |
| `loom status` | the daemon, each model server and whether it answered, counts, free disk space |
| `loom open [--print]` | open the web UI in the browser (`--print` prints the address instead) |
| `loom run [options] <task...>` | start a session and follow it; `-d` starts it and returns |
| `loom chat [options]` | turn-by-turn `chat` session; `--session <id>` continues one; `/quit` leaves |
| `loom ls [-a]` | sessions (`-a`: archived too) |
| `loom tail <session> [--since <seq>] [--no-follow]` | print a session's record and follow it |
| `loom send <session> <text...>` | add a message to a running or idle session (`-d` to return at once) |
| `loom stop <session>` / `resume <session>` | stop the turn, its jobs and agents / let a stopped session carry on |
| `loom reweave <session>` | fold old tool output out of the context now |
| `loom archive <session> [--undo]` | hide a finished session; archiving settles the mission's agents |
| `loom rule <session> <text...>` | set a standing rule (a ledger constraint) for the mission |
| `loom rule <session> --withdraw <rule-id> [--reason <text>]` | withdraw a rule |
| `loom approve <session> <text...> [--scope <text>]` | record an approval |
| `loom scope <session> <host>... [--note <text>]` | let the mission's tools reach these hosts (one host per argument) |
| `loom release <session> <reason...>` | accept a blocked mission as it is and close it: "closed by operator, goal not established" |
| `loom inbox` / `loom answer <item> <text...>` | what waits for you / answer one |
| `loom ledger <session>` | the mission ledger |
| `loom score <session> [--json]` | what the mission's work took: steps, malformed calls, refused finishes and quotes, verifier verdicts, fresh starts, `hand_off` and `ask_for` uses |
| `loom window <session>` | what is in the model's context, and what was folded out |
| `loom net <session> [-n <limit>]` | network requests and how each was decided, and the hosts you granted |
| `loom out <handle> [--lines a:b]` | print a stored tool output |
| `loom gc [--apply]` | delete stored outputs that nothing refers to |
| `loom config path` / `check` / `init` | the configuration file |
| `loom service install` / `uninstall` / `status` | the macOS login service |

Options of `run` and `chat`: `-w/--workspace`, `--pack`, `--role`, `-m/--model` (a profile name),
`-t/--title`, `--attended` (do not resume by itself after a restart), `--max-steps`, `--max-minutes`;
and for display `--reasoning`, `--full`, `-v`. A `<session>` is an id, the beginning of one, or `last`.
`-` as the text reads standard input.

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
terminal, `loom answer <item> <text...>` keeps it working and `loom release <session> <reason...>`
closes it.

When you answer, point at the next step instead of asking a yes/no question. "Is it blocked?" invites
"yes". "Run the build with the staging config, then read the first failure" gives it something to do.
A verifier that rejects a finish no longer parks the session on you: the agent gets the objection and
continues. By default it continues from a fresh start: the goal is open again and its context is folded,
so that it works from what the verifier found and not from its own account of the attempt (see Packs,
below).

`loom score <session>` counts what a mission's work took, from its logs: one row per session (the lead,
then its agents and verifiers) and a total. `steps` and `to finish` (steps up to the delivered finish,
`-` when there was none), `calls` and how many were `malformed` (cut short or refused as invalid),
`finish refused` (of how many finish calls), `quote refused` (a finish or an evidence record whose
quote did not check), `verifier` (finishes accepted, of those a verifier judged), `fresh starts`, and how often a session used
`hand_off` and `ask_for`.
`?` marks a count that a log written by an older loom did not record. `--json` prints the same counts
for a script. They say what the work cost and how often the harness sent it back, not whether the
result is right. To see whether a change to a prompt, a pack or the configuration helped, score the
same tasks before and after it.

`loom gc` reports the stored outputs that appear in no file under `~/.loom/sessions` or
`~/.loom/missions` and are older than one hour; `--apply` deletes them. Deleting a session's directory
is what makes its outputs collectable. The scan does not read session temp directories, follows no link
below a session or mission directory, and never opens FIFOs, sockets or devices. It reads at most
4 GiB of any one file and runs at most 5 minutes; past either limit, or on an entry it cannot read, it
stops with a sentence naming the path and deletes nothing.

## The web UI

`loom open` asks the daemon for a one-time login code (valid 60 seconds) and opens
`http://127.0.0.1:7878/#code=<code>`. The page exchanges the code for a secret that it keeps in the
tab's session storage and sends as a bearer token on every request; there is no cookie. The page and
its scripts need no login; every `/api` route does. After a daemon restart, or a stale tab, run
`loom open` again. `loom open --print` prints the address (with a fresh code) instead of opening a
browser. The API token itself is never printed or put on a command line.

For scripts, `Authorization: Bearer $(cat ~/.loom/token)` works on every `/api` route.

## A daemon on another machine

The daemon listens on loopback only, and it accepts only its own port number in the `Host` header, so
use the same port number at both ends of the tunnel. The `loom` client reads the address from
`$LOOM_HOME/daemon.json` (else the config) and the token from `$LOOM_HOME/token`, so give it a small
home of its own that holds the remote token:

```
# on your laptop
mkdir -p ~/.loom-remote && chmod 700 ~/.loom-remote
(umask 077; ssh your-host 'cat ~/.loom/token' > ~/.loom-remote/token)
ssh -N -L 7878:127.0.0.1:7878 your-host &
LOOM_HOME=~/.loom-remote loom status
LOOM_HOME=~/.loom-remote loom open
```

If the remote daemon listens on another port, write `[daemon]` / `bind = "127.0.0.1:<port>"` in
`~/.loom-remote/config.toml` and forward that port on both sides. The port must be free locally (do not
run a local daemon on it at the same time). `loom-desk` (`gui/`) does the same for you: it opens the
tunnel, fetches the token and keeps it in the Keychain.

## Packs

A pack is a directory with a `pack.toml`. `core` is built into the binary. Others are loaded from
`~/.loom/packs/<name>/` at daemon start (a directory named `core` replaces the built-in one). A pack
that does not load stops the daemon from starting and the log names the pack and the key. Unknown keys
are errors. Top level: `name`, `description`, `default_role`, `preamble`, `requires_restricted_network`, `solvable` (true: roles are told the mission was built to be solved and `conclude` refuses `unreachable`; off by default).
Per role (`[roles.<name>]`): `description`, `prompt`, `termination` (`explicit` or `free`), `tools`,
`may_spawn`, `verify_finish`, `verifier`, `read_only`. A role with `verify_finish = true` names its
verifier role (`verifier`, default: the pack's role called `verifier`); that role must be in the same
pack, be `read_only`, and have `verdict` and `out_read` or `out_grep`. Copies of a shipped pack in
`~/.loom/packs` do not update themselves: replace them after upgrading (`rm -rf ~/.loom/packs/vr && cp -R packs/vr ~/.loom/packs/vr`,
then restart the daemon).

Start a session of a pack with `loom run --pack <pack> --role <role> -w <workspace> "..."`. A role that
has `verify_finish` has its `finish` checked by the verifier. A rejected finish is not delivered and
does not stop the session or ask you anything: each objection holds the next finish until a new run of
the target is recorded. With `[agents] fresh_start = true` (the default) the lead also starts afresh at
every rejection. The goal is open again, so it must be concluded anew on a run made after the rejection.
The lead's context is folded: its earlier replies, its reasoning and its finish and conclude calls go
out of view, and it reads what the verifier found in their place. Nothing is deleted: `loom tail` and
the web UI show the whole record, and the agent can open folded output again. A session that keeps the
rejection in view tends to argue with it or to give up again; `fresh_start = false` keeps it in view
all the same. A lead whose finish is refused again and again before a verifier runs, with nothing new
executed since the last rejection, opens one non-blocking question in your inbox (it pauses nothing). When the verifier cannot be run, the finish is held as unverified, a note says so, and
nothing is delivered as finished. `finish` is also refused while the session has running jobs or
running agents. `[agents] verify_finish = false` in the config turns verification off for every role:
the finish is then delivered at once, marked `not verified`.

## Files

Under the loom home: `config.toml`, `token`, `daemon.json`, `daemon.lock`, `keys/`, `logs/loomd.log`,
`packs/`, `blobs/` (stored outputs), `sessions/<id>/` (`log.jsonl`, `meta.json`, `status.json`, `jobs/`,
`tmp/`, `queued/`, `net.jsonl`, and for a child `settlement.json` and, when it works in its own copy
of the workspace, `copy.json`), `missions/<id>/` (`journal.jsonl`, `journal.head`). Session ids made
of anything other than letters, digits, `-`, `_` and `.` never map to a path outside the home.

Beside the loom home, not in it: `~/.loom-copies/<mission>/<agent>/` (the home's name with `-copies`
added), the copies of a workspace that agents started with `workspace: "copy"` or by `attempt` work
in. A copy holds everything the workspace holds except `.loom`, so treat the directory like the
workspaces themselves. On APFS the files are clones and take space only as they change, and only
`agents.copy_max_files` bounds what is copied; elsewhere a copy is a full copy and
`agents.copy_max_mb` bounds it too. Making a copy takes about a second per ten thousand files.
Archiving a mission (`loom archive`) deletes its copies, including changes the lead never adopted,
and `--undo` does not bring them back. Nothing else deletes them.

## First run checklist

1. `loom config check` prints `ok`, then `loom up`, then `loom status` shows ✓ beside your server's
   URL (it answered a request for its models).
2. `loom run -w <a tiny workspace> "how many .rs files are here and how many lines in total?"` (or a
   question about your own files). Confirm: the lead calls `bash`, the result carries the
   `[tool · exit 0 · … · out:…]` header, the lead records a claim with a quote that matches, `finish`
   passes the verifier, and `loom ledger last` shows the goal and the claim. Now `loom status` shows
   the model id the server serves and the window it reported (or the `context_window` you set).
3. `loom window last`: the stable prefix is the system prompt, your message and the turns; the
   `<harness-state>` block is not part of it.

The Bubblewrap host launcher always removes loader/shell startup variables (`LD_*`, `DYLD_*`,
`BASH_FUNC_*`, `BASH_ENV`, `ENV`, `SHELLOPTS`, `BASHOPTS`), even when listed in `env_pass`. Set a
needed library path inside the confined command instead. Its source descriptors are closed by a trusted confined launcher
before target execution; native tests check that they cannot bypass read-only mounts.
