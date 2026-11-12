# Running loom

## Requirements

- Rust 1.85 or newer to build.
- macOS to run commands under the OS sandbox. The sandbox is macOS seatbelt (`/usr/bin/sandbox-exec`)
  only. On any other system the daemon refuses to start unless the config says `[sandbox] mode = "none"`;
  that mode leaves every command the model runs unconfined (the file tools still refuse the protected
  and credential paths). The daemon checks this at start and the message names the alternatives: run on
  macOS, or set `mode = "none"`.
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
  example) ends the request after three attempts in a row whatever this is set to.
- `[context] target_tokens` and `floor_tokens`: a re-weave folds old output out of view when the prompt
  passes the target, down to the floor. The target must be below the model's window.
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

### Sandbox

With `[sandbox] mode = "seatbelt"` (the default) commands run under a macOS sandbox profile:

- they can write only in the workspace, the session's temp directory, `extra_writable`, the system
  temp locations `/private/tmp` (`/tmp`) and `/private/var/folders` (the per-user temp folders), and
  the device files `/dev/null`, `/dev/tty` and `/dev/dtracehelper`;
- `~/.loom`, `<workspace>/.loom` and `protected_paths` are never writable, with one exception: the
  session's temp directory is `~/.loom/sessions/<id>/tmp`, and everything inside it is writable (the
  directory entry itself cannot be removed, renamed or replaced);
- the loom token and keys and `unreadable_paths` are neither readable nor writable;
- no network except the egress proxy (plus `loopback_ports`, `loopback_all`, `unix_sockets`);
- no LaunchServices opens, Apple Events or launchd jobs.

Other files are readable.

`protect_credentials = true` (the default) also makes these unreadable and unwritable to commands and
file tools: `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gh`, `~/.config/gcloud`, `~/.azure`, `~/.kube`,
`~/.docker/config.json`, `~/.netrc`, `~/.npmrc`, `~/.pypirc`, `~/.cargo/credentials(.toml)`,
`~/.git-credentials`, `~/.config/git/credentials`, `~/.password-store`, `~/.config/op`,
`~/Library/Keychains`, `~/Library/Cookies` and the Chrome, Firefox and Safari profile directories. A
listed directory that is or contains the workspace is skipped. This needs a home directory: with
`HOME` unset, every session fails to build its sandbox and the message names `HOME` and
`protect_credentials = false`. Set the key to `false` to turn the protection off.

Environment variables whose names look like secrets (in any case: containing `KEY`, `TOKEN`, `SECRET`,
`PASSWORD`, `PASSWD`, `CREDENTIAL` or `COOKIE`, ending in `_PAT`, `_DSN` or `_PWD`, `DATABASE_URL`,
`SSH_AUTH_SOCK`, anything starting `LOOM_`) are not passed to commands unless listed in `env_pass`.

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
| `loom inbox` / `loom answer <item> <text...>` | what waits for you / answer one |
| `loom ledger <session>` | the mission ledger |
| `loom window <session>` | what is in the model's context, and what was folded out |
| `loom net <session> [-n <limit>]` | network requests and how each was decided |
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
are errors. Top level: `name`, `description`, `default_role`, `preamble`, `requires_restricted_network`.
Per role (`[roles.<name>]`): `description`, `prompt`, `termination` (`explicit` or `free`), `tools`,
`may_spawn`, `verify_finish`, `verifier`, `read_only`. A role with `verify_finish = true` names its
verifier role (`verifier`, default: the pack's role called `verifier`); that role must be in the same
pack, be `read_only`, and have `verdict` and `out_read` or `out_grep`. Copies of a shipped pack in
`~/.loom/packs` do not update themselves: replace them after upgrading (`rm -rf ~/.loom/packs/vr && cp -R packs/vr ~/.loom/packs/vr`,
then restart the daemon).

Start a session of a pack with `loom run --pack <pack> --role <role> -w <workspace> "..."`. A role that
has `verify_finish` has its `finish` checked by the verifier. If the verifier rejects it twice and the lead
finishes a third time, or the verifier cannot be run, the answer is not delivered as finished: you get
a blocking inbox item whose answer is labelled `NOT VERIFIED`, and the next `finish` after you answer is
verified again. `finish` is also refused while the session has running jobs or running agents.
`[agents] verify_finish = false` in the config turns verification off for every role: the finish is
then delivered at once, marked `not verified`.

## Files

Under the loom home: `config.toml`, `token`, `daemon.json`, `daemon.lock`, `keys/`, `logs/loomd.log`,
`packs/`, `blobs/` (stored outputs), `sessions/<id>/` (`log.jsonl`, `meta.json`, `status.json`, `jobs/`,
`tmp/`, `queued/`, `net.jsonl`, and `settlement.json` for a child), `missions/<id>/` (`journal.jsonl`,
`journal.head`). Session ids made of anything other than letters, digits, `-`, `_` and `.` never map
to a path outside the home.

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
