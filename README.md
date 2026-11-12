# loom

An agent harness for long, unattended work on a model you host yourself.

loom is for the case the usual tools are not built for: one operator, an OpenAI-compatible server on
your own network (vLLM and the like, with a large window, automatic prefix caching and several
concurrent sequences), sessions that run for hours while nobody watches, and work where *what was
actually observed* matters more than fluent prose. It is built around the ways long local runs go
wrong: context silently compacted, tool output cut without a trace, questions that wait for hours
because nothing says they are waiting, and state that lived only in the transcript and was lost when
the window filled.

It inverts the cloud assumptions:

- **Tokens are cheap; rebuilding the prefix is what costs.** A cached prefix is free; an edited one is
  re-read from the first change. So a session's request prefix only ever grows, except at explicit,
  logged re-weaves; nothing is trimmed "to save tokens". On a server with prefix caching, a stable
  prefix comes back almost entirely from cache on every later step.
- **Forking is free.** A child that starts from its parent's exact prefix gets a full cache hit, so
  fanning out, verifying and voting all begin with everything the parent already knows.
- **The model is the weakest part, so it gets the smallest job.** The harness owns process, memory,
  bookkeeping and verification; the model fills typed slots inside narrow steps. This does not slow a
  strong model down, and it carries a smaller one.

`docs/DESIGN.md` is the specification; this README is the tour. `docs/RUN.md` is the runbook.

## Requirements

- Rust 1.85 or newer (`rust-version` in `Cargo.toml`) to build.
- macOS to run commands under the OS sandbox. The sandbox is macOS seatbelt (`/usr/bin/sandbox-exec`)
  only. On any other system the daemon refuses to start unless the config says `[sandbox] mode = "none"`,
  which leaves every command the model runs unconfined.
- An OpenAI-compatible `/v1/chat/completions` server that streams.

## Quick start

```
cargo build --release -p loom-daemon      # the binary is target/release/loom
mkdir -p ~/.local/bin                     # or use any other directory on your PATH
install -m 755 target/release/loom ~/.local/bin/loom
loom config init                          # writes ~/.loom/config.toml
$EDITOR ~/.loom/config.toml               # set base_url and model for your server
loom config check                         # prints "ok", or what is wrong
loom up                                   # start the daemon in the background
loom status                               # the daemon, ✓ or ✗ for your model server, what is running
loom run -w /path/to/workspace "your task in one sentence"
```

`~/.local/bin` must be on your `PATH` (add `export PATH="$HOME/.local/bin:$PATH"` to your shell's
startup file if it is not). Until a session has been created since the daemon started, `loom status`
shows the model and window written in the config; after that, the model id the server serves and the
window it reported.

The daemon reads the config file only when it starts, so write and edit the config before `loom up`,
and run `loom down` then `loom up` after changing it. `loom up` starts the program it was run from,
so keep the binary where it is while the daemon runs. If the server cannot be reached when a session
is created and the profile sets no `context_window`, creation is refused with a sentence naming the
URL; set `context_window` or start the server.

By default the tools reach no network host (`[network] mode = "deny_all"`); see "Network" below.

## What it does differently

Each of these is a mechanism, not a line in a prompt.

- **The log is the record; the window is a view.** Every session is an append-only, hash-chained
  event log on disk. The request sent to the model is a pure function of that log (`weave`), so a
  crash, a restart and a context eviction are the same operation: rebuild the view from the log.
- **Window fullness never reaches the model.** It is told once that context is managed and is never
  given a gauge, a message count or an elapsed time to reason about; none of those is ever a reason
  to stop, defer or summarise. Budgets that *do* exist (steps, wall-clock) are named and shown
  separately.
- **Tool output is admitted whole.** The complete output is stored before the model sees any of it.
  If it is too large to show in full, the cut is explicit (which lines were omitted, the sizes, the
  exit status) and the whole thing stays addressable by a handle the model can page (`out_read`) and
  search (`out_grep`). A later eviction replaces old output with a stub that keeps the same handle, so
  "folded out of view" is always distinguishable from "never happened", and the model can pull any of
  it back. Tool calls stay native and are never paraphrased; a call and its result are never
  separated or reordered.
- **State that must outlive the window lives in a sealed ledger.** Goal, constraints, plan, decisions,
  dead ends, claims, evidence, obligations and approvals are typed, HMAC-chained records in a journal
  outside the workspace, written at decision time. A claim may only quote lines the harness actually
  put in front of the model, checked verbatim against the stored bytes. The Markdown you read is a
  generated view, never parsed back.
- **Stopping is an act.** A turn that ends without a tool call goes through a gate: for a working
  role, if the ledger still has open steps, obligations or unverified claims, the harness says exactly
  what is open and continues; "it has been a while" and "context" are not reasons to stop. Work ends
  only through `finish` (mechanically checked, then, for a role that asks for it, attacked by an
  independent verifier), `ask_user`, `report_blocker` or `wait`.
- **Enforcement sits outside the agent's reach.** Keys, config, harness state and the tool set live
  outside the sandbox's writable area. Network scope is enforced by a loopback egress proxy plus an OS
  sandbox that permits no other route, not by reading shell text.
- **Nothing leaves the machine unless you configure it.** No telemetry, no analytics, no fallback
  provider. Model requests go only to the server you named.
- **Unattended is the default.** The daemon survives its own restarts (it resumes what was running
  from the logs), stops cascade to every child, every child has a budget, and anything waiting on a
  human raises a notification.

## Shape

One binary, `loom`:

```
loom daemon        the long-lived local process; owns everything below
loom <command>     a thin client over the daemon's HTTP API (127.0.0.1, bearer token)
web UI             served by the daemon at / (records, context and the inbox, made visible)
```

Crates:

| crate | what it owns |
|---|---|
| `loom-core` | types, the event log, the blob store, the weave and eviction, admission, the ledger journal, config; all sync and pure |
| `loom-model` | the OpenAI-compatible streaming client, a priority request limiter, retry across a server relaunch, a scripted mock server |
| `loom-tools` | the tool trait and registry, the built-in tools, process and job control, the OS sandbox |
| `loom-net` | the loopback egress proxy and its scope policy |
| `loom-agent` | the session loop, the stop and finish gates, the state block, orchestration, the runtime that owns every session |
| `loom-daemon` | the HTTP API, the embedded web UI, and the `loom` command |

State lives under `~/.loom/` (override with `LOOM_HOME`), never inside a workspace: the config, the
API token (`token`), the journal key (`keys/`), one directory per session (its log, a small summary
and its job files), the content-addressed blob store, one journal per mission, logs, and any packs you
install.

## Tools and roles

Built-in tools: `bash` (its own process group under the sandbox; a long call becomes a tracked
background job rather than being killed) with `job_wait`, `job_kill` and `job_list`; `read`, `write`
and `edit` (regular files only; a write refuses when the file changed since the session last read
it); `glob` and `grep`; `out_read` and `out_grep` (page and search any stored output); `web_fetch`
(through the egress proxy); and `cve_lookup`, `cve_search` and `advisory_lookup` (public vulnerability
databases, through the same proxy). The runtime adds the ledger tools (`plan`, `step`, `note`, `claim`,
`claim_update`, `evidence`, `ledger`, `pin`, `log_search`), the agent tools (`agent_spawn`,
`agent_fanout`, `agent_message`, `agent_stop`, `decide`, `verify`) and the terminating tools (`finish`,
`verdict`, `ask_user`, `report_blocker`, `wait`). Which of them a session has depends on its role.

A **pack** is a set of roles; a role is a prompt, a tool list and how it ends. The built-in `core`
pack has `lead` (owns a mission, plans, delegates, finishes through the gate), `worker` (one
assignment, returns quoted evidence), `verifier` (read-only; tries to refute a claim) and `chat` (a
plain turn-by-turn assistant). Domain discipline, such as a research pipeline with its own stages and
evidence tiers, is a pack, not core.

## Commands

```
loom run -w /path/to/workspace "task"     start a lead session in that directory and follow it
loom chat                                 a turn-by-turn chat session on the terminal
loom ls                                   sessions, their state and context size
loom tail <session>                       follow a session's record
loom send <session> "message"             add a message to a session
loom stop <session> | resume <session>    stop the current turn, or let a stopped session carry on
loom inbox                                questions, approvals and blockers waiting for you
loom answer <item> "..."                  answer one
loom rule <session> "text"                set a standing rule for the mission
loom rule <session> --withdraw <rule-id> [--reason "..."]
loom approve <session> "text" [--scope "..."]
loom ledger <session>                     the mission ledger
loom window <session>                     what is in the model's context right now
loom net <session>                        every network request and how it was decided
loom open                                 open the web UI in a browser
loom gc [--apply]                         delete stored outputs nothing refers to (dry run unless --apply)
```

A `<session>` is an id, the beginning of one, or `last`. `docs/RUN.md` lists every command and option.

## Network

The daemon binds `127.0.0.1` and every API request carries a bearer token, so it is reachable only
from the machine it runs on. Commands the model runs can reach the network only through the
daemon's egress proxy, and the proxy's policy comes from `[network]` in the config:

- `deny_all` (the default): tools reach no host. Requests to your model server are not affected.
- `allowlist`: only hosts matching `allow` are reachable.
- `open`: any public host is reachable. Private, loopback and link-local addresses are still refused
  unless listed in `allow_private`.

`web_fetch` and the vulnerability-lookup tools need a route, so with the default they fail with a
refusal that names the policy. `docs/config.example.toml` shows an allowlist.

To use a daemon that runs on another machine, forward its port over SSH and give the client that
daemon's token; `docs/RUN.md` has the recipe.

## Seeing it: the web UI and the desktop app

The daemon serves a web UI at `/` (three columns: missions, the live transcript, and the mission
state: ledger, context window with each item's standing, inbox, network decisions). It is static,
strict-CSP, has no build step, and updates live over SSE. Run `loom open` to open it: the command asks
the daemon for a one-time login code and opens the page with it. The page needs no cookie; it keeps
a secret in the tab's session storage and asks you to run `loom open` again when that is gone.

**loom-desk** (`gui/`) is a small native macOS app around that UI, for leaving missions running and
glancing at them. It manages connections (a named host, an SSH tunnel it opens for you, the token it
fetches), shows running and waiting counts in the menu bar, and raises an OS notification the moment a
mission needs you. See `gui/README.md`.

## Packs

A pack is a set of roles. `core` (built in) is general. `vr` (`packs/vr/`) is a vulnerability-research
pipeline (scope gate, evidence tiers, a judge that attacks the researcher's finish, a report-readiness gate)
expressed as roles, ledger records and the harness's own checks. It is not installed by default; see
`packs/vr/README.md`.

## Building and testing

```
cargo build --release -p loom-daemon      # the `loom` binary, target/release/loom
cargo test --workspace                    # the Rust suite
cargo clippy --workspace --all-targets -- -D warnings
node --test ui/core.test.js               # the web UI's logic; needs Node.js 22.12 or newer
```

`./x` is an optional wrapper that runs cargo on another machine named by `LOOM_BUILD_HOST` (and
`LOOM_BUILD_HOST=local` runs it here); you do not need it. Set `LOOM_BUILD_HOST` whenever you use it:
when it is unset, `./x` falls back to a host name written into the script instead of stopping. The
desktop app builds with `gui/build.sh`, which requires `LOOM_BUILD_HOST`. `docs/IMPLEMENTING.md` is
the contributor guide.

## Reporting a vulnerability

See `SECURITY.md`. Changes between versions are in `CHANGELOG.md`.

## License

MIT.
