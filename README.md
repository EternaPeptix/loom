# loom

An agent harness for long, unattended work on a model you host yourself.

loom is for the case the usual tools are not built for: one operator, an OpenAI-compatible server on
your own network (vLLM and the like, with a large window, automatic prefix caching and several
concurrent sequences), sessions that run for hours while nobody watches, and work where *what was
actually observed* matters more than fluent prose. It was written after auditing an existing harness
and measuring where long local runs go wrong — context silently compacted, tool output cut without a
trace, questions that wait for hours because nothing says they are waiting, state that lived only in
the transcript and was lost when the window filled.

It inverts the cloud assumptions:

- **Tokens are cheap; rebuilding the prefix is what costs.** A cached prefix is free; an edited one is
  re-read from the first change. So a session's request prefix only ever grows, except at explicit,
  logged re-weaves — nothing is trimmed "to save tokens". On the target server, a 30k-token prefix
  that stays stable comes back **~99% from cache** on every later step (sub-second to first token
  instead of ~5 seconds cold).
- **Forking is free.** A child that starts from its parent's exact prefix gets a full cache hit, so
  fanning out, verifying and voting all begin with everything the parent already knows.
- **The model is the weakest part, so it gets the smallest job.** The harness owns process, memory,
  bookkeeping and verification; the model fills typed slots inside narrow steps. This does not slow a
  strong model down, and it carries a smaller one.

`docs/DESIGN.md` is the normative specification; this README is the tour.

## What it does differently

Each of these is a mechanism, not a line in a prompt.

- **The log is the record; the window is a view.** Every session is an append-only, hash-chained
  event log on disk. The request sent to the model is a pure function of that log (`weave`), so a
  crash, a restart and a context eviction are the same operation: rebuild the view from the log.
- **Window fullness never reaches the model.** It is told once that context is managed and is never
  given a gauge, a message count or an elapsed time to reason about — none of those is ever a reason
  to stop, defer or summarise. Budgets that *do* exist (steps, wall-clock) are named and shown
  separately.
- **Tool output is admitted whole.** The complete output is stored before the model sees any of it.
  If it is too large to show in full, the cut is explicit — which lines were omitted, the sizes, the
  exit status — and the whole thing stays addressable by a handle the model can page (`out_read`) and
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
  only through `finish` (mechanically checked, then optionally attacked by an independent verifier),
  `ask_user`, `report_blocker` or `wait`.
- **Enforcement sits outside the agent's reach.** Keys, config, harness state and the tool set live
  outside the sandbox's writable area. Network scope is enforced by a loopback egress proxy plus an OS
  sandbox that permits no other route — not by reading shell text.
- **Nothing leaves the machine unless you configure it.** No telemetry, no analytics, no fallback
  provider. Requests go only to the server you named.
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
| `loom-core` | types, the event log, the blob store, the weave and eviction, admission, the ledger journal, config — all sync and pure |
| `loom-model` | the OpenAI-compatible streaming client, a priority request limiter, retry across a server relaunch, a scripted mock server |
| `loom-tools` | the tool trait and registry, the built-in tools, process and job control, the OS sandbox |
| `loom-net` | the loopback egress proxy and its scope policy |
| `loom-agent` | the session loop, the stop and finish gates, the state block, orchestration, the runtime that owns every session |
| `loom-daemon` | the HTTP API, the embedded web UI, and the `loom` command |

State lives under `~/.loom/` (override with `LOOM_HOME`), never inside a workspace: the config, the
API token, the journal key, one directory per session (its log and a small summary), the
content-addressed blob store, and one journal per mission.

## Tools and roles

Built-in tools: `bash` (its own process group under the sandbox; a long call becomes a tracked
background job rather than being killed), `read` / `write` / `edit` (atomic; a write refuses when the
file changed since the session last read it), `glob` / `grep` (same file set, newest-first, with a
handle to the full list), `out_read` / `out_grep` (page and search any stored output), and
`web_fetch` (through the egress proxy). The runtime adds the ledger tools, the agent tools
(`agent_spawn`, `agent_fanout`, `decide`, `verify`, …) and the terminating tools.

A **pack** is a set of roles; a role is a prompt, a tool list and how it ends. The built-in `core`
pack has `lead` (owns a mission, plans, delegates, finishes through the gate), `worker` (one
assignment, returns quoted evidence), `verifier` (read-only; tries to refute a claim) and `chat` (a
plain turn-by-turn assistant). Domain discipline — say, a research pipeline with its own stages and
evidence tiers — is a pack, not core.

## Status

The engine is built and tested: `loom-core`, `loom-model`, `loom-tools`, `loom-net`, the whole
`loom-agent` session loop and runtime tools, the daemon's client, command line, terminal rendering
and access control, and the web UI. The live client check against the target server
(`cargo run -p loom-model --example live`) confirms the caching behaviour the design turns on. The
HTTP server and the daemon lifecycle are the last pieces being wired in.

## Building

The build runs on a separate host so the operator's machine stays idle (see `./x`). To build
natively instead:

```
cargo build --release      # the `loom` binary
cargo test                 # the whole suite
```

Requires a recent stable Rust. The harness talks to any OpenAI-compatible `/chat/completions` server
that streams; point it at yours in `~/.loom/config.toml` (`loom config init` writes a starting one).

## License

MIT.
