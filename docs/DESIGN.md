# loom — design

loom is an agent harness for long, unattended work on a locally hosted model. It was designed after
auditing an existing harness (DSH) and a research-discipline plugin (dsh-vr) and measuring their
behaviour on real session logs. This document is normative: where code and this text disagree, one of
them is a bug.

## 1. What it optimises for

The deployment it is tuned for: one operator, an OpenAI-compatible server on the LAN (vLLM, 1M-token
window, automatic prefix caching, several concurrent sequences), sessions that run for hours without
anyone watching, and work where *what was actually observed* matters more than fluent prose.

That inverts the usual cloud trade-offs:

- **Tokens cost nothing; rebuilding the prefix costs latency.** A cached prefix is free, an edited one
  is re-read from the edit point. So the request prefix is append-only except at explicit, logged
  re-weaves, and nothing is ever trimmed "to save tokens".
- **Forking is free.** A child that starts from its parent's exact prefix gets a full cache hit, so
  fan-out, verification and voting can each start with everything the parent knows.
- **The model is the weakest component, so it gets the smallest job.** The harness owns process,
  memory, bookkeeping and verification; the model fills typed slots inside narrow steps. A capable
  model is not slowed by this and a small one is carried by it.

## 2. Principles (each is enforced by a mechanism, not a prompt)

1. **The log is the record; the window is a view.** Every session is an append-only, hash-chained
   event log on disk. The context window is a pure function of that log (`weave`). It can be rebuilt
   at any time, so a restart, a crash and an eviction are the same operation.
2. **Window fullness is never an input to a model decision.** The model is told once that context is
   managed and is never a reason to stop, defer or summarise. No gauge is shown. Budgets that do
   exist (steps, wall time) are shown separately and named.
3. **Tool output is admitted whole.** If it cannot be, the cut is explicit (what was omitted, sizes,
   exit status) and the full output stays addressable by a handle the model can page and search.
   Later eviction replaces old output with a stub carrying the same handle. Nothing is ever lost
   silently; "evicted" is always distinguishable from "never happened".
4. **Authorship is preserved.** Every item has an author (`user`, `model`, `tool`, `harness`, or
   another agent). Model-written text never appears under harness or user authority; user messages
   are kept verbatim for the life of the session.
5. **State that must survive lives in the ledger, written at decision time.** Goal, constraints,
   plan, decisions, dead ends, claims, evidence, obligations and approvals are typed records in an
   append-only sealed journal outside the workspace. Markdown is a generated view, never parsed.
6. **A claim rests on evidence the harness witnessed.** Evidence records point at a tool call in a
   session log and the hash of its stored output. The harness checks the pointer when the record is
   written; quotes are checked verbatim against the stored bytes.
7. **Stopping is an act, not a drift.** A turn that ends without tool calls goes through the stop
   gate. Work ends through `finish` (gated, independently verified), `ask_user`, `report_blocker` or
   `wait` — each validated. "Context" and "it has been a long time" are not blockers.
8. **Enforcement sits outside the agent's reach.** Harness state, keys, config and the tool set are
   outside the sandbox's writable area. Network scope is enforced by an egress proxy plus an OS
   sandbox that permits no other route, not by parsing shell text.
9. **Nothing leaves the machine unless configured.** No telemetry, no analytics, no fallback
   provider. Model requests go only to the configured endpoint.
10. **Unattended is the default.** The daemon survives its own crashes (supervised, log-recovered),
    cancels reach every child, every child has a budget, tools that ignore cancellation are killed,
    and anything waiting on a human raises a notification and has a policy for silence.
11. **Observation is the work.** For the work this is built for, the output of a tool call *is* the
    finding, so the harness never paraphrases, summarises or silently shortens it. What the model is
    shown is the stored bytes (after a lossless-by-line normalisation) inside an envelope that states
    the tool, the outcome, the size and the handle at both ends. The harness tracks which lines of
    every stored output have actually been put in front of the model (`observe::coverage`), lists
    executions with unseen lines in the HUD, labels a pattern scan as a text match rather than a
    reading, and refuses evidence whose quote is not in the stored bytes.
12. **Tool calls are replayed exactly.** Every complete call the model made is replayed with its
    arguments byte for byte, paired with exactly one result, in call order, for the life of the
    session. When the window must shrink, replayed reasoning goes first, navigation output second,
    file reads third, execution output last, and what is evicted leaves a stub that names the call,
    its outcome and the handle. A call without a recorded result is rendered as such; a call that was
    cut off by an output limit is never run and the model is told so.

## 3. Shape

```
loom (one binary)
  loom daemon        long-lived local process; owns everything below
  loom <command>     thin client over the daemon's HTTP API (127.0.0.1, bearer token)
  web UI             served by the daemon at /

crates/
  loom-core    types, event log, blob store, weave/eviction, admission, ledger journal, config   (sync, pure)
  loom-model   OpenAI-compatible streaming client, retry across server relaunch, mock server
  loom-tools   Tool trait + registry, built-in tools, process control, sandbox, MCP stdio client
  loom-net     egress proxy with scope policy and audit
  loom-agent   Runtime: agent loop, stop gate, scheduler, orchestration, gates, HUD
  loom-daemon  HTTP/SSE API, recovery, notifications, CLI, embedded UI
packs/         roles (prompts, tool sets, contracts) and optional plugin processes
ui/            static web UI (no build step), embedded into the binary
evals/         behavioural checks that run against the mock model or a live one
```

State root is `~/.loom/` (override `LOOM_HOME`), never inside a workspace:

```
~/.loom/config.toml
~/.loom/token                     0600, API bearer token
~/.loom/keys/journal.key          0600, HMAC key for ledger seals
~/.loom/sessions/<sid>/log.jsonl  the session event log
~/.loom/sessions/<sid>/meta.json  small mutable summary for fast listing (derivable from the log)
~/.loom/blobs/<aa>/<sha256>       content-addressed tool output (+ .idx line index)
~/.loom/missions/<mid>/journal.jsonl   the ledger journal for one mission
~/.loom/logs/loomd.log
```

A **mission** is one goal pursued by one lead session and any number of child sessions; they share a
ledger. A workspace gets generated read-only views under `<workspace>/.loom/` (ledger Markdown).

## 4. Events and the log (`loom-core::event`, `loom-core::log`)

`event.rs` is the normative schema. One JSON object per line:

```
{"seq":12,"ts_ms":1794434009000,"author":"model","prev":"<sha256 of previous line>","kind":"model_response", ...}
```

- `seq` starts at 0 (`session_start`) and increases by one. `prev` chains each line to the bytes of
  the one before it (the first line uses 64 zeros).
- Appends are a single `write` of a complete line followed by `fsync` (durability `always`, the
  default) — intent is durable before side effects: `tool_call` is appended and synced before the
  tool runs.
- Opening a log never fails on damage. A torn final line is dropped; a line that fails to parse or
  breaks the chain ends the readable prefix, the remainder is moved aside to `log.jsonl.damaged-<ts>`
  and the session continues from the last good record with an `interrupted` event describing it.
- Unknown `kind` values deserialize to `Event::Unknown` and are preserved and ignored by `weave`.

## 5. The weave (`loom-core::weave`)

`weave(records) -> Weave` renders the stable request prefix. It is deterministic: same records,
same bytes. The module documentation of `weave.rs` is the precise specification (pairing, merging,
eviction actions); this section is the overview. Rendering rules:

| Event | Rendered as |
|---|---|
| `session_start` | `system` message: the role prompt + project instructions, fixed for the session. Tool specs come from this event and never change mid-session. |
| `user_message` | `user` message, verbatim. |
| `harness_note` | `user`-role message wrapped as `<harness kind="…">…</harness>`. |
| `model_response` | `assistant` message: text and complete tool calls. Reasoning is replayed according to `reasoning_replay` (`all` by default — measured against the server's chat template it stays in the prefix and costs nothing once cached — or `none`), fixed per session. Tool calls cut off by an output limit are not rendered. |
| `tool_result` | `tool` message with the admitted text. A call with no result (crash, in flight at restart) renders `[no result recorded: the call was interrupted; its effects are unknown — check before retrying]`. |
| `child_settled` | `user`-role `<harness kind="agent-report" agent="…" verified="false">…</harness>` block. |
| everything else | not rendered. |

Adjacent `user`-role items are merged into one message (blank line between) so chat templates that
reject consecutive user turns still work.

**Re-weave.** A `reweave` event changes the projection for everything at or before `upto_seq`: it
lists evictions (`stub` with replacement text, or `drop`) and carries a `brief` (a harness note with
the ledger snapshot and resume instructions) that is rendered immediately after the evicted span.
Evictions accumulate across re-weaves; only the latest brief is rendered. The epoch increments.
Everything after `upto_seq` renders normally. Because the record is in the log, the projection stays
a pure function of the log.

**Eviction order** (`plan_reweave`), applied until the estimate is at or below `floor_tokens`,
stopping as soon as it is:

1. replayed reasoning of old steps (the calls and their results stay);
2. navigation output (`ToolClass::Nav`: listings, searches), oldest first;
3. file reads (`ToolClass::Read`), largest first;
4. every other unpinned tool output and agent report, largest first, replaced by a stub:
   `[evicted: <tool> <one-line args> → <status>, <lines> lines / <bytes>; full output: out:<id> — out_read / out_grep]`
   (an execution's stub also keeps its last `stub_tail_lines` lines);
5. assistant text of old steps, only when a digest is supplied (see below);
6. never: the system message, user messages, the assignment, harness notes of kind
   `approval`/`constraint`, pinned output, the most recent `keep_recent_steps` steps.

Tool call/result pairs always stay paired (a stub is still a `tool` message).

A re-weave is planned when the server-reported prompt size exceeds `target_tokens`. Both numbers are
absolute token counts per model profile, not shares of the window: the working set is sized by
latency and quality, and the rest of the window is burst capacity. Defaults for a 1M window:
`target_tokens = 400_000`, `floor_tokens = 180_000`, `keep_recent_steps = 60`. Re-weaves happen only
between steps, never while a tool call is outstanding. The model can `pin` a result it wants kept.

**Digest (optional, cache-friendly).** Before a re-weave that must evict assistant narration, the
agent layer may send the *existing* prefix plus one appended instruction asking for a digest of the
span to be evicted. That request is a full cache hit. The digest is stored in the `reweave` event and
rendered inside the brief under "leads from earlier work — re-check before relying on them".

**Ephemeral tail (HUD).** Not part of the weave. The agent layer appends one final `user`-role
message `<harness-state>…</harness-state>` to each request and never persists it in the window; the
next request diverges from the cache only after the previous last stable message. It carries: goal
(first line), standing constraints, plan with statuses, open obligations, stale-observation and
repetition flags, and named budgets. It is recorded (hash + blob) on the `model_request` event.

**Prefix guard** (`loom-core::prefix`). For each request the agent layer hands the stable messages to
`PrefixGuard::check`, which compares them with the previous request of the same session: unless the
epoch changed, the previous stable messages must be an exact prefix of the new ones. A violation
appends a `cache_break` event naming the first differing message and is a test failure.

## 6. Admission (`loom-core::admit`)

The module documentation of `admit.rs` is the precise specification; this is the overview.

Every tool output is normalised (invalid UTF-8, terminal escape sequences, carriage-return
overwrites and control characters are handled without changing the number of lines) and stored whole
in the blob store first. `admit` then builds what the model sees — always an envelope:

```
[bash · exit 1 · 2.4 s · stderr 37 lines · 18412 lines · CUT · out:7f3a9c1e]
…body…
[end of bash output · exit 1]
```

- at or below `max_inline_tokens` (default 60 000 estimated tokens) the body is the stored text,
  unmodified;
- above, the body is the first `head_lines` and last `tail_lines` (defaults 400 / 400) around a
  marker that names the omitted line range and how to read it, followed by a *pattern scan* of the
  omitted region (lines matching error-like patterns, with their line numbers, capped and labelled
  as a text match, not a reading). Lines longer than `max_line_chars` are cut with an inline
  `…[+N chars]` marker. Binary output is described, not inlined.

The outcome is stated first and last, so it is adjacent to wherever the model is reading. The lines
shown are recorded on the `tool_result` (`meta.shown`); `out_read` and `out_grep` record what they
show of the same blob. `observe::coverage` folds these into "which lines of this output has the
model been shown", which drives the HUD's unseen-output list and the finish gate.

Token estimates use `TokenEstimator`, a chars-per-token ratio calibrated against the server's
reported `prompt_tokens` after every request (start 3.3).

## 7. Ledger (`loom-core::ledger`, `loom-core::journal`)

One journal per mission, `journal.jsonl`: `{n, ts_ms, session, op, mac}` where `mac` is
HMAC-SHA256(key, previous mac ‖ canonical JSON of the entry without `mac`). Appends take an exclusive
file lock, so ids are allocated race-free across processes. A journal that fails verification makes
every ledger write refuse and is surfaced to the operator; the agent cannot repair it.

`LedgerState::fold(entries)` is the only reader. Record kinds (see `ledger.rs`): goal, constraint,
plan step, decision, dead end, claim, evidence, obligation, approval, question, finish claim and
verdict. Rules enforced on write:

- `goal`, `constraint`, `approval` may only be authored from user input (the runtime writes them when
  the user says so; the model has no tool that creates them);
- evidence must name `(session, call_id)` of a `tool_result` that exists in that session's log, and
  the stored blob hash is copied into the record (attestation). A `quote` must occur verbatim in the
  blob within the cited line range. `kind: execution` requires the call's tool class to be `Exec`;
  reading a file is `static`;
- a plan step can be `done` only with a note saying how it was verified or with evidence ids;
- records are never edited: updates are new ops.

`LedgerState::brief()` renders the HUD/resume text; `render_views(dir)` writes Markdown views.

## 8. Agent loop and stop gate (`loom-agent`)

One task per session:

```
wait for a trigger (user message, child settled, job settled, inbox answer, resume)
loop:
    request = weave(log) + HUD            → scheduler slot → stream
    finish_reason = length                → note: "output hit the limit at N tokens; the tool calls in it did not run" → continue
    tool calls present                    → validate, run (read-only calls concurrently, others in order), append results → continue
    no tool calls                         → stop gate
between steps: re-weave check, budget check, cancellation check
```

**Tool-call validation.** Unknown tool → error result listing near names. Arguments are validated
against the tool's JSON Schema; a failure returns the exact path and expectation, not a generic
message. Models with weak tool calling can be run with `tool_choice`/guided decoding per profile.

**Stop gate.** When the model yields without a terminating tool:

- role termination `free` (interactive chat): the turn ends;
- role termination `explicit` (lead, worker, verifier): if the ledger has open plan steps, open
  obligations, unverified claims, or the role's return contract is unmet, the harness appends a
  note listing exactly what is open and continues. After `max_nudges` (3) consecutive nudges without
  progress it opens an inbox item (with notification) and parks the session.

Terminating tools: `finish {summary, evidence}`, `ask_user {question, blocking, meanwhile}`,
`report_blocker {class, what, tried, needs}` (class is an enum of objective blockers; there is no
class for context or elapsed time), `wait {for}` (jobs/children), and for children `return_result`.

**Finish gate.** `finish` is checked mechanically (open steps, obligations, claims without attested
evidence) and then, if the role requires it, by a verifier child: fresh context, read-only sandbox,
the claim and the evidence handles, and an instruction to try to refute. Its verdict must cite the
handles it actually opened (the harness checks its log). Rejection returns the objections to the
agent and the work continues.

**Repetition and staleness.** The runtime flags, in the HUD: the same tool call with the same
arguments and the same output hash seen ≥3 times; a file read before it was last modified by anyone
in the mission; a test/build result older than a later edit.

## 9. Orchestration (`loom-agent`)

- `agent_spawn {role, brief, budget, mode}`; `mode: fresh` starts from the role prompt and the brief,
  `mode: fork` starts from the parent's exact stable prefix plus the brief (full cache hit).
  A brief is typed: `question`, `hypothesis`, `scope`, `do_not`, `return`, `stop_when`.
- `agent_fanout {briefs[]}` starts many and returns when all have settled; `agent_wait`,
  `agent_stop`, `agent_message`, `agent_list`.
- Every child has a budget (`max_steps`, `max_minutes`); exhausting it settles the child as
  `budget_exhausted` with whatever it has returned so far.
- Children end with `return_result {status, answer, quotes[{handle, start, end, text}],
  not_established, evidence}`. The harness verifies each quote against the blob; a failed quote is
  returned to the child as an error. The parent receives a framed, capped, explicitly unverified
  report with a handle to the full text.
- `decide {question, options, k}` forks k voters (different seeds), each must answer with one option
  and a one-paragraph reason; the tally and reasons come back as one result.
- `verify {claim, evidence}` runs the verifier role on demand.
- Stop cascades to all descendants. A settlement arriving at a stopped parent is recorded and does
  not wake it. A stream with no bytes for `stall_timeout_s` is aborted and retried.
- The scheduler bounds concurrent model requests (`max_concurrent`) with priorities:
  interactive lead > children > background (digests, titles).
- Depth and width are limited by role (`may_spawn`), so only a lead fans out.

## 10. Model access (`loom-model`)

- `POST {base_url}/chat/completions`, `stream: true`, `stream_options.include_usage: true`.
- Deltas: `content`, `reasoning` or `reasoning_content`, `tool_calls[]` (index-keyed, `id`/`name`
  on the first chunk, `arguments` appended). `finish_reason`: `stop`, `tool_calls`, `length`.
- Usage: `prompt_tokens`, `completion_tokens`, `prompt_tokens_details.cached_tokens`,
  `completion_tokens_details.reasoning_tokens`.
- Discovery: `GET /models` → `max_model_len` (vLLM), else `context_window`/`context_length`, else
  the configured value. A guess is never silently used: the profile records where the number came
  from.
- Retry: transport errors, 5xx, 429, and a stream that ends before `finish_reason` are retried with
  backoff for up to `retry_window_s` (default 300, long enough for a server relaunch); `Retry-After`
  is honoured by waiting. A partial attempt is never committed. 4xx other than 429 fail the step
  with the server's message shown to the model when it is a request-shape problem.
- No provider fallback. Extra request fields (`reasoning_effort`, sampling, `vllm_xargs`) come from
  the profile verbatim.

## 11. Tools, sandbox, network (`loom-tools`, `loom-net`)

Built-in tools: `bash`, `read`, `write`, `edit`, `glob`, `grep`, `out_read`, `out_grep`, `web_fetch`,
plus runtime-owned tools (ledger, agents, termination, `log_search`). Rules:

- `glob` and `grep` search the same file set (gitignore respected, hidden files skipped) and both
  take `hidden` and `no_ignore`; results are newest-first with "N of M" and a handle to the full list.
- `read` returns numbered lines; `write`/`edit` are atomic and refuse when the file changed since
  this session last read it (the refusal says what changed).
- `bash` runs in its own process group under the sandbox; cancellation sends TERM, then KILL after a
  grace period, to the whole group. A foreground call that exceeds its timeout is promoted to a
  background job (an obligation in the ledger) rather than killed. stdout and stderr are both stored;
  exit code, duration and stderr line count are in the result header.
- The tool set is frozen at session start. External MCP servers are supported as tool providers;
  their instructions are never given system authority.

Sandbox (macOS seatbelt first; a `none` mode exists and is reported loudly): writes are allowed only
under the workspace and a per-session temp dir, and are denied under `<workspace>/.loom`, `~/.loom`,
and configured protected paths; reads of `~/.loom/token` and `~/.loom/keys` are denied; outbound
network is denied except to the loopback egress proxy (and configured loopback ports for local labs).

Egress proxy: HTTP CONNECT and plain-HTTP forward proxy on loopback. Each session gets proxy
credentials, so every decision is attributed. Policy is `open`, `allowlist` (host patterns, `*.`
prefix wildcard, optional port) or `deny_all`, plus a deny list that always wins. Private, loopback
and link-local destinations are refused unless listed. The proxy resolves the name itself and
connects to the address it resolved. Every decision is appended to the session log as a `net` event.

## 12. Daemon API (`loom-daemon`)

Bound to 127.0.0.1. `Authorization: Bearer <token>` or the cookie set by `GET /auth?token=…`.
`Host` and `Origin` are checked. JSON unless noted. Records are served exactly as stored.

```
GET  /api/status
GET  /api/sessions                      → [SessionSummary]
POST /api/sessions                      {workspace, prompt, role?, pack?}
GET  /api/sessions/:id                  → SessionSummary
GET  /api/sessions/:id/records?after=&limit=
GET  /api/sessions/:id/stream?after=    SSE: event `record` (Record), `delta` ({req_id, channel, text}), `state` (SessionSummary)
POST /api/sessions/:id/messages         {text}
POST /api/sessions/:id/stop             {cascade?}
POST /api/sessions/:id/resume
GET  /api/sessions/:id/window           → {epoch, est_tokens, last_prompt_tokens, cached_tokens, items:[{seq, role, kind, est_tokens, state, preview}]}
POST /api/sessions/:id/reweave          force a re-weave (evals)
GET  /api/blobs/:id?start=&end=         text/plain, line range
GET  /api/missions                      → [MissionSummary]
GET  /api/missions/:id/ledger           → LedgerState
GET  /api/inbox                         → [InboxItem]
POST /api/inbox/:id                     {answer}
GET  /api/events                        SSE: `session` (SessionSummary), `inbox` (InboxItem), `status`
```

On start the daemon scans sessions whose last turn did not end, appends `interrupted`, and resumes
those marked unattended. Inbox items raise an OS notification.

## 13. Packs

A pack is a directory: `pack.toml`, role prompts, and optionally a plugin process speaking MCP over
stdio that contributes tools and hooks (`pre_tool`, `hud`, `stop_gate`, `scope`). The built-in `core`
pack has `lead`, `worker`, `verifier` and `chat`. Domain discipline (for example a research pipeline
with scope, threads, evidence tiers and a report gate) is a pack, not core.

## 14. Engineering rules

- Rust 2021, stable. Dependencies come from `[workspace.dependencies]`; add there if you need one.
- No `unwrap`/`expect`/`panic!` outside tests, except on invariants established in the same function.
- Errors are typed per crate with `thiserror`; messages that reach the model say what to do next.
- Every module has unit tests; anything that touches disk uses `tempfile`. Tests never need the
  network or a real model — use `loom_model::mock`.
- No telemetry of any kind. No network access except what this document names.
- Build and test on the build host: `./x test -p <crate>` (never run cargo on the operator's Mac).
