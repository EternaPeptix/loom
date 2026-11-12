# What loom does about the DSH and dsh-vr findings

loom was designed after auditing DeepSeek Harness (DSH) source and the dsh-vr research plugin, and
measuring their behaviour on real session logs. This document takes the findings of those reviews,
grouped by theme, and for each says the mechanism in loom that answers it and the evidence that it
works. "Live" evidence is from missions run against the real dsv41 server on the LAN on 2026-11-11;
session ids are under `~/.loom/sessions/` on the build host.

The through-line: in DSH the *model* is asked to manage context, judge its own certainty, and not
leak — all by prompt. In loom those are mechanisms the model cannot see or skip, so a small model
gets the same discipline as a large one. That is the point of the rewrite.

---

## 1. Context and compaction

| DSH finding | loom |
|---|---|
| Compaction summary reuses no prompt cache (112–145 s each). | There is no summary step. The window is a pure function of the append-only log (`weave`); folding out old material is an eviction recorded in a `reweave` event, and the request prefix stays a growing prefix, so it is a cache hit. When narration must go, a *digest* request is sent **on the existing prefix** — a full cache hit — and stored in the `reweave` record. |
| Summary drops user messages (600k–725k tokens → 6–10k chars). | User messages and the system prompt are never evicted. Enforced in `plan_reweave` (protected classes) and checked live. |
| Cut content has no path back (pruner cuts >8192 chars, no locator). | Every tool output is stored whole first; the model is shown an envelope with a handle; eviction replaces the body with a stub **carrying the same handle**, so `out_read`/`out_grep` reach the original bytes. |
| One fullness threshold for all windows; model told nothing true about context; it remarks "limited context" at <25%. | Fullness is **never** an input to the model. No gauge is shown; the HUD never mentions context, message count or elapsed time. Re-weave fires on absolute token targets per model profile. The role prompt states that context is managed and is never a reason to stop. |
| Output cut-offs are silent; tool calls dropped on length. | A `length` finish appends an explicit `output_cut` note; tool calls cut off mid-emission are marked incomplete and never run or rendered (so the model is told, not silently truncated). |

**Live (`s-1m76jpc57gdaqs09`, targets shrunk to 12k/6k to force it):** 18 re-weaves fired, each
pulling a 26–30k working set back toward ~6k and holding there; **0 cache-break records**; the user
message (seq 1) and system prompt stayed `state=live` and verbatim through all 18; the planted
needle (log3 line 843) was still found after the reads that contained it had been evicted.

## 2. Prompt cache / eviction

| DSH finding | loom |
|---|---|
| Tool-list changes discard the whole prompt cache (41.6M tokens re-read in 7 days). | The tool set is frozen at `session_start` and never changes mid-session; a forked child keeps the parent's tool list exactly (role restrictions are enforced at call time, not by editing the list). |
| System-prompt edits rewrite the whole prefix on the vLLM route. | The system message is fixed for the session's life; request fields that some templates render into the prompt head (reasoning effort, sampling) are fixed per session too. |
| Prefix invalidation is invisible to plugin authors. | A `PrefixGuard` compares each request's stable messages to the previous one's; any non-growth difference appends a `cache_break` event and fails tests. |

**Live:** 92–97% server-reported prefix cache across every mission including fan-out and verifier
children; a standalone client check measured 99.4–99.9% on a stable prefix. Zero `cache_break`
records in any session run.

## 3. Observation — tool output is the work

This is the area the operator asked to be first-class, and it is not a DSH "finding" so much as the
reason for the rewrite.

- Tool calls are native and are **never** paraphrased into prose, reordered, or separated from their
  results; results come back in call order; an evicted result is still a `tool` message in place.
- Every result is one envelope: `[tool · outcome · duration · size · out:handle]`, body, then a
  footer repeating the outcome (the end of a long result is what a model attends to). The header is
  written by the harness from facts, not by the tool's text.
- A cut is explicit: which line ranges are shown, which are omitted, and the handle to page/search
  the rest. A pattern-scan of the omitted region surfaces error/warning lines by number.
- The harness tracks which lines of every output were put in front of the model; a claim's evidence
  may only quote lines that were shown, and quotes are checked **verbatim** against stored bytes.

**Live (`s-1m76jbjhgkefe4sw`, code review fan-out):** the lead recorded a *decision* to report each
module's real defect from observed behaviour rather than its inline `# BUG:` comment — the comment in
`parse.py` misdirected, and observing caught it. A worker's evidence quote that was off by a line was
**rejected** by the harness ("the text does not occur in out:… lines 22-23") and re-quoted. The
consolidated finish carried MD5 checksums proving no file was edited.

## 4. Orchestration

| DSH / dsh-vr finding | loom |
|---|---|
| Child output is unframed and unbounded. | A settled child is rendered to its parent as a framed `<harness kind="agent-report" agent=… outcome=…>` block, capped, explicitly marked unverified, with a handle to the full text. |
| Stop does not reach child agents. | Stop cascades to all descendants; a settlement arriving at a stopped parent is recorded and does not wake it. |
| Default workflow concurrency overruns the subagent pool; children have no budget. | Every child has a step/time budget and settles `budget_exhausted` with what it has; the model scheduler bounds concurrent requests with priorities (lead > children > background). |
| Model "schedules" replay as user messages; settlement notices dropped when parent not live. | Children settle through typed records; a non-awaited settlement is delivered as an arrival that resumes a waiting parent, and is otherwise recorded for when it next runs. |
| A claim is accepted without an independent check. | `finish` is gated mechanically (open plan steps, obligations, unverified claims) and then by an independent **verifier child** with fresh context and a read-only sandbox, whose verdict must cite the handles it actually opened. |

**Live (`s-1m76jbjhgkefe4sw`):** `agent_fanout` to 3 workers returned three framed reports, each with
harness-checked quotes and a handle; the lead then **independently re-ran** each claimed bug before
consolidating. Every `finish` in every mission was accepted by a verifier child (e.g. edit mission
`s-1m76jbr1tp7qkdwa` verified by `s-1m76jdhwtjzdaegv` over 12 steps).

## 5. Nothing leaves the machine unless configured

| DSH finding | loom |
|---|---|
| Session-log upload on by default for the DeepSeek adapter. | No upload path exists. Model requests go only to the configured endpoint. |
| Feedback upload sends the unredacted session. | There is no feedback channel. |
| Desktop product analytics on by default, no toggle (device id, event names). | No telemetry or analytics of any kind is compiled in. |
| Remote images load with no CSP. | The UI serves a strict CSP (`default-src 'none'`), no inline script or style, no remote origins. |
| A hosted-API request fired from a workspace session. | No provider fallback; the only outbound destinations in the binary are the CLI→daemon loopback, the configured model endpoint, the loopback egress proxy, and `web_fetch` **through** that proxy. |

**Live:** source grep finds no telemetry/analytics/phone-home (the only matches are `segments()` on
IP octets and a path-sanitising `segment()`); under `network.mode = "deny_all"` the egress proxy
allowed 0 outbound connections; private/loopback/link-local destinations are refused unless listed.

## 6. Unattended runs

| DSH finding | loom |
|---|---|
| An unhandled rejection exits the Host; no auto-restart. | The daemon is supervised and log-recovered: on start it scans sessions whose last turn did not end, writes an `interrupted` record, and resumes those marked unattended. |
| Jobs vanish on restart; process trees orphaned. | Background jobs are recorded as obligations; their output is stored and survives a crash; the job table resumes job numbering from the log. |
| Approvals/questions wait forever; no OS notification. | Anything waiting on a human opens an inbox item that raises an OS notification with a repeat policy. |

**Live (`s-1m76jzp8pnhvfdwt`):** the daemon was `kill -9`'d mid-turn; on restart the session got
exactly **1 `interrupted` record** and resumed on its own (step 2 → 4); the background job it had
started (`tick 1`…`tick 8`) **survived the crash** with its stored output intact.

## 7. Permissions and enforcement outside the agent's reach

| DSH / dsh-vr finding | loom |
|---|---|
| Full-access mode lets the agent install Host code without a prompt; a sandbox command can plant project skills. | Harness state, keys, config and the tool set live outside the sandbox's writable area. The tool set is frozen at session start; there is no "install a tool" path for the model. |
| "Operation not permitted" reported as a sandbox denial regardless of cause. | Tool status distinguishes `denied` (policy) from `error` (the tool ran and failed) from `invalid` (nothing ran); denials name the rule. |
| Writes not confined to the workspace; token/keys readable. | A macOS seatbelt sandbox allows writes only under the workspace and the session temp dir, denies writes under `~/.loom` and `<workspace>/.loom`, and denies reads of `~/.loom/token` and `~/.loom/keys`. File tools also refuse writes to content changed since the session last read it (staleness guard). |
| dsh-vr: allowlist fails open; host guard not installed when the deny list is empty; a judge can't see the URL it judges. | Network scope is an egress proxy plus an OS sandbox that permits no other route — not shell-text parsing. Every decision is attributed to a session and logged as a `net` event; the proxy resolves the name itself and connects to the address it resolved. |

**Live:** sandbox profile verified in isolation on the host — writes outside the workspace denied,
writes under `.loom` denied, `~/.loom/token` unreadable, direct network denied except the proxy
port, symlink escape denied, signalling processes outside the sandbox denied. The edit mission showed
the read-before-write staleness guard in use.

## 8. State discipline (from the dsh-vr review)

dsh-vr used Markdown as a database and hit escaping bugs, newline injection, and concurrent writes
overwriting each other. In loom, mission state is a typed, append-only, HMAC-sealed journal
(`ledger`); Markdown is a generated view that is never parsed. Appends take an exclusive lock so ids
are race-free across processes; a journal that fails verification refuses every further write and is
surfaced to the operator, not repaired by the agent. Evidence records point at a `(session, call)`
and carry the stored output's hash; a quote must occur verbatim in that output.

**Live:** every mission with a goal built a ledger (goal → plan → claims → evidence → finish);
quote-checking rejected a misaligned quote; finishes were gated on open items.

---

## What is proven, and what is not yet

**Exercised live against dsv41:** single-task missions, a 3-worker code-review fan-out with
independent re-verification, a multi-file edit with staleness guard and verifier, an 18-re-weave
compaction stress run with needle retrieval, hard-crash restart recovery with job survival, and
deny-all egress. 680 tests pass; clippy is clean.

**Not yet exercised:** a digest-backed re-weave on genuinely huge single outputs (the stress run
evicted by stub before a digest was needed); the notification repeat timer; a long (hours) autonomous
run; a domain pack mirroring the research workspace (`AGENTS.md`) rather than the general `core` pack.
These are the next missions, not gaps in the design.

## Runtime regression coverage added on 2026-11-12

The runtime recovery changes were checked with 740 passing Rust workspace tests on an isolated
build-host lane, 42 passing browser-core tests, and a native desktop DEBUG build with passing
self-checks. These are regression and mock-model checks, not additional live dsv41 evidence.

- Child results: full typed reports, long-answer handles, payloads and usage survive interruption
  after the outbox or before parent acknowledgement. Repeated delivery produces one child-id
  receipt; stopped awaited children and archived-family joins retain their results. A crash between
  an awaited tool result and its inline acknowledgement can still repeat report text on recovery.
- Mission state: fresh and forked workers and fresh verifiers receive the current mission state
  independently of their brief. Protected text stays verbatim; workers write only notes and their
  own claims/evidence, verifiers cannot write, and an unreadable journal stops child execution.
- Processes: tests retain leaderless descendants, late output, cancellation and output limits;
  zombie-only groups complete, and mismatched restored leaders are refused. This covers the original
  process group, not descendants that escape it or universal identity across numeric PGID reuse.
- Desktop SSH: endpoint/argument and occupied-port self-checks enforce matching local/remote ports
  without relaxing daemon Host/Origin checks. No new live desktop-to-daemon SSH integration run is
  claimed by these checks.
- [Guarded continuations](HARNESSMM.md): the opt-in prototype demonstrably omits actor callbacks
  while preserving literal native calls, budgets, output records and fallback. Failed/incomplete
  receipts, changed inputs/rules, new instructions, cancellation and restart are covered. Deferred
  controller output is not credited as model-observed before a completed actor request includes it.
  Real-model quality and performance, including comparison with ordinary tool/shell batching,
  remain unmeasured.
