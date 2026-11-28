# Contracts: compaction, fewer scaffolds, completeness facts

Normative for the work merged with it. Each part names the files it owns. When a part is done its
rules move into `docs/DESIGN.md` (and `docs/UI.md` for the UI), and this file shrinks to a pointer.

## Why

Sessions are meant to run for about 30 days; the longest so far ran 3.9 days. In it, each re-weave
landed higher than the last (after-fold estimates 414k → 569k → 709k → 896k tokens) and the last
request was 1.02M tokens: the window was full on day 4. A re-weave shrinks old output to stubs but
keeps every call with its arguments (604k tokens of `tool_call` records in that log), every reply,
and every stub, so what it cannot remove grows with the session. At 30 days that is several times
any window. Every step also re-renders the whole log from record 1.

The fix is a compaction: a model call writes a note that cites keys, the harness builds an exact
table of those keys from the log, and everything older than a short recent tail leaves the window.
Nothing is deleted from the log; every output stays readable by its key.

The other parts follow the operator's review of what the harness should do and what the model should
(2026-11-23): remove hypotheses and the rule engine, keep the deterministic checks, say more about
what a result did not cover, and drop advice the model does not need.

---

## Part K: compaction (replaces re-weave)

Owns: `crates/ferret-core/src/{event.rs, weave.rs, config.rs}`, `crates/ferret-agent/src/{session.rs
(context management, step loop), runtime.rs (route), texts.rs (compaction texts)}`,
`crates/ferret-daemon/src/{api.rs, cli.rs, client.rs}` (compact route, records `before`), docs.

K1. Record. New `Event::Compaction(Compaction)`, additive (old logs load unchanged):

```rust
pub struct Compaction {
    pub epoch: u32,            // previous epoch + 1 (re-weaves count as epochs)
    pub upto_seq: Seq,         // records <= upto_seq leave the window
    pub reason: String,        // "size" | "refused" | "stall" | "operator" | "fresh_start"
    pub before_tokens: u64,    // request size that triggered it (measured, else estimated)
    pub after_tokens_est: u64, // estimate of the first request after it
    pub note: Option<String>,  // the model's note; None when the note request failed
    pub note_req: Option<ReqId>,
    pub table: String,         // the key table, rendered by the harness (K5)
    pub keys: Vec<String>,     // every key listed in `table`, in order
    pub dropped_keys: Vec<String>, // keys the note cited that do not exist (K4), removed from it
    pub objections: Option<String>, // fresh_start: what the verifier objected to
}
```

K2. When. Before each model request of a step:
- `size`: the request size (as `measured_size`, else the estimate) is at or above `compact_at`.
  `compact_at` is `[context] compact_at_tokens`, default 0 meaning 40% of the profile's context
  window, but never above 400_000 (a smaller first request is cheaper to prefill after a cache loss).
- `refused`: the server refused the request for its size or content (today's `Fold::Refused` and
  `Fold::Overflow` cases). Tail is empty (K3) and the note request uses the headers-only window (K4).
- `stall`: the same step request has hit `stall_timeout_s` 3 times and its prompt is at least
  `compact_at / 2`: the size is the likely cause, so compact instead of retrying it again.
- `operator`: `POST /api/sessions/{id}/compact` (`/reweave` stays as an alias), `ferret compact <id>`
  (`ferret reweave` alias). Runs before the next request; on an idle session it compacts without
  starting a turn.
- `fresh_start`: where a fresh start happens today (a `finish` its verifier did not accept, with
  `agents.fresh_start` on). Tail is empty; `objections` carries the verifier's objections.
A compaction whose `after_tokens_est` would not be below 70% of `before_tokens` is still recorded
(unlike a re-weave, it always removes the calls); there is no "not worth it" path.

K3. Tail. `upto_seq` is the seq just before the first record of the recent tail. The tail is the
last whole steps (a step starts at a `model_response`; its calls, results and the notes after them
belong to it) whose estimated size together is at most 15% of `compact_at`, at least the last whole
step when that alone fits within 50% of `compact_at`, else empty. Empty for `refused` and
`fresh_start`. User messages inside the tail stay in the tail.

K4. The note request. `messages` = the current window exactly as the last step request sent it (so
the server's cache of it is used) plus one `user` message: `texts::COMPACT_PROMPT`, then, for
`fresh_start`, `texts::compact_objections(objections)`. Same tools (cache), `max_tokens:
COMPACT_MAX_TOKENS` (12_000), recorded as `model_request{purpose: Compact}`, sent at the session's
priority, watched like a step request but with its stream kept from the sink. Tool calls and
reasoning in the reply are ignored; its text, trimmed, is the note.
- For `refused` and `stall`, the window is first made headers-only: every tool result's content is
  replaced by its first line (the `[tool · … · out:…]` header) and last line, every agent report is
  cut to its first 2_000 characters. If the server refuses that too, there is no note.
- Keys in the note: every `out:` followed by 8 to 64 hex characters must be the handle (or a prefix
  of exactly one handle) of a stored output of this session; every ledger id (`p`, `c`, `e`, `n`
  followed by digits, as the ledger names them) must exist. Unknown ones: one retry, appending the
  reply and `texts::compact_unknown_keys(&keys)` to the same messages. Still unknown: each is
  replaced in the note by `[unknown key]` and listed in `dropped_keys`.
- Error, cancellation of the request (not the session), empty text: `note: None`. A compaction never
  fails because its note did; it never blocks the session.

K5. The key table, built by the harness from the records `<= upto_seq`, the ledger and the previous
compaction's table. Deterministic (same log, same table). Sections, each omitted when empty:

```
Outputs — read one with read(path: "out:<key>"); search everything with log_search
out:e134a0f0b4bf46c1 · bash · python3 public_sequence.py · exit 0 · 7 lines · step 412, 11-19 14:02
out:cc8752638528652e · edit · crates/ferret-agent/src/runtime.rs · edited · +3 −2 · step 418
… 1,204 earlier outputs (steps 1–380) are not listed: search them with log_search.
Files changed by edit/write (shell commands are not tracked)
crates/ferret-agent/src/runtime.rs · +3 −2 · 2 edits · last out:cc8752638528652e
Agents
s-fl-web · Solver: web build hooks · web_solver · finished · report out:5a1c…
Jobs still running
j4 · cargo test --workspace · since step 410
```

Output rows (16-hex keys; `what` is the command, path or pattern cut to 80 characters; outcome as
the result header says it; size in lines; step and local date-time): rows for outputs (a) the
ledger cites, (b) the note cites, (c) of the last 40 calls before the tail, (d) listed in the
previous compaction's table. At most 400 rows: drop (d) oldest first, then (c) oldest first; (a) and
(b) are kept, newest first, up to 800. Every other output of the session is counted in the "not
listed" line. Files: every path an `edit`/`write` result changed (as the UI's Files changed). Agents:
every child of this session. Jobs: every job not settled at `upto_seq`.

K6. The window after a compaction (weave). System message, then one `user` item
`<harness kind="compaction">` holding, in order:
1. `texts::compaction_head(step, reason)`: "Context was compacted at step {n} ({reason}). Earlier
   messages are out of view; nothing was deleted. Read any output by its key with read (path
   `out:…`); log_search searches the whole log."
2. The operator's messages `<= upto_seq`, verbatim, oldest first, each headed `Operator, step {n},
   {date}:`. When together they pass 20% of `compact_at`, the oldest are replaced by one line each
   (their first 120 characters and `log_search` for the rest) until they fit.
3. The ledger brief, as `ledger.brief(hud::brief_opts(..))` renders it today.
4. Pinned outputs (`pin`), newest first, verbatim, together at most 10% of `compact_at`; the rest are
   rows in the table.
5. The key table (K5).
6. When there is a note: "Your note from before the compaction (written by you, not verified: check
   a key before relying on it):" and the note.
Then every record after `upto_seq`, rendered as today. A compaction replaces the previous one:
nothing before the latest compaction's `upto_seq` renders. Re-weave records before a session's first
compaction keep rendering as today (old logs); no new `reweave` record is ever written.

K7. Weave cost. The weave starts at the latest compaction record: a step renders the records after
its `upto_seq` (plus the compaction item), not the whole log. The session finds the latest
compaction once at open and on each new one. (Keeping only those records in memory is a follow-up.)

K8. Removed: `plan_reweave`, `plan_fresh_start`, the digest request and `DIGEST_PROMPT`, stubs and
evictions for new records, `ReweavePolicy::{floor_tokens, keep_recent_steps, stub_tail_lines}`.
`[context]` keeps loading old configs: those keys are accepted and ignored (with a startup warning),
`target_tokens` is read as `compact_at_tokens` when the latter is absent.

K9. `texts::COMPACT_PROMPT` (exact):

> Your context is about to be compacted. Everything above will be taken out of view and replaced
> by: the operator's messages, the mission ledger, a table of keys for this session's outputs,
> files, agents and jobs (built by the harness from the log, so it is exact), and the note you write
> now. Nothing is deleted: any output stays readable by its key with `read` (path `out:` and the
> key), and `log_search` searches the whole log.
>
> Write the note you will need to carry on without rereading everything. Cite keys rather than
> copying output: an output as `out:` with the key exactly as its result header shows it, a ledger
> item by its id (p2, c3, e5). Copy text only when it is short and you will need it word for word: a
> command line, an error message, a value.
>
> Use these headings, each with a short list:
> ## Goal — what the operator wants, in your words, and every instruction of theirs that still applies.
> ## State — where the work stands now: what exists or was changed, what is running, with keys.
> ## Established — what a run has shown, each with the key that shows it.
> ## Ruled out — what a run disproved, with the exact boundary of what was tested and its key.
> ## Tried, not settled — attempts that failed without disproving their approach, and what would have to change.
> ## Open leads — what you have not followed up yet, and where it is: files and lines, commands, keys.
> ## Next — the step you had decided to take next, and why.
>
> Be specific. Do not retell the session in order. Do not call tools. At most 1,500 words.

`texts::compact_objections(o)`: "The verifier did not accept your last finish: {o} Do not list the
result it rejected under Established; put what it objected to under Tried, not settled."
`texts::compact_unknown_keys(k)`: "These keys do not exist in this session: {k}. Write the note again,
citing only keys that appear in the result headers above."

K10. Records page backward: `GET /api/sessions/{id}/records?before=<seq>&limit=n` returns the n
records before `seq`, oldest first, with `prev_before` (the seq to ask for next, or null at the
start). `after` and `before` together are a 400.

K11. Tests: a size compaction removes every call before the tail (no stub, no call left); the next
request carries the compaction item and the tail only; weave of a log with a compaction renders
nothing before `upto_seq`; table determinism (same log twice); table row choice and caps; unknown
keys retried once then dropped; failed note request still compacts; headers-only window for
`refused`; `stall` after 3 stalls; `fresh_start` with objections and an empty tail; operator route on
an idle session; old log with re-weaves still renders the same until its first compaction; config
with old `[context]` keys loads; records `before` paging. A long-run test: a scripted session of
5,000 steps with outputs of 2k tokens and `compact_at` 50k never sends a request above `compact_at` +
one step, and its first request after each compaction is below 40% of `compact_at`.

---

## Part H: hypotheses and the rule engine come out of the harness

Owns: `crates/ferret-core/src/security_state.rs`, `crates/ferret-core/src/security_state/causal.rs`,
`crates/ferret-agent/src/rtools/security.rs`, `crates/ferret-agent/src/rtools/security/shapes.rs`,
`crates/ferret-agent/src/{prior.rs, frontier.rs, hud.rs}` (their hypothesis and projection parts),
packs' texts that mention them.

H1. `security_record` no longer offers `hypothesis_open`, `hypothesis_priority`,
`hypothesis_evidence`, `hypothesis_verdict`, `rule_install`, `rule_retract`; a call with one is
refused: "Hypotheses are not recorded in the security state any more: write the idea as a note
(`note` with kind `decision`) or test it and record what the run showed." `security_query` no longer
offers `hypotheses`, `facts`, `why`, `what_if`, `path_suggest`. The Datalog projection, its rules and
`path_suggest` are removed with their tests; the HUD and the brief no longer show hypotheses or
derived facts; `prior` no longer carries hypotheses into a new mission; `frontier` no longer reads
them.
H2. Old records with those operations still load (the variants stay deserializable) and are ignored
when the state is projected. Verdict, coverage, assets, credentials, footholds, crash signatures and
conditions are unchanged.
H3. Repairs instead of refusals (113 of 411 `security_record` failures were these): a host given with
a scheme, port, path or credentials is reduced to the host; an endpoint or service URL without a
scheme gets `https://` when its port is 443 and `http://` otherwise; `ops` is read as `operations`.
Each repair is said in the result, as other argument repairs are.

## Part N: say what a result did not cover

Owns: `crates/ferret-tools/src/{bash.rs (facts only), search.rs, fstools.rs (read facts), lib.rs
(meta)}`, `crates/ferret-agent/src/rtools/agents.rs` (report header), the verifier's request text.

N1. `bash`/`box_exec`: the proxy decisions in the session's `net.jsonl` stamped between the call's
start and its result are counted; when any was denied, the fact `network: {k} connections denied
({up to 3 hosts})` and meta `net_denied: k`. (A command that "found nothing" because its traffic was
refused must say so.)
N2. `grep`/`glob`: entries the sandbox made unreadable are counted (today they are skipped
silently): fact `{k} entries unreadable in the sandbox were skipped`.
N3. `read`: when the file changed since this session last read it, the fact `changed since your
last read (step {n})`.
N4. An agent report from a child that ended by budget, an operator stop or an error starts with
`[incomplete: ended by {budget|operator stop|error} at step {n}]`.
N5. Every tool result's meta gets `complete: false` and `limits: [..]` (short words: `cut`,
`timeout`, `idle stop`, `output limit`, `net denied`, `unreadable skipped`, `search cap`, `child
incomplete`) when any applies; none when complete. The verifier's request lists, next to each piece
of evidence it is shown, the limits of the output it cites. Information only: nothing is refused for
it.

## Part T: less steering, fewer tool mistakes

Owns: `crates/ferret-agent/src/{gate.rs, rtools/terminal.rs, rtools/agents.rs, texts.rs (nudge and
refusal texts), session.rs (nudge decisions only)}`, `packs/*/pack.toml`, `pack.rs` tests.

T1. A harness message names only tools the role is shown: every `has(..)` that decides wording uses
the shown tools (role tools minus `hidden_tools`). `conclude` → `finish` with `status`; `wait` →
`job_wait` without `job`; `agent_stop` → `agent_message` with `stop: true` (T4). The §4.4 guard test
is extended to the runtime's messages: each message builder is run for every role of every built-in
pack and must not name a hidden tool in backticks.
T2. Removed: the stall note (`texts::stall`, "the last N steps recorded nothing…") and the idle-goal
paragraph of the yield nudge. The "ended without a tool call" nudge is sent at most once per turn; a
second text-only reply in the same turn ends the turn (as `implicit_finish` would, or `yielded`).
T3. Nothing else changes in retries: `retry_window_s = 0` still retries an unreachable server until
it returns. A request that stalls because of its size is compacted (K2 `stall`).
T4. `agent_message` takes `stop: true` (text optional then): it stops the agent as `agent_stop` does
and says so in its result; `agent_stop` stays as a hidden alias. The core and harnessmm leads show
`agent_message` again (23 tools). `fresh`/`fork` and the rest of spawning are unchanged.

## Part U: the UI for compaction and long sessions

Owns: `ui/`, `tools/ui-preview.mjs`, `docs/UI.md`.

U1. A `compaction` record renders as a divider card: "Context compacted · step {n} · {before} →
{after} tokens · {reason}", with two collapsed parts: "Note" (rendered as a reply, with every
`out:` key a link that opens the output viewer) and "Key table" (monospace, keys linked the same
way). `dropped_keys`, when any, are listed under the note.
U2. Session sheet and Context tab: "Compact now" (replaces the re-weave action), confirm with "The
model writes a note and everything before the last few steps leaves its view; nothing is deleted."
U3. Context tab parts: "Compaction" (head, operator messages, ledger, pins, table, note) replaces
"Re-weave brief" and "Folded-out stubs"; the threshold line says "compacts at {compact_at}".
U4. Long sessions load from the end: on open, the page loads the records after the latest
compaction's `upto_seq` (or the last 1,000 records, whichever is more) with `before` paging, enables
Send as soon as those are in, and loads earlier pages when the reader scrolls to the top ("Load
earlier records") or Find asks for them.
U5. Fixture: a session with two compactions (one with a note citing keys, one `fresh_start` with
objections, one with a dropped key) and a long session that pages backward.
