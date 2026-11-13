# loom — design

loom is an agent harness for long, unattended work on a locally hosted model. It was designed after
auditing an existing harness (DSH) and a research-discipline plugin (dsh-vr) and measuring their
behaviour on real session logs. This document is normative: where code and this text disagree, one of
them is a bug. Where a module's documentation is more detailed than a section here, that module
documentation is the precise specification and the section is the overview; the sections name those
modules. What earlier versions of this document described and the code does not have is listed under
*Roadmap* at the end; nothing listed there may be relied on.

## 1. What it optimises for

The deployment it is tuned for: one operator, an OpenAI-compatible server on the LAN (vLLM, 1M-token
window, automatic prefix caching, several concurrent sequences), sessions that run for hours without
anyone watching, and work where *what was actually observed* matters more than fluent prose.

That inverts the usual cloud trade-offs:

- **Tokens cost nothing; rebuilding the prefix costs latency.** A cached prefix is free, an edited one
  is re-read from the edit point. So the request prefix is append-only except at explicit, logged
  re-weaves, and nothing is ever trimmed "to save tokens".
- **Forking is free.** A child that starts from its parent's exact prefix gets a full cache hit, so
  delegation and voting can start with everything the parent knows.
- **The model is the weakest component, so it gets the smallest job.** The harness owns process,
  memory, bookkeeping and verification; the model fills typed slots inside narrow steps. A capable
  model is not slowed by this and a small one is carried by it.

## 2. Principles (each is enforced by a mechanism, not a prompt)

1. **The log is the record; the window is a view.** Every session is an append-only, hash-chained
   event log on disk. The context window is a pure function of that log (`weave`). It can be rebuilt
   at any time, so a restart, a crash and an eviction are the same operation.
2. **Window fullness is never an input to a model decision.** The model is told once, in the pack
   preamble, that context is managed and is never a reason to stop, defer or summarise. No gauge is
   shown. Budgets that do exist (steps, active time) are the harness's to enforce, not the model's to ration: no running count is shown, only one heads-up when a budget is nearly used, and the harness parks on exhaustion regardless.
3. **Tool output is admitted whole.** If it cannot be, the cut is explicit (which lines were omitted,
   sizes, outcome) and the full output stays addressable by a handle the model can page and search.
   Later eviction replaces old output with a stub carrying the same handle. Nothing is ever lost
   silently; "evicted" is always distinguishable from "never happened".
4. **Authorship is preserved.** Every record has an author (`user`, `model`, `tool`, `harness`, or
   another agent). Model-written text never appears under harness or user authority: text the
   harness embeds in its own blocks cannot open or close a harness tag, and an agent's words inside a
   harness-built report are fenced line by line. User messages are kept verbatim for the life of the
   session.
5. **State that must survive lives in the ledger, written at decision time.** Goal, constraints,
   plan, decisions, dead ends, claims, evidence, approvals and questions are typed records in an
   append-only sealed journal outside the workspace. Markdown is a generated view, never parsed.
6. **A claim rests on evidence the harness witnessed.** Evidence records point at a tool call in a
   session log and the id (SHA-256) of its stored output. The harness resolves the pointer when the
   record is written, accepts only observations (command output, file reads, fetched records), never a
   message from the harness, another agent's text or the model's own words played back, and checks
   quotes against the stored bytes.
7. **Stopping is an act, not a drift.** A turn that ends without tool calls goes through the stop
   gate. Work ends through `finish` (gated, and for a lead independently verified), `ask_user`,
   `report_blocker` or `wait` — each validated; a verifier ends with `verdict`. "Context" and "it has
   been a long time" are not blockers.
8. **Enforcement sits outside the agent's reach.** Harness state, keys, config and the tool set are
   outside the sandbox's writable area. Network scope is enforced by an egress proxy plus an OS
   sandbox that permits no other route, not by parsing shell text.
9. **Nothing leaves the machine unless configured.** No telemetry, no analytics, no fallback
   provider. Model requests go only to the configured endpoint, and tools reach no host at all until
   the operator chooses a network mode other than the default `deny_all`.
10. **Unattended is the default.** Every session is recovered from its log after a crash or restart
    (and the daemon can run as a launchd agent that restarts it), cancels reach every child, every
    child has a budget, tools that ignore cancellation are killed, and anything waiting on a human
    raises a notification, repeated while it waits when configured.
11. **Observation is the work.** For the work this is built for, the output of a tool call *is* the
    finding, so the harness never paraphrases, summarises or silently shortens it. What the model is
    shown is the stored text (after a lossless-by-line normalisation) inside an envelope that states
    the tool, the outcome, the size and the handle at both ends. The harness tracks which lines of
    every stored output have actually been put in front of the model (`loom_core::observe`), lists
    executions with unseen lines in the HUD, labels a pattern scan as a text match rather than a
    reading, and refuses evidence whose quote is not in the stored text.
12. **Tool calls are replayed exactly.** Every complete call the model made is replayed with its
    arguments byte for byte, paired with exactly one result, in call order, for the life of the
    session. When the window must shrink, replayed reasoning goes first, navigation output second,
    file reads third, every other output after them, and what is evicted leaves a stub that names the
    call, its outcome and the handle. A call without a recorded result is rendered as such; a call
    that was cut off by an output limit, or whose arguments are not a JSON object, is never run or
    replayed, and the model is told so.

## 3. Shape

```
loom (one binary, built from loom-daemon)
  loom daemon        long-lived local process; owns everything below
  loom <command>     thin client over the daemon's HTTP API (loopback, bearer token)
  web UI             served by the daemon at /

crates/
  loom-core    types, event log, blob store, weave/eviction, admission, observation, ledger + journal,
               harness-tag safety, config and paths                                   (sync, pure)
  loom-model   OpenAI-compatible streaming client, retry across server relaunch, request limiter,
               mock server
  loom-tools   Tool trait + registry, argument checking, built-in tools, process control and jobs,
               sandbox
  loom-net     egress proxy, scope policy, chained audit file
  loom-agent   runtime: sessions and their step loop, stop and finish gates, runtime tools,
               orchestration, HUD, packs, operator notifications
  loom-daemon  HTTP/SSE API, authentication, CLI, embedded UI
packs/         role packs: core (also built into the binary) and vr
ui/            static web UI (no build step), embedded into the binary — docs/UI.md
gui/           loom-desk, a macOS menu-bar app around the web UI — gui/DESIGN.md
tools/         import-dsh.py: imports DSH sessions as ended, read-only loom sessions
```

The command line (`loom --help`): `daemon`, `up`, `down`, `status`, `open`, `run`, `chat`, `ls`,
`tail`, `send`, `stop`, `resume`, `reweave`, `archive`, `rule`, `approve`, `gc`, `inbox`, `answer`,
`ledger`, `window`, `net`, `out`, `config`, `service` (the module documentation of
`loom_daemon::cli` is its specification).

The state root is `~/.loom/` (override `LOOM_HOME`), never inside a workspace. Every directory the harness
creates under it is 0700 and every file 0600, set at creation (the process umask is not changed, so commands
keep the user's umask in the workspace); at start the daemon also tightens the home, `keys/`, `sessions/`,
`missions/`, `blobs/` and `logs/` to 0700 when they exist with group or other access.

```
config.toml                          optional; every key has a default, unknown keys are errors
token                                0600, the API bearer token (64 hex)
keys/journal.key                     0600, HMAC key for ledger seals
daemon.lock                          0600, empty; locked by the running daemon, never removed
daemon.json                          {pid, bind, started_ms} of the running daemon
packs/<name>/                        installed packs (one named core replaces the built-in one)
sessions/<sid>/log.jsonl             the session event log
sessions/<sid>/log.jsonl.damaged-<ms>   bytes cut off a damaged log
sessions/<sid>/meta.json             what the session is; fixed at creation except `archived`
sessions/<sid>/status.json           its latest status
sessions/<sid>/net.jsonl             its egress decisions, hash-chained
sessions/<sid>/settlement.json       a child's settlement, kept for a delivery a restart cut
sessions/<sid>/queued/               operator rules, approvals, withdrawals not recorded yet
sessions/<sid>/jobs/                 jN.out, jN.status, jN.pid of its commands
sessions/<sid>/tmp/                  the session temp dir ($TMPDIR of its commands); emptied when the session ends for good or is archived
blobs/<aa>/<id>, blobs/<aa>/<id>.idx content-addressed tool output (id = SHA-256) and its line index
blobs/tmp/                           writes in progress, and blobs a collection is removing
missions/<mid>/journal.jsonl         the ledger journal of one mission
missions/<mid>/journal.jsonl.lock    its lock file
missions/<mid>/journal.head          its sealed head record
logs/loomd.log                       the daemon's output when started by `loom up` or as a service
logs/net-unattributed.jsonl          proxy answers that name no session, hash-chained
```

Files made atomically (the token, the journal key) go through a synced temporary file
`.<name>.<16 hex>.tmp` that is hard-linked under the final name; a leftover one is harmless and may be
deleted. Session ids are `s-…` and mission ids `m-…` (time-sortable). An id made only of ASCII letters,
digits, `-`, `_` and `.` (1 to 128 bytes, not starting with `.`) is used as a directory name; any other
id maps to `sessions/.unsafe-ids/<sha256>` (or `missions/…`), so a lookup for it finds nothing and
nothing can reach outside the home.

A **mission** is one goal pursued by one lead (root) session and the agents it starts. When the
lead's role ends explicitly the mission keeps a ledger, which the lead and all its agents share.

## 4. Events and the log (`loom-core::event`, `loom-core::log`)

`event.rs` is the normative schema; `log.rs` documents the file contract precisely. One JSON object
per line:

```
{"seq":12,"ts_ms":1794434009000,"author":"model","prev":"<sha256 of previous line>","kind":"model_response", ...}
```

- `seq` starts at 0 (`session_start`) and increases by one. `prev` is the SHA-256 of the previous
  line's bytes without its newline (the first line uses 64 zeros). `author` is `"user"`, `"model"`,
  `"tool"`, `"harness"` or `{"agent": "<session id>"}`. The `session_start` record carries the log's
  schema number (`event::SCHEMA`, now 1).
- Appends are a single write of a complete line followed by `sync_data` (`Durability::Always`, which
  every session uses). Intent is durable before side effects: a call's `tool_call` record is appended
  and synced before the tool runs in its turn. The one exception is the early start of side-effect-free
  lookups (§8): they may begin before their `tool_call` record exists, and their result is used only
  after it has been appended.
- Creating a log syncs its directory. Creating or opening a log for writing takes an exclusive,
  non-blocking advisory lock on the file, held for the life of the writer; a second writer, in this
  process or another, is refused (`LogError::Locked`). Readers take no lock.
- Opening a log never fails on damage. Reading stops at the first line that is incomplete, is not a
  JSON object with `seq` and `prev`, has the wrong `seq`, or has a `prev` that does not match.
  Everything after the good prefix (a torn final line included) is moved to
  `log.jsonl.damaged-<ms>`, the file is truncated to the prefix, and the session records an
  `interrupted` event describing the damage and continues from the last good record.
- A record of a kind this build does not know is read as `Event::Unknown`: it stays in the file as
  written, advances the chain, and is ignored by the weave and by every fold of session state.
- A line whose chain header is right but whose body this build cannot read otherwise (a value written
  by a newer loom) is not damage: it is kept as an opaque record (also `Event::Unknown`), advances the
  chain, and is ignored the same way — unless the next line has the next `seq` but does not chain to
  it, in which case it is damage. A log with opaque records, or whose `session_start` carries a
  higher schema than this build's, can be read but is refused for writing (`LogError::Newer`) and
  left untouched, so the session is not run.
- `read_records`, `read_page` and `PageReader` read under the same stopping rule and change nothing.
  A `PageReader` keeps checkpoints of what it has verified, so that pages fetched in sequence cost
  time proportional to the page; the runtime keeps one per session for the 16 most recently paged
  sessions. A `PageReader` also hands out the stored line of every record it reads as
  `Event::Unknown`, and the API serves that line in place of the parsed record (§12), so such a
  record reaches clients with every field.
- A forked child's log starts with a byte-identical copy of its parent's lines up to the fork point,
  followed by its own `forked` record. Each line is checked as `open` checks it before it is copied
  (a whole line, not opaque, the expected `seq`, a `prev` that matches); when one fails, the fork is
  refused with a sentence naming that record and no child log is left, so a child never inherits a
  prefix that its next open would cut back together with its own records.

## 5. The weave (`loom-core::weave`)

`weave(records) -> Weave` renders the stable request prefix. It is deterministic: same records,
same bytes. The module documentation of `weave.rs` is the precise specification (pairing, merging,
eviction actions, the protected region); this section is the overview. Rendering rules:

| Record | Rendered as |
|---|---|
| `session_start` | `system` message: the system prompt fixed at creation — the pack preamble, the role prompt, and an `# Environment` section (workspace, platform, sandbox, network) with nothing that changes between requests. The tool specs come from this record and never change mid-session. |
| `forked` | `user`-role `<harness kind="assignment" from="{parent}">` block holding the fork contract (the child's role, prompt and tools) and the brief. The records before it are the parent's and render exactly as they do for the parent. |
| `user_message` | `user` message, verbatim. |
| `harness_note` | `user`-role `<harness kind="{kind}">…</harness>`; with `from="{id}"` when another agent authored it (an assignment, a message from the lead). |
| `model_response` | `assistant` message: text and the complete tool calls, arguments verbatim. Reasoning is replayed according to `reasoning_replay` (`all` by default — measured against the server's chat template it stays in the prefix and costs nothing once cached — or `none`), fixed per session. Calls that are not complete (cut by the output limit, or arguments that are not a JSON object) are not rendered; a response that ended `aborted` or `error`, or holds neither text nor a complete call, is not rendered. |
| `tool_result` | `tool` message with the admitted text, in call order whatever order the results were logged in. A rendered call with no result (crash, in flight at a restart) renders `[no result recorded: the call was interrupted; its effects are unknown — check before retrying]`. |
| `child_settled` | `user`-role `<harness kind="agent-report" agent="{child}" outcome="{outcome}">…</harness>`; nothing for an `inline` settlement, whose report is the result of the call that waited for it. |
| everything else | not rendered. |

Consecutive `user`-role items are merged into one message (blank line between) so chat templates that
reject consecutive user turns still work, except that a `user`-role item directly after a `tool`
message starts its own message.

**Harness blocks** (`loom-core::tagsafe`). Every `<harness …>` block, the resume block and the
`<harness-state>` block are built by `tagsafe`, never by hand. What a block embeds from the log is a
payload; at render time (stored records are never rewritten) the `<` of every `<harness` and
`</harness` in a payload, in any letter case, is written `&lt;`, so no payload can close its block or
open another. Attribute values have `"`, `<` and `>` escaped and line breaks written as spaces. Inside a
harness-built report, text the harness did not write is fenced line by line: `>` before each line, or
`  | ` before each further line of a list item (§9).

**Re-weave.** A `reweave` record changes the projection for everything at or before `upto_seq`: it
lists evictions (`stub` with replacement text, `drop`, or `drop_reasoning`) and carries a brief (the
ledger snapshot and resume instructions) that is rendered as a `<harness kind="resume">` block
directly after the last item at or before `upto_seq`. Evictions accumulate across re-weaves (a later
one wins for the same record); only the latest brief is rendered. The epoch increments. Everything
after `upto_seq` renders normally. Because the record is in the log, the projection stays a pure
function of the log. `drop` on a tool result renders `[evicted from view; the call and its result
remain in the session record]`; on a model response it removes the text and reasoning and keeps the
calls, so pairing holds. Evictions that name a protected item are ignored.

**Eviction order** (`plan_reweave`), applied until the estimate is at or below the floor, stopping as
soon as it is:

1. replayed reasoning of model responses (the calls and their results stay);
2. navigation output (`ToolClass::Nav`: listings, searches), oldest first;
3. file reads and other lookups (`ToolClass::Read`), largest first;
4. every other unpinned tool output and agent report, largest first;
5. assistant text, only in the second plan the session makes when the first cannot free enough
   (see below);
6. never: the system message, user messages, the `forked` record, harness notes of kind
   `constraint`, `approval` and `assignment`, pinned output, and the protected recent region — the
   last `keep_recent_steps` model responses (rendered or not) and everything after the first of them.

A stub is the evicted result's first line (its envelope header: call, outcome, size, handle); for an
execution, the last `stub_tail_lines` (12) lines follow under `[last N lines as first shown]`; then
`[evicted from view, not from the record: {lines} lines / {bytes} bytes. Full output: out:… — read it
again with out_read or out_grep before relying on it.]`, or, when nothing was stored, `[evicted from
view, not from the record. Run it again if the result matters.]`. Tool call/result pairs always stay
paired (a stub is still a `tool` message).

**When and how much.** `target_tokens`, `floor_tokens` and `keep_recent_steps` (defaults 400 000,
180 000 and 60) are absolute numbers per configuration, not shares of the window: the working set is
sized by latency and quality, and the rest of the window is burst capacity. Before each step request
the session compares the size of the request it is about to send, as the server counts it, with a
limit. The size is the `prompt_tokens` the server reported for the latest answered step request of
the current epoch plus the estimated tokens of what has been added since (before the first answer of
an epoch, the estimate alone). The limit is `target_tokens`, lowered when the window is known to
`window − reserve` and to four fifths of the window; `reserve` is `max_output_tokens` plus
min(4 096, window/4), or min(20 480, window/4) when no reply length is configured or the window cannot
hold it. The floor is `floor_tokens`, lowered to half the window, and to half the limit when it is not
below it. A 1M window keeps 400 000 / 180 000, and windows of 81 920 tokens and more keep the full
reserve. When the server refuses a prompt as too long (`overflow`), the window used is the smaller of
the known one and the limit stated in the error.

A re-weave that nobody asked for (`target`) happens only when it is worth it: every re-weave starts a
new epoch and loses the server's cache, so one that frees little would be needed again a step later.
The plan must bring the size to the midpoint between floor and limit; if it cannot, the session halves
`keep_recent_steps` (down to 2) and plans again, then plans once more allowing assistant text to go.
When even that is not enough, nothing is recorded and the context grows until the window forces an
`overflow` re-weave. Forced re-weaves (`overflow`, and `operator` from `POST …/reweave` or
`loom reweave`) take what the plan can free. Re-weaves happen only between steps (or while idle, on
operator request), never while a tool call is outstanding. The model can `pin` a result it wants
kept.

**Digest (cache-friendly).** Before a re-weave that evicts assistant text, unless it is for an
overflow (the server has just refused that prefix), the session sends the *existing* stable prefix
plus one appended instruction asking for a digest. That request is a full cache hit; it is recorded as
a `model_request` with purpose `digest` (its reply is not a record), capped at 8 000 tokens, and waits
for a request slot at the session's own priority. A non-empty reply is stored in the `reweave` record
and rendered in the resume block under `Leads from earlier work (written by the model, not verified —
re-check before relying on them):`. Without a digest the re-weave goes ahead all the same: the ledger
brief is the durable state.

**HUD (ephemeral tail).** Not part of the weave. Each step request ends with one `user`-role message
`<harness-state>…</harness-state>` (`loom-agent::hud`) that is never part of the stable prefix, so the
next request diverges from the cache only after the previous last stable message. It is stored as a
blob named by the request's `model_request.hud`. It carries, each section only when non-empty: the
current time (UTC, minutes); the mission state from the ledger brief (§7); command outputs with at
least `agents.unviewed_min_lines` (20) lines never shown; calls repeated with the same arguments and the
same output; reads and command results that a later write of this session made out of date; running
jobs and agents; ledger questions waiting on the operator; and, only in the last stretch of a step or
time budget, one heads-up to wrap up — with no running count, so a rising number is never shown. It
never mentions context size, message counts or elapsed session time.

**Prefix guard** (`loom-core::prefix`). For each step request the session hands the stable messages to
`PrefixGuard::check`, which compares them with those of the previous request: unless the epoch
changed, the previous stable messages must be a prefix of the new ones. The one allowed difference is
text appended to the previous request's last stable message (a request whose reply was never recorded,
followed by a user-role item that the weave merges into it), which keeps everything the server cached
but its closing tokens. A violation appends a `cache_break` record naming the first differing message.
Opening a session primes the guard with the weave of its records up to the last `model_request`, so
the first request after a restart is checked like any other; when that weave no longer hashes to what
the record stored (an upgrade changed the rendering), one `cache_break` is appended saying so.

## 6. Admission (`loom-core::admit`)

The module documentation of `admit.rs` is the precise specification; this is the overview.

Every tool output is normalised (invalid UTF-8, terminal escape sequences, carriage-return
overwrites and control characters are handled without changing the number of lines) and stored whole
in the blob store first. `admit` then builds what the model sees — always an envelope:

```
[bash · exit 1 · 2.4s · 18412 lines · CUT · out:7f3a9c1e2b4d6f80]
…body…
[end of bash output · exit 1]
```

- the header is the tool, the outcome and the tool's other facts, the line count, `CUT` when the body
  is a cut, the normalisation notes when any (`3 terminal escape sequences removed`, …) and the handle:
  `out:` and the first 16 hex characters of the blob id (any unambiguous prefix of 8 or more is
  accepted back);
- at or below `max_inline_tokens` (default 60 000 estimated tokens) the body is the stored text,
  unmodified;
- above, the body is the first `head_lines` and last `tail_lines` (defaults 400 / 400; halved until
  they fit when they would cover everything) around a marker that names the omitted line range, its
  size, that nothing was discarded and how to read it, followed by a *pattern scan* of the omitted
  region (lines matching error-like patterns, with their line numbers, at most `salient_max` (40)
  spread evenly, labelled as a text match, not a reading). In a cut body, lines longer than
  `max_line_chars` (4 000) are cut with an inline `…[+N chars]` marker. Binary output is described
  (`binary data, N bytes, starts with …`), not inlined; empty output is `(no output)`.
- results that store nothing of their own (views such as `read`, `out_read`, `out_grep`, and plain
  messages) carry the same header and footer around their text, without the admission's line count
  and handle (their facts state the range shown; a `read` names the handle of the file text it
  stored).

The outcome is stated first and last, so it is adjacent to wherever the model is reading. The lines
shown are recorded on the `tool_result` (`meta.shown`); views record which blob they showed
(`meta.of_blob`) and which of its lines. `loom_core::observe` folds these into "which lines of this
output has the model been shown", which drives the HUD's list of executions with unseen output.

Token estimates use `TokenEstimator`, a chars-per-token ratio calibrated against the server's
reported `prompt_tokens` after every request (start 3.3).

## 7. Ledger (`loom-core::ledger`, `loom-core::journal`)

The module documentation of `journal.rs` and `ledger.rs` is the precise specification.

**Journal.** One journal per mission, `missions/<mid>/journal.jsonl`, one entry per line:
`{n, ts_ms, session, from_user, op, …the op's fields, mac}` (the op is flattened under its `op` tag;
an evidence op's own session is stored as `evidence_session`). `mac` is
hex(HMAC-SHA256(key, previous mac ‖ the entry's bytes as stored, without the `mac` key)), with 64
zeros before the first entry. Verification recomputes over the bytes on disk.

- An append takes an exclusive lock on `journal.jsonl.lock`, reads and verifies the whole journal,
  folds it, checks the op against the rules below (and the caller's own check), writes one line and
  syncs it; so ids are allocated race-free across processes. A write or sync failure truncates the
  file back; when that fails too the error says the entry may or may not be there
  (`JournalError::Unconfirmed`), and the model is told to look before repeating the call.
- **Head record.** After every append, while the lock is held, `journal.head` is rewritten atomically
  with `{n, mac, seal}`, the seal an HMAC over a label, the mission directory's name, `n` and `mac`. A
  head with a valid seal requires entry `n` to exist with exactly that mac, so removing the last
  entries, deleting the journal, or putting another mission's journal (and head) in its place is
  detected. The journal may be ahead of its head by entries that verify (a crash between the two
  writes); the next append repairs it. A journal without a head (written before heads existed) is
  accepted at any length and gets one at its next append. So the head detects truncation and
  substitution only while it is in place: deleting `journal.head` together with the last entries (or
  putting another mission's journal in place without a head) is not detected, deleting the journal
  and the head together reads as a mission that never had a ledger, and restoring an older journal
  together with its older head rolls the mission back unnoticed. Anyone who holds the key can forge
  everything.
- **Torn tail.** Bytes after the last newline (a crash or full disk mid-append) are ignored on read
  and removed by the next append. A complete line that fails verification makes the journal
  `Tampered`: every ledger write refuses and the ledger view reports it; the agent cannot repair it.
- **Newer entries.** An entry with a valid seal whose op this build cannot parse is kept in the chain
  and skipped when folding; appends are refused (`NewerVersion`) and the model is told that loom must
  be upgraded before the mission can continue. Reads do not hide this: the ledger view (`LedgerView`:
  `skipped`, `skipped_detail`, `torn_tail`, `ahead_of_head`) reports skipped entries, an ignored torn
  tail and entries the head record does not vouch for; `loom ledger` and the web UI show a line for each
  that is present, and the state block tells the model how many entries are not shown.
- **Key.** `keys/journal.key`: 32 random bytes as hex, created 0600 (inside `keys/`, which is 0700 like the loom home) by
  publishing a synced temporary file under the final name with a hard link and syncing the directory,
  so a crash never leaves a partial key and two creators end with the same one. An existing file that
  does not hold 64 hex characters is an error and is never replaced; an empty one tells the operator to
  delete it only if no mission journals exist, otherwise to restore it from a backup.

**Who writes it.** A mission keeps a journal when its lead's role ends explicitly (`termination =
"explicit"`); the lead and every agent it starts write to the same journal, each entry naming its
session, and every agent's HUD shows the mission state. Sessions of a role that ends freely (`chat`)
have none.

**Records.** `LedgerState::fold(entries)` is the only reader. Record kinds: goal, constraint (and its
retirement), plan step, decision, dead end, claim, evidence, approval, question (and its answer),
finish claim and finish verdict. The schema and the fold also know obligations and approval uses; no
tool or runtime path in this version writes them (an open obligation would block `finish`). Rules
enforced on write (`LedgerState::validate`):

- the goal, constraints and their retirement, approvals and answers to questions come only from the
  operator (`from_user`); the model has no tool that writes them. The first user message of a mission
  sets the goal;
- a plan step can be `done` only with a note saying how it was verified or with evidence ids, and
  `dropped` only with a note; a claim can be `supported` only when attested evidence supporting it is
  attached, and `refuted` or `withdrawn` only with a note;
- a finish claim is refused while the ledger has open items: plan steps todo or doing, open claims,
  unanswered blocking questions (and open obligations);
- records are never edited: updates are new ops.

Three further records. None has a model-facing id except the scope grant's `s1…` in the Markdown view;
the first two are singletons.

- **Goal-met claim** (`goal_met`, written by `GoalMetSet`, model-authored). A harness-held claim about
  whether the goal is met, separate from the goal text (operator only) and from `claims`: it is never
  counted among open claims and never blocks `finish`. It is absent before a goal is set and `open` from
  the `GoalSet` on; its other states are `supported` (the goal is met) and `refuted` (the goal cannot be
  met as stated). There is no withdrawn state and `open` is never a write target, so the model can move
  it toward a conclusion but never retract it. A write needs a goal, a note, and cited evidence ids that
  all exist and are attested and supporting, at least one of kind `execution` (a static-only basis is
  refused: run the target and cite the run). A concluded claim may be written again only with the other
  terminal state and at least one execution evidence record added after the entry that set the current
  state. A later gate and verifier check the claim; the ledger only holds it.
- **Operator release** (`release`, written by `OperatorRelease`, operator only). The operator accepts the
  result short of the goal and the work may stop. A reason is required, a goal must be set, and only one
  release is recorded. It never changes `goal_met`; the views show it as `released by the operator (goal
  not established): <reason>`. Never evicted.
- **Scope grant** (`scope_grants`, written by `ScopeGrant`, operator only). The network hosts the
  operator authorized for the mission, with an optional note: the ledger's audit account, not the
  enforcement (the proxy and the configuration own host syntax and policy). The list must be non-empty,
  each entry non-blank and free of whitespace and commas (one host per entry); hosts are kept as
  written. `LedgerState::granted_hosts()` returns all hosts granted so far, de-duplicated ignoring ASCII
  case, in first-seen order. Never evicted.

`brief()` shows, right after the goal, `Goal status: open (not yet concluded)` / `met — <note>
(evidence: …)` / `cannot be met as stated — <note> (evidence: …)`, the release line when present, and
`authorized hosts: a, b, c` (or `none granted`). `render_markdown()` has the sections Goal status and
Network scope. A journal written before these records existed folds unchanged; the new state fields
default to empty.

**Evidence** (the `evidence` tool, `loom-agent::rtools::ledger`). The model names a claim, a stored
output by handle, a line range, a quote and a note. The harness:

1. checks the quote against those lines of the stored text (below);
2. finds the producer of the output among the mission's sessions (a session's own records only):
   the tool call whose result stored it; for a `read`, the call that stored the file text its header
   names; for the complete output of a background job, the call that started the job. A view
   (`out_read`, `out_grep`) stores nothing of its own, so a quote taken from one cites the output it
   viewed and is judged by what produced that output. An output no call of the mission produced is
   refused;
3. accepts only observations: an output produced by a runtime tool (everything in `rtools::NAMES`:
   the ledger tools and `log_search` play the model's own words back, the agent tools return another
   agent's text) or by a tool of class `State`, `Terminal` or `Write` (the diff `write` and `edit`
   return) is refused. The rule is one function, applied to every quote of `finish` too (a child's and a
   lead's): a quote of a ledger, a log search, an agent's report or a diff of the model's own edit is
   refused with `Nothing was delivered.`;
4. records `{claim, kind, supports, session, call_id, blob, lines, quote, note, attested: true}`, where
   `kind` is `execution` when the producer is of class `Exec` and `static` otherwise, and `quote` is
   the verified text without line-number prefixes. A quote that is a part of a line is recorded as the
   complete line or lines it lies on, with their numbers (a window of them on long lines, below).

**Quote check** (`observe::check_quote`, also used for the quotes of `finish`). Both sides are prepared
the same way: trailing whitespace is removed from every line, and blank lines at either end of the
quote are ignored. The quote is looked for as written. Only when that fails (or finds only a fragment
that is too short or inside a word) and every non-blank line of the quote starts with a line-number
prefix as the read tools print them (`N:`, `N-`, `N|`, `N│` or `N<TAB>`, the numbers increasing), the
prefixes are removed
and the rest is looked for, and each number must then be the real number of the line its text is on.
An occurrence counts only when it spans whole lines or has at least 8 non-whitespace characters and sits
on token boundaries: when the quote begins (ends) with a letter or digit, the character before (after) it
in the line is not one: `0 failed; 0 ignored` is not found inside `10 failed; 0 ignored`, and the model is
told that the text occurs only inside a longer word or number. The text recorded and shown as the
attested quote is the complete line or lines the accepted occurrence lies on when they have at most 300
characters (`observe::QUOTE_RECORD_CHARS`); on longer lines it is the occurrence, whole, with as much of
the lines around it as fits in 300 characters and `…` where text was left out, so the quoted text is
always shown and the record stays bounded. There is no other leniency: case, indentation, inner spacing
and punctuation must match.

**Views.** `LedgerState::render_markdown()` is the full Markdown view (the `ledger` tool, the API's
`markdown`, `loom ledger`). A mission whose lead keeps a ledger but has written nothing yet has an
empty one; for a mission whose lead keeps none the API answers `No ledger: this mission's lead does
not keep one.` `LedgerState::brief()` is the compact text of the HUD and of the re-weave
brief: goal, constraints and approvals are the operator's words and never cut; every other line is
cut at 400 characters; it shows the last 12 decisions and the last 20 dead ends, each list starting
with `(N older not shown: d1–d3; call `ledger` to read them)` when older ones are left out.

## 8. Agent loop and stop gate (`loom-agent::session`, `loom-agent::gate`)

The module documentation of `session.rs` is the precise specification of the loop; `gate.rs` and
`rtools/terminal.rs` specify the gates. One task per session:

```
idle: wait for an input (user message, inbox answer, agent report, job end, agent message,
      resume, operator rule / approval / withdrawal, reweave, stop)
turn (turn_start{trigger}):
  step:
    cancellation check
    drain arrivals (anything queued is recorded now; nothing starts a turn)
    budget check → note, then park / settle after 2 more steps
    stall check → note
    re-weave check (§5)
    request = weave(log) + HUD → request slot → stream (lookups may start early, below)
    reply:
      ended with an error                → the turn fails
      complete tool calls                → run in call order; a terminating tool's effect ends the turn
      calls with malformed arguments     → not run; one nudge note each
      finish_reason = length             → "output cut" note → next step
      no tool calls                      → stop gate
turn_end{reason}   yielded | finished | asked | blocked | waiting | stopped | parked | budget_exhausted | error
```

**Idle inputs.** A user message is recorded and starts a turn. An inbox answer resolves the item
(answers to questions and blockers are also recorded in the ledger) and, when not blank, starts a turn
with the answer as a user message; a blank answer to a non-blocking item is a **dismissal**: it
resolves the item without a user message or a turn, a dismissed question or blocker is closed in the
ledger with `(dismissed by the operator without an answer)`, and the model gets a note that no answer
will come. Operator rules, approvals and withdrawals are recorded at once — a ledger entry when the
mission keeps one, and a protected note authored by the user that stays in view — and start no turn.
An agent report and the end of a job are recorded and start a turn only when the last turn ended
`waiting` or `yielded` (a job end is announced in a note unless the model already saw how it ended
through `job_wait`). A message from the lead reaches a child as a note authored by the lead.

**Stop** is sticky. Stopping a session cancels its turn, kills its jobs and stops its agents; a running
tool returns its own result before `interrupted` is recorded. A child that is stopped settles
`stopped`. A root stopped while idle after a turn that ended `waiting` or `yielded` records
`interrupted` and a `stopped` turn end, so the reports and job ends the stop causes are recorded
without starting a turn; only a user message, an inbox answer or a resume runs it again. A stop found
among inputs queued during a turn cancels the turn at the next step. The next turn begins with a note
saying the previous one was stopped, by the operator during a turn, between turns, or by a restart.

**Tool-call validation** (`loom-tools::schema`). An unknown tool gets an error result naming the
nearest tool names. Arguments are checked against the tool's parameter schema: an unambiguous shape
error is repaired and the repair is reported (`read "12" as the integer 12`); anything else is refused
with the argument, what was received and what is expected, every problem at once; unknown arguments
are never silently dropped. After a call that ended the turn, the reply's remaining calls are refused
unrun. A call to a tool outside a forked child's role (its parent's tool list is in its prefix) is
refused as not part of its assignment.

**Malformed calls.** A call that has a name but whose arguments are not a JSON object, in a reply not
cut by the output limit, is not run, gets no `tool_call` record and is never replayed to the server.
A nudge note per such call names the tool, gives the parser's error with its position, shows the
arguments received (cut at 600 characters) and asks for the call again; it is written after the
results of the calls that ran. A reply whose only calls were malformed, and an output-limit reply with
no complete call, count in the same counter as the stop gate's nudges; one past `agents.max_nudges` a
lead parks and a child settles `failed`, each with a text naming the cause. The counter returns to 0
on any tool result with status `ok`, a user message, or a new turn.

**Order and early starts.** Calls run in the order of the reply, one at a time, with one exception
(`tools.speculate`, default true). Tools opt in through `Tool::speculative`: `read`, `glob`, `grep`,
`out_read` and `out_grep`, which only read local state and have no effect outside the harness. While a
reply streams, such a call starts as soon as the next call of the reply begins
(`StreamEvent::ToolCallReady`, never sent for the last call), provided every earlier call of the attempt
was ready and is of such a tool (a gap, or any other tool, ends early starts for the attempt), its
arguments pass `loom_tools::prepare`, and fewer than 8 early tasks are running (discarded ones count
until they have ended). It runs in a task of its own, under the id the reply will keep (the server's id
when it is non-empty and unused, else a fresh `call-…`), with a cancellation token under the turn's and a
`FileTracker` of its own. When the reply is in, the rest of its leading run of such tools starts
together. The in-order loop then **claims** each early run whose index, tool name, arguments (byte for
byte) and id match the call: it appends the `tool_call`, awaits the run, moves the file records the run
staged into the session's tracker, and only then stores and admits the output (`Ran::finish`, with the
estimator as calibrated by the finished reply); the `tool_result` carries `meta.early_ms`, how many
milliseconds the call started ahead of its turn (not shown to the model). Early runs are **discarded**
without a record on a new attempt (a retry), a failed request, a stop or cancellation, the end of the
session, or when the finished reply does not hold the call byte for byte (other name or arguments,
fewer calls, cut by the output limit, malformed); a discarded read never lets a later `write` or
`edit` through. No early task outlives its step. Every other call — `bash`, `write`, `edit`,
`web_fetch`, the CVE tools, the runtime tools — and every call after one of them runs alone, in its
turn, so it sees what the calls before it did. Records and what the model sees are those of running
every call in place, except timings, session-made call ids and `early_ms`. With `speculate = false`
every call runs after the whole reply has arrived, one at a time. Counts of early starts are logged at
debug level at the end of each turn.

**Stop gate** (`gate::on_yield`). When the model replies without a tool call:

- role termination `free` (interactive chat): the turn ends `yielded`;
- role termination `explicit` (lead, worker, verifier): the harness appends a nudge note saying the
  reply delivered nothing and the turn has not ended (and that text shaped like a tool call is never
  executed), listing for a lead the ledger's open plan steps, obligations, open claims and
  questions waiting for the operator (at most 12) and what is still running, and naming the terminating tools the role
  has. After `max_nudges` (3) consecutive nudges without progress a lead opens a blocking `parked`
  inbox item (with notification) and the turn ends `parked`; a child settles `failed`.

Terminating tools: `finish {answer, quotes?, not_established?, evidence?}`, `ask_user {question,
options?, blocking?, meanwhile?}` (leads only; `blocking` defaults to true, and `meanwhile` is required
when it is false), `report_blocker {class, what, tried, needs}` (class `needs_approval`, `needs_input`,
`environment` or `impossible`; there is no class for context or elapsed time), `wait {reason?}` (refused when no job or agent is running), and for verifiers
`verdict {accepted, objections?, opened}`. `verdict` is refused while the verifier has a running job
(`job_wait`, or `job_kill` where the role has it): a check it has not seen end cannot support a verdict.

**Finish gate** (`rtools::terminal`). It fails closed: a lead's result reaches the operator as finished
only when every check passes and, where verification is required, a verifier accepted it.

- `answer` must not be blank, and each quote (`{handle, start, end, text}`) must pass the quote check and
  quote an observation (the rule of `evidence`, §7).
- `finish` is refused, in a lead and in a child alike, while a background job of the session or an
  agent it started is running; the refusal names them and says what to do (`wait`, `job_kill`,
  `agent_stop`; `job_kill` and `finish` can go in one reply). This is live state, not ledger
  obligations; the finish gate's own verifier does not count.
- A child's `finish` delivers its report to its parent (§9).
- The goal-met pre-gate. In a role with explicit termination, `finish` is refused in the same step,
  before a finish is recorded, a verifier started or an inbox item opened, while the mission has a goal
  and the goal-met claim (§7) is not concluded; a nudge note says to run the target and call `conclude`
  once a run shows the goal met or the goal is established unreachable, or `report_blocker` for what only
  the operator can supply. The ledger, not the wording of a reply, decides whether a stop is a
  deliverable. `conclude {status: met|unreachable, note, evidence}` writes the goal-met claim (the
  ledger checks the evidence, §7); `unreachable` is also refused while a plan step is open, so every route
  is closed first, and the verifier is then told to name one untried route or get one step further, not to
  confirm impossibility. A mission the operator released (`OperatorRelease`) may finish without a
  conclusion; it is delivered as `[closed by operator, goal not established]` and is not verified. Free
  termination roles are not gated.
- A lead's `finish` is refused while the ledger has open items (§7); otherwise a finish claim `f{n}` is
  recorded. Verification is required when the role has `verify_finish` and the config's
  `agents.verify_finish` is on (default). Without it the result is delivered marked `[not verified]`.
  With it the harness starts the role's verifier (§13) itself — not limited by `may_spawn` or
  `max_children` — in a fresh, read-only session, with a brief holding the answer, what the lead says
  it did not establish, its quotes and the ledger evidence (with handles) of the finish and of every
  supported claim, and the instruction to try to refute it. The verifier's `verdict` must list in
  `opened` outputs that its own session produced or opened, including at least one of the handles its
  assignment names, and a rejection must carry objections.
  - accepted: the verdict is recorded and a `finished` inbox item is opened with the answer, `Not
    established (stated by the lead):`, `Quoted support (checked against the stored output):` and
    `[verified by s-…]`; the turn ends `finished`;
  - rejected: the verdict is recorded and `finish` returns the objections as an error; the lead works
    on;
  - rejected, continued: each objection is opened as an `objection` obligation, which holds every later
    finish until execution evidence is recorded after it (the harness settles it then, at the next
    finish); answering an inbox item, rewording the result or finishing again settles nothing. From
    `MAX_FINISH_REJECTIONS` (2) rejections counted since the latest accepted finish, each rejection also
    writes a non-blocking note (`finish rejected n times; continuing`); nobody is asked and the session
    works on until its budget;
  - a verifier that cannot be started, or ends without a verdict, is a fault of the harness: a fresh
    one is started up to two more times; if none runs, the finish stays recorded without a verdict, a
    non-blocking note labelled an infrastructure fault is written, `finish` returns an error saying so,
    and nothing is delivered as finished or opened for the operator;
  - a shutdown or a crash during verification records nothing for the call; after the restart a
    `finish` made again with the same brief joins the verifier that was cut, or takes the verdict it
    gave, instead of starting another. The verifier is marked as the gate's, with its brief, in its
    own `meta.json` before its first turn, so a crash cannot turn it into an ordinary agent.

Only `report_blocker` (objective class), budget exhaustion and the operator's own release can park the
operator: a rejected or unrunnable verification never opens a blocking item, and an operator's answer to
an inbox item is never a release: it does not conclude the goal, settle an objection or move the count
of rejections.

**Budget.** A session's budget is `max_steps` and/or `max_minutes` (a child's from its assignment, at
most `agents.child_max_steps` / `child_max_minutes`, 200 / 120 by default; a root's from its creation,
none by default). When one is reached the session gets a budget note; two steps later a child settles
`budget_exhausted` with its last reply, and a root opens a blocking `parked` item and its turn ends
`budget_exhausted`. The next turn the operator starts for that root (message, answer, resume) grants a
fresh budget of the configured size, counted from that turn, and the model is told so.
Schema 2 records active-time intervals: limiter queues, retry backoff/outages and idle turns do not
consume minute budgets. After a crash, an interrupted active interval closes at the latest durable
pre-interruption timestamp; unknown time after that checkpoint is excluded. Schema 1 logs retain their
previous wall accounting until their first clock transition. During the two grace steps the unchanged
tool schemas remain in the prefix, but dispatch admits existing-output inspection, ledger cleanup,
bounded waiting/stopping and delivery. Probes, writes, new plans/claims and delegation are refused,
including speculative starts. A finish requiring fresh execution may still refuse; report the blocker
and partial result rather than claiming verification. See [runtime controls](RUNTIME-CONTROLS.md).

**Stall.** In a session with a ledger whose role has `note`, `claim` or `evidence`, when the last
`agents.stall_steps` (30) steps recorded nothing in the ledger, changed no file and started or received
no agent, a note asks the model to record what it learned or change its approach (at most once in that
span).

**Repetition and staleness** (HUD, over the session's own records, `loom_core::observe`): the same tool
called with the same arguments and the same output at least 3 times (navigation, reads and commands);
a file read before this session later wrote it; the latest command result older than a later write.

**Failure.** A model request that fails after the client's retries (§10), or a reply that ended with
an error, fails the step: a child settles `failed` with the reason and its last reply; a lead opens a
blocking `parked` inbox item stating the reason and the turn ends `error`. The model is not shown the
server's error.

## 9. Orchestration (`loom-agent`)

The module documentation of `runtime.rs` (*Children*, *Start*, *Shutdown*) and `rtools/agents.rs` is
the precise specification.

- Only a lead (root session) starts agents, only of roles its role lists in `may_spawn`, and at most
  `agents.max_children` (6) unsettled agents at once (a model-started spawn also counts a finish
  verifier that is still running). Agents do not start agents, so depth is one.
- `agent_spawn {question, role?, hypothesis?, scope?, do_not?, return?, stop_when?, context?, mode?,
  max_steps?, max_minutes?, background?}`. The brief is rendered as `Question:`, `Hypothesis:`,
  `Scope:`, `Not yours:`, `Return:`, `Stop when:`, `Context:`. `mode: fresh` starts from the role's own
  system prompt and the brief; `mode: fork` starts from the parent's exact log up to its last request
  plus the brief (full cache hit), and is refused when the child's role needs a tool the parent lacks.
  By default the call waits until the agent settles and its report is the call's result (recorded as an
  `inline` settlement); with `background: true` it returns at once and the report arrives later as an
  `agent-report` block that wakes a waiting lead.
- `agent_fanout {agents[2..max_children], max_steps?, max_minutes?}` checks every assignment before
  starting any, starts them, waits for all and returns one result with a `=====` header per agent; a
  report line that starts with `=====` is prefixed `> `, so a report cannot forge a header.
- `agent_message {agent, text}`; `agent_stop {agent | all}`, which waits up to `tools.kill_grace_s`
  + 2 s for the agent to settle and says `stopped` or `stopping`; `wait` ends the lead's turn until a
  job or an agent ends. Running agents are listed in the HUD.
- **How a child ends.** It settles exactly once: `returned` (its `finish`), `blocked`
  (`report_blocker`), `budget_exhausted`, `stopped` (stopped by its lead or the operator, or its
  mission archived), or `failed` (a model or server failure, giving up after nudges, a failure of its
  task, or a log that cannot be opened after a restart). The settlement (outcome, report, the full
  answer's handle when the report was cut, verdict or quote payload, steps, usage) is written to its
  `settlement.json` and delivered to the lead once.
- **What the lead sees** (`gate::render_report`): `Outcome:`, then `Quotes (checked against the stored
  output by the harness):` with handle and lines (further lines of a quote continue with `  | `), then
  `This report was written by a sub-agent. The quotes are verbatim; everything else is unverified.`,
  then the agent's own words — `Answer:` and `Not established:` — with every line prefixed `> `. The
  answer is cut at 12 000 characters with the handle of the full text. A child's blocker report fences
  its fields the same way, and a verdict's objections continue with `  | `.
- `decide {question, options[2..6], k?}` (k 3 to 9, default 5) sends k requests built on the session's
  stable prefix up to its last request plus a vote prompt, with seeds 1..k and no tools run; the tally
  and reasons come back as one result, marked as advice from copies of the model, not evidence.
- `verify {claim | statement, handles?}` runs the role's verifier on demand (it must be in
  `may_spawn`) and returns its verdict; it does not change the claim's status.
- Agents share the mission's ledger (§7).
- **Stop** cascades from a lead to its agents (§8). An archive settles a mission's agents `stopped`;
  unarchiving delivers what they settled with and restores those that had not settled.
- **Request slots** (`loom-model::limit`): per model profile at most `max_concurrent` requests in
  flight, highest priority first and first come first served within a priority: `Lead` for root
  sessions (and their digests) above `Child` for agents and votes.
- **Restart.** A child that a shutdown cut is resumed, not settled: at start every unsettled child of a
  mission that is not archived is activated; one that had a turn is held and gets exactly one resume
  (at once when its mission is unattended, when it was told how a job ended, or when its lead is told to
  carry on; otherwise as soon as its lead next carries on: an operator message, resume or answer to the
  lead, or any turn the lead starts, such as one an agent's report starts); one that never had a turn
  starts by itself; one whose log cannot be opened while its lead's can is settled `failed` on its
  behalf. A settlement whose
  delivery a restart cut is delivered from `settlement.json` (or from the child's log), unless the
  lead's waiting call has a recorded result for an agent that had ended. A finish verifier (known
  from its `meta.json`) is never delivered as a report, listed among the lead's agents, or counted as
  its running work.

## 10. Model access (`loom-model`)

The module documentation of `client.rs`, `assemble.rs` and `request.rs` is the precise specification.

- `POST {base_url}/chat/completions` with `Authorization: Bearer …` when `api_key_env` names a
  non-empty variable. The body's keys come in a fixed order — `model`, `messages`, `tools`,
  `tool_choice` (omitted: the session always uses `auto`), `stream: true`,
  `stream_options.include_usage: true`, `max_tokens` when `max_output_tokens` is set, `seed` (votes
  only), then `extra_body` (`reasoning_effort`, sampling, `vllm_xargs`, …) verbatim — and the same
  inputs give the same bytes, because some chat templates render request fields into the prompt
  head. `extra_body` can never replace `model`, `messages`, `tools`, `stream` or `stream_options`.
- Deltas: `content`, `reasoning` or `reasoning_content`, `tool_calls[]` (index-keyed, `id`/`name` on
  the first element of an index, `arguments` appended). `finish_reason`: `stop`, `tool_calls` or
  `function_call`, `length`; anything else counts as `stop`. A call whose arguments do not parse as a
  JSON object is incomplete. Usage: `prompt_tokens`, `completion_tokens`,
  `prompt_tokens_details.cached_tokens`, `completion_tokens_details.reasoning_tokens`.
- Stream limits: a line of 8 MiB, an event of 16 MiB, and 64 MiB each for content, reasoning, and
  tool-call names plus arguments; a stream over a limit fails the attempt as malformed.
- Connecting has a 10 s timeout; waiting more than `stall_timeout_s` (240) for the headers or the next
  bytes fails the attempt as a stall.
- **Retry.** Transport errors, stalls, HTTP 408, 425, 429 and 5xx, and an error object inside a 200
  stream are retried for up to `retry_window_s` from the request's first failure (default 300, long
  enough for a server relaunch). 0 retries them until the server returns or the step is stopped, so
  such a failure that never heals is retried for ever. Failures that waiting cannot cure — a 200 that
  is not an event stream, a malformed or oversized stream, a stream that ends cleanly without a
  `finish_reason`, and send errors that are not about reaching the server (the request cannot be
  built, a TLS certificate or protocol error, an answer that is not HTTP) — end the request after 3
  such attempts in a row whatever the window; a failure of the other kind in between starts the count
  again. Delays are 0.5 s doubling to `retry_max_delay_s` (30) with ±10% jitter; a larger
  `Retry-After` (up to 600 s) wins. Viewers see each retry as a `retrying` delta. A partial attempt
  is never committed, and a cancellation returns promptly with the text streamed so far.
- **Unavailable notice.** When one model request of a session (a step's or a digest's) is retrying
  and its outage began `agents.unavailable_notice_s` ago (default 300; 0 = never), the session
  opens a non-blocking `blocker` inbox item, notified like every other: the server's
  address, since when it has been unavailable, the last error, and until when the request is retried
  (or that it is retried until the server answers), with the note that nothing needs an answer. The
  outage begins at the request's first failure, and again at a failure that ends an attempt the
  server had been answering for at least that long. No item is opened when the retry window ends
  first: the request then fails at its next failed attempt (a failed step opens its own item, §8), so
  with both values at their defaults the notice serves a longer window or `retry_window_s = 0`. At
  most one is open per session. When the request ends the harness resolves
  the item itself, saying whether the server answered, the request failed (it is then handled as any
  failed request, §8) or the step was stopped; an item a session left open when the daemon stopped is
  resolved when the session is next activated. Neither record reaches the model's context or starts
  a turn, and the request being retried is sent unchanged. The votes of `decide` (§9) are not
  watched: a vote that keeps retrying holds the call until its window ends or the step is stopped.
- **Redirects** are not followed: a 3xx is refused with a sentence naming `Location` and the base URL
  it implies.
- **Model id.** `GET {base_url}/models` selects the served id: the entry equal to the profile's `model`,
  else the only entry when there is exactly one (several and none matching is a configuration error).
  A 404 asks the server again: when no id has been selected in this process yet (a session restored
  while the server was down), the new one is remembered and the request is sent again once; when one
  has (the server was relaunched with another model), the 404 is refused with a sentence naming the
  model now served — loom never follows a new model by itself, because what a session recorded at its
  start describes the old one.
- **Context overflow.** A 400 or 413 whose message reads like an over-long prompt (`maximum context
  length`, `context length`, `too many tokens`, `prompt is too long`, `max_model_len`) is reported with
  the limit and request size parsed from it; the session then re-weaves (`overflow`) and sends again,
  once per step, and fails the step when nothing can be folded.
- **Other 4xx** are refused with the server's message; the step fails (§8).
- **Discovery and the window.** The first session created for a profile asks `GET {base_url}/models`
  (the first success is remembered for the process). The window is the first positive integer of
  `max_model_len`, `context_window`, `context_length`, `max_context_length` in the model's entry; a
  `context_window` in the profile takes precedence. A guess is never silently used: creating a session
  is refused when the server cannot be asked and the profile sets no window, and when the server
  answers but reports none and the profile sets none. With the server down and a configured window, the
  session starts with the configured model and window, and the daemon log says so. The window is
  recorded in the session's `session_start` and fixed for its life.
- No provider fallback. A profile's `extra_body` is fixed for the life of a session.

## 11. Tools, sandbox, network (`loom-tools`, `loom-net`)

**Tools.** Built in (`Registry::builtin`): `bash`, `job_wait`, `job_kill`, `job_list`, `read`,
`write`, `edit`, `glob`, `grep`, `out_read`, `out_grep`, `web_fetch`, `cve_lookup`, `cve_search`,
`advisory_lookup`. Runtime-owned (`loom-agent::rtools`, `NAMES`): `plan`, `step`, `note`, `claim`,
`claim_update`, `evidence`, `ledger`, `pin`, `log_search`, `finish`, `verdict`, `ask_user`,
`report_blocker`, `wait`, `agent_spawn`, `agent_fanout`, `agent_message`, `agent_stop`, `decide`,
`verify`. A role lists the tools it has, in request order; a name in neither set is a pack error. The
set is frozen in `session_start`. Every call goes through one pipeline (`loom_tools::prepare` → `run`
→ `finish`): lookup, argument check, run (a panic becomes an error result), store and admit. Each tool
has a class — `Nav`, `Read`, `Exec`, `Write`, `State`, `Terminal` — which drives eviction order,
evidence kind and staleness. Each module's documentation is the precise specification of its tools.

- `glob` and `grep` search the same file set: a walk that respects `.gitignore`, `.ignore` and global
  git excludes and skips hidden files unless `no_ignore` / `hidden` are set, always skips `.git`, does
  not follow links, skips what the sandbox makes unreadable, and stops on cancellation. `glob` lists
  paths most recently modified first; `grep` prints `path:line:text` in path order (context up to 20
  lines, or `files_only`), skips binary and non-UTF-8 files (an 8 KiB probe) and does not read files
  above 16 MiB, naming them and saying the search is incomplete. Both keep at most
  `tools.search_max_results` (200) entries and 4 MiB of text; a cut result carries `[Showing S of [at
  least] T …]` at both ends, and the outcome keeps the exact totals. A search with no match says how
  many files would match with `hidden` or `no_ignore` (a bounded pass).
- `read` works on regular files only (a device, FIFO or socket is refused without being opened). A file
  of up to 64 MiB is read whole, normalised and stored; the result shows a window of numbered lines
  (`tools.read_max_lines`, 2 000) and names the handle of the stored text, whose line numbers are the
  ones shown, so a file read can be quoted as evidence. A larger file needs a range: it is streamed,
  at most 80 000 bytes of a line and 4 MiB of window are kept, and the window is stored without a
  citable handle.
- `write` and `edit` are atomic (temporary file, sync, rename; permissions kept) and refuse when the
  file exists and this session has not read it, or when it changed on disk since (the refusal says
  what changed). `edit` replaces one unique occurrence, or all with `all`, and explains a miss without
  guessing. `edit`, and a `write` that replaces a file, return the unified diff; a `write` that creates
  a file returns `(new file)`, and one that replaces a file above 64 MiB says that there is no diff and
  why. Files above 64 MiB are not edited.
- `out_read` / `out_grep` page and search a stored output by handle and record what they showed.
- `bash` runs the command with `/bin/bash -c` under the sandbox, in its own process group, stdin
  `/dev/null`, stdout and stderr interleaved into one output file. It is over only when its whole
  process group is empty.
  - A foreground command still running after `tools.bash_foreground_s` (300) is not killed: it
    becomes a background job, and the result says so with the output so far. With `timeout_s` it is
    stopped instead (status `timeout`). `background: true` starts a job at once.
  - When the shell exits while other processes of its group are still alive 200 ms later, the result
    carries the shell's status and the output so far, and the rest continues as a job whose end is
    reported like any other.
  - The status the wrapper writes is always reported as an exit code (`exit <code>`); for a code above
    128 a fact says that 128+N conventionally means death by signal N, then names signal `code − 128`
    (with its name when known), or says that `code − 128` is not a signal number and so the code is the
    command's own. `killed by signal` appears only when the shell itself died of a signal.
  - Output past `tools.max_output_bytes` (64 MiB) kills the group at once (SIGKILL, and any grace
    period in progress ends); only the first `max_output_bytes` are kept, and the result gives the true
    size.
  - Cancellation sends TERM to the whole group, then KILL after `tools.kill_grace_s` (5).
  - A process that leaves its command's process group (`setsid`, `daemon()`, `redis-server --daemonize
    yes`, `tmux new -d`) is not tracked: `job_kill`, stop, the end of the session and daemon shutdown do
    not stop it, although it stays under the seatbelt profile.
  - In seatbelt mode a failure whose output mentions `Operation not permitted` gets a reminder fact
    about the sandbox.
- **Jobs** (`loom-tools::jobs`, `proc`). Ids `j1`, `j2`, … per session. `job_wait` returns the output
  written since the last look (waiting up to `tools.job_wait_s`, 120, by default), `job_kill` stops a
  job (TERM, then KILL), `job_list` lists them. When a job settles its complete output is stored, the
  session is told in a note unless the model already saw its end, and a session whose last turn
  ended `waiting` or `yielded` starts a turn.
  Every command writes `jobs/jN.out`, `jN.status` and `jN.pid` (created fresh); the pid record holds the
  shell's pid and start time, the members of a group that outlived it, and the owning daemon. At the
  next start a previous daemon's process group is killed only when its leader or a recorded member is
  confirmed by start time, and its pid record is removed. A command whose group was already gone and
  whose status file holds an exit code ended by itself while no daemon watched it: its output and
  status are kept until its session has recorded them; the files of every other command are removed.
  No id that has files on disk is handed out again. When the session is opened, a job the log shows as
  unsettled, or one a call's result gave the model but whose registration never reached the log (it
  is registered then), is settled: with its exit status and stored output when it ended by itself (the
  note says it finished while the harness was down), else with an unknown outcome. The model is told
  unless it already saw the job end, or an earlier `interrupted` note covered a lost job; a session
  that was waiting or yielded starts a turn.
- `web_fetch` fetches an `http`/`https` URL through the session's proxy, following up to 10 redirects
  itself so each hop passes the policy, within `tools.web_fetch_timeout_s` (60) and
  `tools.web_fetch_max_bytes` (20 MiB, with a fact when the response is larger). HTML is rendered to
  text and the raw bytes are stored too (`meta.raw_blob`). Any HTTP response is an observation (status
  `ok`). A refusal by the proxy is reported as `denied`: for an http URL from the proxy's own marked
  answer; for an https URL from a `LOOM-CHECK` asked before each request and again when it fails to
  connect (a marker inside a tunnel comes from the destination and is not trusted).
- `cve_lookup` (NVD record with EPSS), `cve_search` (NVD, ranked by EPSS) and `advisory_lookup` (OSV)
  reach only `services.nvd.nist.gov`, `api.first.org` and `api.osv.dev`, through the proxy, so the
  network policy must allow them; each stores the upstream JSON beside its text report.
- `pin {handle, reason, unpin?}` keeps a stored output and every view of it in view through re-weaves;
  `log_search {pattern, in?, max?}` searches the session's own record.

**Sandbox** (`loom-tools::sandbox`; its module documentation holds the exact seatbelt profile). Mode
`seatbelt` (default) runs commands under `/usr/bin/sandbox-exec`; the daemon refuses to start when the
mode cannot work on the host (not macOS, or no `sandbox-exec`). Mode `none` confines nothing, which the
system prompt states. Linux `bubblewrap` is a separate deny-all command-network mode: it requires
`/usr/bin/bwrap`, refuses loopback/Unix socket exceptions and host proxy bridges, uses isolated
namespaces, a read-only host filesystem, private `/tmp`, `/var/tmp` and `/run`, and a seccomp filter
that denies socket creation/connection (including filesystem Unix sockets and io_uring setup).
Protected mounts are read-only. User home (with credential protection), Loom home, and workspace
`.loom` are hidden by private mounts; scoped workspace/temp roots are restored from pinned sources.
This hides future oracle-secret/credential creation too. Missing explicit unreadable paths outside
hidden parents are refused; a whole user-home writable root is refused. The session temp remains
writable. It never falls back to `none`. In-process tools still use the daemon's network policy.
Only x86_64 and aarch64 Linux are supported. Bind sources are pinned by open harness descriptors,
resolved through the original host proc mount, so replacing a writable root or temp ancestor does
not grant a different directory. Missing protected paths inside a writable root are refused unless
an existing read-only ancestor covers them; create those paths before running a writable session.
The Seatbelt policy:

- writable: the workspace, the session temp dir, `sandbox.extra_writable`, and the device files
  commands need. Shared system temp directories are not writable by default;
- never writable, even inside a writable root: `<workspace>/.loom`, the loom home, and
  `sandbox.protected_paths`. The session temp dir (`<loom home>/sessions/<id>/tmp`) is the exception:
  what is in it can be written, and it tests as writable, but the directory itself cannot be removed,
  renamed, replaced or swapped for a link. A temp dir that is `/`, or is or contains the loom home, is
  refused;
- not readable, and not writable either (renaming and removing included), wherever they lie, even in
  the workspace: `<loom home>/token`, `<loom home>/keys`, `<workspace>/.loom/oracle-secrets`, `sandbox.unreadable_paths`, and, while
  `sandbox.protect_credentials` is on (default), the user's credential stores (`~/.ssh`, `~/.aws`,
  `~/.gnupg`, `~/.config/gh`, `~/.config/gcloud`, `~/.azure`, `~/.kube`, `~/.docker/config.json`,
  `~/.netrc`, `~/.npmrc`, `~/.pypirc`, cargo and git credentials, `~/.password-store`, `~/.config/op`,
  `~/.cache/huggingface`, `~/.huggingface`, `~/.pgpass`, `~/.my.cnf`, `~/.mylogin.cnf`, `~/.vault-token`,
  `~/.terraform.d`, `~/.config/rclone`, `~/.s3cfg`, `~/.boto`, `~/.gem/credentials`, `~/.m2/settings.xml`,
  `~/.m2/settings-security.xml`, `~/.gradle/gradle.properties`, `~/.yarnrc.yml`, `~/.composer/auth.json`,
  `~/.codex/auth.json`, `~/.claude.json`, `~/.claude/.credentials.json`, `~/.config/github-copilot`,
  `~/.config/hub`, `~/.config/glab-cli`, `~/.oci`, `~/.config/doctl`, `~/.fly`, `~/.config/heroku`,
  `~/.heroku`, `~/.config/netlify`, `~/.config/sops`, `~/.age`, `~/.config/age`, `~/.bitcoin`,
  `~/.ethereum`, `~/.config/solana`, `~/.wrangler`, `~/.config/.wrangler`, `~/.pulumi`,
  `~/Library/Keychains`, `~/Library/Cookies`, the Chrome (also Beta and Canary), Chromium, Brave, Edge,
  Arc, Vivaldi, Opera, Firefox and Safari profiles; under `~/Library/Application Support`: `Bitwarden`,
  `Bitwarden CLI`, `1Password`, `Telegram Desktop`, `Claude/claude_desktop_config.json`, `doctl` and
  `sops`; `~/Library/Containers/com.bitwarden.desktop`, `~/Library/Preferences/netlify`,
  `~/Library/Preferences/.wrangler`, `~/Library/Group Containers`, `~/Library/Mail`, `~/Library/Messages`).
  Other stores go in `sandbox.unreadable_paths`. A store that is or
  contains the workspace is skipped; when the home directory is unknown the sandbox is refused. A path
  that a link makes differ from its canonical form is denied as written too;
- a writable directory that holds any of these, or the session temp dir, cannot be removed or renamed,
  nor created as a link, since that would carry what it holds out of its rule;
- denied: LaunchServices opens (`lsopen`), Apple Events, launchd job creation, and signals to anything
  outside the sandbox;
- network: denied, except loopback connections to the egress proxy, to `sandbox.loopback_ports` (or
  every loopback port with `loopback_all`) and to `sandbox.unix_sockets`; listening on loopback is
  allowed.

Git configuration, hooks and gitdir/commondir pointers are protected by default. Existing nested
repositories and linked worktrees are discovered without running host Git; resolved gitdir and
commondir metadata is protected too. Discovery refuses unreadable or excessive trees (100000
workspace directories, 4096 metadata pointers, 4096 bytes per pointer). Seatbelt and file tools also
refuse future nested `.git` configuration/hook writes. Bubblewrap freezes discovered Git directories
as a whole; it cannot reserve future `.git` names in writable directories, so new repositories must
be created outside a session. These protections do not establish immunity to arbitrary host Git bugs.

Paths are made canonical when the sandbox is built. On macOS the rules that refuse are compared without
regard to case (volumes are case-insensitive by default); the rules that allow are compared exactly. The
file tools apply the same policy in-process (`check_read`, `check_write`) to the path resolved through
links, so a link inside the workspace grants nothing; in mode `none` they still apply the never-writable
and not-readable rules. `read`, `write` and `edit` apply it again to the real path of the object they
opened, never only to a path checked earlier, so a directory swapped for a link during a call grants
nothing either: a file is opened and the real path of the open descriptor is checked (macOS
`F_GETPATH`, Linux `/proc/self/fd`; elsewhere the file tools refuse to work); a write opens the
directory without following a link in its last component (missing directories are made one at a time
below an open ancestor, each checked first and opened without following a link), checks the real
path of that directory joined with the file name, and creates, syncs and renames the temporary file
relative to that descriptor. A file name that is itself a link is read and followed by the writer, at
most 8 links, so the directory checked is the target's. A role with `read_only` gets no `extra_writable`
and its workspace is added to the never-writable paths, so it can still write in its session temp dir,
and to the device files, and nowhere else. This is a write policy; readable untrusted files remain
untrusted inputs. In `none`, read-only roles do not constrain shell commands. Commands get the daemon's environment without any variable whose
name (case-insensitive) contains `KEY`, `TOKEN`, `SECRET`, `PASSWORD`, `PASSWD`, `PASSPHRASE`,
`CREDENTIAL`, `AUTH_TOKEN`, `COOKIE`, `SESSION_KEY` or `PRIVATE`, has `SESSION`, `AUTH`, `PASS`, `JWT`
or `WEBHOOK` as a part delimited by `_` or the ends of the name, ends in `_PAT`, `_DSN`, `_PWD` or `_PW`,
is `DATABASE_URL`, `SSH_AUTH_SOCK` or the `api_key_env` of any model profile, or starts with `LOOM_`, or
whose value holds, anywhere, a URL with a password in its user-info part (`scheme://user:password@host`)
(unless listed in `sandbox.env_pass`), plus
`TERM=dumb`, `NO_COLOR=1`, `PAGER=cat`, `GIT_PAGER=cat`, `GIT_TERMINAL_PROMPT=0`, `TMPDIR` = the temp
dir, and the proxy variables.

**Egress proxy** (`loom-net::proxy`, `policy`; their module documentation is the precise
specification). One HTTP/1.1 proxy on `127.0.0.1:daemon.proxy_port` (0 = any free port): `CONNECT`
tunnels, plain-HTTP forwarding of absolute `http://` URIs (one request per connection, proxy headers
dropped, `Connection: close`), and the check `LOOM-CHECK`. Anything else, a head above 64 KiB, or no
head within 10 s gets `400`.

- Every session, also under `deny_all`, gets credentials (user = session id, a random password) and
  the variables `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and their lower-case forms, with `NO_PROXY`
  empty; so every decision is attributed. Missing or wrong credentials get `407`. A session's grant is
  revoked when it settles.
- **Policy** (`[network]`): `mode` is `deny_all` (the default: tools reach no host; model requests are
  not affected), `allowlist` (only hosts matching `allow`: `host` or `*.suffix`, optional `:port`) or
  `open` (every public destination). The name is checked first: a `deny` entry wins, then the mode.
  The proxy then resolves the name itself and checks every address before connecting: `deny` entries
  that are IP literals or CIDR blocks match the resolved address, before any allow and before
  `allow_private`, in every mode; a private, loopback, link-local or otherwise special address is
  refused unless `allow_private` lists the name (pattern) or the address (literal or CIDR). The
  connection is made to the first allowed address, never by name again, so a second lookup cannot
  change the destination. Rules are reported as `deny {entry}`, `mode deny_all`, `not in allow list`,
  `allow {pattern}`, `mode open`, `allow_private {entry}` or `deny private-address {addr}`.
- **Per-session scope grants.** The operator can authorize more hosts for a running mission without a
  restart (`Runtime::grant_scope`, `POST /api/sessions/{id}/scope`, `loom scope`). The egress policy of
  every running session of the mission becomes the configured network plus the granted hosts: under
  `deny_all` the granted hosts become an allowlist, under `allowlist` they are added to `allow`, under
  `open` nothing changes. The configured `deny` list and the private-address rules still bind a granted
  host. The lead records the grant in the ledger (`ScopeGrant`, when the mission keeps one) and gets a
  protected note; no turn starts. A grant lives as long as the mission's sessions: a session started
  or restored later is built from the configured network plus the ledger's `granted_hosts()`, so
  grants survive a daemon restart. A lead asks with the `request_scope` tool (`hosts`, `why`), which
  opens a non-blocking inbox question and grants nothing; the agent carries on and may use the hosts
  once they appear in its state block as authorized.
- **Special addresses**: IPv4 0/8, 10/8, 100.64/10, 127/8, 169.254/16, 172.16/12, 192.0.0/24,
  192.168/16, 198.18/15, 224/4 and above; IPv6 `::`, `::1`, fc00::/7, fe80::/10, ff00::/8, 100::/64,
  100:0:0:1::/64, 2001::/23 (Teredo among them) except 2001:1::1–3, 2001:3::/32 and 2001:4:112::/48,
  2001:db8::/32, 3fff::/20, 5f00::/16, and the rest of 64:ff9b::/32. IPv6 forms that carry an IPv4
  address — IPv4-mapped, IPv4-compatible, NAT64 (`64:ff9b::/96` and the /96 form of `64:ff9b:1::/48`)
  and 6to4 (`2002::/16`) — are judged by that IPv4 address, for the special ranges, the deny list and
  `allow_private`. Entries written in the mapped, compatible or NAT64 form stand for the IPv4 block
  they carry (an `allow_private` entry of that kind wider than /8 is refused at load); entries in 6to4
  form match 6to4 addresses only. Network-specific NAT64 prefixes are not unwrapped: listing one in
  `allow_private` admits every IPv4 address behind it.
- **Answers.** A refusal is `403` with `X-Loom-Proxy: 1` and a text naming the destination, the rule,
  and that the operator sets the policy; an unreachable destination is `502`. Every response the proxy
  generates carries `X-Loom-Proxy: 1` and `Connection: close`; a destination's plain-HTTP response head
  is re-written with CRLF line ends, without any `X-Loom-Proxy` header, and with the destination's
  `Connection`, `Keep-Alive` and `Proxy-Connection` headers replaced by `Connection: close` (one that
  does not parse, or whose `Content-Length` is invalid or conflicting, gets `502`). A forwarded
  connection carries one request and one response: the request body is forwarded up to its end, the
  response is relayed up to the end its head gives (none for `HEAD`, `204` and `304`, the last chunk
  and trailers, `Content-Length` bytes, else the destination's close), and then the connection is
  closed, so a destination cannot answer a later request on it. When the client sends more than its
  request, a response that runs until the destination closes is cut after its head. The tools' HTTP
  clients keep no idle connections. `LOOM-CHECK host:port` (or `http://host:port/`) applies the policy
  and resolves the name but connects to nothing: `200` allowed, `403` refused, `502` the name does not
  resolve, with the rule in `X-Loom-Rule`.
- **Limits** (`loom_net::Limits` defaults, not configurable): 256 connections in all — at the limit a
  new one takes the slot of the oldest connection that has not sent a head yet or is only being
  answered by the proxy itself, else `503` with `Retry-After: 5`; 64 per session (`429`, `Retry-After:
  5`); 16 name lookups at once, 4 per session, 10 s each; a 10-minute idle timeout with no byte either
  way (a forwarded request with no answer yet gets `504`); a forwarded request whose client has ended
  its side still gets the response, until the destination is silent for 30 s.
- **Audit.** Every decision goes through the runtime's audit hook. An allowed connection's record is
  written to `sessions/<sid>/net.jsonl` and synced after the lookup and TCP connect and before any byte
  moves either way; when it cannot be written the client gets `502` saying that the egress audit log
  could not be written, and the connection is closed. Refusals, unreachable destinations and the
  proxy's own `400`/`407`/`429`/`503` answers are recorded best effort. A connection on record as
  allowed that then fails gets a second decision with the rule suffixed `(failed after the allow:
  …)`; a check is recorded with method `LOOM-CHECK` and the rule suffixed `(check only)`. Answers that
  name no granted session go to `logs/net-unattributed.jsonl`, at most 10 a minute, the next one saying
  how many were left out; the API has no reader for that file, and these decisions are not published.
  Each decision attributed to a session is also published as a `net` event once its record is written.
- **The audit file is a chain** (`loom-net::netlog`). Each line's `prev` is the SHA-256 of the previous
  line's bytes (64 zeros for the first); appends are serialised and each is synced. Lines written
  before the chain existed (no `prev`) still load, and the chain starts at the first line that has it.
  An unterminated final fragment that is not a JSON object is a torn append, not a break: it is cut off
  before the next append, and readers verify the lines before it. `GET /api/sessions/{id}/net` and
  `loom net` verify the chain and refuse to serve a broken one, with a sentence naming the line.

## 12. Daemon API (`loom-daemon`)

The module documentation of `api.rs`, `auth.rs`, `serve.rs` and `client.rs` is the precise
specification.

**Listening.** `[daemon] bind` must name a loopback host (`127.0.0.1`, `localhost` or `[::1]`, checked
when the config is loaded), and the daemon binds only a loopback address the name resolves to (a name
that resolves to none is refused). Every request passes three gates: the `Host` header must be exactly
`127.0.0.1:<port>`, `localhost:<port>` or `[::1]:<port>` with the bound port (else `403`); a request
other than GET or HEAD with an `Origin` must come from `http://` and one of those hosts (else `403`);
and every route except those marked open below needs `Authorization: Bearer <secret>`, where the secret
is the API token (`~/.loom/token`) or a web-session secret (else `401`).

**Web login.** There are no authentication cookies (a cookie is sent to every port on the host,
including a dev server an agent started). `loom open` asks for a login code with the API token and
opens `http://<bind>/#code=<code>`; the token is never printed or put on a process's argv. Codes are 32
hex characters, single use, valid 60 s, compared in constant time, held in memory only, at most 16
outstanding (the oldest dropped). The page trades the code for a web-session secret (32 hex, in memory
until the daemon exits, at most 32, the oldest dropped), keeps it in `sessionStorage`, removes the
fragment from the address bar, and sends it as the bearer of every request, event streams included
(which it reads with `fetch`, since `EventSource` cannot send headers). After a daemon restart the page
asks for `loom open` again. `GET /?token=<API token>` (older clients) answers `303` to
`/#code=<fresh code>` and sets no cookie; the index page tells a browser that still holds an older
daemon's `loom_token` cookie to drop it.

**Identity proof.** `GET /healthz?nonce=<32–128 hex>` answers `{"ok": true, "proof": hex(HMAC-SHA256(key
= the token's bytes as stored (64 hex characters), "loom-healthz-v1:" + nonce))}`, which only a holder
of the token can compute; without a nonce it answers `ok`, and a malformed nonce is `400`. The CLI
(`Client::from_home`) asks for a fresh proof before every request that would carry the token, stream
openings included, and compares it in constant time; a listener that cannot prove itself does not get
the token, and the error says to restart an older daemon (`loom --unverified-daemon down`, then `loom
up`). The global flag `--unverified-daemon` sends the token anyway with a warning. `loom up` and `loom
daemon` do not take an unproven listener for the running daemon. loom-desk proves the daemon the same
way (gui/DESIGN.md).

**Routes.** JSON unless noted. The bodies of `crate::wire` and `NewSession` (at its top level) reject
unknown fields; the `{code}` body of `POST /api/web-sessions` and the `budget` object inside
`NewSession` ignore them.

```
Open (no bearer):
GET  /                                        the UI page; ?token=<API token> → 303 /#code=<code> (else 401)
GET  /app.js  /core.js  /style.css            UI assets
GET  /healthz                                 "ok"; ?nonce=<hex> → {ok, proof}
POST /api/web-sessions                        {code} → {secret}; a wrong, used or expired code → 401

API token only (a web-session secret is refused):
POST /api/login-codes                         → {code, expires_in_s: 60}

API token or web-session secret:
GET  /api/status                              → StatusView
GET  /api/sessions?archived=true|false        → [SessionInfo], newest first
POST /api/sessions                            NewSession → 201 SessionInfo
                                              {workspace, pack?, role?, model?, title?, unattended?, budget?, message?}
GET  /api/sessions/{id}                       → SessionDetail (SessionInfo + children, oldest first)
GET  /api/sessions/{id}/records?after=&limit= → {records, next_after}   (limit: default 500, at most 2000)
GET  /api/sessions/{id}/stream?after=         SSE, below (Last-Event-ID when after is absent)
POST /api/sessions/{id}/messages              {text} → 202 {}
POST /api/sessions/{id}/rules                 {text} → 202 RuleReceipt
POST /api/sessions/{id}/approvals             {text, scope?} → 202 RuleReceipt
POST /api/sessions/{id}/rules/{rule_id}/withdraw   {reason?} → 202 RuleReceipt
POST /api/sessions/{id}/scope                 {hosts, note?} → 202 ScopeReceipt {lead, hosts, ledger}
POST /api/sessions/{id}/release               {reason} → 202 RuleReceipt
POST /api/sessions/{id}/stop                  → 202 {}
POST /api/sessions/{id}/resume                → 202 {}
POST /api/sessions/{id}/reweave               → 202 {}
POST /api/sessions/{id}/archive               {archived} → 200 {}
GET  /api/sessions/{id}/window                → WindowView
GET  /api/sessions/{id}/net?limit=            → [NetEntry], the last `limit` (default 200, at most 2000)
GET  /api/missions                            → [MissionInfo]
GET  /api/missions/{id}/ledger                → LedgerView {state, markdown, skipped, skipped_detail, torn_tail, ahead_of_head}
GET  /api/inbox                               → [InboxEntry], oldest first
POST /api/inbox/{item_id}                     {answer} → 202 {}
GET  /api/blobs/{handle}                      → BlobRef {id, bytes, lines}
GET  /api/blobs/{handle}/raw                  the stored bytes (application/octet-stream, attachment)
GET  /api/blobs/{handle}/lines?start=&end=    → {text, first, last, total}  (1-based; default 1–2000, ≤ 5000 lines)
GET  /api/events?deltas=true|false            SSE, below
POST /api/gc                                  {apply?} → SweepReport
POST /api/shutdown                            → 202 {}
```

The wire types are `crate::wire` and the serde form of the runtime's types; `docs/UI.md` lists the
conventions. **Records** are served as this build reads them: a known record is re-encoded field for
field (fields an older line lacked appear with their defaults), and a record read as `Event::Unknown`
(a kind this build does not know, or an opaque record) is served as its stored line, verbatim, by the
records route and by a session stream's replay (a carriage return between its tokens goes out as a
space on a stream). The stored line is the record of truth; `prev` verifies against the file, not
against re-encoded JSON.

**Errors.** Every non-2xx answer has the body `{"error": "<sentence>"}`. `400`: a body or query that is
not valid; `401`: a missing or wrong bearer; `403`: the Host or Origin gate; `404`: an unknown path, a
runtime answer that starts with "There is no" or "No ", a blob handle that is unknown or malformed;
`405`: a wrong method; `409`: every other runtime refusal, an ambiguous blob handle (the sentence lists
up to 5 candidate ids), an unreadable blob; `500`: a read that could not be finished. Every response
carries `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`; the page and assets also carry
the content security policy (`ui::CSP`) and `Referrer-Policy: no-referrer`.

**Event streams.** Server-sent events. No frame has an `event:` field; each has one `data:` line with
a JSON `BusEvent` whose `type` is the kind — `session` {info}, `record` {session, record}, `delta`
{session, req_id, delta}, `status` {session, status}, `net` {session, entry}, `settled` {session,
settlement}, `error` {session?, message}, `lagged` {missed}. A record frame adds `id: <seq>`; the
others carry `data:` only. A comment is sent every 15 s. A `delta` is `attempt_start`, `text`,
`reasoning`, `tool_call_start`, `tool_call_args` or `retrying`. `/api/events` sends every event of the daemon, deltas only with `deltas=true`.
`/api/sessions/{id}/stream` sends the session's status first, then its records after `after` from the
log, then its live records, deltas and statuses, without duplicates. A subscriber that falls more than
8 192 events behind gets `lagged` (a session stream then replays the records it missed from the log).
Streams end when the daemon stops.

**Running.** `loom daemon` (and `loom up`, which starts it in the background, or `loom service install`,
a launchd agent that restarts it after a crash) raises its open-file limit, creates the home and its top-level directories (0700, tightened if they exist looser) and
takes an exclusive lock on `daemon.lock` for its lifetime, so a second daemon on the same home is
refused (`A loom daemon is already running for <home> (pid N, <addr>).`) even when both start at once.
It then loads and checks the config, checks that the sandbox mode can work on this host, creates or
reads the token (0600, atomically, never replaced), binds, starts the runtime, writes `daemon.json`, and
serves until SIGINT, SIGTERM or `POST /api/shutdown` (`loom down`), giving open requests 3 s.

**Start** (`Runtime::start`). Packs are loaded and every role's tools checked (a broken pack stops the
daemon); then the journal key, blob store, model clients and proxy. Every session's `meta.json` and
`status.json` are read. Activated: sessions that are not archived, not ended, and were running a turn,
waiting, holding open inbox items, or ended a turn `yielded` while a job they started was unsettled
or was told how a job ended with no turn since; and every unsettled child of a mission that is not
archived (parents first). Before activation, off the async workers, a previous daemon's leftover
process groups are cleared for every other session that is not archived (the output and status of a
command that ended by itself stay for its session).
Opening a session's log records a cut turn as `interrupted` (the harness was restarted) with a
`stopped` turn end, and settles the previous daemon's jobs (§11, Jobs). Then: an unattended root whose
turn was cut, or that was waiting with no unsettled agent, is resumed; any root that was waiting or
yielded and was told how a job ended with no turn since is resumed, attended or not; children are held
or resumed as in §9; deliveries a
restart cut are recovered; and every open blocking inbox item is notified again (`Still waiting: …`)
with its repeat armed. A session of a pack that requires a restricted network is not activated (nor
created) while the network mode is `open`.

**Shutdown.** Every running turn is cancelled first: a running tool gets TERM, then KILL after
`tools.kill_grace_s`, its result is recorded, and the session records `interrupted` (the harness was
restarted) and a `stopped` turn end; a child is not settled, so the next start resumes it. Idle
sessions end when their inputs close, after killing their jobs and recording how those ended (each
end says that the shutdown stopped the job). The runtime waits up to `kill_grace_s` + 3 s for the
tasks, then aborts the rest, kills the jobs and stops the proxy. A lead blocked in a call that waits for an agent
is let go at once and the call keeps no result; what the call had started is already in its log.

**Operator actions.** Messages go to root sessions only. Rules, approvals and withdrawals may name any
session of a mission and go to its lead: each is written durably to the lead's `queued/` before it is
sent and deleted once the lead has recorded it (at once when idle, at the next step of a running turn,
never during a tool call; replayed oldest first when the lead next runs, so a daemon stop does not lose
it). The answer (`RuleReceipt`) names the lead and says whether it was in a turn (`queued`), whether
the mission keeps a ledger (without one a rule is a note with no id), and the stock scope or reason
recorded for a blank one. A withdrawal names a rule id the ledger has in force. `stop` reaches any
session; `resume` and `archive` roots only; archiving is refused while the mission is running a turn.
The same actions exist in the CLI (`loom send`, `rule`, `approve`, `rule --withdraw`, `stop`,
`resume`, `reweave`, `archive`, `answer`) and in the web UI.

**Scope and release.** `POST /scope` (`loom scope`) is the only way a session's reachable hosts grow
while it runs, and only the operator can call it: it goes to the mission's lead like a rule and is
recorded as a `scope_grant` (and a standing rule); the grant lasts as long as the session. An agent asks
with the `request_scope` tool, which opens a non-blocking inbox item (kind `approval`, the hosts as its
`options`, the reason as its text) and does not stop the session; the UI and app show the hosts with an
Approve button that calls `/scope` and then resolves the item, and `loom inbox` prints the `loom scope`
command to run. Nothing is granted without that call. `POST /release` (`loom release`) takes a reason,
which must not be blank, records an `operator_release` and closes the mission; the outcome reads "closed
by operator, goal not established", never "finished". A blocking blocker or park offers the choices
"Keep working", "Keep working (more budget)" (budget parks), "Provide what's missing" (blockers) and
"Accept as blocked and close"; the last needs a typed reason and a confirmation. `GET /api/missions/{id}/ledger`
carries `scope_grants`, `goal_met` and `release`, which the UI shows as the granted hosts and the outcome.

**Notifications.** Every `inbox_opened` and every session that fails notifies the operator: with
`notify.command` set, that program is run (no shell) with `LOOM_KIND`, `LOOM_SESSION`, `LOOM_TITLE` and
`LOOM_TEXT` (500 characters) in its environment and killed after 30 s; otherwise, on macOS, a
notification through `osascript` with the texts as arguments; on any other platform with no
`notify.command`, nobody is notified, and the daemon logs one warning at start saying so and how to set
`[notify] command`. With `notify.repeat_minutes` above 0 a blocking item is announced again at that
interval while it stays open. The text of an item a tool call opened (written by the model) starts with
`[From the agent, unverified] `; in an item the harness opened itself, the paragraph that quotes the
ledger carries the same label. A child's title was written by the model and starts with `unverified: `.
When the volume of the loom home turns low (under 5 GiB or 5 percent free, checked once a minute) one
notification of kind `disk` is raised, and no other until the disk has recovered and turned low again;
the web UI shows a warning line while `GET /api/status` reports the disk as low.

**Garbage collection.** Stored outputs are never deleted except by an explicit collection: `POST
/api/gc {"apply": bool}` (default a dry run), `loom gc [--apply]`. A blob is kept when its full id
appears (either case) in any file under `sessions/` and `missions/`, or a handle of it (`out:` and 8 to
16 of its hex characters) does, or when it is younger than one hour; removing a session's directory is
what makes its outputs collectable. The scan follows links only for the direct entries of those two
directories, never opens FIFOs, sockets or devices, skips the sessions' `tmp/`, reads at most 4 GiB of
one file and runs at most 5 minutes; past a limit, or on an entry it cannot read, it stops and deletes
nothing, with a `409` naming the path. A blob is moved aside and its age checked again before it is
deleted, so one stored again meanwhile survives. `SweepReport` gives examined, kept and collected
counts and bytes and whether it applied. The blob store itself writes each line index through a synced
temporary file and rename, syncs the shard directory, rebuilds a missing or inconsistent index from the
blob, refreshes a blob's age when the same bytes are stored again (or writes it anew when it cannot),
and removes temporary files older than an hour when it opens.

**Status.** `GET /api/status` (`loom status`) reports the version, pid, address, proxy port, home, each
model profile (reachable, served model, window, `max_concurrent`), session and inbox counts, and `disk`
(`{free_bytes, total_bytes}` of the volume that holds the home, or null); `loom status` warns when less
than 5 GiB or 5 percent of it is free.

## 13. Packs (`loom-agent::pack`)

A pack is a directory holding `pack.toml`, an optional preamble file and the role prompt files; the
module documentation of `pack.rs` is the precise specification.

```toml
name = "core"                         # [a-z0-9-]+
description = "…"
default_role = "lead"
preamble = "harness.md"               # optional; the built-in preamble otherwise
requires_restricted_network = false   # true: sessions refused while [network] mode = "open"

[roles.lead]
description = "…"
prompt = "roles/lead.md"
termination = "explicit"              # or "free"
tools = ["bash", "read", "…"]         # request order
may_spawn = ["worker", "verifier"]
verify_finish = true
verifier = "verifier"                 # default: the pack's role named verifier
read_only = false
```

Unknown keys are errors, file paths stay inside the pack directory, and an invalid pack stops the
daemon rather than run without it. The built-in `core` pack (compiled into the binary) has `lead`,
`worker`, `verifier` and `chat`; packs in `~/.loom/packs/` are loaded after it, and one named `core`
replaces it. A role that needs a verifier (`verify_finish`, or an explicit `verifier`) must name a role
of the same pack that is `read_only` and has `verdict` and `out_read` or `out_grep`. A pack with
`requires_restricted_network = true` says in its prompts that the network is restricted, so its sessions
are refused at creation and at every activation while the network mode is `open`. The system prompt is
the preamble, the role prompt and an `# Environment` section, joined by blank lines and identical for
identical inputs.

Two tools belong to roles that may need them. `request_scope {hosts, why}` asks the operator for hosts
(see section 12); `core` `lead` and `chat` and `vr` `researcher`, `scout` and `chat` have it. `conclude
{status: "met" | "unreachable", note, evidence}` records the goal-met claim in the ledger; a role finishes
only after it, and `chat`, which keeps no ledger, does not have it. The prompts say that not being there
yet is a note, not a finish, that a rejection is answered with new execution evidence, and that an
operator message is input, not permission to finish.

The repository also ships `packs/vr` (vulnerability research: `researcher`, `scout`, `judge`, `chat`;
the researcher's finish is verified by `judge`). Domain discipline is a pack, not core.

## 14. Engineering rules

- Rust 2021, stable (`rust-version` 1.85). Dependencies come from `[workspace.dependencies]`; add there
  if you need one.
- No `unwrap`/`expect`/`panic!` outside tests, except on invariants established in the same function.
- Errors are typed per crate with `thiserror`; messages that reach the model say what to do next.
- Every module has unit tests; anything that touches disk uses `tempfile`. Tests never need the
  network or a real model — use `loom_model::mock`.
- No telemetry of any kind. No network access except what this document names.
- Building is plain cargo: `cargo build --release -p loom-daemon`, `cargo test --workspace`,
  `cargo clippy --workspace --all-targets -- -D warnings`. The UI's pure module is tested with
  `node --test ui/core.test.js`. `./x` is an optional wrapper that copies the tree to another host
  named by `LOOM_BUILD_HOST` and runs cargo there (`LOOM_BUILD_HOST=local` runs it in place;
  `LOOM_LANE` gives a run its own source copy and target directory on that host). Set
  `LOOM_BUILD_HOST` before using it: unset, the script falls back to a host name of its author's.

## Roadmap (not implemented)

Earlier versions of this document described these; the code does not have them. Nothing here may be
relied on.

- An MCP stdio client in `loom-tools`, and external MCP servers as tool providers.
- Pack plugin processes contributing tools and hooks (`pre_tool`, `hud`, `stop_gate`, `scope`).
- An `evals/` directory of behavioural checks against the mock or a live model.
- `tool_choice` or guided decoding per model profile, and forcing a tool call after repeated invalid
  calls (the config key `agents.invalid_calls_before_forcing` is accepted and has no effect).
- A `return_result` tool for children (they end with `finish` or `report_blocker`), and the tools
  `agent_wait` and `agent_list` (the lead uses `wait` and the HUD).
- Ledger obligations written by the runtime for running jobs, children, promoted jobs, questions or
  unverified edits, and recorded approval uses (the ops exist; nothing writes them).
- Generated ledger views in the workspace (`<workspace>/.loom/`, `render_views(dir)`).
- A stop-gate check of a role's return contract.
- Project instruction files (such as `AGENTS.md`) in the system prompt.
- A login route `GET /auth?token=` and an authentication cookie.
- Named SSE events (`record`, `delta`, `state`, `session`, `inbox`), an `inbox` event, a `cascade`
  option on stop, and a text/plain line-range route `GET /api/blobs/{id}?start=&end=`.
- A stderr line count in the `bash` header (stdout and stderr are one stream).
- A separate handle to the full list of a `glob` or `grep` result beyond the stored result itself.
- Staleness across the mission (a file another session modified).
- Background request priority for digests and titles (`Priority::Background` exists and nothing uses
  it; titles are not written by a model).
- A warning when a configured context window is larger than the one the server reports
  (`Discovered::server_window` is computed and not reported).

### Reference service capabilities

`network.reference_hosts` reserves host patterns for trusted in-process GET clients. The raw command
proxy refuses those names even when `allow`, open mode, or a mission grant would permit them. A
separate random `ReferenceGrant` is held in tool memory and never included in command environment
variables; revoking a session revokes both grants. Deny and resolved private-address rules still apply.
Plain HTTP reference requests permit GET only and strip Authorization, Cookie and Referer. HTTPS
CONNECT remains opaque: the in-process client must enforce GET and credential stripping, reject URL
user-info, and recheck each redirect. Name reservations are not alias/IP or data-flow isolation.
GET paths and queries can disclose data, so this is not an exfiltration-proof channel.
