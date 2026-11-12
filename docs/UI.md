# The web UI

The UI is what the operator leaves open while missions run. It is four static files in `ui/`
(`index.html`, `style.css`, `core.js`, `app.js`), embedded in the binary and served by the daemon at
`/`, `/style.css`, `/core.js` and `/app.js`. No build step, no framework, no dependency, nothing
loaded from anywhere else.

It exists because of what went wrong in the harness loom replaces: tool output that was cut without
a trace, context compaction the operator could not see, questions that waited for hours because
nothing said they were waiting, and model output that could load remote images. So the UI's job is
to make the record, the context and the things waiting for the operator *visible*.

## Hard rules

- **Content security policy** (sent by the daemon): `default-src 'none'; script-src 'self';
  style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none';
  frame-ancestors 'none'`. So: no inline `<script>`, no inline `style=""` attribute, no `on…=""`
  attribute, no `eval`. Styles come from classes; dynamic sizes (the context meter) use
  `element.style.setProperty` from script, which the policy allows.
- **Text from records is never parsed as HTML.** Everything a model, a tool or the network produced
  is inserted with `textContent` / `createTextNode`. There is no `innerHTML` with data in it, no
  Markdown-to-HTML conversion, no linkifying into `<a href>` except for links the UI itself builds
  to its own routes. Images are never rendered from record content.
- **Authentication** is a bearer secret; there is no cookie. The page and its three assets need no
  authentication; every `/api` request does, except the code exchange `POST /api/web-sessions`, where
  the login code is the credential. `loom open` (or loom-desk) opens the page as
  `/#code=<login code>`: at load the page takes the single-use code from the fragment, removes the
  fragment with `history.replaceState`, and trades the code for a web-session secret
  (`POST /api/web-sessions {code}` → `{secret}`). The secret is kept in `sessionStorage` (in memory
  when storage is blocked) and sent as `Authorization: Bearer <secret>` on every request, event
  stream included; every `fetch` uses `credentials: "omit"`. With no code and no stored secret, or
  on a `401` anywhere, the page is replaced with: `This page is not signed in. Run "loom open"
  again.` Web-session secrets live in the daemon's memory, so a daemon restart needs `loom open`
  again.
- Works in current Safari, Chrome and Firefox. ES modules (`<script type="module" src="/app.js">`).
- `core.js` is pure (no `document`, no `window`, no `fetch`): state, reducers, formatting, parsing.
  It is what `node --test ui/core.test.js` exercises. `app.js` is the DOM and the network.

## Data

Routes and bodies: `crates/loom-daemon/src/api.rs`, `wire.rs`, and the types they name in
`crates/loom-agent/src/runtime.rs` (`SessionInfo`, `BusEvent`, `InboxEntry`, `WindowView`,
`LedgerView`, …), `crates/loom-agent/src/session.rs` (`Status`), `crates/loom-core/src/event.rs`
(`Record` and every event kind), `crates/loom-core/src/ledger.rs` (`LedgerState`). Read those files
for the exact field names — serde conventions: enums and `kind`/`type` tags are `snake_case`; a
`Record` is flat (`{seq, ts_ms, author, prev, kind, …fields of the event}`); `author` is `"user"`,
`"model"`, `"tool"`, `"harness"` or `{"agent": "s-…"}`; `SessionInfo` is its `meta` fields
flattened plus `active` and `status`. One exception to the names in the Rust types: an inbox item's
kind is `item_kind` on the wire (in an `inbox_opened` record and in `InboxEntry.item`), because
`kind` is the record's own tag.

- At load: `GET /api/sessions?archived=true`, `GET /api/inbox`, `GET /api/status`; then one stream
  on `/api/events?deltas=true` for everything live. `EventSource` cannot send an `Authorization`
  header, so the stream is read with `fetch` and a streaming reader, and `core.js` parses the
  server-sent events. No frame has an `event:` field: each has a `data:` line with one JSON object
  whose `type` is the kind (`session`, `record`, `delta`, `status`, `net`, `settled`, `error`,
  `lagged`), and a `record` frame also has `id: <seq>`. The daemon sends a comment every 15 s; a
  stream silent for 45 s is dropped. A dropped stream is opened again after 1 s, doubling up to 15 s;
  the header's dot is red meanwhile.
- Opening a session: `GET /api/sessions/{id}/records` page by page (`after`, `next_after`) until
  the end, then keep it current from the event stream (records carry `seq`: apply one only if it
  is the next one; a gap means fetch the missing page). Sessions not open are not fetched.
- `lagged`, or the stream reconnecting: refetch the session list, the inbox, the status and the open
  session's records after the last seq held.
- A blocking inbox item is also announced with the browser's `Notification` API when permission was
  granted (a button in the inbox view asks for it; never ask unprompted).

## Layout

Three columns, full height, each scrolling by itself. Below 1100 px the right column becomes a
drawer opened from the header; below 700 px the left one does too.

### Left: missions

- Header: `loom`, a dot for the daemon/model state (green: every model reachable; amber: one is
  not — the tooltip says which and why; red: the event stream is disconnected), an **Inbox** button
  with the count of open items (highlighted when any is blocking), and **New**.
- The list: root sessions newest first, each with its agents nested under it (indent, role name).
  Each row: a state mark, the title, and one dim line: role · step N · context size · age.
  State marks (also used in the header of the transcript): running (animated), waiting for jobs or
  agents, needs you (an open inbox item — the most prominent), stopped, finished, failed, idle.
  A toggle at the bottom shows archived sessions.
- **New** opens a form: workspace (text, required), message (textarea, required), role (select
  from: lead, chat — default lead), model profile (select from `status.models`), title (optional),
  "resume by itself after a restart" (checkbox, default on). Submits `POST /api/sessions`
  and opens the new session. Errors are shown in the form, verbatim.

### Middle: the transcript

Header: title, state mark and words, `step N`, a context meter (below), and the actions that apply:
**Stop** (while running or waiting), **Resume** (after a stop), **Archive**/**Unarchive**.

The transcript is the session's record, in order, one block per record kind:

- `user_message`: the operator's words. Full width, strong.
- `harness_note`: labelled with its kind (`nudge`, `output_cut`, `budget`, `stall`, `arrival`,
  `assignment`, …), dim, collapsed to three lines with *show*. An `assignment` is open by default.
- `model_response`: reasoning first, collapsed to a one-line summary (`reasoning · N lines`) that
  expands; then the text, whitespace preserved (`white-space: pre-wrap`); a footer line: prompt
  tokens, cached share as a percentage, completion tokens, seconds, attempts when above 1. A reply
  cut by the output limit (`finish: "length"`) says so in amber.
- `tool_call` + its `tool_result` (matched by `call_id`): one block. Header: tool name, the
  arguments on one line (for `bash` the command itself, for file tools the path; otherwise compact
  JSON), status mark, duration. Body: the result text in a monospace box, collapsed beyond 24 lines
  (*show all N lines*). When the result has `cut: true` or a stored `output`, a line says how much
  the model was shown of how much (`meta.shown` ranges against `output.lines`) with **open full
  output**, which loads `GET /api/blobs/{handle}/lines` page by page into a viewer panel. A call
  with no result yet shows *running…*; a call whose turn was interrupted shows *no result
  recorded*. Status other than `ok` is marked red (`error`, `timeout`, `denied`, `invalid`,
  `interrupted`).
- `child_spawned`: a card — role, mode, the brief's question — linking to the agent's session.
  `child_settled`: outcome and the report (collapsed beyond 24 lines). An `inline` settlement is
  shown as a one-line marker only (its report is the result of the call above it).
- `job_registered` / `job_settled`: one line each.
- `ledger`: one dim line (`ledger #n: summary`).
- `reweave`: a full-width divider: `context re-woven (reason) — N items folded out of view, about X
  → Y tokens`, expanding to the list of evictions (seq, action) and the brief that was put in
  view. Nothing was deleted; say so in the expanded view: `Folded items stay in the record above
  and can be read back by the model.`
- `inbox_opened`: a prominent card with the text, the options as buttons (clicking one fills the
  answer), an answer box and **Send answer** (`POST /api/inbox/{item_id}`); for kind `finished`
  the card is the result, with **Dismiss** (an empty answer). Once the matching `inbox_resolved`
  exists the card shows the answer and no form.
- `cache_break`: an amber line (`cache break at message N: detail`). `interrupted`: an amber line.
- `turn_end`: a thin divider with the reason in words. `session_end`: a final line.
- `turn_start`, `model_request`, `pin`, `unpin`, `net`, unknown kinds: not shown, except that a
  toggle **details** in the header shows `model_request` lines (step, epoch, estimated tokens).

While a reply streams (`delta` events for the open session): a live block at the end with the
reasoning and text so far and the tool calls being written (name, then arguments as they arrive).
It is replaced by the real blocks when the `model_response` record arrives. `retrying` deltas show
`retrying (attempt N): reason`.

The view follows the end while the operator is at the end, and stops following when they scroll up
(a **jump to latest** button appears).

Composer (root sessions only; hidden for agents, with a line saying messages go to the lead):
a textarea, **Send** (Enter sends, Shift+Enter is a newline). While a turn is running, sending is
still allowed (the message is delivered between steps) and the button says **Send (delivered
between steps)**.

### Right: state

Tabs:

- **Ledger** (`GET /api/missions/{mission}/ledger`, refetched when a `ledger` record arrives for
  any session of the mission). At the top, the **Rules and approvals** control for the mission of
  the open session (a child's id is fine: the daemon routes it to the lead): a standing rule and
  **Add rule** (`POST /api/sessions/{id}/rules {text}`); something to approve, what it covers
  (optional) and **Approve** (`POST …/approvals {text, scope}`); then the rules in force, each with
  **Withdraw**, which opens a row asking for an optional reason and only that row's
  **Withdraw k<n>** sends (`POST …/rules/{rule_id}/withdraw {reason}`; **Keep** closes the row), and
  the approvals, a used one marked as such. Blank text is refused in the page. After the daemon's
  receipt the control says when the input is not recorded yet (the lead was in a turn and records it
  at its next step, not while a tool call runs; there is no need to send it again) or when the
  mission keeps no ledger (the lead gets it as a note that stays in its context, and nothing is
  listed). The control is built once per open session, so redraws of the ledger keep what is being
  typed. Below it: goal; constraints; plan (each step with its status mark and note); claims
  (status, with their evidence: quote, handle + lines, note; `attested` shown as a check); open
  obligations; decisions; dead ends; questions. When the mission has no ledger, the daemon's sentence
  is shown; a ledger with no entries yet says so.
- **Context** (`GET /api/sessions/{id}/window`, refetched on each `turn_end` and `reweave` and
  on demand): the meter — a bar scaled to the model's window showing what is in view, with marks
  at `floor_tokens` and `target_tokens`; the numbers (in view, last request's prompt tokens, cached
  share, epoch); then the items in view, each: seq, kind, state (`live`, `stubbed`,
  `reasoning_dropped`, `dropped`), size, a pin mark, the preview. A **Fold now** button
  (`POST …/reweave`). The header's small context meter is the same bar without the list.
- **Network** (`GET /api/sessions/{id}/net`, plus live `net` events): the newest 500 decisions,
  newest first: time, allowed/refused, method, host:port, the rule that decided. When the load
  failed (for example because the egress audit log is damaged) the daemon's sentence is shown in red
  above the rows, also while live decisions arrive.
- **Session**: id, mission, role, pack, model, workspace, created, budget, unattended, parent (a
  link), agents (links).

### Inbox view

Replaces the middle column: every open item, oldest first, with its session's title (a link), age,
text, options, answer box. Blocking items first. A line at the top: `Notifications: on/off` with
the button that asks for permission.

## Look

Dark by default, light with `prefers-color-scheme: light`. System font for prose, a monospace stack
for tool output and arguments. Dense but calm: the transcript is the page; chrome is quiet. One
accent colour for "needs you". No animation except the running mark.

## `core.js` (pure, tested with `node --test ui/core.test.js`)

At least: the session store (apply a session list, a `session` event, a `status` event; build the
tree of roots and agents; the state mark of a session from its `status` and open inbox count);
the record store of the open session (append in order, detect a gap, pair `tool_call` with
`tool_result`, pair `inbox_opened` with `inbox_resolved`, fold the live deltas into a pending
reply and clear it on the `model_response` with the same `req_id`); formatters (`tokens`: `812`,
`12.3k`, `1.05M`; `seconds`; `age`; cached share; the one-line form of a tool call's arguments;
shown-of-total for a cut output); the login code of a fragment (`#code=<hex>`), the server-sent-event
parser and the reconnect delay; the rules control's requests, lists and receipt sentences.
`ui/core.test.js` covers each of these.
