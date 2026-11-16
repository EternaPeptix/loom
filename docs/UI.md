# The web UI

The operator supervises missions through four static files in `ui/`: `index.html`, `style.css`,
`core.js`, and `app.js`. The daemon embeds them; there is no frontend build step or runtime
framework. `core.js` owns pure state and presentation decisions; `app.js` owns DOM and network IO.

## Content and authority

- Keep the daemon's strict CSP: scripts, styles and requests are same-origin; no inline handlers,
  executable record content, remote images, analytics, or third-party resources.
- Model prose may use a small presentation subset: headings, paragraphs, lists, bold text, inline
  code and fenced code. Create each element and text node directly. Source HTML, links and images
  stay inert. Every formatted response also exposes its exact raw text. Tool output stays raw.
- The event log remains the record. Overview text is derived deterministically from records and
  typed ledger fields; it is not a generated summary or a substitute for the full record.
- Display a quote's attestation as “Quote matches stored output.” Keep that distinct from recorded
  claim status and independent verification. The runtime refuses a quote that does not match, so
  an unattested quote is one it did not check: show “Quote not checked against stored output”,
  never a failed match. Opening evidence in the UI never changes model observation coverage or
  verifies a claim.
- Icons are drawings in the `<template id="icons">` of `index.html`, cloned by `app.js`. Markup is
  never built from strings, and a namespaced element is never created from script (the namespace
  URL would break the no-remote-URL check). Every drawing is `aria-hidden`; the words beside it
  carry the meaning, and each state has its own shape so it is not told apart by colour alone.
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

## Missions and navigation

![The pre-redesign overview tab with illustrative fixture data](images/mission-overview.jpg)

The sidebar lists root sessions grouped by workspace: the heading is the last component of the
workspace path (the full path is its tooltip), groups are ordered by most recent activity, and roots
inside a group likewise. A root's activity is the newest record of its whole mission. A **Needs you**
group is pinned on top whenever a root has a blocking item (its own or a child's); those roots appear
there instead of under their workspace. Agents are collapsed under the root by default; opening an
agent expands its ancestors. Archived roots remain hidden until Show archived is enabled.

Each row has one status mark, chosen by strict precedence: needs you, running, new since your last
visit (records after the stored watermark; a session never visited is not marked new), ended
failed, then idle or ended. An ended session whose outcome is `stopped` has its own square shape, not
the check of one that finished. A mission counts as running, or as waiting for jobs or agents, when any
session in it is. Every mark has its own shape and a word for assistive technology, so the state is
never told by colour alone. Line 1 is the title. Line 2 is the identity line in monospace,
`<profile> · <role> · <age>`. The profile is never truncated, so the model is readable at the sidebar's
272px; only the role and age after it may be cut. When something waits on the operator, the identity
line drops the age and the reason is a line of its own below it (for example "Approval waiting 5m", or
"3 requests waiting", in amber with the diamond shape). A nonblocking question ("Question open 2m",
a question mark in blue) and an available result ("Result ready 10m", an outline diamond in green) are
said the same way, without the urgent treatment. The age is the time of the latest recorded event the
page has seen, kept in tab storage beside the watermarks so it survives a reload; for a session whose
records have not been loaded it reads "activity not loaded". The creation time orders such rows but is
never shown as an age. The
earlier row summary (what waits and for how long, how the root stands, recorded activity) remains the
row's tooltip and description, so nothing it said is lost. Blocking requests, nonblocking questions
and available results have different labels, and only blocking requests use the urgent attention
treatment. Ages come from recorded times, never from creation, and activity that has not been loaded
is explicitly unknown. The open session's row is never "new": opening it, or returning to it from
Inbox or New mission, moves its watermark to the latest record. The agents toggle under a mission says how many agents it has and how many are
running. Token counts and step counters are run details rather than a measure of completion.

### Live data and the event stream

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

Routes are `#/s/<id>/chat`, `/overview` and `/evidence`. `#/s/<id>` and `/chat` open Chat, the
default tab; the earlier `/record` is accepted and rewritten to `/chat` with `history.replaceState`.
loom-desk opens `#/s/<id>`, which keeps working. `#/inbox` and `#/new` retain their meaning. Browser
Back/Forward restores the selected mission view.

The sidebar header holds the connection dot, a short connection word (`Live`, `Connecting…`,
`Reconnecting…`, `Offline`) and the inbox count; **New mission** is a full-width button below it. The
detail (the last-update time, a failed status request, each unreachable model profile) is the tooltip
of that line and of the dot, not text in the sidebar; an unreachable model is also on the `#s-model`
chip. At 1100px and narrower the sidebar and inspector are drawers, and the top bar is shown. It holds
their buttons and a compact identity summary of the open session that is always in view: `#bar-model`
(the profile, in the look of `#s-model`, its tooltip the full model text, with the unreachable
warning) and `#bar-run` (the run state with its shape). Both follow the header on every update and are
hidden when no session is open. Below 700px they take their own row under the two drawer buttons. A
lost connection is also said in the bar there (under 700px only, so a screen reader does not hear it
twice beside the open sidebar).

The session header is an identity bar. Line 1 is the breadcrumb: for an agent, the mission title,
an ellipsis where ancestors are skipped, and its role, with ancestors as links to their sessions; for a
root, just the title. The current crumb is the title (the id when untitled; its tooltip is the full
id), and the action buttons (Rename, Stop, Resume, Archive, Unarchive, Inspector) sit on the right.
Line 2 is a row of chips that wraps and is never hidden at any width:

- `#s-model`: the model in effect now, `<profile> · <model id> · <context window>` (for example
  `qwen · qwen4-max-preview · 1M`), in monospace with an accent tint. Its tooltip gives the base URL
  and whether the profile is reachable (from `/api/status`). A profile reported unreachable adds an
  alert shape and the word "unreachable". It updates live from a `session` frame or a `model_switched`
  record.
- `#s-role`: `<pack> / <role>`; for an agent, the tooltip says which mission it belongs to.
- `#s-id`: a button showing the first ten characters of the session id. It copies the full id and says
  "Copied" briefly, also to assistive technology. Without clipboard access it selects the whole id
  and says so.
- `#s-run`: the run state in words with its shape: `Running · step N · <time since this run began>`,
  `Idle · step N`, `Waiting for you`, or `Ended · <outcome>`; an open nonblocking question adds
  `· question open` and a result waiting to be reviewed `· result ready`, so these are said in words
  and not only by shape. The elapsed time updates at most once a second and only while running and
  while the event stream is connected: with the stream down the chip reads `Last known · …` without
  a clock.
- `#s-standing`: the standing chips, separate facts: what is waiting on the operator, how the lead (or
  agent) stands, and how many agents are running. A root session is called the lead only when its role
  is `lead`.

Line 3 is the goal, `#s-goal`, clamped to one line. A **Show all** / **Show less** button appears only
when it overflows. Expanded, it stays bounded in height and scrolls within its own box, so a long one
(a whole prompt recorded as the goal) cannot grow the header past the viewport and leave the chat
below it unreachable.

Under the composer, a stats line shows the open session's figures as separate spans, each omitted
when unknown rather than shown as zero: `#s-speed` (generation speed), `#s-cache` (`cache 92%`, the
cached share of the latest prompt), `#s-context` (`context 31% of 1M`, the latest prompt tokens over
the context window) and `#s-step` (`step 214`). The speed is the latest reply's tokens per second and,
once there is more than one, the rate over the latest replies together. Each measures the tokens
after the first over the time from the first streamed token to the end of the stream, so the wait for
the first token is left out; a reply of fewer than two tokens, or one recorded before the daemon kept
this timing, contributes none. The same figure is on every model reply's footer. The line is blank off
a session view.

Chat is the default tab, then Overview, then Evidence. Overview's main column holds the questions
waiting on the operator, the recorded plan with a progress bar over the steps still in it, and recent
activity. Its rail holds the agents (or, for an agent, the mission it is part of), the counts of
claims and obligations, and the run numbers. Activity lists the latest ten recorded changes, newest
first, and says so when more were recorded. After a prior visit, the changes recorded after the last
fully loaded sequence seen when leaving are grouped under “New since your last visit”; the earlier
ones stay listed below them. Only sequence watermarks and inspector width are saved in tab-scoped
storage; message and answer text stays in memory.

Evidence lists claims with their recorded status, source quotes and remaining notes, and can be
filtered by that status. Each evidence item shows two separate facts: whether its quote matches the
stored output, and which way the agent says it points. Each source
reference opens its cited range with surrounding context.

### Chat

Chat is the whole record presented as a conversation, oldest first, in a column centred at
`clamp(640px, 70%, 920px)`; the composer is the same width. It retains all previous event
presentation: native tool call/result pairing, explicit missing results and output cuts, child
reports, re-weaves, inbox resolutions, request details, reasoning and live output. Folding is
presentation only. Scrolling up stops following new output and reveals Jump to latest. Activity links
open their corresponding chat blocks.

- Operator messages are a right-aligned bubble; the author is named only when it is not the operator.
  Harness notes stay full-width, labelled and clipped. Model replies with text have no bubble; the
  prose subset applies and the raw text stays available. Reasoning is a collapsed `Thought · N lines`
  row above the prose. Each reply's footer is one quiet line: the profile when it differs from the
  segment's model, then tokens per second, seconds and cache share, with the full token counts in its
  tooltip.
- **Model attribution.** Each run of assistant output (the first reply or work group after a user
  message, note, inbox card, divider, child card or the session's start) begins with a small
  monospace chip naming the profile that produced it; its tooltip gives the model id and window. A new
  chip starts after every switch. A `model_switched` record is a visible full-width line showing both
  sides (`profile · model · window`) and the reason.
- **Work groups.** A maximal run of consecutive tool calls, replies without text (their reasoning
  becomes `Thought` rows inside the group) and job, ledger, cache and request lines is one group. A
  user message, note, inbox card, divider, child card, end block, interrupted line or model switch
  ends a group. Request-detail lines (Show request details) never start, end or split a group: one inside
  a run joins the group, one outside stands alone, so the groups and their keys are the same with the
  box on or off. The header says what it holds: `Worked for <duration> · <n> tool calls`, plus
  `· <k> failed` with a cross shape when any call failed, `· N without a result` for calls with no
  recorded result, `· N warnings` (an alert shape) for cut or failed replies, jobs that exited non-zero
  and cache breaks inside it, and `· running` while a call runs. The ticking duration is aria-hidden;
  the header's accessible name says `Work in progress · …` without it. A group of only ledger, job or cache lines or
  reasoning reads `Activity · N records`. A group is expanded when it is the last item of the chat,
  contains a running call, or the operator opened it; the operator's choice is kept per group in memory
  and reset per session. **Expand all work** (beside Show request details) opens every group and
  holds them open. A collapsed group builds only its header and opens with one click or Enter. An open group is
  reconciled by member: a new record appends a row and a changed one replaces only its own row, so an
  open Thought or Raw response, a focused control and the output viewer's opener survive live updates.
  A group that crosses the start of the rendered window shows only the members inside it, under an
  "N earlier in this work" control that is Show earlier, and keeps its model chip.
  Deep links and Activity links to a call inside a folded group expand it, open the call and
  highlight it.
- **Tool rows** inside a group are one line: an icon for the kind of tool (terminal, file, pencil,
  search, list, people), the name, a monospace arguments line with ellipsis, and a capsule (`ok`,
  `exit N`, failed with a cross, "no result" with an alert, running with a dot) and duration. Clicking
  the row or pressing Enter opens its output as before: 24-line clip with show all, the cut note with
  “open full output”, the arguments toggle, "no result recorded" and "running…".
- The live reply is shown at the bottom as a reply in progress with its model chip.

## Drafts, submissions and updates

Drafts are keyed by session ID for messages and item ID for inbox answers. They survive mission/view
switching, stream reconnection and snapshot refreshes while the page remains open. They do not
persist after a page reload or tab closure. Keyed inbox nodes preserve focus and selection when
another question arrives. Suggested answers are toggles over the one draft: pressing one fills the
draft, pressing it again clears it, and nothing is sent until Send answer. The card always says what
would be sent. When suggestions exist, “Write your own…” reveals the text field; a draft that is not
one of the suggestions keeps the field in view. Send answer stays disabled for a blocking request
with an empty draft; a nonblocking question with an empty draft offers Dismiss instead.

Capture the destination and submitted text before awaiting a request. An acknowledgement for one
mission must not clear another mission's draft or steal its focus. Clear a draft only if its value
still equals the submitted text. Disable duplicate in-flight submissions per destination. Require a
fully loaded initial record watermark before sending or correlating delivery. A message accepted by
the API waits for its matching recorded receipt before another submission reuses that watermark;
a following model-request event updates its delivery standing. These are observable UI receipts,
not proof that the model understood the message.

Stop, Resume, Archive and Unarchive have explicit pending states. Stop's description identifies its
scope: the session, descendant agents and tracked jobs. Message receipts distinguish acceptance,
recording and a subsequent model step. Failures retain the draft and explain what happened.

### Model

The composer's toolbar holds the model seat, `#model-seat`: a select listing the profiles from
`GET /api/models` (fetched when a session opens; `/api/status` models are the fallback), showing the
open session's current profile. An unreachable profile is labelled "(not reachable)", and a current
profile that is no longer configured is still listed as "(not configured)". It is disabled, with the
reason ("This session has ended; its model no longer changes.") as its tooltip and accessible
description, for an ended session, which the daemon refuses to re-seat; archived sessions can still be
re-seated. A switch in flight holds only its own session's seat. Until a session is known to the page the
seat is disabled and the identity chips are empty rather than showing the previous session.

Choosing another profile does not switch at once. An inline confirmation (`#model-confirm`) says:
“Switch this session to <profile> (<model>) from its next step? The next request re-reads the whole
prompt once.” (with “<profile> is not reachable now; the next step fails until it answers.” added for
an unreachable target), and offers **Switch** and **Keep <current>**. Escape or Keep reverts the
select and returns focus to it. Switch sends `POST /api/sessions/{id}/model {"profile": "<name>"}`,
which answers `{session, model: {profile, model, context_window}, live}`. The receipt appears in the
send-state region: “Switched to <profile> (<model>); takes effect at the next step.”, or, when the
session was not live, “… The session records the switch and uses it when it next runs.” An error shows
the daemon's own sentence (for example, an unknown profile names the configured ones). A switch takes
effect at the session's next step, not mid-call, and the first request after it re-reads the whole
prompt once. The header chip, the stats line and a `model_switched` line in Chat update from the
session frame and the record; the receipt is applied optimistically only if no session frame has
changed the session's model since the request was sent. The question is announced in the send-state
live region when a profile is picked, and its buttons follow the select in tab order. The status line
shows the newer of the switch sentence and the message receipt or failure, and the loading sentence
while the record loads. After the response, focus returns to the select only if it was not moved on.

Snapshot requests use destination and request-generation guards on both success and failure.
Session/inbox refreshes must not overwrite newer stream events. Connection status and snapshot
freshness remain separate from mission attention; a disconnected stream makes execution standing
unknown while retaining the last update time.

## Inspector and responsive behavior

The mission inspector is closed by default. It contains Ledger, Context, Network, Models and Session
tabs.
On a wide display, opening it adds a resizable side pane. Drag the separator or use its arrow keys;
Home/End select the bounds. On narrower displays it becomes a drawer. Below 700px the mission
sidebar is also a drawer. Closed surfaces are inert; modal drawers trap keyboard focus, close with
Escape, and restore focus. Background content is inert while a modal drawer is open.

Tabs have explicit tab/tabpanel semantics and arrow/Home/End keyboard navigation. Use system text
for prose and monospace for source, commands and logs. Keep visible focus, readable form controls,
light/dark appearance and reduced-motion support. Avoid dependence on color or hover alone.

### Rules and network in the inspector

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
- **Network** (`GET /api/sessions/{id}/net`, plus live `net` events): the newest 500 decisions,
  newest first: time, allowed/refused, method, host:port, the rule that decided. When the load
  failed (for example because the egress audit log is damaged) the daemon's sentence is shown in red
  above the rows, also while live decisions arrive.
- **Models** (`GET /api/sessions/{id}/models`, refetched when a `session` event arrives for the
  mission it shows): one stacked row per model, each a full-width select of the live profiles (the
  inspector is too narrow for a two-column grid). **lead**: the lead's profile, its model and window
  below; changing it is `POST /api/sessions/{lead}/model`. **every role** (`*`) and one row per role
  the lead starts (the finish gate's verifier marked as such): the operator's choice, whose empty
  option names what applies without one (every role's choice, or what the pack picks: its model,
  the profiles it rotates, the one it escalates to), and below, the role's running agents with their
  profiles. Changing one is `POST /api/sessions/{lead}/role-model {role, profile, now}` (empty:
  clear). **Also move the running agents of a role when choosing for it** sets `now`. Changes run
  one at a time (the selects are disabled meanwhile), say what happened in the notice bar, and read
  the models again. A lead that starts no agents shows only its own model.

The new-mission form's **Agents' model** sends `role_models: {"*": profile}`; it is disabled unless
the role is `lead`, the only form role that starts agents.

## Stored output dialog

Use a native modal dialog with an accessible title, focus containment, Escape dismissal and focus
restoration, including when a live update replaces the original source button. The viewer shows
snapshot identity, producing session/call when available, numbered lines and highlighted citations.
It supports paging in both directions, Go to line, copying the source reference, and literal Find
in displayed lines. Search is explicitly limited to the loaded range; it does not claim to search
an entire unseen blob. Jumping to another line updates the copied citation. Loading an old range
cannot overwrite a newly opened source dialog.

The dialog holds two fields, so it is not a form: a form with two fields and no submit button
swallows Enter. Each field handles its own Enter. Go to line scrolls to a loaded line, or loads the
range around a line that is not loaded, and refuses a line outside the output with the allowed
range. Find searches the text of the lines, never their numbers; Enter and Next go forward,
Shift+Enter and Previous go back, both wrap, and the count says which match is shown. Neither
action moves focus or closes the dialog. Opening the dialog puts focus on the lines, so the arrow
keys scroll them at once and Enter never rests on Close. Loading earlier lines keeps the lines
being read where they are. A cited line, the line gone to and a search match are marked
differently, since all three can meet on one line.

## Validation

Run the pure regressions and safety checks with:

```sh
node --test ui/core.test.js
node --check ui/app.js
```

For browser checks without a model or real daemon:

```sh
node tools/ui-preview.mjs
```

Open the printed loopback URL, `/#code=fixture`: the fixture answers `POST /api/web-sessions` for
that code, so the page signs in as it would from `loom open` (alternatively set the `sessionStorage`
secret `fixture-secret` and open `/#/s/s-audit`). The fixture contains three workspaces
(`/fixture/loom`, `/fixture/indexer`, `/fixture/docs`) and three model profiles with different
context windows: `dsv41` (1M), `qwen` (`qwen4-max-preview`, 262k) and `necromicon` (128k), the last
reported unreachable by `/api/status` and `GET /api/models`. Its sessions are a mission lead with a
blocking question that switched from `necromicon` to `dsv41` mid-record, a running agent nested under
it, a running mission whose status carries prompt and cached token counts, and an ended mission with
a finished result on the unreachable profile. The records include a work group with a failed tool
result, a cut output, formatted/inert source text, and two claims: an open one citing output at
line 1596, and a supported one with a matching quote at lines 212–214 and an unchecked quote that
undermines it. `POST /api/sessions/{id}/model` is the model switch: it updates the session, appends a
`model_switched` record and emits `session` and `record` frames. Message responses are delayed so
navigation during submission can be checked. The fixture-only `POST /__fixture/question` injects a
nonblocking arrival, `POST /__fixture/reconnect` drops the stream to exercise refreshes, and
`POST /__fixture/stream` streams a short live reply into `s-other` (reasoning, text and a tool call
as `delta` frames, then the `model_response`, `tool_call` and `tool_result` records, twice), so the live
reply, the running work group and its ticking label can be exercised. A model switch on the ended
session is refused with the daemon's sentence (409). `GET /__fixture/state` lists only
synthetic submission receipts.

Check mission and answer draft isolation, focus after an arrival/reconnect, duplicate submission
prevention, evidence jumps/search/copy, Enter in both fields of the stored output dialog, paging to
earlier lines, the model switch (confirm, Escape revert, error sentence, header chip update), work-group folding and deep links into a folded group, Back/Forward, inspector tabs/resizing, closed-drawer tab order, modal focus
restoration, light and dark appearance, and 320px/desktop layouts. The preview binds loopback and never reads
credentials, starts a model or writes a workspace. Rust/native builds follow the separate-host rule
in `docs/IMPLEMENTING.md` and `gui/DESIGN.md`.
