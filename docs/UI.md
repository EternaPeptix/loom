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

![Mission overview with illustrative fixture data](images/mission-overview.jpg)

The sidebar groups root sessions into Needs your answer, Running, Ready to review, and Other
missions. Blocking child inbox items contribute to their mission's attention. Agents are collapsed
under the root by default; opening an agent expands its ancestors. Peer order stays based on creation
order inside each group. Archived roots remain hidden until Show archived is enabled.

Blocking requests, nonblocking questions and available results have different labels. Only blocking
requests use the urgent attention treatment. The second line of a mission row says what is waiting
on the operator and for how long, then how its root session stands; with nothing waiting it shows
recorded activity and its age. Ages come from recorded times, never from creation, and activity that
has not been loaded is explicitly unknown. The agents toggle under a mission says how many agents it
has and how many are running. Token counts and step counters are run details rather than a measure
of completion.

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

Routes are `#/s/<id>/overview`, `/evidence`, and `/record`; the old `#/s/<id>` route opens Overview.
`#/inbox` and `#/new` retain their meaning. Browser Back/Forward restores the selected mission view.

The header keeps the goal and current plan step visible at all supported widths. Its standing is a
row of separate facts: what is waiting on the operator, how the lead (or agent) stands, and how many
agents are running. A root session is called the lead only when its role is `lead`.

Overview is the default. Its main column holds the questions waiting on the operator, the recorded
plan with a progress bar over the steps still in it, and recent activity. Its rail holds the agents
(or, for an agent, the mission it is part of), the counts of claims and obligations, and the run
numbers. Activity lists the latest ten recorded changes, newest first, and says so when more were
recorded. After a prior visit, the changes recorded after the last fully loaded sequence seen when
leaving are grouped under “New since your last visit”; the earlier ones stay listed below them.
Only sequence watermarks and inspector width are saved in tab-scoped storage; message and answer
text stays in memory.

Evidence lists claims with their recorded status, source quotes and remaining notes, and can be
filtered by that status. Each evidence item shows two separate facts: whether its quote matches the
stored output, and which way the agent says it points. Each source
reference opens its cited range with surrounding context. Full record retains all previous event
presentation: native tool call/result pairing, explicit missing results and output cuts, child
reports, re-weaves, inbox resolutions, request details, reasoning and live output. Scrolling up
stops following new output and reveals Jump to latest. Activity links open their corresponding
record blocks.

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

Snapshot requests use destination and request-generation guards on both success and failure.
Session/inbox refreshes must not overwrite newer stream events. Connection status and snapshot
freshness remain separate from mission attention; a disconnected stream makes execution standing
unknown while retaining the last update time.

## Inspector and responsive behavior

The mission inspector is closed by default. It contains Ledger, Context, Network and Session tabs.
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

Open the printed loopback URL. The fixture contains three missions, a running agent, a blocking
question, a nonblocking completed result, a failed tool result, formatted/inert source text, and
two claims: an open one citing output at line 1596, and a supported one with a matching quote at
lines 212–214 and an unchecked quote that undermines it. Message responses are delayed so navigation during submission can be checked. The fixture-only
`POST /__fixture/question` injects a nonblocking arrival, and `POST /__fixture/reconnect` drops the
stream to exercise refreshes. `GET /__fixture/state` lists only synthetic submission receipts.

Check mission and answer draft isolation, focus after an arrival/reconnect, duplicate submission
prevention, evidence jumps/search/copy, Enter in both fields of the stored output dialog, paging to
earlier lines, Back/Forward, inspector tabs/resizing, closed-drawer tab order, modal focus
restoration, light and dark appearance, and 320px/desktop layouts. The preview binds loopback and never reads
credentials, starts a model or writes a workspace. Rust/native builds follow the separate-host rule
in `docs/IMPLEMENTING.md` and `gui/DESIGN.md`.
