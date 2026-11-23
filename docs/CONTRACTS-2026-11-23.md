# Contracts of 2026-11-23: shell directory, quoting, project instructions, images, queued messages

Normative for the work merged with it. Each part names the files it owns. When a part is done, its
rules move into `docs/DESIGN.md` (and `docs/UI.md` for the UI) and this file shrinks to a pointer.

Evidence from the operator's logs (551 sessions, 21,272 calls) that shaped these:

- `cd` is the first word of 75% of `bash` commands (6,848 of 9,080): models re-establish a
  directory every call, because the trained shell keeps it and loom's did not.
- 14 of 20,872 `bash` results were cut (the inline limit is a window/8 token budget). Output is
  already shown whole. Yet `out_read` ran 1,416 times, 1,094 of them on `bash` output that had been
  shown whole (median 20 lines), and no `evidence` call ever quoted by text alone (783 by line
  numbers, 437 with both). Models re-read what they saw to get line numbers for evidence.

## A. The shell directory persists (`crates/loom-tools/src/bash.rs`, `lib.rs`, runtime `ToolCtx`)

1. A session has one shell directory, `ToolCtx.shell: Arc<ShellState>` (`ShellState { cwd:
   Mutex<Option<PathBuf>> }`), created with the session's `ToolCtx` (`runtime.rs`, where `jobs` is
   made). A child agent or fork has its own, starting empty.
2. A `bash` call without `cwd` (and not a `box_exec` launch) runs in the shell directory when it is
   set and is still a directory, else in the workspace. When it was set and is no longer a
   directory, the call runs in the workspace, the state is cleared, and the result has the fact
   `shell directory reset to the workspace ({old} no longer exists)`.
3. The script runs as `trap 'pwd -P >| "$LOOM_SHELL_CWD" 2>/dev/null' EXIT; {script}` (same line, so
   line numbers in shell errors are the script's), with `LOOM_SHELL_CWD` in the command's
   environment naming `{tmp_dir}/.shell-cwd-{job id}`, a path the sandbox lets the command write.
   A script that sets its own EXIT trap just does not move the shell directory.
4. After a foreground call that ended (exit status or signal; not a timeout, not cancelled, not a
   call that became a job, not `background`): read that file (trimmed, absolute, a directory),
   delete it, and set the shell directory to it. When it differs from where the call started, the
   result has the fact `cwd now {dir}` (relative to the workspace when inside it, `.` for the
   workspace itself, else absolute) and meta `cwd: {absolute}`. The read-tracking of the call uses
   the directory it started in, as now.
5. With `cwd` given the call runs there, and rule 4 applies after it.
6. A session opened from its log (restart, resume) starts with the shell directory of the last
   `bash` result whose meta has `cwd`, if it is still a directory.
7. Descriptions (both dialects): `bash` says "The working directory persists between calls: after
   `cd dir`, later commands run in `dir`. Environment variables do not persist." The `cwd`
   argument says "Directory to run this command in (default: where the last command left the
   shell, at first the workspace)." The core `harness.md` and role prompts drop any advice to `cd`
   in every command.
8. Tests: cd persists across two calls; `cd` into a directory that is then removed resets with the
   fact; `exit 3` after `cd` still moves it; a call that times out or becomes a job does not;
   `background` does not; `cwd` given then `cd` moves it; error line numbers unchanged (`bash -c`
   with a syntax error on line 2 says line 2); restart restores from meta.

## B. Quote what you saw (`crates/loom-agent/src/rtools/ledger.rs`, `loom-core` evidence matching)

1. `evidence` and `claim` descriptions lead with quoting by text: "Copy the exact text from an
   output you were shown into `quote`; line numbers are not needed." Remove the advice to get line
   numbers from `out_read`/`read` first. `start`/`end` stay, described as "only when the quote
   appears more than once".
2. A `quote` that matches more than once is refused with every match listed as `line {n}: {line}`
   (at most 10, each cut at 200 characters), and "add `start` to say which". Nothing re-read.
3. A `quote` that does not match exactly but matches exactly one place once runs of whitespace are
   collapsed and line ends normalised is taken; the evidence records the stored lines, and the
   result says which lines it took ("matched lines 12-14 ignoring spacing"). Check what the
   matcher already does first and keep anything it already accepts.
4. Tests for 2 and 3, and that a quote-only call on a `bash` output shown whole records the right
   lines.

## C. Project instructions (`crates/loom-agent/src/pack.rs`, session start, `loom-core` config)

1. When a session starts (lead, child, chat), loom reads the workspace root's `AGENTS.md` and
   `CLAUDE.md` (both when both exist; the second is left out when its bytes equal the first). Only
   valid UTF-8 files are read; others are left out with a harness note.
2. The system prompt gets, after the role prompt and before `# Environment`:
   `# Project instructions\n\nFrom the workspace's {names}. They describe this project; the
   operator's rules and the mission's constraints come first where they differ.\n\n## {name}\n\n
   {content}` per file. The total is cut at 32 KiB with `[cut: {n} more bytes; read {name}]`.
3. The text read is recorded in `session_start` (new field `project_instructions: Vec<{name,
   text}>`, serde default empty) so that a resumed or re-rendered session keeps the same system
   prompt (prefix cache) even when the file has changed since. Changing the file mid-mission
   changes nothing until a new session starts.
4. Config `[agents] project_instructions = true` (default true) turns it off.
5. The Context inspector's "System prompt" part keeps counting it (no new part needed), and the
   Session tab lists the file names under "project instructions".
6. Tests: both files, identical files, non-UTF-8, the cut, off by config, resume keeps the recorded
   text after the file changed.

## D. Images (core, model, tools, daemon, UI)

Images are content, not paths. A model whose profile says `vision = true` is sent them; any other
model is told in text that an image is there and where its file is.

1. `ImageRef { blob: String (the blob store's hex id), mime: String, bytes: u64, width: u32,
   height: u32, name: Option<String> }` in `loom-core`. Accepted: PNG, JPEG, GIF, WebP, detected by
   magic bytes (not by extension); width and height read from the header (hand-written parsers, no
   new dependency).
2. Events: `UserMessage` and `ToolResult` gain `images: Vec<ImageRef>` (serde default empty, skipped
   when empty, so old logs read and new logs of image-less sessions are byte-identical).
3. Where images come from:
   - An attachment (`MessageBody.attachments`, `NewSession.attachments`) whose file is an image is
     also stored in the blob store and carried in the user message's `images`, besides its line in
     the attachment list.
   - `read` of an image file returns text `[read · image · {path} · {w}x{h} {FORMAT} · {size}]`
     with the image in the result's `images` (status ok). An image over `max_image_bytes` (config
     `[tools]`, default 5 MiB) is not attached; the text says so and why.
4. `Message` gains `images: Vec<ImageRef>`. The request builder turns them into OpenAI content
   parts, reading each blob at build time:
   - a user message with images: `content` is `[{type:"text",text}, {type:"image_url",
     image_url:{url:"data:{mime};base64,…"}}…]`;
   - tool messages stay text; the images of the tool results that answer one assistant message are
     sent in one user message placed right after that run of tool messages: text `Images from the
     tool results above:` then, per image, `[{tool} {call_id}: {name or path}]` and its part. The
     call/result pairing is untouched.
   - profile `vision = false` (the default; `ModelProfile.vision: bool`): no image parts; the text
     gets `[image not shown: this model does not take images — {name} {w}x{h} {mime}]`.
5. Context: an image is estimated at `min(2000, max(85, ceil(w*h/750)))` tokens. Folding may stub a
   tool result's images like its text (`[image folded — read {path} again to see it]`); images in
   user messages are never folded. The Context inspector counts them in a new part "Images".
6. Daemon: `GET /api/images/{blob}` serves an image blob that a record of a session names, with its
   mime type, inline, `Cache-Control: private, max-age=31536000, immutable`; 404 otherwise. The CSP
   already allows `img-src 'self'`.
7. UI: user messages and tool rows show thumbnails (max 240×240, `loading="lazy"`); a click opens
   the image full size in a dialog with its name, size and Copy path. Composer chips for images
   show a small thumbnail. A model without vision shows a note on the chip: "This model does not
   take images; it gets the file path."
8. `loom models` lists `vision`. `docs/config.example.toml` documents `vision`.
9. Tests: magic-byte detection and header sizes for each format; event round-trip with and without
   images; request body shape (user message, tool-result run, vision off); estimate; the route's
   404 for a blob no record names; old log without `images` reads.

## E. Queued messages (daemon API, session inputs, UI, CLI)

Today a message sent while the lead runs reaches it at its next step ("steer"). Add "queue": a
message held until the lead's turn ends, then sent as the start of the next turn.

1. `MessageBody.when: "now" | "after_turn"` (default `now`, today's behaviour). `after_turn` while
   the lead is idle is the same as `now`.
2. A queued message is kept on disk in the session's `queued/` directory (new `KeptInput::User {
   id, text, attachments, created_ms }`) and recorded as a `user_message` when the turn ends, in
   the order queued; the first starts the next turn and the rest arrive with it.
3. `GET /api/sessions/{id}/queued` → `[{id, text, attachments, created_ms}]` (user messages only).
   `PUT /api/sessions/{id}/queued/{qid}` `{text}` edits one; `DELETE` removes one;
   `POST …/queued/{qid}/send` sends it now (steer) and removes it. 404 for an id no longer
   queued (it may have just been sent). The SSE stream sends `{type:"queued", session}` on every
   change, so pages re-read the list.
4. Stopping a session keeps its queued messages queued; they are sent when the operator next
   resumes or messages it. Archiving discards them after a confirmation in the UI.
5. UI: while the lead runs, Enter sends now (as today) and ⌥Enter (Alt+Enter) queues; the send
   button has a small menu "Send now / Queue for after this turn". Queued messages sit in a list
   above the composer, each with Edit, Send now and Remove, and a count in the composer caption.
   The help line says which key does which.
6. CLI: `loom send {id} TEXT --after-turn`.
7. Tests: order, edit, remove, send-now, idle equals now, survives a daemon restart, stop keeps
   them.
