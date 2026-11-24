# Changelog

## Unreleased

### MCP servers become tools

- New `[mcp]` configuration: stdio (`command`) and Streamable HTTP (`url`) servers whose tools are offered as
  `mcp__{server}__{tool}`. A mission's lead lists each server whose `roles` match once and records the listing in
  `session_start.mcp`; children and reopened sessions reuse it. Role selection (`roles`, `read_only`, `tools`), a
  `max_schema_tokens` budget per role and a start note saying what each server gave and what was left out.
- A server's `hosts` are added to the allowed hosts of sessions whose role gets it (they reach `bash` too).
- `GET /api/sessions/{id}/mcp`, `POST /api/mcp/{server}/check`, `loom mcp list`, `loom mcp check`.
- A session without `[mcp]` sends the same requests as before. Secret values are never recorded or logged.

### Hypotheses and the rule engine leave the harness

- `security_record` no longer takes `hypothesis_open`, `hypothesis_priority`, `hypothesis_evidence`,
  `hypothesis_verdict`, `rule_install` or `rule_retract`; a call is refused with "Hypotheses are not recorded in
  the security state any more: write the idea as a note (`note` with kind `decision`) or test it and record what
  the run showed." `security_query` no longer has `hypotheses`, `facts`, `why`, `what_if` or `path_suggest`. The
  Datalog module, `projection()` and `path_suggest()` are gone with their tests; the HUD, the prior-mission brief
  and the frontier no longer carry hypotheses or derived facts.
- Older logs stay readable: the six operations keep their serde variants and change nothing when applied; a
  snapshot with `hypotheses`, `rules`, `died` or `retraction_limitation` loads and drops them. `SecurityState`
  lost those fields (nothing is renamed; nothing new is serialized).
- Repairs instead of refusals: a host given with a scheme, port, path or credentials is recorded as the host;
  a service or endpoint URL without a scheme gets `https://` for port 443 and `http://` otherwise; `ops` is read
  as `operations` (also when `action` is missing). Each is said under `normalized`.
### Compaction replaces re-weave

- A session's window is bounded by compaction (CONTRACTS-COMPACTION Part K). When a request reaches `compact_at`
  (`[context] compact_at_tokens`, 0 = 40% of the model's window, at most 400 000), when the server refuses a request,
  when a large request stalls three times, when the operator asks (`POST /api/sessions/{id}/compact`, `loom compact`;
  `/reweave` and `loom reweave` stay as aliases) or when a lead's finish is not accepted, the model writes a note
  (`model_request` purpose `compact`, same window and tools as the last step), the harness builds a table of keys for
  every output, file, agent and job, and a `compaction` record is appended. The next request is the system message,
  one `<harness kind="compaction">` item (operator messages, ledger, pins, key table, note) and the records after
  `upto_seq`. Nothing is deleted from the log. A failed note request still compacts, with no note.
- The weave starts at the latest compaction, so its cost no longer grows with the age of the session.
- New event `compaction`; `reweave` records of old logs still load and render as they did until the first compaction;
  no new `reweave` record is written. New purpose `compact` (`digest` stays readable). No more stubs, evictions or
  digest request for new records.
- `[context]` keys `target_tokens`, `floor_tokens`, `keep_recent_steps` and `stub_tail_lines` are accepted, ignored and
  warned about at startup; `target_tokens` is read as `compact_at_tokens` when that is absent.
- `GET /api/sessions/{id}/records?before=<seq>&limit=n` pages backward and answers `prev_before`; `after` and
  `before` together are a 400. `WindowView.fold_at` is `compact_at`.

### The shell directory persists between `bash` calls

- A session has one shell directory (`ToolCtx::shell`, new field): a `bash` call without `cwd` runs where the last
  call left the shell, so `cd dir` carries over (variables still do not). The result says `cwd now {dir}` and
  carries the new `ToolResult::meta` key `cwd` (`META_CWD`); a removed directory resets to the workspace with a
  fact; a reopened session restores it from the last such result. Older logs stay readable. The tool descriptions
  no longer tell the model to `cd` in every command.

### Queued messages

- `POST /api/sessions/{id}/messages` takes `when: "now" | "after_turn"`. A message sent `after_turn` while the lead
  is in a turn is kept on disk (`queued/`) and recorded as a `user_message` when the turn ends; the first starts the
  next turn and the rest arrive with it. `GET /api/sessions/{id}/queued`, `PUT`/`DELETE .../queued/{qid}` and
  `POST .../queued/{qid}/send` list, edit, remove and send one now; the event streams send `{type:"queued",session}`
  on every change. A stop keeps the queue; archiving discards it. `loom send --after-turn`.

### Evidence quotes by text; project instructions

- `evidence` and `claim` lead with quoting by text: copy the exact text from an output you were shown; line numbers
  are not needed. A quote that occurs more than once is refused with every place listed (`line {n}: {line}`, at most
  10) and `start` picks one. A quote that matches in one place once spacing and line ends are ignored is taken, and
  the result says which lines.
- The workspace's `AGENTS.md` and `CLAUDE.md` go into each new session's system prompt (`# Project instructions`),
  recorded in `session_start.project_instructions`. `[agents] project_instructions = false` turns it off.

### Images

- `user_message` and `tool_result` records can carry `images` (`{blob, mime, bytes, width, height, name}`). Image
  attachments and `read` of a PNG, JPEG, GIF or WebP file (up to `[tools] max_image_bytes`, 5 MiB) are stored in the
  blob store and, for a profile with `vision = true`, sent as `image_url` parts (tool images in one user message after
  the run of tool messages); other models get a sentence naming the image. `GET /api/images/{blob}` serves them;
  `loom models` and `GET /api/models` list `vision`; the Context breakdown has an "Images" part.

### File uploads

- `POST /api/uploads?workspace=&name=` (raw body, at most 32 MiB) stores a file in `<workspace>/.loom/uploads/` (name
  cleaned, numbered when taken, written atomically). `MessageBody` and `NewSession` take `attachments`, absolute paths of
  uploads of the session's workspace; the runtime appends an attachment block (list, and an inline copy of small text
  files) to the recorded message. The Files routes serve `.loom/uploads` and nothing else under `.loom`; under
  Bubblewrap `.loom/uploads` is bound read-only inside the hidden `.loom`. `loom send` and `loom run` take
  `--file PATH` (repeatable). See `docs/UPLOADS.md`.

### Stored outputs are the mission's own

- `out_read`, `out_grep`, `pin`, `evidence` and `finish` quotes, `security_record` secret handles,
  `security_ingest`, the oracle's candidate and a verdict's `opened` open a handle only among the outputs of the
  session's mission (`loom_tools::outputs`): before, they resolved it against the whole blob store, which every
  mission shares, so a session that learned another mission's handle could read that output. A foreign handle
  gets exactly the refusal of one that names nothing, and a quote check no longer reports a line count or a
  closest line of an output it may not read. `ToolCtx` has a new field, `outputs`.
- `gate::check_quotes` is now `async fn check_quotes(ctx: &ToolCtx, quotes)`.
- New `ToolResult::meta` key `also_stored` (`META_ALSO_STORED`): `dep_scan` lists there the further VDRs,
  SBOMs and console it stores, so they count as the mission's outputs. Older logs stay readable.

### Recall of earlier missions, chosen by the operator

- `NewSession.prior` (`loom run --prior <mission>`, repeatable, at most 8; `POST /api/sessions`; the web form's
  *Recall earlier missions*) names earlier missions for a new lead to recall, kept as `prior` in its
  `meta.json` (left out when empty, so older files are unchanged). Before the lead's first model request it gets
  one `info` note per the new `loom_agent::prior`: each mission's goal, rules and answers (the operator's words),
  goal status, where its work stood when its ledger was last written (written by the model there, not
  verified), and its security record as counts and asset locators (identities are counted, never named; URLs in model
  text (found at every `://`, also when cut, quoted or glued to other text) and in locators lose query, fragment
  and userinfo, and text that does not parse as a URL loses them by cutting; the operator's words are verbatim; a request that names
  no earlier mission is sent without the `prior` key, so an older daemon still accepts it). The source is each mission's sealed
  journal; one that fails verification or was written by a newer loom is named unreadable. No log-schema change.

### Sandbox: Git metadata, the trustd route, the daemon port, and adoption by descriptor

- Commands and the file tools can no longer plant what Git runs as the operator. In every writable root (the
  workspace, the session temp dir, `extra_writable`) the profile and `check_write` refuse Git configuration,
  hooks and `commondir`/`gitdir` pointers of linked worktrees (`.git/worktrees/<n>/`) and submodule repositories
  (`.git/modules/<n>/`, deinitialized and nested ones included), and refuse making or moving a `.git`, a
  worktree gitdir or a submodule repository into place. Before, a command could point an external worktree's
  `commondir` at a config of its own, plant a submodule hook, or `git init` a repository in `$TMPDIR` and move it
  into the workspace behind a gitlink, and the operator's next `git status` ran its command (reproduced on macOS
  27, Git 2.50). Existing worktree and submodule gitdirs are discovered at construction and protected (and
  mounted read-only by Bubblewrap). `git init` and non-bare clones no longer work anywhere commands write: a bare
  clone does; `git worktree add` and `git submodule update --init` are for the operator, and the refusal and the
  system prompt say so.
- The file tools' `check_write` compares those Git names as APFS folds them (`ſ`, the Kelvin sign, `ß` and the
  `ﬀ`–`ﬆ` ligatures), so `write` can no longer make `.git/moduleſ/<n>/hooks/<hook>`, which Git reads as
  `.git/modules/<n>/hooks/<hook>`; the profile's Git regexes spell the same folds (Seatbelt already matched
  the folded name on macOS 27).
- Under `network.mode = deny_all`, commands can no longer reach `com.apple.trustd.agent`, `com.apple.trustd` or
  `com.apple.ocspd`. A command could have trustd fetch any URL named in a certificate (AIA), past the proxy and
  `net.jsonl`. Programs that check certificates through macOS (Swift, Go, `security`, `codesign --verify`) now
  fail in deny_all; curl and Python are unaffected. In the other modes this stays a documented residual.
- Commands can no longer mount a file system or attach a disk image over a directory (`file-mount` and the
  DiskArbitration/disk-image services are denied): `hdiutil attach -mountpoint` of an image a command made
  replaced `.git/hooks`, and works over `~/.ssh` or `~/Library/LaunchAgents` (reproduced on macOS 27; this
  predates the release). `hdiutil attach` and `diskutil` now fail in every session.
- Commands can no longer write macOS preferences (`user-preference-write`): `cfprefsd` wrote
  `~/Library/Preferences` for them outside the sandbox. Reading preferences still works.
- Under `deny_all`, background URL sessions (`nsurlsessiond`) and WebKit's networking services are denied as
  well: each fetched a URL for a command driven from `osascript -l JavaScript`.
- Below `.git/modules/<name>/` nothing can be made or removed except inside the submodule repositories found
  when the sandbox was built (a slash-named submodule set up mid-session could be replaced by a copy carrying
  `core.fsmonitor`). The `core.hooksPath` directory and included files named by each repository's, the
  enclosing repository's and the user's global Git configuration are protected (husky's `.husky/` hooks could be
  planted), resolved against every working tree they serve: submodules (`core.worktree`), linked worktrees,
  `~user/` values. A `HEAD` and `objects` planted in a directory no longer stop the next session's discovery. Bare repositories
  in the workspace are found; pointer targets count only when they are repositories. `agent_adopt` asks the
  sandbox about every path before it looks at the workspace (no more existence oracle through a link) and
  again once each file is in place.
- The daemon's own port is refused to commands in every profile, even with `loopback_all` or when listed in
  `loopback_ports`, so a `loom open` login code on another process's command line cannot be redeemed. New
  non-configuration fields `SandboxCfg::daemon_port` and `SandboxCfg::network_deny_all` carry what the profile
  needs. With `loopback_all` the loopback allow is written for TCP and UDP (not `ip`), because a deny of one port
  after an allow of `(remote ip "localhost:*")` is unreliable on macOS 27; loopback ICMP is no longer allowed then.
- `agent_adopt` writes, makes and removes relative to directories it opened without following a link and judged
  by their real path (as `write` does), so a background command that swaps a workspace directory for a link
  during adoption can no longer redirect an unsandboxed write (into `~/.ssh` or `.git/hooks`, say).

### The sandbox hides the whole loom home

- Commands (seatbelt profile) and the file tools (`check_read`) can no longer read anything under the loom
  home except the session temp dir (an isolated replay: its staged workspace and temp); before, only `token`,
  `keys` and `oracle-secrets` were hidden, so a command could read its own or another session's log, a stored
  output, a mission journal or an earlier run's results. The home and the directories down to the temp dir stay
  stat-able (`cd`, `pwd -P`, `mkdir -p` in `$TMPDIR` work) but cannot be listed. A hard link from the temp dir to
  a file that is not readable is refused by seatbelt (probed on macOS 27). A workspace that is or lies inside
  the loom home is now refused at construction, and the system prompt says loom's own files are not readable.
  Linux Bubblewrap already hid the home; its file tools now agree.
- The names under the home are hidden too (`file-test-existence`, and `file-search` everywhere), so a command
  can no longer list the home by file id (`fsgetpath`) or `searchfs`. The session's job output directory gives
  commands the metadata of its files, which `cat` and Python take of their inherited stdout; without it they
  lost their output. Binary-analysis inputs are staged in `<session dir>/analysis/<random>/target`, which
  commands can read (rizin and gdb open it) and never write.
- A path written through `/System/Volumes/Data/...` is given its usual form back, so `grep`, `glob`,
  `continuation` guards and the workspace check judge it as the plain path. `grep`, `dep_scan` report files, guard
  hashing and the copy of a workspace made for an agent (and its adoption) now judge the real path of the file
  they open, so a link swapped in after a check reads and copies nothing refused. `dep_scan` names the report
  files it refused. `workcopy::make` and `adopt` take a read judge.
- Missing names in the directories between the home and the temp dir answer "no such file" again (only their
  direct children can be tested for existence; existing ones still give EPERM, nothing deeper is testable), so
  `node a.js` and `require` from `$TMPDIR`, `npm test`, Node spawning `sh` by name with an ancestor's
  `node_modules/.bin` on `PATH`, and Python 3.9's `pathlib` upward walks work, in a replay too.
- `~/.fly` and `~/.pulumi` are protected as `~/.fly/config.yml` and `~/.pulumi/credentials.json` instead of whole
  directories: with their `bin` directories on `PATH` (the installers add them) every Node spawn of a bare
  command name failed with EPERM since names were hidden. `flyctl` and `pulumi` can run from there again.
- Messages that told the model to read a job output file now say to run the command again; `describe()` in mode
  `none` words the loom-home rule as the file tools' own.

### Model traffic, the daemon's environment and proxy credentials stay where they belong

- Model requests ignore `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and the system's proxy settings. Before,
  a proxy exported in the shell that ran `loom up` received every transcript and the bearer key, or, when
  closed, made every step fail after the whole retry window.
- `loom up` starts the daemon with a cleared environment: `PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`,
  `LANG`, `LC_*`, `TZ`, `TMPDIR`, `LOOM_LOG`, `RUST_BACKTRACE`, the profiles' `api_key_env` variables and
  the `[sandbox] env_pass` names. Any process of the user, sandboxed commands included, can read the
  environment a process was started with (macOS `KERN_PROCARGS2`), so the shell's tokens and cloud
  credentials no longer sit where commands can read them. **Commands no longer inherit other variables
  of that shell**: list one they need (`JAVA_HOME`, say) in `env_pass`.
- New profile key `api_key_file`: a file name in `~/.loom/keys/models` (yours, mode 0600), read once at
  start; the daemon refuses to start, naming the profile and the file, when it cannot use it. `api_key_env`
  keeps working unchanged, with a warning from `loom up`, `loom config check` and the daemon log that the
  key is readable by commands, and how to move it (RUN.md, *Model API keys*). `loom service install`
  refuses a profile with `api_key_env`, which a login service never had. A profile may not set both.
- Each session gets a proxy listener of its own; its sandbox allows that port only, its credentials are
  refused on any other listener, and the proxy refuses to connect to any of its own ports whatever the
  policy allows. A session's port is retired when it ends and never given to another session while the
  daemon runs, so no later session gets a port a leftover process may still be allowed. A command that reads another session's proxy
  credentials from the environment of that session's commands can no longer use them (except with
  `loopback_all`).
- Under `deny_all`, a scope grant allows exactly the granted hosts: before, the first grant also switched
  on every host in the configured `allow` list.
- `request_scope` and `loom scope` refuse `*`, a wildcard over a top-level domain (`*.com`) or over IP
  addresses (`*.0.1`), the unspecified address (`0.0.0.0`, `::`) and a loopback address without a port
  (`127.0.0.1`). Grants already in a ledger are kept as they are.
- The daemon's start warnings name the variables of its environment that look like secrets (a
  `loom daemon` run straight from a shell keeps that shell's environment).
- `ModelClient::new` takes the key directory; `Proxy::grant` returns a `Result` and must run inside a
  Tokio runtime. SECURITY.md lists what `KERN_PROCARGS2` still exposes.

### Evidence grades: analysis no longer counts as a run

- The harness now grades every quoted output: `run`, `analysis`, `read` or `reference`
  (`loom_core::event::EvidenceGrade`). A tool states the grade in its result's meta under the new key
  `META_EVIDENCE_GRADE` (`evidence_grade`); without it an `Exec` result is a `run` and anything else a
  `read`, which is what the harness did before, so old logs grade as they did. The key can only lower a
  grade. `dep_scan`, `bin_decompile` and `bin_xrefs` (all `Exec`) now say `analysis`; `cve_lookup`,
  `cve_search`, `advisory_lookup`, and `web_fetch` through the reference client say `reference`.
- Behaviour change: only a `run` is recorded as `kind: execution`. A quote of a dependency scan or a
  decompilation used to be execution evidence because those tools are `Exec`, so it could conclude the goal
  (the `vr` pack has no oracle), settle a verifier's objection and reset stuck detection; it no longer can.
  A `conclude` that cites only such evidence is refused with a sentence that names each record's grade and
  tool and says that analysis is not a run.
- `Producer` gains `grade`. `EvidenceInput` gains `tool` and `grade` (`#[serde(default)]`, not serialized
  when absent, so existing journal entries, and their MACs, are unchanged). Evidence lists in the
  `evidence` result, the brief, the ledger Markdown, the journal summary and verifier assignments name each
  record's grade and tool (`e1 run by bash`, `e2 analysis by dep_scan`).
- A result of `dep_scan`, `bin_decompile`, `bin_xrefs` or the CVE/advisory tools logged before this
  change (no grade key) is graded as those tools now state (`EvidenceGrade::of_tool_result`), so an output
  stored before the upgrade does not become a run by being cited after it. Evidence records already in a
  journal are not regraded: one recorded from a scan before the upgrade stays `execution`.
- The same scanner run through `bash` is a `run`: the grade belongs to the tool, not the command.
- New evalkit scenario `concludes_on_a_scan`, played with a fake `depscan` that the `eval` example puts
  first on its own PATH.

### Never wedge on an oversized view or a refused request

- Views are admitted like any other output. `read`, `out_read`, `out_grep` and the `bin_*` views hold at
  most `AdmitPolicy::view_chars` characters (`ToolCtx.view_chars`, new field), end at a whole line and
  say where to continue (`window ended at line N …; continue with start N+1`); `out_grep` stops adding
  match groups and says how many it left out. `finalize` cuts any view still over the bound at a line
  boundary with the handle, and admits an oversized plain message like raw output. An oversized view in
  the protected recent region used to make every request overflow and the session fail on every answer.
- Admission follows the session's window: `max_inline_tokens` is at most `window / 8`
  (`AdmitPolicy::for_window`, computed at each call). The configured value is unchanged.
- A stray NUL byte no longer turns a whole text output into a one-line description: output is binary
  only when NULs pass 1% of it or most of its first 8 KiB is not text; a NUL is shown as `\x00`.
- llama.cpp's overflow (`exceeds the available context size`, `exceed_context_size_error`), 422s,
  `input is too long`, `context_length_exceeded`, and overflow errors inside a 200 stream are context
  overflows. The limit is `n_ctx`, else the number after `maximum context length is` or `context size (`
  (vLLM's `max_tokens` refusal names `max_tokens` first), else the wording `A > B`, else the smaller of two
  numbers. An overflow re-weave may fold the latest step's output (down to no protected step).
- A refusal (400/413/422 that is not an overflow, such as a content filter refusing a page in the window)
  refused again on the same prefix re-weaves once with every tool output out of view whatever the size,
  the replies kept and no digest asked (reason `refused`), before parking; the park text says what an answer will do, and after that re-weave, that the model or
  its settings must change. An operator re-weave right after a refusal folds the latest step too.
- Re-weaves fold old harness notes: nudges, stall, verdict, output-cut, budget and interrupted notes
  early, arrival and info notes (agents' messages included) after the tool outputs. A view's stub keeps
  the handle of the output it showed.
- No serialized shape changed. `reweave.reason` gains the value `refused`.

### A smaller HUD on long missions

- The ledger brief in the HUD (the last message of every request, never prompt-cached) lists every todo
  and doing plan step but only the last 5 done ones, every open claim but only the last 10 settled ones,
  and the last 20 open obligations; each capped list starts with `(N older done|settled|open not shown:
  p1–p9, p12; call `ledger` to read them)`. `BriefOpts` gains `max_plan_done`, `max_claims` and
  `max_obligations`. A brief with 65 done steps, 74 claims and 25 open obligations went from 35 485 to
  11 625 characters; the 504-step mission this was measured on paid about 20 000 uncached tokens per step
  for its HUD. The re-weave brief uses the same caps; `ledger` still shows everything.
- `security_record` returns what the write touched (`recorded`, `removed`, `counts`, `more`) instead of
  the whole security state; `entry` and `normalized` are unchanged. The `state` key is gone from its
  result; read the state with `security_query`.

### Daemon: what a request is made of (`GET /api/sessions/{id}/window`)

- Additive fields on `WindowView` (old keys unchanged; a reader of an older answer gets defaults): `breakdown`
  (`basis`, `chars_per_token`, `total_tokens` and 14 `segments`: system, tools, rules, assignment, resume,
  conversation, tool_output, pinned, agent_reports, notes, stubs, other, framing, hud, each with `chars`, `tokens`
  and, for the parts that hold several things, `count`; the tokens always add up to `total_tokens`), `measured_now`
  (the server's count for the latest answered step request of the epoch plus an estimate of what was added since;
  `null` before the first), `last_request` (the latest step request with the server's count for its reply, 0 while
  missing) and `fold_at` / `fold_to` (`reweave_bounds` of the configured target and floor for the session's window
  and profile). `items[].note` names the kind of a `harness_note` item; `Weave::resume_chars` counts the resume block.
- `est_tokens` now counts the tool list in bytes, as `session` does (it counted characters). No stored shape changed.

### Web UI: phone pass 1 and the context card

- **Phones (699px and under).** The session scrolls as one: `#view-session` is the only vertical scroller, the tabs stick under the
  bar and the composer to the bottom, a tool output has no scroll box of its own (visible chat at 375x812 was 191px, now about
  590px). A session with its own open question lands on that card, and the Jump button never covers it (an amber "Approval
  waiting · Show" while it is off screen). The bar is one row of about 52px: Missions (with the count that need you), the
  title over the model and run state, and Find; its button opens the new **Session details sheet** (run with a confirmed
  Stop, context, model, view, session actions). Find is a two-row sticky bar of about 100px. The composer is a grid of about 110-130px
  with a one-line caption ("Plan 1 of 3 · context 9% · cache 98% ›") that opens the sheet; on the other tabs it is one "Message
  the lead…" button. With a coarse pointer Enter adds a line and Ctrl/Cmd+Enter sends; a narrow window with a mouse still sends
  on Enter. Work-group headers have a short form, text is 16px and targets 44px for touch, and the viewport allows safe areas.
- **Context card** (the inspector's Context tab and the sheet): the size with its window and share, one bar whose segments are
  also the legend (colour family plus a pattern, never colour alone), rows by group, the fold marks from the daemon's effective
  `fold_at` / `fold_to` in words and shapes (no amber), the cached/read-anew split, and notes. Estimates carry "~". Needs the
  additive `/window` fields below; an older daemon's answer shows the hero only.
- Riders: a profile named for its model is said once; the session id chip ends in an ellipsis when cut; the page title counts what
  needs you; the Models-panel row class no longer collides with the chat's chip row; the inspector tabs scroll instead of wrapping;
  the notification line says why they are off; `#f-workspace` turns autocorrect off. UI only apart from the `/window` fields.

### Web UI: copy buttons and opt-in copy on select

- Copy buttons: Copy reply (the exact raw text), Copy code (a fenced block without its fence), Copy message
  (operator and agent), Copy reasoning, and on an open tool row Copy command / Copy path / Copy arguments (named for what it copies: the bash command, a file tool's path,
  else the arguments as JSON), Copy output and Copy full output… (the whole stored output through
  `/api/blobs/{handle}/raw`, refused above 2 MiB with a pointer to the viewer). The stored-output and file viewers
  gain Copy lines (the selected lines, else every loaded line, without numbers) beside Copy reference / Copy path;
  inbox cards gain Copy text and evidence cards Copy quote. Icon buttons have names and tooltips, show on hover and
  focus and always on touch, and are 44 px on coarse pointers. Success shows "Copied" and is announced politely.
- One `copyText` helper does every copy: the clipboard API, else the selected text and the copy command, else the
  text left selected for Ctrl+C; the session-id chip uses it too. What each button copies is decided in `core.js`
  (tested). An opt-in **Copy on select** checkbox (inspector Session tab, off by default, `localStorage` key
  `loom_copy_on_select`) copies a selection wholly inside the chat or the viewer on mouseup/keyup, never while typing
  in a field, never twice for the same selection, and says "Copied N characters".
- loom-desk needs no change: its `WKWebView` offers `navigator.clipboard.writeText` and the copy command (checked
  with a stand-alone view configured like `WebPane`, by injected script, which WebKit counts as a user gesture, so a real
  click is not covered; Copy full output… therefore starts its write inside the click with the fetch as a promise, and keeps
  the text for a "Copy now" click if the browser still refuses). The fixture serves the raw blob route. UI only; no stored shape
  changed. `docs/UI.md` has a "Copying" section.

### Workspace folders: create a missing workspace, pick a folder, browse the workspace

- `POST /api/sessions` accepts `create_workspace` (default false). When the workspace does not exist and the flag is
  set, the daemon makes it (`create_dir_all`) and the 201 answer carries `created: true`; without the flag the refusal
  says the folder does not exist and how to create it. Refused before anything is made: a relative path, a path inside
  the loom home or its copies folder, a path under a file, `.`/`..` in the part that does not exist, `/` or the home
  itself. `~` and `~/x` expand to the daemon user's home. `loom run --create-workspace` (and `loom chat`) does the same
  and prints `created workspace <path>`.
- `GET /api/fs/dirs?path=` lists the folders in a folder (folders only, never file names; links marked; the loom home
  refused). `GET /api/sessions/{id}/files?path=` and `.../files/lines?path=&start=&count=` read a session's workspace
  (read-only, confined to it, `.loom` never shown, links that leave are not followed, files over 32 MiB refused, binary
  files named as such); they record nothing in the session. Additive; no stored shape changed.
- Web UI: a **Browse…** folder picker and a "Create and start" confirmation on the New mission form; a **Files** tab in
  the inspector (and a Files button in the session header), a file viewer mode, and **Open file** on tool rows. The
  fixture (`tools/ui-preview.mjs`) mirrors the routes. `docs/UI.md`, `docs/DESIGN.md` section 12 and `docs/RUN.md`
  are updated.
- Hardening: "inside the loom home or copies folder" is judged by file identity, so `/System/Volumes/Data/...` and links
  no longer get around it (also re-judged once a new workspace exists, which is removed again if it landed there); a new
  workspace gets its `.loom` (0700), so Bubblewrap can start in it, and a request that fails after the folder was made
  removes what it made; an existing workspace inside the loom home is refused. Both listings read a folder through one
  open descriptor, and the Files routes refuse anything that resolves into the loom home (a workspace may hold it); a
  line page keeps no per-line index. UI: the first read of the workspace root is no longer started twice, the folder
  lists no longer leak scroll height, the focused row is scrolled into view, coarse-pointer targets are 44 px, and
  Backspace/Alt+Up go up from an empty folder. Additive; no stored shape changed.

### Web UI pass 2: supervising many missions

- Switcher (Ctrl/Cmd+K, `Switch…`), Alt+Up/Down and Alt+Shift+Up/Down (next mission that needs you), and a `?`
  shortcut sheet; no key stops a session.
- An **Agents** tab (`#/s/<id>/agents`): agents grouped Needs you, Running, Waiting, Idle, Ended in stable
  creation order, with per-agent figures from `GET /api/missions/{id}/score` (on open, Refresh, at most every 120 s).
- **Find in the record** (`/`): literal search of the whole loaded record including folded groups, with an honest
  count; cut outputs are searched in the viewer.
- Browser notifications for blocking items, results and mission endings: only when the page is hidden, batched within
  5 s, never for a stop this tab asked for, closed when the item resolves.
- A quiet indicator ("no new record for 41m"), a "New since your last visit" divider, "Jump to latest · N new" and
  a progress line (plan, current step, budget as a limit) above the composer.
- Tool statuses have their own shapes (`exit N`, denied, invalid, timeout, interrupted) with counts in group
  headers, and a "partial" mark when the model saw only part of an output.
- "Ways out" on parked and blocker cards (fold the context, switch model, last recorded error); the inbox is
  grouped by mission with Ctrl/Cmd+Enter to send, focus to the next card, and "Refuse…" on scope requests.
- Fixes: snapshot merge keeps live session state, Overview work only runs on its tab, the ledger is re-read after
  a reconnect or `lagged`, an approved scope request is no longer shown as "Dismissed", Fold now and the model
  selects confirm first, code blocks render in linear time, and the inbox self-heals every 60 s.
- UI only; `docs/UI.md` is updated.

### Web UI: chat-first layout and visible model identity

- The session opens on **Chat**, the whole record as a conversation (`#/s/<id>` and `/chat`; `/record` is
  rewritten to `/chat`), then Overview and Evidence. Operator messages are bubbles; replies are plain prose
  with a collapsed `Thought` row; consecutive tool calls, text-less replies and ledger/job lines fold into
  work groups headed `Worked for <duration> · <n> tool calls` (failed and running counts included), open
  for the last group, a running call or an operator click. **Expand all work** opens them; deep links and
  Activity links expand the group they point into.
- The header is an identity bar: breadcrumb, chips for the model in effect (`profile · model · window`,
  with an "unreachable" warning), role, a copyable short id and the run state with elapsed time, the
  standing facts, and a one-line goal with Show all.
- Each stretch of assistant output carries a chip naming the profile that produced it, and a
  `model_switched` record is a visible line showing both sides.
- The composer has a model seat: choosing another profile asks for confirmation, then
  `POST /api/sessions/{id}/model`; the switch takes effect at the next step and re-reads the prompt once.
- A stats line under the composer replaces the top-bar speed: tok/s, cache share, context use, step.
- The sidebar groups missions by workspace with a pinned **Needs you** group; each row has one mark by
  strict precedence and an identity line `<profile> · <role> · <age>`.
- The preview fixture signs in from `/#code=fixture` and covers models, the model switch, an unreachable
  profile and `POST /__fixture/stream`.
- The top bar (below 1100px) carries the open session's model profile and run state; the sidebar's
  connection line is short (`Live`, `Reconnecting…`) with the detail in its tooltip; a row's identity line
  never truncates the profile, and a waiting reason has its own line, including nonblocking questions and
  ready results. A row's age comes from recorded activity (kept across a reload) or reads "activity not
  loaded"; an ended-stopped session has its own shape.
- Work groups update by member, so an open Thought, focus and the output viewer survive live records, a
  long open group is windowed, warnings are counted in its header, and request-detail lines no longer
  change the groups. The model seat is disabled for ended sessions and per-session while switching.
- `loom ls` shows a MODEL column (the session's profile) after ROLE.

### security_record reads near misses

- `security_record` now reads an operation where its meaning is unambiguous (`ops`/`items` for
  `operations`, wrapper fields at the top level, `username` for `principal`, a `hypothesis: {...}` wrapper,
  word priorities, `verdict` for `status`, `host:port` or URL host locators, a method or trailing text on a
  URL, a path under its `parent`) and lists each rewrite under a new `normalized` key of the result; the
  key is present only when something was rewritten. Everything else is refused with the exact shape to send,
  and role-forbidden actions (a verdict from a non-verifier, a child opening a hypothesis) are refused first.
  Evidence still has to exist and be attested. A single `hypothesis_open` that carries evidence is recorded
  with it in one atomic append.
- The tool description now lists the shape of every action and differs for the lead, a child, and a
  verifier. A failing operation inside a batch is named in the core's error (`SecurityOp::action`, added).
  `loom-agent` depends on `url` for locator reading. No serialized shape changed; see `docs/SECURITY_STATE.md`.

### OWASP dep-scan tool

- New built-in `dep_scan` tool wraps the operator-installed OWASP
  [dep-scan](https://github.com/owasp-dep-scan/dep-scan) `depscan` command under the sandbox: scan a
  project directory (`--src`) or one CycloneDX SBOM (`--bom`), write reports/`HOME`/`VDB_HOME` only
  under the session temp dir, parse and store the VDR and SBOM as citable blobs, and summarise
  prioritized/reachable findings (at most 50 lines; counts cover all). A missing binary is install
  guidance, not a clean scan. `command_bounded` raises the analysis-command timeout ceiling for the
  first-run database download. Granted to `core` and `vr` roles; see README, DESIGN § tools, and
  `docs/SECURITY-TOOLS.md`.

### Structured tool interfaces, HTTP/recon hygiene, and exact view/state repeat tracking

- `codec_calc` gains `op = "rebase"`: subtracts a symbol offset from an observed runtime address, enforces
  power-of-two page alignment (`>= 4096`, default `4096`), and resolves up to 32 named target offsets into
  decimal, hex, `le64`, and `be64` forms in one checked operation (`loom-tools::codec`).
- `bin_survey` on ELF objects now includes bounded static `sections` (`SHF_ALLOC`, `writable`, `executable`,
  `nobits`), dynamic/PLT `relocations` (`symbol`, `address`), and defined `symbols` (`function`, `object`,
  `other`, including zero-size labels) without executing the binary (`loom-tools::binary`, `packs/ctf`).
- `command_guard` decodes up to three rounds of percent-encoding before checking interactive or unbounded
  command patterns (`loom-tools::capabilities`).
- `http_send` and `http_repeat` refuse quarantined session-ending, destructive-lifecycle, and single-use token
  URLs unless `allow_quarantined: true` is passed, extract bounded `<form>` and `hidden`/`readonly`/`disabled`
  field metadata on HTML responses, and record cross-principal `2xx` vs `401/403` status differentials on
  normalized route templates (`loom-tools::http`, `packs/ctf`).
- `security_ingest` classifies quarantined lifecycle/token URLs and queryless static-asset URLs as
  `mandatory = false` and orders mandatory API/auth/query endpoints ahead of generic and non-mandatory routes
  (`loom-agent::rtools::security`, `packs/redteam`).
- `observe::repetitions` now also counts repeated `Read`/`Nav` views (`META_OF_BLOB` + `META_SHOWN`) and
  `State`/`Nav`/`Read`/`Exec` plain-message results whose canonical arguments and result text match byte for
  byte (`loom-core::observe`).

### Box: a remote container for commands

- New `[box]` config (off by default) and tools `box_exec`, `box_get`, `box_reset`, given to the `ctf` solver
  roles. One hardened container per mission on a Docker host reached by an ssh-forwarded or local socket; the
  agent never sees Docker. Images must be pinned by digest; egress is the mission's granted exact hosts and IPs
  (per-mission network and host firewall chain, updated on grants and releases, removed with the mission);
  workspace files are copied in (never what the agent could not read) and `box_get` unpacks results through the
  `write` tool's own path with size, entry and type limits. New modules `loom-tools::boxctl`, `boxfs`,
  `loom-agent::rtools::boxtools`; `proc::spawn_launched` and `bash::run_launched` run a loom-built launcher
  outside the sandbox with `bash`'s procedure. The ctf tool cap is 30. See docs/RUN.md and SECURITY.md.
- Box security review: a mission's box lifecycle (create, reset, re-rule, teardown, reconcile) is serialized
  by one lock per mission and its chain is removed only after the container and network are gone; every box
  bridge is dropped by a static `LOOM-ALL` chain unless its own chain accepts; IPv6 is off in the container
  and dropped on the host; a stopped mission's box stays down until the lead is resumed; a running box's
  rules are re-checked and reinstalled or the command refused; a network that is not the box's own is never
  adopted; file push opens by descriptor with `O_NOFOLLOW`; `box_get` refuses `.`/`..` components and tar
  typeflag 7; `ssh` and the docker client are resolved once, run with a fixed environment and a private
  directory; the box is refused with `sandbox.mode = "none"` or a `unix_sockets` entry that reaches its
  socket.
- Box fix: the container has a read-only root, so Docker mounts `/etc/hosts` read-only too and the root
  writer failed (every `box_exec` and `box_reset` said the box could not be made ready). The writer and
  its root `docker exec` are gone; the granted names are given to `docker run` as `--add-host name:ip`
  (sorted, built from validated names and `Ipv4Addr` only). A name granted after the box exists has its
  address reachable at once (the rules are updated) but resolves inside the box only after `box_reset`;
  until then every `box_exec` result says so.
- Box fix: `docker cp` fails on a `--read-only` container (it writes to the rootfs and cannot see the tmpfs
  `/work`). `push` now runs `docker exec -i -u 1000:1000 <ctr> /usr/bin/tar --extract --directory=/work
  --no-same-owner` and `box_get` runs `tar --create --format=pax --directory=<parent> -- <name>`, read up to the
  byte cap and then killed; the I6 and I7 rules are unchanged. The box image needs `/usr/bin/tar`.

### Morale: keeping a model on a hard task

- The step block gains `Where the work stands:`, read from the ledger alone: results established, what is
  ruled out with evidence, what is only set aside (a dead end is not a refutation), open leads, security
  surfaces closed and untested, and the attempts run in this session. Security records appear by id only.
  New module `loom-agent::frontier` (`frontier`, `attempts_run`, `render`, `directions`).
- `claim_update` to `supported` adds one line, `Established: {id}. Results established in this mission so
  far: {n} ({ids}).`, so a banked result stays in view.
- New pack key `solvable` (default false). In a solvable pack the system prompt says the operator built the mission to be solved, and `conclude` with status `unreachable` is refused with a pointer to `report_blocker`. The `ctf` pack sets it; `core`, `vr` and `redteam` do not.
- A refused `finish` (goal not concluded) now lists the routes the ledger still shows open, from
  `frontier::directions`, and says to pick one and run it. When the ledger shows none it asks for three
  untried approaches, then names the role's real ways out (`ask_for`, `agent_spawn`, `report_blocker`).
  The text says what is missing and how to close it, in a collaborative tone, never as a judgment of the
  work. Outside a solvable pack it adds that a well-evidenced `unreachable` conclusion is a reportable
  outcome, not a failure; in a solvable pack `unreachable` is never offered.
  `conclude` unreachable with open plan steps adds that those steps are routes still open.
- The other `finish` refusals are worded the same way: open items (what is still open and how to close each
  kind, "not a verdict on the work"), a verifier objection (the concrete gaps, and that only new execution
  evidence settles them), the mechanical failures (quote shape and match, empty answer, running work) as
  cheap fixes, and the stop-gate idle paragraph. Wherever `conclude` `unreachable` is offered as a path, a
  solvable pack leaves it out.
- Stuck detection: when a lead's `finish` is refused before a verifier runs (goal not concluded, or open
  items) twice in a row with no new attested execution evidence, one non-blocking `Question` inbox item
  opens for the operator (Keep working / Narrow the goal / Release the mission / Conclude unreachable;
  the last is left out in a solvable pack). It pauses nothing, is not a ledger question and never blocks a
  finish. The refusal text says the operator was told, with no count. The count resets when fresh evidence
  appears and is in memory only.
- New ledger tool `reflect` (`ruled_out`, `next_route`, `would_change`) records a structured reflection
  for a session going in circles; it is rendered in the ledger document and granted to the lead and worker
  roles of `core`, `harnessmm` and `vr`. The step block shows `- Reflections recorded: {n}` in `Where the
  work stands:` when there are any. There is no count of rejected finishes anywhere in the model's view.
- The `core`, `harnessmm` and `vr` prompts say that a well-evidenced `unreachable` conclusion is a
  successful mission outcome.
- A re-weave now leaves a map, not a chronicle of failures: the resume brief adds the frontier block (when the
  session has a ledger) and says a failed attempt rules out that attempt, not the approach, and the digest
  request asks for Established / Ruled out / Tried, not ruled out / Open leads / Next instead of a list of leads.
- New tools for a stuck model, neither a finish nor a claim that the work cannot be done. `ask_for`
  (lead: `core` `lead`, `vr` `researcher`, `ctf` `dispatcher`) asks the operator for budget, a tool, a
  hint or direction without ending the turn. `hand_off` (`core` `worker`, `vr` `scout`, the `ctf`
  solvers) returns an assignment unfinished with its state, open leads and an ask; it settles the child
  as `returned`, and an ask for `stronger_model` selects the role's `escalation_model` next time.
  `ctf` `binary_solver` now has 26 tools. Installed packs under `~/.loom/packs` are not updated by an upgrade.

### Watched jobs, agents in their own copies, and attempts

- `bash` takes `wake_on` (a regular expression) and `wake_every_s`. The background job the call
  leaves behind is watched: when its output has a matching line the session is told, with the lines
  and a handle to that part of the output, and a session that ended its turn with `wait` is resumed
  as it is when a job ends. Before, a job that runs for hours could only be polled, a step per look.
  New record `job_matched` and turn trigger `job_output`; `tools.job_wake_gap_s` (30) and
  `tools.job_wake_max` (20) bound how often one job reports.
- `agent_spawn` and `agent_fanout` take `workspace: "copy"`: the agent works in its own copy of the
  lead's workspace (`~/.loom-copies/<mission>/<agent>`, cloned files on APFS) instead of beside the
  lead, and the lead is shown which files it changed. New tool `agent_adopt` brings one agent's
  changes into the workspace, all or nothing: a path that changed on both sides is a conflict and
  nothing is merged. `agents.copy_max_files` bounds what is copied, and `agents.copy_max_mb` does
  where a copy duplicates the bytes (not on APFS, where files are cloned).
- New tool `attempt`: one assignment attempted by several agents at once, each a fork of the lead in
  its own copy. The harness runs the lead's `check` command in every copy and reports each exit
  status, output and changed files; the lead adopts one attempt.
- The built-in `core` lead and the `vr` researcher have `attempt` and `agent_adopt`. Packs installed
  under `~/.loom/packs` are not updated by an upgrade: replace an installed `vr` with the shipped one,
  and add the two tools to the lead's `tools` of a pack of your own (see `docs/RUN.md`). In `vr` a
  scout has tools the researcher lacks, so it always starts fresh; the researcher's prompt said a scout
  starts from everything the researcher has seen, and now says what happens.
- `packs/vr/workspace/AGENTS.md` is new: the `vr` pack's standards in one file written for the agents,
  to copy into an engagement workspace and name in the first message. It covers scope requests,
  `conclude`, watched jobs, agents in their own copies and attempts. loom does not load it.
- Archiving a mission deletes its agents' copies, including changes that were never adopted.
- `meta.json` of an agent in a copy has `copy_of`; older daemons ignore it.

### Quoting, fresh starts and measuring a change

Upgrading: restart the daemon (`loom down`, `loom up`); `loom score` says so when the running daemon
is older. Replace copies of shipped packs in `~/.loom/packs` to get the new role texts; a running
session keeps the system text and the tool descriptions it started with (a quote without its text is
accepted there too).
`fresh_start` is on by default and changes what a lead reads after a rejected finish; set
`[agents] fresh_start = false` to keep the earlier behaviour. A session that had a fresh start has a
`remove` eviction in its log and a `goal_reopen` entry in its ledger, which an older `loom` does not
know: do not go back to an older build on a home with such sessions.

- **Quotes by line numbers.** The `text` of a `finish` quote and the `quote` of `evidence` may be left
  out: the harness then takes the lines `start`-`end` from the stored output, so nothing is retyped and
  nothing can be mistyped. Such a quote takes at most 20 lines and 2000 characters, and its range is
  not clamped: a range past the end of the output, or of blank lines only, is refused. `evidence` plays
  back what it recorded, since nothing compared the numbers with a text. A quote given with its text is
  checked as before. The tool descriptions and the worker, scout and `vr` harness texts say to leave
  the text out when the line numbers come from `out_read`, `out_grep` or `read`.
- **A fresh start after a rejected finish** (`[agents] fresh_start`, default `true`). When the verifier
  does not accept a lead's finish, the goal is open again (a new `conclude` needs execution evidence
  recorded after the rejection) and the lead's window is folded: its replies and reasoning go out of
  view, every `finish` and `conclude` call since the last delivered result is taken out of the window
  with its result, other output is shortened to stubs, and nudge, stall and verdict notes are dropped.
  The lead reads a brief instead: what the verifier found, that the goal is unsolved and not decided
  either way, where folded material is, and the `Where the work stands:` picture of the Morale section
  (a failed attempt rules out that attempt, not the approach). It states no count and never says that a
  finish was made or rejected. This happens at every rejection, and it is the only rejection text left in
  view: the harness's own note about the rejection is dropped by the same fold, and the stuck detection of
  the Morale section keeps counting refusals that come before a verifier runs, with the same notion of new
  execution evidence (recorded after the last rejection; a reopened goal asks for the same). Nothing is deleted: the
  record, `loom tail`, the web UI, `log_search`, `out_read` and `out_grep` have all of it. The HUD's
  finish line no longer says "finish again". A mission the operator released is not reopened.
- **The advisory "Possible repeated outcomes" section of the HUD is gone**, with
  `observe::outcome_repetitions`. A repeat is listed only when the call and its result were the same,
  byte for byte.
- **`loom score <session|mission> [--json]`** and `GET /api/missions/{id}/score`: what a mission's work
  took, one row per session and a total (steps, steps to the delivered finish, calls, malformed calls,
  refused finishes, refused quotes, verifier verdicts, fresh starts, and the uses of `hand_off` and
  `ask_for`). Refusals over a quote or by the
  verifier, and whether a delivered finish was verified, are now marked in the tool result's `meta`
  (`refusal`, `verified`), so the counts read no prose; a log from before shows `?` for them. The
  counts say what the work cost, not whether the result is right.
- **An evaluation kit for harness changes** (`loom-agent::evalkit`, `cargo run -p loom-agent --example
  eval [--json] [scenario…]`): eight scripted models (does everything right, retypes its quotes wrong,
  finishes early, makes malformed calls, is rejected once with and without the fresh start, delegates,
  gives up) played against the real runtime and the mock server on one small task, with the scorecard
  of each. Its tests pin the counts. It needs no model and no network, and it measures the harness's
  side only: how a real model reacts is measured by scoring recorded runs before and after a change.

### Domain packs and evaluation

- Added opt-in CTF and Redteam packs with specialist tool surfaces (CTF roles at most 26 per role,
  Redteam at most 18), bounded epochs, credential-gated lateral assignments, observers and
  operator-contract judges. Existing installed packs and running session prefixes are not
  automatically replaced.
- The `ctf` dispatcher gained `grep`, `glob`, `wait`, `attempt` and `agent_adopt`; `solver` gained
  `grep`, `glob` and `wait`; `web_solver`, `binary_solver` and `crypto_solver` gained `edit`, `grep`,
  `glob` and `wait`, and `binary_solver`/`crypto_solver` also gained the PTY tools
  (`pty_open`/`pty_exec`/`pty_close`); `web_solver` also gained `job_wait`. Packs installed under
  `~/.loom/packs` are not updated by an upgrade: replace an installed `ctf` with the shipped one.
- Added a paired qualification protocol and a JSONL analyzer that retains censored failures, unknown
  usage and pairing errors. It performs no model/target calls and claims no benchmark improvement.

### Structured execution and security gates

- Added opt-in session-local PTY, structured HTTP replay/cookie/capture/race, exact codec/TOTP,
  binary-analysis and operator-oracle tools. PTYs participate in stop/finish/recovery accounting;
  subprocess outputs and partial failures retain normal output provenance. Backend analysis uses
  content-pinned inputs and bounded generated views. See `docs/SECURITY-TOOLS.md`.
- HTTP tools share a daemon-wide per-host limit; reference web/CVE GETs use a distinct in-process
  credential, validate redirect hops and strip ambient credentials. Reference OSV POST is refused.
- Security roles can require an independent current-contract oracle receipt, matching live credential
  prerequisites and hard child step slices. Verdict disqualifiers override accepting model prose.
  Coverage remains checked atomically; output text/PTY frames are not independent success oracles.
- Typed coverage/revisit/hypothesis summaries are shown in the HUD without copied secrets. Child IDs
  accept exact IDs, unambiguous prefixes and `last` within the parent's actual children.
- Rust 1.88 is now required by the RFC HTTP cookie-store dependency (previously 1.85).

### Role runtime controls

- Packs can route fresh children through named model profiles, rotate sibling profiles, escalate
  subsequent assignments after failure, require a distinct named verifier profile, and cap admitted
  execution attempts. Cross-profile forks are refused; existing pack defaults are unchanged.
- Session log schema 2 adds non-rendered active-budget and Exec-admission records. Schema 1 logs remain
  readable; older binaries refuse new session headers. Time excludes recorded queues, retries and idle
  turns. Wrap-up admission now blocks probes/new work on both normal and speculative paths while
  retaining output inspection, cleanup and honest blocker delivery.
- Reasoning-only replies receive a specific bounded nudge. Optional flag-pattern alerts are advisory
  and do not verify success. See `docs/RUNTIME-CONTROLS.md`.
### Containment and reference capabilities

- Shared macOS system temp directories are no longer blanket writable roots. Commands use their
  session `$TMPDIR`; read-only verifiers cannot write sibling system temp locations.
- Git configuration/hooks/pointers are protected, including nested repositories, linked gitdirs and
  commondirs. Seatbelt/file tools guard future metadata names; Bubblewrap makes discovered Git dirs
  wholly read-only and does not reserve future repository names in writable directories.
- Oracle supervisor secrets under `<workspace>/.loom/oracle-secrets` are unreadable, including before
  creation and through symlinks. `Sandbox::isolated_replay` enforces separate harness-owned replay
  workspace/temp siblings, rejects unconfined mode and removes the actor's writable roots.
- Added the serialized sandbox mode `bubblewrap` (old config modes remain readable): Linux
  namespaces, descriptor-pinned read-only/masked mounts and seccomp deny-all socket policy, without
  unconfined fallback. Missing protected paths inside writable roots are refused.
- Added optional `network.reference_hosts` (defaults empty): separate in-process GET proxy grants
  kept out of command env, raw proxy refusal of reference names, method/header restrictions for plain
  HTTP, and session revocation of both credentials. HTTPS GET/redirect policy belongs to the trusted
  client. This is a capability restriction, not an exfiltration-proof channel.

These changes follow a review of the first version of loom. They are grouped by area. Read "Before you
upgrade" first; the rest says what behaves differently.

### Before you upgrade

1. **The network is closed by default.** `[network] mode` now defaults to `deny_all`: bash, `web_fetch`
   and the vulnerability lookups reach no host through the egress proxy. Before, the default was `open`.
   Requests to your model server are not affected. To keep the old behaviour, set
   `[network] mode = "open"`; to reach only some hosts, set `mode = "allowlist"` and list them in
   `allow`. The `vr` pack refuses to run when the mode is `open`.

   **Check your existing config file.** The new default applies only where the file does not set the
   mode. A `~/.loom/config.toml` written by the first version's `loom config init` says
   `mode = "open"` under `[network]`, so after upgrading its network is still open and `vr` sessions are
   refused. Change that line to `mode = "deny_all"` (or `"allowlist"` with an `allow` list) to get the
   new default and to run the `vr` pack, then restart the daemon.
2. **Credential directories are unreadable to commands by default.** `~/.ssh`, `~/.aws`, `~/.gnupg`,
   `~/.config/gh`, `~/.config/gcloud`, `~/.azure`, `~/.kube`, `~/.docker/config.json`, `~/.netrc`, `~/.npmrc`,
   `~/.pypirc`, cargo and git credential files, `~/.password-store`, `~/.config/op`, the Keychains and
   Cookies folders and the Chrome, Firefox and Safari profiles can no longer be read or written by
   commands or the file tools. If a workflow needs one of them (a package manager that reads a registry
   token from `~/.npmrc`, or a tool that reads `~/.netrc`, to reach a host your `[network]` policy allows
   through the proxy, for example), set `[sandbox] protect_credentials = false`, or run that step
   yourself. Turning the key off does not by itself make a `git push` over SSH work: commands reach the
   network only through the egress proxy, which `ssh` does not use on its own, and `SSH_AUTH_SOCK` is
   not passed to them. A listed directory that is or contains the workspace stays readable. The key
   needs a home directory: with `HOME` unset, sessions fail with a message that names it.
3. **Replace installed packs.** Pack loading is stricter: a role whose `finish` is verified must have a
   verifier role of the same pack that is read-only and has `verdict` and `out_read` or `out_grep`
   (unknown keys were already errors and still are), and the researcher in `vr` now says
   `verifier = "judge"`. A copy of a shipped pack in `~/.loom/packs` (for example `~/.loom/packs/vr`)
   from the first version no longer loads, and the daemon refuses to start with it. Replace it with
   the shipped one:
   `rm -rf ~/.loom/packs/vr && cp -R packs/vr ~/.loom/packs/vr`. Prompts changed too, and a session
   keeps the system text it started with, so only new sessions get them.
4. **Restart the old daemon, then rebuild the desktop app.** The daemon now proves it holds the token
   (`GET /healthz?nonce=...`) before the `loom` command or `loom-desk` sends the token to it. A new
   client refuses a daemon from the first version, naming the address and saying the token was not
   sent. Stop the old one with `loom --unverified-daemon down`, then start the new one with `loom up`.
   `loom-desk` must be rebuilt (`LOOM_BUILD_HOST=<host> gui/build.sh --pull`): the new app logs in with
   a one-time code and does not fall back to a token in the URL, so it cannot use an older daemon; and
   the first version's app, which relied on the daemon's cookie, is not supported against the new daemon.
5. **Web login changed; old browser cookies are void.** The web UI no longer uses a cookie. Open it with
   `loom open` (it prints the address only with `--print`). The first version stored your API token in
   a `loom_token` cookie for `127.0.0.1` and `localhost`; the new daemon tells a browser that still
   sends it to forget it the next time the page loads, but you should clear those cookies yourself, or
   rotate the token (stop the daemon, delete `~/.loom/token`, start it; copies of the old token, such
   as one kept by `loom-desk` or in a remote client's `LOOM_HOME`, must be replaced). A bookmarked
   `/?token=...` address redirects to a login-code address and sets no cookie.
6. **The model retry window defaults to 300 seconds.** `retry_window_s` used to default to `0`, which
   retried an unreachable server until it came back. It now gives up after five minutes (long enough
   for a server relaunch). Set `retry_window_s = 0` for the old behaviour.
7. **Speculative tool calling is on.** `[tools] speculate = true` (new, default `true`) starts a reply's
   leading read-only calls (`read`, `glob`, `grep`, `out_read`, `out_grep`) while the reply is still
   streaming. Records, their order and what the model sees are the same except timings, the ids of
   calls started early, and an `early_ms` entry in a result's metadata. Set `speculate = false` to
   turn it off.
8. **`LOOM_BUILD_HOST` is required by `gui/build.sh`** (a host, or `local`); it has no default host and
   the script stops when it is unset. Set it every time you run `./x` too: `./x` does not stop when it
   is unset but falls back to a host name written into the script, which is not a machine of yours.
   `./x` is optional and `cargo build --release -p loom-daemon` is the normal way to build. `./x` reads
   `LOOM_LANE` for separate build copies.
9. **Linux can use explicit `mode = "bubblewrap"`** with `/usr/bin/bwrap` on x86_64/aarch64. It has
   deny-all command networking and refuses host proxy/loopback/Unix socket exceptions. Other
   unsupported systems require explicit `mode = "none"`; that leaves shell commands unconfined.
10. **Going back to the first version is unsafe.** This version and later ones refuse to add to a
    session log that has a newer `schema` or records they cannot read, or to a mission journal with an
    operation they do not know, with a sentence telling you to upgrade; reading such a session still
    works. The first version has no such check: it keeps adding to a session log whose records it
    cannot read, and it reports a journal entry it cannot read as tampering. Do not go back to it on a
    home that this version has used.

### New commands and options

- `loom open [--print]` opens the web UI with a one-time login code.
- `loom rule <session> <text>`, `loom rule <session> --withdraw <rule-id> [--reason <text>]` and
  `loom approve <session> <text> [--scope <text>]` set and withdraw standing rules and record
  approvals. They are also available in the API and in the Ledger tab of the web UI. Inputs given while
  the lead is in a turn are kept on disk until it records them.
- `loom gc [--apply]` deletes stored outputs that no session or mission refers to (dry run by
  default).
- `loom --unverified-daemon` (global flag) sends the token to a daemon that cannot prove its identity,
  with a warning; meant only for moving off a first-version daemon.
- `loom status` shows free space on the volume of the loom home and warns below 5 GiB or 5 percent.
- New config keys: `[sandbox] protect_credentials`, `[tools] speculate`. Changed defaults:
  `[network] mode` (`deny_all`) and `retry_window_s` (300).
- Pack keys: `requires_restricted_network` (top level) and `verifier` (per role).
- API additions: `POST /api/login-codes`, `POST /api/web-sessions`, `POST /api/sessions/{id}/rules`,
  `/approvals`, `/rules/{rule_id}/withdraw`, `/scope`, `/release`, `POST /api/gc`, `GET /healthz?nonce=`, and a `disk` field
  in `GET /api/status`.

### Scope, conclusions and release

- `loom scope <session> <host>... [--note <text>]` (and `POST /api/sessions/{id}/scope`) lets one session
  reach more hosts while it runs. An agent asks with the new `request_scope` tool; the request waits in
  `loom inbox`, the web UI and the app without stopping the session, and you approve it there. Grants are
  per session and recorded in the ledger. `loom net` and the Ledger and Network tabs list them.
- `loom release <session> <reason...>` (and `POST /api/sessions/{id}/release`) accepts a blocked mission
  and closes it as "closed by operator, goal not established". A blocker or used-up budget now offers
  choices in the UI and the app: keep working, keep working with more budget, provide what is missing,
  or accept as blocked and close (a typed reason and a confirmation).
- The `core` lead and the `vr` researcher and scout have a `conclude` tool, and the `core` lead and chat
  and the `vr` researcher, scout and chat have `request_scope`; their prompts say finishing needs a run
  that shows the goal met or an established "cannot be met", and that scope is widened only by you.
  Replace installed copies of the packs to get them.

### Daemon and web UI

- The web UI bounds the mission goal's height in the session header and scrolls it within its own box.
  A goal that is a whole recorded prompt no longer grows the header past the viewport, which had left
  the tabs, the record and the composer below it off screen and the page with nothing to scroll.
- The web UI shows each model reply's generation speed in its footer (tokens after the first over the
  time from the first streamed token to the end of the stream, so the wait for the first token is left
  out), and the open session's speed in the top bar beside the stream freshness — the latest reply,
  then the rate over the latest replies together — where a long goal cannot push it out of view. This
  is in the desktop app too, which shows the same page. Replies recorded before the daemon kept this
  timing show no figure.
- The web UI shows a warning line when the disk of the loom home is low, and the daemon raises one
  notification when it turns low (and again only after it has recovered).
- A session's scratch directory (`tmp/`) is emptied when the session ends for good or is archived.
- Where notifications are off (no `[notify] command` off macOS) the daemon logs a warning at start, as
  it does with `[sandbox] mode = "none"`. A profile whose configured `context_window` is larger
  than the server's is warned about at its first discovery (when the first session of that profile is created).
- Notifications mark model-written text: a child's title starts with `unverified: ` and the ledger lines
  of a parked session carry the `[From the agent, unverified]` label.
- A config with a `context_window` below `context.target_tokens` loads; a session clamps the bounds to the window.
- `agents.invalid_calls_before_forcing` is documented as reserved (it has no effect); the login-code exchange
  rejects unknown fields.
- The daemon takes `<home>/daemon.lock` first, so two daemons cannot start on one home. It binds only
  loopback addresses, and creates the token and keys atomically.
- `/` and the page assets need no login; every `/api` route needs the bearer token or a web-session
  secret. The page reads its event streams with `fetch`, not `EventSource`, and says `Run "loom open"
  again` when its secret is gone. Web-session secrets live in the daemon's memory, so a daemon restart
  needs `loom open` again.
- The ledger view (`loom ledger`, the web UI, the model's state block) says when entries written by a
  newer loom are not shown, when a torn tail was ignored and when entries are not covered by the head
  record.
- Start-up sweeps the process groups a previous daemon left running and notifies you again of inbox
  items that were still waiting.
- A session record this build cannot read in full (a kind or value written by a newer loom) is served
  by `/api/sessions/{id}/records` and the session stream as it is stored, with every field, instead of
  as `"kind": "unknown"` with only its header.

### Sandbox and tools

- Commands cannot write to credential stores, the temp directory entry cannot be removed or replaced,
  and LaunchServices opens, Apple Events and launchd jobs are denied. More environment variables are
  withheld (names ending `_PAT`, `_DSN` or `_PWD`, `DATABASE_URL`, `SSH_AUTH_SOCK`, and names
  containing `COOKIE`). Path rules that refuse ignore case on macOS.
- More credential stores are unreadable to commands by default (model-hub, AI-tool, database, cloud,
  registry, password-manager, wallet, browser, chat, Mail and Messages stores; see `docs/DESIGN.md`;
  whole directories such as `~/.cache/huggingface` and `~/.fly`, with what else they hold), and more
  environment variables are withheld: names with a session, auth, pass, jwt, webhook or private part,
  names containing `PASSPHRASE` or ending `_PW`, every model profile's `api_key_env`, and any value that
  holds a URL with a password. A process that leaves its command's process group (`setsid`,
  `daemonize`) is still not stopped by `job_kill` or session end.
- A command is over only when its whole process group is empty. A command whose leader exits while
  others run returns at once with the output so far and a job id. Exit codes above 128 are reported as
  exit codes with a note that 128+N usually means signal N. A command whose output passes
  `max_output_bytes` is killed at once and only the first part is kept.
- `read`, `write` and `edit` work on regular files only; `read` loads at most 64 MiB (use a line range
  for larger files); `grep` skips files over 16 MiB and says so. `grep` and `glob` list at most
  `search_max_results` entries and 4 MiB of text, and say when a result is cut.
- `read`, `write` and `edit` check the real path of the file or directory they opened, and write
  relative to the opened directory, so a command that swaps a directory for a link during a call can
  no longer make them read a protected file or write outside the writable areas.
- Evidence can be cited from a `read` result (its header now ends with an `out:` handle) and from a
  finished background job's complete output. Output produced by the runtime's own tools (ledger,
  agent reports, `finish`, ...) can no longer be cited as evidence. A quote copied with line numbers
  must carry the real line numbers, and a partial-line quote needs at least 8 non-space characters.

### Network and egress

- The deny list also matches the resolved address and accepts IP addresses and CIDR blocks, in every
  mode. IPv6 forms that carry an IPv4 address are judged by that address; Teredo and other special IPv6
  ranges are refused unless listed in `allow_private`.
- Every allowed connection is written to the session's `net.jsonl` (now a hash chain) before it is used;
  if the write fails the client gets 502. The proxy has fixed limits on connections, lookups and idle
  time. `web_fetch` and the CVE tools check the policy before https requests.
- The operator can authorize more hosts for a running mission without a restart; the grant is recorded
  in the mission ledger, applies to the mission's running sessions at once and is re-applied after a
  restart. A lead can ask for hosts with the new `request_scope` tool, which only opens an inbox item.
- A forwarded plain-HTTP response says `Connection: close` and ends the connection where the response
  ends, so a destination cannot pass a later answer off as one of the proxy's; `web_fetch` and the CVE
  tools open a new connection for every request.

### Model client

- The client follows no redirects: a 3xx fails with the `Location` and tells you to fix `base_url`.
- Requests carry the model id the server reports; a 404 for an unserved model makes the client look at
  `/models` once. If several models are served and yours is not among them, that is a configuration
  error listing them.
- Failures waiting cannot cure end the request after three attempts in a row. Streams over fixed size
  limits fail as malformed.
- A session is not created when the server cannot be reached and the profile sets no `context_window`.
- A model request still retrying after `[agents] unavailable_notice_s` (new, default 300; 0 = never)
  opens a non-blocking inbox item, with a notification, naming the server, since when it is down and
  the last error; the item closes by itself when the request ends. None opens when the retry window
  ends first.

### Sessions, agents and finishing

- The harness-state block no longer shows a running turn/step count or a finish-rejection tally; a rising number read as time pressure. The step and time budget is enforced as before, with one late heads-up to wrap up, and the finish line is a steady instruction to conclude the goal first.

- A lead can no longer finish by conceding: `finish` is refused in the same step while the goal is not
  concluded, and a new `conclude` tool (`met` or `unreachable`, with execution evidence) records the
  conclusion. A verifier's objections become obligations that only new execution evidence settles. A
  rejected or unrunnable verification no longer opens a blocking item for the operator: it writes a note
  and the session works on (an unrunnable verifier is retried twice first).
- A child agent always settles exactly once and its lead receives the settlement, including after a
  restart. `agent_stop` waits for the agent to end. Archiving settles the mission's agents.
- On shutdown running turns are cancelled first, and the jobs the shutdown kills are recorded as
  killed, with their output and a note that the shutdown stopped them. Sessions that were waiting on
  them resume after the restart.
- A background job that finishes while the daemon is down (after a crash) is reported after the
  restart with its real exit status and output, also when the crash came before its start was
  recorded; only a job whose outcome is unknown is reported as lost. A session told of such job ends
  is resumed even when the daemon goes down again before that turn.
- A finish verifier cut by a crash (not only by a shutdown) is still the finish's after the restart: it
  does not block the next `finish`, its verdict never arrives as an agent report, and the `finish`
  made again uses it instead of starting a second one.
- A verified role's `finish` is delivered only after the verifier accepts it. After two rejections, or
  when the verifier cannot be run, you get a blocking `NOT VERIFIED` inbox item. `finish` is refused
  while the session has running jobs or agents.
- `stop` is sticky: after an idle stop, settlements and job ends do not start a turn until you send a
  message, answer or resume. An empty answer to a non-blocking inbox item dismisses it. A root session
  whose budget ran out gets a fresh budget when you start its next turn.
- The re-weave trigger uses the prompt size the server reported. A model reply with a malformed tool
  call is not run and is nudged; repeated malformed or cut replies park the lead.
- Text from tool results, files and agent reports is neutralised where it could pass for a harness
  block. Reports show the agent's own words with every line prefixed `> `.
- The quotes of `finish` must come from observations (a command's output or a file read), as evidence
  does: a quote of a ledger, a log search or an agent's report is refused.
- A quote that is part of a line must start and end on word boundaries (the model is told when it
  occurs only inside a longer word or number) and is recorded as its whole line, or as a window of at
  most 300 characters around it on a longer line.
- `verdict` is refused while the verifier has a running job.
- The received arguments in the note about a malformed call are quoted line by line.

### Logs, journal and storage

- The mission journal has a sealed `journal.head` beside it; a torn last line is repaired by the next
  append instead of counting as tampering, and truncation, deletion and substitution are detected while
  the head is in place (`SECURITY.md` lists what it cannot detect).
- Session logs are locked while open for writing, and an unreadable line with a sound chain header is
  kept as an opaque record instead of being treated as damage.
- A fork checks every line it copies from its parent's log and is refused, naming the record, when
  that part of the log is not a sound chain; before, the child took the damage with it and lost its
  own records at its next open.
- The blob store removes stale temporary files, repairs missing indexes, and is cleaned only by
  `loom gc`.
- The loom home and every directory the harness creates under it are created 0700 and every file the harness
  writes there 0600 (the daemon log included, which `loom service install` now creates before launchd opens it),
  also when the home already existed; files that commands write in a session's temp directory keep the user's
  umask. The daemon tightens the home, `keys/`, `sessions/`, `missions/`, `blobs/` and `logs/` at start; files
  from earlier versions keep their mode but other accounts can no longer open them. `chmod -R go-rwx ~/.loom`
  tightens them too.
- The ledger has three new records (nothing writes them yet): a goal-met claim (open once a goal is set,
  then `supported` or `refuted` on execution evidence, never withdrawn), an operator-only release
  ("goal not established") and operator-only scope grants (`authorized hosts: …`); the brief and the
  Markdown view show them. Older journals fold unchanged.
- A finish verifier's `meta.json` has a new optional `gate` field (its assignment); files without it
  load as before.
- Reading lines of a stored output reads only the line-index entries it needs, so a page costs the
  same however many lines the output has.

### Packs and documents

- The `vr` chat role no longer lists `note`, which a session without a ledger cannot use.
- The shipped prompts no longer promise hooks, no longer let a scout start agents, and say that the
  judge delivers a scope check through `verdict`. `vr` documents its network policy.
- `README.md`, `docs/RUN.md`, `docs/config.example.toml` and `docs/IMPLEMENTING.md` were rewritten to
  match the code. `SECURITY.md` was added. `docs/REVIEW-COVERAGE.md` is a dated record.

### Durable security state

- Add evidence-linked typed assets, secret handles, footholds, mandatory coverage dispositions,
  condition revisits, bounded crash attempts, and independently judged hypotheses to the sealed ledger.
- Add bounded stratified causal rules, provenance explanations, nonmutating hypothetical queries,
  downstream retraction invalidation, aliases, and expiry-aware path suggestions.
- Add opt-in `security_record`, `security_query`, and observed-blob `security_ingest` tools with atomic
  scanner imports. Existing journal op shapes and old ledger snapshots remain readable; older builds
  refuse append after the new `security` op. See `docs/SECURITY_STATE.md` for limits and supported formats.
