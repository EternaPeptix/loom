# Changelog

## Unreleased

### Morale: keeping a model on a hard task

- The step block gains `Where the work stands:`, read from the ledger alone: results established, what is
  ruled out with evidence, what is only set aside (a dead end is not a refutation), open leads, security
  surfaces closed and untested, and the attempts run in this session. Security records appear by id only.
  New module `loom-agent::frontier` (`frontier`, `attempts_run`, `render`, `directions`).
- `claim_update` to `supported` adds one line, `Established: {id}. Results established in this mission so
  far: {n} ({ids}).`, so a banked result stays in view.

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

### Domain packs and evaluation

- Added opt-in CTF and Redteam packs with specialist tool surfaces (CTF roles at most 25 per role,
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
- Reasoning-only replies receive a specific bounded nudge. Similar-outcome HUD warnings and optional
  flag-pattern alerts are advisory and do not verify success. See `docs/RUNTIME-CONTROLS.md`.
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
