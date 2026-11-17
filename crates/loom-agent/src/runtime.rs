//! The runtime: owns every session of this loom home, starts and restores them, connects parents and
//! children, and is the one thing the daemon talks to.
//!
//! CONTRACT (public signatures and types are fixed;
//! private fields, types and helpers are yours). `docs/DESIGN.md` §3, §8, §9 and §12 are the base
//! text; where this file is more specific, this file wins. Every text shown to the model comes from
//! `crate::texts`, `loom_core::weave` or the sentences quoted in this contract. Errors returned by
//! the public methods are sentences for the operator; errors returned through
//! [`Orchestrator`](crate::rtools::Orchestrator) are sentences for the model.
//!
//! ## Files (under `paths.session_dir(id)`)
//! - `log.jsonl` — the session's log; written only by its [`Session`](crate::session::Session).
//! - `meta.json` — [`SessionMeta`], written when the session is created (for a verifier the finish
//!   gate starts, with `gate`, before its first turn); rewritten only by [`Runtime::archive`]. Writes
//!   are atomic (temporary file in the same directory, then rename).
//! - `status.json` — the latest [`Status`](crate::session::Status), rewritten atomically whenever
//!   the session publishes one.
//! - `net.jsonl` — one [`NetEntry`] per line, hash-chained (`prev`): every decision the egress proxy
//!   made for the session.
//! - `settlement.json` — a child's [`Settlement`](crate::rtools::Settlement), written atomically
//!   when its task ends with one. Read only when a delivery lost to a restart is recovered (see
//!   *Start*), so that the parent gets the whole report. A child that ended without the file (a
//!   crash between its `session_end` and the write, or a log from before the file existed) is
//!   recovered from its log instead, with the first line of its report.
//! - `tmp/` (`paths.session_tmp`) — the session's scratch directory, emptied once the session can run no
//!   command again (see *When a session's task ends*, `archive` and *Start*); `jobs/` — its job table's files.
//! - `queued/` — operator rules, approvals and withdrawals handed to the session and not recorded
//!   yet, one JSON file each (`session::queue_input`); the session deletes each once recorded.
//!
//! A session directory without a readable `meta.json` is ignored (`tracing::warn!`).
//!
//! ## Active sessions
//! A session is *active* when a task is driving it (`Session::run`). The runtime keeps, per active
//! session: the sender of its inputs, its `Control`, its `Arc<Shared>`, its job table, its latest
//! status, and for a child its settlement once there is one. Sessions that are not active are known
//! from `meta.json`, `status.json` and any durable child result in their logs.
//!
//! *Activating* a session = building its `Deps` (below), `Session::open`, spawning the task.
//! Activating a child first activates its parent. Activation happens:
//! - at start, for every session that is not archived and whose `status.json` says `phase ==
//!   Running`, or `last_end == Waiting`, or `open_inbox > 0`, or `last_end == Yielded` while its log
//!   holds a `job_registered` with no `job_settled`, or a job end it was told of that no turn has
//!   followed (`session::has_job_news`: the job's end would have started a turn; the log is read only
//!   when the session has a `jobs/` directory), and for every child that
//!   has not ended, whatever it was doing (parents before children — session ids sort by creation
//!   time);
//! - on demand, by `send_message`, `resume`, `reweave`, `answer`, and when a settlement has to be
//!   delivered to a parent that is not active.
//!
//! A session whose `status.json` says `phase == Ended`, or whose durable `child_completed` record
//! says it ended, is never activated. Neither is a session of
//! a pack with `requires_restricted_network` while `config.network.mode` is `Open`: its prompt
//! says the network is restricted. Activation (and `create_session`) is refused with `The pack
//! "{pack}" needs a restricted network, but the network mode is open, so its sessions are not run.
//! Set [network] mode = "allowlist" (or "deny_all") in the config and restart the daemon.`
//!
//! When a session's task ends:
//! - `End::Settled(s)`: the session becomes inactive; its proxy grant is revoked; the settlement is
//!   kept (for `join`, `children`) — see *Children*.
//! - `End::Closed`: inactive. A child ends this way only at a shutdown (it is cut, and resumed by the
//!   next start) or when its log had ended already: a child whose inputs close otherwise settles
//!   itself (`Stopped`), so that every child that stops taking part has exactly one settlement.
//! - `End::Fatal(e)`: inactive; `tracing::error!`; a [`BusEvent::Error`]; the operator is notified
//!   (kind `error`). A child is then settled on its behalf so that nothing waits for it forever:
//!   `Settlement{outcome: Failed, report: texts::failed_report(&e, ""), full: None, payload: Null,
//!   steps and usage from the last status (usage: default)}`, and its status becomes `Ended` /
//!   `Failed` (published and written), so that a later start does not run it again beside the
//!   settlement its parent was given.
//!
//! A child that settled or failed, a session an archive closed and one whose log had ended can run no
//! command again: its scratch directory (`tmp/`) is emptied, off the async workers (a command may have
//! left many files there). A child's is emptied after its settlement has been recorded and delivered; a
//! session that ended `Closed` has its emptied before its task gives up its place, so that an unarchive
//! cannot start it again while the removal runs. A session that ended just before a crash, before its task
//! got this far, keeps its scratch directory until it is archived.
//!
//! A panic in a session's task is caught and ends the session as `End::Fatal(texts::task_failed(
//! <the panic's message>, <is a child>))`.
//!
//! ## Set-up of one session (`Deps`)
//! - `paths`, `agents`, `context`, `admit` from the config (`agents.stall_steps` is 0 for a role
//!   with none of the tools `note`, `claim`, `evidence`: the stall note asks for a ledger record,
//!   and with the journal every child would otherwise be given it); `client` and `limiter` of the session's
//!   model profile (one `ModelClient` and one `Limiter::new(profile.max_concurrent)` per profile,
//!   made at start); `priority` `Lead` for a root session, `Child` for a child;
//!   `context_window` from `meta`.
//! - `shared`: `Shared::new(id, Some(mission), parent, role, journal, paths.session_log(id),
//!   agents, orchestrator)`. `journal` is `Some(Journal::new(paths.journal(mission), key))` when the
//!   root session's role has `Termination::Explicit`, and for every child. Children read current
//!   mission state independently of their brief; runtime rules limit child writes by role and claim
//!   ownership. `key` = `journal::load_or_create_key(paths.journal_key())`, read once at start.
//!   The orchestrator handed to `Shared` must not keep the runtime alive in a reference cycle
//!   (hold a `Weak`, and answer "The harness is shutting down." when it is gone).
//! - `ctx`: `ToolCtx{session, call_id: empty, workspace (canonical), tmp_dir: paths.session_tmp(id)
//!   (created, canonical), blobs: BlobStore::open(paths.blobs_dir()), outputs: the outputs of
//!   `meta.mission` (see *Outputs of a mission*), cfg: tools config, sandbox,
//!   env, files: new FileTracker, jobs: JobTable::new(<session dir>/jobs, blobs, sender,
//!   tools.max_output_bytes), cancel: new token}`.
//!   - The proxy grant is made first (`proxy.grant(id, policy)`; a failure to open the session's
//!     listener fails the set-up with `The egress proxy cannot open a port for this session: {error}`).
//!   - `sandbox`: `Sandbox::new(&cfg, workspace, tmp_dir, paths.home, Some(grant.port))` (the session's
//!     own proxy listener, never the shared `proxy.port()`, so a command can connect to no other
//!     session's listener and other sessions' credentials are of no use to it; `None` under bubblewrap;
//!     the sandbox `child_copy` builds for commands run in an agent's copy uses the port of the session
//!     whose environment those commands get, `proxy.session_port(..)`, and `None` when it holds no grant), then
//!     `.with_jobs_dir(<session dir>/jobs)` (commands' own output files are there: their metadata can be read,
//!     not their content; `child_copy` uses the parent's) and `.with_identity(<session id>)` (`child_copy`: the
//!     parent's, whose environment and commands they are; the census finds a session's processes, `crate::census`),
//!     with the config's `SandboxCfg`; for a role with
//!     `read_only`, `extra_writable` is retained as internal
//!     replay-untrusted metadata before its grants are emptied, and the
//!     workspace is added to `protected_paths`; every model profile's `api_key_env` name is added to
//!     `secret_env`, so commands never see it. The fetch-service deny and the `mach-lookup` default-deny are in
//!     every sandbox it makes (sessions, agents' copies, judges), in every `network.mode`, unless the
//!     configuration says `sandbox.allow_fetch_services` (`docs/MONITOR.md` §2.2, E2); `daemon_port` is whatever
//!     the caller set (the daemon's port; `None` without one).
//!   - `env`: the session's proxy grant (`proxy.grant(id, policy)`), `env()`. The policy is
//!     `Policy::with_hosts(&config.network, granted)`, `granted` being the hosts the operator authorized
//!     for the mission (`grant_scope`): the ledger's `granted_hosts()` and those granted since the daemon
//!     started and not yet recorded, so that a restored session keeps its authorizations.
//!     The policy then has the infrastructure deny (E1): `with_infrastructure(infra_spec(&config))`: the
//!     daemon's port (`sandbox.daemon_port`), the `host:port` of every model profile's `base_url`, the box's
//!     `ssh_host` when the box is enabled, and `network.infrastructure`; `Runtime::start` parses them once
//!     and refuses to start on an entry it cannot read (`The network configuration cannot be used: …`). The
//!     spec also carries what `crate::infra` resolved (the box's Docker host from `ssh -G`, the addresses of
//!     every named entry, this machine's own addresses), at start and every `RESOLVE_EVERY`; a `box.ssh_host`
//!     of the form `user@host` or `ssh://user@host:2222` is reduced to its host, and one whose host the policy
//!     cannot read is left out with a warning. `Runtime::start` sets `config.sandbox.infra_ports` (the loopback
//!     ports of model endpoints and `network.infrastructure`, `crate::infra::loopback_ports`).
//!     Hosts the operator revoked in this run (`revoke_scope`) are left out of `granted_hosts`.
//!     Every session gets a grant, also under `deny_all` (in-process fetches go through the proxy
//!     too, so the policy is what refuses them).
//! - `job_events`: the receiver of the job table's channel; `sink`: the runtime; `control`: new.
//!
//! ## Creating a root session (`create_session`)
//! 1. `workspace` must be an existing directory (canonicalised). Role: `packs.role(pack, role)`.
//!    Profile: `config.profile(model)`.
//! 2. Model facts: `client.discover()` once per profile (the first success with a window is
//!    remembered; a discovery that finds no window refuses the creation and is not remembered). On
//!    `Unavailable`, carry on with the profile's `model` and `context_window` (logged as coming from
//!    the configuration); without a configured window the creation is refused. On
//!    `Rejected`/`Config`: return its message.
//! 3. New `SessionId`, new `MissionId`. `title`: the given one, else the first line of `message` cut
//!    to 80 characters, else `untitled`.
//!    `NewSession.prior: Vec<MissionId>` (serde default) names the earlier missions the operator chose
//!    for this one to recall (`crate::prior`); `SessionMeta.prior: Vec<MissionId>` (serde default, not
//!    written when empty; always empty for a child) keeps what was accepted. Each id
//!    is trimmed; blanks dropped; repeats dropped (first kept); more than `prior::MAX_PRIOR` refused
//!    (`Name at most {MAX_PRIOR} earlier missions to recall; {n} were named.`); every id must be the
//!    mission of a known session (`There is no mission {id} to recall.`). Archived missions may be
//!    named. They are read before the session is made (`prior::read` on a blocking thread, the lead's
//!    meta giving the title) and `meta.prior` keeps them in the given order.
//! 4. `SessionStart{session, mission, parent: None, workspace, pack, role, termination,
//!    model: ModelRef{profile, model, context_window}, reasoning_replay (profile),
//!    system_prompt: pack::system_prompt(role, &pack.preamble, &PromptEnv{workspace,
//!    platform: "{OS} ({ARCH})" from std::env::consts, sandbox: sandbox.describe(),
//!    network: texts::network_sentence(mode, allow, deny, allow_private)}), tools: empty,
//!    budget, unattended (default: the role's termination is `Explicit`), title}`.
//! 5. `Session::create(deps, start, None)`; with a `prior`, `session.recall(prior::brief(&recalled))`
//!    (one `harness_note` of kind `Info`, before any turn and so before the first model request; written
//!    once, never again after a restart); write `meta.json`, spawn the task, publish
//!    [`BusEvent::Session`]. With a `message`: `send_message`. A failure of any of these steps forgets
//!    the session, as the earlier ones do.
//!
//! ## Children (`Orchestrator`)
//! `spawn(parent, req)`:
//! - `parent` must be an active root session: otherwise `Only the lead session of a mission can
//!   start agents.`
//! - the role must exist in the parent's pack and be in the parent role's `may_spawn`: otherwise
//!   `` `{role}` is not a role this session can start. Roles it can start: {list}. ``
//! - at most `agents.max_children` unsettled children per parent, not counting the finish gate's
//!   verifiers (as in `children`): otherwise `{n} agents are already running, which is the most
//!   allowed at once. Wait for one to finish (`wait`) or stop one (`agent_stop`), then start this
//!   one.`
//! - role `model` selects a named profile; fresh children otherwise inherit. `alloy_models` rotates
//!   fresh siblings, and `escalation_model` is selected for subsequent children of a role after a
//!   failed/budget-exhausted result or a `hand_off` that asked for a `stronger_model`. This never mutates a running session or promises provider cache hits.
//!   A fork selecting a different profile is refused. Distinct verifier profile checks compare names,
//!   not model families. Discovery and limiter selection follow the chosen profile.
//! - a request with `harness: true` (the finish gate's verifier) is exempt from both of the last two rules.
//! - the actual child role's `requires_credential` requires explicit matching asset/credential IDs from
//!   the parent's mission. Missing, unattested, wrong-asset and expired observations refuse dispatch
//!   before allocation, including harness requests. Canonical IDs are persisted in the brief context.
//! - role `max_steps` caps the child budget; omitted/zero caller budgets cannot bypass a configured cap.
//! - join/message/stop resolve exact IDs first, then `last` or an unambiguous prefix of at least four
//!   characters within this parent's children only. Ambiguity never picks an arbitrary child.
//! - `SpawnMode::Fork`: the parent's status must have a `fork_point`, and every tool of the child
//!   role must be among the parent role's tools (`hand_off` aside: a forked agent is not offered it); otherwise `A `{role}` agent cannot be forked from
//!   this session: it needs tools this session does not have ({list}). Start it with mode `fresh`
//!   and put what it needs to know in the assignment.` The child is
//!   `Session::fork(deps, &paths.session_log(parent), fork_point, Forked{session, parent, upto_seq:
//!   fork_point, role, termination, budget, brief, contract: texts::fork_contract(role name, role
//!   prompt, role tools), allowed_tools: Some(role tools), title})`.
//! - `SpawnMode::Fresh`: `Session::create(deps, SessionStart{… as for a root, with the child's
//!   role and system prompt, parent: Some(parent), the parent's mission, workspace, model and
//!   `unattended`, budget: req.budget, title: req.title}, Some((parent,
//!   weave::render_brief(&req.brief))))`.
//! - `Workspace::Copy` (see *Copies* below): refused for a role that only reads; otherwise the copy
//!   is made after the child has its place among the known sessions (so it counts against
//!   `max_children` while the files are copied) and before its session exists, and a failure of any
//!   later step removes it again.
//! - Then: `meta.json` (`mode`, `awaited`, `copy_of`, and `gate: Some(req.brief)` for a `harness`
//!   request),
//!   spawn the task (a child starts its first turn by itself), publish `BusEvent::Session`, and queue
//!   in the parent's log
//!   `parent_shared.emit(Author::Harness, Event::ChildSpawned(ChildSpawned{child, role, mode, brief,
//!   budget, call_id}))`. Return the child's id.
//!
//! ### Copies
//! A child spawned with `Workspace::Copy` works in its own copy of its parent's workspace, at
//! `paths.agent_copy(mission, child)` — under `paths.copies_dir()`, which is beside the loom home and
//! not in it, because nothing in the home is writable to a session's commands. Its `meta.json` has
//! `workspace` = the copy and `copy_of` = the parent's workspace, so everything built from the meta
//! (tools, sandbox, system prompt, a restart) uses the copy without knowing about copies.
//! - Made by `workcopy::make` on a blocking thread, within `agents.copy_max_files` and (where
//!   files are not cloned) `agents.copy_max_mb`; its refusals are the spawn's error. What the copy
//!   was made from (`workcopy::Manifest`) is written to `sessions/<child>/copy.json`.
//! - The assignment's context begins with `texts::copy_header`: where the copy is (as `pwd` prints
//!   it), that nothing changed there reaches the original, for a fork that earlier paths name the
//!   original, and what was left out (a Git pointer to a repository outside the workspace).
//! - Sandbox (`with_copies`): the child may not write to the workspace its copy was made from
//!   (`protected_paths`), and the copies directory is an untrusted origin of every session's replays
//!   (`replay_untrusted_paths`), as any place an agent can write is. In Bubblewrap mode the copies
//!   directory is created when a session is built, since only an existing directory can be hidden.
//! - `child_copy(parent, child)` (the id resolved as for `join`): `None` for a child that shares the
//!   workspace; otherwise the canonical copy directory (an error when it is gone), the manifest,
//!   whether the child is unsettled, the commands the child ran to their end with `bash`, from its
//!   own log records (`runs_of`: an own `bash` result with `META_EXIT_CODE` or `META_SIGNAL`, with the
//!   time its call was recorded), and a sandbox for commands the parent has the harness run there:
//!   the child's rules, with the copy and the parent's scratch directory writable.
//! - Archiving a mission removes its directory of copies once the family's tasks have ended (an
//!   agent archived alone: its own copy). What was not adopted is gone; an agent that had not settled
//!   cannot be opened after an unarchive and is settled `failed`.
//!
//! `join(parent, child, cancel)`: `child` must be a child of `parent` (`{child} is not an agent this
//! session started.`) spawned with `awaited` (`{child} was started in the background; its report
//! arrives by itself.`). Waits for the settlement; `cancel` first → `Err("Interrupted before the
//! agent finished.")`, and the settlement counts as taken (the call's result says what happened) —
//! except during shutdown, when the call does not return at all (see *Shutdown*). The first
//! successful join of a child queues
//! `parent_shared.emit(Author::Agent(child), Event::ChildSettled(ChildSettled{child, outcome,
//! report, full, usage, steps, inline: true}))`; later joins return the same settlement and queue
//! nothing.
//!
//! When a child settles and it was not `awaited`, or it was restored after a restart (nobody can be
//! waiting for it any more): send `Input::ChildSettled(settlement)` to its parent, activating the
//! parent if necessary. Each settlement is delivered once; one that cannot be delivered (the lead is
//! archived) is delivered when the lead is unarchived or by the next start. The child's synced
//! `child_completed` is the durable outbox. Recovery restores every typed settlement field from it,
//! even when terminal/status writes were cut, and parent receipts acknowledge delivery once per
//! child. A legacy terminal log without this payload recovers as explicitly incomplete rather than
//! fabricating a successful answer from its summary. A verifier the finish
//! gate started (`harness: true`) is never delivered: its verdict belongs to the `finish` that joins it.
//! A `harness` spawn whose parent has a verifier of the same role and assignment that a shutdown cut
//! (no `join` took it, and it has a task and has not ended, or it ended with a verdict) gets that
//! verifier's id instead of a new one (a `finish` that a restart cut, made again); the parent's other
//! verifiers that no `join` took are given up, and stopped if they have not ended.
//!
//! `stop_child(parent, child)`: not its child → the sentence above; already settled → `{child} has
//! already finished ({outcome word}).`; else `control.stop_turn()` and `Input::Stop`, then wait for
//! it to settle, at most `tools.kill_grace_s` + [`STOP_SETTLE_WAIT`] (an idle child settles at once).
//! `stop_children(parent)`: the same for every unsettled child, without errors.
//! `message_child(parent, child, text)`: same two refusals; else `Input::AgentMessage{from: parent,
//! text}`.
//! `children(parent)`: every child of `parent` in creation order except the finish gate's verifiers:
//! `ChildInfo{id, role, title, step: latest status, running: not settled}`.
//!
//! `poll(session, question, options, k, cancel)`: the session's status must have a `fork_point`
//! (`Nothing has been sent to the model in this session yet, so there is nothing to vote on.`).
//! Read the session's log (`log::read_records`), keep records with `seq <= fork_point`, `weave`
//! them. Send `k` requests concurrently, each `ChatRequest{messages: stable messages + one user
//! message texts::vote_prompt(question, options), tools: the weave's, tool_choice: Auto,
//! max_tokens: Some(VOTE_MAX_TOKENS), seed: Some(i) for i in 1..=k, extra: empty}` through the
//! profile's limiter at `Priority::Child`. Each reply's text goes through `texts::parse_vote(text,
//! options.len())`; a failed request is `Vote{option: None, reason: texts::sentence(&error)}`.
//! `cancel` → `Err("Interrupted before the votes were in.")`. Votes are returned in seed order.
//!
//! `producer(mission, blob)`: the first record that stores `blob` among the sessions of the mission (a
//! session's own records only — a fork's copied records belong to its parent): a `tool_result` with
//! `output.id == blob`; a successful `read` result whose `META_OF_BLOB` is `blob` (the file text it
//! stored); a `job_settled` whose output is `blob`, or a `job_matched` whose stored part is, credited
//! to the call named by the `job_registered` of that job (`bash`, class `Exec`). Views of runtime tools
//! register nothing.
//! `Producer{session, call_id, tool: name, class, grade}`, where `grade` is `EvidenceGrade::of_tool_result(name,
//! class, meta)` of that `tool_result` (so `dep_scan`, `bin_decompile` and `bin_xrefs` give `Analysis`, the CVE
//! and advisory tools and a reference-host `web_fetch` give `Reference`, any other `Exec` result `Run`, any
//! other result `Read`), and a job's output is `Run` (the `bash` call that started it). A log written
//! before the grade key existed grades by class, as before, except the results of those six tools, which get
//! the grade the tools state now: an output a scan stored before an upgrade is not a run when it is cited
//! after it. Kept as an in-memory index fed by
//! every record that passes through the sink; on a miss for a mission whose logs have not been
//! scanned since start, scan the logs of all its sessions once, then answer.
//!
//! ## Outputs of a mission
//! The blob store is shared by every mission, so a session's tools open stored outputs only through
//! `ToolCtx::outputs` (`loom_tools::outputs`). The runtime's `OutputScope` for a session holds `blob`
//! when some record of a session of the session's mission names `blob` as an output (a session's own
//! records; a fork's copied records are its parent's, of the same mission):
//! - every blob `producer` would find (see above);
//! - of a `tool_result` that is not `out_read` or `out_grep`: `output`, `meta[META_OF_BLOB]`,
//!   `meta[META_RAW_BLOB]`, and every string in `meta[META_ALSO_STORED]` (every stored blob a result's text
//!   names is one of these: `attempt` names the complete output of each check in `META_ALSO_STORED`);
//! - the `output` of every `job_settled` and `job_matched`;
//! - the `full` of every `child_settled` and `child_completed`.
//!
//! The ids that are not already in the producer index are kept in a second in-memory index keyed by
//! (mission, blob), fed by the sink as the producer index is, and filled by the same once-per-mission
//! scan (one scan fills both; `scanned` is shared). So `holds` is a map lookup once the mission has been
//! scanned, and a miss before that scans the mission's logs once; `OutputScope::ready` (called by `open` before
//! it lists the store) does that scan, so the first use takes the same time whatever the handle names. Scans
//! are serialized (a second caller waits, then finds the mission scanned), and a scan that fails to run
//! (its blocking task is lost) does not mark the mission scanned. The second index leaves out what the
//! producer index already holds (a result's `output`, the text of a successful `read`). A view (`out_read`, `out_grep`) names
//! nothing new, so reading an output never makes another one readable. The scope holds a `Weak` of the
//! runtime (as the orchestrator does) and answers `false` once the runtime is gone. What the operator reads
//! (`loom out`, the API) is not scoped.
//!
//! ## The sink
//! The runtime is the `Sink` of every session.
//! - `record`: feed the producer index and the inbox index (`inbox_opened` adds an
//!   [`InboxEntry`], `inbox_resolved` removes it); an `inbox_opened` notifies the operator; publish
//!   [`BusEvent::Record`].
//! - `status`: remember it, write `status.json`, publish [`BusEvent::Status`].
//! - `delta`: publish [`BusEvent::Delta`].
//!
//! Activating a session adds its open inbox items (from its records) to the inbox index.
//! Publishing never blocks and never fails (`broadcast::Sender::send`, result ignored). The bus
//! holds [`BUS_CAPACITY`] events.
//!
//! ## Network decisions
//! One `loom_net::Proxy` for the runtime: its shared listener on `config.daemon.proxy_port` serves the
//! in-process reference clients, and each session's grant has a listener of its own, closed when the
//! grant is revoked. Every decision it reports is
//! appended to the session's `net.jsonl` and published as [`BusEvent::Net`]. Decisions that name no
//! session are appended to `logs/net-unattributed.jsonl`.
//! The floor's controls are put into it at start (`crate::floor::Floor::install`, E4): the synchronous veto, the
//! canary hook and the lab-listener check; `Runtime::floor()` is the handle (canary users and hosts, the events).
//! `Runtime::cut_mission(mission)` ends the open tunnels and forwards of every session of a mission
//! (`Proxy::cut_sessions`) and returns how many. The infrastructure policy the veto asks is rebuilt whenever the
//! daemon resolves its infrastructure names again (every `infra::RESOLVE_EVERY`). A floor event of severity S4
//! (a decoy credential or host) or S3 (an infrastructure attempt, a squatted lab port) raises a notification of
//! kind `floor` (`LOOM_KIND=floor`, `LOOM_SESSION` the attributed session or empty), at most once per label (S4) or
//! per kind and session (S3) every 10 minutes. Every floor event is also appended, one JSON line, to
//! `logs/floor.jsonl` (synced before the hook that raised it answers), where the monitor reads it by cursor. The
//! lab-listener check is given the connecting session, the address and the local end of the connection, and leaves
//! out the processes of the session's own mission; the proxy is told this machine's interface addresses
//! (`Proxy::set_local_addrs`, refreshed with the infrastructure) so that the check also covers them.
//!
//! ## Box counters
//! Every `BOX_COUNTERS_EVERY` (60 s, not under test) the runtime reads the rule counters of each mission box it has a
//! handle for (`MissionBox::poll_counters`), warns when a DROP rule counted, and appends one line per mission that
//! moved to `logs/box-counters.jsonl`: `{"ts_ms", "mission", "chain", "rules": [{"rule", "packets", "bytes",
//! "drop"}]}` with the deltas since the last poll. A box that cannot be read is logged once until it can be again.
//! `Runtime::box_counters_now()` polls and records now and returns the deltas.
//!
//! ## Notifying the operator
//! For every `inbox_opened` and every `End::Fatal`. `kind` is the inbox kind in snake case
//! (`question`, `blocker`, `parked`, `finished`, `approval`) or `error`.
//! - `config.notify.command` not empty: run it (no shell) with the environment extended by
//!   `LOOM_KIND`, `LOOM_SESSION`, `LOOM_TITLE` (session title) and `LOOM_TEXT` (the item's text cut
//!   to 500 characters); stdin closed; killed after 30 s; failure is a `tracing::warn!`.
//! - empty, on macOS: `/usr/bin/osascript -e 'on run argv' -e 'display notification (item 2 of
//!   argv) with title (item 1 of argv)' -e 'end run' "loom: {kind} — {title}" "{text cut to 200}"`
//!   (the texts are arguments, never part of the script). Elsewhere: nothing, and `start` logs one warning
//!   saying so and how to set `[notify] command`.
//! - `config.notify.repeat_minutes > 0`: while a blocking item stays open, notify again every that
//!   many minutes.
//! - The text of an item opened by a tool call (a question, blocker or finish the model wrote)
//!   starts with `[From the agent, unverified] `. In an item the harness opened itself, the paragraph
//!   that quotes the ledger (`Still open:`, written by the model) starts with that label; the rest is
//!   unchanged. The title of a child session was written by the model: it starts with `unverified: `
//!   in the notification title (`LOOM_TITLE` too).
//! - Low disk: when the volume of the loom home turns low ([`disk_is_low`]: under `LOW_DISK_BYTES` or
//!   `LOW_DISK_PERCENT` free; checked once a minute, off the async workers) one notification of kind
//!   `disk` is raised, and no other until the disk has recovered and turned low again.
//! - Egress: when the sandbox self-probe (`crate::egress`) turns egress unbounded one notification of kind `egress` is
//!   raised, and no other until it was bounded again; a problem the probe finds (a leak, a probe that cannot run,
//!   the resolver's socket) is told once too, even while `sandbox.allow_fetch_services` already holds egress
//!   unbounded, and again only after it cleared. `LOOM_KIND` is `egress` and `LOOM_SESSION` is empty.
//! - Census (`crate::census`, `docs/MONITOR.md` §2.2, E3): every 60 s (not under test) the daemon finds the
//!   processes of its non-archived sessions by sandbox identity, keeps the view (`census()`; `census_now()` takes
//!   one), and logs once a warning for each process an ended (finished or stopped) session left running, however long
//!   the process had been running before. `census_kill(session)` stops what the census finds for one session and its
//!   known process groups (`There is no session …` for an id that is not known; an error when the process table could
//!   not be read). Nothing is stopped by the periodic census. A census that runs without sandbox identity although
//!   commands are confined is logged and notified once (kind `census`). Archiving stops, once the family's tasks
//!   have ended, what the sessions left running by sandbox identity (an archived session is not in the census).
//! - At start, every restored open blocking item is notified once (`Still waiting: {text}`) and its
//!   repeat notice is armed as for a live one.
//!
//! ## Operator actions
//! - `send_message(id, text)`: root sessions only (`Messages go to the lead session of a mission;
//!   {id} is one of its agents.`); empty text refused; ended session refused; activate;
//!   `Input::User`; then its children that a restart cut are resumed as `resume` does (the lead's
//!   turn starts with `AFTER_RESTART`, which says so).
//! - `add_rule(id, text)`, `approve(id, text, scope)`, `withdraw_rule(id, rule_id, reason)`: any
//!   session; the input goes to the lead (root) session of its mission, which owns the ledger.
//!   `text`, `scope`, `rule_id` and `reason` are trimmed. Blank `text` or `rule_id` is refused
//!   (`Write the rule to set.`, `Write what is approved.`, `Name the rule to withdraw (its id, such
//!   as k1).`), an archived lead as for `send_message`. The mission keeps a ledger when its lead's
//!   role ends explicitly. `withdraw_rule` reads the mission's journal first, because the session
//!   drops a withdrawal its ledger refuses: `There is no rule {rule_id} to withdraw: this mission
//!   keeps no ledger, so its rules have no ids. Tell the lead in a message that the rule no longer
//!   applies.`, `There is no rule {rule_id} in this mission; its rules are {ids in force}.` (none
//!   in force: `…; it has no rules in force.`), `Rule {rule_id} is already withdrawn.` Then
//!   activate the lead; `Input::Constraint`, `Input::Approval` or `Input::Withdraw`. When the
//!   mission keeps a ledger, a blank `scope` is sent as `only what the approval says` and a blank
//!   `reason` as `no reason given` (the ledger refuses blank ones); without a ledger a blank scope
//!   stays blank and the note words it itself. The input is sent as `session::queue_input` makes it,
//!   kept on disk until the lead has recorded it (deleted again when the lead refuses input). The
//!   lead records the input at once when idle and at the next step of a running turn (a lead started
//!   after a daemon stop, first): a ledger entry when the mission keeps a ledger (the lead's
//!   state block then lists it), and a protected note in the lead's window. No turn is started.
//!   The answer is a [`RuleReceipt`]: the lead, whether it was in a turn (`queued`), whether the
//!   mission keeps a ledger, and the stock text when one was used.
//! - `grant_scope` refuses a host that infrastructure refuses (`Policy::infrastructure_refusal`: a literal
//!   address of a model endpoint, the box's Docker host, cloud metadata, DevTools or Docker API ports on this
//!   machine; `The host `{h}` is infrastructure …`) and grants nothing of the list; it reaches every known session
//!   of the mission, not only the active ones, and bumps the mission's `scope_gen`.
//! - `revoke_scope(mission, host, reason)`: the operator withdraws one granted host (exactly as granted, case
//!   ignored). Blank host or reason refused with a sentence saying what to write; a mission without a lead
//!   or a host that is not granted refused (the sentence lists the granted hosts, and names the wildcard grant
//!   that covers the host when there is one: revoke that). In order: the revoke is
//!   appended to the mission's journal as `ScopeRevoke` when the ledger lists the host as granted (a mission
//!   without a ledger skips this; a grant the lead has not recorded yet, still queued on disk, is revoked
//!   without a record and the receipt says `recorded: false`; revoking the host again once the lead has recorded
//!   the grant records it; any journal failure refuses the call and changes nothing); the host leaves the
//!   in-memory grants and the mission's revoked hosts (`<mission dir>/scope_revoked.json`, written durably, read
//!   at start; `scope_revoked` in memory) keep it out of `granted_hosts` until granted again (`grant_scope` of it
//!   clears that) — also after a restart, whatever the ledger says of a grant recorded later. Every session of
//!   the mission that is known, started or being started, gets its rebuilt policy through `Proxy::set_policy`,
//!   which refuses the revoked host whatever else allows it (`Policy::with_revoked`: `deny revoked {host}`: a
//!   wildcard grant, `network.allow` and `mode open` do not reach it), and `Proxy::cut_hosts` ends its open
//!   connections to the host; a session that is built while this runs derives its policy again when the
//!   mission's grants changed meanwhile (`scope_gen`); the box rules are applied again; a running
//!   lead gets `Input::ScopeRevoked` (a protected note, no turn). Receipt: [`ScopeRevokeReceipt`]. A policy
//!   that cannot be rebuilt for a session is an error naming it, after everything else was done; a revoke
//!   that is not recorded and could not be saved says that a restart undoes it.
//! - `stop(id)`: any session. Active: `control.stop_turn()` and `Input::Stop`. Not active: nothing.
//! - `resume(id)`: root only; activate; `Input::Resume` to it and to each of its unsettled children
//!   that a restart left idle and that have not been resumed since (activating them): each gets one
//!   `Resume` for the restart, however many operator actions follow before its turn starts. Only a
//!   restart leaves a child idle that way: a child that is stopped settles. Unsettled children that
//!   have no task (the lead could not be opened at start) are first restored as an unarchive does,
//!   and what children ended with while the lead could not take it is delivered.
//! - `reweave(id)`: activate; `Input::Reweave`.
//! - `answer(item_id, answer)`: the item must be open (`There is no open inbox item {item_id}.`);
//!   an empty answer to a blocking item is refused (`This item is waiting for an answer; write
//!   one.`); activate the session; `Input::Answer`; a non-empty answer also resumes the session's
//!   children that a restart cut, as `resume` does. (An empty answer to a non-blocking item
//!   dismisses it: the session resolves it without starting a turn.)
//! - `archive(id, archived)`: root only; refused while the session or one of its children is
//!   running a turn (`Stop the session before archiving it.`). Sets `archived` in the `meta.json`
//!   of the session and its children; archiving closes their inputs (the lead's task ends `Closed`,
//!   each child settles `Stopped`; a task keeps its place until it has ended). Unarchiving waits for
//!   those tasks to end (at most `tools.kill_grace_s` + `SHUTDOWN_TASK_WAIT`), delivers what the
//!   children settled with in the meantime, and restores those that had not settled as the start
//!   does (an unattended mission's go on at once). Archiving empties the scratch directories of the
//!   sessions of the family that have no task before it returns; the others' are emptied as their tasks end.
//!   Archived sessions are listed only by `sessions(true)` and are not activated at start;
//!   `send_message`/`resume` on one are refused (`This session is archived; unarchive it first.`).
//!
//! ## Start (`Runtime::start`)
//! 1. `config.check()`; create the directories; load packs (`Packs::load(paths.packs_dir())`) and
//!    check every role's tools against `Registry::builtin().names()` plus `rtools::NAMES`; journal
//!    key; blob store; clients (`ModelClient::new(name, profile, paths.model_keys_dir())`, so a profile's
//!    `api_key_file` is read here and a refusal stops the start) and limiters; proxy. The start warnings
//!    (`tracing::warn!`) include `config.key_env_warnings(paths.model_keys_dir(), …)` judged against the
//!    daemon's own environment: a key named by `api_key_env` that is in it, where commands can read it,
//!    and one that is missing. And one sentence naming, never with their values, the variables of the
//!    daemon's environment that commands are not given as secrets (`loom_tools::sandbox::withheld(name,
//!    value)`), other than `LOOM_*` ones, the profiles' `api_key_env` and the `sandbox.env_pass` names:
//!    every command can read them from the daemon's environment; start the daemon with `loom up` or
//!    `loom service install`, which pass only what it needs (a `loom daemon` run from a shell keeps it all).
//! 2. Read every session's `meta.json` and `status.json` (missing status = default idle status).
//! 3. Activate as described under *Active sessions*. A session that cannot be opened is skipped
//!    with `tracing::error!` and a `BusEvent::Error`; a child that cannot be opened while its lead
//!    can will never run again, and is settled on its behalf: `Failed`, report
//!    `texts::unopenable_report(error)`, kept in `settlement.json`, status `Ended`/`Failed` (and its
//!    scratch directory is emptied, off the async workers). Before that, off the async workers, what
//!    a previous daemon left in the `jobs/` of every other session that is not archived is cleared
//!    (`loom_tools::jobs::clear_leftovers`, logged: the output and status of a command that ended by
//!    itself stay for its session's next `open`); a session to
//!    activate is left to its job table, so one whose activation fails keeps its records for the
//!    next start.
//! 4. Restored root sessions with `meta.unattended` are told to carry on (`Input::Resume`) when
//!    - `open` cut a running turn (after `open`, the last own `turn_end` is `Stopped`, the latest
//!      own `interrupted` reason is `REASON_RESTART` or starts with `the session log was damaged`,
//!      and no own `turn_start` follows it), or
//!    - the last turn ended `Waiting` and the session has no unsettled child (other than a verifier
//!      of the finish gate): a lead waiting for its agents is woken by their reports.
//!
//!    Attended or not, a restored session is told to carry on when its last turn ended `Waiting`
//!    or `Yielded` and it was told of job ends that no turn has followed (`Session::pending_job_ends`
//!    is not 0: those `open` recorded for the previous daemon's jobs, or a shutdown for the jobs it
//!    killed; the job's end would have started a turn). A session whose last turn ended `Waiting` or
//!    `Yielded` and to which
//!    a lost delivery is recovered (below) is not told to carry on — the delivery starts its turn —
//!    but counts as carrying on for its children.
//!
//!    A restored child that has had a turn is idle (the restart cut its turn, or it was between
//!    turns) and is *held*: it is told to carry on now when it was told of job ends as above, when its
//!    mission is unattended, or when its parent carries on, and otherwise as soon as its parent is
//!    (a message, a resume or an answer to the lead, or any turn the lead starts, such as one a
//!    report starts): what the lead is told about its agents (`AFTER_RESTART`) is then what
//!    happened. A child that never had a turn starts its first one by itself. So every child of a
//!    mission that is not archived is, after this pass, running, held for its lead (an attended
//!    mission whose lead waits for the operator), or settled.
//!
//!    Children restored this way count as not `awaited` from now on.
//!
//!    A delivery lost to the restart is recovered: a child that has ended and whose parent's log
//!    holds no `child_settled` for it is delivered to the parent as `Input::ChildSettled`, from its
//!    `settlement.json` or else from its log (see *Files*) — unless it had ended and the call that
//!    started it was `awaited` and has a recorded result (which told the lead how it ended; an agent
//!    that a shutdown cut instead of stopping goes on, and is delivered), or it is a verifier of
//!    the finish gate (known from its `meta.json`'s `gate`, so also after a crash that lost the
//!    queued `child_spawned`; for an agent written before that field, from the `child_spawned` record
//!    of a `finish` call). A settlement made during this pass is left to this recovery.
//!
//! ## Shutdown (`Runtime::shutdown`)
//! Mark the runtime as shutting down. From that moment the orchestrator's `stop_child` and
//! `stop_children` do nothing and return `Ok` (a parent whose awaited call was cut must not end its
//! child for good), `spawn`/`poll` answer `The harness is shutting down.`, and every public method
//! that returns a `Result` returns the same sentence while the listing methods keep answering from
//! what is known. Then cancel every running turn through `Control::stop_for_shutdown` — a running
//! tool is cancelled the usual way (a command gets TERM, then KILL after `tools.kill_grace_s`) and
//! its result is recorded, and the session itself records `interrupted{REASON_RESTART}` and a
//! `Stopped` turn end (a child is not settled) — and close every active session's inputs channel,
//! which ends every idle session cleanly (it kills its jobs and records how they ended, so that the
//! next start does not take them for lost). Wait up to `tools.kill_grace_s` + `SHUTDOWN_TASK_WAIT`
//! for the tasks to end (the grace is the cancelled tool's: a foreground command whose task is
//! aborted before its KILL would be left running, since nothing else tracks it); abort the tasks
//! that have not, wait up to `SHUTDOWN_ABORT_WAIT` more, kill the sessions' jobs (grace
//! `tools.kill_grace_s`), abort background tasks, and shut the proxy down. A turn still running
//! when its task is aborted is cut rather than ended: its child is not settled, and the next
//! `Session::open` records `interrupted{REASON_RESTART}` and a `Stopped` turn end, so a later start
//! resumes exactly what a clean stop would have left.
//!
//! A `join` whose `cancel` fires during shutdown does not return: its child is not stopped but cut
//! and resumed by the next start, so a result saying the call was interrupted and the agent stopped
//! would be false. The task waiting in it is aborted as soon as it is seen there (no need to wait
//! out the deadline), the call keeps no recorded result, and after the restart the weave shows it
//! as interrupted while the child's report arrives by itself. What the call queued for the parent's
//! log (`child_spawned`, `ledger`) is appended to it before the task parks, so that the next start
//! knows what the call started: a `finish` made again after the restart joins the verifier it had
//! started (or takes the verdict that verifier gave) instead of starting a second one. A report that
//! another `join` of the same call took (`agent_fanout`) is appended with `inline: false`, so that the
//! lead is shown it although the call has no result.
//!
//! A runtime dropped without `shutdown` (the daemon unwinding) lets go of its tasks the same way
//! (`Control::stop_for_shutdown` before their inputs close): no agent is settled because of it.
//!
//! ## Reading
//! - `sessions(include_archived)`: newest first. `session(id)`.
//! - `records(id, after, limit)`: a page of at most `min(limit, 2_000)` records with `seq > after`
//!   from the session's `log::PageReader` over `paths.session_log(id)`. One reader is kept per
//!   session so that paging in sequence does not rescan the log; only the `PAGERS_MAX` (16) most
//!   recently paged sessions keep theirs. `stored_records(id, after, limit)`: the same page from
//!   `PageReader::read_stored`, so that a record read as `Event::Unknown` keeps its stored line.
//! - `window(id)`: `log::read_records` → `weave` → [`WindowView`] (`est_tokens` with a default
//!   `TokenEstimator` over the messages plus the tool specs' JSON).
//! - `missions()`: one per root session. `ledger(mission)`: the journal read and folded
//!   (`No ledger: this mission's lead does not keep one.` when there is no journal file and the
//!   lead's role keeps none or can no longer be looked up; a lead that keeps one but has no journal
//!   file yet has an empty ledger). The id
//!   must be the mission of a known session, checked before a path is made from it (`There is no
//!   mission {id}.`).
//! - `score(mission)`: what the mission's work took, as a [`ScoreView`]: `loom_core::scorecard::score`
//!   over `log::read_records` of each of its sessions (the lead first, then the others, oldest first),
//!   and `total`, the lead's card with every other session's added (`Scorecard::add`). The logs are
//!   read on a blocking thread: a mission can have many, and a fork's begins with a copy of its
//!   parent's. The id is checked as for `ledger`. It counts records and judges nothing: whether the
//!   result was right is not in a log.
//! - `inbox()`: open items, oldest first. `net(id, limit)`: the last `limit` entries.
//! - `health()`: for every profile, `client.health()` and what discovery last reported.
//!
//! ## Tests required (a `MockServer` as the model, `SandboxMode::None`, a temporary loom home; no
//! real network; notifications through a `notify.command` that appends to a file)
//! - create + message: the turn runs; records arrive on the bus in log order; `meta.json` and
//!   `status.json` exist; the system prompt has the four environment lines;
//! - a lead reply calling `agent_spawn` (fresh, awaited): the child runs, `finish`es, the lead's
//!   call returns the report; the parent's log has `child_spawned` and an inline `child_settled`
//!   after the call's result; the child's first request carries its own system prompt and the
//!   assignment;
//! - fork: the child's first request starts with the parent's request messages byte for byte
//!   (compare the bodies the mock received) and continues with the assignment message that begins
//!   with the fork contract; forking a role whose tools the parent lacks is refused with the
//!   sentence above;
//! - background child: its settlement arrives in the parent as an `agent-report` and resumes a
//!   parent that ended its turn with `wait`;
//! - `max_children`, unknown role, spawning from a child: refused with the sentences above;
//! - the floor (E4): `cut_mission` ends the tunnels of one mission's sessions within a second and not another's,
//!   the runtime's proxy has the veto and the canary hook installed (a decoy user is a `407` and an S4 event
//!   attributed to the session), the box counters are polled, recorded as deltas only when they moved, and a box
//!   that cannot be read is not a record;
//! - stop: stopping the lead while its awaited child is mid-request settles the child `Stopped`
//!   and ends the lead's turn `Stopped`; `stop_child` on an idle child settles it;
//! - `poll`: `k` requests whose messages equal the session's stable prefix plus the vote prompt,
//!   distinct seeds, votes parsed, a failed request counted as no choice;
//! - `producer`: found through the live index and, after a restart, through the scan; the part a
//!   watched job's match stored is found while the job runs, after the mission's logs were scanned;
//! - outputs of a mission: a session's `out_read` opens its own output, its lead's (a fresh child), a
//!   job's settled output and a result's `META_RAW_BLOB`, live and after a restart (the scan); it is
//!   refused, with the sentence of an unknown handle, an output of another mission whose handle it was
//!   given in a message; an `out_read` view of another mission's output already in a log (one written
//!   before this rule) does not make that output readable;
//! - `prior`: a lead created with `prior` has, right after `session_start` and before its first
//!   `model_request`, one `harness_note{Info}` that is `prior::brief` of those missions; an unknown id and
//!   more than `MAX_PRIOR` are refused and leave no session; `meta.json` keeps `prior`; a restart writes no
//!   second note;
//! - inbox: a `finish` opens an item and notifies (the command's file has the kind); `answer`
//!   resolves it; an empty answer dismisses a non-blocking item without a turn and is refused for a
//!   blocking one;
//! - restart: a runtime shut down mid-turn and started again over the same home resumes an
//!   unattended session by itself (next request carries the `AFTER_RESTART` note) and leaves an
//!   attended one idle; open inbox items are back; an ended child is not activated; a finish
//!   verifier whose `child_spawned` a crash kept out of the lead's log is still the gate's;
//! - a read-only role's sandbox configuration protects the workspace; every session's environment
//!   names the proxy, on the session's own port: two sessions' `HTTP_PROXY` ports differ, neither is
//!   `proxy_port()`, and each session's sandbox allows (`loopback_ports`) its own port and not the other's;
//!   `start_warnings` holds the `api_key_env` warning when the variable is set and when it is not, and
//!   none for a profile with `api_key_file`; the secret-variable warning names `GITHUB_TOKEN` and a variable
//!   whose value is `https://u:p@h/`, holds neither value, and leaves out `LOOM_HOME`, an `api_key_env` and an
//!   `env_pass` name, and there is none when nothing is left; a profile whose key file is missing stops
//!   `Runtime::start`;
//! - `archive` hides, refuses messages, and survives a restart;
//! - copies: an agent started with `Workspace::Copy` is told where it works and its command runs
//!   there, the lead's workspace is unchanged until `agent_adopt` and has the agent's files after it,
//!   archiving removes the copy; `attempt` forks into copies, the check's result per attempt is the
//!   harness's, only the adopted attempt's files reach the workspace; a read-only role and a
//!   workspace past the limit are refused and leave no agent and no directory; `runs_of`;
//!   `with_copies`;
//! - `records` paging and `window` totals; `ledger` after a goal was set by the first message;
//! - `score`: a mission whose finish a verifier accepted (the lead's card, the verifier's, the total);
//!   a mission no session belongs to.

use crate::pack::{self, Packs, PromptEnv, RoleDef};
use crate::prior;
use crate::rtools::{
    self, ChildCopy, ChildInfo, Orchestrator, Producer, Run, Settlement, Shared, SpawnReq, Vote, Workspace,
};
use crate::session::{queue_input, Control, Deps, End, Input, Phase, Session, Sink, Status};
use crate::texts;
use async_trait::async_trait;
use futures_util::FutureExt;
use loom_core::config::{ensure_private_dir, Config, NetworkMode, Paths, SandboxCfg, SandboxMode};
use loom_core::estimate::TokenEstimator;
use loom_core::event::{
    Author, Brief, Budget, ChildOutcome, ChildSettled, ChildSpawned, Event, EvidenceGrade, Forked, InboxItem, ModelRef,
    NetDecision, Record, Seq, SessionOutcome, SessionStart, SpawnMode, Termination, ToolClass, ToolStatus,
    TurnEndReason, Usage, META_ALSO_STORED, META_EXIT_CODE, META_OF_BLOB, META_RAW_BLOB, META_SIGNAL,
};
use loom_core::journal::{self, Journal};
use loom_core::ledger::{LedgerOp, LedgerState};
use loom_core::log::{read_records, Durability, PageReader, SessionLog, StoredRecord};
use loom_core::scorecard::{self, Scorecard};
use loom_core::weave::{render_brief, weave, WindowItem};
use loom_core::{now_ms, BlobId, BlobRef, BlobStore, CallId, MissionId, SessionId};
use loom_model::{ChatRequest, Discovered, Limiter, ModelClient, ModelError, Priority, StreamEvent, ToolChoice};
use loom_net::policy::{InfraSpec, Policy};
use loom_net::proxy::Proxy;
use loom_tools::boxctl::{DockerHost, MissionBox};
use loom_tools::jobs::JobTable;
use loom_tools::outputs::OutputScope;
use loom_tools::sandbox::Sandbox;
use loom_tools::workcopy;
use loom_tools::ToolCtx;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Events the bus keeps for a slow subscriber before it is told it lagged.
pub const BUS_CAPACITY: usize = 8_192;

/// What the operator gives to start a session.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NewSession {
    pub workspace: PathBuf,
    /// Pack name; absent = `core`.
    pub pack: Option<String>,
    /// Role name; absent = the pack's default role.
    pub role: Option<String>,
    /// Model profile name; absent = the config's default.
    pub model: Option<String>,
    pub title: Option<String>,
    /// Resume by itself after a restart. Absent = yes for roles that end explicitly.
    pub unattended: Option<bool>,
    pub budget: Budget,
    /// The first message, sent as soon as the session exists.
    pub message: Option<String>,
    /// Earlier missions this one may recall: what their sealed ledgers recorded is put into the lead's log
    /// once, before its first model request (`crate::prior`). Not written when empty, so that a request that
    /// names none is accepted by a daemon older than this field.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub prior: Vec<MissionId>,
}

/// `meta.json`: what a session is, fixed when it is created.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SessionMeta {
    pub id: SessionId,
    pub mission: MissionId,
    #[serde(default)]
    pub parent: Option<SessionId>,
    pub workspace: String,
    /// For an agent that works in its own copy of its parent's workspace: the workspace the copy was
    /// made from. `workspace` is then the copy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copy_of: Option<String>,
    pub pack: String,
    pub role: String,
    /// Model profile name in the config.
    pub profile: String,
    /// Model id sent with requests.
    pub model: String,
    #[serde(default)]
    pub context_window: Option<u64>,
    #[serde(default)]
    pub title: String,
    pub created_ms: u64,
    /// How a child was started.
    #[serde(default)]
    pub mode: Option<SpawnMode>,
    /// A child whose report is returned to the call that started it.
    #[serde(default)]
    pub awaited: bool,
    #[serde(default)]
    pub unattended: bool,
    #[serde(default)]
    pub archived: bool,
    /// A verifier the finish gate of its parent started, with the assignment it was given. Its
    /// settlement belongs to that `finish`, or to a `finish` made again with the same assignment after
    /// a restart, never to the parent as an agent's report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gate: Option<Brief>,
    /// The earlier missions the operator chose for this one to recall, in the order given. Empty for a child.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prior: Vec<MissionId>,
}

/// A session as listed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SessionInfo {
    #[serde(flatten)]
    pub meta: SessionMeta,
    /// A task is driving it now.
    pub active: bool,
    pub status: Status,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MissionInfo {
    pub id: MissionId,
    /// The lead session.
    pub root: SessionId,
    pub title: String,
    pub created_ms: u64,
    pub has_ledger: bool,
    pub archived: bool,
}

/// An open inbox item and where it came from.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InboxEntry {
    pub session: SessionId,
    pub mission: MissionId,
    /// The session's title.
    pub title: String,
    pub opened_ms: u64,
    pub item: InboxItem,
}

/// One line of `net.jsonl`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NetEntry {
    pub ts_ms: u64,
    #[serde(flatten)]
    pub decision: NetDecision,
}

/// What is in a session's request now.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WindowView {
    pub epoch: u32,
    pub items: Vec<WindowItem>,
    /// Estimate for the stable messages plus the tool list.
    pub est_tokens: u64,
    pub target_tokens: u64,
    pub floor_tokens: u64,
    pub context_window: Option<u64>,
    /// As reported by the server for the latest request.
    pub prompt_tokens: u64,
    pub cached_tokens: u64,
}

/// A mission's ledger as the operator sees it, with what the read could not show.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct LedgerView {
    pub state: LedgerState,
    pub markdown: String,
    /// Entries sealed by a newer loom that this build cannot read: they are not in `state`.
    #[serde(default)]
    pub skipped: u64,
    /// The first of them: its number and why it could not be read.
    #[serde(default)]
    pub skipped_detail: Option<String>,
    /// The journal ends in an interrupted write, which was ignored.
    #[serde(default)]
    pub torn_tail: bool,
    /// Entries after the ones the journal's head record vouches for: removing them would go unnoticed.
    #[serde(default)]
    pub ahead_of_head: u64,
}

impl LedgerView {
    /// One sentence for each thing that makes `state` less than the whole ledger; empty when it is whole.
    pub fn notices(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.skipped > 0 {
            let detail = self.skipped_detail.as_deref().map(|d| format!(" (first: {d})")).unwrap_or_default();
            out.push(format!(
                "{} ledger {} written by a newer loom {} not shown{detail}. Upgrade loom to see {}.",
                self.skipped,
                if self.skipped == 1 { "entry" } else { "entries" },
                if self.skipped == 1 { "is" } else { "are" },
                if self.skipped == 1 { "it" } else { "them" },
            ));
        }
        if self.torn_tail {
            out.push(
                "The ledger ends in an interrupted write, which is ignored; the next entry written removes it."
                    .to_string(),
            );
        }
        if self.ahead_of_head > 0 {
            out.push(format!(
                "{} ledger {} not vouched for by the ledger's head record, so removing {} would go unnoticed.",
                self.ahead_of_head,
                if self.ahead_of_head == 1 { "entry is" } else { "entries are" },
                if self.ahead_of_head == 1 { "it" } else { "them" },
            ));
        }
        out
    }
}

/// The scorecard of one session of a mission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionScore {
    pub session: SessionId,
    pub role: String,
    #[serde(default)]
    pub parent: Option<SessionId>,
    pub card: Scorecard,
}

/// What a mission's work took (see [`Runtime::score`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoreView {
    pub mission: MissionId,
    /// The lead first, then the other sessions, oldest first.
    pub sessions: Vec<SessionScore>,
    /// The lead's card with every other session's added: the result is the lead's, the cost everyone's.
    pub total: Scorecard,
}

/// What became of a rule, an approval or a withdrawal the operator sent (see [`Runtime::add_rule`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleReceipt {
    /// The lead session it was handed to.
    pub lead: SessionId,
    /// The lead was running a turn: it records this at its next step. Until then it is queued, and
    /// kept on disk so that a daemon stop does not lose it.
    pub queued: bool,
    /// The mission keeps a ledger, so this is recorded there (a rule or an approval under an id) as
    /// well as in a note. Without one it is a note in the lead's window only.
    pub ledger: bool,
    /// The stock scope or reason recorded because none was given.
    pub stock: Option<String>,
}

/// What became of a scope grant the operator made (see [`Runtime::grant_scope`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeReceipt {
    /// The lead session of the mission, which records the grant.
    pub lead: SessionId,
    /// The hosts granted, trimmed.
    pub hosts: Vec<String>,
    /// The mission keeps a ledger, so the grant is recorded there as well as in a note.
    pub ledger: bool,
}

/// What became of a scope revoke the operator made (see [`Runtime::revoke_scope`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeRevokeReceipt {
    /// The lead session of the mission.
    pub lead: SessionId,
    /// The host revoked, as it was granted.
    pub host: String,
    /// The mission keeps a ledger.
    pub ledger: bool,
    /// The revoke is in the ledger (false when the mission keeps none, or the grant itself was not recorded
    /// there yet).
    pub recorded: bool,
    /// The sessions of the mission whose egress policy was narrowed.
    pub sessions: u32,
    /// The open connections ended.
    pub cut: u32,
}

/// The infrastructure the daemon knows about, for the implicit deny of every command policy (E1): its own
/// port, the `host:port` of every model endpoint, the box's Docker host and `network.infrastructure`.
fn infra_spec(config: &Config) -> InfraSpec {
    let model_endpoints = config.models.values().filter_map(|m| endpoint_of(&m.base_url)).collect::<BTreeSet<_>>();
    let ssh = config.boxed.ssh_host.trim();
    let mut docker_hosts = Vec::new();
    if config.boxed.enabled && !ssh.is_empty() {
        // The host of the ssh destination (`user@host`, `ssh://user@host:2222`), as the policy reads one. A
        // destination whose host the policy cannot read does not stop the daemon: it is left out, loudly.
        match crate::infra::docker_host_of(ssh) {
            Some(h)
                if Policy::new(&loom_core::config::NetworkCfg::default())
                    .and_then(|p| {
                        p.with_infrastructure(&InfraSpec { docker_hosts: vec![h.clone()], ..InfraSpec::default() })
                    })
                    .is_ok() =>
            {
                docker_hosts.push(h)
            }
            _ => tracing::warn!(
                "box.ssh_host \"{ssh}\" has no host name the egress policy can read, so the box's Docker host is not \
                 refused by name: add its address to network.infrastructure"
            ),
        }
    }
    InfraSpec {
        daemon_port: config.sandbox.daemon_port,
        model_endpoints: model_endpoints.into_iter().collect(),
        docker_hosts,
        extra: config.network.infrastructure.clone(),
        resolved: Vec::new(),
        local_addrs: Vec::new(),
    }
}

/// `infra_spec` with what the daemon resolved (see `crate::infra`): the Docker host's other names, the
/// addresses of every named entry and this machine's own addresses.
fn infra_spec_resolved(config: &Config, res: &crate::infra::Resolution) -> InfraSpec {
    let mut spec = infra_spec(config);
    for h in &res.docker_hosts {
        if !spec.docker_hosts.contains(h) {
            spec.docker_hosts.push(h.clone());
        }
    }
    spec.resolved = res.addrs.clone();
    spec.local_addrs = res.local.clone();
    spec
}

/// A policy of the daemon's infrastructure alone, which the floor's veto asks (`crate::floor`).
fn infra_policy(config: &Config, res: &crate::infra::Resolution) -> Result<Policy, String> {
    Policy::new(&loom_core::config::NetworkCfg::default())
        .and_then(|p| p.with_infrastructure(&infra_spec_resolved(config, res)))
}

/// The `host:port` a base URL connects to (`http://h:8000/v1` is `h:8000`; no port is 80 for http and 443
/// for https; user information and the path are left out). `None` for text that is not an http(s) URL.
pub(crate) fn endpoint_of(base_url: &str) -> Option<String> {
    let (scheme, rest) = base_url.trim().split_once("://")?;
    let default = match scheme.to_ascii_lowercase().as_str() {
        "http" => 80,
        "https" => 443,
        _ => return None,
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit_once('@').map_or(authority, |(_, a)| a);
    if authority.is_empty() {
        return None;
    }
    let has_port = match authority.strip_prefix('[') {
        Some(v6) => v6.split_once(']').is_some_and(|(_, after)| after.starts_with(':')),
        None => authority.contains(':'),
    };
    Some(if has_port { authority.to_string() } else { format!("{authority}:{default}") })
}

/// The hosts kept in `path` (a JSON list); none when the file is missing or unreadable (with a warning for
/// the second).
fn load_revoked(path: &Path) -> Vec<String> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            tracing::warn!("the revoked hosts in {} cannot be read ({e}); they are not applied", path.display());
            Vec::new()
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => {
            tracing::warn!("the revoked hosts in {} cannot be read ({e}); they are not applied", path.display());
            Vec::new()
        }
    }
}

/// The grant among `granted` that covers `host` by its wildcard (`*.suffix` covers `x.suffix`), if any.
fn covering_grant<'a>(granted: &'a [String], host: &str) -> Option<&'a str> {
    let h = host.to_ascii_lowercase();
    let name = h.rsplit_once(':').map_or(h.as_str(), |(n, _)| n);
    granted.iter().map(String::as_str).find(|g| {
        g.strip_prefix("*.").is_some_and(|suffix| {
            name.len() > suffix.len() && name.ends_with(&format!(".{}", suffix.to_ascii_lowercase()))
        })
    })
}

/// The scope recorded in the ledger for an approval given without one.
const STOCK_SCOPE: &str = "only what the approval says";
/// The reason recorded in the ledger for a rule withdrawn without one.
const STOCK_REASON: &str = "no reason given";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ModelHealth {
    pub profile: String,
    pub base_url: String,
    pub model: String,
    pub reachable: bool,
    /// Why not, when it is not.
    pub detail: String,
    pub context_window: Option<u64>,
    pub max_concurrent: u32,
}

/// A streamed piece of a model reply, in a form the API can send on.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "delta", rename_all = "snake_case")]
pub enum Delta {
    AttemptStart { attempt: u32 },
    Text { text: String },
    Reasoning { text: String },
    ToolCallStart { index: u32, name: String },
    ToolCallArgs { index: u32, text: String },
    Retrying { attempt: u32, after_ms: u64, reason: String },
}

/// Everything that happens, as it happens, for whoever is watching.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BusEvent {
    /// A session was created.
    Session {
        info: Box<SessionInfo>,
    },
    Record {
        session: SessionId,
        record: Box<Record>,
    },
    Delta {
        session: SessionId,
        req_id: String,
        delta: Delta,
    },
    Status {
        session: SessionId,
        status: Status,
    },
    Net {
        session: SessionId,
        entry: NetEntry,
    },
    /// A child settled (also visible as records; this is for listings).
    Settled {
        session: SessionId,
        settlement: Box<Settlement>,
    },
    Error {
        session: Option<SessionId>,
        message: String,
    },
    /// Never published by the runtime. The API sends it to a subscriber that fell behind and
    /// missed `missed` events; the subscriber should fetch what it shows again.
    Lagged {
        missed: u64,
    },
}

/// What every public method answers once `shutdown` has begun.
const SHUTTING: &str = "The harness is shutting down.";
/// Most records a `records` page holds.
const PAGE_MAX: usize = 2_000;
/// Sessions whose log paging state is kept; the least recently paged one is dropped beyond this.
const PAGERS_MAX: usize = 16;
/// How long tasks get to end by themselves after their inputs were closed at shutdown, on top of
/// the grace a cancelled command gets between TERM and KILL.
const SHUTDOWN_TASK_WAIT: Duration = Duration::from_secs(3);
/// How often shutdown looks for tasks that have ended or are parked in a `join`.
const SHUTDOWN_POLL: Duration = Duration::from_millis(20);
/// How long an aborted task gets to be dropped.
const SHUTDOWN_ABORT_WAIT: Duration = Duration::from_secs(5);
/// How long `stop_child` and `stop_children` wait for a stopped agent to settle, on top of the grace
/// its running commands get between TERM and KILL.
const STOP_SETTLE_WAIT: Duration = Duration::from_secs(2);
/// How long a notification command may run.
const NOTIFY_TIMEOUT: Duration = Duration::from_secs(30);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn no_session(id: &SessionId) -> String {
    format!("There is no session {id}.", id = id.as_str())
}

fn cut_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn idle_status() -> Status {
    Status {
        phase: Phase::Idle,
        step: 0,
        last_end: None,
        outcome: None,
        fork_point: None,
        epoch: 0,
        prompt_tokens: 0,
        cached_tokens: 0,
        completion_tokens_total: 0,
        open_inbox: 0,
    }
}

/// Write `value` as JSON to `path`: a temporary file in the same directory, then a rename.
fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    let text = serde_json::to_vec_pretty(value).map_err(std::io::Error::other)?;
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let tmp = path.with_file_name(format!(".{name}.tmp"));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    std::io::Write::write_all(&mut options.open(&tmp)?, &text)?;
    std::fs::rename(&tmp, path)
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Option<T> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// The records a session wrote itself: for a fork, those after its `forked` record.
fn own_records(records: &[Record]) -> &[Record] {
    match records.iter().rposition(|r| matches!(r.event, Event::Forked(_))) {
        Some(i) => &records[i + 1..],
        None => records,
    }
}

/// Beside the log of an agent that works in its own copy of the workspace: what the copy was made
/// from (`loom_tools::workcopy::Manifest`).
const COPY_MANIFEST: &str = "copy.json";

/// The commands a session ran itself with `bash` to their end, oldest first: every own `bash` result
/// that carries how the command ended (an exit code or a signal). A command that became a job has no
/// such result and is not listed.
fn runs_of(records: &[Record]) -> Vec<Run> {
    let mut calls: HashMap<&CallId, (&str, u64)> = HashMap::new();
    let mut runs = Vec::new();
    for r in own_records(records) {
        match &r.event {
            Event::ToolCall(c) if c.name == "bash" => {
                if let Some(command) = c.args.get("command").and_then(Value::as_str) {
                    calls.insert(&c.call_id, (command, r.ts_ms));
                }
            }
            Event::ToolResult(t) if t.name == "bash" => {
                let exit_code = t.meta.get(META_EXIT_CODE).and_then(Value::as_i64);
                if exit_code.is_none() && !t.meta.contains_key(META_SIGNAL) {
                    continue;
                }
                if let Some((command, started_ms)) = calls.remove(&t.call_id) {
                    runs.push(Run {
                        command: command.to_string(),
                        started_ms,
                        exit_code,
                        output: t.output.as_ref().map(BlobRef::handle),
                    });
                }
            }
            _ => {}
        }
    }
    runs
}

/// The stored output an event makes citable as evidence, and what produced it. A result's own
/// output; the text a `read` showed (the result is a view, `META_OF_BLOB` names the stored file text);
/// the complete output of a background job, attributed to the call that started it (`jobs` is filled by
/// `job_registered`, which states that call, and emptied by `job_settled`; only `bash` starts jobs); the
/// part of a running job's output a `job_matched` stored, attributed to the same call. A view of a
/// runtime tool's output (`out_read`, `out_grep`) is not an observation and registers nothing.
fn produced_by(
    session: &SessionId,
    jobs: &mut HashMap<(SessionId, String), Producer>,
    event: &Event,
) -> Option<(BlobId, Producer)> {
    match event {
        Event::ToolResult(t) => {
            let p = Producer {
                session: session.clone(),
                call_id: t.call_id.clone(),
                tool: t.name.clone(),
                class: t.class,
                grade: EvidenceGrade::of_tool_result(&t.name, t.class, &t.meta),
            };
            if let Some(o) = &t.output {
                return Some((o.id.clone(), p));
            }
            if t.name == "read" && t.class == ToolClass::Read && t.status == ToolStatus::Ok {
                let of = t.meta.get(META_OF_BLOB).and_then(|v| v.as_str()).filter(|s| !s.is_empty())?;
                return Some((BlobId::from(of), p));
            }
            None
        }
        Event::JobRegistered { job_id, call_id, .. } => {
            let p = Producer {
                session: session.clone(),
                call_id: call_id.clone(),
                tool: "bash".into(),
                class: ToolClass::Exec,
                grade: EvidenceGrade::Run,
            };
            jobs.insert((session.clone(), job_id.clone()), p);
            None
        }
        Event::JobSettled { job_id, output, .. } => {
            let p = jobs.remove(&(session.clone(), job_id.clone()))?;
            output.as_ref().map(|o| (o.id.clone(), p))
        }
        Event::JobMatched { job_id, output, .. } => {
            let p = jobs.get(&(session.clone(), job_id.clone()))?.clone();
            output.as_ref().map(|o| (o.id.clone(), p))
        }
        _ => None,
    }
}

/// The stored outputs an event names besides what `produced_by` finds: of a result that is not a view
/// (`out_read`, `out_grep`), the text it shows, its raw bytes and its further stored
/// reports; the output of a settled or matched job; the complete report of a child.
fn also_outputs(event: &Event) -> Vec<BlobId> {
    let mut out: Vec<BlobId> = Vec::new();
    let mut add = |id: &str| {
        if !id.is_empty() {
            out.push(BlobId::from(id));
        }
    };
    match event {
        Event::ToolResult(t) if t.name != "out_read" && t.name != "out_grep" => {
            // `produced_by` indexes `output`, and the text of a successful `read` that has no output.
            let indexed_of =
                t.name == "read" && t.class == ToolClass::Read && t.status == ToolStatus::Ok && t.output.is_none();
            for key in [META_OF_BLOB, META_RAW_BLOB] {
                if key == META_OF_BLOB && indexed_of {
                    continue;
                }
                if let Some(id) = t.meta.get(key).and_then(Value::as_str) {
                    add(id);
                }
            }
            for id in t.meta.get(META_ALSO_STORED).and_then(Value::as_array).into_iter().flatten() {
                if let Some(id) = id.as_str() {
                    add(id);
                }
            }
        }
        Event::JobSettled { output: Some(o), .. } | Event::JobMatched { output: Some(o), .. } => add(o.id.as_str()),
        Event::ChildSettled(c) => {
            if let Some(f) = &c.full {
                add(f.id.as_str());
            }
        }
        Event::ChildCompleted(c) => {
            if let Some(f) = &c.full {
                add(f.id.as_str());
            }
        }
        _ => {}
    }
    out
}

/// The completed result is authoritative even when a later terminal/status write was interrupted.
fn completed_settlement(records: &[Record], child: &SessionId) -> Option<Settlement> {
    own_records(records).iter().rev().find_map(|record| match &record.event {
        Event::ChildCompleted(result) if &result.child == child => Some(Settlement {
            child: result.child.clone(),
            role: result.role.clone(),
            outcome: result.outcome,
            report: result.report.clone(),
            full: result.full.clone(),
            payload: result.payload.clone(),
            steps: result.steps,
            usage: result.usage,
        }),
        _ => None,
    })
}

fn settled_status(previous: &Status, result: &Settlement) -> Status {
    let (outcome, last_end) = match result.outcome {
        ChildOutcome::Returned => (SessionOutcome::Done, TurnEndReason::Finished),
        ChildOutcome::Blocked => (SessionOutcome::Done, TurnEndReason::Blocked),
        ChildOutcome::BudgetExhausted => (SessionOutcome::BudgetExhausted, TurnEndReason::BudgetExhausted),
        ChildOutcome::Stopped => (SessionOutcome::Stopped, TurnEndReason::Stopped),
        ChildOutcome::Failed => (SessionOutcome::Failed, TurnEndReason::Error),
    };
    Status {
        phase: Phase::Ended,
        outcome: Some(outcome),
        last_end: Some(last_end),
        step: result.steps,
        completion_tokens_total: result.usage.completion_tokens,
        // Prompt/cache metrics describe the latest request, while settlement usage is cumulative.
        ..previous.clone()
    }
}

/// The inbox items still open after `records`, with the time each was opened.
fn open_items(records: &[Record]) -> Vec<(InboxItem, u64)> {
    let mut open: Vec<(InboxItem, u64)> = Vec::new();
    for r in own_records(records) {
        match &r.event {
            Event::InboxOpened(item) => {
                open.retain(|(i, _)| i.item_id != item.item_id);
                open.push((item.clone(), r.ts_ms));
            }
            Event::InboxResolved { item_id, .. } => open.retain(|(i, _)| &i.item_id != item_id),
            _ => {}
        }
    }
    open
}

/// True when `open` cut a running turn: the last own `turn_end` is `Stopped`, the latest own
/// `interrupted` names a restart (or log damage) and no own `turn_start` follows it.
fn cut_by_restart(records: &[Record]) -> bool {
    let own = own_records(records);
    let last_end = own.iter().rev().find_map(|r| match &r.event {
        Event::TurnEnd { reason } => Some(*reason),
        _ => None,
    });
    if last_end != Some(TurnEndReason::Stopped) {
        return false;
    }
    let Some(at) = own.iter().rposition(|r| matches!(r.event, Event::Interrupted { .. })) else {
        return false;
    };
    let restarted = matches!(&own[at].event, Event::Interrupted { reason }
        if reason == texts::REASON_RESTART || reason.starts_with("the session log was damaged"));
    restarted && !own[at + 1..].iter().any(|r| matches!(r.event, Event::TurnStart { .. }))
}

fn child_outcome_of(outcome: SessionOutcome) -> ChildOutcome {
    match outcome {
        SessionOutcome::Done => ChildOutcome::Returned,
        SessionOutcome::Stopped => ChildOutcome::Stopped,
        SessionOutcome::Failed => ChildOutcome::Failed,
        SessionOutcome::BudgetExhausted => ChildOutcome::BudgetExhausted,
    }
}

/// Revokes a session's proxy grant (closing its listener) when dropped while armed, so that a set-up
/// that fails after the grant leaks no listener.
struct RevokeOnDrop<'a> {
    proxy: &'a Proxy,
    session: &'a SessionId,
    armed: bool,
}

impl Drop for RevokeOnDrop<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.proxy.revoke(self.session);
        }
    }
}

/// The sandbox configuration a session of `role` runs under.
/// Every model profile's `api_key_env` name is withheld from its commands.
fn sandbox_cfg_for(
    base: &SandboxCfg,
    role: &RoleDef,
    workspace: &Path,
    models: &BTreeMap<String, loom_core::config::ModelProfile>,
) -> SandboxCfg {
    let mut cfg = base.clone();
    for name in models.values().filter_map(|p| p.api_key_env.as_deref()).filter(|n| !n.is_empty()) {
        if !cfg.secret_env.iter().any(|n| n == name) {
            cfg.secret_env.push(name.to_string());
        }
    }
    if role.read_only {
        for path in &cfg.extra_writable {
            if !cfg.replay_untrusted_paths.contains(path) {
                cfg.replay_untrusted_paths.push(path.clone());
            }
        }
        cfg.extra_writable.clear();
        cfg.protected_paths.push(workspace.display().to_string());
    }
    cfg
}

/// `cfg` with what agents' own copies of a workspace add. Every copy is a place some agent can
/// write, so none of them is an input of an isolated replay; and an agent that works in a copy may
/// not write to the workspace the copy was made from.
fn with_copies(mut cfg: SandboxCfg, copies: &Path, copy_of: Option<&str>) -> SandboxCfg {
    let copies = copies.display().to_string();
    if !cfg.replay_untrusted_paths.contains(&copies) {
        cfg.replay_untrusted_paths.push(copies);
    }
    if let Some(source) = copy_of {
        cfg.protected_paths.push(source.to_string());
    }
    cfg
}

/// The message a panic carried.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "no message".to_string())
}

/// Titles of sessions whose task panics when it starts (tests only).
#[cfg(test)]
static PANIC_TITLES: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Every agent a `Resume` was sent to, once per `Resume` (tests only).
#[cfg(test)]
static RESUMES: Mutex<Vec<SessionId>> = Mutex::new(Vec::new());

fn network_text(config: &Config) -> String {
    let mode = match config.network.mode {
        NetworkMode::Open => "open",
        NetworkMode::Allowlist => "allowlist",
        NetworkMode::DenyAll => "deny_all",
    };
    texts::network_sentence(mode, &config.network.allow, &config.network.deny, &config.network.allow_private)
}

// ---- state --------------------------------------------------------------------------------------

/// What the runtime holds for a session that has a task driving it.
struct ActiveSession {
    gen: u64,
    inputs: UnboundedSender<Input>,
    control: Arc<Control>,
    shared: Arc<Shared>,
    jobs: Arc<JobTable>,
    task: JoinHandle<()>,
}

/// What the runtime knows about a session.
struct Known {
    meta: SessionMeta,
    status: Status,
    active: Option<ActiveSession>,
    /// A child's settlement, once there is one.
    settlement: Option<Settlement>,
    settled_tx: watch::Sender<Option<Settlement>>,
    /// The settlement reached the parent: a `join` took it (and recorded it in the parent's log), or it
    /// was handed to the parent as input. Whoever sets it delivers; a delivery that fails clears it.
    joined: bool,
    /// Activated from disk: nobody can be waiting for this session any more.
    restored: bool,
    /// An agent that a restart left idle (its turn cut, or between turns with nothing that would wake
    /// it): only a `Resume` runs it again, and it gets one when its lead goes on. Cleared when that
    /// `Resume` is sent and when the agent publishes that it is running, so that a second operator
    /// action before its turn starts sends no second one.
    held: bool,
    /// The finish gate of its parent started it, with this assignment (`meta.gate`; for an agent written
    /// before that field, known from the parent's log once restored). Its settlement belongs to the
    /// `finish` that waits for it: it is never delivered as an agent report, and the parent's agent
    /// listing leaves it out.
    gate: Option<Brief>,
}

impl Known {
    fn new(meta: SessionMeta, status: Status) -> Known {
        let (settled_tx, _) = watch::channel(None);
        let gate = meta.gate.clone();
        Known {
            meta,
            status,
            active: None,
            settlement: None,
            settled_tx,
            joined: false,
            restored: false,
            held: false,
            gate,
        }
    }

    fn finished(&self) -> bool {
        self.settlement.is_some() || self.status.phase == Phase::Ended
    }

    /// Nothing of it should be running: it finished or it was stopped (`census::has_ended`).
    fn census_ended(&self) -> bool {
        crate::census::has_ended(self.finished(), self.status.phase, self.status.last_end)
    }

    fn outcome(&self) -> ChildOutcome {
        match (&self.settlement, self.status.outcome) {
            (Some(s), _) => s.outcome,
            (None, Some(o)) => child_outcome_of(o),
            (None, None) => ChildOutcome::Stopped,
        }
    }
}

#[derive(Default)]
struct State {
    known: BTreeMap<SessionId, Known>,
    route_cursor: HashMap<(SessionId, String), usize>,
    inbox: Vec<InboxEntry>,
    producers: HashMap<(MissionId, BlobId), Producer>,
    /// The outputs of a mission that the producer index does not cover (see *Outputs of a mission*).
    extra_outputs: HashSet<(MissionId, BlobId)>,
    scanned: HashSet<MissionId>,
    /// The call that started each background job, by session and job id (for the job's complete output).
    job_starts: HashMap<(SessionId, String), Producer>,
    /// Background tasks (net forwarder, notification repeaters).
    tasks: Vec<JoinHandle<()>>,
    /// Sessions whose task waits in a `join` that shutdown cancelled and that will not return.
    parked: HashSet<SessionId>,
    /// Hosts the operator granted to each mission since the daemon started (a superset of what the
    /// ledger records of them until the lead has recorded a grant that is still queued).
    scope: HashMap<MissionId, Vec<String>>,
    /// Hosts the operator revoked from each mission since the daemon started: left out of `granted_hosts`
    /// at once, whatever the ledger or `scope` still holds (a grant that is queued, a revoke that is not
    /// recorded). A grant of the same host again takes it out of here.
    scope_revoked: HashMap<MissionId, Vec<String>>,
    /// Bumped by every grant and revoke of a mission, before the sessions are told: a session that was
    /// built with an older value has its policy derived again (see `Inner::policy_is_current`).
    scope_gen: HashMap<MissionId, u64>,
    /// The box of each mission that has used one (see `Inner::box_for`).
    boxes: HashMap<MissionId, Arc<MissionBox>>,
    /// Missions whose box was removed because the mission was stopped, ended or archived: no box is made for
    /// one of them until its lead is resumed (see `Inner::box_for`).
    box_closed: HashSet<MissionId>,
}

/// One model profile, made at start.
struct ProfileRt {
    client: Arc<ModelClient>,
    limiter: Arc<Limiter>,
    discovered: Mutex<Option<Discovered>>,
}

/// What the runtime keeps of a session's `Deps`.
struct Parts {
    control: Arc<Control>,
    shared: Arc<Shared>,
    jobs: Arc<JobTable>,
}

/// What `activate` found out about a session.
struct Activation {
    /// A task was already driving it.
    already: bool,
    /// `open` cut a running turn.
    cut: bool,
    /// The session was waiting and has been told of job ends no turn has followed (`open` recorded
    /// those of the previous daemon, or a shutdown those of the jobs it killed): it has to be woken.
    woken: bool,
}

/// Private state; its fields are the implementer's.
struct Inner {
    me: Weak<Inner>,
    config: Config,
    paths: Paths,
    blobs: BlobStore,
    bus: broadcast::Sender<BusEvent>,
    packs: Packs,
    key: Vec<u8>,
    profiles: BTreeMap<String, ProfileRt>,
    proxy: Proxy,
    state: Mutex<State>,
    /// Held across a scan of a mission's logs (`scan_outputs`).
    scan_lock: tokio::sync::Mutex<()>,
    /// Held while sessions are activated (never across an `.await`).
    activation: Mutex<()>,
    shutting: AtomicBool,
    /// The volume of the loom home was low at the last check (see `note_disk`).
    disk_low: AtomicBool,
    /// The start-up pass has not looked at the leads' logs yet: a settlement made until then is left
    /// for its recovery to deliver (see `record_settlement`).
    restoring: AtomicBool,
    next_gen: AtomicU64,
    orch: Arc<dyn Orchestrator>,
    sink: Arc<dyn Sink>,
    /// Paging state per recently viewed session, least recently used first.
    pagers: Mutex<Vec<(SessionId, Arc<Mutex<PageReader>>)>>,
    /// The Docker host of `[box]`, when the operator enabled one (see `loom_tools::boxctl`).
    box_host: Option<Arc<DockerHost>>,
    /// What the daemon resolved about its infrastructure (`crate::infra`), for every session's policy.
    infra: Mutex<crate::infra::Resolution>,
    /// Whether commands can reach the network outside the proxy, as the last self-probe found it (`crate::egress`).
    egress: Mutex<crate::egress::EgressView>,
    /// The operator was told that egress is unbounded, and it has not been bounded since.
    egress_told: AtomicBool,
    /// The operator was told that the self-probe found a problem (a leak, a probe that cannot run, the resolver's
    /// socket) while the level was `Unbounded`, and the problem has not cleared since. Kept apart from
    /// `egress_told` so a problem is told even when the setting `allow_fetch_services` already made egress unbounded.
    egress_problem_told: AtomicBool,
    /// The last process and listener census of the sessions (`crate::census`), `None` until the first finishes.
    census: Mutex<Option<crate::census::CensusView>>,
    /// The survivors the operator was told of (`crate::census::tell`).
    census_told: Mutex<crate::census::Told>,
    /// The operator was told that the census runs without sandbox identity, and it has not had identity since.
    census_blind_told: AtomicBool,
    /// The proxy's veto, canary hooks and lab-listener check (`crate::floor`, E4).
    floor: crate::floor::Floor,
    /// The missions whose box counters could not be read at the last poll and the operator's log was told so,
    /// until a poll works again (`poll_box_counters`).
    box_counters_failed: Mutex<BTreeSet<MissionId>>,
}

impl Inner {
    /// The sessions a census asks about (every one that is not archived) and those of them that have ended or were
    /// stopped: nothing of those should be running.
    fn census_sessions(&self) -> (Vec<(String, PathBuf)>, BTreeSet<String>) {
        // The state lock is held only to list the sessions: `members` canonicalizes each one's temp dir.
        let (live, ended): (Vec<SessionId>, BTreeSet<String>) = {
            let st = self.st();
            let live = st.known.iter().filter(|(_, k)| !k.meta.archived).map(|(id, _)| id.clone()).collect();
            let ended = st
                .known
                .iter()
                .filter(|(_, k)| !k.meta.archived && k.census_ended())
                .map(|(id, _)| id.as_str().to_string())
                .collect();
            (live, ended)
        };
        (crate::census::members(&self.paths, &live), ended)
    }

    /// The sessions of the mission `who` belongs to (itself included): what the lab-listener check does not take
    /// for a squatter. Just `who` for a session that is not known.
    fn mission_peers(&self, who: &SessionId) -> Vec<String> {
        let st = self.st();
        let Some(mission) = st.known.get(who).map(|k| k.meta.mission.clone()) else {
            return vec![who.as_str().to_string()];
        };
        st.known.iter().filter(|(_, k)| k.meta.mission == mission).map(|(id, _)| id.as_str().to_string()).collect()
    }

    /// Whether commands run under Seatbelt, the only mode in which a process can be told by its profile.
    fn census_confined(&self) -> bool {
        self.config.sandbox.mode == SandboxMode::Seatbelt
    }

    /// Takes a census on a blocking thread, keeps it, and logs what an ended session left running that the
    /// operator was not told yet.
    async fn run_census(&self) -> Option<crate::census::CensusView> {
        let (members, ended) = self.census_sessions();
        let home = self.paths.home.clone();
        let confined = self.census_confined();
        let view = tokio::task::spawn_blocking(move || crate::census::take(&home, &members, confined)).await.ok()?;
        let lines = {
            let mut told = self.census_told.lock().unwrap_or_else(|p| p.into_inner());
            crate::census::tell(&mut told, &view, &ended)
        };
        for line in lines {
            tracing::warn!("{line}");
        }
        // A census that cannot tell by sandbox is not a failure to hide: it is told, once, until identity returns.
        if view.readable && confined && !view.identity {
            let notice = crate::census::blind_notice(&view.identity_detail);
            tracing::warn!("{notice}");
            if !self.census_blind_told.swap(true, Ordering::SeqCst) {
                self.notify("census", &SessionId::from(""), "The process census is blind", &notice);
            }
        } else if view.identity {
            self.census_blind_told.store(false, Ordering::SeqCst);
        }
        *self.census.lock().unwrap_or_else(|p| p.into_inner()) = Some(view.clone());
        Some(view)
    }

    /// Reads the rule counters of every mission box that is up, appends what moved since the last poll to
    /// `<home>/logs/box-counters.jsonl` (one line per mission with a delta: `ts_ms`, `mission`, `chain`, `rules`) and
    /// returns the deltas. A box that cannot be read is logged once until it can again; a failed write is logged.
    async fn poll_box_counters(&self) -> Vec<(MissionId, Vec<loom_tools::boxctl::RuleCount>)> {
        let boxes: Vec<(MissionId, Arc<MissionBox>)> =
            self.st().boxes.iter().map(|(m, b)| (m.clone(), b.clone())).collect();
        let mut moved = Vec::new();
        for (mission, b) in boxes {
            match b.poll_counters().await {
                Ok(Some(rules)) => {
                    self.box_counters_failed.lock().unwrap_or_else(|p| p.into_inner()).remove(&mission);
                    if rules.is_empty() {
                        continue;
                    }
                    let dropped: u64 = rules.iter().filter(|r| r.drop).map(|r| r.packets).sum();
                    if dropped > 0 {
                        tracing::warn!(
                            "The box of mission {} had {dropped} packet(s) dropped by its egress rules since the last poll.",
                            mission.as_str()
                        );
                    }
                    let line = serde_json::json!({
                        "ts_ms": now_ms(),
                        "mission": mission.as_str(),
                        "chain": b.names().chain,
                        "rules": rules,
                    });
                    if let Err(e) = append_line(&self.paths.logs_dir().join(BOX_COUNTERS_FILE), &line.to_string()) {
                        tracing::warn!("The box counters of mission {} could not be recorded: {e}", mission.as_str());
                    }
                    moved.push((mission, rules));
                }
                Ok(None) => {
                    self.box_counters_failed.lock().unwrap_or_else(|p| p.into_inner()).remove(&mission);
                }
                Err(e) => {
                    let first =
                        self.box_counters_failed.lock().unwrap_or_else(|p| p.into_inner()).insert(mission.clone());
                    if first {
                        tracing::warn!(
                            "The rule counters of the box of mission {} could not be read: {e}",
                            mission.as_str()
                        );
                    }
                }
            }
        }
        moved
    }

    /// Waits until the tasks of `family` have ended, then stops by sandbox identity what each left running (see
    /// `Runtime::archive`), and says so in the log.
    async fn stop_leftovers(&self, family: &[SessionId]) {
        self.until_closed(family).await;
        let (home, confined) = (self.paths.home.clone(), self.census_confined());
        let members = crate::census::members(&self.paths, family);
        let killed = tokio::task::spawn_blocking(move || {
            let home = crate::census::canonical_home(&home);
            let mut stopped = Vec::new();
            for (id, tmp) in &members {
                let member = loom_tools::sandbox::census::Member { id, tmp };
                let done = loom_tools::sandbox::census::kill(&home, &[member], &[], &[], confined);
                if done.killed > 0 || !done.left.is_empty() {
                    stopped.push((id.clone(), done.killed, done.left.len()));
                }
            }
            stopped
        })
        .await
        .unwrap_or_default();
        for (id, stopped, left) in killed {
            tracing::warn!(
                "Session {id} was archived with processes still running under its sandbox: {stopped} stopped, {left} could not be stopped"
            );
        }
    }

    /// The last resolution of the infrastructure names and this machine's addresses.
    fn infra(&self) -> crate::infra::Resolution {
        self.infra.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Take a self-probe's report (`crate::egress`): keep the view, write the report to `<home>/egress-probe.json`
    /// and, when egress turned unbounded, tell the operator once (again only after it was bounded).
    fn record_egress(&self, report: Option<loom_tools::sandbox::selfprobe::Report>) {
        let now = loom_core::now_ms();
        let view = crate::egress::assess(&self.config.sandbox, report.as_ref(), report.as_ref().map(|_| now));
        if let Some(report) = &report {
            let body = serde_json::json!({ "at_ms": now, "view": view, "report": report });
            let path = self.paths.home.join("egress-probe.json");
            let tmp = self.paths.home.join("egress-probe.json.tmp");
            let written = serde_json::to_vec_pretty(&body)
                .map_err(|e| e.to_string())
                .and_then(|b| std::fs::write(&tmp, b).map_err(|e| e.to_string()))
                .and_then(|()| std::fs::rename(&tmp, &path).map_err(|e| e.to_string()));
            if let Err(e) = written {
                tracing::warn!("The self-probe's result could not be written to {}: {e}", path.display());
            }
        }
        let level = view.level;
        let view_problem = view.probe_problem && level == crate::egress::Level::Unbounded;
        for reason in &view.reasons {
            tracing::warn!("Egress is {level:?}: {reason}");
        }
        *self.egress.lock().unwrap_or_else(|p| p.into_inner()) = view;
        let problem = view_problem;
        let fresh_problem = if problem {
            !self.egress_problem_told.swap(true, Ordering::SeqCst)
        } else {
            self.egress_problem_told.store(false, Ordering::SeqCst);
            false
        };
        let fresh_level = match level {
            crate::egress::Level::Unbounded => !self.egress_told.swap(true, Ordering::SeqCst),
            crate::egress::Level::Bounded => {
                self.egress_told.store(false, Ordering::SeqCst);
                false
            }
            crate::egress::Level::Unprobed => false,
        };
        if fresh_problem || fresh_level {
            self.notify("egress", &SessionId::from(""), "Egress is unbounded", crate::egress::UNBOUNDED_NOTICE);
        }
    }
}

impl Drop for Inner {
    /// Let go of the tasks without `shutdown` (the daemon unwinding) as a shutdown does, before their
    /// inputs close: an agent is then cut for the next start, not settled as stopped by the operator.
    fn drop(&mut self) {
        let st = self.state.get_mut().unwrap_or_else(|p| p.into_inner());
        for a in st.known.values().filter_map(|k| k.active.as_ref()) {
            a.control.stop_for_shutdown();
        }
    }
}

struct SinkImpl(Weak<Inner>);

impl Sink for SinkImpl {
    fn record(&self, session: &SessionId, record: &Record) {
        if let Some(inner) = self.0.upgrade() {
            inner.on_record(session, record);
        }
    }

    fn delta(&self, session: &SessionId, req_id: &str, event: &StreamEvent) {
        if let Some(inner) = self.0.upgrade() {
            let delta = match event {
                StreamEvent::AttemptStart { attempt } => Delta::AttemptStart { attempt: *attempt },
                StreamEvent::Text(t) => Delta::Text { text: t.clone() },
                StreamEvent::Reasoning(t) => Delta::Reasoning { text: t.clone() },
                StreamEvent::ToolCallStart { index, name } => {
                    Delta::ToolCallStart { index: *index, name: name.clone() }
                }
                StreamEvent::ToolCallArgs { index, delta } => {
                    Delta::ToolCallArgs { index: *index, text: delta.clone() }
                }
                StreamEvent::Retrying { attempt, after_ms, reason } => {
                    Delta::Retrying { attempt: *attempt, after_ms: *after_ms, reason: reason.clone() }
                }
                // For the session only: viewers already have the call from its start and arguments.
                StreamEvent::ToolCallReady { .. } => return,
            };
            inner.publish(BusEvent::Delta { session: session.clone(), req_id: req_id.to_string(), delta });
        }
    }

    fn status(&self, session: &SessionId, status: &Status) {
        if let Some(inner) = self.0.upgrade() {
            inner.on_status(session, status);
        }
    }
}

/// What the tools of a session reach the runtime through. Holds the runtime weakly.
struct Orch(Weak<Inner>);

impl Orch {
    fn up(&self) -> Result<Arc<Inner>, String> {
        match self.0.upgrade() {
            Some(i) if !i.shutting.load(Ordering::SeqCst) => Ok(i),
            _ => Err(SHUTTING.to_string()),
        }
    }
}

const NOT_YOURS: &str = "is not an agent this session started.";

#[async_trait]
impl Orchestrator for Orch {
    async fn spawn(&self, parent: &SessionId, req: SpawnReq) -> Result<SessionId, String> {
        let inner = self.up()?;
        if !req.harness {
            return inner.spawn_child(parent, req).await;
        }
        // A recovered harness verifier must meet the current credential gate too; reusing a held
        // child cannot bypass the actual target role's dispatch prerequisites.
        let (shared, required) = {
            let state = inner.st();
            let p = state
                .known
                .get(parent)
                .filter(|k| k.meta.parent.is_none())
                .ok_or_else(|| "Only the lead session of a mission can start agents.".to_string())?;
            let role = inner.packs.role(Some(&p.meta.pack), Some(&req.role))?;
            let shared = p.active.as_ref().map(|a| a.shared.clone()).ok_or_else(|| SHUTTING.to_string())?;
            (shared, role.requires_credential)
        };
        rtools::validate_dispatch_prerequisite(&shared, required, req.prerequisite.as_ref(), now_ms())?;
        if let Some(verifier) = inner.cut_verifier(parent, &req.role, &req.brief) {
            // The finish waits for it now: one the restart left idle goes on (an ended one has its verdict).
            inner.resume_held(&verifier);
            return Ok(verifier);
        }
        // Marked as the gate's in its `meta.json`, written before its first turn: a crash cannot lose that.
        inner.spawn_child(parent, req).await
    }

    async fn box_access(&self, session: &SessionId) -> Result<Arc<MissionBox>, String> {
        self.up()?.box_for(session)
    }

    async fn child_copy(&self, parent: &SessionId, child: &SessionId) -> Result<Option<ChildCopy>, String> {
        let inner = self.0.upgrade().ok_or_else(|| SHUTTING.to_string())?;
        let child = inner.resolve_child_id(parent, child)?;
        let (meta, running) = {
            let st = inner.st();
            let Some(k) = st.known.get(&child).filter(|k| k.meta.parent.as_ref() == Some(parent)) else {
                return Err(format!("{} {NOT_YOURS}", child.as_str()));
            };
            (k.meta.clone(), !k.finished())
        };
        let Some(source) = meta.copy_of.clone() else { return Ok(None) };
        let role = inner.packs.role(Some(&meta.pack), Some(&meta.role))?.clone();
        let (record, log) = (inner.paths.session_dir(&child).join(COPY_MANIFEST), inner.paths.session_log(&child));
        let (tmp, home, copies) = (inner.paths.session_tmp(parent), inner.paths.home.clone(), inner.paths.copies_dir());
        let parent_jobs = inner.paths.session_dir(parent).join("jobs");
        let identity = parent.as_str().to_string();
        let (base, models, port) = (
            inner.config.sandbox.clone(),
            inner.config.models.clone(),
            // The commands run with the parent's environment, so on the parent's listener.
            inner.proxy.session_port(parent),
        );
        let read = tokio::task::spawn_blocking(move || {
            let dir = std::fs::canonicalize(&meta.workspace).map_err(|e| {
                format!(
                    "The copy of agent {} ({}) cannot be used: {e}. An agent's copy is removed when its mission is archived.",
                    child.as_str(),
                    meta.workspace
                )
            })?;
            let manifest = read_json(&record).ok_or_else(|| {
                format!(
                    "The record of what the copy of agent {} was made from ({}) cannot be read, so what the agent changed cannot be told. Its files are in {}.",
                    child.as_str(),
                    record.display(),
                    dir.display()
                )
            })?;
            // A log that cannot be read shows no commands; the files are still compared.
            let runs = read_records(&log).map(|report| runs_of(&report.records)).unwrap_or_default();
            // Commands the parent has the harness run in the copy: they write there and to the
            // parent's own scratch directory, under the rules the agent itself ran under.
            let cfg = with_copies(sandbox_cfg_for(&base, &role, &dir, &models), &copies, Some(&source));
            let bubblewrap = cfg.mode == SandboxMode::Bubblewrap;
            let sandbox = Sandbox::new(&cfg, &dir, &tmp, &home, if bubblewrap { None } else { port })
                .and_then(|s| s.with_jobs_dir(&parent_jobs))
                .and_then(|s| s.with_identity(&identity))
                .map_err(|e| format!("The sandbox for the copy of agent {} cannot be set up: {e}", child.as_str()))?;
            Ok(ChildCopy { agent: child, dir, manifest, running, runs, sandbox: Arc::new(sandbox) })
        });
        match read.await {
            Ok(copy) => copy.map(Some),
            Err(e) => Err(format!("The agent's copy could not be read: {e}")),
        }
    }

    async fn join(
        &self,
        parent: &SessionId,
        child: &SessionId,
        cancel: &CancellationToken,
    ) -> Result<Settlement, String> {
        let inner = self.0.upgrade().ok_or_else(|| SHUTTING.to_string())?;
        let resolved = inner.resolve_child_id(parent, child)?;
        let child = &resolved;
        let (mut rx, parent_shared) = {
            let st = inner.st();
            let k = st.known.get(child).filter(|k| k.meta.parent.as_ref() == Some(parent));
            let Some(k) = k else {
                return Err(format!("{} {NOT_YOURS}", child.as_str()));
            };
            if !k.meta.awaited {
                return Err(format!("{} was started in the background; its report arrives by itself.", child.as_str()));
            }
            // Taken now: a shutdown takes the parent's active state away before this call parks.
            let parent_shared = st.known.get(parent).and_then(|p| p.active.as_ref()).map(|a| a.shared.clone());
            (k.settled_tx.subscribe(), parent_shared)
        };
        let settlement = loop {
            let current = rx.borrow_and_update().clone();
            if let Some(s) = current {
                break s;
            }
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    if inner.shutting.load(Ordering::SeqCst) {
                        // The child is not stopped by a shutdown: it is cut, and resumed by the next
                        // start. A result written now would tell the model that the call was
                        // interrupted and the agent stopped, so the call gets none: this task stays
                        // here until `shutdown` aborts it, and `open` records the cut. What the call
                        // queued for the log is written first, so that the restart knows the agents
                        // it started.
                        if let Some(shared) = &parent_shared {
                            inner.write_for_parked(parent, shared);
                        }
                        inner.st().parked.insert(parent.clone());
                        std::future::pending::<()>().await;
                    }
                    // The call's result says that it was interrupted: nothing takes this settlement any
                    // more (a `finish` made again starts a new verifier).
                    if let Some(k) = inner.st().known.get_mut(child) {
                        k.joined = true;
                    }
                    return Err("Interrupted before the agent finished.".to_string());
                }
                changed = rx.changed() => {
                    if changed.is_err() {
                        return Err(SHUTTING.to_string());
                    }
                }
            }
        };
        let first = match inner.st().known.get_mut(child) {
            Some(k) if !k.joined => {
                k.joined = true;
                true
            }
            _ => false,
        };
        if let Some(shared) = parent_shared.filter(|_| first) {
            shared.emit(
                Author::Agent(child.clone()),
                Event::ChildSettled(ChildSettled {
                    child: child.clone(),
                    outcome: settlement.outcome,
                    report: settlement.report.clone(),
                    full: settlement.full.clone(),
                    usage: settlement.usage,
                    steps: settlement.steps,
                    inline: true,
                }),
            );
        }
        Ok(settlement)
    }

    async fn stop_child(&self, parent: &SessionId, child: &SessionId) -> Result<(), String> {
        let Some(inner) = self.0.upgrade() else { return Ok(()) };
        if inner.shutting.load(Ordering::SeqCst) {
            return Ok(());
        }
        let resolved = inner.resolve_child_id(parent, child)?;
        let child = &resolved;
        inner.check_child(parent, child)?;
        inner.stop_and_wait(std::slice::from_ref(child)).await;
        Ok(())
    }

    async fn stop_children(&self, parent: &SessionId) {
        let Some(inner) = self.0.upgrade() else { return };
        if inner.shutting.load(Ordering::SeqCst) {
            return;
        }
        let running: Vec<SessionId> = {
            let st = inner.st();
            st.known
                .iter()
                .filter(|(_, k)| k.meta.parent.as_ref() == Some(parent) && !k.finished())
                .map(|(id, _)| id.clone())
                .collect()
        };
        inner.stop_and_wait(&running).await;
    }

    async fn message_child(&self, parent: &SessionId, child: &SessionId, text: &str) -> Result<(), String> {
        let inner = self.up()?;
        let resolved = inner.resolve_child_id(parent, child)?;
        let child = &resolved;
        inner.check_child(parent, child)?;
        let activated = {
            let _g = lock(&inner.activation);
            inner.activate_locked(child)
        };
        activated?;
        if inner.send_input(child, Input::AgentMessage { from: parent.clone(), text: text.to_string() }) {
            Ok(())
        } else {
            Err(format!("{} is not running.", child.as_str()))
        }
    }

    async fn children(&self, parent: &SessionId) -> Vec<ChildInfo> {
        let Some(inner) = self.0.upgrade() else { return Vec::new() };
        let st = inner.st();
        // The finish gate's verifiers are the harness's, not agents the session started: nothing waits
        // for them or is refused because of them, and their verdicts go to `finish` only.
        st.known
            .iter()
            .filter(|(_, k)| k.meta.parent.as_ref() == Some(parent) && k.gate.is_none())
            .map(|(id, k)| ChildInfo {
                id: id.clone(),
                role: k.meta.role.clone(),
                title: k.meta.title.clone(),
                step: k.status.step,
                running: !k.finished(),
            })
            .collect()
    }

    async fn child_role(&self, parent: &SessionId, child: &SessionId) -> Option<String> {
        let inner = self.0.upgrade()?;
        let st = inner.st();
        st.known.get(child).filter(|k| k.meta.parent.as_ref() == Some(parent)).map(|k| k.meta.role.clone())
    }

    async fn resolve_child(&self, parent: &SessionId, child: &SessionId) -> Result<SessionId, String> {
        self.up()?.resolve_child_id(parent, child)
    }

    async fn poll(
        &self,
        session: &SessionId,
        question: &str,
        options: &[String],
        k: u32,
        cancel: &CancellationToken,
    ) -> Result<Vec<Vote>, String> {
        let inner = self.up()?;
        let (fork_point, profile) = {
            let st = inner.st();
            let known = st.known.get(session).ok_or_else(|| no_session(session))?;
            (known.status.fork_point, known.meta.profile.clone())
        };
        let Some(fork_point) = fork_point else {
            return Err(
                "Nothing has been sent to the model in this session yet, so there is nothing to vote on.".to_string()
            );
        };
        let rt =
            inner.profiles.get(&profile).ok_or_else(|| format!("model profile \"{profile}\" is not configured."))?;
        let records = read_records(&inner.paths.session_log(session)).map_err(|e| e.to_string())?.records;
        let upto: Vec<Record> = records.into_iter().filter(|r| r.seq <= fork_point).collect();
        let w = weave(&upto);
        let mut messages = w.messages.clone();
        messages.push(loom_core::Message::user(texts::vote_prompt(question, options)));
        let n_options = options.len();
        let votes = futures_util::future::join_all((1..=u64::from(k)).map(|seed| {
            let request = ChatRequest {
                messages: messages.clone(),
                tools: w.tools.clone(),
                tool_choice: ToolChoice::Auto,
                max_tokens: Some(texts::VOTE_MAX_TOKENS),
                seed: Some(seed),
                extra: serde_json::Map::new(),
            };
            let client = rt.client.clone();
            let limiter = rt.limiter.clone();
            async move {
                let Some(_permit) = limiter.acquire(Priority::Child, cancel).await else {
                    return Vote { option: None, reason: "Interrupted before the votes were in.".to_string() };
                };
                match client.complete(&request, None, cancel).await {
                    Ok(c) => {
                        let (option, reason) = texts::parse_vote(&c.text, n_options);
                        Vote { option, reason }
                    }
                    Err(e) => Vote { option: None, reason: texts::sentence(&e.to_string()) },
                }
            }
        }))
        .await;
        if cancel.is_cancelled() {
            return Err("Interrupted before the votes were in.".to_string());
        }
        Ok(votes)
    }

    async fn producer(&self, mission: &MissionId, blob: &BlobId) -> Option<Producer> {
        let inner = self.0.upgrade()?;
        let key = (mission.clone(), blob.clone());
        if let Some(p) = inner.st().producers.get(&key) {
            return Some(p.clone());
        }
        inner.scan_outputs(mission).await;
        let found = inner.st().producers.get(&key).cloned();
        found
    }
}

/// The outputs of one mission, for the tools of one of its sessions (`loom_tools::outputs`).
struct MissionOutputs {
    runtime: Weak<Inner>,
    mission: MissionId,
}

#[async_trait]
impl OutputScope for MissionOutputs {
    async fn holds(&self, blob: &BlobId) -> bool {
        let Some(inner) = self.runtime.upgrade() else { return false };
        let key = (self.mission.clone(), blob.clone());
        if inner.holds_output(&key) {
            return true;
        }
        inner.scan_outputs(&self.mission).await;
        inner.holds_output(&key)
    }

    async fn ready(&self) {
        if let Some(inner) = self.runtime.upgrade() {
            inner.scan_outputs(&self.mission).await;
        }
    }
}

// ---- the runtime ------------------------------------------------------------------------------

impl Inner {
    fn st(&self) -> MutexGuard<'_, State> {
        lock(&self.state)
    }

    fn publish(&self, event: BusEvent) {
        let _ = self.bus.send(event);
    }

    fn publish_error(&self, session: Option<&SessionId>, message: String) {
        self.publish(BusEvent::Error { session: session.cloned(), message });
    }

    fn check_open(&self) -> Result<(), String> {
        if self.shutting.load(Ordering::SeqCst) {
            Err(SHUTTING.to_string())
        } else {
            Ok(())
        }
    }

    fn me(&self) -> Option<Arc<Inner>> {
        self.me.upgrade()
    }

    fn info_of(k: &Known) -> SessionInfo {
        SessionInfo { meta: k.meta.clone(), active: k.active.is_some(), status: k.status.clone() }
    }

    /// Send `input` to an active session. False when no task drives it.
    fn send_input(&self, id: &SessionId, input: Input) -> bool {
        let st = self.st();
        match st.known.get(id).and_then(|k| k.active.as_ref()) {
            Some(a) => a.inputs.send(input).is_ok(),
            None => false,
        }
    }

    /// Stop one session: cancel its turn and tell it.
    fn stop_one(&self, id: &SessionId) {
        let st = self.st();
        if let Some(a) = st.known.get(id).and_then(|k| k.active.as_ref()) {
            a.control.stop_turn();
            let _ = a.inputs.send(Input::Stop);
        }
    }

    /// Stop the agents `ids` and wait until they have settled, up to the kill grace of their running
    /// commands plus [`STOP_SETTLE_WAIT`]. An agent settles in its own task: an idle one at once, a
    /// working one when its turn has unwound. Waiting lets the caller say what really happened.
    async fn stop_and_wait(&self, ids: &[SessionId]) {
        // Only an agent with a task can settle: one without is not waited for.
        let settled: Vec<watch::Receiver<Option<Settlement>>> = {
            let st = self.st();
            ids.iter()
                .filter_map(|id| st.known.get(id).filter(|k| k.active.is_some()).map(|k| k.settled_tx.subscribe()))
                .collect()
        };
        for id in ids {
            self.stop_one(id);
        }
        let wait = Duration::from_secs(self.config.tools.kill_grace_s).saturating_add(STOP_SETTLE_WAIT);
        let all = futures_util::future::join_all(settled.into_iter().map(|mut rx| async move {
            // The `Ref` is dropped at once: one held would block the next send on its channel.
            rx.wait_for(Option::is_some).await.is_ok()
        }));
        let _ = tokio::time::timeout(wait, all).await;
    }

    /// Wait until no task of `ids` is ending after its inputs were closed (an archive), up to the kill
    /// grace of its jobs plus [`SHUTDOWN_TASK_WAIT`], as a shutdown waits for its tasks.
    async fn until_closed(&self, ids: &[SessionId]) {
        let wait = Duration::from_secs(self.config.tools.kill_grace_s).saturating_add(SHUTDOWN_TASK_WAIT);
        let begun = tokio::time::Instant::now();
        loop {
            let closing = {
                let st = self.st();
                let closed = |id: &SessionId| {
                    st.known.get(id).and_then(|k| k.active.as_ref()).is_some_and(|a| a.inputs.is_closed())
                };
                ids.iter().any(closed)
            };
            if !closing || begun.elapsed() >= wait {
                return;
            }
            tokio::time::sleep(SHUTDOWN_POLL).await;
        }
    }

    /// Resolve only within this parent's actual children, retaining exact-ID precedence.
    fn resolve_child_id(&self, parent: &SessionId, wanted: &SessionId) -> Result<SessionId, String> {
        let st = self.st();
        let own: Vec<_> = st.known.iter().filter(|(_, k)| k.meta.parent.as_ref() == Some(parent)).collect();
        if own.iter().any(|(id, _)| *id == wanted) {
            return Ok(wanted.clone());
        }
        if wanted.as_str() == "last" {
            return own
                .into_iter()
                .max_by(|(a, ka), (b, kb)| ka.meta.created_ms.cmp(&kb.meta.created_ms).then_with(|| a.cmp(b)))
                .map(|(id, _)| id.clone())
                .ok_or_else(|| "This session has no child agents; start one before using last.".into());
        }
        if wanted.as_str().len() < 4 {
            return Err("Use an exact child ID, last, or an unambiguous prefix of at least four characters.".into());
        }
        let mut matches = own.into_iter().filter(|(id, _)| id.as_str().starts_with(wanted.as_str()));
        let first = matches.next().map(|(id, _)| id.clone());
        if matches.next().is_some() {
            return Err(format!("Child prefix {} is ambiguous; give more characters or its exact ID.", wanted));
        }
        first.ok_or_else(|| format!("{} {NOT_YOURS}", wanted.as_str()))
    }

    fn check_child(&self, parent: &SessionId, child: &SessionId) -> Result<(), String> {
        let st = self.st();
        match st.known.get(child).filter(|k| k.meta.parent.as_ref() == Some(parent)) {
            None => Err(format!("{} {NOT_YOURS}", child.as_str())),
            Some(k) if k.finished() => {
                Err(format!("{} has already finished ({}).", child.as_str(), texts::outcome_word(k.outcome())))
            }
            Some(_) => Ok(()),
        }
    }

    /// Whether the indexes already hold `key` as an output of its mission.
    fn holds_output(&self, key: &(MissionId, BlobId)) -> bool {
        let st = self.st();
        st.producers.contains_key(key) || st.extra_outputs.contains(key)
    }

    /// Read the logs of every session of `mission` once (off the async workers) and fill the producer index
    /// and the index of other outputs from them. Does nothing for a mission already scanned.
    async fn scan_outputs(self: &Arc<Self>, mission: &MissionId) {
        if self.st().scanned.contains(mission) {
            return;
        }
        // One scan at a time: a second caller waits for the first and then finds the mission scanned.
        let _one = self.scan_lock.lock().await;
        let ids = {
            let st = self.st();
            if st.scanned.contains(mission) {
                return;
            }
            st.known.iter().filter(|(_, k)| &k.meta.mission == mission).map(|(id, _)| id.clone()).collect::<Vec<_>>()
        };
        let paths = self.paths.clone();
        let scanned = tokio::task::spawn_blocking(move || {
            let mut out: Vec<(BlobId, Producer)> = Vec::new();
            let mut extra: Vec<BlobId> = Vec::new();
            let mut jobs: HashMap<(SessionId, String), Producer> = HashMap::new();
            for id in ids {
                let Ok(report) = read_records(&paths.session_log(&id)) else { continue };
                for r in own_records(&report.records) {
                    out.extend(produced_by(&id, &mut jobs, &r.event));
                    extra.extend(also_outputs(&r.event));
                }
            }
            (out, extra)
        })
        .await;
        // A scan that did not finish says nothing about the mission: it is tried again at the next miss.
        let Ok((found, extra)) = scanned else { return };
        let mut st = self.st();
        for (b, p) in found {
            let owner = st.known.get(&p.session).map(|k| k.meta.mission.clone());
            if let Some(m) = owner {
                st.producers.entry((m, b)).or_insert(p);
            }
        }
        for b in extra {
            st.extra_outputs.insert((mission.clone(), b));
        }
        st.scanned.insert(mission.clone());
    }

    // ---- sink -------------------------------------------------------------------------------

    fn on_record(self: &Arc<Self>, session: &SessionId, record: &Record) {
        let mut opened: Option<(InboxItem, String)> = None;
        {
            let mut st = self.st();
            let found = st.known.get(session).map(|k| (k.meta.mission.clone(), k.meta.title.clone()));
            if let Some((mission, title)) = found {
                match &record.event {
                    Event::ToolResult(_)
                    | Event::JobRegistered { .. }
                    | Event::JobSettled { .. }
                    | Event::JobMatched { .. }
                    | Event::ChildSettled(_)
                    | Event::ChildCompleted(_) => {
                        if let Some((blob, p)) = produced_by(session, &mut st.job_starts, &record.event) {
                            st.producers.entry((mission.clone(), blob)).or_insert(p);
                        }
                        for blob in also_outputs(&record.event) {
                            st.extra_outputs.insert((mission.clone(), blob));
                        }
                    }
                    Event::InboxOpened(item) => {
                        st.inbox.retain(|e| e.item.item_id != item.item_id);
                        st.inbox.push(InboxEntry {
                            session: session.clone(),
                            mission,
                            title: title.clone(),
                            opened_ms: record.ts_ms,
                            item: item.clone(),
                        });
                        opened = Some((item.clone(), title));
                    }
                    Event::InboxResolved { item_id, .. } => st.inbox.retain(|e| &e.item.item_id != item_id),
                    _ => {}
                }
            }
        }
        if let Some((item, title)) = opened {
            let kind = inbox_kind_word(&item);
            self.notify(&kind, session, &title, &notice_text(&item, false));
            if item.blocking && self.config.notify.repeat_minutes > 0 {
                self.repeat_notice(&kind, session, &title, &item);
            }
        }
        self.publish(BusEvent::Record { session: session.clone(), record: Box::new(record.clone()) });
    }

    fn on_status(&self, session: &SessionId, status: &Status) {
        let held: Vec<SessionId> = {
            let mut st = self.st();
            let started = match st.known.get_mut(session) {
                Some(k) => {
                    let started = k.status.phase != Phase::Running && status.phase == Phase::Running;
                    k.status = status.clone();
                    if status.phase == Phase::Running {
                        k.held = false;
                    }
                    started
                }
                None => false,
            };
            // A lead that starts a turn, whatever started it, takes the agents a restart left idle along.
            if started {
                let mine = |k: &Known| k.held && k.meta.parent.as_ref() == Some(session);
                st.known.iter().filter(|(_, k)| mine(k)).map(|(id, _)| id.clone()).collect()
            } else {
                Vec::new()
            }
        };
        for id in &held {
            self.resume_held(id);
        }
        let dir = self.paths.session_dir(session);
        if dir.is_dir() {
            if let Err(e) = write_json_atomic(&dir.join("status.json"), status) {
                tracing::warn!("cannot write status.json of {}: {e}", session.as_str());
            }
        }
        self.publish(BusEvent::Status { session: session.clone(), status: status.clone() });
    }

    // ---- notifications ----------------------------------------------------------------------

    fn notify(&self, kind: &str, session: &SessionId, title: &str, text: &str) {
        let command = self.config.notify.command.clone();
        // A child's title is the question the model gave when it started it.
        let child = self.st().known.get(session).is_some_and(|k| k.meta.parent.is_some());
        let title = notice_title(title, child);
        let (kind, session, text) = (kind.to_string(), session.as_str().to_string(), text.to_string());
        tokio::spawn(async move { run_notify(command, kind, session, title, text).await });
    }

    /// The result of a disk check. Raises one notification when the disk turns low, and none again until a check
    /// found it recovered and it turned low once more.
    fn note_disk(&self, low: bool) {
        if self.disk_low.swap(low, Ordering::SeqCst) != low && low {
            self.notify("disk", &SessionId::from(""), "Low disk space", LOW_DISK_NOTICE);
        }
    }

    /// Empty the scratch directory of a session that can no longer run commands (see `clear_scratch_dir`).
    fn clear_scratch(&self, id: &SessionId) -> tokio::task::JoinHandle<()> {
        clear_scratch_dir(self.paths.session_tmp(id))
    }

    /// The scratch directory of `id`, whose task ended `Closed`, when it can run no command again: an archive
    /// closed it, or its log had ended. `None` otherwise (a shutdown, which the next start goes on from).
    fn scratch_after_close(&self, id: &SessionId) -> Option<PathBuf> {
        let st = self.st();
        let over = st.known.get(id).is_some_and(|k| k.meta.archived || k.status.phase == Phase::Ended);
        over.then(|| self.paths.session_tmp(id))
    }

    fn repeat_notice(self: &Arc<Self>, kind: &str, session: &SessionId, title: &str, item: &InboxItem) {
        let weak = self.me.clone();
        let (kind, session, title, item) = (kind.to_string(), session.clone(), title.to_string(), item.clone());
        let every = Duration::from_secs(u64::from(self.config.notify.repeat_minutes) * 60);
        let task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                let Some(inner) = weak.upgrade() else { return };
                if inner.shutting.load(Ordering::SeqCst) {
                    return;
                }
                let open = inner.st().inbox.iter().any(|e| e.item.item_id == item.item_id);
                if !open {
                    return;
                }
                inner.notify(&kind, &session, &title, &notice_text(&item, false));
            }
        });
        self.st().tasks.push(task);
    }

    /// After a restart: every open blocking item that was restored is notified once as still waiting, and its
    /// repeat notice is armed as it is for an item opened live.
    fn renotify_open_blocking(self: &Arc<Self>) {
        let open: Vec<InboxEntry> = self.st().inbox.iter().filter(|e| e.item.blocking).cloned().collect();
        for entry in open {
            let kind = inbox_kind_word(&entry.item);
            self.notify(&kind, &entry.session, &entry.title, &notice_text(&entry.item, true));
            if self.config.notify.repeat_minutes > 0 {
                self.repeat_notice(&kind, &entry.session, &entry.title, &entry.item);
            }
        }
    }

    /// Kill what a crashed daemon left running in the jobs directories of the sessions it knows, including the ones
    /// nobody activates (a session that was idle at the crash). Runs off the async workers; logs what it did.
    /// `activating` are left out: their job tables clear them when built, and one whose activation fails keeps its
    /// records for the next start. The output and status of a command that ended by itself stay for its session to
    /// take when it is next opened.
    async fn clear_crash_leftovers(&self, activating: &[SessionId]) {
        let dirs: Vec<(SessionId, PathBuf)> = {
            let st = self.st();
            st.known
                .iter()
                .filter(|(id, k)| !k.meta.archived && !activating.contains(id))
                .map(|(id, _)| (id.clone(), self.paths.session_dir(id).join("jobs")))
                .collect()
        };
        let swept = tokio::task::spawn_blocking(move || {
            let mut out = Vec::new();
            for (id, dir) in dirs {
                let has_records = std::fs::read_dir(&dir)
                    .is_ok_and(|d| d.flatten().any(|e| e.path().extension().and_then(|x| x.to_str()) == Some("pid")));
                if has_records {
                    out.push((id, loom_tools::jobs::clear_leftovers(&dir)));
                }
            }
            out
        })
        .await;
        match swept {
            Ok(swept) => {
                for (id, found) in swept.into_iter().filter(|(_, f)| !f.is_empty()) {
                    let killed = found.iter().filter(|l| l.killed).count();
                    let left = found.iter().filter(|l| l.left_running).count();
                    let ended = found.iter().filter(|l| l.ended_by_itself()).count();
                    tracing::warn!(
                        session = id.as_str(),
                        "cleared {} command(s) a previous daemon left behind: {killed} killed, {left} left alone because their process group could not be confirmed, {ended} had ended by themselves (their status and output are kept for the session)",
                        found.len()
                    );
                }
            }
            Err(e) => tracing::warn!("the sweep for a previous daemon's commands did not finish: {e}"),
        }
    }

    // ---- building a session -----------------------------------------------------------------

    /// Whether the mission of `meta` keeps a ledger (its root role ends explicitly).
    fn mission_explicit(&self, meta: &SessionMeta) -> Result<bool, String> {
        let root_meta = match &meta.parent {
            None => meta.clone(),
            Some(p) => self.st().known.get(p).map(|k| k.meta.clone()).ok_or_else(|| no_session(p))?,
        };
        Ok(self.packs.role(Some(&root_meta.pack), Some(&root_meta.role))?.termination == Termination::Explicit)
    }

    /// Sessions of a pack whose text says the network is restricted do not run while it is open.
    fn check_network(&self, pack: &str) -> Result<(), String> {
        if self.config.network.mode == NetworkMode::Open
            && self.packs.get(pack).is_some_and(|p| p.requires_restricted_network)
        {
            return Err(format!(
                "The pack \"{pack}\" needs a restricted network, but the network mode is open, so its sessions are not run. Set [network] mode = \"allowlist\" (or \"deny_all\") in the config and restart the daemon."
            ));
        }
        Ok(())
    }

    // ---- the box -----------------------------------------------------------------------------

    /// The lead session of `mission`, as it is known.
    fn mission_lead(&self, mission: &MissionId) -> Option<SessionMeta> {
        let st = self.st();
        st.known.values().find(|k| k.meta.parent.is_none() && &k.meta.mission == mission).map(|k| k.meta.clone())
    }

    /// What a mission's box may reach: the hosts granted to the mission and the effective policy of its
    /// sessions, as they are at this moment.
    fn box_egress(&self, mission: &MissionId) -> Result<(Vec<String>, Policy), String> {
        let lead = self
            .mission_lead(mission)
            .ok_or_else(|| format!("The mission {} has no lead session.", mission.as_str()))?;
        let explicit = self.mission_explicit(&lead)?;
        Ok((self.granted_hosts(&lead, explicit), self.session_policy(&lead, explicit)?))
    }

    /// The box of the mission `session` belongs to, made when it is first asked for (its container is
    /// made by the first command). The error sentences are the ones the box tools return.
    fn box_for(&self, session: &SessionId) -> Result<Arc<MissionBox>, String> {
        let host = self.box_host.clone().ok_or_else(|| rtools::boxtools::NO_BOX.to_string())?;
        let meta = self.st().known.get(session).map(|k| k.meta.clone()).ok_or_else(|| no_session(session))?;
        if meta.copy_of.is_some() {
            return Err(rtools::boxtools::BOX_IN_COPY.to_string());
        }
        if meta.archived {
            return Err("This session is archived; unarchive it first.".to_string());
        }
        let mut st = self.st();
        if st.box_closed.contains(&meta.mission) {
            return Err(rtools::boxtools::BOX_CLOSED.to_string());
        }
        if let Some(b) = st.boxes.get(&meta.mission) {
            return Ok(b.clone());
        }
        let (weak, mission) = (self.me.clone(), meta.mission.clone());
        let source: loom_tools::boxctl::EgressSource = Arc::new(move || {
            let inner = weak.upgrade().ok_or_else(|| SHUTTING.to_string())?;
            inner.box_egress(&mission)
        });
        let made = MissionBox::new(host, meta.mission.as_str(), source);
        st.boxes.insert(meta.mission, made.clone());
        Ok(made)
    }

    /// The mission's lead runs again: its box may be made again.
    fn box_reopen(&self, mission: &MissionId) {
        self.st().box_closed.remove(mission);
    }

    /// `session` was activated by an operator message, an inbox answer or a rule: when it is a lead, its
    /// mission runs again, so its box may be made again (a message to a stopped lead reopens it).
    fn box_reopen_for(&self, session: &SessionId) {
        let mut st = self.st();
        let mission = st.known.get(session).filter(|k| k.meta.parent.is_none()).map(|k| k.meta.mission.clone());
        if let Some(m) = mission {
            st.box_closed.remove(&m);
        }
    }

    /// Whether the daemon still has a use for the box of mission `m`: its lead has a task, or a box handle
    /// for it exists (made after the start's listing of leftovers).
    fn box_in_use(&self, m: &str) -> bool {
        let st = self.st();
        st.known.values().any(|k| k.meta.parent.is_none() && k.active.is_some() && k.meta.mission.as_str() == m)
            || st.boxes.keys().any(|b| b.as_str() == m)
    }

    /// Bring the rules of the mission's box, when it has one, to the mission's grants of now (I5).
    async fn box_resync(&self, mission: &MissionId) {
        let b = self.st().boxes.get(mission).cloned();
        if let Some(b) = b {
            b.resync().await;
        }
    }

    /// Remove the mission's box (container, network, rules), in the background, best effort (I5), and keep it
    /// down: no box is made for the mission again until its lead is resumed (`box_reopen`).
    fn box_teardown(&self, mission: &MissionId) {
        let Some(host) = self.box_host.clone() else { return };
        let known = {
            let mut st = self.st();
            st.box_closed.insert(mission.clone());
            st.boxes.remove(mission)
        };
        let mission = mission.clone();
        let task = tokio::spawn(async move {
            match known {
                Some(b) => b.teardown().await,
                // Not asked for by this run of the daemon: what an earlier run left is removed by name.
                None => loom_tools::boxctl::teardown_mission(&host, mission.as_str()).await,
            }
        });
        // Not tracked: it ends by itself, and a shutdown does not wait for the Docker host.
        drop(task);
    }

    /// At start: remove what boxes of this loom home left on the Docker host for missions that have no
    /// running lead (I5). In the background; the daemon does not wait for the Docker host.
    fn reconcile_boxes(self: &Arc<Self>) {
        let Some(host) = self.box_host.clone() else { return };
        // Asked for each mission once the mission's lock is held, so that a mission that started after this
        // listing began is not removed from under itself.
        let weak = self.me.clone();
        let task = tokio::spawn(async move {
            let keep = move |mission: &str| weak.upgrade().is_none_or(|inner| inner.box_in_use(mission));
            let cleaned = loom_tools::boxctl::reconcile(&host, &keep).await;
            if !cleaned.is_empty() {
                tracing::info!("box: removed what {} mission(s) left on the Docker host", cleaned.len());
            }
        });
        self.st().tasks.push(task);
    }

    /// The hosts the operator has authorized for the mission of `meta`: those in its ledger (when it
    /// keeps one) and those granted since the daemon started, de-duplicated ignoring case.
    fn granted_hosts(&self, meta: &SessionMeta, explicit: bool) -> Vec<String> {
        let mut hosts: Vec<String> = Vec::new();
        if explicit {
            // A journal not written yet reads as an empty ledger.
            let journal = Journal::new(self.paths.journal(&meta.mission), self.key.clone());
            match journal.state() {
                Ok(state) => hosts = state.granted_hosts(),
                Err(e) => tracing::warn!(session = %meta.id, "granted hosts not read from the ledger: {e}"),
            }
        }
        let mut st = self.st();
        for h in st.scope.get(&meta.mission).into_iter().flatten() {
            if !hosts.iter().any(|x| x.eq_ignore_ascii_case(h)) {
                hosts.push(h.clone());
            }
        }
        // What the operator revoked leaves at once, recorded or not (the overlay is kept on disk).
        let revoked = st
            .scope_revoked
            .entry(meta.mission.clone())
            .or_insert_with(|| load_revoked(&self.revoked_path(&meta.mission)));
        hosts.retain(|h| !revoked.iter().any(|r| r.eq_ignore_ascii_case(h)));
        hosts
    }

    /// Where the hosts the operator revoked from `mission` are kept, so that a revoke the ledger does not
    /// hold (a grant still queued for the lead) survives a restart.
    fn revoked_path(&self, mission: &MissionId) -> PathBuf {
        self.paths.mission_dir(mission).join("scope_revoked.json")
    }

    /// The hosts revoked from `mission` (kept on disk, read once).
    fn revoked_hosts(&self, mission: &MissionId) -> Vec<String> {
        let mut st = self.st();
        st.scope_revoked.entry(mission.clone()).or_insert_with(|| load_revoked(&self.revoked_path(mission))).clone()
    }

    /// Write the revoked hosts of `mission` durably.
    fn save_revoked(&self, mission: &MissionId, hosts: &[String]) -> Result<(), String> {
        let path = self.revoked_path(mission);
        let dir = path.parent().ok_or_else(|| format!("{} has no directory", path.display()))?;
        ensure_private_dir(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        let text = serde_json::to_vec(hosts).map_err(|e| e.to_string())?;
        let tmp = dir.join(".scope_revoked.json.tmp");
        std::fs::write(&tmp, text)
            .and_then(|()| std::fs::rename(&tmp, &path))
            .map_err(|e| format!("cannot write {}: {e}", path.display()))
    }

    /// The generation of the mission's grants and revokes.
    fn scope_generation(&self, mission: &MissionId) -> u64 {
        self.st().scope_gen.get(mission).copied().unwrap_or(0)
    }

    /// A grant or revoke of `mission` is about to be applied to its sessions.
    fn bump_scope_generation(&self, mission: &MissionId) {
        let mut st = self.st();
        let g = st.scope_gen.entry(mission.clone()).or_insert(0);
        *g = g.wrapping_add(1);
    }

    /// After a session's proxy grant was made from a policy derived at generation `built`: when the mission's
    /// grants changed since, derive the policy again and give it to the session. A grant or revoke that
    /// comes later finds the session's proxy grant and sets its own policy.
    fn policy_is_current(&self, meta: &SessionMeta, explicit: bool, built: u64) {
        if self.scope_generation(&meta.mission) == built {
            return;
        }
        match self.session_policy(meta, explicit) {
            Ok(policy) => {
                self.proxy.set_policy(&meta.id, policy);
            }
            Err(e) => tracing::warn!(session = %meta.id, "policy not derived again after a scope change: {e}"),
        }
    }

    /// The proxy policy of a session: the configured network plus the mission's granted hosts. A
    /// granted host that cannot be parsed is left out (with a warning), which only narrows the policy.
    /// The infrastructure that policy refuses to every command, grants or not (E1), is added last.
    fn session_policy(&self, meta: &SessionMeta, explicit: bool) -> Result<Policy, String> {
        let hosts = self.granted_hosts(meta, explicit);
        let policy = match Policy::with_hosts(&self.config.network, &hosts) {
            Ok(p) => Ok(p),
            Err(e) if !hosts.is_empty() => {
                tracing::warn!(session = %meta.id, "granted hosts ignored: {e}");
                Policy::new(&self.config.network)
            }
            Err(e) => Err(e),
        }?;
        let revoked = self.revoked_hosts(&meta.mission);
        let policy = match policy.clone().with_revoked(&revoked) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(session = %meta.id, "revoked hosts ignored: {e}");
                policy
            }
        };
        policy.with_infrastructure(&infra_spec_resolved(&self.config, &self.infra()))
    }

    /// The `Deps` of a session (granting it its proxy credentials).
    fn build(&self, meta: &SessionMeta, explicit: bool) -> Result<(Deps, Parts), String> {
        let role = self.packs.role(Some(&meta.pack), Some(&meta.role))?.clone();
        let profile = self
            .profiles
            .get(&meta.profile)
            .ok_or_else(|| format!("The model profile \"{}\" is not in the configuration.", meta.profile))?;
        let id = &meta.id;
        let workspace = std::fs::canonicalize(&meta.workspace)
            .map_err(|e| format!("The workspace {} cannot be used: {e}", meta.workspace))?;
        let tmp = self.paths.session_tmp(id);
        loom_core::config::ensure_private_dir(&tmp).map_err(|e| format!("cannot create {}: {e}", tmp.display()))?;
        let tmp = std::fs::canonicalize(&tmp).map_err(|e| format!("cannot resolve {}: {e}", tmp.display()))?;
        let copies = self.paths.copies_dir();
        let cfg = with_copies(
            sandbox_cfg_for(&self.config.sandbox, &role, &workspace, &self.config.models),
            &copies,
            meta.copy_of.as_deref(),
        );
        let bubblewrap = cfg.mode == loom_core::config::SandboxMode::Bubblewrap;
        if bubblewrap {
            // Bubblewrap can keep a replay out of a directory only when the directory exists.
            let _ = ensure_private_dir(&copies);
        }
        if bubblewrap && self.config.network.mode != loom_core::config::NetworkMode::DenyAll {
            return Err("Bubblewrap requires network.mode = deny_all. Explicit mission grants apply only to trusted in-process HTTP tools; subprocess proxy bridges are unsupported.".into());
        }
        let jobs_dir = self.paths.session_dir(id).join("jobs");
        let built_at = self.scope_generation(&meta.mission);
        let policy = self.session_policy(meta, explicit)?;
        // The session's own proxy listener comes first: its port is the only one the sandbox allows.
        let grant = self
            .proxy
            .grant(id, policy)
            .map_err(|e| format!("The egress proxy cannot open a port for this session: {e}"))?;
        // A grant or revoke that ran while the policy was being derived reached no proxy grant of this session.
        self.policy_is_current(meta, explicit, built_at);
        // From here a failure takes the grant, and with it the listener, back.
        let mut revoke = RevokeOnDrop { proxy: &self.proxy, session: id, armed: true };
        let sandbox = Sandbox::new(&cfg, &workspace, &tmp, &self.paths.home, (!bubblewrap).then_some(grant.port))
            .and_then(|s| s.with_jobs_dir(&jobs_dir))
            .and_then(|s| s.with_identity(id.as_str()))
            .map_err(|e| format!("The sandbox for this session cannot be set up: {e}"))?;
        let (events_tx, job_events) = unbounded_channel();
        let jobs = Arc::new(JobTable::new(jobs_dir, self.blobs.clone(), events_tx, self.config.tools.max_output_bytes));
        let reference_proxy = if self.config.network.reference_hosts.is_empty() {
            None
        } else {
            Some(self.proxy.grant_reference(id, &self.config.network)?)
        };
        let pack = self.packs.get(&meta.pack).ok_or_else(|| format!("Pack {} is no longer loaded.", meta.pack))?;
        let ctx = ToolCtx {
            session: id.clone(),
            call_id: CallId::from(""),
            workspace,
            tmp_dir: tmp,
            blobs: self.blobs.clone(),
            outputs: Arc::new(MissionOutputs { runtime: self.me.clone(), mission: meta.mission.clone() }),
            cfg: Arc::new(self.config.tools.clone()),
            sandbox: Arc::new(sandbox),
            env: Arc::new(grant.env()),
            reference_proxy,
            files: Arc::new(loom_tools::files::FileTracker::new()),
            jobs: jobs.clone(),
            cancel: CancellationToken::new(),
            capabilities: Arc::new(loom_tools::capabilities::SessionTools::new(
                pack.command_guard,
                pack.target_concurrency,
            )),
            // The session sets it again for every call from its admission of that moment.
            view_chars: self
                .config
                .admit
                .for_window(meta.context_window)
                .view_chars(&loom_core::estimate::TokenEstimator::default()),
        };
        // The mission journal is shared by the lead and all its children; a child is always bound to
        // it, so that it has explicit access to the mission state.
        let journal = (explicit || meta.parent.is_some())
            .then(|| Journal::new(self.paths.journal(&meta.mission), self.key.clone()));
        // The stall note asks for a ledger record (`note`, or `claim` with `evidence`): a role that
        // can write none (a verifier) is not given it.
        let mut agents = self.config.agents.clone();
        if !role.tools.iter().any(|t| matches!(t.as_str(), "note" | "claim" | "evidence")) {
            agents.stall_steps = 0;
        }
        let shared = Arc::new(Shared::new(
            id.clone(),
            Some(meta.mission.clone()),
            meta.parent.clone(),
            role,
            journal,
            self.paths.session_log(id),
            self.config.agents.clone(),
            self.orch.clone(),
        ));
        let control = Arc::new(Control::new());
        let deps = Deps {
            paths: self.paths.clone(),
            agents,
            context: self.config.context.clone(),
            admit: self.config.admit.clone(),
            client: profile.client.clone(),
            limiter: profile.limiter.clone(),
            priority: if meta.parent.is_some() { Priority::Child } else { Priority::Lead },
            context_window: meta.context_window,
            shared: shared.clone(),
            ctx,
            job_events,
            sink: self.sink.clone(),
            control: control.clone(),
        };
        revoke.armed = false;
        Ok((deps, Parts { control, shared, jobs }))
    }

    /// The `session_start` of a session whose `deps` were built.
    fn start_record(&self, meta: &SessionMeta, deps: &Deps, budget: Budget) -> Result<SessionStart, String> {
        let role = &deps.shared.role;
        let pack = self.packs.get(&meta.pack).ok_or_else(|| format!("There is no pack \"{}\".", meta.pack))?;
        let env = PromptEnv {
            workspace: deps.ctx.workspace.display().to_string(),
            platform: format!("{} ({})", std::env::consts::OS, std::env::consts::ARCH),
            sandbox: deps.ctx.sandbox.describe(),
            network: network_text(&self.config),
        };
        let replay = self.config.models.get(&meta.profile).map(|p| p.reasoning_replay).unwrap_or_default();
        Ok(SessionStart {
            session: meta.id.clone(),
            mission: meta.mission.clone(),
            parent: meta.parent.clone(),
            workspace: deps.ctx.workspace.display().to_string(),
            pack: meta.pack.clone(),
            role: meta.role.clone(),
            termination: role.termination,
            model: ModelRef {
                profile: meta.profile.clone(),
                model: meta.model.clone(),
                context_window: meta.context_window.unwrap_or(0),
            },
            reasoning_replay: replay,
            system_prompt: pack::system_prompt(role, &pack.preamble, &env),
            tools: Vec::new(),
            budget,
            unattended: meta.unattended,
            schema: loom_core::event::SCHEMA,
            title: meta.title.clone(),
        })
    }

    /// Spawn the task driving `session` and record it as the active one of `id`. The state lock is
    /// held by the caller so that the task cannot end before it is recorded.
    fn launch(self: &Arc<Self>, st: &mut State, id: &SessionId, session: Session, parts: Parts) {
        let Parts { control, shared, jobs } = parts;
        let gen = self.next_gen.fetch_add(1, Ordering::SeqCst);
        let (inputs, rx) = unbounded_channel();
        let weak = self.me.clone();
        let sid = id.clone();
        let is_child = st.known.get(id).is_some_and(|k| k.meta.parent.is_some());
        #[cfg(test)]
        let title = st.known.get(id).map(|k| k.meta.title.clone()).unwrap_or_default();
        let task = tokio::spawn(async move {
            let run = async move {
                #[cfg(test)]
                if lock(&PANIC_TITLES).contains(&title) {
                    panic!("test hook: this session's task panics");
                }
                session.run(rx).await
            };
            // A panic must still reach `on_end`, or the session would stay active and its parent
            // would wait for it for ever.
            let end = match std::panic::AssertUnwindSafe(run).catch_unwind().await {
                Ok(end) => end,
                Err(payload) => End::Fatal(texts::task_failed(&panic_message(payload.as_ref()), is_child)),
            };
            // Emptied while the task still holds the session's place, so that nothing starts it again (an
            // unarchive waits for the task) while the removal runs.
            if matches!(end, End::Closed) {
                if let Some(dir) = weak.upgrade().and_then(|inner| inner.scratch_after_close(&sid)) {
                    let _ = clear_scratch_dir(dir).await;
                }
            }
            if let Some(inner) = weak.upgrade() {
                inner.on_end(&sid, gen, end);
            }
        });
        if let Some(k) = st.known.get_mut(id) {
            k.active = Some(ActiveSession { gen, inputs, control, shared, jobs, task });
        }
    }

    /// Make sure a task is driving `id` (and its parent). The caller holds `activation`.
    fn activate_locked(self: &Arc<Self>, id: &SessionId) -> Result<Activation, String> {
        self.check_open()?;
        let meta = {
            let st = self.st();
            let k = st.known.get(id).ok_or_else(|| no_session(id))?;
            if k.active.is_some() {
                return Ok(Activation { already: true, cut: false, woken: false });
            }
            if k.meta.archived {
                return Err("This session is archived; unarchive it first.".to_string());
            }
            if k.status.phase == Phase::Ended {
                return Err("This session has ended.".to_string());
            }
            k.meta.clone()
        };
        self.check_network(&meta.pack)?;
        if let Some(parent) = &meta.parent {
            self.activate_locked(parent)?;
        } else {
            // A lead that runs again (a message after its end, an unarchive) may have its box again.
            self.box_reopen(&meta.mission);
        }
        let explicit = self.mission_explicit(&meta)?;
        let (deps, parts) = self.build(&meta, explicit)?;
        let session = match Session::open(deps) {
            Ok(s) => s,
            Err(e) => {
                self.proxy.revoke(id);
                return Err(e);
            }
        };
        let cut = cut_by_restart(session.records());
        let open = open_items(session.records());
        let status = session.status();
        let woken = session.pending_job_ends() > 0
            && matches!(status.last_end, Some(TurnEndReason::Waiting | TurnEndReason::Yielded));
        {
            let mut st = self.st();
            for (item, opened_ms) in open {
                st.inbox.retain(|e| e.item.item_id != item.item_id);
                st.inbox.push(InboxEntry {
                    session: id.clone(),
                    mission: meta.mission.clone(),
                    title: meta.title.clone(),
                    opened_ms,
                    item,
                });
            }
            if let Some(k) = st.known.get_mut(id) {
                k.status = status;
                k.restored = true;
            }
            self.launch(&mut st, id, session, parts);
        }
        Ok(Activation { already: false, cut, woken })
    }

    /// `activate_locked` for callers that do not hold the lock.
    fn activate(self: &Arc<Self>, id: &SessionId) -> Result<Activation, String> {
        let _g = lock(&self.activation);
        self.activate_locked(id)
    }

    // ---- the end of a session ---------------------------------------------------------------

    fn on_end(self: &Arc<Self>, id: &SessionId, gen: u64, end: End) {
        self.proxy.revoke(id);
        // The end of a mission's lead is the end of its box, except at a shutdown, which the next start
        // resumes from (it keeps the box of a mission that is running again).
        if !self.shutting.load(Ordering::SeqCst) {
            let lead = self.st().known.get(id).map(|k| k.meta.clone()).filter(|m| m.parent.is_none());
            if let Some(lead) = lead {
                self.box_teardown(&lead.mission);
            }
        }
        let settlement = match end {
            End::Settled(s) => Some(s),
            // A child ends `Closed` only at a shutdown, which the next start resumes it from: a child
            // whose inputs close otherwise settles itself, and one whose log had already ended is
            // `Ended` from its activation on, so the recovery of the start delivers what it ended with.
            End::Closed => {
                self.clear_active(id, gen);
                None
            }
            End::Fatal(e) => {
                tracing::error!("session {} stopped: {e}", id.as_str());
                self.publish_error(Some(id), format!("Session {} stopped: {e}", id.as_str()));
                self.clear_active(id, gen);
                let title = self
                    .st()
                    .known
                    .get(id)
                    .map(|k| (k.meta.title.clone(), k.meta.parent.is_some(), k.meta.role.clone(), k.status.step));
                match title {
                    Some((title, is_child, role, steps)) => {
                        if !self.shutting.load(Ordering::SeqCst) {
                            self.notify("error", id, &title, &e);
                        }
                        // A result the child synced before the fault is its settlement, and it ends the
                        // session as that result says (`record_settlement`); only without one is the
                        // child failed on its own account.
                        let done = if is_child {
                            read_records(&self.paths.session_log(id))
                                .ok()
                                .and_then(|log| completed_settlement(&log.records, id))
                        } else {
                            None
                        };
                        if is_child && done.is_none() {
                            self.mark_failed(id);
                        }
                        is_child.then(|| {
                            done.unwrap_or_else(|| Settlement {
                                child: id.clone(),
                                role,
                                outcome: ChildOutcome::Failed,
                                report: texts::failed_report(&e, ""),
                                full: None,
                                payload: serde_json::Value::Null,
                                steps,
                                usage: Usage::default(),
                            })
                        })
                    }
                    None => None,
                }
            }
        };
        let Some(s) = settlement else { return };
        // Kept beside the log so that a delivery lost to a restart carries the whole report.
        if let Err(e) = write_json_atomic(&self.paths.session_dir(id).join("settlement.json"), &s) {
            tracing::warn!("cannot write settlement.json of {}: {e}", id.as_str());
        }
        self.clear_active(id, gen);
        self.record_settlement(id, s);
        // A child that settled or failed is never activated again: its scratch directory is emptied once its
        // report is on its way, without waiting for the removal.
        self.clear_scratch(id);
    }

    /// A child whose task ended without writing a `session_end` (a log fault, a panic), or whose
    /// session cannot be opened again after a restart, is over all the same. Its status says so,
    /// durably, so that a later start does not run it again beside the settlement its parent was given.
    fn mark_failed(&self, id: &SessionId) {
        let status = {
            let mut st = self.st();
            st.known.get_mut(id).map(|k| {
                k.status.phase = Phase::Ended;
                k.status.outcome = Some(SessionOutcome::Failed);
                k.status.clone()
            })
        };
        if let Some(status) = status {
            self.on_status(id, &status);
        }
    }

    fn clear_active(&self, id: &SessionId, gen: u64) {
        let mut st = self.st();
        if let Some(k) = st.known.get_mut(id) {
            if k.active.as_ref().is_some_and(|a| a.gen == gen) {
                k.active = None;
            }
        }
    }

    /// Keep a child's settlement, wake whoever waits for it, and deliver it to the parent when
    /// nobody can be waiting. A verifier of the finish gate is never delivered: its verdict is the
    /// `finish`'s, which takes it with a `join` (after a restart, the `finish` made again).
    fn record_settlement(self: &Arc<Self>, id: &SessionId, s: Settlement) {
        let (parent, deliver, status) = {
            let mut st = self.st();
            let Some(k) = st.known.get_mut(id) else { return };
            if k.settlement.is_some() {
                return;
            }
            let terminal = settled_status(&k.status, &s);
            let status = (terminal != k.status).then(|| {
                k.status = terminal.clone();
                terminal
            });
            k.settlement = Some(s.clone());
            k.settled_tx.send_replace(Some(s.clone()));
            // During the start-up pass the recovery that ends it delivers what settled before then: it
            // is the one that knows which agents the finish gate started.
            let deliver = (!k.meta.awaited || k.restored)
                && k.gate.is_none()
                && !k.joined
                && !self.shutting.load(Ordering::SeqCst)
                && !self.restoring.load(Ordering::SeqCst);
            if deliver {
                k.joined = true;
            }
            (k.meta.parent.clone(), deliver, status)
        };
        if let Some(status) = status {
            self.on_status(id, &status);
        }
        self.publish(BusEvent::Settled { session: id.clone(), settlement: Box::new(s.clone()) });
        if let (Some(parent), true) = (parent, deliver) {
            self.deliver(&parent, s);
        }
    }

    /// Hand a settlement to its parent as input, activating the parent if need be. The caller has
    /// claimed the delivery (`joined`); one that fails gives the claim back, so that a recovery (after
    /// a restart, or when an archived lead is unarchived) makes it later.
    fn deliver(self: &Arc<Self>, parent: &SessionId, s: Settlement) {
        let handed = match self.activate(parent) {
            Err(e) => {
                tracing::warn!(
                    "the settlement of {} cannot be delivered to {}: {e}",
                    s.child.as_str(),
                    parent.as_str()
                );
                false
            }
            Ok(_) => {
                let sent = self.send_input(parent, Input::ChildSettled(s.clone()));
                if !sent {
                    tracing::warn!("the settlement of {} was not accepted by {}", s.child.as_str(), parent.as_str());
                }
                sent
            }
        };
        if !handed {
            if let Some(k) = self.st().known.get_mut(&s.child) {
                k.joined = false;
            }
        }
    }

    // ---- children ---------------------------------------------------------------------------

    /// Make the copy of the workspace `source` an agent will work in, at `dest`, and record what it
    /// was made from beside the agent's log. On `Err` nothing is left at `dest`.
    async fn make_copy(
        &self,
        parent: &SessionId,
        child: &SessionId,
        source: PathBuf,
        dest: PathBuf,
    ) -> Result<workcopy::Made, String> {
        // What the parent's own session may read decides which files are copied: the rules are the same in every
        // mode (the sandbox is built here only to judge paths, so no mode is needed).
        let (pack, role) = self
            .st()
            .known
            .get(parent)
            .map(|p| (p.meta.pack.clone(), p.meta.role.clone()))
            .ok_or_else(|| "Only the lead session of a mission can start agents.".to_string())?;
        let role = self.packs.role(Some(&pack), Some(&role))?.clone();
        let mut judge_cfg = sandbox_cfg_for(&self.config.sandbox, &role, &source, &self.config.models);
        judge_cfg.mode = loom_core::config::SandboxMode::None;
        let (home, tmp) = (self.paths.home.clone(), self.paths.session_tmp(parent));
        let limits = workcopy::Limits {
            max_files: self.config.agents.copy_max_files,
            max_bytes: self.config.agents.copy_max_mb.saturating_mul(1024 * 1024),
        };
        let record = self.paths.session_dir(child).join(COPY_MANIFEST);
        let work = tokio::task::spawn_blocking(move || {
            // Private like the loom home: a copy holds what the workspace holds.
            if let Some(root) = dest.parent() {
                ensure_private_dir(root).map_err(|e| format!("Cannot create {}: {e}", root.display()))?;
            }
            let judge = Sandbox::new(&judge_cfg, &source, &tmp, &home, None)
                .map_err(|e| format!("The copy of the workspace could not be made: {e}"))?;
            let made = workcopy::make(&source, &dest, &limits, &|real| judge.check_read(real).map(|_| ()))?;
            let written = match record.parent() {
                Some(dir) => ensure_private_dir(dir).and_then(|()| write_json_atomic(&record, &made.manifest)),
                None => write_json_atomic(&record, &made.manifest),
            };
            if let Err(e) = written {
                let _ = std::fs::remove_dir_all(&dest);
                return Err(format!("The agent could not be started: cannot write {}: {e}", record.display()));
            }
            Ok(made)
        });
        match work.await {
            Ok(made) => made,
            Err(e) => Err(format!("The copy of the workspace could not be made: {e}")),
        }
    }

    async fn spawn_child(self: &Arc<Self>, parent: &SessionId, mut req: SpawnReq) -> Result<SessionId, String> {
        self.check_open()?;
        let (shared, requires_credential, max_steps) = {
            let st = self.st();
            let p = st
                .known
                .get(parent)
                .filter(|k| k.active.is_some() && k.meta.parent.is_none())
                .ok_or_else(|| "Only the lead session of a mission can start agents.".to_string())?;
            let prole = self.packs.role(Some(&p.meta.pack), Some(&p.meta.role))?;
            let role = self
                .packs
                .role(Some(&p.meta.pack), Some(&req.role))
                .ok()
                .filter(|_| req.harness || prole.may_spawn.contains(&req.role))
                .ok_or_else(|| {
                    format!(
                        "`{}` is not a role this session can start. Roles it can start: {}.",
                        req.role,
                        prole.may_spawn.join(", ")
                    )
                })?;
            if req.workspace == Workspace::Copy && role.read_only {
                return Err(format!(
                    "A `{}` agent only reads the workspace, so a copy of it would hold nothing to adopt. Start it without `workspace: \"copy\"`.",
                    req.role
                ));
            }
            let shared = p.active.as_ref().map(|a| a.shared.clone()).ok_or_else(|| SHUTTING.to_string())?;
            (shared, role.requires_credential, role.max_steps)
        };
        if let Some(cap) = max_steps {
            req.budget.max_steps = Some(req.budget.max_steps.filter(|n| *n > 0).map(|n| n.min(cap)).unwrap_or(cap));
        }
        req.prerequisite =
            rtools::validate_dispatch_prerequisite(&shared, requires_credential, req.prerequisite.as_ref(), now_ms())?;
        if let Some(p) = &req.prerequisite {
            let header=format!("Dispatch prerequisite checked by Loom: asset {}; credential {}. This observation does not grant network scope or guarantee the credential remains valid.",p.asset,p.credential);
            req.brief.context = Some(match req.brief.context.take() {
                Some(context) => format!("{header}\n\n{context}"),
                None => header,
            });
        }
        // Reserve rotation before discovery: parallel fanout siblings get different slots. Restarts
        // derive the initial cursor from persisted child metadata rather than a process-global counter.
        let (profile_name, inherited_model, inherited_window) = {
            let mut st = self.st();
            let p = st
                .known
                .get(parent)
                .filter(|k| k.active.is_some() && k.meta.parent.is_none())
                .ok_or_else(|| "Only the lead session of a mission can start agents.".to_string())?;
            let prole = self.packs.role(Some(&p.meta.pack), Some(&p.meta.role))?;
            let role = self
                .packs
                .role(Some(&p.meta.pack), Some(&req.role))
                .ok()
                .filter(|_| req.harness || prole.may_spawn.contains(&req.role))
                .ok_or_else(|| {
                    format!(
                        "`{}` is not a role this session can start. Roles it can start: {}.",
                        req.role,
                        prole.may_spawn.join(", ")
                    )
                })?;
            let inherited = (p.meta.profile.clone(), p.meta.model.clone(), p.meta.context_window);
            let prior: Vec<_> = st
                .known
                .values()
                .filter(|k| k.meta.parent.as_ref() == Some(parent) && k.meta.role == req.role)
                .collect();
            // A hand-off asking for a stronger model escalates like a failure; any other ask does not.
            let failed = prior.iter().any(|k| {
                matches!(
                    k.settlement.as_ref().map(|s| s.outcome),
                    Some(ChildOutcome::Failed | ChildOutcome::BudgetExhausted)
                ) || k
                    .settlement
                    .as_ref()
                    .is_some_and(|s| s.payload["handed_off"]["ask"].as_str() == Some("stronger_model"))
            });
            let prior_count = prior.len();
            let cursor = st.route_cursor.entry((parent.clone(), req.role.clone())).or_insert(prior_count);
            let selected = if failed && role.escalation_model.is_some() {
                role.escalation_model.clone()
            } else if !role.alloy_models.is_empty() {
                role.alloy_models.get(*cursor % role.alloy_models.len()).cloned()
            } else {
                role.model.clone()
            };
            *cursor = cursor.saturating_add(1);
            let profile = selected.unwrap_or_else(|| inherited.0.clone());
            if req.mode == SpawnMode::Fork && profile != inherited.0 {
                return Err(texts::cross_profile_fork(&inherited.0, &profile));
            }
            if prole.verifier.as_deref() == Some(req.role.as_str())
                && prole.require_distinct_verifier_profile
                && profile == inherited.0
            {
                return Err(texts::same_verifier_profile(&profile));
            }
            (profile, inherited.1, inherited.2)
        };
        let parent_profile = self.st().known.get(parent).map(|p| p.meta.profile.clone());
        let (model, window) = if parent_profile.as_deref() == Some(profile_name.as_str()) {
            (inherited_model, inherited_window)
        } else {
            let (model, window, _) = self.facts(&profile_name).await?;
            (model, window)
        };
        self.check_open()?;
        let child_id = SessionId::generate();
        let (meta, crole, fork_point, parent_shared, explicit) = {
            let mut st = self.st();
            let p = st
                .known
                .get(parent)
                .filter(|k| k.active.is_some() && k.meta.parent.is_none())
                .ok_or_else(|| "Only the lead session of a mission can start agents.".to_string())?;
            let prole = self.packs.role(Some(&p.meta.pack), Some(&p.meta.role))?.clone();
            let pack = self.packs.get(&p.meta.pack).ok_or_else(|| format!("There is no pack \"{}\".", p.meta.pack))?;
            let crole = match pack.roles.get(&req.role).filter(|_| req.harness || prole.may_spawn.contains(&req.role)) {
                Some(r) => r.clone(),
                None => {
                    let list = if prole.may_spawn.is_empty() { "none".to_string() } else { prole.may_spawn.join(", ") };
                    return Err(format!(
                        "`{}` is not a role this session can start. Roles it can start: {list}.",
                        req.role
                    ));
                }
            };
            // Model discovery may have waited. Recheck current mission state and expiry immediately
            // before allocating the child, including trusted harness dispatches.
            let shared = p.active.as_ref().map(|a| a.shared.clone()).ok_or_else(|| SHUTTING.to_string())?;
            rtools::validate_dispatch_prerequisite(
                &shared,
                crole.requires_credential,
                req.prerequisite.as_ref(),
                now_ms(),
            )?;
            let running = st
                .known
                .values()
                .filter(|k| k.meta.parent.as_ref() == Some(parent) && !k.finished() && k.gate.is_none())
                .count();
            if !req.harness && running >= self.config.agents.max_children as usize {
                return Err(format!(
                    "{running} agents are already running, which is the most allowed at once. Wait for one to finish (`wait`) or stop one (`agent_stop`), then start this one."
                ));
            }
            let mut fork_point = None;
            if req.mode == SpawnMode::Fork {
                // `hand_off` is bound to the role's assignment, not to what the parent's prefix defines: a
                // lead has none, and a forked agent is simply not offered it.
                let missing: Vec<&String> =
                    crole.tools.iter().filter(|t| !prole.tools.contains(t) && t.as_str() != "hand_off").collect();
                if !missing.is_empty() {
                    let list = missing.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
                    return Err(format!(
                        "A `{}` agent cannot be forked from this session: it needs tools this session does not have ({list}). Start it with mode `fresh` and put what it needs to know in the assignment.",
                        crole.name
                    ));
                }
                fork_point = Some(p.status.fork_point.ok_or_else(|| {
                    "Nothing has been sent to the model in this session yet, so there is nothing to fork.".to_string()
                })?);
            }
            let shared = p.active.as_ref().map(|a| a.shared.clone()).ok_or_else(|| SHUTTING.to_string())?;
            let (workspace, copy_of) = match req.workspace {
                Workspace::Shared => (p.meta.workspace.clone(), None),
                Workspace::Copy => (
                    self.paths.agent_copy(&p.meta.mission, &child_id).display().to_string(),
                    Some(p.meta.workspace.clone()),
                ),
            };
            let meta = SessionMeta {
                id: child_id.clone(),
                mission: p.meta.mission.clone(),
                parent: Some(parent.clone()),
                workspace,
                copy_of,
                pack: p.meta.pack.clone(),
                role: crole.name.clone(),
                profile: profile_name.clone(),
                model: model.clone(),
                context_window: window,
                title: req.title.clone(),
                created_ms: now_ms(),
                mode: Some(req.mode),
                awaited: req.awaited,
                unattended: p.meta.unattended,
                archived: false,
                gate: req.harness.then(|| req.brief.clone()),
                prior: Vec::new(),
            };
            let explicit = prole.termination == Termination::Explicit;
            st.known.insert(child_id.clone(), Known::new(meta.clone(), idle_status()));
            (meta, crole, fork_point, shared, explicit)
        };
        let copy_dir = meta.copy_of.as_ref().map(|_| PathBuf::from(&meta.workspace));
        let forget = |this: &Inner| {
            this.proxy.revoke(&child_id);
            this.st().known.remove(&child_id);
            if let Some(dir) = copy_dir.clone() {
                // Not on this thread: a copy can hold some hundred thousand files.
                drop(tokio::task::spawn_blocking(move || std::fs::remove_dir_all(dir)));
            }
        };
        // The child is known (and counted against `max_children`) while its copy is made.
        if let (Some(source), Some(dest)) = (meta.copy_of.clone(), copy_dir.clone()) {
            let made = match self.make_copy(parent, &child_id, PathBuf::from(&source), dest).await {
                // The daemon may have begun to stop while the files were copied.
                Ok(made) => self.check_open().map(|()| made),
                Err(e) => Err(e),
            };
            let made = match made {
                Ok(made) => made,
                Err(e) => {
                    forget(self);
                    return Err(e);
                }
            };
            // As its commands will see it: `pwd` prints the path with every link resolved.
            let copy = std::fs::canonicalize(&meta.workspace).map(|p| p.display().to_string());
            let copy = copy.unwrap_or_else(|_| meta.workspace.clone());
            let header = texts::copy_header(&copy, &source, &made, req.mode == SpawnMode::Fork);
            req.brief.context = Some(match req.brief.context.take() {
                Some(context) => format!("{header}\n\n{context}"),
                None => header,
            });
        }
        let (deps, parts) = match self.build(&meta, explicit) {
            Ok(x) => x,
            Err(e) => {
                forget(self);
                return Err(e);
            }
        };
        let created = match fork_point {
            Some(upto) => {
                let tools: Vec<String> = crole.tools.iter().filter(|t| t.as_str() != "hand_off").cloned().collect();
                Session::fork(
                    deps,
                    &self.paths.session_log(parent),
                    upto,
                    Forked {
                        session: child_id.clone(),
                        parent: parent.clone(),
                        upto_seq: upto,
                        role: crole.name.clone(),
                        termination: crole.termination,
                        budget: req.budget.clone(),
                        brief: req.brief.clone(),
                        contract: texts::fork_contract(&crole.name, &crole.prompt, &tools),
                        allowed_tools: Some(tools),
                        title: req.title.clone(),
                    },
                )
            }
            None => match self.start_record(&meta, &deps, req.budget.clone()) {
                Ok(start) => Session::create(deps, start, Some((parent.clone(), render_brief(&req.brief)))),
                Err(e) => Err(e),
            },
        };
        let session = match created {
            Ok(s) => s,
            Err(e) => {
                forget(self);
                return Err(format!("The agent could not be started: {e}"));
            }
        };
        if let Err(e) = write_json_atomic(&self.paths.session_dir(&child_id).join("meta.json"), &meta) {
            forget(self);
            return Err(format!("The agent could not be started: cannot write its meta.json: {e}"));
        }
        let info = {
            let mut st = self.st();
            if let Some(k) = st.known.get_mut(&child_id) {
                k.status = session.status();
            }
            self.launch(&mut st, &child_id, session, parts);
            st.known.get(&child_id).map(Inner::info_of)
        };
        if let Some(info) = info {
            self.publish(BusEvent::Session { info: Box::new(info) });
        }
        parent_shared.emit(
            Author::Harness,
            Event::ChildSpawned(ChildSpawned {
                child: child_id.clone(),
                role: crole.name.clone(),
                mode: req.mode,
                brief: req.brief,
                budget: req.budget,
                call_id: Some(req.call_id),
            }),
        );
        Ok(child_id)
    }

    // ---- start ------------------------------------------------------------------------------

    /// Model facts of a profile: discovery once, the first success with a window remembered; a
    /// discovery that finds no window refuses the creation and is not remembered. The flag is true
    /// when the server could not be asked and the numbers come from the profile alone. Without a
    /// configured window that is refused: a session must not start with a window nobody knows.
    async fn facts(&self, profile_name: &str) -> Result<(String, Option<u64>, bool), String> {
        let rt = self
            .profiles
            .get(profile_name)
            .ok_or_else(|| format!("The model profile \"{profile_name}\" is not configured."))?;
        let remembered = lock(&rt.discovered).clone();
        let profile = rt.client.profile();
        let found = match remembered {
            Some(d) => Some(d),
            None => match rt.client.discover().await {
                Ok(d) if d.context_window.is_none() => {
                    // Not remembered: every creation is refused until the profile sets a window.
                    return Err(format!(
                        "The model server at {} answered but reports no context window for the model, so the session would start without knowing it. Set context_window in [models.{profile_name}] of the config and restart the daemon: the config is read only at start.",
                        profile.base_url
                    ));
                }
                Ok(d) => {
                    // Remembered once, so this is the one warning of the profile.
                    if let Some(w) = window_warning(profile_name, profile.context_window, d.server_window) {
                        tracing::warn!("{w}");
                    }
                    *lock(&rt.discovered) = Some(d.clone());
                    Some(d)
                }
                Err(ModelError::Unavailable { last, .. }) => {
                    if profile.context_window.is_none() {
                        return Err(format!(
                            "The model server at {} could not be asked for its models ({last}), and the profile \"{profile_name}\" sets no context_window, so the session would start without knowing the model's window. Start the model server, or set context_window in [models.{profile_name}] of the config and restart the daemon: the config is read only at start.",
                            profile.base_url
                        ));
                    }
                    None
                }
                Err(e) => return Err(e.to_string()),
            },
        };
        match found {
            Some(d) => Ok((d.served_model, d.context_window, false)),
            None => Ok((profile.model.clone(), profile.context_window, true)),
        }
    }

    /// Deliveries lost to a restart, or to a lead that was archived or not running when its agents
    /// settled: an agent of a live lead (of those `scope` selects) has ended, its settlement did not
    /// reach the lead, and the lead's log holds no `child_settled` for it. It is delivered as
    /// `Input::ChildSettled`, from the settlement kept in memory or in `settlement.json`, or else from
    /// its log (see *Files*), unless the lead was told already: the call that started an `awaited`
    /// agent that had ended has a recorded result, which said that the agent was stopped. A verifier
    /// of the finish gate is not delivered: its settlement is kept for the `finish` made again
    /// ([`Inner::cut_verifier`]). Marks the agents the finish gate started. Returns the leads something
    /// was delivered to.
    fn recover_settlements(self: &Arc<Self>, scope: impl Fn(&Known) -> bool) -> HashSet<SessionId> {
        let mut delivered_to = HashSet::new();
        let candidates: Vec<(SessionId, SessionId, SessionMeta, bool, bool)> = {
            let st = self.st();
            st.known
                .iter()
                .filter_map(|(id, k)| {
                    let parent = k.meta.parent.clone()?;
                    let parent_ok =
                        st.known.get(&parent).is_some_and(|p| !p.meta.archived && p.status.phase != Phase::Ended);
                    let wanted = scope(k) && !k.joined && !k.meta.archived && parent_ok;
                    // A completed child of an archived or ended family still gets its result back in
                    // memory, so that `join` and `watch` work once the family is reopened; only the
                    // delivery depends on the lead being eligible.
                    let restorable = k.settlement.is_none() && k.status.phase == Phase::Ended;
                    (wanted || restorable).then(|| (id.clone(), parent, k.meta.clone(), k.finished(), wanted))
                })
                .collect()
        };
        // First what the leads' logs say about each agent; then the deliveries.
        let mut seen: HashMap<SessionId, Spawns> = HashMap::new();
        let mut open: Vec<(SessionId, SessionId, SessionMeta, bool, bool)> = Vec::new();
        for (id, parent, meta, ended, wanted) in candidates {
            if !wanted {
                open.push((id, parent, meta, false, false));
                continue;
            }
            let spawns = seen.entry(parent.clone()).or_insert_with(|| {
                read_records(&self.paths.session_log(&parent)).map(|r| Spawns::of(&r.records)).unwrap_or_default()
            });
            // A verifier written before `meta.gate` existed is known from the lead's log only.
            let gate = meta.gate.clone().or_else(|| spawns.gate.get(&id).cloned());
            // The lead had it: nothing is delivered, and a `finish` made again does not take it. A result
            // of the call told the lead how the agent ended only if it had: one that a shutdown cut
            // instead of stopping goes on, and its report is delivered.
            let had = spawns.settled.contains(&id) || (meta.awaited && ended && spawns.answered.contains(&id));
            if let Some(k) = self.st().known.get_mut(&id) {
                k.joined |= had;
                if gate.is_some() {
                    k.gate = gate.clone();
                }
            }
            if had {
                // Already told to the lead: nothing is delivered, but the complete result is still
                // restored in memory (for `join`, `watch` and the family's reopening).
                open.push((id, parent, meta, false, false));
            } else {
                open.push((id, parent, meta, gate.is_some(), true));
            }
        }
        // From here on a settlement is delivered as it is made; what settled before is delivered
        // below. The claim each delivery takes under the state lock makes it one.
        self.restoring.store(false, Ordering::SeqCst);
        for (id, parent, meta, gate, wanted) in open {
            let (kept, ended) = match self.st().known.get(&id) {
                Some(k) => (k.settlement.clone(), k.status.phase == Phase::Ended || k.settlement.is_some()),
                None => continue,
            };
            if !ended || (!wanted && kept.is_some()) {
                continue;
            }
            // What the child's task handed over when it ended: first the complete result its log
            // holds (`child_completed`, synced before any terminal write, so it is authoritative even
            // when those were cut), then the `settlement.json` kept beside the log. Without either (see
            // *Files*) the child ended before results were persisted whole: it is reported as an
            // incomplete recovery, never as a success made up from its summary.
            let persisted = kept
                .or_else(|| {
                    read_records(&self.paths.session_log(&id)).ok().and_then(|r| completed_settlement(&r.records, &id))
                })
                .or_else(|| {
                    read_json::<Settlement>(&self.paths.session_dir(&id).join("settlement.json"))
                        .filter(|p| p.child == id)
                });
            let s = match persisted {
                Some(s) => s,
                None => {
                    let Ok(report) = read_records(&self.paths.session_log(&id)) else { continue };
                    let own = own_records(&report.records);
                    let detail = own.iter().rev().find_map(|r| match &r.event {
                        Event::SessionEnd { detail, .. } => Some(detail.as_str()),
                        _ => None,
                    });
                    let Some(detail) = detail else { continue };
                    let steps = self.st().known.get(&id).map(|k| k.status.step).unwrap_or(0);
                    Settlement {
                        child: id.clone(),
                        role: meta.role.clone(),
                        outcome: ChildOutcome::Failed,
                        report: texts::recovery_incomplete(detail),
                        full: None,
                        payload: serde_json::json!({"recovery_incomplete": true}),
                        steps,
                        usage: Usage::default(),
                    }
                }
            };
            // A child of a family that is not delivered to keeps its result for `join` only.
            if !wanted {
                let mut st = self.st();
                if let Some(k) = st.known.get_mut(&id) {
                    if k.settlement.is_none() {
                        k.settlement = Some(s.clone());
                        k.settled_tx.send_replace(Some(s));
                    }
                    k.restored = true;
                }
                continue;
            }
            // Claimed under the lock: the settlement of an agent that ends now is delivered once.
            let claimed = {
                let mut st = self.st();
                match st.known.get_mut(&id) {
                    Some(k) if !k.joined => {
                        if k.settlement.is_none() {
                            k.settlement = Some(s.clone());
                            k.settled_tx.send_replace(Some(s.clone()));
                        }
                        k.restored = true;
                        k.joined = !gate;
                        true
                    }
                    _ => false,
                }
            };
            if claimed && !gate {
                self.deliver(&parent, s);
                delivered_to.insert(parent);
            }
        }
        delivered_to
    }

    /// Whether `id` has an agent that has not settled. The finish gate's verifiers do not count: they
    /// never wake their lead.
    fn has_unsettled_child(&self, id: &SessionId) -> bool {
        self.st().known.values().any(|k| k.meta.parent.as_ref() == Some(id) && !k.finished() && k.gate.is_none())
    }

    /// Whether the session's log holds a job that was registered and never settled, or a job end it
    /// was told of that no turn has followed (`session::has_job_news`). The log is read only when the
    /// session has a jobs directory. Every command creates it, a foreground one as well as a background
    /// job, and nothing removes it (even when `open` has taken every file in it), so this passes over
    /// only the sessions that never ran a command; for the others the log decides.
    fn has_job_news(&self, id: &SessionId) -> bool {
        if !self.paths.session_dir(id).join("jobs").is_dir() {
            return false;
        }
        let Ok(report) = read_records(&self.paths.session_log(id)) else { return false };
        crate::session::has_job_news(own_records(&report.records))
    }

    /// Tell the children of `lead` that a restart left idle to carry on (see `held`). An agent gets one
    /// `Resume` for the cut: a second one would start a turn it did not ask for once the resumed one
    /// ends. Agents without a task (their lead could not be opened when the runtime started) are
    /// restored first, and what they ended with meanwhile is delivered.
    fn resume_cut_children(self: &Arc<Self>, lead: &SessionId) {
        let (restore, recover) = {
            let st = self.st();
            let mine: Vec<&Known> = st.known.values().filter(|k| k.meta.parent.as_ref() == Some(lead)).collect();
            (
                mine.iter().any(|k| !k.finished() && k.active.is_none()),
                mine.iter().any(|k| k.finished() && k.restored && !k.joined && k.gate.is_none()),
            )
        };
        if restore {
            self.restore_children(|p| p == lead);
        }
        if restore || recover {
            self.recover_settlements(|k| k.meta.parent.as_ref() == Some(lead) && k.restored);
        }
        let children: Vec<SessionId> = {
            let st = self.st();
            st.known
                .iter()
                .filter(|(_, k)| k.meta.parent.as_ref() == Some(lead) && k.held && !k.finished())
                .map(|(c, _)| c.clone())
                .collect()
        };
        for child in children {
            match self.activate(&child) {
                Ok(_) => self.resume_held(&child),
                Err(e) => tracing::warn!("child {} cannot be resumed: {e}", child.as_str()),
            }
        }
    }

    /// Send the one `Resume` of an agent that a restart left idle.
    fn resume_held(&self, id: &SessionId) {
        let mut st = self.st();
        let Some(k) = st.known.get_mut(id).filter(|k| k.held) else { return };
        if k.active.as_ref().is_some_and(|a| a.inputs.send(Input::Resume).is_ok()) {
            k.held = false;
            #[cfg(test)]
            lock(&RESUMES).push(id.clone());
        }
    }

    /// The agents of `leads` that have not settled and have no task, after a restart or an unarchive:
    /// each is activated, so that a stop or an archive reaches it, and becomes `held` when it will not
    /// run by itself (a restart cut its turn, or left it idle). As at the start, it is resumed now when
    /// it was told of job ends no turn has followed or its mission is unattended, and otherwise when its lead goes on. One
    /// that cannot be opened any more is settled `Failed` on its behalf, with what went wrong, so
    /// that its lead is not left waiting for it; a recovery delivers that.
    fn restore_children(self: &Arc<Self>, leads: impl Fn(&SessionId) -> bool) {
        let children: Vec<SessionId> = {
            let st = self.st();
            st.known
                .iter()
                .filter(|(_, k)| {
                    k.meta.parent.as_ref().is_some_and(|p| {
                        leads(p) && st.known.get(p).is_some_and(|p| !p.meta.archived && p.status.phase != Phase::Ended)
                    }) && !k.meta.archived
                        && !k.finished()
                        && k.active.is_none()
                })
                .map(|(id, _)| id.clone())
                .collect()
        };
        for id in children {
            match self.activate(&id) {
                Ok(a) if a.already => {}
                Ok(a) => {
                    let resume = self.st().known.get_mut(&id).is_some_and(|k| {
                        // An agent that never started a turn starts its first one by itself.
                        k.held = !k.finished() && k.status.phase != Phase::Running && k.status.last_end.is_some();
                        k.held && (a.woken || k.meta.unattended)
                    });
                    if resume {
                        self.resume_held(&id);
                    }
                }
                Err(e) => {
                    tracing::error!("session {} cannot be restored: {e}", id.as_str());
                    self.publish_error(Some(&id), format!("Session {} cannot be restored: {e}", id.as_str()));
                    if self.lead_is_active(&id) {
                        self.settle_unopenable(&id, &e);
                    }
                }
            }
        }
    }

    /// Whether `id` is an agent whose lead has a task. An agent that cannot be opened while its lead
    /// can will never run again; when the lead cannot be opened either, the mission is not running.
    fn lead_is_active(&self, id: &SessionId) -> bool {
        let st = self.st();
        let parent = st.known.get(id).and_then(|k| k.meta.parent.clone());
        parent.and_then(|p| st.known.get(&p)).is_some_and(|p| p.active.is_some())
    }

    /// Settle an agent whose session cannot be opened: it will never run again. Its log is left as it
    /// is; its status says `Ended`/`Failed` and `settlement.json` keeps what its lead is told.
    fn settle_unopenable(&self, id: &SessionId, error: &str) {
        let s = {
            let st = self.st();
            let Some(k) = st.known.get(id) else { return };
            Settlement {
                child: id.clone(),
                role: k.meta.role.clone(),
                outcome: ChildOutcome::Failed,
                report: texts::unopenable_report(error),
                full: None,
                payload: serde_json::Value::Null,
                steps: k.status.step,
                usage: Usage::default(),
            }
        };
        if let Err(e) = write_json_atomic(&self.paths.session_dir(id).join("settlement.json"), &s) {
            tracing::warn!("cannot write settlement.json of {}: {e}", id.as_str());
        }
        self.mark_failed(id);
        {
            let mut st = self.st();
            if let Some(k) = st.known.get_mut(id) {
                k.settlement = Some(s.clone());
                k.settled_tx.send_replace(Some(s));
                k.restored = true;
            }
        }
        // It will never run a command again; nobody waits for the removal.
        self.clear_scratch(id);
    }

    /// The verifier of `role` that a finish of `parent` started for `brief` and that a shutdown cut, for
    /// the finish made again after the restart: the gate joins that one (or takes the verdict it
    /// already gave) instead of starting a second. Only one that has a task and has not ended, or that
    /// ended with a verdict, is taken. The other verifiers of `parent` that no `join` took are given up:
    /// nothing takes them any more, and one that has not ended is stopped.
    fn cut_verifier(&self, parent: &SessionId, role: &str, brief: &Brief) -> Option<SessionId> {
        let (found, stale) = {
            let mut st = self.st();
            let mut found = None;
            let mut stale = Vec::new();
            let parent_meta = st.known.get(parent).map(|k| k.meta.clone());
            let prole = parent_meta.as_ref().and_then(|m| self.packs.role(Some(&m.pack), Some(&m.role)).ok());
            let target = parent_meta.as_ref().and_then(|m| self.packs.role(Some(&m.pack), Some(role)).ok());
            for (id, k) in st.known.iter_mut().filter(|(_, k)| k.meta.parent.as_ref() == Some(parent) && !k.joined) {
                let Some(given) = &k.gate else { continue };
                // One that was stopped, failed, or ended without a verdict gives nothing to take.
                let verdict = k
                    .settlement
                    .as_ref()
                    .is_some_and(|s| s.payload.get("accepted").is_some_and(serde_json::Value::is_boolean));
                let profile_ok = target.and_then(|r| r.model.as_ref()).is_none_or(|p| p == &k.meta.profile)
                    && !(prole.is_some_and(|r| r.require_distinct_verifier_profile)
                        && parent_meta.as_ref().is_some_and(|p| p.profile == k.meta.profile));
                let usable = profile_ok && (verdict || (!k.finished() && k.active.is_some()));
                if found.is_none() && usable && given == brief && k.meta.role == role {
                    found = Some(id.clone());
                    continue;
                }
                k.joined = true;
                if !k.finished() {
                    stale.push(id.clone());
                }
            }
            (found, stale)
        };
        for id in &stale {
            self.stop_one(id);
        }
        found
    }

    /// Append to the log of `parent`, whose task is about to park in a `join` that a shutdown
    /// cancelled, what its call queued (`child_spawned`, `ledger`): the step loop that would have
    /// appended it after the call's result never runs again, and the next start needs it to know
    /// what the call started. The parked task writes nothing more, so the log keeps one writer.
    fn write_for_parked(self: &Arc<Self>, parent: &SessionId, shared: &Shared) {
        let queued = shared.take_emitted();
        if queued.is_empty() {
            return;
        }
        // The parked task still holds the log's lock and will not write again: open beside it.
        let mut log = match SessionLog::open_beside(&self.paths.session_log(parent), Durability::Always) {
            Ok((log, _)) => log,
            Err(e) => {
                tracing::warn!("cannot record what the cut call of {} queued: {e}", parent.as_str());
                return;
            }
        };
        for (author, mut event) in queued {
            // A report a `join` of the call took has no result to be shown in: it is shown as one that
            // arrived by itself.
            if let Event::ChildSettled(c) = &mut event {
                c.inline = false;
            }
            match log.append(author, event) {
                Ok(record) => self.on_record(parent, &record),
                Err(e) => {
                    tracing::warn!("cannot record what the cut call of {} queued: {e}", parent.as_str());
                    return;
                }
            }
        }
    }
}

/// What a lead's log says about the agents it started.
#[derive(Default)]
struct Spawns {
    /// Agents whose settlement the log holds.
    settled: HashSet<SessionId>,
    /// Agents whose starting call has a recorded result: the lead of an `awaited` one that had ended
    /// was told how it ended (its report, or that it was stopped).
    answered: HashSet<SessionId>,
    /// Verifiers of the finish gate (started by a `finish` call), with the assignment each was given.
    gate: HashMap<SessionId, Brief>,
}

impl Spawns {
    fn of(records: &[Record]) -> Spawns {
        let own = own_records(records);
        let mut finishes: HashSet<&CallId> = HashSet::new();
        let mut results: HashSet<&CallId> = HashSet::new();
        for r in own {
            match &r.event {
                Event::ToolCall(c) if c.name == "finish" => {
                    finishes.insert(&c.call_id);
                }
                Event::ToolResult(t) => {
                    results.insert(&t.call_id);
                }
                _ => {}
            }
        }
        let mut out = Spawns::default();
        for r in own {
            match &r.event {
                Event::ChildSettled(c) => {
                    out.settled.insert(c.child.clone());
                }
                Event::ChildSpawned(c) => {
                    let Some(call) = &c.call_id else { continue };
                    if results.contains(call) {
                        out.answered.insert(c.child.clone());
                    }
                    if finishes.contains(call) {
                        out.gate.insert(c.child.clone(), c.brief.clone());
                    }
                }
                _ => {}
            }
        }
        out
    }
}

/// Empty the scratch directory `dir` of a session that can no longer run commands, off the async workers: a
/// command may have left many files there. Failures are warnings. The handle ends when the removal has.
fn clear_scratch_dir(dir: PathBuf) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        if let Err(e) = empty_dir(&dir) {
            tracing::warn!("cannot empty the scratch directory {}: {e}", dir.display());
        }
    })
}

/// Remove everything inside the directory `dir` (not `dir` itself). Links are removed, never followed: one inside
/// `dir` is removed as a file, and a `dir` that is itself a link (or anything but a directory) is left alone with
/// an error. A missing directory, and an entry something else removed meanwhile, are empty already.
fn empty_dir(dir: &Path) -> std::io::Result<()> {
    let gone = |e: &std::io::Error| e.kind() == std::io::ErrorKind::NotFound;
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.is_dir() => {}
        Ok(_) => {
            return Err(std::io::Error::other("it is not a directory (a symbolic link, say), so it was left alone"));
        }
        Err(e) if gone(&e) => return Ok(()),
        Err(e) => return Err(e),
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if gone(&e) => return Ok(()),
        Err(e) => return Err(e),
    };
    let mut first_error = None;
    for entry in entries {
        let result = entry.and_then(|entry| {
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                std::fs::remove_dir_all(&path)
            } else {
                std::fs::remove_file(&path)
            }
        });
        if let Some(e) = result.err().filter(|e| !gone(e)) {
            first_error.get_or_insert(e);
        }
    }
    first_error.map_or(Ok(()), Err)
}

/// Free space below which the disk counts as low: 5 GiB …
pub const LOW_DISK_BYTES: u64 = 5 << 30;

/// … or 5 percent of the volume.
pub const LOW_DISK_PERCENT: u64 = 5;

/// What the low-disk notification says.
const LOW_DISK_NOTICE: &str =
    "The disk that holds the loom home is nearly full, so sessions will fail when it fills. Free space, or run `loom gc`.";

/// How often the disk is checked.
#[cfg(not(test))]
const DISK_CHECK_EVERY: Duration = Duration::from_secs(60);

/// Free and total bytes of the volume that holds `path` (`statvfs`); `None` when they cannot be read.
pub fn volume_space(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: `statvfs` is plain integers, for which all-zero is a valid value.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c_path` is a NUL-terminated string and `st` a live, exclusively borrowed `statvfs`.
    if unsafe { libc::statvfs(c_path.as_ptr(), &mut st) } != 0 {
        return None;
    }
    // Counts are in fragments (`f_frsize`); a file system that leaves that 0 counts in blocks.
    let unit = u128::from(if st.f_frsize > 0 { st.f_frsize } else { st.f_bsize });
    let free = u64::try_from(u128::from(st.f_bavail) * unit).ok()?;
    let total = u64::try_from(u128::from(st.f_blocks) * unit).ok()?;
    (total > 0 && free <= total).then_some((free, total))
}

/// Whether `free` of `total` bytes is low: under `LOW_DISK_BYTES`, or under `LOW_DISK_PERCENT` of the volume. The
/// one rule for the low-disk notification and for what the daemon's status says.
pub fn disk_is_low(free: u64, total: u64) -> bool {
    free < LOW_DISK_BYTES || u128::from(free) * 100 < u128::from(total) * u128::from(LOW_DISK_PERCENT)
}

/// What `start` warns about in the configuration, one sentence each. `key_is_set` says whether a variable
/// is present and not empty in the daemon's environment; `env` is that environment (names and values).
fn start_warnings(
    config: &Config,
    macos: bool,
    keys_dir: &std::path::Path,
    key_is_set: impl Fn(&str) -> bool,
    env: &[(String, String)],
) -> Vec<String> {
    let mut out = Vec::new();
    if config.notify.command.is_empty() && !macos {
        out.push(
            "Notifications are off on this platform: inbox items and fatal errors notify nobody. Set [notify] command in the config to a program that shows them, and restart the daemon."
                .to_string(),
        );
    }
    if config.sandbox.mode == SandboxMode::None {
        out.push(
            "The sandbox is off ([sandbox] mode = \"none\"): the commands of every session run unconfined. Set mode = \"seatbelt\" on macOS to confine them."
                .to_string(),
        );
    }
    out.extend(config.key_env_warnings(keys_dir, key_is_set));
    out.extend(secret_env_warning(config, env));
    out
}

/// The warning that names (never with their values) the variables of the daemon's environment that
/// commands are not given as secrets but can read from the daemon's environment: all but `LOOM_*`, the
/// profiles' `api_key_env` (reported on their own) and the `sandbox.env_pass` names.
fn secret_env_warning(config: &Config, env: &[(String, String)]) -> Option<String> {
    let known = |name: &str| {
        name.to_ascii_uppercase().starts_with("LOOM_")
            || config.models.values().any(|p| p.api_key_env.as_deref() == Some(name))
            || config.sandbox.env_pass.iter().any(|n| n == name)
    };
    let names: std::collections::BTreeSet<&str> = env
        .iter()
        .filter(|(name, value)| loom_tools::sandbox::withheld(name, value) && !known(name))
        .map(|(name, _)| name.as_str())
        .collect();
    if names.is_empty() {
        return None;
    }
    let list = names.into_iter().collect::<Vec<_>>().join(", ");
    Some(format!(
        "The daemon's environment holds variables that look like secrets: {list}. Commands are not given them, but every command can read them from the daemon's environment. Start the daemon with `loom up` or `loom service install`, which pass only what it needs; a `loom daemon` run from a shell keeps all of that shell's variables."
    ))
}

/// The warning for a profile whose configured window is larger than the one its server reports.
fn window_warning(profile: &str, configured: Option<u64>, server: Option<u64>) -> Option<String> {
    match (configured, server) {
        (Some(c), Some(s)) if c > s => Some(format!(
            "The profile \"{profile}\" sets context_window = {c}, but its server reports a window of {s}: requests may be refused. Lower context_window in [models.{profile}] of the config, or remove it to use the server's, and restart the daemon."
        )),
        _ => None,
    }
}

/// The notification title: the model wrote a child's, so it is marked.
fn notice_title(title: &str, child: bool) -> String {
    if child {
        format!("{UNVERIFIED_TITLE}{title}")
    } else {
        title.to_string()
    }
}

/// Starts the title of a notification whose session title the model wrote.
const UNVERIFIED_TITLE: &str = "unverified: ";

/// Starts the text of a notification the model wrote.
const UNVERIFIED_TEXT: &str = "[From the agent, unverified] ";

/// The inbox kind in snake case, as notifications name it.
fn inbox_kind_word(item: &InboxItem) -> String {
    serde_json::to_value(item.kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "question".to_string())
}

/// What a notification says about an inbox item. An item opened by a tool call (`call_id` set: a question, a
/// blocker or a finish the model wrote) starts with a fixed label saying so. In one the harness opened itself
/// (`call_id` unset) only the paragraph that quotes the ledger, which the model wrote, carries the label.
/// `still_waiting` is the restart notice for an item that is still open.
fn notice_text(item: &InboxItem, still_waiting: bool) -> String {
    let waiting = if still_waiting { "Still waiting: " } else { "" };
    if item.call_id.is_some() {
        return format!("{UNVERIFIED_TEXT}{waiting}{}", item.text);
    }
    let text = item
        .text
        .split("\n\n")
        .map(|p| if p.starts_with(crate::gate::OPEN_HEADING) { format!("{UNVERIFIED_TEXT}{p}") } else { p.to_string() })
        .collect::<Vec<_>>()
        .join("\n\n");
    format!("{waiting}{text}")
}

/// Run the notification for one event. Failures are warnings.
async fn run_notify(command: Vec<String>, kind: String, session: String, title: String, text: String) {
    let mut cmd = if let Some((program, args)) = command.split_first() {
        let mut c = tokio::process::Command::new(program);
        c.args(args)
            .env("LOOM_KIND", &kind)
            .env("LOOM_SESSION", &session)
            .env("LOOM_TITLE", &title)
            .env("LOOM_TEXT", cut_chars(&text, 500));
        c
    } else if cfg!(target_os = "macos") {
        let mut c = tokio::process::Command::new("/usr/bin/osascript");
        c.args([
            "-e",
            "on run argv",
            "-e",
            "display notification (item 2 of argv) with title (item 1 of argv)",
            "-e",
            "end run",
        ])
        .arg(format!("loom: {kind} \u{2014} {title}"))
        .arg(cut_chars(&text, 200));
        c
    } else {
        return;
    };
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    match tokio::time::timeout(NOTIFY_TIMEOUT, cmd.status()).await {
        Ok(Ok(status)) if status.success() => {}
        Ok(Ok(status)) => tracing::warn!("the notification command ended with {status}"),
        Ok(Err(e)) => tracing::warn!("the notification command could not be run: {e}"),
        Err(_) => tracing::warn!("the notification command was killed after {} s", NOTIFY_TIMEOUT.as_secs()),
    }
}

/// Publish a proxy decision that the audit hook (`net_audit`) could not put on record; the proxy sends
/// only those here.
fn record_net(inner: &Inner, session: SessionId, decision: NetDecision) {
    let entry = NetEntry { ts_ms: now_ms(), decision };
    inner.publish(BusEvent::Net { session, entry });
}

/// Where the proxy's decisions that name no session are kept, under `logs/`.
const UNATTRIBUTED_NET: &str = "net-unattributed.jsonl";

/// Where the rule counters of the mission boxes are recorded, under `logs/`.
const BOX_COUNTERS_FILE: &str = "box-counters.jsonl";

/// Where the floor's events (decoy hits, vetoes, squatted lab ports) are appended, under `logs/`.
const FLOOR_EVENTS_FILE: &str = "floor.jsonl";

/// How often the mission boxes' rule counters are read.
#[cfg_attr(test, allow(dead_code))]
const BOX_COUNTERS_EVERY: Duration = Duration::from_secs(60);

/// Appends `line` and a newline to `path` (made, with its directory, when missing) and syncs it.
fn append_line(path: &Path, line: &str) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    f.write_all(format!("{line}\n").as_bytes())?;
    f.sync_data()
}

/// The proxy's audit hook: appends the decision to the session's `net.jsonl` as a chained line, syncs
/// it to disk, and then publishes the same entry as [`BusEvent::Net`]; so an allowed connection is on
/// record before it is used. A decision that names no session goes to `logs/net-unattributed.jsonl`.
fn net_audit(paths: Paths, bus: broadcast::Sender<BusEvent>) -> loom_net::AuditFn {
    let writer = loom_net::netlog::NetLogWriter::new();
    Arc::new(move |session: Option<&SessionId>, decision: &NetDecision| {
        let entry = NetEntry { ts_ms: now_ms(), decision: decision.clone() };
        let Some(session) = session else {
            return writer.append(&paths.logs_dir().join(UNATTRIBUTED_NET), &entry);
        };
        let dir = paths.session_dir(session);
        if !dir.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("the session directory {} does not exist", dir.display()),
            ));
        }
        writer.append(&dir.join("net.jsonl"), &entry)?;
        let _ = bus.send(BusEvent::Net { session: session.clone(), entry });
        Ok(())
    })
}

/// The runtime. Cheap to clone; all clones are the same runtime.
#[derive(Clone)]
pub struct Runtime {
    inner: Arc<Inner>,
}

impl Runtime {
    /// Bring the runtime up over `paths` and restore what was running. See *Start*.
    pub async fn start(mut config: Config, paths: Paths) -> Result<Runtime, String> {
        // The loopback ports of infrastructure that no command may reach, whatever loopback it is allowed.
        config.sandbox.infra_ports = crate::infra::loopback_ports(&config);
        config.check().map_err(|e| e.to_string())?;
        // The infrastructure every command policy refuses is checked now, not at the first session.
        // The names are resolved here, once, and again every `RESOLVE_EVERY` (see `crate::infra`).
        let resolution = {
            let config = config.clone();
            tokio::task::spawn_blocking(move || crate::infra::resolve_system(&config)).await.unwrap_or_default()
        };
        let floor_policy =
            infra_policy(&config, &resolution).map_err(|e| format!("The network configuration cannot be used: {e}"))?;
        paths
            .ensure_private_layout()
            .map_err(|e| format!("cannot create {} as a private directory: {e}", paths.home.display()))?;
        let packs = Packs::load(&paths.packs_dir())?;
        packs.check_tools(&rtools::known_tools())?;
        packs.check_profiles(&config.models)?;
        let key = journal::load_or_create_key(&paths.journal_key())
            .map_err(|e| format!("cannot read or create the journal key {}: {e}", paths.journal_key().display()))?;
        let blobs = BlobStore::open(paths.blobs_dir()).map_err(|e| format!("cannot open the blob store: {e}"))?;
        let mut profiles = BTreeMap::new();
        for (name, profile) in &config.models {
            let client = ModelClient::new(name, profile.clone(), &paths.model_keys_dir()).map_err(|e| e.to_string())?;
            profiles.insert(
                name.clone(),
                ProfileRt {
                    client: Arc::new(client),
                    limiter: Arc::new(Limiter::new(profile.max_concurrent)),
                    discovered: Mutex::new(None),
                },
            );
        }
        let env_key_is_set = |var: &str| std::env::var_os(var).is_some_and(|v| !v.is_empty());
        let daemon_env: Vec<(String, String)> = std::env::vars_os()
            .map(|(k, v)| (k.to_string_lossy().into_owned(), v.to_string_lossy().into_owned()))
            .collect();
        for warning in
            start_warnings(&config, cfg!(target_os = "macos"), &paths.model_keys_dir(), env_key_is_set, &daemon_env)
        {
            tracing::warn!("{warning}");
        }
        config.check_box_paths(&paths.home)?;
        let box_host = if config.boxed.enabled {
            Some(DockerHost::new(&config.boxed, &paths.home).map_err(|e| format!("The box cannot be used: {e}"))?)
        } else {
            None
        };
        let (bus, _) = broadcast::channel(BUS_CAPACITY);
        let (net_tx, mut net_rx) = unbounded_channel();
        let audit = net_audit(paths.clone(), bus.clone());
        let proxy = Proxy::start_with(config.daemon.proxy_port, net_tx, Some(audit), Default::default())
            .await
            .map_err(|e| e.to_string())?;
        // Until the first self-probe finishes (`crate::egress`).
        let initial_egress = crate::egress::assess(&config.sandbox, None, None);
        // A seatbelt start has no probe yet, which is not a problem to tell; mode `none` is one that stands.
        let problem_told_at_start = initial_egress.level == crate::egress::Level::Unbounded
            && initial_egress.probe_problem
            && config.sandbox.mode != SandboxMode::Seatbelt;
        let inner = Arc::new_cyclic(|me: &Weak<Inner>| Inner {
            me: me.clone(),
            config,
            paths,
            blobs,
            bus,
            packs,
            key,
            profiles,
            proxy,
            state: Mutex::new(State::default()),
            scan_lock: tokio::sync::Mutex::new(()),
            activation: Mutex::new(()),
            shutting: AtomicBool::new(false),
            disk_low: AtomicBool::new(false),
            restoring: AtomicBool::new(true),
            next_gen: AtomicU64::new(1),
            orch: Arc::new(Orch(me.clone())),
            sink: Arc::new(SinkImpl(me.clone())),
            pagers: Mutex::new(Vec::new()),
            box_host,
            infra: Mutex::new(resolution),
            egress_told: AtomicBool::new(initial_egress.level == crate::egress::Level::Unbounded),
            egress_problem_told: AtomicBool::new(problem_told_at_start),
            egress: Mutex::new(initial_egress),
            census: Mutex::new(None),
            census_told: Mutex::new(crate::census::Told::new()),
            census_blind_told: AtomicBool::new(false),
            floor: crate::floor::Floor::new(floor_policy),
            box_counters_failed: Mutex::new(BTreeSet::new()),
        });

        let weak = Arc::downgrade(&inner);
        let forwarder = tokio::spawn(async move {
            while let Some((session, decision)) = net_rx.recv().await {
                match weak.upgrade() {
                    Some(inner) => record_net(&inner, session, decision),
                    None => return,
                }
            }
        });
        inner.st().tasks.push(forwarder);
        // Not under test: whether the disk of the machine that runs the tests is low must not change them.
        #[cfg(not(test))]
        {
            let weak = Arc::downgrade(&inner);
            let watcher = tokio::spawn(async move {
                loop {
                    let Some(inner) = weak.upgrade() else { return };
                    let home = inner.paths.home.clone();
                    drop(inner);
                    let space = tokio::task::spawn_blocking(move || volume_space(&home)).await.ok().flatten();
                    let Some(inner) = weak.upgrade() else { return };
                    if let Some((free, total)) = space {
                        inner.note_disk(disk_is_low(free, total));
                    }
                    drop(inner);
                    tokio::time::sleep(DISK_CHECK_EVERY).await;
                }
            });
            inner.st().tasks.push(watcher);
        }

        // Not under test: a resolver of the machine that runs the tests must not change them.
        #[cfg(not(test))]
        {
            let weak = Arc::downgrade(&inner);
            let config = inner.config.clone();
            let refresher = tokio::spawn(async move {
                loop {
                    tokio::time::sleep(crate::infra::RESOLVE_EVERY).await;
                    let config = config.clone();
                    let fresh = tokio::task::spawn_blocking(move || crate::infra::resolve_system(&config)).await;
                    let (Some(inner), Ok(fresh)) = (weak.upgrade(), fresh) else { return };
                    if let Ok(policy) = infra_policy(&inner.config, &fresh) {
                        inner.floor.set_infrastructure(policy);
                    }
                    inner.proxy.set_local_addrs(fresh.local.clone());
                    *inner.infra.lock().unwrap_or_else(|p| p.into_inner()) = fresh;
                }
            });
            inner.st().tasks.push(refresher);
        }

        // The self-probe of the sandbox (E2): at start and every `PROBE_EVERY`. Not under test: a test runtime
        // must not run commands against the machine's services.
        #[cfg(not(test))]
        {
            let weak = Arc::downgrade(&inner);
            let (cfg, home) = (inner.config.sandbox.clone(), inner.paths.home.clone());
            let prober = tokio::spawn(async move {
                loop {
                    let report = crate::egress::probe(cfg.clone(), home.clone()).await;
                    let Some(inner) = weak.upgrade() else { return };
                    inner.record_egress(Some(report));
                    drop(inner);
                    tokio::time::sleep(crate::egress::PROBE_EVERY).await;
                }
            });
            inner.st().tasks.push(prober);
        }

        // The floor's controls in the proxy (E4): the veto, the canary hooks and the lab-listener check. The
        // listener check asks the census's machinery who listens on a loopback port, over the sessions known now.
        {
            let weak = Arc::downgrade(&inner);
            let probe: crate::floor::ListenerProbe = Arc::new(move |who, to, client| {
                let Some(inner) = weak.upgrade() else { return loom_tools::sandbox::census::Listening::Unknown };
                let (members, _) = inner.census_sessions();
                let asked: Vec<loom_tools::sandbox::census::Member<'_>> =
                    members.iter().map(|(id, tmp)| loom_tools::sandbox::census::Member { id, tmp }).collect();
                let peers = inner.mission_peers(who);
                let own: Vec<&str> = peers.iter().map(String::as_str).collect();
                let home = crate::census::canonical_home(&inner.paths.home);
                loom_tools::sandbox::census::listener_of(&home, &asked, to, client, inner.census_confined(), &own)
            });
            inner.floor.set_log(Some(inner.paths.logs_dir().join(FLOOR_EVENTS_FILE)));
            inner.proxy.set_local_addrs(inner.infra().local);
            inner.floor.install(&inner.proxy, Some(probe));
            let weak = Arc::downgrade(&inner);
            inner.floor.set_notifier(Some(Arc::new(move |e: &crate::floor::FloorEvent| {
                let Some(inner) = weak.upgrade() else { return };
                let session = e.session.clone().unwrap_or_else(|| SessionId::from(""));
                let (title, text) = crate::floor::notice(e);
                inner.notify("floor", &session, &title, &text);
            })));
        }

        // The mission boxes' rule counters (E4f): every `BOX_COUNTERS_EVERY`. Not under test: a test runtime
        // has no Docker host to ask unless the test provides one.
        #[cfg(not(test))]
        if inner.box_host.is_some() {
            let weak = Arc::downgrade(&inner);
            let poller = tokio::spawn(async move {
                loop {
                    tokio::time::sleep(BOX_COUNTERS_EVERY).await;
                    let Some(inner) = weak.upgrade() else { return };
                    inner.poll_box_counters().await;
                }
            });
            inner.st().tasks.push(poller);
        }

        // The process and listener census of the sessions (E3): every `census::EVERY`. Not under test: a test
        // runtime must not scan the machine's process table.
        #[cfg(not(test))]
        {
            let weak = Arc::downgrade(&inner);
            let census = tokio::spawn(async move {
                loop {
                    let Some(inner) = weak.upgrade() else { return };
                    inner.run_census().await;
                    drop(inner);
                    tokio::time::sleep(crate::census::EVERY).await;
                }
            });
            inner.st().tasks.push(census);
        }

        inner.load_known();
        let mut restored: Vec<SessionId> = Vec::new();
        // The flag marks a session that is wanted only for a job (its turn yielded while the job ran,
        // or before it was told how the job ended, and the job's end would have started the next one).
        let candidates: Vec<(SessionId, bool)> = {
            let st = inner.st();
            st.known
                .iter()
                .filter(|(_, k)| !k.meta.archived && k.status.phase != Phase::Ended)
                .filter_map(|(id, k)| {
                    // An agent of a mission that is not archived is restored whatever it was doing:
                    // it goes on, or it is settled now, so that its lead is never left waiting for it.
                    let wanted = k.status.phase == Phase::Running
                        || k.status.last_end == Some(TurnEndReason::Waiting)
                        || k.status.open_inbox > 0
                        || k.meta.parent.is_some();
                    let yielded = k.status.last_end == Some(TurnEndReason::Yielded);
                    (wanted || yielded).then(|| (id.clone(), !wanted))
                })
                .collect()
        };
        let wanted: Vec<SessionId> = candidates
            .into_iter()
            .filter(|(id, for_a_job)| !for_a_job || inner.has_job_news(id))
            .map(|(id, _)| id)
            .collect();
        // After the candidates are chosen: the sweep leaves the sessions to activate to their job tables.
        inner.clear_crash_leftovers(&wanted).await;
        let mut cut: HashSet<SessionId> = HashSet::new();
        let mut woken: HashSet<SessionId> = HashSet::new();
        for id in wanted {
            match inner.activate(&id) {
                Ok(a) => {
                    if a.cut {
                        cut.insert(id.clone());
                    }
                    if a.woken {
                        woken.insert(id.clone());
                    }
                    if !a.already {
                        restored.push(id);
                    }
                }
                Err(e) => {
                    tracing::error!("session {} cannot be restored: {e}", id.as_str());
                    inner.publish_error(Some(&id), format!("Session {} cannot be restored: {e}", id.as_str()));
                    // An agent whose lead runs but that cannot be opened itself will never run again.
                    if inner.lead_is_active(&id) {
                        inner.settle_unopenable(&id, &e);
                    }
                }
            }
        }
        let recovered = inner.recover_settlements(|_| true);
        // After the settlements: delivering one activates a parent, which restores its open items too.
        inner.renotify_open_blocking();
        // The sessions told to carry on (parents come before their children).
        let mut going: HashSet<SessionId> = HashSet::new();
        for id in restored {
            let (unattended, last_end, active, parent, finished) = {
                let st = inner.st();
                match st.known.get(&id) {
                    Some(k) => {
                        (k.meta.unattended, k.status.last_end, k.active.is_some(), k.meta.parent.clone(), k.finished())
                    }
                    None => continue,
                }
            };
            if !active || finished {
                continue;
            }
            if let Some(parent) = parent {
                // An agent that has had a turn is idle now (the restart cut its turn, or it was between
                // turns): it is held until its lead goes on, the lead being told that its unfinished
                // agents were resumed. One that never had a turn starts its first one by itself.
                if last_end.is_some() {
                    if let Some(k) = inner.st().known.get_mut(&id) {
                        k.held = true;
                    }
                    if woken.contains(&id) || unattended || going.contains(&parent) {
                        inner.resume_held(&id);
                    }
                }
                continue;
            }
            // The settlement recovered for it starts a turn by itself.
            let turn_coming =
                recovered.contains(&id) && matches!(last_end, Some(TurnEndReason::Waiting | TurnEndReason::Yielded));
            // A session that waited on a job the restart lost is woken, attended or not: the job's
            // arrival would have woken it. A lead that waits for its agents is woken by their reports.
            let carry_on = !turn_coming
                && (woken.contains(&id)
                    || (unattended
                        && (cut.contains(&id)
                            || (last_end == Some(TurnEndReason::Waiting) && !inner.has_unsettled_child(&id)))));
            if carry_on {
                inner.send_input(&id, Input::Resume);
            }
            if carry_on || turn_coming {
                going.insert(id);
            }
        }
        inner.reconcile_boxes();
        Ok(Runtime { inner })
    }

    pub fn config(&self) -> &Config {
        &self.inner.config
    }

    pub fn paths(&self) -> &Paths {
        &self.inner.paths
    }

    pub fn blobs(&self) -> &BlobStore {
        &self.inner.blobs
    }

    /// Whether a sandboxed command can reach the network outside the egress proxy: the last self-probe's view
    /// (`crate::egress`), `Unprobed` until the first one finishes.
    pub fn egress(&self) -> crate::egress::EgressView {
        self.inner.egress.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// The last process and listener census (`crate::census`), `None` until the first one has finished.
    pub fn census(&self) -> Option<crate::census::CensusView> {
        self.inner.census.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// A census taken now, and kept as the last one.
    pub async fn census_now(&self) -> Result<crate::census::CensusView, String> {
        self.inner
            .run_census()
            .await
            .ok_or_else(|| "The census could not be taken: the thread that reads the process table failed.".to_string())
    }

    /// Stops every process the census finds for `session` (a lead or an agent; a child's commands in the
    /// parent's copy are the parent's): SIGSTOP then SIGKILL, repeated until none is left. Nothing else is stopped.
    pub async fn census_kill(&self, session: &SessionId) -> Result<loom_tools::sandbox::census::Killed, String> {
        let known = self.inner.st().known.contains_key(session);
        if !known {
            return Err(no_session(session));
        }
        let hints = crate::census::known_groups(self.census().as_ref(), session.as_str());
        let (id, home) = (session.as_str().to_string(), self.inner.paths.home.clone());
        let tmp = crate::census::members(&self.inner.paths, std::slice::from_ref(session)).remove(0).1;
        let confined = self.inner.census_confined();
        let killed = tokio::task::spawn_blocking(move || {
            let member = loom_tools::sandbox::census::Member { id: &id, tmp: &tmp };
            loom_tools::sandbox::census::kill(&crate::census::canonical_home(&home), &[member], &[], &hints, confined)
        })
        .await
        .map_err(|e| format!("The census kill failed to run: {e}."))?;
        if !killed.readable {
            return Err(format!(
                "The process table could not be read, so nothing of session {} was stopped. Try again, or stop its processes by hand.",
                session.as_str()
            ));
        }
        if !killed.left.is_empty() {
            tracing::warn!(
                "{} process(es) of session {} survived the census kill; ask for the census again or stop them by hand",
                killed.left.len(),
                session.as_str()
            );
        }
        Ok(killed)
    }

    /// The floor's controls of the proxy (`crate::floor`): canary users and hosts, and the events of the veto, the
    /// canary hook and the lab-listener check.
    pub fn floor(&self) -> crate::floor::Floor {
        self.inner.floor.clone()
    }

    /// Ends every open tunnel and forwarded request of the sessions of `mission` (its lead, its agents and their
    /// copies), reference grants' included (`loom_net::Proxy::cut_sessions`, E4a), and returns how many were
    /// ended. It does not change any policy: a caller that is holding the mission sets the hold first.
    pub fn cut_mission(&self, mission: &MissionId) -> usize {
        let sessions: Vec<SessionId> = self
            .inner
            .st()
            .known
            .iter()
            .filter(|(_, k)| &k.meta.mission == mission)
            .map(|(id, _)| id.clone())
            .collect();
        self.inner.proxy.cut_sessions(sessions.iter())
    }

    /// The rule counters of the mission boxes that moved since the last poll, read now (and recorded in
    /// `<home>/logs/box-counters.jsonl` as the periodic poll does).
    pub async fn box_counters_now(&self) -> Vec<(MissionId, Vec<loom_tools::boxctl::RuleCount>)> {
        self.inner.poll_box_counters().await
    }

    /// Take a self-probe report as the probe loop does (tests, and a caller that probed by other means).
    pub fn record_egress_probe(&self, report: loom_tools::sandbox::selfprobe::Report) {
        self.inner.record_egress(Some(report));
    }

    /// Port of the egress proxy on 127.0.0.1.
    pub fn proxy_port(&self) -> u16 {
        self.inner.proxy.port()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<BusEvent> {
        self.inner.bus.subscribe()
    }

    pub async fn create_session(&self, new: NewSession) -> Result<SessionInfo, String> {
        let inner = &self.inner;
        inner.check_open()?;
        let workspace = std::fs::canonicalize(&new.workspace)
            .map_err(|e| format!("The workspace {} cannot be used: {e}", new.workspace.display()))?;
        if !workspace.is_dir() {
            return Err(format!("The workspace {} is not a directory.", workspace.display()));
        }
        let role = inner.packs.role(new.pack.as_deref(), new.role.as_deref())?.clone();
        inner.check_network(&role.pack)?;
        let profile_name = inner
            .config
            .profile(new.model.as_deref().or(role.model.as_deref()))
            .map_err(|e| e.to_string())?
            .0
            .to_string();
        let (model, window, from_config) = inner.facts(&profile_name).await?;
        let title = match new.title.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
            Some(t) => t.to_string(),
            None => {
                let first = new.message.as_deref().and_then(|m| m.lines().map(str::trim).find(|l| !l.is_empty()));
                match first {
                    Some(l) => cut_chars(l, 80),
                    None => "untitled".to_string(),
                }
            }
        };
        let (prior_ids, recalled) = self.recall_earlier(&new.prior).await?;
        let id = SessionId::generate();
        let explicit = role.termination == Termination::Explicit;
        let meta = SessionMeta {
            id: id.clone(),
            mission: MissionId::generate(),
            parent: None,
            workspace: workspace.display().to_string(),
            copy_of: None,
            pack: role.pack.clone(),
            role: role.name.clone(),
            profile: profile_name.clone(),
            model,
            context_window: window,
            title,
            created_ms: now_ms(),
            mode: None,
            awaited: false,
            unattended: new.unattended.unwrap_or(explicit),
            archived: false,
            gate: None,
            prior: prior_ids,
        };
        inner.st().known.insert(id.clone(), Known::new(meta.clone(), idle_status()));
        let forget = |inner: &Inner| {
            inner.proxy.revoke(&id);
            inner.st().known.remove(&id);
        };
        let (deps, parts) = match inner.build(&meta, explicit) {
            Ok(x) => x,
            Err(e) => {
                forget(inner);
                return Err(e);
            }
        };
        let start = match inner.start_record(&meta, &deps, new.budget.clone()) {
            Ok(s) => s,
            Err(e) => {
                forget(inner);
                return Err(e);
            }
        };
        let mut session = match Session::create(deps, start, None) {
            Ok(s) => s,
            Err(e) => {
                forget(inner);
                return Err(e);
            }
        };
        if !recalled.is_empty() {
            if let Err(e) = session.recall(prior::brief(&recalled)) {
                forget(inner);
                return Err(e);
            }
        }
        if let Err(e) = write_json_atomic(&inner.paths.session_dir(&id).join("meta.json"), &meta) {
            forget(inner);
            return Err(format!("cannot write the session's meta.json: {e}"));
        }
        if from_config {
            // Recorded in the daemon log only, once the session exists.
            tracing::info!(
                session = %id.as_str(), profile = %profile_name, context_window = ?window,
                "the model server did not answer; this session's context window comes from the configuration"
            );
        }
        let info = {
            let mut st = inner.st();
            if let Some(k) = st.known.get_mut(&id) {
                k.status = session.status();
            }
            let me = inner.me().ok_or_else(|| SHUTTING.to_string())?;
            me.launch(&mut st, &id, session, parts);
            st.known.get(&id).map(Inner::info_of)
        };
        let info = info.ok_or_else(|| no_session(&id))?;
        inner.publish(BusEvent::Session { info: Box::new(info) });
        if let Some(message) = new.message.as_deref().filter(|m| !m.trim().is_empty()) {
            self.send_message(&id, message).await?;
        }
        self.session(&id).ok_or_else(|| no_session(&id))
    }

    /// The earlier missions `named` by the operator: trimmed, blanks and repeats dropped, each the mission of a
    /// known session, and what their sealed journals hold (read on a blocking thread).
    async fn recall_earlier(&self, named: &[MissionId]) -> Result<(Vec<MissionId>, Vec<prior::Recalled>), String> {
        let mut ids: Vec<MissionId> = Vec::new();
        let mut seen: HashSet<&str> = HashSet::new();
        for m in named {
            let m = m.as_str().trim();
            if !m.is_empty() && seen.insert(m) {
                // Only the first MAX_PRIOR are kept; the rest are only counted.
                if ids.len() <= prior::MAX_PRIOR {
                    ids.push(MissionId::from(m));
                }
            }
        }
        if seen.len() > prior::MAX_PRIOR {
            return Err(format!(
                "Name at most {} earlier missions to recall; {} were named.",
                prior::MAX_PRIOR,
                seen.len()
            ));
        }
        let mut found: Vec<(MissionId, String, Journal)> = Vec::new();
        {
            let st = self.inner.st();
            for m in &ids {
                let sessions = || st.known.values().filter(|k| &k.meta.mission == m);
                if sessions().next().is_none() {
                    return Err(format!("There is no mission {m} to recall."));
                }
                // The title is the lead's; a mission whose lead is not known has none (a child's title is
                // written by the model).
                let title = sessions().find(|k| k.meta.parent.is_none()).map(|k| k.meta.title.clone());
                found.push((
                    m.clone(),
                    title.unwrap_or_else(|| "untitled".to_string()),
                    Journal::new(self.inner.paths.journal(m), self.inner.key.clone()),
                ));
            }
        }
        let mut recalled = Vec::new();
        for (id, title, journal) in found {
            let recall = tokio::task::spawn_blocking(move || prior::read(&journal))
                .await
                .map_err(|e| format!("Reading the ledger of mission {id} failed ({e}); try again."))?;
            recalled.push(prior::Recalled { id, title, recall });
        }
        Ok((ids, recalled))
    }

    pub fn sessions(&self, include_archived: bool) -> Vec<SessionInfo> {
        let st = self.inner.st();
        let mut out: Vec<SessionInfo> =
            st.known.values().filter(|k| include_archived || !k.meta.archived).map(Inner::info_of).collect();
        out.sort_by(|a, b| b.meta.created_ms.cmp(&a.meta.created_ms).then_with(|| b.meta.id.cmp(&a.meta.id)));
        out
    }

    pub fn session(&self, id: &SessionId) -> Option<SessionInfo> {
        self.inner.st().known.get(id).map(Inner::info_of)
    }

    /// The meta of `id`, refusing archived sessions and (when `root`) children.
    fn operable(&self, id: &SessionId, root: Option<&str>) -> Result<SessionMeta, String> {
        self.inner.check_open()?;
        let st = self.inner.st();
        let k = st.known.get(id).ok_or_else(|| no_session(id))?;
        if let (Some(_), Some(_)) = (root, &k.meta.parent) {
            return Err(match root {
                Some("message") => {
                    format!("Messages go to the lead session of a mission; {} is one of its agents.", id.as_str())
                }
                Some("resume") => {
                    format!("Resume goes to the lead session of a mission; {} is one of its agents.", id.as_str())
                }
                _ => {
                    format!("Only the lead session of a mission can be archived; {} is one of its agents.", id.as_str())
                }
            });
        }
        Ok(k.meta.clone())
    }

    pub async fn send_message(&self, id: &SessionId, text: &str) -> Result<(), String> {
        let meta = self.operable(id, Some("message"))?;
        if text.trim().is_empty() {
            return Err("Write a message to send.".to_string());
        }
        if meta.archived {
            return Err("This session is archived; unarchive it first.".to_string());
        }
        self.inner.activate(id)?;
        self.inner.box_reopen_for(id);
        if !self.inner.send_input(id, Input::User(text.to_string())) {
            return Err(format!("Session {} is not accepting input.", id.as_str()));
        }
        // The lead works again, so its agents do: after a restart its turn starts with a note
        // saying they were resumed.
        self.inner.resume_cut_children(id);
        Ok(())
    }

    /// The lead session of `id`'s mission (a child's id leads to its root): the session that owns the
    /// mission's ledger and takes the operator's rules and approvals.
    fn lead_of(&self, id: &SessionId) -> Result<SessionMeta, String> {
        self.inner.check_open()?;
        let st = self.inner.st();
        let k = st.known.get(id).ok_or_else(|| no_session(id))?;
        let lead = match &k.meta.parent {
            None => k.meta.clone(),
            Some(_) => st
                .known
                .values()
                .find(|r| r.meta.parent.is_none() && r.meta.mission == k.meta.mission)
                .map(|r| r.meta.clone())
                .ok_or_else(|| format!("There is no lead session for the mission of {}.", id.as_str()))?,
        };
        if lead.archived {
            return Err("This session is archived; unarchive it first.".to_string());
        }
        Ok(lead)
    }

    /// Hand `input` to the lead session `lead`, activating it. The session handles it at once when
    /// it is idle and at the next step of a running turn; until then it is queued, which the receipt
    /// says (`queued`), and kept on disk (`session::queue_input`), so that a daemon stop before then
    /// does not lose it. `ledger`: the mission keeps one; `stock`: the text put in place of a blank
    /// scope or reason.
    fn send_to_lead(
        &self,
        lead: &SessionId,
        input: Input,
        ledger: bool,
        stock: Option<&str>,
    ) -> Result<RuleReceipt, String> {
        self.inner.activate(lead)?;
        self.inner.box_reopen_for(lead);
        let input = queue_input(&self.inner.paths, lead, input)?;
        let kept = match &input {
            Input::Queued { file, .. } => Some(file.clone()),
            _ => None,
        };
        let sent = match self.inner.st().known.get(lead) {
            None => Err(no_session(lead)),
            Some(k) => {
                let queued = k.status.phase == Phase::Running;
                if k.active.as_ref().is_some_and(|a| a.inputs.send(input).is_ok()) {
                    Ok(RuleReceipt { lead: lead.clone(), queued, ledger, stock: stock.map(str::to_string) })
                } else {
                    Err(format!("Session {} is not accepting input.", lead.as_str()))
                }
            }
        };
        if let (Err(_), Some(file)) = (&sent, kept) {
            // Refused: the operator is told to send it again, so it must not be recorded later as well.
            let _ = std::fs::remove_file(file);
        }
        sent
    }

    /// Set a standing rule for the mission of `id` (any of its sessions; the rule goes to the lead).
    /// `Ok` means the rule was handed to the lead, not that it is recorded yet: the lead records it
    /// at once when it is idle, and at the next step of a running turn otherwise (so not while a
    /// tool call, such as an awaited agent, is still running; it is kept on disk until then, and a
    /// lead started after a daemon stop records it first). The receipt's `queued` says which of the
    /// two it was. Recording is a ledger entry, constraint `k<n>`, when the mission keeps a ledger
    /// (the lead's state block then lists the rule), and in
    /// every mission a protected note in the lead's window that is never folded out of view; the
    /// note tells the lead that the rule also binds the work it assigns to its agents. No turn is
    /// started: the lead reads the rule with its next request to the model. Without a ledger
    /// (receipt `ledger: false`) the rule has no id, is listed nowhere and cannot be withdrawn by id.
    pub async fn add_rule(&self, id: &SessionId, text: &str) -> Result<RuleReceipt, String> {
        let text = text.trim();
        if text.is_empty() {
            return Err("Write the rule to set.".to_string());
        }
        let lead = self.lead_of(id)?;
        let ledger = self.inner.mission_explicit(&lead)?;
        self.send_to_lead(&lead.id, Input::Constraint(text.to_string()), ledger, None)
    }

    /// Close the mission of `id` short of its goal, with the operator's `reason`. Handed to the lead
    /// and recorded like a rule (see [`Runtime::add_rule`]): an `OperatorRelease` ledger entry when
    /// the mission keeps a ledger, a protected note in the lead's window, no turn started. After it
    /// the finish gate no longer holds a finish for the goal. The session is not forced to stop; the
    /// operator stops it separately if they want it to end now.
    pub async fn release(&self, id: &SessionId, reason: &str) -> Result<RuleReceipt, String> {
        let reason = reason.trim();
        if reason.is_empty() {
            return Err("Write why the mission is closed without the goal established.".to_string());
        }
        let lead = self.lead_of(id)?;
        let ledger = self.inner.mission_explicit(&lead)?;
        let receipt = self.send_to_lead(&lead.id, Input::Release { reason: reason.to_string() }, ledger, None)?;
        // The box never has more than the mission's grants: its rules are brought to them again.
        self.inner.box_resync(&lead.mission).await;
        Ok(receipt)
    }

    /// Record that the operator approved something, with what the approval covers. Handed to the
    /// lead and recorded like a rule (see [`Runtime::add_rule`]): ledger entry `a<n>` when the
    /// mission keeps a ledger, a protected note in the lead's window, no turn started. In a mission
    /// with a ledger a blank `scope` is recorded as `only what the approval says` (receipt `stock`);
    /// without one it stays blank and the note says that the approval covers only what it says.
    pub async fn approve(&self, id: &SessionId, text: &str, scope: &str) -> Result<RuleReceipt, String> {
        let (text, scope) = (text.trim(), scope.trim());
        if text.is_empty() {
            return Err("Write what is approved.".to_string());
        }
        let lead = self.lead_of(id)?;
        let ledger = self.inner.mission_explicit(&lead)?;
        // The ledger refuses an approval without a scope, which would leave it a note without an id.
        let stock = (ledger && scope.is_empty()).then_some(STOCK_SCOPE);
        let input = Input::Approval { text: text.to_string(), scope: stock.unwrap_or(scope).to_string() };
        self.send_to_lead(&lead.id, input, ledger, stock)
    }

    /// Withdraw the standing rule `rule_id` (`k<n>`, as listed in the ledger) of the mission of `id`.
    /// Refused unless the mission's ledger lists that rule as in force. Only recorded entries are seen:
    /// a rule still queued for a running lead, or a withdrawal queued earlier, is not in the ledger
    /// yet, so a rule that was just set may be refused as unknown until the lead has recorded it. A mission that keeps no
    /// ledger has no rule ids, and the refusal says to tell the lead in a message instead. Then
    /// handed to the lead like a rule (see [`Runtime::add_rule`]): the ledger marks the rule retired
    /// with `reason` and the lead gets a protected note saying so; no turn is started. A blank
    /// `reason` is recorded as `no reason given` (receipt `stock`).
    pub async fn withdraw_rule(&self, id: &SessionId, rule_id: &str, reason: &str) -> Result<RuleReceipt, String> {
        let (rule_id, reason) = (rule_id.trim(), reason.trim());
        if rule_id.is_empty() {
            return Err("Name the rule to withdraw (its id, such as k1).".to_string());
        }
        let lead = self.lead_of(id)?;
        // The session drops a withdrawal its ledger refuses and tells nobody, so what the ledger
        // would refuse is refused here, where the operator is told why.
        if !self.inner.mission_explicit(&lead)? {
            return Err(format!(
                "There is no rule {rule_id} to withdraw: this mission keeps no ledger, so its rules have no ids. Tell the lead in a message that the rule no longer applies."
            ));
        }
        // A journal not written yet reads as an empty ledger.
        let path = self.inner.paths.journal(&lead.mission);
        let rules = Journal::new(path, self.inner.key.clone()).state().map_err(|e| e.to_string())?.constraints;
        match rules.iter().find(|c| c.id == rule_id) {
            Some(c) if c.retired.is_none() => {}
            Some(_) => return Err(format!("Rule {rule_id} is already withdrawn.")),
            None => {
                let live: Vec<&str> = rules.iter().filter(|c| c.retired.is_none()).map(|c| c.id.as_str()).collect();
                return Err(if live.is_empty() {
                    format!("There is no rule {rule_id} in this mission; it has no rules in force.")
                } else {
                    format!("There is no rule {rule_id} in this mission; its rules are {}.", live.join(", "))
                });
            }
        }
        // The ledger refuses a retirement without a reason.
        let stock = reason.is_empty().then_some(STOCK_REASON);
        let input = Input::Withdraw { id: rule_id.to_string(), reason: stock.unwrap_or(reason).to_string() };
        self.send_to_lead(&lead.id, input, true, stock)
    }

    /// Authorize network access to `hosts` for the mission of `id` (any of its sessions): its egress
    /// policy becomes the configured network plus every host granted to the mission so far, for the
    /// lead and for each of its agents that is running, at once and without a restart (an agent started
    /// later gets it when it starts). The lead records the grant in the ledger (`ScopeGrant`, when the
    /// mission keeps one; receipt `ledger`) and gets a protected note saying so; no turn is started. A
    /// restored session gets its grants back from the ledger. The configured `deny` list and private
    /// address rules still apply to a granted host. Refused: an unknown or archived session, no host,
    /// a blank or invalid host, a session that is not running.
    pub async fn grant_scope(
        &self,
        id: &SessionId,
        hosts: &[String],
        note: Option<&str>,
    ) -> Result<ScopeReceipt, String> {
        let hosts = loom_net::policy::check_hosts(hosts)?;
        // Infrastructure is refused to every command whatever is granted: say so now, not at the first connect.
        let infra = Policy::new(&self.inner.config.network)
            .and_then(|p| p.with_infrastructure(&infra_spec_resolved(&self.inner.config, &self.inner.infra())))?;
        for h in &hosts {
            if let Some(rule) = infra.infrastructure_refusal(h) {
                return Err(format!(
                    "The host `{h}` is infrastructure of this machine or of loom ({rule}); no grant lets a command reach it, so nothing was granted. Grant the target by its own name or address instead."
                ));
            }
        }
        let note = note.map(str::trim).filter(|n| !n.is_empty()).map(str::to_string);
        let lead = self.lead_of(id)?;
        let ledger = self.inner.mission_explicit(&lead)?;
        // Held by the mission from now on, so that a lead activated by the send below gets the policy.
        let (added, unrevoked): (Vec<String>, Vec<String>) = {
            let mut st = self.inner.st();
            // A host granted again after a revoke is granted again.
            let revoked = st
                .scope_revoked
                .entry(lead.mission.clone())
                .or_insert_with(|| load_revoked(&self.inner.revoked_path(&lead.mission)));
            let unrevoked: Vec<String> =
                revoked.iter().filter(|r| hosts.iter().any(|h| h.eq_ignore_ascii_case(r))).cloned().collect();
            if !unrevoked.is_empty() {
                revoked.retain(|r| !unrevoked.iter().any(|u| u.eq_ignore_ascii_case(r)));
                let kept = revoked.clone();
                if let Err(e) = self.inner.save_revoked(&lead.mission, &kept) {
                    tracing::warn!("the revoked hosts could not be saved: {e}");
                }
            }
            let granted = st.scope.entry(lead.mission.clone()).or_default();
            let mut added = Vec::new();
            for h in &hosts {
                if !granted.iter().any(|x| x.eq_ignore_ascii_case(h)) {
                    granted.push(h.clone());
                    added.push(h.clone());
                }
            }
            let g = st.scope_gen.entry(lead.mission.clone()).or_insert(0);
            *g = g.wrapping_add(1);
            (added, unrevoked)
        };
        let input = Input::Scope { hosts: hosts.clone(), note };
        if let Err(e) = self.send_to_lead(&lead.id, input, ledger, None) {
            {
                let mut st = self.inner.st();
                if let Some(granted) = st.scope.get_mut(&lead.mission) {
                    granted.retain(|h| !added.contains(h));
                }
                // The revokes that this grant lifted stand again.
                if !unrevoked.is_empty() {
                    let revoked = st.scope_revoked.entry(lead.mission.clone()).or_default();
                    revoked.extend(unrevoked.iter().cloned());
                    let kept = revoked.clone();
                    if let Err(e) = self.inner.save_revoked(&lead.mission, &kept) {
                        tracing::warn!("the revoked hosts could not be saved: {e}");
                    }
                }
            }
            // A lead activated by the failed send was built with the new hosts: take them back.
            if !added.is_empty() || !unrevoked.is_empty() {
                self.inner.bump_scope_generation(&lead.mission);
                for meta in self.mission_family(&lead.mission) {
                    if let Ok(policy) = self.inner.session_policy(&meta, ledger) {
                        self.inner.proxy.set_policy(&meta.id, policy);
                    }
                }
            }
            return Err(e);
        }
        let family = self.mission_family(&lead.mission);
        let mut lead_set = false;
        for meta in &family {
            let policy = self.inner.session_policy(meta, ledger)?;
            let set = self.inner.proxy.set_policy(&meta.id, policy);
            lead_set |= set && meta.id == lead.id;
        }
        // The mission's box, when it has one, gets the new grants too (I5).
        self.inner.box_resync(&lead.mission).await;
        if !lead_set {
            return Err(format!(
                "Session {} is not running, so the authorization could not be applied to it now. It is recorded for the mission and applies when the session is resumed.",
                lead.id.as_str()
            ));
        }
        Ok(ScopeReceipt { lead: lead.id, hosts, ledger })
    }

    /// Withdraw the operator's grant of `host` (exactly as it was granted, ignoring case) from `mission`, for
    /// `reason`. In this order: (1) the revoke is appended to the mission's ledger (`ScopeRevoke`, the
    /// ledger refuses a host that is not granted, with a sentence listing what is; a mission without a
    /// ledger checks the grants held in memory); (2) the host leaves the mission's grants held in memory and
    /// is kept out of `granted_hosts` until it is granted again; (3) every running session of the mission
    /// gets its narrowed egress policy and its open tunnels and forwards to the host are cut
    /// (`Proxy::cut_hosts`); (4) the mission's box rules are applied again; (5) the lead, when it is
    /// running, gets a protected note (`Input::ScopeRevoked`, no turn). A session that starts later is built
    /// without the host. The infrastructure deny (E1) is not touched. A step after the first that fails
    /// does not undo the earlier ones: the error says what stands. Refused: a blank host or reason, a mission
    /// with no lead, a host that is not granted.
    pub async fn revoke_scope(
        &self,
        mission: &MissionId,
        host: &str,
        reason: &str,
    ) -> Result<ScopeRevokeReceipt, String> {
        self.inner.check_open()?;
        let (host, reason) = (host.trim(), reason.trim());
        if host.is_empty() {
            return Err(
                "Name the host to revoke, exactly as it was granted (a host or `*.suffix`, optionally with `:port`)."
                    .into(),
            );
        }
        if reason.is_empty() {
            return Err("Say why the host is revoked: the reason is kept in the ledger and shown to the lead.".into());
        }
        let lead = self.inner.mission_lead(mission).ok_or_else(|| {
            format!("There is no mission {} with a lead session; `loom ls` lists the missions.", mission.as_str())
        })?;
        let ledger = self.inner.mission_explicit(&lead)?;
        let granted = self.inner.granted_hosts(&lead, ledger);
        // What the ledger holds as granted now, apart from what was revoked here and not recorded: the lead
        // may have recorded the grant since, and then the revoke can be recorded too.
        let journal = Journal::new(self.inner.paths.journal(mission), self.inner.key.clone());
        let in_ledger: Vec<String> = if ledger {
            journal.state().map(|state| state.granted_hosts()).map_err(|e| {
                format!("The ledger of the mission cannot be read ({e}); nothing was changed. Try again.")
            })?
        } else {
            Vec::new()
        };
        let entry = match granted.iter().chain(&in_ledger).find(|h| h.eq_ignore_ascii_case(host)) {
            Some(h) => h.clone(),
            None => {
                let now = if granted.is_empty() {
                    "no host is granted to this mission".to_string()
                } else {
                    format!("granted to this mission: {}", granted.join(", "))
                };
                return Err(match covering_grant(&granted, host) {
                    Some(g) => format!("The host `{host}` is not granted by itself; the grant `{g}` covers it. Revoke `{g}` (a revoke names a grant exactly as it was written), then grant the hosts that should stay. ({now})"),
                    None => format!("The host `{host}` is not granted, so there is nothing to revoke ({now}). Write the host exactly as it was granted."),
                });
            }
        };
        // (1) The record first: a revoke that is not recorded would come back at the next start. The ledger
        // holds the grant when it lists the host itself; a grant the lead has not recorded yet (it is queued
        // on disk) is revoked here without a record, and the revoked-hosts file keeps it out.
        let mut recorded = false;
        if ledger && in_ledger.iter().any(|h| h.eq_ignore_ascii_case(&entry)) {
            let op = LedgerOp::ScopeRevoke { host: entry.clone(), reason: reason.to_string() };
            match journal.append(&lead.id, true, op, &|_| Ok(())) {
                Ok(_) => recorded = true,
                Err(e) => {
                    return Err(format!(
                        "The revoke could not be recorded in the ledger ({e}); nothing was changed. Try again."
                    ))
                }
            }
        }
        // (2) Out of the grants held in memory, and kept out until granted again: in memory and on disk, so
        // that it holds after a restart, whatever the ledger says of a grant recorded later.
        self.inner.bump_scope_generation(mission);
        let kept = {
            let mut st = self.inner.st();
            if let Some(held) = st.scope.get_mut(mission) {
                held.retain(|h| !h.eq_ignore_ascii_case(&entry));
            }
            let revoked = st
                .scope_revoked
                .entry(mission.clone())
                .or_insert_with(|| load_revoked(&self.inner.revoked_path(mission)));
            if !revoked.iter().any(|r| r.eq_ignore_ascii_case(&entry)) {
                revoked.push(entry.clone());
            }
            revoked.clone()
        };
        let saved = self.inner.save_revoked(mission, &kept);
        // (3) Every session of the mission, started or being started: the narrowed policy, then the open
        // connections.
        let (mut sessions, mut cut, mut failed) = (0u32, 0u32, Vec::new());
        for meta in self.mission_family(mission) {
            match self.inner.session_policy(&meta, ledger) {
                Ok(policy) => {
                    if self.inner.proxy.set_policy(&meta.id, policy) {
                        sessions = sessions.saturating_add(1);
                        let n = self.inner.proxy.cut_hosts(&meta.id, &entry);
                        cut = cut.saturating_add(u32::try_from(n).unwrap_or(u32::MAX));
                    }
                }
                Err(e) => failed.push(format!("{}: {e}", meta.id.as_str())),
            }
        }
        // (4) The box.
        self.inner.box_resync(mission).await;
        // (5) The lead is told; no turn, and nothing when it is not running.
        if let Some(k) = self.inner.st().known.get(&lead.id) {
            if let Some(a) = k.active.as_ref() {
                let _ = a.inputs.send(Input::ScopeRevoked { host: entry.clone(), reason: reason.to_string() });
            }
        }
        if let Err(e) = saved {
            if !recorded {
                return Err(format!(
                    "The revoke of {entry} is applied to the running sessions but could not be saved ({e}), and the ledger does not hold the grant yet: it is undone by a restart of the daemon. Free the disk or fix the permissions of the loom home, then revoke it again."
                ));
            }
            tracing::warn!("the revoked hosts of {} could not be saved: {e}", mission.as_str());
        }
        if !failed.is_empty() {
            return Err(format!(
                "The revoke of {entry} is recorded and kept out of every new session, but the egress policy of {} could not be rebuilt ({}): stop that session so that it restarts without the host.",
                failed.len(),
                failed.join("; ")
            ));
        }
        Ok(ScopeRevokeReceipt { lead: lead.id, host: entry, ledger, recorded, sessions, cut })
    }

    /// The metas of every session of `mission` that is known, started or not: one that is being started
    /// holds its proxy grant before it is active, and a grant or revoke must reach it.
    fn mission_family(&self, mission: &MissionId) -> Vec<SessionMeta> {
        let st = self.inner.st();
        st.known.values().filter(|k| &k.meta.mission == mission).map(|k| k.meta.clone()).collect()
    }

    pub async fn stop(&self, id: &SessionId) -> Result<(), String> {
        self.inner.check_open()?;
        let meta = self.inner.st().known.get(id).map(|k| k.meta.clone()).ok_or_else(|| no_session(id))?;
        self.inner.stop_one(id);
        // Stopping the lead of a mission ends its box (I5); an agent's stop does not.
        if meta.parent.is_none() {
            self.inner.box_teardown(&meta.mission);
        }
        Ok(())
    }

    pub async fn resume(&self, id: &SessionId) -> Result<(), String> {
        let meta = self.operable(id, Some("resume"))?;
        if meta.archived {
            return Err("This session is archived; unarchive it first.".to_string());
        }
        self.inner.activate(id)?;
        // Resuming the lead gives the mission its box back (it was removed when the mission was stopped).
        self.inner.box_reopen(&meta.mission);
        self.inner.send_input(id, Input::Resume);
        self.inner.resume_cut_children(id);
        Ok(())
    }

    pub async fn reweave(&self, id: &SessionId) -> Result<(), String> {
        self.inner.check_open()?;
        if !self.inner.st().known.contains_key(id) {
            return Err(no_session(id));
        }
        self.inner.activate(id)?;
        self.inner.box_reopen_for(id);
        self.inner.send_input(id, Input::Reweave);
        Ok(())
    }

    pub async fn archive(&self, id: &SessionId, archived: bool) -> Result<(), String> {
        self.operable(id, Some("archive"))?;
        let family: Vec<SessionId> = {
            let st = self.inner.st();
            let mut ids = vec![id.clone()];
            ids.extend(st.known.iter().filter(|(_, k)| k.meta.parent.as_ref() == Some(id)).map(|(c, _)| c.clone()));
            if archived
                && ids
                    .iter()
                    .any(|i| st.known.get(i).is_some_and(|k| k.active.is_some() && k.status.phase == Phase::Running))
            {
                return Err("Stop the session before archiving it.".to_string());
            }
            ids
        };
        let mut closing: Vec<UnboundedSender<Input>> = Vec::new();
        for sid in &family {
            let meta = {
                let mut st = self.inner.st();
                let Some(k) = st.known.get_mut(sid) else { continue };
                k.meta.archived = archived;
                if let Some(a) = k.active.as_mut().filter(|_| archived) {
                    // The task keeps its place until it has ended, so that nothing opens the session
                    // beside it while it settles.
                    let (closed, _) = unbounded_channel();
                    closing.push(std::mem::replace(&mut a.inputs, closed));
                }
                k.meta.clone()
            };
            if let Err(e) = write_json_atomic(&self.inner.paths.session_dir(sid).join("meta.json"), &meta) {
                return Err(format!("cannot write the meta.json of {}: {e}", sid.as_str()));
            }
        }
        // Dropping the inputs ends the tasks: the lead's `Closed`, each agent's with its settlement,
        // which reaches the lead when the mission is unarchived.
        drop(closing);
        if archived {
            // An archived session is not in the census, so what its task did not take with it (a process that left
            // its process group) is stopped now, once the tasks have ended, while it can still be found.
            let inner = self.inner.clone();
            let ids = family.clone();
            let leftovers = tokio::spawn(async move { inner.stop_leftovers(&ids).await });
            self.inner.st().tasks.push(leftovers);
            let lead = self.inner.st().known.get(id).map(|k| k.meta.clone()).filter(|m| m.parent.is_none());
            if let Some(lead) = lead {
                self.inner.box_teardown(&lead.mission);
            }
            // A session with a task has its scratch directory emptied as the task ends (`launch`, `on_end`).
            let idle: Vec<&SessionId> = {
                let st = self.inner.st();
                family.iter().filter(|sid| st.known.get(*sid).is_some_and(|k| k.active.is_none())).collect()
            };
            for sid in idle {
                let _ = self.inner.clear_scratch(sid).await;
            }
            // The agents' own copies of the workspace go with the mission: what was not adopted from
            // them is discarded. After their tasks have ended, so that no command still runs there.
            // A lead takes the mission's whole directory of copies, which also holds what a daemon
            // that died while copying left behind; an agent archived alone takes its own copy.
            let copies: Vec<PathBuf> = {
                let st = self.inner.st();
                let known = |sid: &SessionId| st.known.get(sid).map(|k| k.meta.clone());
                let own = |m: &SessionMeta| m.copy_of.as_ref().map(|_| PathBuf::from(&m.workspace));
                match known(id) {
                    Some(lead) if lead.parent.is_none() => {
                        let had = family.iter().filter_map(known).any(|m| m.copy_of.is_some());
                        let dir = self.inner.paths.mission_copies(&lead.mission);
                        if had || dir.exists() {
                            vec![dir]
                        } else {
                            Vec::new()
                        }
                    }
                    Some(agent) => own(&agent).into_iter().collect(),
                    None => Vec::new(),
                }
            };
            if !copies.is_empty() {
                self.inner.until_closed(&family).await;
                let removal = tokio::task::spawn_blocking(move || {
                    for dir in copies {
                        let _ = std::fs::remove_dir_all(&dir);
                        // The mission's directory, once its last copy is gone.
                        let _ = dir.parent().map(std::fs::remove_dir);
                    }
                });
                let _ = removal.await;
            }
        }
        if !archived {
            // A task an archive closed keeps its place until it has ended, and what is handed to it is
            // lost: those of the family end first.
            self.inner.until_closed(&family).await;
            // What the agents settled with while the mission was archived is delivered now, and an
            // agent that had not settled goes on with its lead (or is settled, if it cannot be opened).
            self.inner.restore_children(|p| p == id);
            self.inner.recover_settlements(|k| k.meta.parent.as_ref() == Some(id));
        }
        Ok(())
    }

    /// Garbage-collect stored outputs. Keeps every blob whose id, or `out:` handle, appears anywhere in the text
    /// of any file under the sessions and missions directories (logs, damaged-log remainders, meta, status, net
    /// audit, journals, job output), and every blob younger than `min_age` (default one hour) when the scan
    /// began. Only the rest is deleted, and only with `apply`; otherwise the report says what would be.
    /// Removing a session's directory is what makes its outputs collectable (those that another session's or a
    /// mission's files still name stay). Session temp directories are not read, links below a session or
    /// mission directory are not followed, and FIFOs, sockets and devices are not opened (`scan_tree_for_ids`).
    /// A file larger than `GC_FILE_MAX` (4 GiB), a scan that takes longer than `GC_SCAN_TIME` (5 minutes), and
    /// anything that cannot be read abort the collection before anything is deleted.
    pub async fn gc(&self, apply: bool, min_age: Option<Duration>) -> Result<loom_core::blob::SweepReport, String> {
        self.gc_within(apply, min_age, GC_FILE_MAX, GC_SCAN_TIME).await
    }

    /// `gc` whose scan reads at most `file_max` bytes of one file and stops after `time`.
    async fn gc_within(
        &self,
        apply: bool,
        min_age: Option<Duration>,
        file_max: u64,
        time: Duration,
    ) -> Result<loom_core::blob::SweepReport, String> {
        let blobs = self.inner.blobs.clone();
        // Only session directories have a temp directory.
        let roots = [(self.inner.paths.sessions_dir(), true), (self.inner.paths.missions_dir(), false)];
        let min_age = min_age.unwrap_or(loom_core::blob::DEFAULT_GC_MIN_AGE);
        tokio::task::spawn_blocking(move || {
            let started = std::time::Instant::now();
            let bounds = ScanBounds { file_max, time, started };
            let stored =
                blobs.ids().map_err(|e| format!("cannot list the blob store ({e}); nothing was collected."))?;
            let mut keep = HashSet::new();
            for (root, temp_dirs) in &roots {
                scan_tree_for_ids(root, *temp_dirs, &stored, &mut keep, &bounds)?;
            }
            // Ages count from the start of the scan: a blob stored since then (so not in `stored`), or stored
            // again, is kept whatever names it.
            let min_age = min_age.saturating_add(started.elapsed());
            blobs.sweep(&keep, min_age, apply).map_err(|e| format!("cannot sweep the blob store: {e}"))
        })
        .await
        .map_err(|e| format!("the collection task failed: {e}"))?
    }

    pub fn inbox(&self) -> Vec<InboxEntry> {
        let mut items = self.inner.st().inbox.clone();
        items.sort_by_key(|e| e.opened_ms);
        items
    }

    pub async fn answer(&self, item_id: &str, answer: &str) -> Result<(), String> {
        self.inner.check_open()?;
        let entry = self
            .inner
            .st()
            .inbox
            .iter()
            .find(|e| e.item.item_id == item_id)
            .cloned()
            .ok_or_else(|| format!("There is no open inbox item {item_id}."))?;
        if entry.item.blocking && answer.trim().is_empty() {
            return Err("This item is waiting for an answer; write one.".to_string());
        }
        self.inner.activate(&entry.session)?;
        if !answer.trim().is_empty() {
            self.inner.box_reopen_for(&entry.session);
        }
        if !self
            .inner
            .send_input(&entry.session, Input::Answer { item_id: item_id.to_string(), answer: answer.to_string() })
        {
            return Err(format!("Session {} is not accepting input.", entry.session.as_str()));
        }
        // An answer starts a turn (an empty one only dismisses the item): as for a message.
        if !answer.trim().is_empty() {
            self.inner.resume_cut_children(&entry.session);
        }
        Ok(())
    }

    pub fn records(&self, id: &SessionId, after: Option<Seq>, limit: usize) -> Result<Vec<Record>, String> {
        Ok(self.stored_records(id, after, limit)?.into_iter().map(|stored| stored.record).collect())
    }

    /// The page `records` gives, each record with its stored line when it was read as `Event::Unknown`.
    pub fn stored_records(
        &self,
        id: &SessionId,
        after: Option<Seq>,
        limit: usize,
    ) -> Result<Vec<StoredRecord>, String> {
        self.inner.check_open()?;
        if !self.inner.st().known.contains_key(id) {
            return Err(no_session(id));
        }
        let reader = {
            let mut pagers = lock(&self.inner.pagers);
            let reader = match pagers.iter().position(|(s, _)| s == id) {
                Some(i) => pagers.remove(i),
                None => (id.clone(), Arc::new(Mutex::new(PageReader::new(&self.inner.paths.session_log(id))))),
            };
            pagers.push(reader.clone());
            if pagers.len() > PAGERS_MAX {
                pagers.remove(0);
            }
            reader.1
        };
        let mut reader = lock(&reader);
        reader.read_stored(after, limit.min(PAGE_MAX)).map_err(|e| e.to_string())
    }

    pub fn window(&self, id: &SessionId) -> Result<WindowView, String> {
        self.inner.check_open()?;
        let (context_window, status) = {
            let st = self.inner.st();
            let k = st.known.get(id).ok_or_else(|| no_session(id))?;
            (k.meta.context_window, k.status.clone())
        };
        let records = read_records(&self.inner.paths.session_log(id)).map_err(|e| e.to_string())?.records;
        let w = weave(&records);
        let estimator = TokenEstimator::default();
        let tools_chars: usize = w.tools.iter().map(|t| t.to_openai().to_string().chars().count()).sum();
        let est_tokens = estimator.tokens_for_messages(&w.messages) + estimator.tokens(tools_chars);
        Ok(WindowView {
            epoch: w.epoch,
            items: w.items,
            est_tokens,
            target_tokens: self.inner.config.context.target_tokens,
            floor_tokens: self.inner.config.context.floor_tokens,
            context_window,
            prompt_tokens: status.prompt_tokens,
            cached_tokens: status.cached_tokens,
        })
    }

    pub fn missions(&self) -> Vec<MissionInfo> {
        let st = self.inner.st();
        let mut roots: Vec<&Known> = st.known.values().filter(|k| k.meta.parent.is_none()).collect();
        roots.sort_by(|a, b| b.meta.created_ms.cmp(&a.meta.created_ms).then_with(|| b.meta.id.cmp(&a.meta.id)));
        roots
            .into_iter()
            .map(|k| MissionInfo {
                id: k.meta.mission.clone(),
                root: k.meta.id.clone(),
                title: k.meta.title.clone(),
                created_ms: k.meta.created_ms,
                has_ledger: self.inner.paths.journal(&k.meta.mission).is_file(),
                archived: k.meta.archived,
            })
            .collect()
    }

    pub fn ledger(&self, mission: &MissionId) -> Result<LedgerView, String> {
        self.inner.check_open()?;
        // The id comes from a URL: only a mission some known session belongs to may reach a path.
        if !self.inner.st().known.values().any(|k| &k.meta.mission == mission) {
            return Err(format!("There is no mission {}.", mission.as_str()));
        }
        let path = self.inner.paths.journal(mission);
        if !path.is_file() {
            // A lead that keeps a ledger and has recorded nothing yet has an empty one; only a lead that keeps none has no ledger.
            // A lead whose role can no longer be looked up (its pack was removed) is taken to keep none.
            let lead = self
                .inner
                .st()
                .known
                .values()
                .find(|k| &k.meta.mission == mission && k.meta.parent.is_none())
                .map(|k| k.meta.clone());
            if !lead.is_some_and(|meta| self.inner.mission_explicit(&meta).unwrap_or(false)) {
                return Err("No ledger: this mission's lead does not keep one.".to_string());
            }
        }
        let read = Journal::new(path, self.inner.key.clone()).read_report().map_err(|e| e.to_string())?;
        let state = LedgerState::fold(&read.entries);
        let markdown = state.render_markdown();
        Ok(LedgerView {
            state,
            markdown,
            skipped: read.unknown,
            skipped_detail: read.unknown_detail,
            torn_tail: read.torn_tail,
            ahead_of_head: read.ahead_of_head,
        })
    }

    pub async fn score(&self, mission: &MissionId) -> Result<ScoreView, String> {
        self.inner.check_open()?;
        let mut sessions: Vec<SessionMeta> =
            self.inner.st().known.values().filter(|k| &k.meta.mission == mission).map(|k| k.meta.clone()).collect();
        // The id comes from a URL: only a mission some known session belongs to is looked at.
        if sessions.is_empty() {
            return Err(format!("There is no mission {}.", mission.as_str()));
        }
        sessions
            .sort_by(|a, b| (a.parent.is_some(), a.created_ms, &a.id).cmp(&(b.parent.is_some(), b.created_ms, &b.id)));
        let paths = self.inner.paths.clone();
        let mission = mission.clone();
        let scored = tokio::task::spawn_blocking(move || {
            let mut scored = Vec::with_capacity(sessions.len());
            for meta in sessions {
                let records = read_records(&paths.session_log(&meta.id)).map_err(|e| e.to_string())?.records;
                scored.push(SessionScore {
                    session: meta.id,
                    role: meta.role,
                    parent: meta.parent,
                    card: scorecard::score(&records),
                });
            }
            Ok::<_, String>(scored)
        })
        .await
        .map_err(|e| format!("The logs of mission {} could not be read: {e}", mission.as_str()))??;
        let mut total = scored.first().map(|lead| lead.card.clone()).unwrap_or_default();
        for other in scored.iter().skip(1) {
            total.add(&other.card);
        }
        Ok(ScoreView { mission, sessions: scored, total })
    }

    pub fn net(&self, id: &SessionId, limit: usize) -> Result<Vec<NetEntry>, String> {
        self.inner.check_open()?;
        if !self.inner.st().known.contains_key(id) {
            return Err(no_session(id));
        }
        let path = self.inner.paths.session_dir(id).join("net.jsonl");
        // Lossy, so an append torn inside a character does not hide the lines before it.
        let text = match std::fs::read(&path) {
            Ok(t) => String::from_utf8_lossy(&t).into_owned(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        };
        if let Err(b) = loom_net::netlog::verify(&text) {
            return Err(format!(
                "The egress audit log {} is damaged at {b}. Do not trust it: it was edited, truncated or written by something else. Keep a copy for review and move it aside to start a new chain.",
                path.display()
            ));
        }
        if let Some(torn) = loom_net::netlog::torn_tail(&text) {
            tracing::warn!("the egress audit log {} ends in a torn append: {torn}", path.display());
        }
        let mut entries: Vec<NetEntry> = text.lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
        if entries.len() > limit {
            entries.drain(..entries.len() - limit);
        }
        Ok(entries)
    }

    pub async fn health(&self) -> Vec<ModelHealth> {
        let mut out = Vec::new();
        for (name, rt) in &self.inner.profiles {
            let reachable = rt.client.health().await;
            let profile = rt.client.profile();
            let discovered = lock(&rt.discovered).clone();
            let (model, window) = match &discovered {
                Some(d) => (d.served_model.clone(), d.context_window),
                None => (profile.model.clone(), profile.context_window),
            };
            out.push(ModelHealth {
                profile: name.clone(),
                base_url: profile.base_url.clone(),
                model,
                reachable,
                detail: if reachable {
                    String::new()
                } else {
                    format!("{} did not answer a request for its models.", profile.base_url)
                },
                context_window: window,
                max_concurrent: rt.limiter.capacity(),
            });
        }
        out
    }

    /// Stop everything in a way the next start can pick up. See *Shutdown*.
    pub async fn shutdown(&self) {
        let inner = &self.inner;
        if inner.shutting.swap(true, Ordering::SeqCst) {
            return;
        }
        let (actives, background) = {
            let mut st = inner.st();
            let mut actives = Vec::new();
            for (id, k) in st.known.iter_mut() {
                actives.extend(k.active.take().map(|a| (id.clone(), a)));
            }
            (actives, std::mem::take(&mut st.tasks))
        };
        let grace = Duration::from_secs(inner.config.tools.kill_grace_s);
        let mut tasks = Vec::new();
        let mut jobs = Vec::new();
        for (id, a) in actives {
            let ActiveSession { inputs, task, jobs: table, control, .. } = a;
            // A running turn is cancelled the normal way (tools get TERM, then KILL) and recorded as
            // cut by the restart; closing the inputs then ends the session. What does not end in
            // time is aborted below, which `open` recovers from.
            control.stop_for_shutdown();
            drop(inputs);
            tasks.push((id, task));
            jobs.push(table);
        }
        // The wait covers the grace a cancelled command gets before its KILL: a foreground command
        // is tracked by nothing but its tool call, so aborting the task earlier would leave it
        // running. A task parked in a `join` will not end, and is aborted as soon as it is there.
        let wait = grace.saturating_add(SHUTDOWN_TASK_WAIT);
        let begun = tokio::time::Instant::now();
        loop {
            let parked = std::mem::take(&mut inner.st().parked);
            for (id, task) in &tasks {
                if parked.contains(id) {
                    task.abort();
                }
            }
            if tasks.iter().all(|(_, task)| task.is_finished()) || begun.elapsed() >= wait {
                break;
            }
            tokio::time::sleep(SHUTDOWN_POLL).await;
        }
        for (_, task) in &tasks {
            if !task.is_finished() {
                task.abort();
            }
        }
        for (_, task) in &mut tasks {
            if !task.is_finished() {
                let _ = tokio::time::timeout(SHUTDOWN_ABORT_WAIT, &mut *task).await;
            }
        }
        let kill = futures_util::future::join_all(jobs.iter().map(|j| j.kill_all(grace)));
        let _ = tokio::time::timeout(grace + Duration::from_secs(5), kill).await;
        for task in background {
            task.abort();
        }
        // The self-probe's commands and decoys must not outlive the daemon.
        loom_tools::sandbox::selfprobe::stop();
        if let Some(host) = &inner.box_host {
            host.shutdown().await;
        }
        // The proxy's connections record how they ended; the process may exit right after this returns.
        inner.proxy.stop(SHUTDOWN_TASK_WAIT).await;
    }
}

/// The most a collection reads of one file under the sessions and missions directories. A larger file (a sparse
/// file can claim any size) aborts the collection without being read.
const GC_FILE_MAX: u64 = 4 << 30;

/// How long a collection may spend reading the sessions and missions directories before it aborts.
const GC_SCAN_TIME: Duration = Duration::from_secs(300);

/// What one collection's scan may read: at most `file_max` bytes of one file, until `time` after `started`.
struct ScanBounds {
    file_max: u64,
    time: Duration,
    started: std::time::Instant,
}

/// Why a scan stopped before the end.
enum ScanStop {
    Unreadable(std::io::Error),
    TooLarge,
    OutOfTime,
}

impl ScanBounds {
    fn out_of_time(&self) -> bool {
        self.started.elapsed() >= self.time
    }

    /// The sentence for a scan that stopped at `path`.
    fn stopped(&self, path: &Path, why: ScanStop) -> String {
        let path = path.display();
        match why {
            ScanStop::Unreadable(e) => {
                format!("cannot read {path} ({e}); nothing was collected. Fix or remove it and run it again.")
            }
            ScanStop::TooLarge => format!(
                "cannot read {path} (it is larger than {} bytes, the most a collection reads of one file); nothing was \
                 collected. Remove it, or the session or mission it belongs to, and run it again.",
                self.file_max
            ),
            ScanStop::OutOfTime => format!(
                "stopped at {path}: reading the sessions and missions took longer than {} seconds; nothing was \
                 collected. Remove the sessions you no longer need and run it again.",
                self.time.as_secs()
            ),
        }
    }
}

/// A file being scanned. A read past `file_max` bytes or after the time is up fails, and `stop` says which.
struct BoundedRead<'a> {
    file: std::fs::File,
    read: u64,
    bounds: &'a ScanBounds,
    stop: Option<ScanStop>,
}

impl std::io::Read for BoundedRead<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let stop = if self.bounds.out_of_time() {
            ScanStop::OutOfTime
        } else {
            let n = std::io::Read::read(&mut self.file, buf)?;
            self.read = self.read.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
            if self.read <= self.bounds.file_max {
                return Ok(n);
            }
            ScanStop::TooLarge
        };
        self.stop = Some(stop);
        Err(std::io::Error::other("the scan stopped"))
    }
}

/// Whether an error means there is nothing at a path to read: it is gone, it dangles, or it is a link that loops
/// or that `O_NOFOLLOW` did not follow.
fn is_absent(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::NotFound || matches!(e.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR))
}

/// Open `path` for reading, with the metadata of what the handle holds. A link there is followed only with
/// `follow`, and the open never blocks (a FIFO does not wait for a writer).
fn open_unblocked(path: &Path, follow: bool) -> std::io::Result<(std::fs::File, std::fs::Metadata)> {
    use std::os::unix::fs::OpenOptionsExt;
    let flags = libc::O_NONBLOCK | libc::O_NOCTTY | if follow { 0 } else { libc::O_NOFOLLOW };
    let file = std::fs::OpenOptions::new().read(true).custom_flags(flags).open(path)?;
    let meta = file.metadata()?;
    Ok((file, meta))
}

/// Add to `keep` every stored blob that a regular file below `root` names (`scan_ids`). A missing `root` is an
/// empty tree; a `root` that is not a directory, or that cannot be opened for any other reason (a link that
/// loops, say), stops the scan. An entry of `root` itself is read through a link (a session or mission directory
/// kept elsewhere), and is passed over only when it is gone, dangles or loops. Below that no link is followed:
/// every entry is opened with `O_NOFOLLOW` and read as what the open handle holds, so one replaced by a link
/// after it was listed is passed over too. Nothing blocks: FIFOs, sockets and devices are not opened, and opens
/// do not wait. With `temp_dirs`, the `tmp` directory of each entry of `root` (a session's temp dir: the one
/// directory of the tree a sandboxed command can change, and nothing the harness wrote) is not read. A directory
/// is checked through its handle and then listed by its path; outside the temp dirs no command can put a link in
/// its place in between. The scan keeps to `bounds`; when it cannot finish, the error is the sentence that says
/// where and why.
fn scan_tree_for_ids(
    root: &Path,
    temp_dirs: bool,
    stored: &loom_core::blob::StoredIds,
    keep: &mut HashSet<String>,
    bounds: &ScanBounds,
) -> Result<(), String> {
    // What to read and its depth below `root`.
    let mut todo = vec![(root.to_path_buf(), 0usize)];
    while let Some((path, depth)) = todo.pop() {
        if bounds.out_of_time() {
            return Err(bounds.stopped(&path, ScanStop::OutOfTime));
        }
        let unreadable = |e: std::io::Error| bounds.stopped(&path, ScanStop::Unreadable(e));
        // Gone meanwhile (a session directory being removed), or, below the root, a link: an entry of `root`
        // that dangles or loops, or an entry further down that was replaced by one since it was listed.
        let nothing_there =
            |e: &std::io::Error| e.kind() == std::io::ErrorKind::NotFound || (depth > 0 && is_absent(e));
        let (file, meta) = match open_unblocked(&path, depth <= 1) {
            Ok(opened) => opened,
            Err(e) if nothing_there(&e) => continue,
            Err(e) => return Err(unreadable(e)),
        };
        if depth == 0 && !meta.is_dir() {
            return Err(unreadable(std::io::Error::from_raw_os_error(libc::ENOTDIR)));
        }
        if meta.is_file() {
            if meta.len() > bounds.file_max {
                return Err(bounds.stopped(&path, ScanStop::TooLarge));
            }
            let mut reader = BoundedRead { file, read: 0, bounds, stop: None };
            if let Err(e) = loom_core::blob::scan_ids(&mut reader, stored, keep) {
                return Err(bounds.stopped(&path, reader.stop.take().unwrap_or(ScanStop::Unreadable(e))));
            }
            continue;
        }
        // Not a directory either: a FIFO, socket or device put in the place of what was listed.
        if !meta.is_dir() {
            continue;
        }
        drop(file);
        let entries = match std::fs::read_dir(&path) {
            Ok(e) => e,
            Err(e) if nothing_there(&e) => continue,
            Err(e) => return Err(unreadable(e)),
        };
        for entry in entries {
            if bounds.out_of_time() {
                return Err(bounds.stopped(&path, ScanStop::OutOfTime));
            }
            let entry = entry.map_err(unreadable)?;
            let child = entry.path();
            let listed = match entry.file_type() {
                Ok(t) => t,
                Err(e) if is_absent(&e) => continue,
                Err(e) => return Err(bounds.stopped(&child, ScanStop::Unreadable(e))),
            };
            let kind = if !listed.is_symlink() {
                listed
            } else if depth > 0 {
                continue;
            } else {
                match std::fs::metadata(&child) {
                    Ok(m) => m.file_type(),
                    Err(e) if is_absent(&e) => continue,
                    Err(e) => return Err(bounds.stopped(&child, ScanStop::Unreadable(e))),
                }
            };
            if temp_dirs && depth == 1 && entry.file_name() == "tmp" {
                continue;
            }
            if kind.is_dir() || kind.is_file() {
                todo.push((child, depth.saturating_add(1)));
            }
        }
    }
    Ok(())
}

impl Inner {
    /// Read every `meta.json` / `status.json` under the sessions directory.
    fn load_known(&self) {
        let Ok(dir) = std::fs::read_dir(self.paths.sessions_dir()) else { return };
        let mut st = self.st();
        for entry in dir.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let Some(meta) = read_json::<SessionMeta>(&path.join("meta.json")) else {
                tracing::warn!("{} has no readable meta.json; ignored", path.display());
                continue;
            };
            let mut status = read_json::<Status>(&path.join("status.json")).unwrap_or_else(idle_status);
            if meta.parent.is_some() {
                if let Ok(log) = read_records(&self.paths.session_log(&meta.id)) {
                    if let Some(result) = completed_settlement(&log.records, &meta.id) {
                        status = settled_status(&status, &result);
                    }
                }
            }
            st.known.insert(meta.id.clone(), Known::new(meta, status));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loom_core::config::{ModelProfile, SandboxMode};
    use loom_core::event::{Brief, InboxKind, NoteKind};
    use loom_model::mock::{Action, MockServer, Reply, Script};
    use serde_json::{json, Value};

    const WAIT: Duration = Duration::from_secs(30);

    struct Env {
        dir: tempfile::TempDir,
        server: MockServer,
        rt: Runtime,
        ws: PathBuf,
        config: Config,
    }

    fn has_tool(body: &Value, name: &str) -> bool {
        body["tools"].as_array().is_some_and(|t| t.iter().any(|x| x["function"]["name"] == name))
    }

    fn last_role(body: &Value) -> String {
        body["messages"]
            .as_array()
            .and_then(|m| m.iter().rev().find(|m| !m["content"].as_str().unwrap_or("").starts_with("<harness-state>")))
            .and_then(|m| m["role"].as_str())
            .unwrap_or("")
            .to_string()
    }

    fn tool_msgs(body: &Value) -> usize {
        body["messages"].as_array().map_or(0, |m| m.iter().filter(|m| m["role"] == "tool").count())
    }

    /// The state block of a request.
    fn hud_of(body: &Value) -> String {
        body["messages"]
            .as_array()
            .and_then(|m| {
                m.iter().rev().find_map(|m| m["content"].as_str().filter(|c| c.starts_with("<harness-state>")))
            })
            .unwrap_or("")
            .to_string()
    }

    fn mentions(body: &Value, s: &str) -> bool {
        body.to_string().contains(s)
    }

    fn call(name: &str, args: Value) -> Action {
        Action::Reply(Reply::tool(name, args.to_string()))
    }

    fn finish(answer: &str) -> Action {
        call("finish", json!({ "answer": answer }))
    }

    async fn until<F: FnMut() -> bool>(what: &str, mut f: F) {
        let end = tokio::time::Instant::now() + WAIT;
        while !f() {
            assert!(tokio::time::Instant::now() < end, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn config_for(server: &MockServer, notify_file: Option<&Path>) -> Config {
        let mut c = Config::default();
        c.models.clear();
        c.models.insert(
            "mock".into(),
            ModelProfile {
                base_url: server.base_url(),
                model: "mock".into(),
                context_window: Some(1_000_000),
                retry_window_s: 1,
                retry_max_delay_s: 1,
                stall_timeout_s: 30,
                ..ModelProfile::default()
            },
        );
        c.default_model = "mock".into();
        c.sandbox.mode = SandboxMode::None;
        c.network.mode = NetworkMode::DenyAll;
        c.agents.verify_finish = false;
        c.tools.kill_grace_s = 1;
        if let Some(f) = notify_file {
            c.notify.command =
                vec!["/bin/sh".into(), "-c".into(), format!("echo \"$LOOM_KIND $LOOM_SESSION\" >> '{}'", f.display())];
        }
        c
    }

    /// The built-in `core` pack with a lead that cannot `conclude` or `request_scope`, written into `packs` so it
    /// replaces the built-in one. These tests use `finish` only to end a turn; a lead without `conclude` is not held
    /// by the goal-met claim (gate.rs), so `finish` ends the turn as it did before the finish gate asked for a
    /// conclusion. The gate, conclude and scope behaviours are covered where they belong (rtools/terminal.rs,
    /// ledger.rs, gate.rs), on a role that has the tools.
    fn plain_core_pack(packs: &Path) {
        let core = packs.join("core");
        std::fs::create_dir_all(core.join("roles")).unwrap();
        let toml = include_str!("../../../packs/core/pack.toml").replacen("\"request_scope\", \"conclude\", ", "", 1);
        assert!(!toml.contains("\"conclude\""), "the lead's tool list changed shape");
        std::fs::write(core.join("pack.toml"), toml).unwrap();
        std::fs::write(core.join("harness.md"), include_str!("../../../packs/core/harness.md")).unwrap();
        for (name, text) in [
            ("lead", include_str!("../../../packs/core/roles/lead.md")),
            ("worker", include_str!("../../../packs/core/roles/worker.md")),
            ("verifier", include_str!("../../../packs/core/roles/verifier.md")),
            ("chat", include_str!("../../../packs/core/roles/chat.md")),
        ] {
            std::fs::write(core.join("roles").join(format!("{name}.md")), text).unwrap();
        }
    }

    async fn env_with(script: Script, notify: bool, tweak: impl FnOnce(&mut Config)) -> Env {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let server = MockServer::start(script).await.unwrap();
        let nf = dir.path().join("notified.txt");
        let mut config = config_for(&server, notify.then_some(nf.as_path()));
        tweak(&mut config);
        let paths = Paths::at(dir.path().join("home"));
        plain_core_pack(&paths.packs_dir());
        let rt = Runtime::start(config.clone(), paths).await.unwrap();
        Env { dir, server, rt, ws, config }
    }

    async fn env(script: Script) -> Env {
        env_with(script, false, |_| {}).await
    }

    impl Env {
        fn new_session(&self, message: Option<&str>) -> NewSession {
            NewSession { workspace: self.ws.clone(), message: message.map(str::to_string), ..NewSession::default() }
        }

        fn records(&self, id: &SessionId) -> Vec<Record> {
            self.rt.records(id, None, 2_000).unwrap_or_default()
        }

        fn kinds(&self, id: &SessionId) -> Vec<String> {
            self.records(id)
                .iter()
                .map(|r| serde_json::to_value(r).unwrap()["kind"].as_str().unwrap_or("").to_string())
                .collect()
        }

        fn has(&self, id: &SessionId, f: impl Fn(&Event) -> bool) -> bool {
            self.records(id).iter().any(|r| f(&r.event))
        }

        fn children(&self, id: &SessionId) -> Vec<SessionInfo> {
            self.rt.sessions(true).into_iter().filter(|s| s.meta.parent.as_ref() == Some(id)).collect()
        }
    }

    fn lead_script(child_args: Value) -> Script {
        Script::new(move |body, _| {
            if has_tool(body, "agent_spawn") {
                if last_role(body) == "tool" {
                    finish("lead done")
                } else {
                    call("agent_spawn", child_args.clone())
                }
            } else {
                finish("child report")
            }
        })
    }

    /// Like `env_with`, but `packs` may write pack directories into the home before the runtime starts.
    async fn env_with_packs(script: Script, tweak: impl FnOnce(&mut Config), packs: impl FnOnce(&Path)) -> Env {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let server = MockServer::start(script).await.unwrap();
        let mut config = config_for(&server, None);
        tweak(&mut config);
        let paths = Paths::at(dir.path().join("home"));
        plain_core_pack(&paths.packs_dir());
        packs(&paths.packs_dir());
        let rt = Runtime::start(config.clone(), paths).await.unwrap();
        Env { dir, server, rt, ws, config }
    }

    /// The handle of the latest stored output shown in a request's tool messages.
    fn shown_handle(body: &Value) -> Option<String> {
        body["messages"].as_array()?.iter().rev().filter(|m| m["role"] == "tool").find_map(|m| {
            let text = m["content"].as_str()?;
            let hex: String = text[text.find("out:")? + 4..].chars().take_while(|c| c.is_ascii_hexdigit()).collect();
            (hex.len() >= 16).then(|| format!("out:{}", &hex[..16]))
        })
    }

    /// One step of a verifier: look at something, then give a verdict that names what it looked at.
    fn verifier_turn(body: &Value, accept: bool) -> Action {
        match shown_handle(body) {
            None => call("bash", json!({"command": "echo checked"})),
            Some(h) if accept => call("verdict", json!({"accepted": true, "opened": [h]})),
            Some(h) => call("verdict", json!({"accepted": false, "objections": ["no test ran"], "opened": [h]})),
        }
    }

    fn inbox_kinds(e: &Env) -> Vec<InboxKind> {
        e.rt.inbox().iter().map(|i| i.item.kind).collect()
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_looser_existing_home_is_tightened_and_new_session_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let e = env_with_packs(
            Script::new(|_, _| finish("ok")),
            |_| {},
            |packs| {
                std::fs::create_dir_all(packs).unwrap();
                for d in [packs.parent().unwrap(), packs] {
                    std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o755)).unwrap();
                }
            },
        )
        .await;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let home = e.dir.path().join("home");
        for d in ["", "keys", "sessions", "missions", "blobs", "logs"] {
            assert_eq!(mode(&home.join(d)), 0o700, "{d}");
        }
        let id = e.rt.create_session(e.new_session(Some("hi"))).await.unwrap().meta.id;
        until("turn end", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { .. }))).await;
        let sdir = home.join("sessions").join(id.as_str());
        until("status.json", || sdir.join("status.json").is_file()).await;
        for f in ["log.jsonl", "meta.json", "status.json"] {
            assert_eq!(mode(&sdir.join(f)), 0o600, "{f}");
        }
        for d in [sdir.clone(), sdir.join("tmp")] {
            assert_eq!(mode(&d), 0o700, "{}", d.display());
        }
    }

    #[tokio::test]
    async fn create_and_message_runs_a_turn() {
        let e = env(Script::new(|_, _| finish("all good"))).await;
        let mut bus = e.rt.subscribe();
        let info = e.rt.create_session(e.new_session(Some("do the thing"))).await.unwrap();
        let id = info.meta.id.clone();
        assert_eq!(info.meta.title, "do the thing");
        until("turn end", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { .. }))).await;
        let home = e.dir.path().join("home/sessions").join(id.as_str());
        assert!(home.join("meta.json").is_file());
        until("status.json", || home.join("status.json").is_file()).await;
        let mut seen = Vec::new();
        while let Ok(ev) = bus.try_recv() {
            if let BusEvent::Record { session, record } = ev {
                if session == id {
                    seen.push(record.seq);
                }
            }
        }
        assert!(!seen.is_empty());
        assert!(seen.windows(2).all(|w| w[0] < w[1]));
        let prompt = match &e.records(&id)[0].event {
            Event::SessionStart(s) => s.system_prompt.clone(),
            other => panic!("first record is {other:?}"),
        };
        for line in ["Workspace:", "Platform:", "Sandbox:", "Network:"] {
            assert!(prompt.contains(line), "missing {line}");
        }
        let ledger = e.rt.ledger(&info.meta.mission).unwrap();
        assert_eq!(ledger.state.goal.as_deref(), Some("do the thing"));
        let page = e.rt.records(&id, Some(1), 2).unwrap();
        assert_eq!(page.len(), 2);
        assert!(page[0].seq > 1);
        let w = e.rt.window(&id).unwrap();
        assert!(w.est_tokens > 0 && !w.items.is_empty());
        assert_eq!(e.rt.missions().len(), 1);
        e.rt.shutdown().await;
        assert_eq!(e.rt.send_message(&id, "x").await.unwrap_err(), "The harness is shutting down.");
    }

    #[tokio::test]
    async fn creation_with_the_model_server_down_needs_a_configured_window() {
        // No configured window: refused, naming the base URL and both remedies.
        let e = env_with(Script::new(|_, _| finish("ok")), false, |c| {
            if let Some(p) = c.models.get_mut("mock") {
                p.context_window = None;
            }
        })
        .await;
        e.server.shutdown().await;
        let err = e.rt.create_session(e.new_session(None)).await.unwrap_err();
        assert!(err.contains(&e.server.base_url()), "{err}");
        assert!(err.contains("Start the model server") && err.contains("context_window"), "{err}");
        assert!(e.rt.sessions(true).is_empty());
        e.rt.shutdown().await;
        // The server answers but reports no window, and the profile sets none: refused too.
        let e = env_with(Script::new(|_, _| finish("ok")), false, |c| {
            if let Some(p) = c.models.get_mut("mock") {
                p.context_window = None;
            }
        })
        .await;
        e.server.set_model("mock", None);
        let err = e.rt.create_session(e.new_session(None)).await.unwrap_err();
        assert!(err.contains(&e.server.base_url()) && err.contains("context_window"), "{err}");
        assert!(e.rt.sessions(true).is_empty());
        e.rt.shutdown().await;
        // A configured window: the session starts with it.
        let e = env(Script::new(|_, _| finish("ok"))).await;
        e.server.shutdown().await;
        let info = e.rt.create_session(e.new_session(None)).await.unwrap();
        assert_eq!(info.meta.context_window, Some(1_000_000));
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn operator_rules_reach_the_ledger_and_the_lead_through_a_child_id_without_a_turn() {
        use loom_core::event::NoteKind;
        let e = env(lead_script(json!({"question": "CHILDMARK find it"}))).await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let id = info.meta.id.clone();
        until("lead turn end", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { .. }))).await;
        until("idle", || e.rt.session(&id).is_some_and(|s| s.status.phase == Phase::Idle)).await;
        let child = e.children(&id)[0].meta.id.clone();
        let turns = |e: &Env| e.kinds(&id).iter().filter(|k| *k == "turn_start").count();
        let before = turns(&e);

        // Sent through a child, with stray white space: it goes to the idle lead, trimmed.
        let receipt = e.rt.add_rule(&child, "  never touch prod\n").await.unwrap();
        assert_eq!(receipt, RuleReceipt { lead: id.clone(), queued: false, ledger: true, stock: None });
        let mission = info.meta.mission.clone();
        until("rule in ledger", || {
            e.rt.ledger(&mission).is_ok_and(|l| l.state.constraints.iter().any(|c| c.text == "never touch prod"))
        })
        .await;
        let note = |kind: NoteKind| {
            e.records(&id).iter().any(|r| matches!(&r.event, Event::HarnessNote { note, .. } if *note == kind))
        };
        until("note", || note(NoteKind::Constraint)).await;
        let receipt = e.rt.approve(&id, "deploy to staging\n", " staging only\n").await.unwrap();
        assert_eq!(receipt.stock, None);
        until("approval", || e.rt.ledger(&mission).is_ok_and(|l| l.state.approvals.len() == 1)).await;
        assert!(note(NoteKind::Approval));
        let approval = e.rt.ledger(&mission).unwrap().state.approvals[0].clone();
        assert_eq!((approval.text.as_str(), approval.scope.as_str()), ("deploy to staging", "staging only"));
        let rule_id = e.rt.ledger(&mission).unwrap().state.constraints[0].id.clone();
        e.rt.withdraw_rule(&id, &rule_id, " done\n").await.unwrap();
        until("retired", || e.rt.ledger(&mission).is_ok_and(|l| l.state.constraints[0].retired.is_some())).await;
        assert_eq!(e.rt.ledger(&mission).unwrap().state.constraints[0].retired.as_deref(), Some("done"));
        assert_eq!(turns(&e), before, "operator rules must not start a turn");

        assert!(e.rt.add_rule(&id, "  ").await.is_err());
        assert!(e.rt.approve(&id, "", "x").await.is_err());
        assert!(e.rt.withdraw_rule(&id, " ", "x").await.is_err());
        let unknown = SessionId::from("s-nope");
        assert_eq!(e.rt.add_rule(&unknown, "x").await.unwrap_err(), "There is no session s-nope.".to_string());
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn a_scope_grant_widens_the_running_sessions_policy_and_is_recorded_without_a_turn() {
        use loom_core::event::NoteKind;
        let e = env(Script::new(|_, _| finish("ok"))).await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let (id, mission) = (info.meta.id.clone(), info.meta.mission.clone());
        until("turn end", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { .. }))).await;
        until("idle", || e.rt.session(&id).is_some_and(|s| s.status.phase == Phase::Idle)).await;
        let turns = |e: &Env| e.kinds(&id).iter().filter(|k| *k == "turn_start").count();
        let before = turns(&e);
        let rule = |host: &str| e.rt.inner.proxy.check_name(&id, host, 443).map(|v| v.rule);
        assert_eq!(rule("api.example.test").as_deref(), Some("mode deny_all"));

        let hosts = vec![" api.example.test ".to_string()];
        let receipt = e.rt.grant_scope(&id, &hosts, Some(" the target ")).await.unwrap();
        assert_eq!(receipt, ScopeReceipt { lead: id.clone(), hosts: vec!["api.example.test".into()], ledger: true });
        // The proxy allows it at once; anything else is still refused.
        assert_eq!(rule("api.example.test").as_deref(), Some("allow api.example.test"));
        assert_eq!(rule("other.example.test").as_deref(), Some("not in allow list"));
        until("grant in ledger", || {
            e.rt.ledger(&mission).is_ok_and(|l| l.state.granted_hosts() == ["api.example.test"])
        })
        .await;
        let grants = e.rt.ledger(&mission).unwrap().state.scope_grants;
        assert_eq!(grants[0].note.as_deref(), Some("the target"));
        let noted = |needle: &str| {
            e.has(
                &id,
                |ev| matches!(ev, Event::HarnessNote { note: NoteKind::Approval, text } if text.contains(needle)),
            )
        };
        until("note", || noted("The operator authorized network access to: api.example.test.")).await;
        assert!(noted("a standing authorization for this session"));

        // A second grant adds to the first.
        e.rt.grant_scope(&id, &["*.cdn.test".to_string(), "api.example.test".to_string()], None).await.unwrap();
        assert_eq!(rule("api.example.test").as_deref(), Some("allow api.example.test"));
        assert_eq!(rule("x.cdn.test").as_deref(), Some("allow *.cdn.test"));
        until("both in ledger", || {
            e.rt.ledger(&mission).is_ok_and(|l| l.state.granted_hosts() == ["api.example.test", "*.cdn.test"])
        })
        .await;
        assert_eq!(turns(&e), before, "a scope grant must not start a turn");

        // Refusals say what to do.
        let none: [String; 0] = [];
        assert!(e.rt.grant_scope(&id, &none, None).await.unwrap_err().contains("at least one host"));
        assert!(e.rt.grant_scope(&id, &["  ".to_string()], None).await.unwrap_err().contains("blank"));
        assert!(e
            .rt
            .grant_scope(&id, &["a*b.test".to_string()], None)
            .await
            .unwrap_err()
            .contains("cannot be authorized"));
        assert!(e.rt.grant_scope(&id, &["*.com".to_string()], None).await.unwrap_err().contains("top-level domain"));
        let unknown = SessionId::from("s-nope");
        let err = e.rt.grant_scope(&unknown, &["a.test".to_string()], None).await.unwrap_err();
        assert_eq!(err, "There is no session s-nope.");
        assert_eq!(rule("a.test").as_deref(), Some("not in allow list"));
        e.rt.archive(&id, true).await.unwrap();
        let err = e.rt.grant_scope(&id, &["a.test".to_string()], None).await.unwrap_err();
        assert!(err.contains("archived"), "{err}");
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn scope_grants_are_applied_again_to_a_session_restored_after_a_restart() {
        let e = env(Script::new(|_, _| finish("ok"))).await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let (id, mission) = (info.meta.id.clone(), info.meta.mission.clone());
        until("idle", || e.rt.session(&id).is_some_and(|s| s.status.phase == Phase::Idle)).await;
        e.rt.grant_scope(&id, &["api.example.test".to_string()], None).await.unwrap();
        until("grant in ledger", || e.rt.ledger(&mission).is_ok_and(|l| l.state.scope_grants.len() == 1)).await;
        e.rt.shutdown().await;

        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        // The new daemon holds no grant in memory: the host comes back from the ledger.
        assert!(rt2.inner.st().scope.is_empty());
        rt2.inner.activate(&id).unwrap();
        let rule = |host: &str| rt2.inner.proxy.check_name(&id, host, 443).map(|v| v.rule);
        assert_eq!(rule("api.example.test").as_deref(), Some("allow api.example.test"));
        assert_eq!(rule("other.example.test").as_deref(), Some("not in allow list"));
        rt2.shutdown().await;
    }

    #[tokio::test]
    async fn a_scope_revoke_narrows_the_running_policy_is_recorded_and_survives_a_restart() {
        use loom_core::event::NoteKind;
        let e = env(Script::new(|_, _| finish("ok"))).await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let (id, mission) = (info.meta.id.clone(), info.meta.mission.clone());
        until("idle", || e.rt.session(&id).is_some_and(|s| s.status.phase == Phase::Idle)).await;
        let rule = |rt: &Runtime, host: &str| rt.inner.proxy.check_name(&id, host, 443).map(|v| v.rule);
        let hosts = vec!["api.example.test".to_string(), "*.cdn.test".to_string()];
        e.rt.grant_scope(&id, &hosts, None).await.unwrap();
        until("grants in ledger", || e.rt.ledger(&mission).is_ok_and(|l| l.state.scope_grants.len() == 1)).await;
        assert_eq!(rule(&e.rt, "api.example.test").as_deref(), Some("allow api.example.test"));
        let turns = || e.kinds(&id).iter().filter(|k| *k == "turn_start").count();
        let before = turns();

        // Refusals say what to write.
        let m = mission.clone();
        let err = e.rt.revoke_scope(&m, "api.example.test", "  ").await.unwrap_err();
        assert!(err.contains("Say why"), "{err}");
        let err = e.rt.revoke_scope(&m, " ", "r").await.unwrap_err();
        assert!(err.contains("Name the host"), "{err}");
        let err = e.rt.revoke_scope(&m, "nope.example.test", "r").await.unwrap_err();
        assert!(err.contains("not granted") && err.contains("api.example.test, *.cdn.test"), "{err}");
        let err = e.rt.revoke_scope(&MissionId::from("m-nope"), "api.example.test", "r").await.unwrap_err();
        assert!(err.contains("no mission m-nope"), "{err}");
        assert_eq!(
            rule(&e.rt, "api.example.test").as_deref(),
            Some("allow api.example.test"),
            "refusals change nothing"
        );

        // The revoke: recorded, narrowed at once (the lead was running), noted, no turn.
        let receipt = e.rt.revoke_scope(&m, " API.example.test ", " wrong target ").await.unwrap();
        assert_eq!(
            receipt,
            ScopeRevokeReceipt {
                lead: id.clone(),
                host: "api.example.test".into(),
                ledger: true,
                recorded: true,
                sessions: 1,
                cut: 0
            }
        );
        assert_eq!(rule(&e.rt, "api.example.test").as_deref(), Some("deny revoked api.example.test"));
        assert_eq!(rule(&e.rt, "x.cdn.test").as_deref(), Some("allow *.cdn.test"), "the other grant stands");
        let state = e.rt.ledger(&mission).unwrap().state;
        assert_eq!(state.granted_hosts(), ["*.cdn.test"]);
        assert_eq!(
            (state.scope_revokes[0].host.as_str(), state.scope_revokes[0].reason.as_str()),
            ("api.example.test", "wrong target")
        );
        until("note", || {
            e.has(&id, |ev| matches!(ev, Event::HarnessNote { note: NoteKind::Approval, text } if text.contains("withdrew network access to api.example.test") && text.contains("wrong target")))
        })
        .await;
        assert_eq!(turns(), before, "a revoke must not start a turn");
        // Twice: the ledger no longer has it.
        let err = e.rt.revoke_scope(&m, "api.example.test", "again").await.unwrap_err();
        assert!(err.contains("not granted"), "{err}");

        // Granted again, it is allowed again.
        e.rt.grant_scope(&id, &["api.example.test".to_string()], None).await.unwrap();
        assert_eq!(rule(&e.rt, "api.example.test").as_deref(), Some("allow api.example.test"));
        until("regrant in ledger", || {
            e.rt.ledger(&mission).is_ok_and(|l| l.state.granted_hosts() == ["*.cdn.test", "api.example.test"])
        })
        .await;
        e.rt.revoke_scope(&m, "api.example.test", "once more").await.unwrap();
        e.rt.shutdown().await;

        // A new daemon builds the session from the ledger: the revoked host stays out.
        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        rt2.inner.activate(&id).unwrap();
        assert_eq!(rule(&rt2, "api.example.test").as_deref(), Some("deny revoked api.example.test"));
        assert_eq!(rule(&rt2, "x.cdn.test").as_deref(), Some("allow *.cdn.test"));
        rt2.shutdown().await;
    }

    #[tokio::test]
    async fn no_grant_reaches_the_infrastructure() {
        let e = env(Script::new(|_, _| finish("ok"))).await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let id = info.meta.id.clone();
        until("idle", || e.rt.session(&id).is_some_and(|s| s.status.phase == Phase::Idle)).await;
        // The grant is refused up front, with the rule, and grants nothing of the list.
        for bad in ["169.254.169.254", "127.0.0.1:9222", "127.0.0.1:2375", "metadata.google.internal"] {
            let hosts = vec![bad.to_string(), "lab.example.test".to_string()];
            let err = e.rt.grant_scope(&id, &hosts, None).await.unwrap_err();
            assert!(
                err.contains(bad) && err.contains("deny infrastructure: ") && err.contains("nothing was granted"),
                "{err}"
            );
        }
        e.rt.grant_scope(&id, &["lab.example.test".to_string()], None).await.unwrap();
        let check =
            |host: &str, port: u16| e.rt.inner.proxy.check_name(&id, host, port).map(|v| v.rule).unwrap_or_default();
        assert_eq!(check("lab.example.test", 443), "allow lab.example.test");
        for (host, port) in
            [("169.254.169.254", 80), ("127.0.0.1", 9222), ("127.0.0.1", 2375), ("metadata.google.internal", 80)]
        {
            let r = check(host, port);
            assert!(r.starts_with("deny infrastructure: "), "{host}:{port} {r}");
        }
        e.rt.shutdown().await;
    }

    /// The tailnet case: the model host is configured by name, the agent asks for its IP address.
    #[tokio::test]
    async fn a_literal_grant_of_the_address_a_model_host_resolves_to_is_refused() {
        let e = env(Script::new(|_, _| finish("ok"))).await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let (id, mission) = (info.meta.id.clone(), info.meta.mission.clone());
        until("idle", || e.rt.session(&id).is_some_and(|s| s.status.phase == Phase::Idle)).await;
        *e.rt.inner.infra.lock().unwrap() = crate::infra::Resolution {
            addrs: vec![loom_net::InfraAddr {
                label: "model endpoint spark-one.tail1234.ts.net:8000".into(),
                addr: "100.101.102.103".parse().unwrap(),
                port: Some(8000),
            }],
            ..Default::default()
        };
        let err = e.rt.grant_scope(&id, &["100.101.102.103:8000".to_string()], None).await.unwrap_err();
        assert!(err.contains("deny infrastructure: model endpoint spark-one"), "{err}");
        // A grant that was recorded before the address was known is inert at the connection.
        let meta = e.rt.inner.st().known.get(&id).unwrap().meta.clone();
        e.rt.inner.st().scope.entry(mission).or_default().push("100.101.102.103:8000".into());
        let policy = e.rt.inner.session_policy(&meta, true).unwrap();
        let v = policy.check_addr("100.101.102.103", 8000, "100.101.102.103".parse().unwrap(), "r");
        assert!(!v.allowed && v.rule.starts_with("deny infrastructure: model endpoint"), "{v:?}");
        e.rt.shutdown().await;
    }

    /// A revoke is a withdrawal: a wildcard grant that also covers the host does not keep it reachable.
    #[tokio::test]
    async fn a_revoked_host_stays_refused_under_a_covering_wildcard_and_after_a_restart() {
        let e = env(Script::new(|_, _| finish("ok"))).await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let (id, mission) = (info.meta.id.clone(), info.meta.mission.clone());
        until("idle", || e.rt.session(&id).is_some_and(|s| s.status.phase == Phase::Idle)).await;
        let rule = |rt: &Runtime, host: &str| rt.inner.proxy.check_name(&id, host, 443).map(|v| v.rule);
        let hosts = vec!["*.lab.test".to_string(), "api.lab.test".to_string()];
        e.rt.grant_scope(&id, &hosts, None).await.unwrap();
        until("grants in ledger", || e.rt.ledger(&mission).is_ok_and(|l| l.state.scope_grants.len() == 1)).await;
        // A host only the wildcard grants: the sentence names the wildcard.
        let err = e.rt.revoke_scope(&mission, "web.lab.test", "r").await.unwrap_err();
        assert!(err.contains("not granted by itself") && err.contains("`*.lab.test` covers it"), "{err}");
        e.rt.revoke_scope(&mission, "api.lab.test", "out of scope").await.unwrap();
        assert_eq!(rule(&e.rt, "api.lab.test").as_deref(), Some("deny revoked api.lab.test"));
        assert_eq!(rule(&e.rt, "web.lab.test").as_deref(), Some("allow *.lab.test"));
        e.rt.shutdown().await;
        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        rt2.inner.activate(&id).unwrap();
        assert_eq!(rule(&rt2, "api.lab.test").as_deref(), Some("deny revoked api.lab.test"));
        // Granting it again lifts the revoke.
        rt2.grant_scope(&id, &["api.lab.test".to_string()], None).await.unwrap();
        assert_eq!(rule(&rt2, "api.lab.test").as_deref(), Some("allow *.lab.test"));
        rt2.shutdown().await;
    }

    /// The grant is held in memory (its input is queued for the lead); the revoke holds across a restart and
    /// can be recorded once the lead has recorded the grant.
    #[tokio::test]
    async fn a_revoke_of_a_grant_the_lead_has_not_recorded_survives_a_restart_and_can_be_recorded_later() {
        let e = env(Script::new(|_, _| finish("ok"))).await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let (id, mission) = (info.meta.id.clone(), info.meta.mission.clone());
        until("idle", || e.rt.session(&id).is_some_and(|s| s.status.phase == Phase::Idle)).await;
        e.rt.inner.st().scope.entry(mission.clone()).or_default().push("late.example.test".into());
        let receipt = e.rt.revoke_scope(&mission, "late.example.test", "wrong target").await.unwrap();
        assert!(!receipt.recorded, "{receipt:?}");
        assert!(e.rt.inner.revoked_path(&mission).exists());
        // The lead records the queued grant afterwards.
        let journal = Journal::new(e.rt.inner.paths.journal(&mission), e.rt.inner.key.clone());
        let op = LedgerOp::ScopeGrant { hosts: vec!["late.example.test".into()], note: None };
        journal.append(&id, true, op, &|_| Ok(())).unwrap();
        e.rt.shutdown().await;
        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        rt2.inner.activate(&id).unwrap();
        let rule = |host: &str| rt2.inner.proxy.check_name(&id, host, 443).map(|v| v.rule);
        assert_eq!(
            rule("late.example.test").as_deref(),
            Some("deny revoked late.example.test"),
            "the ledger grant does not win"
        );
        // The documented remedy works: run the revoke again and it is recorded.
        let again = rt2.revoke_scope(&mission, "late.example.test", "wrong target").await.unwrap();
        assert!(again.recorded, "{again:?}");
        assert!(rt2.ledger(&mission).unwrap().state.granted_hosts().is_empty());
        rt2.shutdown().await;
    }

    /// A session built while a revoke runs derives its policy again when the mission's grants changed.
    #[tokio::test]
    async fn a_session_built_while_a_scope_change_runs_gets_the_current_policy() {
        let e = env(Script::new(|_, _| finish("ok"))).await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let (id, mission) = (info.meta.id.clone(), info.meta.mission.clone());
        until("idle", || e.rt.session(&id).is_some_and(|s| s.status.phase == Phase::Idle)).await;
        let meta = e.rt.inner.st().known.get(&id).unwrap().meta.clone();
        let rule = |host: &str| e.rt.inner.proxy.check_name(&id, host, 443).map(|v| v.rule);
        let built_at = e.rt.inner.scope_generation(&mission);
        // The grant lands after the policy was derived and before the session was told: no `set_policy` of
        // the grant reached it.
        e.rt.inner.st().scope.entry(mission.clone()).or_default().push("late.example.test".into());
        e.rt.inner.bump_scope_generation(&mission);
        assert_eq!(rule("late.example.test").as_deref(), Some("mode deny_all"));
        e.rt.inner.policy_is_current(&meta, true, built_at);
        assert_eq!(rule("late.example.test").as_deref(), Some("allow late.example.test"));
        // Nothing changed since: nothing is derived again.
        let now = e.rt.inner.scope_generation(&mission);
        e.rt.inner.st().scope.clear();
        e.rt.inner.policy_is_current(&meta, true, now);
        assert_eq!(rule("late.example.test").as_deref(), Some("allow late.example.test"));
        e.rt.shutdown().await;
    }

    #[test]
    fn the_infrastructure_of_a_configuration_names_its_endpoints_daemon_port_and_docker_host() {
        let mut config = Config::default();
        config.models.clear();
        for (name, url) in [
            ("a", "http://127.0.0.1:9920/v1"),
            ("b", "https://spark-one.tail1234.ts.net:8000/v1"),
            ("c", "https://api.example.test/v1/"),
            ("d", "http://user:secret@10.0.0.5/v1"),
            ("e", "http://[fd00::5]:8080/v1"),
            ("same", "http://127.0.0.1:9920/v1"),
            ("junk", "not a url"),
            ("scheme", "ftp://x:21/"),
        ] {
            let p = ModelProfile { base_url: url.into(), ..ModelProfile::default() };
            config.models.insert(name.into(), p);
        }
        config.sandbox.daemon_port = Some(7878);
        config.network.infrastructure = vec!["*.tailnet.test".into()];
        let spec = infra_spec(&config);
        assert_eq!(spec.daemon_port, Some(7878));
        assert_eq!(
            spec.model_endpoints,
            [
                "10.0.0.5:80",
                "127.0.0.1:9920",
                "[fd00::5]:8080",
                "api.example.test:443",
                "spark-one.tail1234.ts.net:8000"
            ]
            .map(String::from)
        );
        assert!(spec.docker_hosts.is_empty(), "a disabled box has no Docker host");
        assert_eq!(spec.extra, ["*.tailnet.test"]);
        config.boxed.enabled = true;
        config.boxed.ssh_host = "loom-box".into();
        assert_eq!(infra_spec(&config).docker_hosts, ["loom-box"]);
        // An ssh destination is reduced to its host; one that has none does not stop the daemon.
        for target in ["jeweled@loom-box", "ssh://jeweled@loom-box:2222", "loom-box:22"] {
            config.boxed.ssh_host = target.into();
            assert_eq!(infra_spec(&config).docker_hosts, ["loom-box"], "{target}");
        }
        config.boxed.ssh_host = "user@".into();
        assert!(infra_spec(&config).docker_hosts.is_empty());
        config.boxed.ssh_host = "loom-box".into();
        // Every entry it produces is one the policy reads.
        assert!(Policy::new(&loom_core::config::NetworkCfg::default())
            .unwrap()
            .with_infrastructure(&infra_spec(&config))
            .is_ok());
    }

    #[tokio::test]
    async fn a_network_infrastructure_entry_that_cannot_be_read_stops_the_start() {
        let e = env(Script::new(|_, _| finish("ok"))).await;
        e.rt.shutdown().await;
        let mut config = e.config.clone();
        config.network.infrastructure = vec!["10.0.0.0/99".into()];
        let err = Runtime::start(config, Paths::at(e.dir.path().join("home2"))).await.err().unwrap();
        assert!(err.contains("network.infrastructure") && err.contains("10.0.0.0/99"), "{err}");
    }

    #[tokio::test]
    async fn a_scope_grant_that_could_not_be_handed_to_the_lead_leaves_no_host_allowed() {
        let e = env(Script::new(|_, _| finish("ok"))).await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let id = info.meta.id.clone();
        until("idle", || e.rt.session(&id).is_some_and(|s| s.status.phase == Phase::Idle)).await;
        e.rt.shutdown().await;

        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        // The lead is not active yet; a file where its queue directory belongs makes keeping the input fail.
        std::fs::write(rt2.inner.paths.session_dir(&id).join("queued"), b"x").unwrap();
        let err = rt2.grant_scope(&id, &["api.example.test".to_string()], None).await.unwrap_err();
        assert!(err.contains("send it again"), "{err}");
        // The send activated the lead with the new host; the failure took it back.
        let rule = rt2.inner.proxy.check_name(&id, "api.example.test", 443).map(|v| v.rule);
        assert_eq!(rule.as_deref(), Some("mode deny_all"));
        assert!(rt2.inner.st().scope.values().all(|h| h.is_empty()));
        rt2.shutdown().await;
    }

    #[tokio::test]
    async fn a_blank_scope_or_reason_is_still_recorded_and_a_withdrawal_the_ledger_would_drop_is_refused() {
        let e = env(Script::new(|_, _| finish("ok"))).await;
        // No first message: the lead is idle and its mission's journal is not written yet.
        let info = e.rt.create_session(e.new_session(None)).await.unwrap();
        let (id, mission) = (info.meta.id.clone(), info.meta.mission.clone());
        let refused = "There is no rule k1 in this mission; it has no rules in force.";
        assert_eq!(e.rt.withdraw_rule(&id, "k1", "").await.unwrap_err(), refused);
        let noted =
            |needle: &str| e.has(&id, |ev| matches!(ev, Event::HarnessNote { text, .. } if text.contains(needle)));

        e.rt.add_rule(&id, "first rule").await.unwrap();
        e.rt.add_rule(&id, "second rule").await.unwrap();
        // The receipt names the stock text that stands in for the blank scope or reason.
        let receipt = e.rt.approve(&id, "ship it", "  ").await.unwrap();
        assert_eq!((receipt.ledger, receipt.stock.as_deref()), (true, Some("only what the approval says")));
        until("approval", || e.rt.ledger(&mission).is_ok_and(|l| l.state.approvals.len() == 1)).await;
        let approval = e.rt.ledger(&mission).unwrap().state.approvals[0].clone();
        assert_eq!((approval.id.as_str(), approval.scope.as_str()), ("a1", "only what the approval says"));
        until("approval note", || noted("gave an approval (a1)")).await;

        for (rule, sentence) in [
            ("k9", "There is no rule k9 in this mission; its rules are k1, k2."),
            ("a1", "There is no rule a1 in this mission; its rules are k1, k2."),
            ("K1", "There is no rule K1 in this mission; its rules are k1, k2."),
        ] {
            assert_eq!(e.rt.withdraw_rule(&id, rule, "why").await.unwrap_err(), sentence);
        }
        let receipt = e.rt.withdraw_rule(&id, " k1 ", "").await.unwrap();
        assert_eq!(receipt.stock.as_deref(), Some("no reason given"));
        until("k1 retired", || e.rt.ledger(&mission).is_ok_and(|l| l.state.constraints[0].retired.is_some())).await;
        let rules = e.rt.ledger(&mission).unwrap().state.constraints;
        assert_eq!((rules[0].retired.as_deref(), rules[1].retired.as_deref()), (Some("no reason given"), None));
        until("withdrawal note", || noted("withdrew rule k1")).await;
        assert_eq!(e.rt.withdraw_rule(&id, "k1", "again").await.unwrap_err(), "Rule k1 is already withdrawn.");
        assert_eq!(
            e.rt.withdraw_rule(&id, "k7", "").await.unwrap_err(),
            "There is no rule k7 in this mission; its rules are k2."
        );
        assert_eq!(e.rt.withdraw_rule(&id, "k2", "lifted").await.unwrap().stock, None);
        until("k2 retired", || e.rt.ledger(&mission).is_ok_and(|l| l.state.constraints[1].retired.is_some())).await;
        assert_eq!(
            e.rt.withdraw_rule(&id, "k3", "").await.unwrap_err(),
            "There is no rule k3 in this mission; it has no rules in force."
        );
        assert!(!e.kinds(&id).iter().any(|k| k == "turn_start"), "operator rules must not start a turn");
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn a_mission_without_a_ledger_takes_rules_as_notes_only_and_says_so() {
        use loom_core::event::NoteKind;
        let e = env(Script::new(|_, _| Action::Stall { ms: 600_000 })).await;
        // The `chat` role ends its turns freely: its mission keeps no ledger.
        let new = NewSession { role: Some("chat".into()), ..e.new_session(None) };
        let info = e.rt.create_session(new).await.unwrap();
        let (id, mission) = (info.meta.id.clone(), info.meta.mission.clone());
        let note = |kind: NoteKind, start: &str, end: &str| {
            e.has(&id, |ev| match ev {
                Event::HarnessNote { note, text } => *note == kind && text.starts_with(start) && text.ends_with(end),
                _ => false,
            })
        };

        let receipt = e.rt.add_rule(&id, " no prod\n").await.unwrap();
        assert_eq!(receipt, RuleReceipt { lead: id.clone(), queued: false, ledger: false, stock: None });
        until("rule note", || note(NoteKind::Constraint, "The operator set a standing rule. ", "\nno prod")).await;
        // No stock scope: nothing would record it, and the note has its own words for a blank one.
        let receipt = e.rt.approve(&id, "ship it", " ").await.unwrap();
        assert_eq!((receipt.ledger, receipt.stock), (false, None));
        let covers = "The operator gave an approval. It covers what is written here and nothing beyond it. ";
        until("approval note", || note(NoteKind::Approval, covers, "\nship it")).await;
        assert_eq!(
            e.rt.withdraw_rule(&id, "k1", "").await.unwrap_err(),
            "There is no rule k1 to withdraw: this mission keeps no ledger, so its rules have no ids. Tell the lead in a message that the rule no longer applies."
        );
        assert!(e.rt.ledger(&mission).unwrap_err().starts_with("No ledger"));
        assert!(!e.kinds(&id).iter().any(|k| k == "turn_start"), "operator rules must not start a turn");
        tokio::time::timeout(Duration::from_secs(30), e.rt.shutdown()).await.unwrap();
    }

    #[tokio::test]
    async fn a_rule_sent_to_a_lead_in_a_turn_is_reported_as_queued_and_not_recorded_yet() {
        let e = env(Script::new(|_, _| Action::Stall { ms: 600_000 })).await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let (id, mission) = (info.meta.id.clone(), info.meta.mission.clone());
        until("request", || !e.server.requests().is_empty()).await;
        until("running", || e.rt.session(&id).is_some_and(|s| s.status.phase == Phase::Running)).await;

        let receipt = e.rt.add_rule(&id, "no prod").await.unwrap();
        assert_eq!(receipt, RuleReceipt { lead: id.clone(), queued: true, ledger: true, stock: None });
        assert!(e.rt.approve(&id, "ship it", "staging").await.unwrap().queued);
        // The lead is waiting for the model: the rule is in its queue, not in the ledger.
        let state = e.rt.ledger(&mission).unwrap().state;
        assert_eq!((state.goal.as_deref(), state.constraints.len(), state.approvals.len()), (Some("go"), 0, 0));
        tokio::time::timeout(Duration::from_secs(30), e.rt.shutdown()).await.unwrap();
    }

    #[tokio::test]
    async fn a_rule_queued_for_a_lead_in_a_turn_is_kept_on_disk_until_it_is_recorded() {
        let stall = Arc::new(AtomicBool::new(true));
        let flag = stall.clone();
        let e =
            env(Script::new(
                move |_, _| {
                    if flag.load(Ordering::SeqCst) {
                        Action::Stall { ms: 600_000 }
                    } else {
                        finish("done")
                    }
                },
            ))
            .await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let (id, mission) = (info.meta.id.clone(), info.meta.mission.clone());
        until("running", || e.rt.session(&id).is_some_and(|s| s.status.phase == Phase::Running)).await;
        until("request", || !e.server.requests().is_empty()).await;
        assert!(e.rt.add_rule(&id, "no prod").await.unwrap().queued);
        let queue = e.rt.paths().session_dir(&id).join("queued");
        assert_eq!(std::fs::read_dir(&queue).unwrap().count(), 1, "kept on disk while the lead is busy");
        e.rt.shutdown().await;
        stall.store(false, Ordering::SeqCst);
        // Recorded exactly once, whether the lead took it on its way down or after the restart.
        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        let r2 = rt2.clone();
        until("the rule", || r2.ledger(&mission).is_ok_and(|l| l.state.constraints.len() == 1)).await;
        until("the queue emptied", || std::fs::read_dir(&queue).map_or(0, |d| d.count()) == 0).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(rt2.ledger(&mission).unwrap().state.constraints.len(), 1);
        rt2.shutdown().await;
    }

    #[tokio::test]
    async fn a_lead_that_keeps_a_ledger_has_an_empty_one_before_its_journal_file_exists() {
        let e = env(Script::new(|_, _| Action::Stall { ms: 600_000 })).await;
        let info = e.rt.create_session(e.new_session(None)).await.unwrap();
        let mission = info.meta.mission.clone();
        let journal = e.rt.paths().journal(&mission);
        assert!(!journal.exists(), "a lead with no goal yet has written nothing");
        let view = e.rt.ledger(&mission).unwrap();
        assert_eq!((view.state.constraints.len(), view.state.goal.as_deref()), (0, None));
        assert!(!journal.exists(), "reading must not create the journal");
        tokio::time::timeout(Duration::from_secs(30), e.rt.shutdown()).await.unwrap();
    }

    #[tokio::test]
    async fn the_ledger_view_reports_what_the_read_could_not_show() {
        let e = env(Script::new(|_, _| Action::Stall { ms: 600_000 })).await;
        let info = e.rt.create_session(e.new_session(None)).await.unwrap();
        let mission = info.meta.mission.clone();
        let journal = Journal::new(e.rt.paths().journal(&mission), e.rt.inner.key.clone());
        journal
            .append(&info.meta.id, true, loom_core::ledger::LedgerOp::GoalSet { text: "ship it".into() }, &|_| Ok(()))
            .unwrap();
        let view = e.rt.ledger(&mission).unwrap();
        assert_eq!((view.skipped, view.torn_tail, view.ahead_of_head), (0, false, 0));
        assert!(view.notices().is_empty(), "{:?}", view.notices());

        // An interrupted append is ignored, and a journal whose head record is gone is ahead of it.
        let path = e.rt.paths().journal(&mission);
        std::fs::remove_file(path.with_extension("head")).unwrap();
        let mut text = std::fs::read(&path).unwrap();
        text.extend_from_slice(b"{\"n\":2,\"ts_ms\"");
        std::fs::write(&path, text).unwrap();
        let view = e.rt.ledger(&mission).unwrap();
        assert_eq!(view.state.goal.as_deref(), Some("ship it"));
        assert_eq!((view.skipped, view.torn_tail, view.ahead_of_head), (0, true, 1));
        let notices = view.notices();
        assert_eq!(notices.len(), 2, "{notices:?}");
        assert!(notices[0].contains("interrupted write"), "{notices:?}");
        assert!(notices[1].contains("1 ledger entry is not vouched for"), "{notices:?}");
        tokio::time::timeout(Duration::from_secs(30), e.rt.shutdown()).await.unwrap();
    }

    /// The seal the journal gives an entry: HMAC-SHA256 under `key` of the previous seal followed by the body.
    fn seal(key: &[u8], prev: &str, body: &str) -> String {
        let bytes = |hex: String| -> Vec<u8> {
            (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect()
        };
        let mut k = if key.len() > 64 { bytes(loom_core::sha256_hex(key)) } else { key.to_vec() };
        k.resize(64, 0);
        let padded = |x: u8| k.iter().map(|b| b ^ x).collect::<Vec<u8>>();
        let inner = [padded(0x36), prev.as_bytes().to_vec(), body.as_bytes().to_vec()].concat();
        loom_core::sha256_hex(&[padded(0x5c), bytes(loom_core::sha256_hex(&inner))].concat())
    }

    #[tokio::test]
    async fn ledger_entries_of_a_newer_loom_are_counted_in_the_view_and_the_state_block() {
        let e = env(Script::new(|_, _| Action::Stall { ms: 600_000 })).await;
        let info = e.rt.create_session(e.new_session(None)).await.unwrap();
        let (id, mission) = (info.meta.id.clone(), info.meta.mission.clone());
        let path = e.rt.paths().journal(&mission);
        let op = loom_core::ledger::LedgerOp::ConstraintAdd { text: "CONSTRAINTMARK never touch prod".into() };
        Journal::new(&path, e.rt.inner.key.clone()).append(&id, true, op, &|_| Ok(())).unwrap();
        // An entry sealed with the mission's key whose op this build does not know.
        let text = std::fs::read_to_string(&path).unwrap();
        let first: Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        let body = format!(r#"{{"n":2,"ts_ms":11,"session":"{id}","from_user":false,"op":"hologram_set","depth":3}}"#);
        let mac = seal(&e.rt.inner.key, first["mac"].as_str().unwrap(), &body);
        std::fs::write(&path, format!("{text}{},\"mac\":\"{mac}\"}}\n", &body[..body.len() - 1])).unwrap();

        let view = e.rt.ledger(&mission).unwrap();
        assert_eq!((view.state.constraints.len(), view.skipped, view.torn_tail), (1, 1, false));
        let detail = view.skipped_detail.clone().unwrap_or_default();
        assert!(detail.starts_with("entry 2: op `hologram_set`"), "{detail}");
        let notices = view.notices();
        assert!(
            notices[0].starts_with("1 ledger entry written by a newer loom is not shown (first: entry 2"),
            "{notices:?}"
        );

        // The model's state block says so as well.
        e.rt.send_message(&id, "go").await.unwrap();
        until("request", || !e.server.requests().is_empty()).await;
        let hud = hud_of(&e.server.requests()[0]);
        assert!(hud.contains("CONSTRAINTMARK"), "{hud}");
        assert!(hud.contains("\n\n1 ledger entry written by a newer loom is not shown"), "{hud}");
        tokio::time::timeout(Duration::from_secs(30), e.rt.shutdown()).await.unwrap();
    }

    #[test]
    fn skipped_ledger_entries_are_named_in_the_view() {
        let view = LedgerView {
            skipped: 2,
            skipped_detail: Some("entry 4: op `hologram_set`: unknown variant".into()),
            ..LedgerView::default()
        };
        let notices = view.notices();
        assert_eq!(notices.len(), 1);
        assert!(
            notices[0].starts_with(
                "2 ledger entries written by a newer loom are not shown (first: entry 4: op `hologram_set`"
            ),
            "{notices:?}"
        );
        // A view from a daemon that does not report them still reads.
        let mut wire = serde_json::to_value(LedgerView::default()).unwrap();
        for key in ["skipped", "skipped_detail", "torn_tail", "ahead_of_head"] {
            wire.as_object_mut().unwrap().remove(key);
        }
        let old: LedgerView = serde_json::from_value(wire).unwrap();
        assert!(old.notices().is_empty());
    }

    #[tokio::test]
    async fn a_lead_whose_pack_is_gone_and_has_no_journal_file_keeps_no_ledger() {
        let pack_toml = "name = \"gone\"\ndefault_role = \"r\"\n[roles.r]\nprompt = \"r.md\"\ntools = [\"finish\"]\ntermination = \"explicit\"\n";
        let e = env_with_packs(
            Script::new(|_, _| Action::Stall { ms: 600_000 }),
            |_| {},
            |packs| {
                std::fs::create_dir_all(packs.join("gone")).unwrap();
                std::fs::write(packs.join("gone/pack.toml"), pack_toml).unwrap();
                std::fs::write(packs.join("gone/r.md"), "Role R.").unwrap();
            },
        )
        .await;
        let mut new = e.new_session(None);
        new.pack = Some("gone".into());
        let mission = e.rt.create_session(new).await.unwrap().meta.mission;
        assert!(!e.rt.paths().journal(&mission).exists());
        assert!(e.rt.ledger(&mission).is_ok(), "its role keeps a ledger: an empty one");
        e.rt.shutdown().await;
        std::fs::remove_dir_all(e.rt.paths().packs_dir().join("gone")).unwrap();
        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        assert_eq!(rt2.ledger(&mission).unwrap_err(), "No ledger: this mission's lead does not keep one.");
        rt2.shutdown().await;
    }

    #[tokio::test]
    async fn ledger_refuses_a_mission_no_session_belongs_to() {
        let e = env(Script::new(|_, _| finish("ok"))).await;
        let err = e.rt.ledger(&MissionId::from("../../etc")).unwrap_err();
        assert_eq!(err, "There is no mission ../../etc.");
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn net_audit_hook_chains_the_session_net_file() {
        let e = env(Script::new(|_, _| finish("ok"))).await;
        let info = e.rt.create_session(e.new_session(Some("net"))).await.unwrap();
        let id = info.meta.id.clone();
        until("turn end", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { .. }))).await;
        let audit = net_audit(e.rt.paths().clone(), e.rt.inner.bus.clone());
        let decision = |host: &str| NetDecision {
            host: host.into(),
            port: 443,
            method: "CONNECT".into(),
            allowed: true,
            rule: "mode open".into(),
            resolved: None,
            sni: None,
        };
        let path = e.rt.paths().session_dir(&id).join("net.jsonl");
        // Lines written before the chain existed still load; new lines chain after them.
        let old = serde_json::to_string(&NetEntry { ts_ms: 1, decision: decision("old.test") }).unwrap();
        std::fs::write(&path, format!("{old}\n")).unwrap();
        audit(Some(&id), &decision("a.test")).unwrap();
        audit(Some(&id), &decision("b.test")).unwrap();
        let hosts: Vec<String> = e.rt.net(&id, 10).unwrap().into_iter().map(|n| n.decision.host).collect();
        assert_eq!(hosts, ["old.test", "a.test", "b.test"]);
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.matches("\"prev\"").count(), 2);
        // An append torn by a crash, here inside a character, does not hide the lines before it.
        std::fs::write(&path, [text.as_bytes(), &"{\"rule\":\"…".as_bytes()[..10]].concat()).unwrap();
        let hosts: Vec<String> = e.rt.net(&id, 10).unwrap().into_iter().map(|n| n.decision.host).collect();
        assert_eq!(hosts, ["old.test", "a.test", "b.test"]);
        // A modified line is reported, not served.
        std::fs::write(&path, text.replace("a.test", "z.test")).unwrap();
        let err = e.rt.net(&id, 10).unwrap_err();
        assert!(err.contains("damaged at line 3"), "{err}");
        // No session directory: the hook fails, so the proxy refuses the connection.
        assert!(audit(Some(&SessionId::from("s-missing")), &decision("c.test")).is_err());
        // A decision that names no session goes to a chained file of its own.
        audit(None, &decision("u.test")).unwrap();
        audit(None, &decision("v.test")).unwrap();
        let text = std::fs::read_to_string(e.rt.paths().logs_dir().join(UNATTRIBUTED_NET)).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert_eq!(loom_net::netlog::verify(&text), Ok(()));
    }

    /// Standard base64, for a Basic credential in a test.
    fn base64(s: &str) -> String {
        const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for c in s.as_bytes().chunks(3) {
            let n = c.iter().enumerate().fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
            for i in 0..4 {
                out.push(if i <= c.len() { ABC[((n >> (18 - 6 * i)) & 63) as usize] as char } else { '=' });
            }
        }
        out
    }

    #[tokio::test]
    async fn the_runtime_proxy_records_each_decision_once_in_the_file_and_on_the_bus() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        assert_eq!(base64("s-x:00ff"), "cy14OjAwZmY=");
        let e = env(Script::new(|_, _| finish("ok"))).await;
        let info = e.rt.create_session(e.new_session(Some("net"))).await.unwrap();
        let id = info.meta.id.clone();
        until("turn end", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { .. }))).await;
        let grant = e.rt.inner.proxy.grant(&id, Policy::new(&e.config.network).unwrap()).unwrap();
        let mut bus = e.rt.subscribe();
        // Command credentials are served on the session's own listener.
        let port = grant.port;
        let ask = move |req: String| async move {
            let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            s.write_all(req.as_bytes()).await.unwrap();
            let mut resp = Vec::new();
            tokio::time::timeout(WAIT, s.read_to_end(&mut resp)).await.unwrap().unwrap();
            String::from_utf8_lossy(&resp).to_string()
        };
        let creds = base64(&format!("{}:{}", grant.user, grant.password));
        let req = format!("CONNECT example.test:443 HTTP/1.1\r\nProxy-Authorization: Basic {creds}\r\n\r\n");
        let resp = ask(req).await;
        assert!(resp.starts_with("HTTP/1.1 403 "), "{resp}");
        // On disk, chained, and served by the session net view.
        let net = e.rt.net(&id, 10).unwrap();
        assert_eq!(net.len(), 1, "{net:?}");
        assert_eq!((net[0].decision.host.as_str(), net[0].decision.rule.as_str()), ("example.test", "mode deny_all"));
        let text = std::fs::read_to_string(e.rt.paths().session_dir(&id).join("net.jsonl")).unwrap();
        assert!(text.contains(&format!("\"prev\":\"{}\"", loom_net::netlog::GENESIS)), "{text}");
        // On the bus: the same entry, once.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut published = Vec::new();
        while let Ok(ev) = bus.try_recv() {
            if let BusEvent::Net { session, entry } = ev {
                published.push((session, entry));
            }
        }
        assert_eq!(published, [(id.clone(), net[0].clone())]);
        // A request that names no session lands in the daemon's own file.
        assert!(ask("garbage\r\n\r\n".to_string()).await.starts_with("HTTP/1.1 400 "));
        let text = std::fs::read_to_string(e.rt.paths().logs_dir().join(UNATTRIBUTED_NET)).unwrap();
        assert_eq!(loom_net::netlog::verify(&text), Ok(()));
        assert!(text.contains("bad request: the request head could not be parsed"), "{text}");
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn awaited_child_returns_to_the_call_and_is_recorded_inline() {
        let e = env(lead_script(json!({"question": "CHILDMARK find it"}))).await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let id = info.meta.id.clone();
        until("lead turn end", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { .. }))).await;
        let kinds = e.kinds(&id);
        let spawned = kinds.iter().position(|k| k == "child_spawned").unwrap();
        let result = kinds.iter().position(|k| k == "tool_result").unwrap();
        let settled = kinds.iter().position(|k| k == "child_settled").unwrap();
        assert!(spawned < settled);
        assert!(result < kinds.len());
        assert_eq!(kinds.iter().filter(|k| *k == "child_settled").count(), 1);
        match &e.records(&id)[settled].event {
            Event::ChildSettled(c) => {
                assert!(c.inline);
                assert_eq!(c.outcome, ChildOutcome::Returned);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(e.children(&id).len(), 1);
        let child_first = e.server.requests().into_iter().find(|b| !has_tool(b, "agent_spawn")).expect("child request");
        let text = child_first.to_string();
        assert!(text.contains("CHILDMARK find it"));
        assert!(text.contains("Workspace:"));
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn children_share_the_mission_journal() {
        let e = env(Script::new(|body, _| {
            if has_tool(body, "agent_spawn") {
                if last_role(body) == "tool" {
                    finish("lead done")
                } else {
                    call("agent_spawn", json!({"question": "CHILDMARK work"}))
                }
            } else {
                match tool_msgs(body) {
                    0 => call("note", json!({"kind": "decision", "text": "worker note", "why": "because"})),
                    1 => call("ledger", json!({})),
                    _ => finish("child report"),
                }
            }
        }))
        .await;
        let info = e.rt.create_session(e.new_session(None)).await.unwrap();
        let id = info.meta.id.clone();
        // An operator constraint, written before the worker exists.
        let journal = Journal::new(e.rt.inner.paths.journal(&info.meta.mission), e.rt.inner.key.clone());
        let op = loom_core::ledger::LedgerOp::ConstraintAdd { text: "CONSTRAINTMARK never touch prod".into() };
        journal.append(&id, true, op, &|_| Ok(())).unwrap();
        e.rt.send_message(&id, "go").await.unwrap();
        until("lead turn end", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { .. }))).await;
        let kids = e.children(&id);
        assert_eq!(kids.len(), 1);
        let results: Vec<(String, loom_core::event::ToolStatus)> = e
            .records(&kids[0].meta.id)
            .into_iter()
            .filter_map(|r| match r.event {
                Event::ToolResult(t) => Some((t.name, t.status)),
                _ => None,
            })
            .collect();
        for name in ["note", "ledger"] {
            let got = results.iter().find(|(n, _)| n == name);
            assert_eq!(got.map(|(_, s)| *s), Some(loom_core::event::ToolStatus::Ok), "{name}: {results:?}");
        }
        // The worker's first request holds no tool result yet, and only its state block is looked at.
        let child_first = e.server.requests().into_iter().find(|b| !has_tool(b, "agent_spawn")).expect("child request");
        assert_eq!(tool_msgs(&child_first), 0);
        let hud = hud_of(&child_first);
        assert!(hud.contains("CONSTRAINTMARK"), "the child's state block lacks the mission constraints: {hud}");
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn the_stall_note_goes_to_a_child_that_can_record_and_not_to_a_verifier() {
        let script = Script::new(|body, _| {
            if !has_tool(body, "agent_spawn") && tool_msgs(body) < 4 {
                call("ledger", json!({}))
            } else {
                Action::Stall { ms: 600_000 }
            }
        });
        let e = env_with(script, false, |c| c.agents.stall_steps = 2).await;
        let id = e.rt.create_session(e.new_session(Some("go"))).await.unwrap().meta.id;
        until("request", || !e.server.requests().is_empty()).await;
        let req = |role: &str| SpawnReq {
            role: role.into(),
            mode: SpawnMode::Fresh,
            brief: Default::default(),
            budget: Budget::default(),
            call_id: CallId::from("c1"),
            title: role.into(),
            awaited: false,
            harness: false,
            prerequisite: None,
            workspace: Workspace::Shared,
        };
        let worker = e.rt.inner.orch.spawn(&id, req("worker")).await.unwrap();
        let verifier = e.rt.inner.orch.spawn(&id, req("verifier")).await.unwrap();
        let steps = |c: &SessionId| e.records(c).iter().filter(|r| matches!(r.event, Event::ModelRequest(_))).count();
        until("five steps each", || steps(&worker) >= 5 && steps(&verifier) >= 5).await;
        let stall_notes = |c: &SessionId| -> Vec<String> {
            e.records(c)
                .into_iter()
                .filter_map(|r| match r.event {
                    Event::HarnessNote { note: loom_core::event::NoteKind::Stall, text } => Some(text),
                    _ => None,
                })
                .collect()
        };
        // Both share the journal, so both are watched; only the one with `note` is asked to use it.
        let given = stall_notes(&worker);
        assert!(!given.is_empty() && given.iter().all(|t| *t == texts::stall(2)), "{given:?}");
        assert!(stall_notes(&verifier).is_empty(), "{:?}", stall_notes(&verifier));
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn fork_child_starts_with_the_parents_messages() {
        let e = env(Script::new(|body, _| {
            if mentions(body, "You are now a separate agent") {
                finish("child report")
            } else if mentions(body, "child report") {
                finish("done")
            } else if mentions(body, "hello") {
                call("agent_spawn", json!({"question": "FORKMARK", "mode": "fork", "role": "worker"}))
            } else {
                call("note", json!({"text": "hello"}))
            }
        }))
        .await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let id = info.meta.id.clone();
        until("lead end", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { .. }))).await;
        let reqs = e.server.requests();
        let parent = reqs
            .iter()
            .find(|b| mentions(b, "hello") && !mentions(b, "FORKMARK") && !mentions(b, "You are now a separate agent"))
            .expect("parent request");
        let child = reqs.iter().find(|b| mentions(b, "You are now a separate agent")).expect("child request");
        let pm = parent["messages"].as_array().unwrap();
        let cm = child["messages"].as_array().unwrap();
        // the parent's request, minus the harness-state message at its end, is a prefix of the child's
        let common = pm.len() - 1;
        assert!(cm.len() > common);
        assert_eq!(pm[..common], cm[..common]);
        assert!(cm[common..].iter().any(|m| m.to_string().contains("FORKMARK")));
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn fresh_forked_and_verifier_children_are_bound_to_current_mission_state() {
        let e = env(Script::new(|_, _| Action::Stall { ms: 600_000 })).await;
        let parent = e.rt.create_session(e.new_session(None)).await.unwrap().meta.id;
        let shared = e.rt.inner.st().known.get(&parent).unwrap().active.as_ref().unwrap().shared.clone();
        for op in [
            loom_core::ledger::LedgerOp::GoalSet { text: "MISSION_STATE_GOAL".into() },
            loom_core::ledger::LedgerOp::ConstraintAdd { text: "MISSION_STATE_RULE: never deploy".into() },
            loom_core::ledger::LedgerOp::ApprovalGrant {
                text: "MISSION_STATE_PERMISSION".into(),
                scope: "read staging".into(),
            },
        ] {
            shared.ledger_append(true, op).unwrap();
        }
        e.rt.send_message(&parent, "establish a fork point").await.unwrap();
        until("parent request", || !e.server.requests().is_empty()).await;
        for (role, mode) in [("worker", SpawnMode::Fresh), ("worker", SpawnMode::Fork), ("verifier", SpawnMode::Fresh)]
        {
            e.rt.inner
                .spawn_child(
                    &parent,
                    SpawnReq {
                        role: role.into(),
                        mode,
                        brief: Brief { question: "a minimal brief".into(), ..Brief::default() },
                        budget: Budget::default(),
                        call_id: CallId::from("state-test"),
                        title: "state test".into(),
                        awaited: true,
                        harness: false,
                        prerequisite: None,
                        workspace: Workspace::Shared,
                    },
                )
                .await
                .unwrap();
        }
        until("three child requests", || {
            e.server.requests().iter().filter(|b| mentions(b, "Mission ledger access:")).count() == 3
        })
        .await;
        let requests = e.server.requests();
        let child_requests: Vec<_> = requests.iter().filter(|b| mentions(b, "Mission ledger access:")).collect();
        assert_eq!(child_requests.len(), 3);
        for request in &child_requests {
            for text in
                ["MISSION_STATE_GOAL", "MISSION_STATE_RULE: never deploy", "MISSION_STATE_PERMISSION", "read staging"]
            {
                assert!(mentions(request, text), "child is missing {text}");
            }
            assert!(has_tool(request, "ledger"));
        }
        assert_eq!(child_requests.iter().filter(|b| mentions(b, "Mission ledger access: read-only")).count(), 1);
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn spawn_refusals() {
        let e = env_with(Script::new(|_, _| Action::Stall { ms: 600_000 }), false, |c| c.agents.max_children = 1).await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let id = info.meta.id.clone();
        until("request", || !e.server.requests().is_empty()).await;
        let orch = e.rt.inner.orch.clone();
        let req = |role: &str| SpawnReq {
            role: role.into(),
            mode: SpawnMode::Fresh,
            brief: Default::default(),
            budget: Budget::default(),
            call_id: CallId::from("c1"),
            title: "t".into(),
            awaited: false,
            harness: false,
            prerequisite: None,
            workspace: Workspace::Shared,
        };
        let err = orch.spawn(&id, req("nobody")).await.unwrap_err();
        assert!(err.contains("is not a role this session can start"), "{err}");
        let child = orch.spawn(&id, req("worker")).await.unwrap();
        let err = orch.spawn(&id, req("worker")).await.unwrap_err();
        assert!(err.contains("most allowed"), "{err}");
        let err = orch.spawn(&child, req("worker")).await.unwrap_err();
        assert!(err.contains("Only the lead"), "{err}");
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn actual_role_credential_gate_and_epoch_cap_apply_before_child_allocation() {
        use loom_core::event::NoteKind;
        use loom_core::ledger::{EvidenceInput, EvidenceKind, LedgerOp};
        use loom_core::security_state::{AssetInput, AssetKind, CredentialInput, SecurityOp};
        let e = env_with_packs(
            Script::new(|_, _| Action::Stall { ms: 600_000 }),
            |_| {},
            |packs| {
                let path = packs.join("core/pack.toml");
                let text = std::fs::read_to_string(&path).unwrap();
                std::fs::write(
                    path,
                    text.replace("[roles.worker]", "[roles.worker]\nrequires_credential = true\nmax_steps = 3"),
                )
                .unwrap();
            },
        )
        .await;
        let parent = e.rt.create_session(e.new_session(Some("fixture goal"))).await.unwrap().meta.id;
        until("parent active", || !e.server.requests().is_empty()).await;
        let request = |prerequisite| SpawnReq {
            role: "worker".into(),
            mode: SpawnMode::Fresh,
            brief: Default::default(),
            budget: Budget { max_steps: Some(0), max_minutes: None },
            call_id: "fixture-call".into(),
            title: "gated fixture".into(),
            awaited: true,
            harness: false,
            prerequisite,
            workspace: Workspace::Shared,
        };
        assert!(e.rt.inner.orch.spawn(&parent, request(None)).await.unwrap_err().contains("requires explicit"));
        assert!(e.children(&parent).is_empty());
        let shared = e.rt.inner.st().known.get(&parent).unwrap().active.as_ref().unwrap().shared.clone();
        shared.ledger_append(false, LedgerOp::ClaimAdd { text: "credential observed".into() }).unwrap();
        shared
            .ledger_append(
                false,
                LedgerOp::EvidenceAdd(EvidenceInput {
                    claim: "c1".into(),
                    kind: EvidenceKind::Execution,
                    supports: true,
                    session: parent.clone(),
                    call_id: "fixture-observation".into(),
                    blob: None,
                    lines: None,
                    quote: None,
                    note: "dummy credential fixture".into(),
                    attested: true,
                    tool: None,
                    grade: None,
                }),
            )
            .unwrap();
        let mut assets = Vec::new();
        for locator in ["first.test", "second.test"] {
            let asset = AssetInput {
                kind: AssetKind::Host,
                locator: locator.into(),
                evidence: vec!["e1".into()],
                mandatory: false,
                parent: None,
            };
            assets.push(asset.id().unwrap());
            shared.ledger_append(false, LedgerOp::Security(SecurityOp::AssetUpsert { asset })).unwrap();
        }
        let mut credential = CredentialInput {
            asset: assets[0].clone(),
            principal: "dummy".into(),
            secret_handle: "out:0123456789abcdef".into(),
            evidence: vec!["e1".into()],
            unlocks: vec![],
            expires_ms: Some(0),
        };
        let (_, state) = shared
            .ledger_append(false, LedgerOp::Security(SecurityOp::CredentialAdd { credential: credential.clone() }))
            .unwrap();
        let id = state.security.credentials.keys().next().unwrap().clone();
        let good = rtools::DispatchPrerequisite { asset: assets[0].clone(), credential: id.clone() };
        let wrong = rtools::DispatchPrerequisite { asset: assets[1].clone(), credential: id };
        assert!(e.rt.inner.orch.spawn(&parent, request(Some(wrong))).await.unwrap_err().contains("another asset"));
        assert!(e.rt.inner.orch.spawn(&parent, request(Some(good.clone()))).await.unwrap_err().contains("expired"));
        assert!(e.children(&parent).is_empty());
        credential.expires_ms = None;
        shared.ledger_append(false, LedgerOp::Security(SecurityOp::CredentialAdd { credential })).unwrap();
        let child = e.rt.inner.orch.spawn(&parent, request(Some(good.clone()))).await.unwrap();
        let records = e.records(&child);
        assert!(records
            .iter()
            .any(|r| matches!(&r.event,Event::SessionStart(start) if start.budget.max_steps==Some(3))));
        assert!(records.iter().any(|r| matches!(&r.event,Event::HarnessNote{note:NoteKind::Assignment,text}
            if text.contains(&good.asset)&&text.contains(&good.credential))));
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn child_reference_aliases_are_exact_first_ambiguous_safe_and_parent_scoped() {
        let e = env(Script::new(|_, _| Action::Stall { ms: 600_000 })).await;
        let first = e.rt.create_session(e.new_session(None)).await.unwrap().meta;
        let second = e.rt.create_session(e.new_session(None)).await.unwrap().meta;
        {
            let mut state = e.rt.inner.st();
            for (id, parent, created) in
                [("s-agentA", &first, 10), ("s-agentB", &first, 20), ("s-age", &first, 30), ("s-foreign", &second, 99)]
            {
                let mut meta = parent.clone();
                meta.id = id.into();
                meta.parent = Some(parent.id.clone());
                meta.created_ms = created;
                state.known.insert(meta.id.clone(), Known::new(meta, idle_status()));
            }
        }
        let resolve = |parent: &SessionId, name: &str| e.rt.inner.resolve_child_id(parent, &name.into());
        assert_eq!(resolve(&first.id, "s-age").unwrap(), SessionId::from("s-age"));
        assert_eq!(resolve(&first.id, "s-agentA").unwrap(), SessionId::from("s-agentA"));
        assert!(resolve(&first.id, "s-agent").unwrap_err().contains("ambiguous"));
        assert_eq!(resolve(&first.id, "last").unwrap(), SessionId::from("s-age"));
        assert_eq!(resolve(&second.id, "s-fore").unwrap(), SessionId::from("s-foreign"));
        assert!(resolve(&first.id, "s-fore").is_err());
        assert!(resolve(&second.id, "s-agent").is_err());
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn a_held_gate_verifier_does_not_use_a_slot_of_max_children() {
        let e = env_with(Script::new(|_, _| Action::Stall { ms: 600_000 }), false, |c| c.agents.max_children = 1).await;
        let id = e.rt.create_session(e.new_session(Some("go"))).await.unwrap().meta.id;
        until("request", || !e.server.requests().is_empty()).await;
        let orch = e.rt.inner.orch.clone();
        let req = |role: &str, harness: bool| SpawnReq {
            role: role.into(),
            mode: SpawnMode::Fresh,
            brief: Default::default(),
            budget: Budget::default(),
            call_id: CallId::from("c1"),
            title: "t".into(),
            awaited: false,
            harness,
            prerequisite: None,
            workspace: Workspace::Shared,
        };
        orch.spawn(&id, req("verifier", true)).await.unwrap();
        orch.spawn(&id, req("worker", false)).await.expect("a gate verifier is not counted against max_children");
        let err = orch.spawn(&id, req("worker", false)).await.unwrap_err();
        assert!(err.starts_with("1 agents are already running"), "{err}");
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn harness_spawn_ignores_max_children_and_may_spawn() {
        let e = env_with(Script::new(|_, _| Action::Stall { ms: 600_000 }), false, |c| c.agents.max_children = 1).await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let id = info.meta.id.clone();
        until("request", || !e.server.requests().is_empty()).await;
        let orch = e.rt.inner.orch.clone();
        let req = |role: &str, harness: bool| SpawnReq {
            role: role.into(),
            mode: SpawnMode::Fresh,
            brief: Default::default(),
            budget: Budget::default(),
            call_id: CallId::from("c1"),
            title: "t".into(),
            awaited: false,
            harness,
            prerequisite: None,
            workspace: Workspace::Shared,
        };
        orch.spawn(&id, req("worker", false)).await.unwrap();
        let err = orch.spawn(&id, req("verifier", false)).await.unwrap_err();
        assert!(err.contains("most allowed"), "{err}");
        let verifier = orch.spawn(&id, req("verifier", true)).await.unwrap();
        // `chat` is not in the lead's may_spawn: only the harness may start it.
        let err = orch.spawn(&id, req("chat", false)).await.unwrap_err();
        assert!(err.contains("is not a role this session can start"), "{err}");
        // Started, not the verifier with the same assignment handed back.
        let chat = orch.spawn(&id, req("chat", true)).await.unwrap();
        assert_ne!(chat, verifier);
        assert_eq!(e.rt.session(&chat).unwrap().meta.role, "chat");
        e.rt.shutdown().await;
        // During a shutdown even the harness gets the sentence that `finish` takes for a restart, not a failure.
        assert_eq!(orch.spawn(&id, req("verifier", true)).await.unwrap_err(), crate::rtools::SHUTTING_DOWN);
    }

    #[tokio::test]
    async fn verified_finish_with_real_children_is_delivered_after_an_accepting_verdict() {
        let e = env_with(
            Script::new(
                |body, _| if has_tool(body, "verdict") { verifier_turn(body, true) } else { finish("lead done") },
            ),
            false,
            |c| c.agents.verify_finish = true,
        )
        .await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let id = info.meta.id.clone();
        until("finished item", || inbox_kinds(&e).contains(&InboxKind::Finished)).await;
        let item = e.rt.inbox().remove(0).item;
        assert!(item.text.starts_with("lead done") && item.text.contains("[verified by s-"), "{}", item.text);
        let ledger = e.rt.ledger(&info.meta.mission).unwrap();
        assert_eq!(ledger.state.finishes.len(), 1);
        assert_eq!(ledger.state.finishes[0].accepted, Some(true));
        until("turn end", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Finished }))).await;
        let kids = e.children(&id);
        assert_eq!(kids.len(), 1);
        assert_eq!(kids[0].meta.role, "verifier");
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn score_counts_each_session_of_a_mission_and_adds_the_others_to_the_leads() {
        let e = env_with(
            Script::new(
                |body, _| if has_tool(body, "verdict") { verifier_turn(body, true) } else { finish("lead done") },
            ),
            false,
            |c| c.agents.verify_finish = true,
        )
        .await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let id = info.meta.id.clone();
        until("turn end", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Finished }))).await;
        let view = e.rt.score(&info.meta.mission).await.unwrap();
        assert_eq!(view.mission, info.meta.mission);
        // The lead first, then the verifier its finish gate started.
        let who: Vec<(&str, Option<&SessionId>)> =
            view.sessions.iter().map(|s| (s.role.as_str(), s.parent.as_ref())).collect();
        assert_eq!(who, vec![("lead", None), ("verifier", Some(&id))]);
        assert_eq!(view.sessions[0].session, id);
        let lead = &view.sessions[0].card;
        assert_eq!((lead.steps, lead.steps_to_finish, lead.calls, lead.malformed_calls), (1, Some(1), 1, 0));
        assert_eq!((lead.finish_calls, lead.finish_refusals, lead.verifier_accepts, lead.unrecorded), (1, 0, 1, false));
        // The verifier looked, then gave its verdict: two steps of the mission's, no finish of its own.
        let verifier = &view.sessions[1].card;
        assert_eq!((verifier.steps, verifier.calls, verifier.finished, verifier.finish_calls), (2, 2, false, 0));
        // The total is the lead's result at everyone's cost.
        let mut total = lead.clone();
        total.add(verifier);
        assert_eq!(view.total, total);
        assert_eq!(
            (view.total.steps, view.total.steps_to_finish, view.total.verifier_accept_rate()),
            (3, Some(1), Some(1.0))
        );
        // The id comes from a URL: one that no session belongs to reaches no path.
        let err = e.rt.score(&MissionId::from("../../etc")).await.unwrap_err();
        assert_eq!(err, "There is no mission ../../etc.");
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn rejected_finish_with_real_children_starts_the_lead_afresh_on_what_the_check_found() {
        let e = env_with(
            Script::new(move |body, _| {
                if has_tool(body, "verdict") {
                    return verifier_turn(body, false);
                }
                // The lead works, gives up in a finish, and, started afresh, goes on working.
                if mentions(body, "What the check found") {
                    return Action::Stall { ms: 600_000 };
                }
                match tool_msgs(body) {
                    0 => Action::Reply(
                        Reply::tool("bash", json!({"command": "echo WORKMARK"}).to_string())
                            .with_text("PLANMARK: one look, then stop."),
                    ),
                    _ => Action::Reply(
                        Reply::tool("finish", json!({"answer": "GIVEUPMARK: no result is possible."}).to_string())
                            .with_text("DESPAIRMARK: nothing more can be done here.")
                            .with_reasoning("REASONMARK: every route is exhausted."),
                    ),
                }
            }),
            false,
            |c| c.agents.verify_finish = true,
        )
        .await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let id = info.meta.id.clone();
        let afresh = |b: &Value| has_tool(b, "finish") && mentions(b, "What the check found");
        until("the lead was started afresh", || e.server.requests().iter().any(afresh)).await;
        let request = e.server.requests().into_iter().find(afresh).unwrap();
        // What the check found is there, as a brief; the run the lead made is still in view.
        assert!(mentions(&request, "no test ran"), "{request}");
        assert!(mentions(&request, "treat the goal as unsolved"), "{request}");
        assert!(mentions(&request, "WORKMARK"), "{request}");
        // Nothing of the attempt is: not the call, not its result, not what the lead said or thought around it.
        for gone in ["GIVEUPMARK", "DESPAIRMARK", "PLANMARK", "REASONMARK", "did not accept it"] {
            assert!(!mentions(&request, gone), "{gone} is still in view: {request}");
        }
        assert_eq!(tool_msgs(&request), 1, "the finish call left the window with its result: {request}");
        let hud = hud_of(&request);
        assert!(hud.contains("Finish: the check raised an objection"), "{hud}");
        assert!(!hud.contains("GIVEUPMARK") && !hud.contains("reject"), "{hud}");
        // Folded, not deleted: the record of the attempt is in the log, after it the re-weave that folded it.
        assert!(e.has(
            &id,
            |ev| matches!(ev, Event::ToolResult(t) if t.name == "finish" && t.text.contains("did not accept it"))
        ));
        assert!(e.has(
            &id,
            |ev| matches!(ev, Event::ToolCall(c) if c.name == "finish" && c.args.to_string().contains("GIVEUPMARK"))
        ));
        let folds: Vec<loom_core::event::Reweave> = e
            .records(&id)
            .into_iter()
            .filter_map(|r| if let Event::Reweave(w) = r.event { Some(w) } else { None })
            .collect();
        assert_eq!(folds.len(), 1, "one rejection, one fresh start");
        assert_eq!(folds[0].reason, texts::FRESH_START_REASON);
        // The brief carries the frontier picture, as a re-weave brief does, and no count of anything refused.
        assert!(folds[0].brief.contains("ground covered"), "{}", folds[0].brief);
        assert!(folds[0].brief.contains("Where the work stands:"), "{}", folds[0].brief);
        assert!(folds[0].brief.contains("a failed attempt rules out that attempt, not the approach"));
        assert!(folds[0].evictions.iter().any(|x| x.action == loom_core::event::EvictAction::Remove));
        let ledger = e.rt.ledger(&info.meta.mission).unwrap();
        let verdicts: Vec<Option<bool>> = ledger.state.finishes.iter().map(|f| f.accepted).collect();
        assert_eq!(verdicts, vec![Some(false)]);
        assert_eq!(ledger.state.finishes[0].objections, vec!["no test ran".to_string()]);
        // The objection is an open obligation until new execution evidence is recorded after it.
        assert_eq!(ledger.state.obligations.len(), 1);
        assert_eq!(ledger.state.obligations[0].kind, loom_core::ledger::ObligationKind::Objection);
        assert!(ledger.state.obligations[0].outcome.is_none());
        assert!(e.rt.inbox().is_empty(), "a rejection never reaches the operator");
        assert_eq!(e.children(&id).len(), 1);
        e.rt.shutdown().await;
    }

    /// After a rejection with a fresh start no model-visible text about the harness's own earlier notes or
    /// about rejections is left: the nudge written before the finish is folded out with the rest.
    #[tokio::test]
    async fn a_fresh_start_leaves_no_harness_note_about_the_attempt_in_view() {
        let e = env_with(
            Script::new(move |body, _| {
                if has_tool(body, "verdict") {
                    return verifier_turn(body, false);
                }
                if mentions(body, "What the check found") {
                    return Action::Stall { ms: 600_000 };
                }
                let replies =
                    body["messages"].as_array().map_or(0, |m| m.iter().filter(|m| m["role"] == "assistant").count());
                match replies {
                    // A reply without a tool call: the harness answers with a nudge note.
                    0 => Action::Reply(Reply::text("NUDGEMARK: that is all.")),
                    1 => call("bash", json!({"command": "echo WORKMARK"})),
                    _ => finish("GIVEUPMARK: done."),
                }
            }),
            false,
            |c| c.agents.verify_finish = true,
        )
        .await;
        let _info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let afresh = |b: &Value| has_tool(b, "finish") && mentions(b, "What the check found");
        until("the lead was started afresh", || e.server.requests().iter().any(afresh)).await;
        // Before the fold the note was in view.
        let before = e.server.requests().into_iter().find(|b| mentions(b, "WORKMARK") && !afresh(b)).unwrap();
        assert!(mentions(&before, "kind=\\\"nudge\\\""), "{before}");
        let after = e.server.requests().into_iter().find(afresh).unwrap();
        assert!(mentions(&after, "WORKMARK"), "{after}");
        for gone in ["kind=\\\"nudge\\\"", "kind=\\\"verdict\\\"", "NUDGEMARK", "GIVEUPMARK", "did not accept"] {
            assert!(!mentions(&after, gone), "{gone} is still in view: {after}");
        }
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn a_fresh_start_keeps_what_was_delivered_and_leaves_the_attempt_reachable() {
        let e = env_with(
            Script::new(move |body, _| {
                if has_tool(body, "verdict") {
                    // The first result is accepted, the one after it is not.
                    return verifier_turn(body, !mentions(body, "SECONDANSWER"));
                }
                if mentions(body, "What the check found") {
                    // Started afresh, the lead looks its attempt up in the record, then works on.
                    return match tool_msgs(body) {
                        1 => call("log_search", json!({"pattern": "SECONDANSWER", "in": "calls"})),
                        _ => Action::Stall { ms: 600_000 },
                    };
                }
                if mentions(body, "MOREMARK") {
                    finish("SECONDANSWER: nothing more is possible.")
                } else {
                    finish("FIRSTANSWER: the first part is done.")
                }
            }),
            false,
            |c| c.agents.verify_finish = true,
        )
        .await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let id = info.meta.id.clone();
        until("the first result was delivered", || inbox_kinds(&e).contains(&InboxKind::Finished)).await;
        e.rt.send_message(&id, "MOREMARK: now the second part").await.unwrap();
        let afresh = |b: &Value| has_tool(b, "finish") && mentions(b, "What the check found");
        until("the lead was started afresh", || e.server.requests().iter().any(afresh)).await;
        let request = e.server.requests().into_iter().find(afresh).unwrap();
        // The delivered result and its call are not an attempt: they stay. The rejected one is gone.
        assert!(mentions(&request, "FIRSTANSWER"), "{request}");
        assert!(mentions(&request, "MOREMARK"), "{request}");
        assert!(!mentions(&request, "SECONDANSWER"), "{request}");
        assert!(!mentions(&request, "did not accept it"), "{request}");
        assert_eq!(tool_msgs(&request), 1, "{request}");
        // The record still has the attempt: a search of the session finds the call.
        until("the search answered", || {
            e.server.requests().iter().any(|b| afresh(b) && tool_msgs(b) == 2 && mentions(b, "SECONDANSWER"))
        })
        .await;
        let kinds = e.kinds(&id);
        assert_eq!(kinds.iter().filter(|k| *k == "reweave").count(), 1, "{kinds:?}");
        assert!(!kinds.iter().any(|k| k == "cache_break"), "a fresh start is a new epoch, not a break: {kinds:?}");
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn with_the_fresh_start_off_a_rejected_finish_stays_in_view_with_its_objections() {
        let e = env_with(
            Script::new(move |body, _| {
                if has_tool(body, "verdict") {
                    return verifier_turn(body, false);
                }
                // The lead finishes once, reads the rejection, and goes on working.
                if tool_msgs(body) == 0 {
                    finish("lead done")
                } else {
                    Action::Stall { ms: 600_000 }
                }
            }),
            false,
            |c| {
                c.agents.verify_finish = true;
                c.agents.fresh_start = false;
            },
        )
        .await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let id = info.meta.id.clone();
        until("the lead saw the objection", || {
            e.server
                .requests()
                .iter()
                .any(|b| has_tool(b, "finish") && mentions(b, "did not accept it") && mentions(b, "no test ran"))
        })
        .await;
        assert!(!e.has(&id, |ev| matches!(ev, Event::Reweave(_))));
        assert!(e.server.requests().iter().all(|b| !mentions(b, "What the check found")));
        let ledger = e.rt.ledger(&info.meta.mission).unwrap();
        assert_eq!(ledger.state.obligations.len(), 1);
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn finish_whose_verifier_cannot_be_started_is_held_and_never_opens_a_blocking_item() {
        let e = env_with(
            Script::new(|body, _| {
                if has_tool(body, "verdict") {
                    verifier_turn(body, true)
                } else {
                    match tool_msgs(body) {
                        0 => call("bash", json!({"command": "cd .. && rm -rf ws"})),
                        1 => finish("lead done"),
                        _ => Action::Stall { ms: 600_000 },
                    }
                }
            }),
            false,
            |c| c.agents.verify_finish = true,
        )
        .await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let id = info.meta.id.clone();
        until("the lead was told the verifier could not be run", || {
            e.server.requests().iter().any(|b| mentions(b, "could not be verified") && mentions(b, "workspace"))
        })
        .await;
        assert!(e.rt.inbox().is_empty(), "verification trouble never reaches the operator: {:?}", inbox_kinds(&e));
        assert!(!e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Blocked })));
        assert!(!e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Finished })));
        assert!(e.server.requests().iter().all(|b| !has_tool(b, "verdict")));
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn a_pack_whose_verifier_role_has_another_name_is_used_for_the_gate() {
        let e = env_with_packs(
            Script::new(|body, _| if has_tool(body, "verdict") { verifier_turn(body, true) } else { finish("lead done") }),
            |c| c.agents.verify_finish = true,
            |packs| {
                let dir = packs.join("jp");
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(
                    dir.join("pack.toml"),
                    "name = \"jp\"\ndefault_role = \"boss\"\n[roles.boss]\nprompt = \"boss.md\"\ntools = [\"bash\", \"finish\"]\nverify_finish = true\nverifier = \"judge\"\n[roles.judge]\nprompt = \"judge.md\"\ntools = [\"bash\", \"out_read\", \"verdict\"]\nread_only = true\n",
                )
                .unwrap();
                std::fs::write(dir.join("boss.md"), "Boss.").unwrap();
                std::fs::write(dir.join("judge.md"), "Judge.").unwrap();
            },
        )
        .await;
        let mut new = e.new_session(Some("go"));
        new.pack = Some("jp".into());
        let info = e.rt.create_session(new).await.unwrap();
        let id = info.meta.id.clone();
        until("finished item", || inbox_kinds(&e).contains(&InboxKind::Finished)).await;
        let kids = e.children(&id);
        assert_eq!(kids.len(), 1);
        assert_eq!(kids[0].meta.role, "judge");
        assert!(e.rt.inbox().remove(0).item.text.contains("[verified by s-"));
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn stop_ends_lead_and_settles_awaited_child() {
        let e = env(Script::new(|body, _| {
            if has_tool(body, "agent_spawn") {
                call("agent_spawn", json!({"question": "CHILDMARK"}))
            } else {
                Action::Stall { ms: 600_000 }
            }
        }))
        .await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let id = info.meta.id.clone();
        until("child request", || e.server.requests().iter().any(|b| !has_tool(b, "agent_spawn"))).await;
        e.rt.stop(&id).await.unwrap();
        until("lead stopped", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Stopped })))
            .await;
        until("child stopped", || {
            let kids = e.children(&id);
            !kids.is_empty() && kids.iter().all(|c| c.status.outcome == Some(SessionOutcome::Stopped))
        })
        .await;
        e.rt.shutdown().await;
    }

    /// A worker's script: start a background job, then wait for it.
    fn idle_worker(body: &Value) -> Action {
        if tool_msgs(body) == 0 {
            call("bash", json!({"command": "sleep 600", "background": true}))
        } else {
            call("wait", json!({}))
        }
    }

    /// Until `child` is between turns, waiting for its own background job.
    async fn until_idle(e: &Env, child: &SessionId) {
        until("the worker waits", || {
            e.has(child, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Waiting }))
        })
        .await;
        until("the worker is idle", || e.rt.session(child).is_some_and(|s| s.status.phase == Phase::Idle)).await;
    }

    /// The stop reached `child` between turns: its `interrupted` follows a `Waiting` turn end directly.
    fn stopped_while_idle(e: &Env, child: &SessionId, reason: &str) -> bool {
        let rs = e.records(child);
        let Some(at) = rs.iter().position(|r| matches!(&r.event, Event::Interrupted { reason: why } if why == reason))
        else {
            return false;
        };
        at > 0 && matches!(rs[at - 1].event, Event::TurnEnd { reason: TurnEndReason::Waiting })
    }

    #[tokio::test]
    async fn stop_child_settles_an_idle_child_before_it_returns() {
        let e = env_with(
            Script::new(|body, _| {
                if !has_tool(body, "agent_spawn") {
                    idle_worker(body)
                } else if mentions(body, "was stopped after") {
                    Action::Stall { ms: 600_000 }
                } else if tool_msgs(body) == 0 {
                    call("agent_spawn", json!({"question": "CHILDMARK", "background": true}))
                } else {
                    call("wait", json!({}))
                }
            }),
            false,
            |c| c.agents.max_children = 1,
        )
        .await;
        let id = e.rt.create_session(e.new_session(Some("go"))).await.unwrap().meta.id;
        until("the lead waits", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Waiting })))
            .await;
        let child = e.children(&id)[0].meta.id.clone();
        until_idle(&e, &child).await;
        let orch = e.rt.inner.orch.clone();
        orch.stop_child(&id, &child).await.unwrap();
        // Settled before the call returned: it is no longer listed as running, and no longer counts.
        let info = e.rt.session(&child).unwrap();
        assert_eq!((info.status.phase, info.status.outcome), (Phase::Ended, Some(SessionOutcome::Stopped)));
        assert!(stopped_while_idle(&e, &child, texts::REASON_PARENT));
        assert_eq!(orch.children(&id).await.iter().filter(|c| c.running).count(), 0);
        let again = SpawnReq {
            role: "worker".into(),
            mode: SpawnMode::Fresh,
            brief: Brief { question: "AGAIN".into(), ..Default::default() },
            budget: Budget::default(),
            call_id: CallId::from("c9"),
            title: "again".into(),
            awaited: false,
            harness: false,
            prerequisite: None,
            workspace: Workspace::Shared,
        };
        orch.spawn(&id, again).await.expect("a stopped agent does not count toward max_children");
        let settled = |c: &ChildSettled| c.child == child && c.outcome == ChildOutcome::Stopped && !c.inline;
        until("the lead got the settlement", || e.has(&id, |ev| matches!(ev, Event::ChildSettled(c) if settled(c))))
            .await;
        e.rt.shutdown().await;
    }

    /// The agent a background `agent_spawn` result in the request names.
    fn started_agent(body: &Value) -> String {
        let text = body.to_string();
        let at = text.find("Agent s-").map_or(0, |i| i + "Agent ".len());
        text[at..].chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '-').collect()
    }

    #[tokio::test]
    async fn agent_stop_settles_an_idle_worker_says_so_and_finish_is_not_refused_for_it() {
        let e = env(Script::new(|body, _| {
            if !has_tool(body, "agent_spawn") {
                return idle_worker(body);
            }
            if mentions(body, "STOPMARK") {
                // One reply: finish runs as soon as agent_stop has returned.
                let stop = json!({"agent": started_agent(body)}).to_string();
                let done = json!({"answer": "lead done"}).to_string();
                return Action::Reply(Reply::tools([("agent_stop", stop), ("finish", done)]));
            }
            if tool_msgs(body) == 0 {
                call("agent_spawn", json!({"question": "CHILDMARK", "background": true}))
            } else {
                call("wait", json!({}))
            }
        }))
        .await;
        let id = e.rt.create_session(e.new_session(Some("go"))).await.unwrap().meta.id;
        until("the lead waits", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Waiting })))
            .await;
        let child = e.children(&id)[0].meta.id.clone();
        until_idle(&e, &child).await;
        e.rt.send_message(&id, "STOPMARK").await.unwrap();
        let turn_ends = || e.records(&id).iter().filter(|r| matches!(r.event, Event::TurnEnd { .. })).count();
        until("the lead's turn ended", || turn_ends() >= 2).await;
        assert!(stopped_while_idle(&e, &child, texts::REASON_PARENT), "{:?}", e.kinds(&child));
        assert_eq!(e.rt.session(&child).unwrap().status.outcome, Some(SessionOutcome::Stopped));
        let result = |name: &str| {
            e.records(&id).into_iter().find_map(|r| match r.event {
                Event::ToolResult(t) if t.name == name => Some(t),
                _ => None,
            })
        };
        let stopped = result("agent_stop").unwrap();
        assert!(
            stopped.text.contains(&format!("{child} was stopped; anything it had not delivered")),
            "{}",
            stopped.text
        );
        let finished = result("finish").unwrap();
        assert_eq!(finished.status, loom_core::event::ToolStatus::Ok, "{}", finished.text);
        assert!(e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Finished })));
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn a_panicking_session_task_ends_the_session_and_settles_the_child() {
        let e = env(Script::new(|_, _| Action::Stall { ms: 600_000 })).await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let id = info.meta.id.clone();
        until("request", || !e.server.requests().is_empty()).await;
        lock(&PANIC_TITLES).push("PANICTITLE".to_string());
        let orch = e.rt.inner.orch.clone();
        let req = SpawnReq {
            role: "worker".into(),
            mode: SpawnMode::Fresh,
            brief: Default::default(),
            budget: Budget::default(),
            call_id: CallId::from("c1"),
            title: "PANICTITLE".into(),
            awaited: true,
            harness: false,
            prerequisite: None,
            workspace: Workspace::Shared,
        };
        let child = orch.spawn(&id, req).await.unwrap();
        let settlement = tokio::time::timeout(WAIT, orch.join(&id, &child, &CancellationToken::new()))
            .await
            .expect("the join must not hang")
            .unwrap();
        assert_eq!(settlement.outcome, ChildOutcome::Failed);
        assert!(settlement.report.contains("internal error"), "{}", settlement.report);
        // The lead reads this report: the next step it names is one the lead can take.
        assert!(settlement.report.contains("start a new agent"), "{}", settlement.report);
        assert!(!settlement.report.contains("send the session a message"), "{}", settlement.report);
        let info = e.rt.session(&child).unwrap();
        assert!(!info.active);
        assert_eq!((info.status.phase, info.status.outcome), (Phase::Ended, Some(SessionOutcome::Failed)));
        lock(&PANIC_TITLES).retain(|t| t != "PANICTITLE");
        // The lead never recorded the settlement (it is inside a model request). A restart does not
        // run the failed child again, and delivers what it was settled with.
        e.rt.shutdown().await;
        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        let rt = rt2.clone();
        until("the failure is delivered", || {
            rt.records(&id, None, 2_000).is_ok_and(|rs| {
                rs.iter().any(|r| {
                    matches!(&r.event, Event::ChildSettled(c)
                    if c.child == child && c.outcome == ChildOutcome::Failed && c.report.contains("internal error"))
                })
            })
        })
        .await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!rt2.session(&child).unwrap().active);
        assert!(e.server.requests().iter().all(|b| has_tool(b, "agent_spawn")), "the failed child ran again");
        rt2.shutdown().await;
    }

    #[tokio::test]
    async fn background_child_wakes_a_waiting_parent() {
        let e = env(Script::new(|body, _| {
            if has_tool(body, "agent_spawn") {
                if mentions(body, "child report") {
                    finish("lead done")
                } else if mentions(body, "is working") {
                    call("wait", json!({}))
                } else {
                    call("agent_spawn", json!({"question": "CHILDMARK", "background": true}))
                }
            } else {
                finish("child report")
            }
        }))
        .await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let id = info.meta.id.clone();
        until("lead finished", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Finished })))
            .await;
        let settled = e.records(&id).into_iter().filter(|r| matches!(r.event, Event::ChildSettled(_))).count();
        assert_eq!(settled, 1);
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn poll_sends_distinct_seeds_and_parses_votes() {
        let e = env(Script::new(|body, _| {
            if mentions(body, "OPTION:") && last_role(body) == "user" {
                Action::Reply(Reply::text("OPTION: 2\nREASON: because"))
            } else {
                finish("ok")
            }
        }))
        .await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let id = info.meta.id.clone();
        until("turn end", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { .. }))).await;
        let votes =
            e.rt.inner
                .orch
                .poll(&id, "which?", &["a".to_string(), "b".to_string()], 3, &CancellationToken::new())
                .await
                .unwrap();
        assert_eq!(votes.len(), 3);
        assert!(votes.iter().all(|v| v.option == Some(2)));
        let seeds: HashSet<u64> = e.server.requests().iter().filter_map(|b| b["seed"].as_u64()).collect();
        assert_eq!(seeds.len(), 3);
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn producer_found_live_and_after_restart() {
        let e = env(Script::new(|body, _| {
            if last_role(body) == "tool" {
                finish("ok")
            } else {
                call("bash", json!({"command": "echo produced-marker"}))
            }
        }))
        .await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let id = info.meta.id.clone();
        until("turn end", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { .. }))).await;
        let blob = e.records(&id).into_iter().find_map(|r| match r.event {
            Event::ToolResult(t) => t.output.map(|o| (o.id, t.call_id)),
            _ => None,
        });
        let (blob, call_id) = blob.expect("bash output is stored");
        let p = e.rt.inner.orch.producer(&info.meta.mission, &blob).await.unwrap();
        assert_eq!(p.session, id);
        assert_eq!(p.call_id, call_id);
        assert_eq!(p.grade, EvidenceGrade::Run);
        e.rt.shutdown().await;
        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        let p2 = rt2.inner.orch.producer(&info.meta.mission, &blob).await.unwrap();
        assert_eq!(p2.call_id, call_id);
        // The scan of the logs after a restart grades the output as the live index did.
        assert_eq!(p2.grade, p.grade);
        rt2.shutdown().await;
    }

    /// The first `out:` handle of 16 or more digits anywhere in a request.
    fn any_handle(body: &Value) -> String {
        let text = body.to_string();
        text.match_indices("out:")
            .find_map(|(at, _)| {
                let hex: String = text[at + 4..].chars().take_while(|c| c.is_ascii_hexdigit()).collect();
                (hex.len() >= 16).then(|| format!("out:{}", &hex[..16]))
            })
            .unwrap_or_default()
    }

    /// The text of every `out_read` result of a session, in order.
    fn out_read_texts(e: &Env, id: &SessionId) -> Vec<String> {
        e.records(id)
            .into_iter()
            .filter_map(|r| match r.event {
                Event::ToolResult(t) if t.name == "out_read" => Some(t.text),
                _ => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn out_read_opens_the_outputs_of_its_own_mission_and_nothing_of_another() {
        let foreign = Arc::new(Mutex::new(String::new()));
        let f = foreign.clone();
        let e = env(Script::new(move |body, _| {
            if mentions(body, "SECONDMISSION") {
                if tool_msgs(body) == 0 {
                    call("bash", json!({"command": "echo FOREIGNMARK"}))
                } else {
                    finish("second done")
                }
            } else if has_tool(body, "agent_spawn") {
                match tool_msgs(body) {
                    0 => call("bash", json!({"command": "echo OWNMARK"})),
                    1 => call("out_read", json!({"handle": handle_in_tool_msg(body, 0)})),
                    2 => call("out_read", json!({"handle": lock(&f).clone()})),
                    3 => call(
                        "agent_spawn",
                        json!({"question": format!("Read {} and say what it holds.", handle_in_tool_msg(body, 0))}),
                    ),
                    _ => finish("lead done"),
                }
            } else if tool_msgs(body) == 0 {
                call("out_read", json!({"handle": any_handle(body)}))
            } else {
                finish("child done")
            }
        }))
        .await;
        // Another mission's lead produces an output; its handle reaches this session in a message.
        let second = e.rt.create_session(e.new_session(Some("SECONDMISSION: print a marker"))).await.unwrap();
        let sid = second.meta.id.clone();
        until("the second mission's turn ends", || e.has(&sid, |ev| matches!(ev, Event::TurnEnd { .. }))).await;
        let other = e
            .records(&sid)
            .into_iter()
            .find_map(|r| match r.event {
                Event::ToolResult(t) => t.output,
                _ => None,
            })
            .expect("the second mission stored an output");
        *lock(&foreign) = other.handle();
        let info = e.rt.create_session(e.new_session(Some(&format!("Look at {} too.", other.handle())))).await.unwrap();
        let id = info.meta.id.clone();
        until("the lead's turn ends", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { .. }))).await;
        let lead = out_read_texts(&e, &id);
        assert_eq!(lead.len(), 2, "{lead:?}");
        assert!(lead[0].contains("1\tOWNMARK"), "{}", lead[0]);
        let want = loom_tools::outputs::Unopened::Unknown.sentence(&other.handle());
        assert!(lead[1].contains(&want), "{}", lead[1]);
        assert!(!lead[1].contains("FOREIGNMARK") && !lead[1].contains("lines"), "{}", lead[1]);
        // A fresh child reads its lead's output.
        let kid = e.children(&id).first().map(|c| c.meta.id.clone()).expect("a child");
        let child = out_read_texts(&e, &kid);
        assert_eq!(child.len(), 1, "{child:?}");
        assert!(child[0].contains("1\tOWNMARK"), "{}", child[0]);
        // After a restart over the same home the first mission still cannot open it, and the second still can.
        let (m1, m2) = (info.meta.mission.clone(), second.meta.mission.clone());
        assert_ne!(m1, m2);
        let own = out_read_texts(&e, &id);
        assert!(own.len() == 2);
        e.rt.shutdown().await;
        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        let scope = |m: &MissionId| MissionOutputs { runtime: Arc::downgrade(&rt2.inner), mission: m.clone() };
        assert!(!scope(&m1).holds(&other.id).await);
        assert!(scope(&m2).holds(&other.id).await);
        rt2.shutdown().await;
    }

    fn named_result(call_id: &str, name: &str, output: Option<&BlobRef>, meta: Value) -> Event {
        Event::ToolResult(loom_core::event::ToolResult {
            call_id: call_id.into(),
            name: name.into(),
            status: ToolStatus::Ok,
            text: "x".into(),
            output: output.cloned(),
            cut: false,
            class: ToolClass::Exec,
            meta: meta.as_object().cloned().unwrap_or_default(),
            duration_ms: 1,
        })
    }

    #[tokio::test]
    async fn the_outputs_a_mission_names_are_its_own_live_and_after_a_restart() {
        use loom_core::event::{ChildCompleted, META_ALSO_STORED, META_RAW_BLOB};
        let e = env(Script::new(|_, _| finish("ok"))).await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let (id, mission) = (info.meta.id.clone(), info.meta.mission.clone());
        until("turn end", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { .. }))).await;
        let put = |text: &str| e.rt.blobs().put_bytes(text.as_bytes()).unwrap();
        let (raw, also, text_of, job, full, report) =
            (put("raw\n"), put("also\n"), put("of\n"), put("job\n"), put("full\n"), put("report\n"));
        let (foreign, viewed, never) = (put("foreign\n"), put("viewed\n"), put("never named\n"));
        let events = vec![
            named_result(
                "n1",
                "web_fetch",
                None,
                json!({ META_RAW_BLOB: raw.id.as_str(), META_ALSO_STORED: [also.id.as_str()], "of_blob": text_of.id.as_str() }),
            ),
            Event::JobSettled {
                job_id: "j1".into(),
                exit_code: Some(0),
                output: Some(job.clone()),
                detail: "d".into(),
            },
            Event::ChildSettled(loom_core::event::ChildSettled {
                child: SessionId::from("s-kid"),
                outcome: ChildOutcome::Returned,
                report: "r".into(),
                full: Some(full.clone()),
                usage: Default::default(),
                steps: 1,
                inline: false,
            }),
            Event::ChildCompleted(ChildCompleted {
                child: SessionId::from("s-kid"),
                role: "worker".into(),
                outcome: ChildOutcome::Returned,
                report: "r".into(),
                full: Some(report.clone()),
                payload: Value::Null,
                steps: 1,
                usage: Default::default(),
            }),
            // Views of outputs, whoever's: they name nothing.
            named_result(
                "v1",
                "out_read",
                None,
                json!({ "of_blob": viewed.id.as_str(), META_RAW_BLOB: foreign.id.as_str() }),
            ),
            named_result("v2", "out_grep", None, json!({ "of_blob": foreign.id.as_str() })),
        ];
        let named = [&raw, &also, &text_of, &job, &full, &report];
        let unnamed = [&foreign, &viewed, &never];
        let scope = |rt: &Runtime| MissionOutputs { runtime: Arc::downgrade(&rt.inner), mission: mission.clone() };
        let check = |rt: &Runtime, what: &'static str| {
            let scope = scope(rt);
            let (named, unnamed) = (named.map(|b| b.id.clone()), unnamed.map(|b| b.id.clone()));
            async move {
                for b in &named {
                    assert!(scope.holds(b).await, "{what}: {b}");
                }
                for b in &unnamed {
                    assert!(!scope.holds(b).await, "{what}: {b}");
                }
            }
        };
        // Live: the sink's records are enough, with no scan of the mission's logs.
        for (n, event) in events.iter().enumerate() {
            let record = Record {
                seq: 1_000 + n as u64,
                ts_ms: 1,
                author: Author::Tool,
                prev: String::new(),
                event: event.clone(),
            };
            e.rt.inner.on_record(&id, &record);
        }
        assert!(e.rt.inner.holds_output(&(mission.clone(), raw.id.clone())));
        assert!(!e.rt.inner.holds_output(&(mission.clone(), foreign.id.clone())));
        // Another mission's session does not make them its own.
        assert!(!e.rt.inner.holds_output(&(MissionId::from("m-other"), raw.id.clone())));
        check(&e.rt, "live").await;
        e.rt.shutdown().await;
        // After a restart: the same records, read from the session's log by the one scan.
        let paths = Paths::at(e.dir.path().join("home"));
        {
            let (mut log, _) = SessionLog::open(&paths.session_log(&id), Durability::Always).unwrap();
            for event in &events {
                log.append(Author::Tool, event.clone()).unwrap();
            }
        }
        let rt2 = Runtime::start(e.config.clone(), paths).await.unwrap();
        assert!(!rt2.inner.st().scanned.contains(&mission));
        check(&rt2, "after a restart").await;
        assert!(rt2.inner.st().scanned.contains(&mission));
        // A runtime that is gone holds nothing.
        let gone = MissionOutputs { runtime: Weak::new(), mission: mission.clone() };
        assert!(!gone.holds(&raw.id).await);
        rt2.shutdown().await;
    }

    #[tokio::test]
    async fn ready_scans_the_mission_whatever_handle_is_asked_for_next() {
        let e = env(Script::new(|_, _| finish("ok"))).await;
        let mission = e.rt.create_session(e.new_session(None)).await.unwrap().meta.mission;
        e.rt.shutdown().await;
        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        assert!(!rt2.inner.st().scanned.contains(&mission));
        let scope = MissionOutputs { runtime: Arc::downgrade(&rt2.inner), mission: mission.clone() };
        // A handle that names nothing: the answer must not depend on whether this mission was scanned before.
        scope.ready().await;
        assert!(rt2.inner.st().scanned.contains(&mission));
        rt2.shutdown().await;
    }

    #[tokio::test]
    async fn a_spawned_child_waits_on_its_own_watched_job_while_its_parent_blocks_in_join() {
        // Bounded, so a failed run leaves no loop behind. The job writes its line only when the test says so.
        let command = "echo scanning; i=0; while [ ! -f release ] && [ $i -lt 1200 ]; do sleep 0.1; i=$((i+1)); done; \
                       echo 'FOUND key=abc'";
        let e = env(Script::new(move |body, _| {
            if has_tool(body, "agent_spawn") {
                if last_role(body) == "tool" {
                    finish("lead done")
                } else {
                    call("agent_spawn", json!({"question": "CHILDMARK work"}))
                }
            } else {
                match tool_msgs(body) {
                    0 => call("bash", json!({"command": command, "background": true, "wake_on": "^FOUND"})),
                    1 => call("wait", json!({})),
                    _ => finish("child report"),
                }
            }
        }))
        .await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let id = info.meta.id.clone();
        until("child registered its job", || {
            e.children(&id).first().is_some_and(|c| e.has(&c.meta.id, |ev| matches!(ev, Event::JobRegistered { .. })))
        })
        .await;
        let kid = e.children(&id)[0].meta.id.clone();
        until("the child's turn waits", || e.has(&kid, |ev| matches!(ev, Event::TurnEnd { .. }))).await;
        // The parent is blocked in `join`: it has sent its spawn request and nothing more, however
        // slow the machine is, until the child settles.
        assert_eq!(e.server.requests().iter().filter(|b| has_tool(b, "agent_spawn")).count(), 1);
        assert!(!e.has(&id, |ev| matches!(ev, Event::ChildSettled(_))));
        std::fs::write(e.ws.join("release"), "").unwrap();
        until("the job matched and woke the child", || e.has(&kid, |ev| matches!(ev, Event::JobMatched { .. }))).await;
        until("the child settled", || {
            e.has(&kid, |ev| matches!(ev, Event::ChildSettled { .. } | Event::TurnEnd { .. }))
        })
        .await;
        until("the parent's turn ends", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { .. }))).await;
        let kid_kinds = e.kinds(&kid);
        assert!(kid_kinds.iter().any(|k| k == "job_matched"), "{kid_kinds:?}");
        assert!(e.has(&id, |ev| matches!(ev, Event::ChildSettled(c) if c.outcome == ChildOutcome::Returned)));
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn the_part_a_watched_job_matched_is_citable_while_the_job_runs() {
        // The job writes its line only when the test says so. Bounded, so a failed run leaves no loop.
        let command = "echo scanning; i=0; while [ ! -f release ] && [ $i -lt 1200 ]; do sleep 0.1; i=$((i+1)); done; \
                       echo 'FOUND key=abc'; sleep 120";
        let e = env(Script::new(move |body, _| {
            if tool_msgs(body) == 0 {
                call("bash", json!({"command": command, "background": true, "wake_on": "^FOUND"}))
            } else {
                Action::Reply(Reply::text("noted"))
            }
        }))
        .await;
        // The chat role ends its turns by replying; it has no `wait`.
        let mut chat = e.new_session(Some("start a job"));
        chat.role = Some("chat".into());
        let info = e.rt.create_session(chat).await.unwrap();
        let id = info.meta.id.clone();
        until("registered", || e.has(&id, |ev| matches!(ev, Event::JobRegistered { .. }))).await;
        let call_id = e
            .records(&id)
            .iter()
            .find_map(|r| match &r.event {
                Event::ToolCall(c) if c.name == "bash" => Some(c.call_id.clone()),
                _ => None,
            })
            .unwrap();
        // The mission's logs have been read for producers once: what follows is learned from the
        // records as they are written, or not at all.
        assert!(e.rt.inner.orch.producer(&info.meta.mission, &BlobId::from("00")).await.is_none());
        std::fs::write(e.ws.join("release"), "").unwrap();
        until("matched", || e.has(&id, |ev| matches!(ev, Event::JobMatched { .. }))).await;
        let part = e.records(&id).into_iter().find_map(|r| match r.event {
            Event::JobMatched { output, .. } => output,
            _ => None,
        });
        let part = part.expect("the matching part is stored");
        assert!(!e.has(&id, |ev| matches!(ev, Event::JobSettled { .. })), "the job is still running");
        let p = e.rt.inner.orch.producer(&info.meta.mission, &part.id).await.expect("the part has a producer");
        assert_eq!((p.session, p.call_id, p.tool.as_str(), p.class), (id, call_id, "bash", ToolClass::Exec));
        e.rt.shutdown().await;
    }

    /// The `out:…` handle in the header of the `n`th tool message of a request.
    fn handle_in_tool_msg(body: &Value, n: usize) -> String {
        let text = body["messages"]
            .as_array()
            .and_then(|m| m.iter().filter(|m| m["role"] == "tool").nth(n))
            .and_then(|m| m["content"].as_str())
            .unwrap_or("");
        let at = text.find("out:").unwrap_or(0);
        text[at..]
            .chars()
            .take_while(|c| *c == 'o' || *c == 'u' || *c == 't' || *c == ':' || c.is_ascii_hexdigit())
            .collect()
    }

    #[tokio::test]
    async fn a_file_read_can_be_cited_by_the_handle_in_its_header() {
        let path = Arc::new(Mutex::new(String::new()));
        let p = path.clone();
        let e = env(Script::new(move |body, _| match tool_msgs(body) {
            0 => call("read", json!({"path": lock(&p).clone()})),
            1 => call("claim", json!({"text": "the file says hello"})),
            2 => call(
                "evidence",
                json!({"claim": "c1", "handle": handle_in_tool_msg(body, 0), "start": 2, "end": 3, "note": "n",
                       "quote": "line two of the file\nline three of the file"}),
            ),
            3 => call(
                "evidence",
                json!({"claim": "c1", "handle": handle_in_tool_msg(body, 0), "start": 1, "end": 3, "note": "n",
                       "quote": "a line that is not in the file"}),
            ),
            4 => call("ledger", json!({})),
            5 => call(
                "evidence",
                json!({"claim": "c1", "handle": handle_in_tool_msg(body, 4), "start": 1, "end": 40, "note": "n",
                       "quote": "the file says hello"}),
            ),
            _ => Action::Reply(Reply::text("done")),
        }))
        .await;
        let file = e.ws.join("notes.txt");
        std::fs::write(&file, "line one of the file\nline two of the file\nline three of the file\n").unwrap();
        *lock(&path) = file.display().to_string();
        let id = e.rt.create_session(e.new_session(Some("go"))).await.unwrap().meta.id;
        let evidence = |e: &Env| -> Vec<(ToolStatus, String)> {
            e.records(&id)
                .into_iter()
                .filter_map(|r| match r.event {
                    Event::ToolResult(t) if t.name == "evidence" => Some((t.status, t.text)),
                    _ => None,
                })
                .collect()
        };
        until("three evidence calls", || evidence(&e).len() == 3).await;
        let got = evidence(&e);
        assert_eq!(got[0].0, ToolStatus::Ok, "{}", got[0].1);
        assert!(got[0].1.contains("read: read call"), "{}", got[0].1);
        assert_eq!(got[1].0, ToolStatus::Error, "{}", got[1].1);
        assert_eq!(got[2].0, ToolStatus::Error, "{}", got[2].1);
        assert!(got[2].1.contains("is the result of `ledger`"), "{}", got[2].1);
        let read_call = e.records(&id).into_iter().find_map(|r| match r.event {
            Event::ToolResult(t) if t.name == "read" => Some(t.call_id),
            _ => None,
        });
        let attributed =
            e.rt.inner.st().producers.values().any(|p| p.tool == "read" && Some(&p.call_id) == read_call.as_ref());
        assert!(attributed, "the read call is registered as a producer");
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn a_finished_jobs_complete_output_can_be_cited_as_execution_evidence() {
        let path = Arc::new(Mutex::new(String::new()));
        let p = path.clone();
        let e = env(Script::new(move |body, _| match tool_msgs(body) {
            0 => call("read", json!({"path": lock(&p).clone()})),
            1 => call("claim", json!({"text": "the job printed two lines"})),
            // This evidence call makes the runtime scan the mission's logs, so the job below is registered live.
            2 => call(
                "evidence",
                json!({"claim": "c1", "handle": handle_in_tool_msg(body, 0), "start": 1, "end": 1, "note": "n", "quote": "line one of the file"}),
            ),
            3 => call("bash", json!({"command": "printf 'alpha line one\\nbeta line two\\n'", "background": true})),
            4 => call("job_wait", json!({"job": "j1", "timeout_s": 30})),
            5 => call(
                "evidence",
                json!({"claim": "c1", "handle": handle_in_tool_msg(body, 4), "start": 1, "end": 2, "note": "n",
                       "quote": "alpha line one\nbeta line two"}),
            ),
            _ => Action::Reply(Reply::text("done")),
        }))
        .await;
        let file = e.ws.join("notes.txt");
        std::fs::write(&file, "line one of the file\nline two of the file\n").unwrap();
        *lock(&path) = file.display().to_string();
        let id = e.rt.create_session(e.new_session(Some("go"))).await.unwrap().meta.id;
        let evidence = |e: &Env| -> Vec<(ToolStatus, String)> {
            e.records(&id)
                .into_iter()
                .filter_map(|r| match r.event {
                    Event::ToolResult(t) if t.name == "evidence" => Some((t.status, t.text)),
                    _ => None,
                })
                .collect()
        };
        until("two evidence calls", || evidence(&e).len() == 2).await;
        let got = evidence(&e);
        assert_eq!(got[0].0, ToolStatus::Ok, "{}", got[0].1);
        assert_eq!(got[1].0, ToolStatus::Ok, "{}", got[1].1);
        // The blob is content-addressed: the wait that returned the whole output may be the first call to
        // store it, so the producer is that wait or the starting bash call. Either way it is a run.
        assert!(got[1].1.contains("run: "), "{}", got[1].1);
        e.rt.shutdown().await;
    }

    fn tool_result(call_id: &str, name: &str, class: ToolClass, output: Option<&str>, meta: Value) -> Event {
        Event::ToolResult(loom_core::event::ToolResult {
            call_id: CallId::from(call_id),
            name: name.into(),
            status: ToolStatus::Ok,
            text: String::new(),
            output: output.map(|id| loom_core::BlobRef { id: BlobId::from(id), bytes: 10, lines: 2 }),
            cut: false,
            class,
            meta: meta.as_object().cloned().unwrap_or_default(),
            duration_ms: 0,
        })
    }

    #[test]
    fn what_makes_a_stored_output_citable() {
        let s = SessionId::from("s-a");
        let mut jobs = HashMap::new();
        // A file read is a view of the text it stored; the view of a runtime tool's output is not.
        let read = tool_result("c1", "read", ToolClass::Read, None, json!({"of_blob": "ff01", "shown": [[1, 2]]}));
        let p = produced_by(&s, &mut jobs, &read).expect("read registers its blob");
        assert_eq!((p.0, p.1.tool.as_str(), p.1.class), (BlobId::from("ff01"), "read", ToolClass::Read));
        let view = tool_result("c2", "out_read", ToolClass::Read, None, json!({"of_blob": "ee02", "shown": [[1, 2]]}));
        assert!(produced_by(&s, &mut jobs, &view).is_none());
        let grep = tool_result("c3", "out_grep", ToolClass::Read, None, json!({"of_blob": "ee02", "shown": [[1, 2]]}));
        assert!(produced_by(&s, &mut jobs, &grep).is_none());
        // A background job's complete output belongs to the call that started it (named by `job_registered`),
        // not to a later wait, and a reused job id is credited to its latest start.
        let reg = |call: &str| Event::JobRegistered {
            job_id: "j1".into(),
            call_id: CallId::from(call),
            command: "make".into(),
        };
        assert!(produced_by(&s, &mut jobs, &reg("c0")).is_none());
        assert!(produced_by(&s, &mut jobs, &reg("c4")).is_none());
        let wait = tool_result("c5", "job_wait", ToolClass::Exec, None, json!({"job": "j1"}));
        assert!(produced_by(&s, &mut jobs, &wait).is_none());
        // A part of its output stored while it runs belongs to that call too, and the job stays known.
        let matched = Event::JobMatched {
            job_id: "j1".into(),
            pattern: "FOUND".into(),
            output: Some(loom_core::BlobRef { id: BlobId::from("cc02"), bytes: 10, lines: 2 }),
            from: 0,
            shown: vec![1],
            matches: 1,
        };
        let p = produced_by(&s, &mut jobs, &matched).expect("the matched part registers");
        assert_eq!(
            (p.0, p.1.call_id, p.1.class, p.1.tool.as_str()),
            (BlobId::from("cc02"), CallId::from("c4"), ToolClass::Exec, "bash")
        );
        assert_eq!(jobs.len(), 1, "a job that matched is still running");
        let settled = Event::JobSettled {
            job_id: "j1".into(),
            exit_code: Some(0),
            output: Some(loom_core::BlobRef { id: BlobId::from("dd03"), bytes: 10, lines: 2 }),
            detail: String::new(),
        };
        let p = produced_by(&s, &mut jobs, &settled).expect("the job output registers");
        assert_eq!(
            (p.0, p.1.call_id, p.1.class, p.1.tool.as_str()),
            (BlobId::from("dd03"), CallId::from("c4"), ToolClass::Exec, "bash")
        );
        assert!(jobs.is_empty(), "a settled job is forgotten");
        // A job nothing is known about registers nothing.
        let other = Event::JobSettled { job_id: "j9".into(), exit_code: None, output: None, detail: String::new() };
        assert!(produced_by(&s, &mut jobs, &other).is_none());
    }

    #[test]
    fn produced_by_grades_what_it_registers() {
        use loom_core::event::META_EVIDENCE_GRADE as KEY;
        let s = SessionId::from("s-a");
        let mut jobs = HashMap::new();
        let grade = |jobs: &mut HashMap<_, _>, e: &Event| produced_by(&s, jobs, e).map(|(_, p)| p.grade);
        // A result that says its output is analysis is analysis, though its tool is class Exec.
        let scan = tool_result("c1", "dep_scan", ToolClass::Exec, Some("aa01"), json!({KEY: "analysis"}));
        assert_eq!(grade(&mut jobs, &scan), Some(EvidenceGrade::Analysis));
        let lookup = tool_result("c2", "cve_lookup", ToolClass::Exec, Some("aa02"), json!({KEY: "reference"}));
        assert_eq!(grade(&mut jobs, &lookup), Some(EvidenceGrade::Reference));
        // A plain command result is a run.
        let bash = tool_result("c3", "bash", ToolClass::Exec, Some("aa03"), json!({}));
        assert_eq!(grade(&mut jobs, &bash), Some(EvidenceGrade::Run));
        // A scan or a lookup logged before the tools stated a grade is still not a run.
        let old_scan = tool_result("c7", "bin_decompile", ToolClass::Exec, Some("aa07"), json!({}));
        assert_eq!(grade(&mut jobs, &old_scan), Some(EvidenceGrade::Analysis));
        let old_lookup = tool_result("c8", "advisory_lookup", ToolClass::Read, Some("aa08"), json!({}));
        assert_eq!(grade(&mut jobs, &old_lookup), Some(EvidenceGrade::Reference));
        // The key cannot raise a read to a run.
        let lying = tool_result("c4", "fetch", ToolClass::Read, Some("aa04"), json!({KEY: "run"}));
        assert_eq!(grade(&mut jobs, &lying), Some(EvidenceGrade::Read));
        // The text a read showed is a read.
        let read = tool_result("c5", "read", ToolClass::Read, None, json!({"of_blob": "ff01", "shown": [[1, 2]]}));
        assert_eq!(grade(&mut jobs, &read), Some(EvidenceGrade::Read));
        // A background job's output is a run, complete or matched.
        let reg = Event::JobRegistered { job_id: "j1".into(), call_id: CallId::from("c6"), command: "make".into() };
        assert!(produced_by(&s, &mut jobs, &reg).is_none());
        let matched = Event::JobMatched {
            job_id: "j1".into(),
            pattern: "FOUND".into(),
            output: Some(loom_core::BlobRef { id: BlobId::from("cc02"), bytes: 10, lines: 2 }),
            from: 0,
            shown: vec![1],
            matches: 1,
        };
        assert_eq!(grade(&mut jobs, &matched), Some(EvidenceGrade::Run));
        let settled = Event::JobSettled {
            job_id: "j1".into(),
            exit_code: Some(0),
            output: Some(loom_core::BlobRef { id: BlobId::from("dd03"), bytes: 10, lines: 2 }),
            detail: String::new(),
        };
        assert_eq!(grade(&mut jobs, &settled), Some(EvidenceGrade::Run));
    }

    #[tokio::test]
    async fn finish_opens_inbox_item_and_notifies_and_answer_resolves() {
        let e = env_with(Script::new(|_, _| finish("result")), true, |_| {}).await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let id = info.meta.id.clone();
        until("inbox", || !e.rt.inbox().is_empty()).await;
        let entry = e.rt.inbox().remove(0);
        assert_eq!(entry.session, id);
        let nf = e.dir.path().join("notified.txt");
        until("notification", || std::fs::read_to_string(&nf).is_ok_and(|t| t.contains("finished"))).await;
        e.rt.answer(&entry.item.item_id, "").await.unwrap();
        until("resolved", || e.rt.inbox().is_empty()).await;
        // A message behind the dismissal starts the second turn. A turn started by the dismissal would
        // have come before it, with its own trigger and the answer as a user message.
        e.rt.send_message(&id, "and now something else").await.unwrap();
        let turn_ends = || e.records(&id).iter().filter(|r| matches!(r.event, Event::TurnEnd { .. })).count();
        until("the next turn", || turn_ends() == 2).await;
        let records = e.records(&id);
        let triggers: Vec<_> = records
            .iter()
            .filter_map(|r| match r.event {
                Event::TurnStart { trigger } => Some(trigger),
                _ => None,
            })
            .collect();
        assert_eq!(triggers, vec![loom_core::event::Trigger::User; 2]);
        let answered =
            |r: &Record| matches!(&r.event, Event::UserMessage { text } if text.starts_with("[The operator's"));
        assert!(!records.iter().any(answered));
        assert!(e.rt.answer("i-nothing", "x").await.is_err());
        e.rt.shutdown().await;
    }

    /// A notify command that appends `kind|text` lines to `file`.
    fn text_logging_notify(file: &Path) -> impl FnOnce(&mut Config) {
        let command = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!("echo \"$LOOM_KIND|$LOOM_TEXT\" >> '{}'", file.display()),
        ];
        move |c: &mut Config| c.notify.command = command
    }

    fn lines_of(file: &Path) -> Vec<String> {
        std::fs::read_to_string(file).unwrap_or_default().lines().map(str::to_string).collect()
    }

    #[test]
    fn notification_text_is_labelled_only_when_a_tool_call_opened_the_item() {
        let item = |call_id: Option<&str>| InboxItem {
            item_id: "i-1".into(),
            kind: InboxKind::Question,
            text: "which one?".into(),
            options: Vec::new(),
            blocking: true,
            call_id: call_id.map(CallId::from),
            reference: None,
        };
        assert_eq!(notice_text(&item(Some("c1")), false), "[From the agent, unverified] which one?");
        assert_eq!(notice_text(&item(Some("c1")), true), "[From the agent, unverified] Still waiting: which one?");
        // Opened by the harness itself: unchanged, whatever the text says.
        assert_eq!(notice_text(&item(None), false), "which one?");
        let mut forged = item(None);
        forged.text = "[From the agent, unverified] x".into();
        assert_eq!(notice_text(&forged, false), "[From the agent, unverified] x");
    }

    #[test]
    fn the_ledger_lines_in_a_harness_opened_item_are_labelled_and_the_rest_is_not() {
        let parked = InboxItem {
            item_id: "i-1".into(),
            kind: InboxKind::Parked,
            text: "The session replied 3 times in a row without calling a tool.\n\nStill open:\nobligation o1: run the tests\n\nSend the session a message to resume it."
                .into(),
            options: Vec::new(),
            blocking: true,
            call_id: None,
            reference: None,
        };
        assert_eq!(
            notice_text(&parked, false),
            "The session replied 3 times in a row without calling a tool.\n\n[From the agent, unverified] Still open:\nobligation o1: run the tests\n\nSend the session a message to resume it."
        );
        assert!(notice_text(&parked, true).starts_with("Still waiting: The session replied"));
    }

    #[test]
    fn the_title_of_an_agent_is_labelled_and_a_lead_s_is_not() {
        assert_eq!(notice_title("Which index?", true), "unverified: Which index?");
        assert_eq!(notice_title("Fix the build", false), "Fix the build");
    }

    #[tokio::test]
    async fn the_notification_of_an_agent_s_item_labels_its_model_written_title() {
        let out = tempfile::tempdir().unwrap();
        let file = out.path().join("n.txt");
        let command = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!("echo \"$LOOM_KIND|$LOOM_TITLE\" >> '{}'", file.display()),
        ];
        let script = Script::new(|body, _| {
            if !has_tool(body, "agent_spawn") {
                return idle_worker(body);
            }
            match tool_msgs(body) {
                0 => call("agent_spawn", json!({"question": "CHILDQ", "background": true})),
                _ => call("wait", json!({})),
            }
        });
        let e = env_with(script, false, move |c| c.notify.command = command).await;
        let lead = e.rt.create_session(e.new_session(Some("go"))).await.unwrap().meta.id;
        until("the agent waits", || !e.children(&lead).is_empty()).await;
        let child = e.children(&lead)[0].clone();
        e.rt.inner.notify("error", &child.meta.id, &child.meta.title, "text");
        e.rt.inner.notify("error", &lead, "Plain lead title", "text");
        until("both notifications", || lines_of(&file).len() == 2).await;
        let lines = lines_of(&file);
        assert!(lines.iter().any(|l| l.starts_with("error|unverified: ") && l.contains("CHILDQ")), "{lines:?}");
        assert!(lines.iter().any(|l| l == "error|Plain lead title"), "{lines:?}");
        e.rt.shutdown().await;
    }

    #[test]
    fn start_warns_about_what_the_operator_must_know() {
        let mut c = Config::default();
        let keys = std::path::Path::new("/h/keys/models");
        let start_warnings = |c: &Config, macos: bool| start_warnings(c, macos, keys, |_| false, &[]);
        assert!(start_warnings(&c, true).is_empty());
        let off = start_warnings(&c, false);
        assert_eq!(off.len(), 1);
        assert!(off[0].contains("Notifications are off") && off[0].contains("[notify] command"), "{off:?}");
        c.notify.command = vec!["/bin/true".into()];
        assert!(start_warnings(&c, false).is_empty());
        c.sandbox.mode = SandboxMode::None;
        let none = start_warnings(&c, true);
        assert_eq!(none.len(), 1);
        assert!(none[0].contains("unconfined"), "{none:?}");
    }

    #[test]
    fn start_warns_about_a_key_held_in_the_environment() {
        let keys = std::path::Path::new("/h/keys/models");
        let mut c = Config::default();
        c.notify.command = vec!["/bin/true".into()];
        c.models.insert(
            "env".into(),
            loom_core::config::ModelProfile { api_key_env: Some("LOOM_TEST_KEY".into()), ..Default::default() },
        );
        c.models.insert(
            "file".into(),
            loom_core::config::ModelProfile { api_key_file: Some("file".into()), ..Default::default() },
        );
        let set = start_warnings(&c, true, keys, |v| v == "LOOM_TEST_KEY", &[]);
        assert_eq!(set.len(), 1, "{set:?}");
        assert!(set[0].contains("models.env") && set[0].contains("LOOM_TEST_KEY") && set[0].contains("can read it"));
        let unset = start_warnings(&c, true, keys, |_| false, &[]);
        assert_eq!(unset.len(), 1, "{unset:?}");
        assert!(unset[0].contains("LOOM_TEST_KEY is not set") && unset[0].contains("api_key_file"), "{unset:?}");
        assert!(set.iter().chain(&unset).all(|w| !w.contains("models.file")));
    }

    #[test]
    fn start_names_the_secret_variables_of_the_daemon_environment_without_their_values() {
        let keys = std::path::Path::new("/h/keys/models");
        let mut c = Config::default();
        c.notify.command = vec!["/bin/true".into()];
        c.models.insert(
            "m".into(),
            loom_core::config::ModelProfile { api_key_env: Some("OPENAI_API_KEY".into()), ..Default::default() },
        );
        c.sandbox.env_pass = vec!["PASSED_TOKEN".into()];
        let var = |n: &str, v: &str| (n.to_string(), v.to_string());
        let env = [
            var("GITHUB_TOKEN", "ghp_valueone"),
            var("DATABASE", "https://u:p@h/"),
            var("LOOM_HOME", "/h"),
            var("LOOM_SECRET_TOKEN", "valuethree"),
            var("OPENAI_API_KEY", "sk-valuefour"),
            var("PASSED_TOKEN", "valuefive"),
            var("PATH", "/usr/bin"),
            var("EDITOR", "vi"),
        ];
        let w = start_warnings(&c, true, keys, |_| true, &env);
        let secret: Vec<_> = w.iter().filter(|x| x.contains("look like secrets")).collect();
        assert_eq!(secret.len(), 1, "{w:?}");
        let line = secret[0];
        assert!(line.contains("GITHUB_TOKEN") && line.contains("DATABASE"), "{line}");
        for left_out in ["LOOM_HOME", "LOOM_SECRET_TOKEN", "PASSED_TOKEN", "PATH", "EDITOR"] {
            assert!(!line.contains(left_out), "{left_out}: {line}");
        }
        assert!(!line.contains("OPENAI_API_KEY"), "{line}");
        for value in ["ghp_valueone", "u:p@h", "sk-valuefour", "valuefive"] {
            assert!(w.iter().all(|x| !x.contains(value)), "{value}: {w:?}");
        }
        assert!(line.contains("loom up") && line.contains("loom service install"), "{line}");
        // Nothing left: no warning.
        let env = [var("LOOM_HOME", "/h"), var("OPENAI_API_KEY", "x"), var("PATH", "/usr/bin")];
        assert!(start_warnings(&c, true, keys, |_| false, &env).iter().all(|x| !x.contains("look like secrets")));
    }

    #[tokio::test]
    async fn a_missing_key_file_stops_start() {
        let dir = tempfile::tempdir().unwrap();
        let server = MockServer::start(Script::new(|_, _| finish("x"))).await.unwrap();
        let mut config = config_for(&server, None);
        if let Some(p) = config.models.get_mut("mock") {
            p.api_key_file = Some("mock".into());
        }
        let paths = Paths::at(dir.path().join("home"));
        plain_core_pack(&paths.packs_dir());
        let key_path = paths.model_keys_dir().join("mock");
        let err = match Runtime::start(config, paths).await {
            Ok(_) => panic!("the runtime started without its key file"),
            Err(e) => e,
        };
        assert!(err.contains("model profile 'mock'") && err.contains(&key_path.display().to_string()), "{err}");
        server.shutdown().await;
    }

    #[test]
    fn a_window_larger_than_the_server_s_is_warned_about() {
        assert!(window_warning("local", Some(1_000_000), Some(32_768))
            .is_some_and(|w| w.contains("local") && w.contains("32768")));
        assert_eq!(window_warning("local", Some(32_768), Some(32_768)), None);
        assert_eq!(window_warning("local", Some(16_000), Some(32_768)), None);
        assert_eq!(window_warning("local", Some(1_000_000), None), None);
        assert_eq!(window_warning("local", None, Some(32_768)), None);
    }

    #[tokio::test]
    async fn a_low_disk_is_notified_once_until_it_has_recovered() {
        let out = tempfile::tempdir().unwrap();
        let file = out.path().join("n.txt");
        let e = env_with(Script::new(|_, _| finish("x")), false, text_logging_notify(&file)).await;
        e.rt.inner.note_disk(false);
        e.rt.inner.note_disk(true);
        e.rt.inner.note_disk(true);
        until("the notification", || !lines_of(&file).is_empty()).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(lines_of(&file).len(), 1, "{:?}", lines_of(&file));
        assert!(lines_of(&file)[0].starts_with("disk|"));
        e.rt.inner.note_disk(false);
        e.rt.inner.note_disk(true);
        until("the second notification", || lines_of(&file).len() == 2).await;
        e.rt.shutdown().await;
    }

    #[test]
    fn emptying_a_directory_keeps_it_and_never_follows_a_link() {
        let dir = tempfile::tempdir().unwrap();
        let keep = dir.path().join("keep");
        std::fs::create_dir_all(&keep).unwrap();
        std::fs::write(keep.join("precious"), "x").unwrap();
        let tmp = dir.path().join("tmp");
        std::fs::create_dir_all(tmp.join("a/b")).unwrap();
        std::fs::write(tmp.join("a/b/f"), "x").unwrap();
        std::os::unix::fs::symlink(&keep, tmp.join("link")).unwrap();
        empty_dir(&tmp).unwrap();
        assert!(tmp.is_dir() && std::fs::read_dir(&tmp).unwrap().next().is_none());
        assert!(keep.join("precious").exists());
        empty_dir(&dir.path().join("missing")).unwrap();
        // A scratch directory that is itself a link is left alone, and so is what it points at.
        let linked = dir.path().join("linked");
        std::os::unix::fs::symlink(&keep, &linked).unwrap();
        let err = empty_dir(&linked).unwrap_err();
        assert!(err.to_string().contains("not a directory"), "{err}");
        assert!(keep.join("precious").exists() && linked.is_symlink());
    }

    #[test]
    fn the_disk_is_low_under_5_gib_or_5_percent_free() {
        const GIB: u64 = 1 << 30;
        assert!(!disk_is_low(400 * GIB, 1000 * GIB));
        assert!(!disk_is_low(5 * GIB, 40 * GIB));
        assert!(disk_is_low(5 * GIB - 1, 40 * GIB));
        assert!(disk_is_low(49 * GIB, 1000 * GIB));
        assert!(!disk_is_low(50 * GIB, 1000 * GIB));
        assert!(!disk_is_low(u64::MAX / 10, u64::MAX));
    }

    #[tokio::test]
    async fn a_question_the_model_wrote_is_notified_with_the_unverified_label() {
        let out = tempfile::tempdir().unwrap();
        let file = out.path().join("n.txt");
        let e = env_with(
            Script::new(|_, n| {
                if n == 0 {
                    call("ask_user", json!({"question": "which one?"}))
                } else {
                    Action::Stall { ms: 600_000 }
                }
            }),
            false,
            text_logging_notify(&file),
        )
        .await;
        e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        until("notification", || !lines_of(&file).is_empty()).await;
        assert_eq!(lines_of(&file)[0], "question|[From the agent, unverified] which one?");
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn an_item_the_harness_opened_is_notified_without_the_label() {
        let out = tempfile::tempdir().unwrap();
        let file = out.path().join("n.txt");
        // A lead that never ends its turn explicitly is nudged and then parked by the harness.
        let e = env_with(Script::new(|_, _| Action::Reply(Reply::text("hm"))), false, |c| {
            text_logging_notify(&file)(c);
            c.agents.max_nudges = 1;
        })
        .await;
        e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        until("notification", || !lines_of(&file).is_empty()).await;
        let lines = lines_of(&file);
        assert!(lines[0].starts_with("parked|") && !lines[0].contains("[From the agent"), "{lines:?}");
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn a_restart_notifies_a_restored_blocking_item_once_and_arms_its_repeat() {
        let out = tempfile::tempdir().unwrap();
        let file = out.path().join("n.txt");
        let e = env_with(
            Script::new(|_, n| {
                if n == 0 {
                    call("ask_user", json!({"question": "which one?"}))
                } else {
                    Action::Stall { ms: 600_000 }
                }
            }),
            false,
            |c| {
                text_logging_notify(&file)(c);
                c.notify.repeat_minutes = 60;
            },
        )
        .await;
        let id = e.rt.create_session(e.new_session(Some("go"))).await.unwrap().meta.id;
        until("live notification", || !lines_of(&file).is_empty()).await;
        until("blocked", || e.rt.inbox().iter().any(|i| i.session == id && i.item.blocking)).await;
        e.rt.shutdown().await;
        std::fs::remove_file(&file).unwrap();

        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        until("restart notification", || !lines_of(&file).is_empty()).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(lines_of(&file), ["question|[From the agent, unverified] Still waiting: which one?"]);
        // The forwarder is one task; the repeat notice of the restored item is another.
        assert!(rt2.inner.st().tasks.len() >= 2, "the repeat notice was not armed");
        rt2.shutdown().await;
    }

    #[tokio::test]
    async fn the_census_is_kept_and_a_kill_names_only_a_known_session() {
        let dir = tempfile::tempdir().unwrap();
        let server = MockServer::start(Script::new(|_, _| finish("ok"))).await.unwrap();
        let config = config_for(&server, None);
        let rt = Runtime::start(config, Paths::at(dir.path().join("home"))).await.unwrap();
        // The loop is not started under test: no view until one is asked for.
        assert!(rt.census().is_none());
        let view = rt.census_now().await.unwrap();
        assert!(view.readable && view.sessions.is_empty(), "{view:?}");
        assert_eq!(rt.census().map(|v| v.taken_ms), Some(view.taken_ms));
        assert_eq!(rt.census_kill(&SessionId::from("s-nope")).await.unwrap_err(), "There is no session s-nope.");
        rt.shutdown().await;
    }

    /// A session's job starts a process that leaves its process group and clears its environment; the census lists
    /// it under that session (through the runtime's own sandbox, members and home), a kill stops it and nothing of
    /// another session, and archiving a session stops what it left.
    #[tokio::test]
    async fn the_census_finds_what_a_session_job_left_and_a_kill_stops_only_that_session() {
        if !cfg!(target_os = "macos") || !Path::new("/usr/bin/sandbox-exec").exists() {
            return;
        }
        let orphan = |seconds: u32| {
            format!(
                "/usr/bin/env -i /usr/bin/perl -MPOSIX -e 'POSIX::setsid(); fork && exit 0; exec \"/bin/sleep\", \"{seconds}\"'"
            )
        };
        let (mine, theirs) = (orphan(73), orphan(74));
        let e = env_with(
            Script::new(move |body, _| {
                let replies =
                    body["messages"].as_array().map_or(0, |m| m.iter().filter(|m| m["role"] == "assistant").count());
                match replies {
                    0 if mentions(body, "ORPHANTWO") => call("bash", json!({ "command": theirs })),
                    0 => call("bash", json!({ "command": mine })),
                    _ => finish("ok"),
                }
            }),
            false,
            with_os_sandbox,
        )
        .await;
        std::fs::create_dir_all(e.ws.join(".loom")).unwrap();
        let first = e.rt.create_session(e.new_session(Some("go"))).await.unwrap().meta.id.clone();
        let second = e.rt.create_session(e.new_session(Some("ORPHANTWO go"))).await.unwrap().meta.id.clone();
        let sleeping = |view: &crate::census::CensusView, id: &SessionId| {
            view.sessions.get(id.as_str()).is_some_and(|p| p.iter().any(|p| p.exe.ends_with("sleep") && p.ppid == 1))
        };
        let end = tokio::time::Instant::now() + WAIT;
        let view = loop {
            let view = e.rt.census_now().await.unwrap();
            if sleeping(&view, &first) && sleeping(&view, &second) {
                break view;
            }
            assert!(tokio::time::Instant::now() < end, "the orphans were not listed: {view:?}");
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        assert!(view.identity && view.readable, "{view:?}");
        // The two sessions' processes are told apart.
        assert!(view.sessions[first.as_str()].iter().all(|p| p.exe.ends_with("sleep") || p.exe.ends_with("perl")));
        // Another session's census kill touches only that session.
        until("the first session has ended its turn", || {
            e.rt.session(&first).is_some_and(|s| s.status.phase == Phase::Idle)
        })
        .await;
        let killed = e.rt.census_kill(&first).await.unwrap();
        assert!(killed.left.is_empty() && killed.killed >= 1, "{killed:?}");
        let view = e.rt.census_now().await.unwrap();
        assert!(!sleeping(&view, &first), "{view:?}");
        assert!(sleeping(&view, &second), "another session's process was stopped: {view:?}");
        // Archiving a session takes with it what its task left (the archived session is no longer in the census).
        until("the second session has ended its turn", || {
            e.rt.session(&second).is_some_and(|s| s.status.phase == Phase::Idle)
        })
        .await;
        e.rt.archive(&second, true).await.unwrap();
        let end = tokio::time::Instant::now() + WAIT;
        loop {
            let again = crate::census::take(
                &e.rt.inner.paths.home,
                &crate::census::members(&e.rt.inner.paths, std::slice::from_ref(&second)),
                true,
            );
            if !again.sessions.contains_key(second.as_str()) {
                break;
            }
            assert!(tokio::time::Instant::now() < end, "the archived session's process survived: {again:?}");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn egress_turns_unbounded_on_a_leak_the_operator_is_told_once_and_the_view_is_kept() {
        use loom_tools::sandbox::selfprobe::{Outcome, Probe, ProbeResult, Report};
        let dir = tempfile::tempdir().unwrap();
        let server = MockServer::start(Script::new(|_, _| finish("ok"))).await.unwrap();
        let file = dir.path().join("notified");
        let mut config = config_for(&server, Some(&file));
        config.sandbox.mode = SandboxMode::Seatbelt;
        let home = dir.path().join("home");
        let rt = Runtime::start(config, Paths::at(&home)).await.unwrap();
        let report = |outcome| Report {
            ran: true,
            results: Probe::ALL.iter().map(|p| ProbeResult { probe: *p, outcome, detail: "d".into() }).collect(),
        };
        // No probe has finished (the loop is not started under test): not probed, and keep-going waits.
        assert_eq!(rt.egress().level, crate::egress::Level::Unprobed);
        rt.record_egress_probe(report(Outcome::Held));
        assert_eq!(rt.egress().level, crate::egress::Level::Bounded);
        assert!(rt.egress().probed_at_ms.is_some());
        let written = std::fs::read_to_string(home.join("egress-probe.json")).unwrap();
        let json: serde_json::Value = serde_json::from_str(&written).unwrap();
        assert_eq!(json["view"]["level"], "bounded");
        assert_eq!(json["report"]["results"].as_array().unwrap().len(), Probe::ALL.len());
        assert!(!home.join("egress-probe.json.tmp").exists());
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!file.exists(), "nothing to tell while bounded");
        // A leak: unbounded, one notification, none for the next leak, one again after it was bounded.
        rt.record_egress_probe(report(Outcome::Leaked));
        assert_eq!(rt.egress().level, crate::egress::Level::Unbounded);
        until("the notification", || file.exists() && std::fs::read_to_string(&file).unwrap().lines().count() == 1)
            .await;
        rt.record_egress_probe(report(Outcome::Failed));
        rt.record_egress_probe(report(Outcome::Held));
        assert_eq!(rt.egress().level, crate::egress::Level::Bounded);
        rt.record_egress_probe(report(Outcome::Leaked));
        until("the second notification", || std::fs::read_to_string(&file).unwrap().lines().count() == 2).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(std::fs::read_to_string(&file).unwrap().lines().count(), 2);
        assert!(std::fs::read_to_string(&file).unwrap().lines().all(|l| l.starts_with("egress")));
        rt.shutdown().await;
    }

    #[tokio::test]
    async fn a_leak_is_told_even_when_the_fetch_services_setting_already_made_egress_unbounded() {
        use loom_tools::sandbox::selfprobe::{Outcome, Probe, ProbeResult, Report};
        let dir = tempfile::tempdir().unwrap();
        let server = MockServer::start(Script::new(|_, _| finish("ok"))).await.unwrap();
        let file = dir.path().join("notified");
        let mut config = config_for(&server, Some(&file));
        config.sandbox.mode = SandboxMode::Seatbelt;
        config.sandbox.allow_fetch_services = true;
        let rt = Runtime::start(config, Paths::at(dir.path().join("home"))).await.unwrap();
        let report = |outcome| Report {
            ran: true,
            results: Probe::ALL.iter().map(|p| ProbeResult { probe: *p, outcome, detail: "d".into() }).collect(),
        };
        // The setting already holds egress unbounded, and a clean probe says nothing more.
        rt.record_egress_probe(report(Outcome::Held));
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!file.exists(), "the operator chose the setting");
        // A leak is a new cause: told once, not again for the next report of it, and again after it cleared.
        rt.record_egress_probe(report(Outcome::Leaked));
        until("the notification", || file.exists() && std::fs::read_to_string(&file).unwrap().lines().count() == 1)
            .await;
        rt.record_egress_probe(report(Outcome::Failed));
        rt.record_egress_probe(report(Outcome::Held));
        rt.record_egress_probe(report(Outcome::Leaked));
        until("the second notification", || std::fs::read_to_string(&file).unwrap().lines().count() == 2).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(std::fs::read_to_string(&file).unwrap().lines().count(), 2);
        rt.shutdown().await;
    }

    #[tokio::test]
    async fn start_leaves_the_fetch_service_setting_as_configured_in_every_network_mode() {
        let dir = tempfile::tempdir().unwrap();
        let server = MockServer::start(Script::new(|_, _| finish("ok"))).await.unwrap();
        for (i, mode) in [NetworkMode::DenyAll, NetworkMode::Allowlist, NetworkMode::Open].into_iter().enumerate() {
            for allow in [false, true] {
                let mut config = config_for(&server, None);
                config.network.mode = mode;
                config.sandbox.allow_fetch_services = allow;
                config.sandbox.daemon_port = Some(4242);
                let rt = Runtime::start(config, Paths::at(dir.path().join(format!("home-{i}-{allow}")))).await.unwrap();
                assert_eq!(rt.config().sandbox.allow_fetch_services, allow);
                assert_eq!(rt.config().sandbox.daemon_port, Some(4242));
                rt.shutdown().await;
            }
        }
    }

    #[tokio::test]
    async fn start_clears_the_leftovers_of_a_session_nobody_activates() {
        use std::os::unix::process::CommandExt;
        let e = env(Script::new(|_, _| finish("ok"))).await;
        let id = e.rt.create_session(e.new_session(Some("go"))).await.unwrap().meta.id;
        until("inbox", || !e.rt.inbox().is_empty()).await;
        // With its finished item dismissed nothing about the session asks for it to be restored.
        let item = e.rt.inbox().remove(0).item.item_id;
        e.rt.answer(&item, "").await.unwrap();
        until("resolved", || e.rt.inbox().is_empty()).await;
        // The dismissal is published at once, so the restart below does not see an open item.
        let status_file = e.rt.paths().session_dir(&id).join("status.json");
        until("status published", || {
            std::fs::read_to_string(&status_file).is_ok_and(|s| s.contains("\"open_inbox\": 0"))
        })
        .await;
        e.rt.shutdown().await;
        // The crash left a command running in its own process group, recorded as an earlier daemon's.
        let mut child = std::process::Command::new("sleep").arg("300").process_group(0).spawn().unwrap();
        let start = loom_tools::proc::process_start(child.id()).unwrap();
        let jobs = e.rt.paths().session_dir(&id).join("jobs");
        std::fs::create_dir_all(&jobs).unwrap();
        std::fs::write(jobs.join("j1.pid"), format!("{} {start}\nowner 1 1.000000\n", child.id())).unwrap();
        assert!(child.try_wait().unwrap().is_none());

        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        assert!(rt2.inner.st().known.get(&id).is_none_or(|k| k.active.is_none()), "the session must stay idle");
        let end = tokio::time::Instant::now() + WAIT;
        while child.try_wait().unwrap().is_none() {
            assert!(tokio::time::Instant::now() < end, "the previous daemon's command was not killed at start");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!jobs.join("j1.pid").exists());
        rt2.shutdown().await;
    }

    #[tokio::test]
    async fn blocking_item_refuses_an_empty_answer() {
        let e =
            env(Script::new(
                |_, n| {
                    if n == 0 {
                        call("ask_user", json!({"question": "which one?"}))
                    } else {
                        finish("fine")
                    }
                },
            ))
            .await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        until("inbox", || !e.rt.inbox().is_empty()).await;
        let item = e.rt.inbox().remove(0);
        assert!(item.item.blocking);
        let err = e.rt.answer(&item.item.item_id, "  ").await.unwrap_err();
        assert_eq!(err, "This item is waiting for an answer; write one.");
        e.rt.answer(&item.item.item_id, "the first").await.unwrap();
        let id = info.meta.id.clone();
        until("finished", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Finished }))).await;
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn restart_resumes_unattended_and_leaves_attended_idle() {
        let stall = Arc::new(AtomicBool::new(true));
        let flag = stall.clone();
        let e = env(Script::new(move |_, _| {
            if flag.load(Ordering::SeqCst) {
                Action::Stall { ms: 600_000 }
            } else {
                finish("after restart")
            }
        }))
        .await;
        let a = e.rt.create_session(e.new_session(Some("unattended one"))).await.unwrap().meta.id;
        let mut att = e.new_session(Some("attended one"));
        att.unattended = Some(false);
        let b = e.rt.create_session(att).await.unwrap().meta.id;
        until("both requests", || e.server.requests().len() >= 2).await;
        e.rt.shutdown().await;
        stall.store(false, Ordering::SeqCst);
        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        let ra = rt2.clone();
        until("unattended resumed", || {
            ra.records(&a, None, 2_000).is_ok_and(|rs| {
                rs.iter().any(|r| matches!(r.event, Event::TurnEnd { reason: TurnEndReason::Finished }))
            })
        })
        .await;
        let after = e.server.requests().into_iter().filter(|b| mentions(b, texts::AFTER_RESTART)).count();
        assert_eq!(after, 1);
        tokio::time::sleep(Duration::from_millis(400)).await;
        let rs = rt2.records(&b, None, 2_000).unwrap();
        assert!(!rs.iter().any(|r| matches!(r.event, Event::TurnEnd { reason: TurnEndReason::Finished })));
        assert!(rt2.session(&b).unwrap().active);
        rt2.shutdown().await;
    }

    /// A lead with a sealed ledger of its own that holds the goal `goal`; returns its mission.
    async fn mission_with_goal(e: &Env, title: &str, goal: &str) -> MissionId {
        let mut new = e.new_session(None);
        new.title = Some(title.into());
        let mission = e.rt.create_session(new).await.unwrap().meta.mission;
        let paths = Paths::at(e.dir.path().join("home"));
        let key = journal::load_or_create_key(&paths.journal_key()).unwrap();
        Journal::new(paths.journal(&mission), key)
            .append(&SessionId::from("s-op"), true, loom_core::ledger::LedgerOp::GoalSet { text: goal.into() }, &|_| {
                Ok(())
            })
            .unwrap();
        mission
    }

    fn recall_notes(rs: &[Record]) -> Vec<String> {
        rs.iter()
            .filter_map(|r| match &r.event {
                Event::HarnessNote { note: NoteKind::Info, text }
                    if text.starts_with("Earlier missions the operator") =>
                {
                    Some(text.clone())
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_new_session_that_names_no_earlier_mission_is_sent_without_the_key() {
        let none = serde_json::to_value(NewSession::default()).unwrap();
        assert!(none.get("prior").is_none(), "{none}");
        let some =
            serde_json::to_value(NewSession { prior: vec![MissionId::from("m-1")], ..Default::default() }).unwrap();
        assert_eq!(some["prior"], json!(["m-1"]));
        // Both forms are read back.
        assert!(serde_json::from_value::<NewSession>(none).unwrap().prior.is_empty());
        assert_eq!(serde_json::from_value::<NewSession>(some).unwrap().prior, [MissionId::from("m-1")]);
    }

    #[tokio::test]
    async fn a_mission_without_a_known_lead_has_no_title_to_show() {
        let e = env(Script::new(|_, _| finish("ok"))).await;
        let earlier = mission_with_goal(&e, "Lead title", "g").await;
        let lead = e.rt.sessions(true).into_iter().find(|s| s.meta.mission == earlier).unwrap().meta.id;
        let (named, recalled) = e.rt.recall_earlier(std::slice::from_ref(&earlier)).await.unwrap();
        assert_eq!((named, recalled[0].title.as_str()), (vec![earlier.clone()], "Lead title"));
        // Only a child of the mission is known: its title (written by the model) is not the mission's.
        {
            let mut st = e.rt.inner.st();
            let mut kid = st.known.get(&lead).unwrap().meta.clone();
            kid.id = SessionId::from("s-kid");
            kid.parent = Some(lead.clone());
            kid.title = "MODEL-WRITTEN-TITLE".into();
            st.known.remove(&lead);
            st.known.insert(kid.id.clone(), Known::new(kid, idle_status()));
        }
        let (_, recalled) = e.rt.recall_earlier(&[earlier]).await.unwrap();
        assert_eq!(recalled[0].title, "untitled");
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn a_lead_recalls_the_missions_the_operator_named_before_its_first_request() {
        let e = env(Script::new(|_, _| finish("ok"))).await;
        let earlier = mission_with_goal(&e, "Lab sweep", "Map the lab network").await;
        let mut new = e.new_session(Some("go"));
        // Blanks and repeats are dropped, the id is trimmed.
        new.prior = vec![MissionId::from(format!("  {earlier}  ")), MissionId::from(""), earlier.clone()];
        let info = e.rt.create_session(new).await.unwrap();
        let id = info.meta.id.clone();
        assert_eq!(info.meta.prior, vec![earlier.clone()]);
        until("finished", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Finished }))).await;
        let rs = e.records(&id);
        let notes = recall_notes(&rs);
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains(&format!("Mission {earlier} (Lab sweep), last recorded ")), "{}", notes[0]);
        assert!(notes[0].contains("> Map the lab network"), "{}", notes[0]);
        let kinds = e.kinds(&id);
        let note_at = rs
            .iter()
            .position(|r| matches!(&r.event, Event::HarnessNote { text, .. } if text.starts_with("Earlier missions")))
            .unwrap();
        let request_at = kinds.iter().position(|k| k == "model_request").unwrap();
        assert_eq!((kinds[0].as_str(), note_at), ("session_start", 1));
        assert!(note_at < request_at, "{kinds:?}");
        assert!(mentions(&e.server.requests()[0], "Map the lab network"));
        // meta.json keeps the missions, in the given order.
        let meta: Value = serde_json::from_slice(
            &std::fs::read(e.dir.path().join("home").join("sessions").join(id.as_str()).join("meta.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(meta["prior"], json!([earlier.as_str()]));
        // A session without any has no such key.
        let plain = e.rt.create_session(e.new_session(None)).await.unwrap().meta.id;
        let meta: Value = serde_json::from_slice(
            &std::fs::read(e.dir.path().join("home").join("sessions").join(plain.as_str()).join("meta.json")).unwrap(),
        )
        .unwrap();
        assert!(meta.get("prior").is_none());
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn an_unreadable_earlier_mission_is_recalled_as_unreadable() {
        let e = env(Script::new(|_, _| finish("ok"))).await;
        let earlier = mission_with_goal(&e, "SECRET-TITLE", "SECRET-GOAL").await;
        let journal_path = Paths::at(e.dir.path().join("home")).journal(&earlier);
        let text = std::fs::read_to_string(&journal_path).unwrap();
        std::fs::write(&journal_path, text.replace("SECRET-GOAL", "SECRET-G0AL")).unwrap();
        let mut new = e.new_session(None);
        new.prior = vec![earlier.clone()];
        let id = e.rt.create_session(new).await.unwrap().meta.id;
        let notes = recall_notes(&e.records(&id));
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains(&format!("Mission {earlier}: its ledger could not be read")), "{}", notes[0]);
        assert!(!notes[0].contains("SECRET"));
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn an_unknown_mission_and_too_many_missions_are_refused_and_leave_no_session() {
        let e = env(Script::new(|_, _| finish("ok"))).await;
        let earlier = mission_with_goal(&e, "one", "g").await;
        let before = e.rt.sessions(true).len();
        let mut new = e.new_session(Some("go"));
        new.prior = vec![earlier.clone(), MissionId::from("m-nope")];
        assert_eq!(e.rt.create_session(new).await.unwrap_err(), "There is no mission m-nope to recall.");
        let mut new = e.new_session(Some("go"));
        new.prior = (0..9).map(|i| MissionId::from(format!("m-{i}"))).collect();
        assert_eq!(
            e.rt.create_session(new).await.unwrap_err(),
            "Name at most 8 earlier missions to recall; 9 were named."
        );
        assert_eq!(e.rt.sessions(true).len(), before);
        assert!(e.server.requests().is_empty());
        // A very long list is counted, not scanned quadratically, and says how many distinct ids it named.
        let mut new = e.new_session(None);
        new.prior = (0..200_000).map(|i| MissionId::from(format!("m-{}", i % 50_000))).collect();
        assert_eq!(
            e.rt.create_session(new).await.unwrap_err(),
            "Name at most 8 earlier missions to recall; 50000 were named."
        );
        // Eight is fine, and a repeat counts once.
        let mut new = e.new_session(None);
        new.prior = vec![earlier.clone(); 12];
        assert!(e.rt.create_session(new).await.is_ok());
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn a_restart_writes_no_second_recall_note() {
        let e = env(Script::new(|_, _| finish("ok"))).await;
        let earlier = mission_with_goal(&e, "one", "the first goal").await;
        let mut new = e.new_session(Some("go"));
        new.prior = vec![earlier.clone()];
        let id = e.rt.create_session(new).await.unwrap().meta.id;
        until("finished", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Finished }))).await;
        e.rt.shutdown().await;
        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        let info = rt2.session(&id).unwrap();
        assert_eq!(info.meta.prior, vec![earlier]);
        assert!(rt2.send_message(&id, "again").await.is_ok());
        let again = rt2.clone();
        until("a second turn", || {
            again.records(&id, None, 2_000).is_ok_and(|rs| {
                rs.iter().filter(|r| matches!(r.event, Event::TurnEnd { reason: TurnEndReason::Finished })).count() == 2
            })
        })
        .await;
        assert_eq!(recall_notes(&rt2.records(&id, None, 2_000).unwrap()).len(), 1);
        rt2.shutdown().await;
    }

    /// What a crash leaves instead of a clean shutdown: the records the session wrote from the first
    /// one of `kind` on (the shutdown's) are cut off its log. The log is hash-chained line by line, so
    /// what is left is a sound log.
    fn crash_log(path: &Path, kind: &str) {
        let text = std::fs::read_to_string(path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let at = lines
            .iter()
            .position(|l| serde_json::from_str::<Value>(l).is_ok_and(|v| v["kind"] == kind))
            .unwrap_or_else(|| panic!("no {kind} record in {}", path.display()));
        let kept: String = lines[..at].iter().map(|l| format!("{l}\n")).collect();
        std::fs::write(path, kept).unwrap();
    }

    #[tokio::test]
    async fn restart_records_lost_jobs_and_wakes_the_session_that_waited_on_them() {
        let after = Arc::new(AtomicBool::new(false));
        let flag = after.clone();
        let e = env(Script::new(move |body, _| {
            if flag.load(Ordering::SeqCst) {
                finish("after the loss")
            } else if tool_msgs(body) == 0 {
                call("bash", json!({"command": "sleep 600", "background": true}))
            } else {
                call("wait", json!({}))
            }
        }))
        .await;
        let mut att = e.new_session(Some("start a job"));
        att.unattended = Some(false);
        let id = e.rt.create_session(att).await.unwrap().meta.id;
        until("waiting", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Waiting }))).await;
        e.rt.shutdown().await;
        // A crash: the job's end was never recorded, and the sweep found nothing to say how it ended.
        crash_log(&e.rt.paths().session_log(&id), "job_settled");
        std::fs::write(e.rt.paths().session_dir(&id).join("jobs/j1.status"), "").unwrap();
        after.store(true, Ordering::SeqCst);
        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        let rt = rt2.clone();
        until("woken and finished", || {
            rt.records(&id, None, 2_000).is_ok_and(|rs| {
                rs.iter().any(|r| matches!(r.event, Event::TurnEnd { reason: TurnEndReason::Finished }))
            })
        })
        .await;
        let rs = rt2.records(&id, None, 2_000).unwrap();
        let settled = rs.iter().find_map(|r| match &r.event {
            Event::JobSettled { job_id, exit_code, detail, .. } => Some((job_id.clone(), *exit_code, detail.clone())),
            _ => None,
        });
        let (job_id, exit_code, detail) = settled.expect("the lost job is settled in the log");
        assert_eq!((exit_code, detail.as_str()), (None, texts::JOB_LOST_DETAIL));
        let lost = texts::job_lost(&job_id, "sleep 600");
        assert!(rs.iter().any(|r| matches!(&r.event, Event::HarnessNote { text, .. } if *text == lost)));
        let last = e.server.requests().pop().expect("a request after the restart");
        assert!(mentions(&last, &lost));
        rt2.shutdown().await;
    }

    #[tokio::test]
    async fn a_job_given_to_the_model_but_never_registered_is_settled_from_what_it_left_and_wakes_the_session() {
        let after = Arc::new(AtomicBool::new(false));
        let flag = after.clone();
        let first = Arc::new(AtomicBool::new(true));
        let e = env(Script::new(move |_, _| {
            if flag.load(Ordering::SeqCst) {
                finish("seen it")
            } else if first.swap(false, Ordering::SeqCst) {
                // The job and the wait in one reply: the turn ends before the job's registration is recorded.
                let bash = json!({"command": "make all", "background": true}).to_string();
                Action::Reply(Reply::tools([("bash", bash), ("wait", "{}".to_string())]))
            } else {
                // The job may end at once on a fast host and wake the session before the restart: the turn then
                // yields, so that the session settles idle instead of starting the job again and again.
                Action::Reply(Reply::text("waiting"))
            }
        }))
        .await;
        let mut att = e.new_session(Some("build it"));
        att.unattended = Some(false);
        let id = e.rt.create_session(att).await.unwrap().meta.id;
        until("waiting", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Waiting }))).await;
        let call_id = e
            .records(&id)
            .iter()
            .find_map(|r| match &r.event {
                Event::ToolCall(c) if c.name == "bash" => Some(c.call_id.clone()),
                _ => None,
            })
            .unwrap();
        until("idle", || e.rt.session(&id).is_some_and(|s| s.status.phase == Phase::Idle)).await;
        e.rt.shutdown().await;
        // A crash before the registration reached the log; the job went on and finished while the harness was down.
        crash_log(&e.rt.paths().session_log(&id), "job_registered");
        let jobs = e.rt.paths().session_dir(&id).join("jobs");
        std::fs::write(jobs.join("j1.pid"), "999999 1\nowner 1 1.000000\n").unwrap();
        std::fs::write(jobs.join("j1.out"), "compiled\nall done\n").unwrap();
        std::fs::write(jobs.join("j1.status"), "0\n").unwrap();
        let before = e.server.requests().len();
        after.store(true, Ordering::SeqCst);
        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        until("a turn after the restart", || e.server.requests().len() > before).await;
        let rs = rt2.records(&id, None, 2_000).unwrap();
        let registered = rs.iter().position(|r| {
            matches!(&r.event, Event::JobRegistered { job_id, call_id: c, command }
                if job_id == "j1" && *c == call_id && command == "make all")
        });
        let settled = rs.iter().position(|r| {
            matches!(&r.event, Event::JobSettled { job_id, exit_code: Some(0), output: Some(_), detail }
                if job_id == "j1" && *detail == texts::job_ended_while_down(""))
        });
        let turn =
            rs.iter().rposition(|r| matches!(r.event, Event::TurnStart { trigger: loom_core::event::Trigger::Resume }));
        assert!(registered.is_some() && registered < settled && settled < turn, "{rs:?}");
        let last = e.server.requests().pop().unwrap();
        assert!(mentions(&last, "Background job j1 ended: exit 0") && mentions(&last, "all done"));
        assert!(mentions(&last, "It finished while the harness was down"));
        // Taken: nothing of it is left to be found again.
        assert!(["pid", "out", "status"].iter().all(|x| !jobs.join(format!("j1.{x}")).exists()));
        rt2.shutdown().await;
    }

    #[tokio::test]
    async fn a_clean_shutdown_records_the_jobs_it_kills_and_the_restart_wakes_a_session_that_yielded_while_they_ran() {
        let after = Arc::new(AtomicBool::new(false));
        let flag = after.clone();
        let e = env(Script::new(move |body, _| {
            if flag.load(Ordering::SeqCst) {
                Action::Reply(Reply::text("noted"))
            } else if tool_msgs(body) == 0 {
                call("bash", json!({"command": "sleep 600", "background": true}))
            } else {
                Action::Reply(Reply::text("it is running; I will look at it when it ends"))
            }
        }))
        .await;
        // The chat role ends its turns by replying; it has no `wait`.
        let mut chat = e.new_session(Some("start a job"));
        chat.role = Some("chat".into());
        let info = e.rt.create_session(chat).await.unwrap();
        assert!(!info.meta.unattended);
        let id = info.meta.id;
        until("yielded", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Yielded }))).await;
        until("idle", || e.rt.session(&id).is_some_and(|s| s.status.phase == Phase::Idle)).await;
        e.rt.shutdown().await;
        // The idle session recorded how the job it killed ended, and why: the next start has nothing to call lost.
        let rs = read_records(&e.rt.paths().session_log(&id)).unwrap().records;
        let killed = rs.iter().position(|r| {
            matches!(&r.event, Event::JobSettled { job_id, exit_code: None, output: Some(_), detail }
                if job_id == "j1" && detail == texts::JOB_SHUTDOWN_DETAIL)
        });
        assert!(killed.is_some(), "{rs:?}");
        let before = e.server.requests().len();
        after.store(true, Ordering::SeqCst);
        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        until("a turn after the restart", || e.server.requests().len() > before).await;
        let rs = rt2.records(&id, None, 2_000).unwrap();
        assert!(!rs
            .iter()
            .any(|r| matches!(&r.event, Event::JobSettled { detail, .. } if detail == texts::JOB_LOST_DETAIL)));
        assert_eq!(rs.iter().filter(|r| matches!(r.event, Event::JobSettled { .. })).count(), 1);
        let turn =
            rs.iter().rposition(|r| matches!(r.event, Event::TurnStart { trigger: loom_core::event::Trigger::Resume }));
        assert!(killed < turn, "settled at {killed:?}, resumed at {turn:?}");
        let last = e.server.requests().pop().unwrap();
        assert!(mentions(&last, &format!("Background job j1 ended: killed. {}", texts::JOB_SHUTDOWN_DETAIL)));
        rt2.shutdown().await;
    }

    #[tokio::test]
    async fn a_restart_wakes_a_session_told_of_a_job_end_even_when_nothing_is_left_in_its_jobs_directory() {
        let after = Arc::new(AtomicBool::new(false));
        let flag = after.clone();
        let e = env(Script::new(move |body, _| {
            if flag.load(Ordering::SeqCst) {
                Action::Reply(Reply::text("noted"))
            } else if tool_msgs(body) == 0 {
                call("bash", json!({"command": "sleep 600", "background": true}))
            } else {
                Action::Reply(Reply::text("it is running; I will look at it when it ends"))
            }
        }))
        .await;
        let mut chat = e.new_session(Some("start a job"));
        chat.role = Some("chat".into());
        let id = e.rt.create_session(chat).await.unwrap().meta.id;
        until("yielded", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Yielded }))).await;
        until("idle", || e.rt.session(&id).is_some_and(|s| s.status.phase == Phase::Idle)).await;
        e.rt.shutdown().await;
        // What an `open` that recorded how the job ended and took its files leaves when the harness goes
        // down again before the turn it owes the session: the end in the log, an empty jobs directory.
        let jobs = e.rt.paths().session_dir(&id).join("jobs");
        for entry in std::fs::read_dir(&jobs).unwrap() {
            std::fs::remove_file(entry.unwrap().path()).unwrap();
        }
        let before = e.server.requests().len();
        after.store(true, Ordering::SeqCst);
        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        until("a turn after the restart", || e.server.requests().len() > before).await;
        assert!(mentions(&e.server.requests().pop().unwrap(), "Background job j1 ended: killed"));
        rt2.shutdown().await;
    }

    #[tokio::test]
    async fn a_crash_left_record_does_not_stop_the_restart_of_a_session_that_yielded_while_its_job_ran() {
        let after = Arc::new(AtomicBool::new(false));
        let flag = after.clone();
        let e = env(Script::new(move |body, _| {
            if flag.load(Ordering::SeqCst) {
                Action::Reply(Reply::text("noted"))
            } else if tool_msgs(body) == 0 {
                call("bash", json!({"command": "sleep 600", "background": true}))
            } else {
                Action::Reply(Reply::text("it is running; I will look at it when it ends"))
            }
        }))
        .await;
        let mut chat = e.new_session(Some("start a job"));
        chat.role = Some("chat".into());
        let id = e.rt.create_session(chat).await.unwrap().meta.id;
        until("yielded", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Yielded }))).await;
        until("idle", || e.rt.session(&id).is_some_and(|s| s.status.phase == Phase::Idle)).await;
        e.rt.shutdown().await;
        // A crash, not a graceful shutdown: the job's end is not in the log, and the command's pid record
        // is left behind, owned by another daemon, with no status.
        crash_log(&e.rt.paths().session_log(&id), "job_settled");
        let jobs = e.rt.paths().session_dir(&id).join("jobs");
        std::fs::create_dir_all(&jobs).unwrap();
        std::fs::write(jobs.join("j1.pid"), "999999 1\nowner 1 1.000000\n").unwrap();
        std::fs::write(jobs.join("j1.status"), "").unwrap();
        let before = e.server.requests().len();
        after.store(true, Ordering::SeqCst);
        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        until("a turn after the restart", || e.server.requests().len() > before).await;
        let rs = rt2.records(&id, None, 2_000).unwrap();
        let lost = rs
            .iter()
            .position(|r| matches!(&r.event, Event::JobSettled { detail, .. } if detail == texts::JOB_LOST_DETAIL));
        let turn =
            rs.iter().rposition(|r| matches!(r.event, Event::TurnStart { trigger: loom_core::event::Trigger::Resume }));
        assert!(lost.is_some() && lost < turn, "lost at {lost:?}, resumed at {turn:?}");
        assert!(mentions(&e.server.requests().pop().unwrap(), &texts::job_lost("j1", "sleep 600")));
        assert!(!jobs.join("j1.pid").exists());
        rt2.shutdown().await;
    }

    #[tokio::test]
    async fn a_restart_that_cannot_run_the_session_keeps_its_job_records_so_the_next_one_wakes_it() {
        let (_dir, home, ws) = strict_home();
        let after = Arc::new(AtomicBool::new(false));
        let flag = after.clone();
        let server = MockServer::start(Script::new(move |body, _| {
            if flag.load(Ordering::SeqCst) {
                Action::Reply(Reply::text("noted"))
            } else if tool_msgs(body) == 0 {
                call("bash", json!({"command": "sleep 600", "background": true}))
            } else {
                Action::Reply(Reply::text("it is running; I will look at it when it ends"))
            }
        }))
        .await
        .unwrap();
        let (mut config, paths) = (config_for(&server, None), Paths::at(home));
        let rt = Runtime::start(config.clone(), paths.clone()).await.unwrap();
        let new = NewSession {
            workspace: ws,
            pack: Some("strict".into()),
            message: Some("start a job".into()),
            ..NewSession::default()
        };
        let id = rt.create_session(new).await.unwrap().meta.id;
        until("yielded", || {
            rt.records(&id, None, 2_000)
                .is_ok_and(|rs| rs.iter().any(|r| matches!(r.event, Event::TurnEnd { reason: TurnEndReason::Yielded })))
        })
        .await;
        until("idle", || rt.session(&id).is_some_and(|s| s.status.phase == Phase::Idle)).await;
        rt.shutdown().await;
        // A crash: see `a_crash_left_record_does_not_stop_the_restart_of_a_session_that_yielded_while_its_job_ran`.
        crash_log(&paths.session_log(&id), "job_settled");
        let jobs = paths.session_dir(&id).join("jobs");
        std::fs::create_dir_all(&jobs).unwrap();
        std::fs::write(jobs.join("j1.pid"), "999999 1\nowner 1 1.000000\n").unwrap();
        std::fs::write(jobs.join("j1.status"), "").unwrap();
        after.store(true, Ordering::SeqCst);
        // The first restart refuses to run the session (its pack needs a restricted network) ...
        config.network.mode = NetworkMode::Open;
        let rt = Runtime::start(config.clone(), paths.clone()).await.unwrap();
        assert!(!rt.session(&id).unwrap().active);
        assert!(jobs.join("j1.pid").exists(), "the records of a session that was not activated were swept");
        rt.shutdown().await;
        // ... and the next one, with the network restricted again, still wakes it for its lost job.
        let before = server.requests().len();
        config.network.mode = NetworkMode::DenyAll;
        let rt = Runtime::start(config, paths).await.unwrap();
        until("a turn after the second restart", || server.requests().len() > before).await;
        let rs = rt.records(&id, None, 2_000).unwrap();
        assert!(rs
            .iter()
            .any(|r| matches!(&r.event, Event::JobSettled { detail, .. } if detail == texts::JOB_LOST_DETAIL)));
        assert!(mentions(&server.requests().pop().unwrap(), &texts::job_lost("j1", "sleep 600")));
        rt.shutdown().await;
    }

    /// A lead and one unfinished worker, both cut by a restart, and the runtime started again. Before
    /// the restart the worker is inside a model request; the lead is inside its `agent_spawn` call
    /// (`awaited`) or, with the worker in the background, inside a model request of its own.
    /// Afterwards the worker delivers `CHILDREPORT` and the lead waits for it. Returns the second
    /// runtime, the lead, and the number of requests made before the restart.
    async fn restart_with_an_unfinished_child(awaited: bool, attended: bool) -> (Env, Runtime, SessionId, usize) {
        restart_with_an_unfinished_child_and(awaited, attended, |_, _| {}).await
    }

    /// The same, with `between` done to the home (given the lead) while the runtime is down.
    async fn restart_with_an_unfinished_child_and(
        awaited: bool,
        attended: bool,
        between: impl FnOnce(&Env, &SessionId),
    ) -> (Env, Runtime, SessionId, usize) {
        let after = Arc::new(AtomicBool::new(false));
        let flag = after.clone();
        let e = env(Script::new(move |body, _| {
            let lead = has_tool(body, "agent_spawn");
            if !flag.load(Ordering::SeqCst) {
                if lead && tool_msgs(body) == 0 {
                    call("agent_spawn", json!({"question": "CHILDMARK", "background": !awaited}))
                } else {
                    Action::Stall { ms: 600_000 }
                }
            } else if !lead {
                finish("CHILDREPORT done")
            } else if mentions(body, "CHILDREPORT") {
                finish("lead done")
            } else {
                call("wait", json!({}))
            }
        }))
        .await;
        let mut new = e.new_session(Some("go"));
        new.unattended = Some(!attended);
        let id = e.rt.create_session(new).await.unwrap().meta.id;
        let lead_requests = if awaited { 1 } else { 2 };
        until("both inside what the restart cuts", || {
            let reqs = e.server.requests();
            reqs.iter().any(|b| !has_tool(b, "agent_spawn"))
                && reqs.iter().filter(|b| has_tool(b, "agent_spawn")).count() == lead_requests
        })
        .await;
        let begun = tokio::time::Instant::now();
        e.rt.shutdown().await;
        if awaited {
            // The lead's task waits in a `join` that will not return: it is not waited out.
            assert!(begun.elapsed() < SHUTDOWN_TASK_WAIT, "shutdown took {:?}", begun.elapsed());
        }
        let before = e.server.requests().len();
        after.store(true, Ordering::SeqCst);
        between(&e, &id);
        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        (e, rt2, id, before)
    }

    /// Whenever the lead is told that its unfinished agents were resumed, they were: the worker runs
    /// again, and its report reaches the lead by itself.
    async fn the_child_was_resumed_as_the_lead_is_told(e: &Env, rt2: &Runtime, id: &SessionId, before: usize) {
        let rt = rt2.clone();
        until("the lead finished", || {
            rt.records(id, None, 2_000).is_ok_and(|rs| {
                rs.iter().any(|r| matches!(r.event, Event::TurnEnd { reason: TurnEndReason::Finished }))
            })
        })
        .await;
        let reqs = e.server.requests();
        let (lead, child): (Vec<&Value>, Vec<&Value>) = reqs[before..].iter().partition(|b| has_tool(b, "agent_spawn"));
        assert!(lead.iter().any(|b| mentions(b, texts::AFTER_RESTART)), "the lead was not told about the restart");
        assert_eq!(child.len(), 1, "the worker did not run again exactly once");
        assert!(
            !reqs.iter().any(|b| mentions(b, "Interrupted while waiting for")),
            "a resumed agent was called stopped"
        );
        let rs = rt2.records(id, None, 2_000).unwrap();
        let settled: Vec<&ChildSettled> = rs
            .iter()
            .filter_map(|r| match &r.event {
                Event::ChildSettled(c) => Some(c),
                _ => None,
            })
            .collect();
        assert_eq!(settled.len(), 1);
        assert_eq!((settled[0].outcome, settled[0].inline), (ChildOutcome::Returned, false));
        assert!(settled[0].report.contains("CHILDREPORT"), "{}", settled[0].report);
        assert_eq!(rt2.sessions(true).iter().filter(|s| s.meta.parent.as_ref() == Some(id)).count(), 1);
    }

    #[tokio::test]
    async fn restart_resumes_the_unfinished_child_of_an_unattended_lead() {
        let (e, rt2, id, before) = restart_with_an_unfinished_child(false, false).await;
        the_child_was_resumed_as_the_lead_is_told(&e, &rt2, &id, before).await;
        rt2.shutdown().await;
    }

    #[tokio::test]
    async fn a_message_to_an_attended_lead_after_a_restart_resumes_its_unfinished_child() {
        let (e, rt2, id, before) = restart_with_an_unfinished_child(false, true).await;
        // Attended: nothing runs until the operator says so.
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(e.server.requests().len(), before);
        rt2.send_message(&id, "carry on").await.unwrap();
        the_child_was_resumed_as_the_lead_is_told(&e, &rt2, &id, before).await;
        rt2.shutdown().await;
    }

    #[tokio::test]
    async fn operator_actions_in_quick_succession_send_a_cut_child_one_resume() {
        let (e, rt2, id, before) = restart_with_an_unfinished_child(false, true).await;
        let child = rt2.sessions(true).into_iter().find(|s| s.meta.parent.as_ref() == Some(&id)).unwrap().meta.id;
        // Before the worker has published that it runs its resumed turn.
        rt2.send_message(&id, "carry on").await.unwrap();
        rt2.resume(&id).await.unwrap();
        rt2.send_message(&id, "and on").await.unwrap();
        the_child_was_resumed_as_the_lead_is_told(&e, &rt2, &id, before).await;
        assert_eq!(lock(&RESUMES).iter().filter(|c| **c == child).count(), 1);
        rt2.shutdown().await;
    }

    /// Move the workspace away while the runtime is down: the mission's sessions cannot be opened.
    fn without_the_workspace(e: &Env, _: &SessionId) {
        std::fs::rename(&e.ws, e.dir.path().join("ws-away")).unwrap();
    }

    #[tokio::test]
    async fn a_lead_that_could_not_be_opened_at_start_takes_its_cut_child_along_when_the_operator_writes() {
        let (e, rt2, id, before) = restart_with_an_unfinished_child_and(false, true, without_the_workspace).await;
        assert!(rt2.sessions(true).iter().all(|s| !s.active && s.status.phase != Phase::Ended));
        std::fs::rename(e.dir.path().join("ws-away"), &e.ws).unwrap();
        rt2.send_message(&id, "carry on").await.unwrap();
        the_child_was_resumed_as_the_lead_is_told(&e, &rt2, &id, before).await;
        rt2.shutdown().await;
    }

    #[tokio::test]
    async fn unarchiving_an_unattended_mission_resumes_the_agent_a_restart_cut() {
        let (e, rt2, id, before) = restart_with_an_unfinished_child_and(false, false, without_the_workspace).await;
        rt2.archive(&id, true).await.unwrap();
        std::fs::rename(e.dir.path().join("ws-away"), &e.ws).unwrap();
        rt2.archive(&id, false).await.unwrap();
        // As the start would have: the worker goes on by itself, and its report reaches the lead.
        let rt = rt2.clone();
        until("the report reached the lead", || {
            rt.records(&id, None, 2_000).is_ok_and(|rs| {
                rs.iter().any(|r| matches!(&r.event, Event::ChildSettled(c) if c.report.contains("CHILDREPORT")))
            })
        })
        .await;
        assert_eq!(e.server.requests()[before..].iter().filter(|b| !has_tool(b, "agent_spawn")).count(), 1);
        rt2.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_inside_an_awaited_agent_spawn_records_no_result_and_the_child_is_resumed() {
        let (e, rt2, id, before) = restart_with_an_unfinished_child(true, false).await;
        the_child_was_resumed_as_the_lead_is_told(&e, &rt2, &id, before).await;
        // The call the shutdown cut has no result: the weave shows it as interrupted.
        let rs = rt2.records(&id, None, 2_000).unwrap();
        assert!(!rs.iter().any(|r| matches!(&r.event, Event::ToolResult(t) if t.name == "agent_spawn")));
        let first = e.server.requests()[before..].iter().find(|b| has_tool(b, "agent_spawn")).cloned().unwrap();
        assert!(mentions(&first, "no result recorded"), "{first}");
        // What the call queued was written before it parked: the restart knew the agent it started.
        assert!(rs.iter().any(|r| matches!(&r.event, Event::ChildSpawned(c) if c.call_id.is_some())));
        rt2.shutdown().await;
    }

    #[tokio::test]
    async fn an_awaited_agent_whose_call_has_a_result_but_that_a_shutdown_cut_still_reports() {
        // What a shutdown inside agent_fanout's spawn loop leaves: the call's result says that no agent
        // was left running, but the agent it had started was cut, not stopped, and goes on.
        let answer = |e: &Env, id: &SessionId| {
            let path = e.rt.paths().session_log(id);
            let records = read_records(&path).unwrap().records;
            let call_id = records.into_iter().find_map(|r| match r.event {
                Event::ChildSpawned(c) => c.call_id,
                _ => None,
            });
            let (mut log, _) = SessionLog::open(&path, Durability::Always).unwrap();
            let result = loom_core::event::ToolResult {
                call_id: call_id.unwrap(),
                name: "agent_spawn".into(),
                status: loom_core::event::ToolStatus::Error,
                text: format!("{SHUTTING} No agent was left running."),
                output: None,
                cut: false,
                class: loom_core::event::ToolClass::State,
                meta: Default::default(),
                duration_ms: 0,
            };
            log.append(Author::Tool, Event::ToolResult(result)).unwrap();
        };
        let (e, rt2, id, before) = restart_with_an_unfinished_child_and(true, false, answer).await;
        the_child_was_resumed_as_the_lead_is_told(&e, &rt2, &id, before).await;
        rt2.shutdown().await;
    }

    #[tokio::test]
    async fn a_report_a_cut_agent_fanout_had_taken_reaches_the_lead_once_after_the_restart() {
        let after = Arc::new(AtomicBool::new(false));
        let flag = after.clone();
        let e = env(Script::new(move |body, _| {
            let go = flag.load(Ordering::SeqCst);
            if has_tool(body, "agent_spawn") {
                if go && mentions(body, "BREPORT") {
                    finish("lead done")
                } else if go {
                    call("wait", json!({}))
                } else if tool_msgs(body) == 0 {
                    call("agent_fanout", json!({"agents": [{"question": "AMARK"}, {"question": "BMARK"}]}))
                } else {
                    Action::Stall { ms: 600_000 }
                }
            } else if mentions(body, "AMARK") {
                finish("AREPORT")
            } else if go {
                finish("BREPORT")
            } else {
                Action::Stall { ms: 600_000 }
            }
        }))
        .await;
        let id = e.rt.create_session(e.new_session(Some("go"))).await.unwrap().meta.id;
        until("both agents started", || e.children(&id).len() == 2).await;
        let a = e.children(&id).into_iter().find(|c| c.meta.title == "AMARK").unwrap().meta.id;
        until("A ended", || e.rt.session(&a).is_some_and(|s| s.status.phase == Phase::Ended)).await;
        let b_asked = || e.server.requests().iter().any(|b| mentions(b, "BMARK") && !has_tool(b, "agent_spawn"));
        until("B is inside a request", b_asked).await;
        // The fanout's join takes A's report before the shutdown cuts the call.
        tokio::time::sleep(Duration::from_millis(300)).await;
        e.rt.shutdown().await;
        let before = e.server.requests().len();
        after.store(true, Ordering::SeqCst);
        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        let rt = rt2.clone();
        until("the lead finished", || {
            rt.records(&id, None, 2_000).is_ok_and(|rs| {
                rs.iter().any(|r| matches!(r.event, Event::TurnEnd { reason: TurnEndReason::Finished }))
            })
        })
        .await;
        let reqs = e.server.requests();
        let lead: Vec<&Value> = reqs[before..].iter().filter(|b| has_tool(b, "agent_spawn")).collect();
        assert!(!lead.is_empty());
        for body in &lead {
            assert_eq!(body.to_string().matches("AREPORT").count(), 1, "{body}");
        }
        let of_a: Vec<ChildSettled> = rt2
            .records(&id, None, 2_000)
            .unwrap()
            .into_iter()
            .filter_map(|r| match r.event {
                Event::ChildSettled(c) if c.child == a => Some(c),
                _ => None,
            })
            .collect();
        assert_eq!(of_a.len(), 1);
        assert!(!of_a[0].inline);
        rt2.shutdown().await;
    }

    #[tokio::test]
    async fn a_finish_made_again_after_a_restart_cut_its_verification_uses_the_same_verifier() {
        let after = Arc::new(AtomicBool::new(false));
        let flag = after.clone();
        let e = env_with(
            Script::new(move |body, _| {
                if !has_tool(body, "verdict") {
                    finish("lead done")
                } else if flag.load(Ordering::SeqCst) {
                    verifier_turn(body, true)
                } else {
                    Action::Stall { ms: 600_000 }
                }
            }),
            false,
            |c| c.agents.verify_finish = true,
        )
        .await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let id = info.meta.id.clone();
        until("the verifier's request", || e.server.requests().iter().any(|b| has_tool(b, "verdict"))).await;
        e.rt.shutdown().await;
        after.store(true, Ordering::SeqCst);
        // The lead is resumed (unattended), calls finish again, and that finish takes the first verifier.
        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        let rt = rt2.clone();
        until("delivered", || rt.inbox().iter().any(|i| i.item.kind == InboxKind::Finished)).await;
        let kids: Vec<SessionInfo> =
            rt2.sessions(true).into_iter().filter(|s| s.meta.parent.as_ref() == Some(&id)).collect();
        assert_eq!(kids.len(), 1, "a second verifier was started");
        let verifier = kids[0].meta.id.clone();
        let item = rt2.inbox().into_iter().find(|i| i.item.kind == InboxKind::Finished).unwrap().item;
        assert!(item.text.contains(&format!("[verified by {verifier}]")), "{}", item.text);
        let finishes = rt2.ledger(&info.meta.mission).unwrap().state.finishes;
        assert_eq!(finishes.iter().map(|f| f.accepted).collect::<Vec<_>>(), vec![None, Some(true)]);
        // Its verdict went to the finish only, not to the lead as an agent's report.
        let settled: Vec<ChildSettled> = rt2
            .records(&id, None, 2_000)
            .unwrap()
            .into_iter()
            .filter_map(|r| match r.event {
                Event::ChildSettled(c) => Some(c),
                _ => None,
            })
            .collect();
        assert_eq!(settled.len(), 1);
        assert_eq!((&settled[0].child, settled[0].inline), (&verifier, true));
        rt2.shutdown().await;
    }

    #[tokio::test]
    async fn a_verifier_whose_spawn_record_a_crash_lost_is_still_the_finish_gates() {
        let after = Arc::new(AtomicBool::new(false));
        let flag = after.clone();
        let e = env_with(
            Script::new(move |body, _| {
                if !has_tool(body, "verdict") {
                    finish("lead done")
                } else if flag.load(Ordering::SeqCst) {
                    verifier_turn(body, true)
                } else {
                    Action::Stall { ms: 600_000 }
                }
            }),
            false,
            |c| c.agents.verify_finish = true,
        )
        .await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let id = info.meta.id.clone();
        until("the verifier's request", || e.server.requests().iter().any(|b| has_tool(b, "verdict"))).await;
        let first = e.children(&id)[0].meta.id.clone();
        assert!(e.rt.inner.st().known.get(&first).is_some_and(|k| k.gate.is_some()));
        e.rt.shutdown().await;
        // A crash: the `child_spawned` that the finish call queued never reached the lead's log.
        let log = e.rt.paths().session_log(&id);
        crash_log(&log, "child_spawned");
        let rs = read_records(&log).unwrap().records;
        assert!(rs.iter().any(|r| matches!(&r.event, Event::ToolCall(c) if c.name == "finish")));
        assert!(!rs.iter().any(|r| matches!(r.event, Event::ChildSpawned(_))));
        after.store(true, Ordering::SeqCst);
        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        // Known as the gate's from its own meta.json: not an agent of the lead, nor running work of it.
        assert!(rt2.inner.st().known.get(&first).is_some_and(|k| k.gate.is_some()));
        assert!(rt2.inner.orch.children(&id).await.is_empty());
        let rt = rt2.clone();
        // The lead (unattended) calls finish again; it is not refused, and it takes the first verifier.
        until("delivered", || rt.inbox().iter().any(|i| i.item.kind == InboxKind::Finished)).await;
        let kids: Vec<SessionInfo> =
            rt2.sessions(true).into_iter().filter(|s| s.meta.parent.as_ref() == Some(&id)).collect();
        assert_eq!(kids.len(), 1, "a second verifier was started");
        let item = rt2.inbox().into_iter().find(|i| i.item.kind == InboxKind::Finished).unwrap().item;
        assert!(item.text.contains(&format!("[verified by {first}]")), "{}", item.text);
        let finishes = rt2.ledger(&info.meta.mission).unwrap().state.finishes;
        assert_eq!(finishes.iter().map(|f| f.accepted).collect::<Vec<_>>(), vec![None, Some(true)]);
        // Its verdict went to the finish only, never to the lead as an agent's report.
        let settled: Vec<ChildSettled> = rt2
            .records(&id, None, 2_000)
            .unwrap()
            .into_iter()
            .filter_map(|r| match r.event {
                Event::ChildSettled(c) => Some(c),
                _ => None,
            })
            .collect();
        assert_eq!(settled.len(), 1);
        assert_eq!((&settled[0].child, settled[0].inline), (&first, true));
        rt2.shutdown().await;
    }

    #[tokio::test]
    async fn a_finish_made_again_after_an_operator_stop_cut_its_verification_starts_a_new_verifier() {
        let after = Arc::new(AtomicBool::new(false));
        let flag = after.clone();
        let e = env_with(
            Script::new(move |body, _| {
                if !has_tool(body, "verdict") {
                    finish("lead done")
                } else if flag.load(Ordering::SeqCst) {
                    verifier_turn(body, true)
                } else {
                    Action::Stall { ms: 600_000 }
                }
            }),
            false,
            |c| c.agents.verify_finish = true,
        )
        .await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let id = info.meta.id.clone();
        until("the verifier's request", || e.server.requests().iter().any(|b| has_tool(b, "verdict"))).await;
        e.rt.stop(&id).await.unwrap();
        let stopped = |ev: &Event| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Stopped });
        until("the lead stopped", || e.has(&id, stopped)).await;
        let first = e.children(&id)[0].meta.id.clone();
        until("the verifier stopped", || e.rt.session(&first).is_some_and(|s| s.status.phase == Phase::Ended)).await;
        after.store(true, Ordering::SeqCst);
        // The same answer again: the stopped verifier gave no verdict, so a new one runs.
        e.rt.resume(&id).await.unwrap();
        until("delivered", || inbox_kinds(&e).contains(&InboxKind::Finished)).await;
        let kids = e.children(&id);
        assert_eq!(kids.len(), 2);
        let second = kids.iter().map(|k| k.meta.id.clone()).find(|k| *k != first).unwrap();
        let item = e.rt.inbox().into_iter().find(|i| i.item.kind == InboxKind::Finished).unwrap().item;
        assert!(item.text.contains(&format!("[verified by {second}]")), "{}", item.text);
        assert!(!inbox_kinds(&e).contains(&InboxKind::Blocker));
        let finishes = e.rt.ledger(&info.meta.mission).unwrap().state.finishes;
        assert_eq!(finishes.iter().map(|f| f.accepted).collect::<Vec<_>>(), vec![None, Some(true)]);
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn a_recovered_report_that_wakes_an_attended_lead_also_resumes_its_cut_child() {
        let after = Arc::new(AtomicBool::new(false));
        let flag = after.clone();
        let e = env(Script::new(move |body, _| {
            if has_tool(body, "agent_spawn") {
                if mentions(body, "BREPORT") {
                    finish("lead done")
                } else if tool_msgs(body) == 0 {
                    call("agent_spawn", json!({"question": "BMARK", "background": true}))
                } else {
                    call("wait", json!({}))
                }
            } else if mentions(body, "AMARK") {
                finish("AREPORT")
            } else if flag.load(Ordering::SeqCst) {
                finish("BREPORT")
            } else {
                Action::Stall { ms: 600_000 }
            }
        }))
        .await;
        let mut new = e.new_session(Some("go"));
        new.unattended = Some(false);
        let id = e.rt.create_session(new).await.unwrap().meta.id;
        until("the lead waits for B", || {
            e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Waiting }))
        })
        .await;
        until("B is inside a request", || e.server.requests().iter().any(|b| !has_tool(b, "agent_spawn"))).await;
        // A ends while nobody can take its report (awaited, never joined).
        let req = SpawnReq {
            role: "worker".into(),
            mode: SpawnMode::Fresh,
            brief: loom_core::event::Brief { question: "AMARK".into(), ..Default::default() },
            budget: Budget::default(),
            call_id: CallId::from("c1"),
            title: "a".into(),
            awaited: true,
            harness: false,
            prerequisite: None,
            workspace: Workspace::Shared,
        };
        let a = e.rt.inner.orch.spawn(&id, req).await.unwrap();
        let kept = e.rt.inner.paths.session_dir(&a).join("settlement.json");
        until("A settled", || kept.is_file()).await;
        e.rt.shutdown().await;
        after.store(true, Ordering::SeqCst);
        // Nothing resumes an attended mission; A's report starts the lead's turn, and B goes on with it.
        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        let rt = rt2.clone();
        until("the lead finished", || {
            rt.records(&id, None, 2_000).is_ok_and(|rs| {
                rs.iter().any(|r| matches!(r.event, Event::TurnEnd { reason: TurnEndReason::Finished }))
            })
        })
        .await;
        let reports: Vec<String> = rt2
            .records(&id, None, 2_000)
            .unwrap()
            .into_iter()
            .filter_map(|r| match r.event {
                Event::ChildSettled(c) => Some(c.report),
                _ => None,
            })
            .collect();
        assert_eq!(reports.len(), 2, "{reports:?}");
        assert!(reports[0].contains("AREPORT") && reports[1].contains("BREPORT"), "{reports:?}");
        rt2.shutdown().await;
    }

    #[tokio::test]
    async fn an_agent_held_after_a_restart_goes_on_when_a_report_starts_its_leads_turn() {
        let after = Arc::new(AtomicBool::new(false));
        let flag = after.clone();
        let e = env(Script::new(move |body, _| {
            let go = flag.load(Ordering::SeqCst);
            if has_tool(body, "agent_spawn") {
                if mentions(body, "AREPORT") && mentions(body, "BREPORT") {
                    finish("lead done")
                } else if tool_msgs(body) < 2 {
                    let question = if tool_msgs(body) == 0 { "AMARK" } else { "BMARK" };
                    call("agent_spawn", json!({"question": question, "background": true}))
                } else {
                    call("wait", json!({}))
                }
            } else if mentions(body, "AMARK") {
                if go {
                    finish("AREPORT")
                } else {
                    Action::Stall { ms: 600_000 }
                }
            } else if go {
                finish("BREPORT")
            } else {
                idle_worker(body)
            }
        }))
        .await;
        let mut new = e.new_session(Some("go"));
        new.unattended = Some(false);
        let id = e.rt.create_session(new).await.unwrap().meta.id;
        until("the lead waits", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Waiting })))
            .await;
        let b = e.children(&id).into_iter().find(|c| c.meta.title == "BMARK").unwrap().meta.id;
        until_idle(&e, &b).await;
        let a_asked = || e.server.requests().iter().any(|r| mentions(r, "AMARK") && !has_tool(r, "agent_spawn"));
        until("A is inside a request", a_asked).await;
        e.rt.shutdown().await;
        after.store(true, Ordering::SeqCst);
        // Attended: A is held. B was told how the shutdown ended its job and reports; that report starts
        // the lead's turn, and A goes on with it.
        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        let rt = rt2.clone();
        until("the lead finished", || {
            rt.records(&id, None, 2_000).is_ok_and(|rs| {
                rs.iter().any(|r| matches!(r.event, Event::TurnEnd { reason: TurnEndReason::Finished }))
            })
        })
        .await;
        let reports: Vec<String> = rt2
            .records(&id, None, 2_000)
            .unwrap()
            .into_iter()
            .filter_map(|r| match r.event {
                Event::ChildSettled(c) => Some(c.report),
                _ => None,
            })
            .collect();
        assert_eq!(reports.len(), 2, "{reports:?}");
        assert!(reports[0].contains("BREPORT") && reports[1].contains("AREPORT"), "{reports:?}");
        rt2.shutdown().await;
    }

    #[tokio::test]
    async fn a_waiting_lead_whose_worker_cannot_be_opened_after_a_restart_is_given_its_failure_and_goes_on() {
        let e = env(Script::new(|body, _| {
            if !has_tool(body, "agent_spawn") {
                idle_worker(body)
            } else if mentions(body, "could not be opened again") {
                finish("lead done")
            } else if tool_msgs(body) == 0 {
                call("agent_spawn", json!({"question": "CHILDMARK", "background": true}))
            } else {
                call("wait", json!({}))
            }
        }))
        .await;
        let id = e.rt.create_session(e.new_session(Some("go"))).await.unwrap().meta.id;
        until("the lead waits", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Waiting })))
            .await;
        let child = e.children(&id)[0].meta.id.clone();
        until_idle(&e, &child).await;
        let child_tmp = e.rt.paths().session_tmp(&child);
        std::fs::write(child_tmp.join("scratch"), "x").unwrap();
        e.rt.shutdown().await;
        // A shutdown keeps the scratch directory of an agent the next start goes on with.
        assert!(child_tmp.join("scratch").exists());
        // The worker's log is lost while the harness is down: it will never run again.
        std::fs::write(e.rt.paths().session_log(&child), "not a log\n").unwrap();
        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        // Settled on its behalf, it can run no command again: its scratch directory is emptied.
        until("the worker's scratch emptied", || !child_tmp.join("scratch").exists()).await;
        let rt = rt2.clone();
        until("the lead finished", || {
            rt.records(&id, None, 2_000).is_ok_and(|rs| {
                rs.iter().any(|r| matches!(r.event, Event::TurnEnd { reason: TurnEndReason::Finished }))
            })
        })
        .await;
        let settled = |rt: &Runtime| -> Vec<ChildSettled> {
            rt.records(&id, None, 2_000)
                .unwrap()
                .into_iter()
                .filter_map(|r| match r.event {
                    Event::ChildSettled(c) => Some(c),
                    _ => None,
                })
                .collect()
        };
        let got = settled(&rt2);
        assert_eq!(got.len(), 1);
        assert_eq!((&got[0].child, got[0].outcome, got[0].inline), (&child, ChildOutcome::Failed, false));
        assert!(got[0].report.contains("could not be opened again after the harness restarted"), "{}", got[0].report);
        let info = rt2.session(&child).unwrap();
        assert_eq!(
            (info.status.phase, info.status.outcome, info.active),
            (Phase::Ended, Some(SessionOutcome::Failed), false)
        );
        rt2.shutdown().await;
        // Settled once: the next start neither runs it nor delivers it again.
        let rt3 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(settled(&rt3).len(), 1);
        assert!(!rt3.session(&child).unwrap().active);
        rt3.shutdown().await;
    }

    #[tokio::test]
    async fn restart_restores_open_inbox_and_does_not_activate_ended_child() {
        let e = env(lead_script(json!({"question": "CHILDMARK"}))).await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let id = info.meta.id.clone();
        until("inbox", || !e.rt.inbox().is_empty()).await;
        until("child ended", || e.children(&id).iter().all(|c| c.status.phase == Phase::Ended)).await;
        e.rt.shutdown().await;
        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        assert_eq!(rt2.inbox().len(), 1);
        let kids: Vec<_> = rt2.sessions(true).into_iter().filter(|s| s.meta.parent.is_some()).collect();
        assert_eq!(kids.len(), 1);
        assert!(!kids[0].active);
        let n =
            rt2.records(&id, None, 2_000).unwrap().iter().filter(|r| matches!(r.event, Event::ChildSettled(_))).count();
        assert_eq!(n, 1);
        rt2.shutdown().await;
    }

    /// A worker that ended while nobody could take its report: it was started `awaited`, nothing
    /// joined it, and the runtime went down. Returns the lead, the worker, and the switch that
    /// lets the lead's model answer.
    async fn a_settlement_nobody_took() -> (Env, SessionId, SessionId, Arc<AtomicBool>) {
        let stall = Arc::new(AtomicBool::new(true));
        let flag = stall.clone();
        let e = env(Script::new(move |body, _| {
            if has_tool(body, "agent_spawn") {
                if flag.load(Ordering::SeqCst) {
                    Action::Stall { ms: 600_000 }
                } else {
                    finish("lead done")
                }
            } else {
                finish("REPORTMARK the answer on the second line")
            }
        }))
        .await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let id = info.meta.id.clone();
        until("lead request", || e.server.requests().iter().any(|b| has_tool(b, "agent_spawn"))).await;
        let req = SpawnReq {
            role: "worker".into(),
            mode: SpawnMode::Fresh,
            brief: Default::default(),
            budget: Budget::default(),
            call_id: CallId::from("c1"),
            title: "t".into(),
            awaited: true,
            harness: false,
            prerequisite: None,
            workspace: Workspace::Shared,
        };
        let child = e.rt.inner.orch.spawn(&id, req).await.unwrap();
        let kept = e.rt.inner.paths.session_dir(&child).join("settlement.json");
        until("child settled", || kept.is_file()).await;
        e.rt.shutdown().await;
        // Read from the file: the runtime that was shut down answers nothing any more.
        let log = read_records(&e.rt.inner.paths.session_log(&id)).unwrap().records;
        assert!(!log.iter().any(|r| matches!(r.event, Event::ChildSettled(_))), "the delivery was not lost");
        (e, id, child, stall)
    }

    /// Start again over the same home and return the settlement the lead is given.
    async fn recovered_settlement(e: &Env, lead: &SessionId) -> (Runtime, ChildSettled) {
        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        let rt = rt2.clone();
        let settled = move || {
            rt.records(lead, None, 2_000).ok().and_then(|rs| {
                rs.into_iter().find_map(|r| match r.event {
                    Event::ChildSettled(c) => Some(c),
                    _ => None,
                })
            })
        };
        until("settlement delivered", || settled().is_some()).await;
        let c = settled().unwrap();
        (rt2, c)
    }

    #[tokio::test]
    async fn a_settlement_recovered_after_a_restart_carries_the_whole_report() {
        let (e, id, child, stall) = a_settlement_nobody_took().await;
        stall.store(false, Ordering::SeqCst);
        let (rt2, c) = recovered_settlement(&e, &id).await;
        assert_eq!((&c.child, c.outcome, c.inline), (&child, ChildOutcome::Returned, false));
        // The whole report, not its first line: the outcome and the child's own (quoted) words.
        assert!(c.report.starts_with("Outcome: returned\n"), "{}", c.report);
        assert!(c.report.contains("\n> REPORTMARK the answer on the second line"), "{}", c.report);
        assert!(c.steps > 0);
        rt2.shutdown().await;
    }

    #[tokio::test]
    async fn a_settlement_recovered_from_a_log_without_a_complete_result_is_reported_incomplete() {
        let (e, id, child, stall) = a_settlement_nobody_took().await;
        // Drop the complete result the log holds as well as the one kept beside it: what is left is
        // a log that ended before results were persisted whole.
        let log = e.rt.inner.paths.session_log(&child);
        let records = read_records(&log).unwrap().records;
        let pos = records.iter().position(|r| matches!(r.event, Event::ChildCompleted(_))).unwrap();
        let text = std::fs::read_to_string(&log).unwrap();
        std::fs::write(&log, format!("{}\n", text.lines().take(pos).collect::<Vec<_>>().join("\n"))).unwrap();
        let (mut writer, _) = loom_core::log::SessionLog::open(&log, loom_core::log::Durability::Always).unwrap();
        writer.append(Author::Harness, Event::TurnEnd { reason: TurnEndReason::Finished }).unwrap();
        writer
            .append(
                Author::Harness,
                Event::SessionEnd { outcome: SessionOutcome::Done, detail: "Outcome: returned".into() },
            )
            .unwrap();
        drop(writer);
        std::fs::remove_file(e.rt.inner.paths.session_dir(&child).join("settlement.json")).unwrap();
        stall.store(false, Ordering::SeqCst);
        let (rt2, c) = recovered_settlement(&e, &id).await;
        assert_eq!((&c.child, c.outcome, c.inline), (&child, ChildOutcome::Failed, false));
        assert!(c.report.contains("Recovery incomplete"), "{}", c.report);
        assert!(c.full.is_none());
        rt2.shutdown().await;
    }

    /// End an awaited child without joining it, leaving the delivery boundary unacknowledged.
    async fn unreceived_child(e: &Env) -> (SessionId, SessionId, loom_core::event::ChildCompleted) {
        let parent = e.rt.create_session(e.new_session(None)).await.unwrap().meta.id;
        let child =
            e.rt.inner
                .spawn_child(
                    &parent,
                    SpawnReq {
                        role: "worker".into(),
                        mode: SpawnMode::Fresh,
                        brief: Brief { question: "inspect this".into(), ..Brief::default() },
                        budget: Budget::default(),
                        call_id: CallId::from("awaited-call"),
                        title: "unreceived child".into(),
                        awaited: true,
                        harness: false,
                        prerequisite: None,
                        workspace: Workspace::Shared,
                    },
                )
                .await
                .unwrap();
        until("child settlement", || e.rt.session(&child).is_some_and(|s| s.status.phase == Phase::Ended && !s.active))
            .await;
        let completed = e
            .records(&child)
            .into_iter()
            .find_map(|r| match r.event {
                Event::ChildCompleted(c) => Some(c),
                _ => None,
            })
            .unwrap();
        assert!(!e.has(&parent, |ev| matches!(ev, Event::ChildSettled(_))));
        e.rt.shutdown().await;
        (parent, child, completed)
    }

    #[tokio::test]
    async fn fatal_after_completed_outbox_persists_terminal_status_without_duplicate_status_events() {
        let e = env(Script::new(|_, _| finish("durable result before terminal failure"))).await;
        let (_, child, _) = unreceived_child(&e).await;
        let paths = Paths::at(e.dir.path().join("home"));
        let expected =
            completed_settlement(&read_records(&paths.session_log(&child)).unwrap().records, &child).unwrap();
        let stale = {
            let mut state = e.rt.inner.st();
            let known = state.known.get_mut(&child).unwrap();
            known.settlement = None;
            known.settled_tx.send_replace(None);
            known.status.phase = Phase::Running;
            known.status.last_end = None;
            known.status.outcome = None;
            known.status.step = 0;
            known.status.completion_tokens_total = 0;
            known.status.clone()
        };
        write_json_atomic(&paths.session_dir(&child).join("status.json"), &stale).unwrap();
        let mut bus = e.rt.subscribe();
        e.rt.inner.on_end(&child, 0, End::Fatal("terminal write failed after the outbox synced".into()));
        let status = e.rt.session(&child).unwrap().status;
        assert_eq!(status.phase, Phase::Ended);
        assert_eq!(status.outcome, Some(SessionOutcome::Done));
        assert_eq!(status.last_end, Some(TurnEndReason::Finished));
        assert_eq!(status.step, expected.steps);
        assert_eq!(status.completion_tokens_total, expected.usage.completion_tokens);
        assert_eq!((status.prompt_tokens, status.cached_tokens), (stale.prompt_tokens, stale.cached_tokens));
        assert_eq!(read_json::<Status>(&paths.session_dir(&child).join("status.json")).unwrap(), status);
        assert_eq!(e.rt.inner.st().known.get(&child).unwrap().settlement.as_ref(), Some(&expected));
        let events: Vec<_> = std::iter::from_fn(|| bus.try_recv().ok()).collect();
        assert_eq!(
            events.iter().filter(|e| matches!(e, BusEvent::Status { session, .. } if session == &child)).count(),
            1
        );

        // The ordinary settlement path already published this terminal status from Session.
        e.rt.inner.st().known.get_mut(&child).unwrap().settlement = None;
        e.rt.inner.record_settlement(&child, expected.clone());
        let events: Vec<_> = std::iter::from_fn(|| bus.try_recv().ok()).collect();
        assert!(!events.iter().any(|e| matches!(e, BusEvent::Status { .. })));
        assert_eq!(events.iter().filter(|e| matches!(e, BusEvent::Settled { .. })).count(), 1);
        e.rt.inner.record_settlement(&child, expected);
        assert!(bus.try_recv().is_err(), "repeated settlement must emit nothing");
    }

    #[tokio::test]
    async fn restart_recovers_complete_child_results_across_both_delivery_boundaries_once() {
        for after_outbox in [false, true] {
            let answer = "complete answer\n".repeat(1_000);
            let e = env(Script::new(move |_, _| {
                Action::Reply(Reply::tool("finish", json!({"answer": answer}).to_string()).with_usage(Usage {
                    prompt_tokens: 4321,
                    cached_tokens: 1234,
                    completion_tokens: 321,
                    reasoning_tokens: 21,
                }))
            }))
            .await;
            let (parent, child, completed) = unreceived_child(&e).await;
            assert!(completed.full.is_some());
            assert_eq!(completed.payload, json!({"quotes": []}));
            let paths = Paths::at(e.dir.path().join("home"));
            if after_outbox {
                // Crash after syncing the result, before TurnEnd/SessionEnd/status.json.
                let records = read_records(&paths.session_log(&child)).unwrap().records;
                let pos = records.iter().position(|r| matches!(r.event, Event::ChildCompleted(_))).unwrap();
                let text = std::fs::read_to_string(paths.session_log(&child)).unwrap();
                std::fs::write(
                    paths.session_log(&child),
                    format!("{}\n", text.lines().take(pos + 1).collect::<Vec<_>>().join("\n")),
                )
                .unwrap();
                write_json_atomic(&paths.session_dir(&child).join("status.json"), &idle_status()).unwrap();
            }
            let expected = Settlement {
                child: completed.child,
                role: completed.role,
                outcome: completed.outcome,
                report: completed.report,
                full: completed.full,
                payload: completed.payload,
                steps: completed.steps,
                usage: completed.usage,
            };
            for _ in 0..2 {
                let rt = Runtime::start(e.config.clone(), paths.clone()).await.unwrap();
                until("recovered child receipt", || {
                    rt.records(&parent, None, 2_000).unwrap().iter().any(|r| matches!(r.event, Event::ChildSettled(_)))
                })
                .await;
                let restored = rt.inner.st().known.get(&child).unwrap().settlement.clone().unwrap();
                assert_eq!(restored, expected, "every typed field must survive restart");
                assert!(!rt.session(&child).unwrap().active, "completed child must not act again");
                assert_eq!(rt.session(&child).unwrap().status.phase, Phase::Ended);
                let receipts: Vec<_> = rt
                    .records(&parent, None, 2_000)
                    .unwrap()
                    .into_iter()
                    .filter_map(|r| match r.event {
                        Event::ChildSettled(c) if c.child == child => Some((r.author, c)),
                        _ => None,
                    })
                    .collect();
                assert_eq!(receipts.len(), 1, "one receipt across repeated recovery");
                assert_eq!(receipts[0].0, Author::Agent(child.clone()));
                assert_eq!(receipts[0].1.report, expected.report);
                assert_eq!(receipts[0].1.full, expected.full);
                assert_eq!(receipts[0].1.usage, expected.usage);
                assert_eq!(receipts[0].1.steps, expected.steps);
                rt.shutdown().await;
            }
            assert_eq!(e.server.requests().len(), 1, "recovery makes no child or parent inference");
        }
    }

    #[tokio::test]
    async fn stopped_awaited_outbox_recovers_and_is_acknowledged_once() {
        let e = env(Script::new(|_, _| Action::Stall { ms: 600_000 })).await;
        let parent = e.rt.create_session(e.new_session(None)).await.unwrap().meta.id;
        let child =
            e.rt.inner
                .spawn_child(
                    &parent,
                    SpawnReq {
                        role: "worker".into(),
                        mode: SpawnMode::Fresh,
                        brief: Brief { question: "inspect this".into(), ..Brief::default() },
                        budget: Budget::default(),
                        call_id: CallId::from("awaited-stop"),
                        title: "stopped awaited child".into(),
                        awaited: true,
                        harness: false,
                        prerequisite: None,
                        workspace: Workspace::Shared,
                    },
                )
                .await
                .unwrap();
        until("child request", || !e.server.requests().is_empty()).await;
        e.rt.stop(&child).await.unwrap();
        until("stopped child", || e.rt.session(&child).is_some_and(|s| s.status.phase == Phase::Ended && !s.active))
            .await;
        let expected = completed_settlement(&e.records(&child), &child).unwrap();
        assert_eq!(expected.outcome, ChildOutcome::Stopped);
        assert!(!e.has(&parent, |ev| matches!(ev, Event::ChildSettled(_))));
        e.rt.shutdown().await;

        let paths = Paths::at(e.dir.path().join("home"));
        for _ in 0..2 {
            let rt = Runtime::start(e.config.clone(), paths.clone()).await.unwrap();
            until("stopped child receipt", || {
                rt.records(&parent, None, 2_000).unwrap().iter().any(|r| matches!(r.event, Event::ChildSettled(_)))
            })
            .await;
            assert_eq!(rt.inner.st().known.get(&child).unwrap().settlement.as_ref(), Some(&expected));
            assert!(!rt.session(&child).unwrap().active);
            let receipts: Vec<_> = rt
                .records(&parent, None, 2_000)
                .unwrap()
                .into_iter()
                .filter_map(|r| match r.event {
                    Event::ChildSettled(c) if c.child == child => Some(c),
                    _ => None,
                })
                .collect();
            assert_eq!(receipts.len(), 1);
            assert_eq!(receipts[0].outcome, ChildOutcome::Stopped);
            assert_eq!(receipts[0].report, expected.report);
            rt.shutdown().await;
        }
        assert_eq!(e.server.requests().len(), 1, "stopped child is never resumed");
    }

    #[tokio::test]
    async fn archived_family_retains_complete_child_result_for_join_after_unarchive() {
        let e = env(Script::new(|_, _| finish("durable archived result"))).await;
        let (parent, child, _) = unreceived_child(&e).await;
        let paths = Paths::at(e.dir.path().join("home"));
        let expected =
            completed_settlement(&read_records(&paths.session_log(&child)).unwrap().records, &child).unwrap();
        for id in [&parent, &child] {
            let path = paths.session_dir(id).join("meta.json");
            let mut meta: SessionMeta = read_json(&path).unwrap();
            meta.archived = true;
            write_json_atomic(&path, &meta).unwrap();
        }
        let rt = Runtime::start(e.config.clone(), paths).await.unwrap();
        assert!(!rt.session(&parent).unwrap().active);
        assert!(!rt.records(&parent, None, 2_000).unwrap().iter().any(|r| matches!(r.event, Event::ChildSettled(_))));
        assert_eq!(rt.inner.st().known.get(&child).unwrap().settlement.as_ref(), Some(&expected));
        rt.archive(&parent, false).await.unwrap();
        rt.inner.activate(&parent).unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            rt.inner.orch.join(&parent, &child, &CancellationToken::new()),
        )
        .await
        .expect("join must not wait on an already completed archived child")
        .unwrap();
        assert_eq!(result, expected);
        rt.shutdown().await;
    }

    #[tokio::test]
    async fn legacy_child_without_a_complete_result_recovers_as_incomplete_not_successful() {
        let e = env(Script::new(|_, _| finish("this answer was never durably stored"))).await;
        let (parent, child, _) = unreceived_child(&e).await;
        let paths = Paths::at(e.dir.path().join("home"));
        let records = read_records(&paths.session_log(&child)).unwrap().records;
        let pos = records.iter().position(|r| matches!(r.event, Event::ChildCompleted(_))).unwrap();
        let text = std::fs::read_to_string(paths.session_log(&child)).unwrap();
        std::fs::write(
            paths.session_log(&child),
            format!("{}\n", text.lines().take(pos).collect::<Vec<_>>().join("\n")),
        )
        .unwrap();
        // The settlement kept beside the log is a complete result too: a legacy child had none.
        let _ = std::fs::remove_file(paths.session_dir(&child).join("settlement.json"));
        let (mut log, _) =
            loom_core::log::SessionLog::open(&paths.session_log(&child), loom_core::log::Durability::Always).unwrap();
        log.append(Author::Harness, Event::TurnEnd { reason: TurnEndReason::Finished }).unwrap();
        log.append(
            Author::Harness,
            Event::SessionEnd { outcome: SessionOutcome::Done, detail: "Outcome: returned".into() },
        )
        .unwrap();
        drop(log);
        let rt = Runtime::start(e.config.clone(), paths).await.unwrap();
        until("legacy recovery receipt", || {
            rt.records(&parent, None, 2_000).unwrap().iter().any(|r| matches!(r.event, Event::ChildSettled(_)))
        })
        .await;
        let result = rt.inner.st().known.get(&child).unwrap().settlement.clone().unwrap();
        assert_eq!(result.outcome, ChildOutcome::Failed);
        assert!(result.report.contains("Recovery incomplete"));
        assert!(result.report.contains("no durable result payload"));
        assert_eq!(result.payload, json!({"recovery_incomplete": true}));
        assert!(result.full.is_none());
        rt.shutdown().await;
    }

    #[test]
    fn read_only_roles_protect_the_workspace() {
        let packs = Packs::builtin().unwrap();
        let ro = packs.role(None, Some("verifier")).unwrap();
        let mut base = SandboxCfg::default();
        base.extra_writable.push("/somewhere".into());
        let none = BTreeMap::new();
        let cfg = sandbox_cfg_for(&base, ro, Path::new("/ws"), &none);
        assert!(cfg.extra_writable.is_empty());
        assert_eq!(cfg.replay_untrusted_paths, ["/somewhere"]);
        assert!(cfg.protected_paths.contains(&"/ws".to_string()));
        let rw = packs.role(None, Some("worker")).unwrap();
        assert_eq!(sandbox_cfg_for(&base, rw, Path::new("/ws"), &none), base);
    }

    #[test]
    fn every_profiles_api_key_variable_is_withheld_from_commands() {
        let packs = Packs::builtin().unwrap();
        let rw = packs.role(None, Some("worker")).unwrap();
        let mut models = BTreeMap::new();
        let vars = [("a", Some("MYSERVER_ACCESS")), ("b", Some("MYSERVER_ACCESS")), ("c", None), ("d", Some("OTHER"))];
        for (name, var) in vars {
            let p = loom_core::config::ModelProfile { api_key_env: var.map(str::to_string), ..Default::default() };
            models.insert(name.to_string(), p);
        }
        let cfg = sandbox_cfg_for(&SandboxCfg::default(), rw, Path::new("/ws"), &models);
        assert_eq!(cfg.secret_env, ["MYSERVER_ACCESS", "OTHER"]);
    }

    /// A loom home with a pack `strict` that requires a restricted network, and a workspace.
    fn strict_home() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let pack = home.join("packs/strict");
        std::fs::create_dir_all(&pack).unwrap();
        std::fs::write(
            pack.join("pack.toml"),
            "name = \"strict\"\ndefault_role = \"r\"\nrequires_restricted_network = true\n[roles.r]\nprompt = \"r.md\"\ntools = [\"bash\"]\ntermination = \"free\"\n",
        )
        .unwrap();
        std::fs::write(pack.join("r.md"), "Role R.").unwrap();
        let ws = dir.path().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        (dir, home, ws)
    }

    fn allowlist(config: &mut Config) {
        config.network.mode = NetworkMode::Allowlist;
        config.network.allow = vec!["example.com".into()];
    }

    #[tokio::test]
    async fn a_pack_that_requires_a_restricted_network_is_refused_under_open() {
        let (_dir, home, ws) = strict_home();
        let server = MockServer::start(Script::new(|_, _| finish("ok"))).await.unwrap();
        let new = || NewSession { workspace: ws.clone(), pack: Some("strict".into()), ..NewSession::default() };
        let mut config = config_for(&server, None);
        config.network.mode = NetworkMode::Open;
        let rt = Runtime::start(config.clone(), Paths::at(home.clone())).await.unwrap();
        let err = rt.create_session(new()).await.unwrap_err();
        assert!(err.contains("[network] mode = \"allowlist\"") && err.contains("restart"), "{err}");
        assert!(rt.sessions(true).is_empty());
        rt.shutdown().await;
        allowlist(&mut config);
        let rt = Runtime::start(config, Paths::at(home)).await.unwrap();
        rt.create_session(new()).await.unwrap();
        rt.shutdown().await;
    }

    #[tokio::test]
    async fn a_session_of_such_a_pack_is_not_run_when_the_daemon_comes_back_under_open() {
        let (_dir, home, ws) = strict_home();
        let server = MockServer::start(Script::new(|_, _| Action::Stall { ms: 600_000 })).await.unwrap();
        let mut config = config_for(&server, None);
        allowlist(&mut config);
        let rt = Runtime::start(config.clone(), Paths::at(home.clone())).await.unwrap();
        let new = NewSession {
            workspace: ws,
            pack: Some("strict".into()),
            unattended: Some(true),
            message: Some("go".into()),
            ..NewSession::default()
        };
        let id = rt.create_session(new).await.unwrap().meta.id;
        until("a turn in flight", || !server.requests().is_empty()).await;
        rt.shutdown().await;
        let before = server.requests().len();
        // The operator opens the network and restarts: the session's prompt still says it is restricted.
        config.network.mode = NetworkMode::Open;
        let rt = Runtime::start(config, Paths::at(home)).await.unwrap();
        assert!(!rt.session(&id).unwrap().active);
        for err in [rt.send_message(&id, "carry on").await.unwrap_err(), rt.resume(&id).await.unwrap_err()] {
            assert!(err.contains("[network] mode = \"allowlist\"") && err.contains("restart"), "{err}");
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!rt.session(&id).unwrap().active);
        assert_eq!(server.requests().len(), before);
        rt.shutdown().await;
    }

    #[tokio::test]
    async fn session_environment_names_the_proxy() {
        let e = env(Script::new(|body, _| {
            if last_role(body) == "tool" {
                finish("ok")
            } else {
                call("bash", json!({"command": "env"}))
            }
        }))
        .await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let id = info.meta.id.clone();
        until("turn end", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { .. }))).await;
        let port = e.rt.inner.proxy.session_port(&id).unwrap();
        assert!(port != 0 && port != e.rt.proxy_port());
        let text = e.records(&id).into_iter().find_map(|r| match r.event {
            Event::ToolResult(t) if t.name == "bash" => Some(t.text),
            _ => None,
        });
        let text = text.unwrap_or_default();
        assert!(text.contains(&format!("@127.0.0.1:{port}")), "{text}");
        assert!(!text.contains(&format!("@127.0.0.1:{}", e.rt.proxy_port())), "{text}");
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn sessions_have_proxy_ports_of_their_own_and_sandboxes_that_allow_only_their_own() {
        let e = env(Script::new(|_, _| finish("ok"))).await;
        let a = e.rt.create_session(e.new_session(Some("a"))).await.unwrap().meta;
        let b = e.rt.create_session(e.new_session(Some("b"))).await.unwrap().meta;
        let port_of = |env: &std::collections::BTreeMap<String, String>| -> u16 {
            let url = env.get("HTTP_PROXY").expect("HTTP_PROXY");
            url.rsplit(':').next().and_then(|p| p.parse().ok()).expect("a port at the end of HTTP_PROXY")
        };
        let shared = e.rt.proxy_port();
        let (da, _) = e.rt.inner.build(&a, false).unwrap();
        let (db, _) = e.rt.inner.build(&b, false).unwrap();
        let (pa, pb) = (port_of(&da.ctx.env), port_of(&db.ctx.env));
        assert!(pa != pb && pa != shared && pb != shared, "{pa} {pb} {shared}");
        assert_eq!(e.rt.inner.proxy.session_port(&a.id), Some(pa));
        assert_eq!(e.rt.inner.proxy.session_port(&b.id), Some(pb));
        assert_eq!(da.ctx.sandbox.loopback_ports().first(), Some(&pa));
        assert_eq!(db.ctx.sandbox.loopback_ports().first(), Some(&pb));
        for (sandbox, own, other) in [(&da.ctx.sandbox, pa, pb), (&db.ctx.sandbox, pb, pa)] {
            let ports = sandbox.loopback_ports();
            assert!(ports.contains(&own) && !ports.contains(&other) && !ports.contains(&shared), "{ports:?}");
        }
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn a_session_that_ends_holds_no_proxy_port_and_its_port_is_not_reissued() {
        let e = env(Script::new(|_, _| finish("ok"))).await;
        let id = e.rt.create_session(e.new_session(Some("a"))).await.unwrap().meta.id;
        until("turn end", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { .. }))).await;
        let port = e.rt.inner.proxy.session_port(&id).unwrap();
        e.rt.inner.proxy.revoke(&id);
        assert_eq!(e.rt.inner.proxy.session_port(&id), None);
        // The port is retired, so no later session is given it.
        let next = e.rt.create_session(e.new_session(Some("b"))).await.unwrap().meta.id;
        until("second turn end", || e.has(&next, |ev| matches!(ev, Event::TurnEnd { .. }))).await;
        let other = e.rt.inner.proxy.session_port(&next).unwrap();
        assert_ne!(other, port);
        e.rt.shutdown().await;
    }

    // ---- the proxy's floor controls (E4) ---------------------------------------------------------------

    /// A tunnel through the session's own proxy listener to `dest`, answered `200`.
    async fn tunnel_of(e: &Env, id: &SessionId, dest: &str) -> tokio::net::TcpStream {
        use base64::Engine as _;
        use tokio::io::AsyncWriteExt;
        let policy = Policy::new(&loom_core::config::NetworkCfg {
            mode: loom_core::config::NetworkMode::Open,
            allow_private: vec!["127.0.0.1".into()],
            ..loom_core::config::NetworkCfg::default()
        })
        .unwrap();
        let grant = e.rt.inner.proxy.grant(id, policy).unwrap();
        let creds = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", grant.user, grant.password));
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", grant.port)).await.unwrap();
        s.write_all(format!("CONNECT {dest} HTTP/1.1\r\nProxy-Authorization: Basic {creds}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            tokio::io::AsyncReadExt::read_exact(&mut s, &mut b).await.unwrap();
            head.push(b[0]);
        }
        assert!(head.starts_with(b"HTTP/1.1 200"), "{}", String::from_utf8_lossy(&head));
        s
    }

    #[tokio::test]
    async fn cut_mission_ends_the_tunnels_of_the_missions_sessions_and_no_others() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = echo.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        let e = env(Script::new(|_, _| finish("ok"))).await;
        let a = e.rt.create_session(e.new_session(Some("a"))).await.unwrap().meta;
        let b = e.rt.create_session(e.new_session(Some("b"))).await.unwrap().meta;
        assert_ne!(a.mission, b.mission);
        let dest = format!("127.0.0.1:{port}");
        let (mut ta, mut tb) = (tunnel_of(&e, &a.id, &dest).await, tunnel_of(&e, &b.id, &dest).await);
        async fn echoes(s: &mut tokio::net::TcpStream) -> Option<()> {
            s.write_all(b"ping").await.ok()?;
            let mut got = [0u8; 4];
            tokio::time::timeout(Duration::from_millis(800), s.read_exact(&mut got)).await.ok()?.ok().map(|_| ())
        }
        assert!(echoes(&mut ta).await.is_some() && echoes(&mut tb).await.is_some());
        assert_eq!(e.rt.cut_mission(&a.mission), 1);
        let mut rest = Vec::new();
        let ended = tokio::time::timeout(Duration::from_secs(1), ta.read_to_end(&mut rest)).await;
        assert!(ended.is_ok(), "the mission's tunnel closes within a second");
        assert!(echoes(&mut tb).await.is_some(), "another mission's tunnel is not touched");
        assert_eq!(e.rt.cut_mission(&a.mission), 0);
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn the_lab_listener_check_leaves_out_the_connectors_own_mission() {
        let e = env(Script::new(|_, _| finish("ok"))).await;
        let a = e.rt.create_session(e.new_session(Some("a"))).await.unwrap().meta;
        let b = e.rt.create_session(e.new_session(Some("b"))).await.unwrap().meta;
        assert_ne!(a.mission, b.mission);
        // A mission's own sessions are not squatters for each other; another mission's are.
        assert_eq!(e.rt.inner.mission_peers(&a.id), vec![a.id.as_str().to_string()]);
        assert_eq!(e.rt.inner.mission_peers(&SessionId::from("unknown")), vec!["unknown".to_string()]);
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn the_runtimes_proxy_has_the_floor_installed() {
        use base64::Engine as _;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let e = env(Script::new(|_, _| finish("ok"))).await;
        let a = e.rt.create_session(e.new_session(Some("a"))).await.unwrap().meta;
        let floor = e.rt.floor();
        floor.add_canary_host("bait.example.test", "CN-4 test").unwrap();
        floor.add_canary_user("loom-decoy-1", "CN-1 test").unwrap();
        let port = e.rt.inner.proxy.session_port(&a.id).unwrap();
        let ask = |creds: String, dest: &'static str| async move {
            let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            s.write_all(format!("CONNECT {dest} HTTP/1.1\r\nProxy-Authorization: Basic {creds}\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut resp = String::new();
            let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_string(&mut resp)).await;
            resp
        };
        // The decoy user: 407, an S4 event attributed to the session whose port it was sent to.
        let resp = ask(base64::engine::general_purpose::STANDARD.encode("loom-decoy-1:x"), "93.184.216.34:443").await;
        assert!(resp.starts_with("HTTP/1.1 407"), "{resp}");
        // The session's own credentials to the decoy host: refused before any lookup.
        let grant =
            e.rt.inner.proxy.grant(&a.id, Policy::new(&loom_core::config::NetworkCfg::default()).unwrap()).unwrap();
        let own = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", grant.user, grant.password));
        let resp = ask(own, "bait.example.test:443").await;
        // The policy (deny_all, the default) refuses the name with its 403, and the floor saw it all the same.
        assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
        let events = floor.events();
        assert!(
            events
                .iter()
                .any(|ev| ev.kind == crate::floor::FloorKind::CanaryCredential && ev.session.as_ref() == Some(&a.id)),
            "{events:?}"
        );
        let hosts = |floor: &crate::floor::Floor| {
            floor.events().iter().filter(|ev| ev.kind == crate::floor::FloorKind::CanaryHost).count()
        };
        assert_eq!(hosts(&floor), 1, "a deny_all mission naming a decoy host is an S4 event: {events:?}");
        // With a policy that lets the name through, the veto is what closes it (502, the fixed sentence).
        let open = Policy::new(&loom_core::config::NetworkCfg {
            mode: loom_core::config::NetworkMode::Open,
            ..loom_core::config::NetworkCfg::default()
        })
        .unwrap();
        let grant = e.rt.inner.proxy.grant(&a.id, open).unwrap();
        let own = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", grant.user, grant.password));
        let resp = ask(own, "bait.example.test:443").await;
        assert!(
            resp.starts_with("HTTP/1.1 502") && resp.contains("closed to this mission by loom's own rules"),
            "{resp}"
        );
        assert_eq!(hosts(&floor), 2);
        // Every event is also on disk.
        let log = std::fs::read_to_string(e.rt.paths().logs_dir().join("floor.jsonl")).unwrap();
        assert!(log.lines().count() >= 3 && log.contains("canary_host"), "{log}");
        e.rt.shutdown().await;
    }

    // ---- the box (I1, I5) -------------------------------------------------------------------------

    use loom_tools::boxctl::fake::FakeDocker;

    /// The box needs the OS sandbox (config load refuses it with `mode = "none"`, R10): whichever the platform has.
    fn with_os_sandbox(c: &mut Config) {
        c.sandbox.mode = if cfg!(target_os = "macos") { SandboxMode::Seatbelt } else { SandboxMode::Bubblewrap };
    }

    /// A runtime whose box is the fake docker of a directory of its own.
    async fn box_env(fake: &FakeDocker) -> Env {
        let cfg = fake.cfg();
        env_with(Script::new(|_, _| finish("ok")), false, move |c| {
            c.boxed = cfg;
            with_os_sandbox(c);
        })
        .await
    }

    async fn idle_lead(e: &Env) -> (SessionId, MissionId) {
        // Bubblewrap (the Linux OS sandbox these tests use) refuses a workspace without its reserved `.loom`.
        std::fs::create_dir_all(e.ws.join(".loom")).unwrap();
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let id = info.meta.id.clone();
        until("idle", || e.rt.session(&id).is_some_and(|s| s.status.phase == Phase::Idle)).await;
        (id, info.meta.mission.clone())
    }

    fn box_container(mission: &MissionId) -> String {
        loom_tools::boxctl::names(mission.as_str()).container
    }

    #[tokio::test]
    async fn without_a_box_in_the_config_the_box_tools_say_so_and_an_agent_copy_has_none() {
        let e = env(Script::new(|_, _| finish("ok"))).await;
        let (id, _) = idle_lead(&e).await;
        let err = e.rt.inner.orch.box_access(&id).await.err().unwrap();
        assert_eq!(err, "No box is configured. The operator sets [box] in config.toml.");
        e.rt.shutdown().await;

        let dir = tempfile::tempdir().unwrap();
        let fake = FakeDocker::new(dir.path());
        let e = box_env(&fake).await;
        let (id, _) = idle_lead(&e).await;
        assert!(e.rt.inner.orch.box_access(&id).await.is_ok());
        // A session that works in its own copy of the workspace is refused with the sentence.
        e.rt.inner.st().known.get_mut(&id).unwrap().meta.copy_of = Some("/somewhere".into());
        let err = e.rt.inner.orch.box_access(&id).await.err().unwrap();
        assert_eq!(err, "box_exec is not available in an agent copy yet; work in the shared workspace.");
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn i5_a_scope_grant_applies_the_rules_to_the_missions_box_again() {
        let dir = tempfile::tempdir().unwrap();
        let fake = FakeDocker::new(dir.path());
        let e = box_env(&fake).await;
        let (id, mission) = idle_lead(&e).await;
        // No box yet: a grant touches no docker (the start only listed leftovers).
        e.rt.grant_scope(&id, &["198.51.100.4".to_string()], None).await.unwrap();
        assert!(fake.sub("run").is_empty() && fake.sub("exec").is_empty(), "{:?}", fake.calls());
        let b = e.rt.inner.orch.box_access(&id).await.unwrap();
        b.ready().await.unwrap();
        let rules = std::fs::read_to_string(fake.dir.join("rules.in")).unwrap();
        assert!(
            rules.contains("-d 198.51.100.4/32 -p tcp -j ACCEPT"),
            "the grant made before the box is in it: {rules}"
        );
        assert!(!rules.contains("203.0.113.7"));
        // A grant on the running box is applied at once, and nothing else is.
        e.rt.grant_scope(&id, &["203.0.113.7:8080".to_string(), "*.wild.test".to_string()], None).await.unwrap();
        let rules = std::fs::read_to_string(fake.dir.join("rules.in")).unwrap();
        assert!(rules.contains("-d 203.0.113.7/32 -p tcp -m tcp --dport 8080 -j ACCEPT"), "{rules}");
        assert!(rules.contains("-d 198.51.100.4/32 -p tcp -j ACCEPT"), "{rules}");
        assert!(!rules.contains("wild") && rules.trim_end().ends_with("COMMIT"));
        assert!(fake.running(&box_container(&mission)));
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn the_boxs_rule_counters_are_polled_recorded_as_deltas_and_only_when_they_moved() {
        let dir = tempfile::tempdir().unwrap();
        let fake = FakeDocker::new(dir.path());
        let e = box_env(&fake).await;
        let (id, mission) = idle_lead(&e).await;
        // No box yet: nothing to poll, no record.
        assert!(e.rt.box_counters_now().await.is_empty());
        let b = e.rt.inner.orch.box_access(&id).await.unwrap();
        b.ready().await.unwrap();
        let counters = fake.dir.join(format!("counters-{}", b.names().chain));
        let listing = |accepted: u32, dropped: u32| {
            format!(
                "Chain {} (1 references)\n    pkts      bytes target     prot opt in     out     source               destination\n    {accepted:>4} {:>9} ACCEPT     tcp  --  *      *       0.0.0.0/0            198.51.100.4         tcp dpt:443\n    {dropped:>4} {:>9} DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0           \n",
                b.names().chain,
                accepted * 60,
                dropped * 60
            )
        };
        std::fs::write(&counters, listing(3, 0)).unwrap();
        let first = e.rt.box_counters_now().await;
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].0, mission);
        assert_eq!(first[0].1.len(), 1);
        assert_eq!((first[0].1[0].packets, first[0].1[0].drop), (3, false));
        // Nothing moved: nothing is recorded.
        assert!(e.rt.box_counters_now().await.is_empty());
        // A drop is recorded as a delta, the accept as none.
        std::fs::write(&counters, listing(3, 5)).unwrap();
        let second = e.rt.box_counters_now().await;
        assert_eq!(second[0].1.len(), 1, "{second:?}");
        assert!(second[0].1[0].drop && second[0].1[0].packets == 5 && second[0].1[0].bytes == 300, "{second:?}");
        let text = std::fs::read_to_string(e.rt.paths().logs_dir().join("box-counters.jsonl")).unwrap();
        let lines: Vec<serde_json::Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(lines.len(), 2, "{text}");
        assert_eq!(lines[1]["mission"], mission.as_str());
        assert_eq!(lines[1]["chain"], b.names().chain.as_str());
        assert_eq!(lines[1]["rules"][0]["packets"], 5);
        assert_eq!(lines[1]["rules"][0]["drop"], true);
        assert!(lines[1]["ts_ms"].as_u64().unwrap_or(0) > 0);
        // A chain that cannot be read is not a record, and the next good poll goes on from where it was.
        std::fs::remove_file(fake.dir.join(format!("chain-{}", b.names().chain))).unwrap();
        assert!(e.rt.box_counters_now().await.is_empty());
        assert!(e.rt.inner.box_counters_failed.lock().unwrap().contains(&mission));
        std::fs::write(fake.dir.join(format!("chain-{}", b.names().chain)), "").unwrap();
        std::fs::write(&counters, listing(3, 6)).unwrap();
        let third = e.rt.box_counters_now().await;
        assert_eq!(third[0].1[0].packets, 1, "{third:?}");
        assert!(e.rt.inner.box_counters_failed.lock().unwrap().is_empty());
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn i5_archiving_and_stopping_the_mission_remove_its_box() {
        let dir = tempfile::tempdir().unwrap();
        let fake = FakeDocker::new(dir.path());
        let e = box_env(&fake).await;
        let (id, mission) = idle_lead(&e).await;
        let container = box_container(&mission);
        e.rt.inner.orch.box_access(&id).await.unwrap().ready().await.unwrap();
        assert!(fake.running(&container));
        e.rt.stop(&id).await.unwrap();
        until("box removed by stop", || !fake.running(&container)).await;
        until("chain removed by stop", || {
            fake.sub("run").iter().any(|r| {
                r.iter().any(|a| a == &loom_tools::boxctl::names(mission.as_str()).chain)
                    && !r.iter().any(|a| a == "--interactive")
            })
        })
        .await;
        // R3: a stopped mission's box stays down: asking for it again is refused, not re-created.
        let runs = fake.sub("run").len();
        let err = e.rt.inner.orch.box_access(&id).await.err().unwrap();
        assert_eq!(
            err,
            "The box of this mission was removed when the mission was stopped. It comes back when the operator resumes the mission."
        );
        assert_eq!(fake.sub("run").len(), runs, "nothing was made");
        assert!(!fake.running(&container));
        // Resuming the lead gives it back, on demand; the archive removes that one.
        e.rt.resume(&id).await.unwrap();
        e.rt.inner.orch.box_access(&id).await.unwrap().ready().await.unwrap();
        assert!(fake.running(&container));
        until("idle again", || e.rt.session(&id).is_some_and(|s| s.status.phase == Phase::Idle)).await;
        let mark = fake.calls().len();
        e.rt.archive(&id, true).await.unwrap();
        until("box removed by archive", || !fake.running(&container)).await;
        until("its chain removed", || fake.calls()[mark..].iter().any(|c| c.get(2).is_some_and(|s| s == "run"))).await;
        // The order of the removal: container, then network, then the chain.
        let subs: Vec<String> = fake.calls()[mark..].iter().filter_map(|c| c.get(2).cloned()).collect();
        let first = |name: &str| subs.iter().position(|s| s == name).unwrap_or(usize::MAX);
        assert!(first("rm") < first("network") && first("network") < first("run"), "{subs:?}");
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn r3_a_mission_that_ended_or_was_stopped_has_no_box_until_its_lead_runs_again() {
        let dir = tempfile::tempdir().unwrap();
        let fake = FakeDocker::new(dir.path());
        let e = box_env(&fake).await;
        let (id, mission) = idle_lead(&e).await;
        let container = box_container(&mission);
        assert!(e.rt.inner.orch.box_access(&id).await.is_ok(), "an untouched mission can have a box");
        e.rt.stop(&id).await.unwrap();
        // `box_access` is what box_exec, box_get and box_reset ask: all three get the refusal.
        let err = e.rt.inner.orch.box_access(&id).await.err().unwrap();
        assert!(err.starts_with("The box of this mission was removed when the mission was stopped."), "{err}");
        assert!(e.rt.inner.st().box_closed.contains(&mission));
        e.rt.resume(&id).await.unwrap();
        assert!(!e.rt.inner.st().box_closed.contains(&mission), "resuming the lead clears the mark");
        let b = e.rt.inner.orch.box_access(&id).await.unwrap();
        b.ready().await.unwrap();
        assert!(fake.running(&container));
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn l3_a_message_to_a_stopped_lead_gives_its_mission_the_box_back() {
        let dir = tempfile::tempdir().unwrap();
        let fake = FakeDocker::new(dir.path());
        let e = box_env(&fake).await;
        let (id, mission) = idle_lead(&e).await;
        e.rt.stop(&id).await.unwrap();
        assert!(e.rt.inner.orch.box_access(&id).await.is_err(), "stopped: no box");
        assert!(e.rt.inner.st().box_closed.contains(&mission));
        e.rt.send_message(&id, "carry on").await.unwrap();
        assert!(!e.rt.inner.st().box_closed.contains(&mission), "the message made the lead run again");
        let b = e.rt.inner.orch.box_access(&id).await.unwrap();
        b.ready().await.unwrap();
        assert!(fake.running(&box_container(&mission)));
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn r10_start_refuses_an_unix_socket_that_leads_to_the_box() {
        let dir = tempfile::tempdir().unwrap();
        let fake = FakeDocker::new(dir.path());
        let e = box_env(&fake).await;
        e.rt.shutdown().await;
        let home = e.dir.path().join("home");
        for socket in [home.join("keys/box.sock"), home.join("keys/anything"), fake.socket.clone()] {
            let mut config = e.config.clone();
            config.sandbox.unix_sockets = vec![socket.display().to_string()];
            let err = Runtime::start(config, Paths::at(home.clone())).await.err().expect("start must refuse");
            assert!(err.contains("sandbox.unix_sockets"), "{}: {err}", socket.display());
        }
        // Without the box, a socket elsewhere is none of its business.
        let mut config = e.config.clone();
        config.boxed.enabled = false;
        config.sandbox.unix_sockets = vec![dir.path().join("lab.sock").display().to_string()];
        let rt = Runtime::start(config, Paths::at(home.clone())).await.expect("no box, no restriction");
        rt.shutdown().await;
        // A container runtime's socket is refused with or without the box.
        let mut config = e.config.clone();
        config.boxed.enabled = false;
        config.sandbox.unix_sockets = vec![fake.socket.display().to_string()];
        let err = Runtime::start(config, Paths::at(home.clone())).await.err().expect("start must refuse");
        assert!(err.contains("container runtime"), "{err}");
    }

    #[tokio::test]
    async fn i5_start_removes_what_boxes_of_missions_that_are_not_running_left() {
        let dir = tempfile::tempdir().unwrap();
        let fake = FakeDocker::new(dir.path());
        // An earlier daemon left a container, a network and a chain for a mission nothing runs.
        let stale = loom_tools::boxctl::names("m-stale");
        std::fs::write(fake.dir.join(format!("ctr-{}", stale.container)), "").unwrap();
        std::fs::write(fake.dir.join(format!("net-{}", stale.network)), "").unwrap();
        std::fs::write(fake.dir.join("ps.txt"), "m-stale\n").unwrap();
        std::fs::write(fake.dir.join("net.txt"), "m-stale\n").unwrap();
        let e = box_env(&fake).await;
        until("stale box removed", || !fake.running(&stale.container)).await;
        until("stale network removed", || !fake.dir.join(format!("net-{}", stale.network)).exists()).await;
        until("chain removed", || fake.sub("run").iter().any(|r| r.iter().any(|a| a == &stale.chain))).await;
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn i1_the_docker_forward_is_unreadable_to_commands_and_never_a_permitted_socket() {
        let dir = tempfile::tempdir().unwrap();
        let fake = FakeDocker::new(dir.path());
        let cfg = {
            let mut c = fake.cfg();
            c.docker_socket = String::new();
            c.ssh_host = "loom-box".into();
            c.remote_socket = "/var/run/docker.sock".into();
            c
        };
        let e = env_with(Script::new(|_, _| finish("ok")), false, move |c| {
            c.boxed = cfg;
            with_os_sandbox(c);
        })
        .await;
        let (id, _) = idle_lead(&e).await;
        let socket = e.rt.inner.box_host.as_ref().unwrap().socket().to_path_buf();
        assert_eq!(socket, e.rt.paths().keys_dir().join("box.sock"));
        std::fs::write(&socket, b"").unwrap();
        // Neither the config the runtime hands the sandbox nor the sandbox that results has the socket.
        let meta = e.rt.session(&id).unwrap().meta;
        let (deps, _parts) = e.rt.inner.build(&meta, true).unwrap();
        assert!(deps.ctx.sandbox.check_read(&socket).is_err(), "commands cannot read the forwarded socket");
        assert!(deps.ctx.sandbox.check_write(&socket).is_err(), "nor write it");
        assert!(!deps.ctx.sandbox.describe().contains("box.sock"));
        let role = e.rt.inner.packs.role(Some(&meta.pack), Some(&meta.role)).unwrap().clone();
        let ws = std::fs::canonicalize(&meta.workspace).unwrap();
        let sandbox_cfg = sandbox_cfg_for(&e.rt.inner.config.sandbox, &role, &ws, &e.rt.inner.config.models);
        assert!(sandbox_cfg.unix_sockets.is_empty());
        assert!(sandbox_cfg
            .extra_writable
            .iter()
            .chain(&sandbox_cfg.loopback_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>())
            .all(|p| !p.contains("box.sock")));
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn archive_hides_refuses_and_survives_restart() {
        let e = env(Script::new(|_, _| finish("ok"))).await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let id = info.meta.id.clone();
        until("turn end", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { .. }))).await;
        until("idle", || e.rt.session(&id).is_some_and(|s| s.status.phase == Phase::Idle)).await;
        // The scratch directory is kept while the session can still run commands, and emptied by the archive.
        let tmp = e.rt.paths().session_tmp(&id);
        std::fs::create_dir_all(tmp.join("sub")).unwrap();
        std::fs::write(tmp.join("sub").join("f"), "x").unwrap();
        std::fs::write(tmp.join("g"), "x").unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(tmp.join("g").exists());
        e.rt.archive(&id, true).await.unwrap();
        until("scratch emptied", || std::fs::read_dir(&tmp).is_ok_and(|mut d| d.next().is_none())).await;
        assert!(e.rt.sessions(false).is_empty());
        assert_eq!(e.rt.sessions(true).len(), 1);
        assert!(e.rt.send_message(&id, "hi").await.is_err());
        e.rt.shutdown().await;
        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        assert!(rt2.sessions(false).is_empty());
        assert!(rt2.session(&id).unwrap().meta.archived);
        assert!(!rt2.session(&id).unwrap().active);
        rt2.archive(&id, false).await.unwrap();
        assert_eq!(rt2.sessions(false).len(), 1);
        rt2.shutdown().await;
    }

    #[tokio::test]
    async fn archiving_a_session_without_a_task_empties_its_scratch_directory_before_it_returns() {
        let e = env(Script::new(|_, _| finish("ok"))).await;
        let id = e.rt.create_session(e.new_session(None)).await.unwrap().meta.id;
        e.rt.shutdown().await;
        // An idle session is not activated by the next start: archiving it ends no task.
        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        assert!(!rt2.session(&id).unwrap().active);
        let tmp = rt2.paths().session_tmp(&id);
        std::fs::create_dir_all(tmp.join("sub")).unwrap();
        std::fs::write(tmp.join("sub").join("f"), "x").unwrap();
        std::fs::write(tmp.join("g"), "x").unwrap();
        rt2.archive(&id, true).await.unwrap();
        assert!(tmp.is_dir() && std::fs::read_dir(&tmp).unwrap().next().is_none());
        rt2.shutdown().await;
    }

    #[tokio::test]
    async fn an_agent_whose_inputs_close_outside_a_shutdown_settles_and_its_lead_gets_the_settlement() {
        let script = Script::new(|body, _| {
            if !has_tool(body, "agent_spawn") {
                return idle_worker(body);
            }
            if mentions(body, "was stopped after") {
                return finish("lead done");
            }
            match tool_msgs(body) {
                // The lead's own job ignores TERM: its task is still ending (until the KILL after the
                // grace) when the mission is unarchived.
                0 => call("bash", json!({"command": "trap '' TERM; sleep 600", "background": true})),
                1 => call("agent_spawn", json!({"question": "CHILDMARK", "background": true})),
                _ => call("wait", json!({})),
            }
        });
        let e = env_with(script, false, |c| c.tools.kill_grace_s = 3).await;
        let id = e.rt.create_session(e.new_session(Some("go"))).await.unwrap().meta.id;
        until("the lead waits", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Waiting })))
            .await;
        let child = e.children(&id)[0].meta.id.clone();
        until_idle(&e, &child).await;
        let child_tmp = e.rt.paths().session_tmp(&child);
        std::fs::write(child_tmp.join("scratch"), "x").unwrap();
        // Archiving closes the inputs of the lead and of its agent for good.
        e.rt.archive(&id, true).await.unwrap();
        until("the agent settled", || e.rt.session(&child).is_some_and(|s| s.status.phase == Phase::Ended)).await;
        // A settled agent can run no more commands: its scratch directory is emptied.
        until("the agent's scratch emptied", || !child_tmp.join("scratch").exists()).await;
        assert_eq!(e.rt.session(&child).unwrap().status.outcome, Some(SessionOutcome::Stopped));
        assert!(stopped_while_idle(&e, &child, texts::REASON_OPERATOR), "{:?}", e.kinds(&child));
        assert!(!e.has(&id, |ev| matches!(ev, Event::ChildSettled(_))), "an archived lead was given a settlement");
        // Unarchived, the lead gets the settlement, which wakes it.
        e.rt.archive(&id, false).await.unwrap();
        until("the lead finished", || {
            e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Finished }))
        })
        .await;
        let settled: Vec<Record> = e
            .records(&id)
            .into_iter()
            .filter(|r| matches!(&r.event, Event::ChildSettled(c) if c.child == child))
            .collect();
        assert_eq!(settled.len(), 1);
        assert!(matches!(&settled[0].event, Event::ChildSettled(c) if c.outcome == ChildOutcome::Stopped && !c.inline));
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn a_runtime_dropped_without_shutdown_cuts_its_idle_agent_instead_of_settling_it() {
        let e = env(Script::new(|body, _| {
            if !has_tool(body, "agent_spawn") {
                idle_worker(body)
            } else if tool_msgs(body) == 0 {
                call("agent_spawn", json!({"question": "CHILDMARK", "background": true}))
            } else {
                call("wait", json!({}))
            }
        }))
        .await;
        let id = e.rt.create_session(e.new_session(Some("go"))).await.unwrap().meta.id;
        until("the lead waits", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Waiting })))
            .await;
        let child = e.children(&id)[0].meta.id.clone();
        until_idle(&e, &child).await;
        let log = e.rt.paths().session_log(&child);
        // The daemon unwinding drops its runtime: the sessions' inputs close without a shutdown.
        let Env { dir, server, rt, .. } = e;
        drop(rt);
        tokio::time::sleep(Duration::from_millis(500)).await;
        let rs = read_records(&log).unwrap().records;
        assert!(!rs.iter().any(|r| matches!(r.event, Event::SessionEnd { .. })), "the agent was settled");
        assert!(!rs
            .iter()
            .any(|r| matches!(&r.event, Event::Interrupted { reason } if reason == texts::REASON_OPERATOR)));
        drop((dir, server));
    }

    /// Store `data` and make the blob two hours old.
    fn old_blob(store: &BlobStore, data: &str) -> String {
        let b = store.put_bytes(data.as_bytes()).unwrap();
        let f = std::fs::OpenOptions::new().write(true).open(store.root().join(&b.id.0[..2]).join(&b.id.0)).unwrap();
        f.set_modified(std::time::SystemTime::now() - Duration::from_secs(7200)).unwrap();
        b.id.0
    }

    #[tokio::test]
    async fn gc_keeps_everything_referenced_anywhere_and_young_blobs() {
        let e = env(Script::new(|_, _| finish("ok"))).await;
        let home = e.dir.path().join("home");
        let store = e.rt.blobs().clone();
        let old = |data: &str| old_blob(&store, data);
        let (in_log, in_journal, in_damaged, in_raw, by_handle, orphan) =
            (old("log\n"), old("journal\n"), old("damaged\n"), old("raw\n"), old("handle\n"), old("orphan\n"));
        let young = store.put_bytes(b"young\n").unwrap().id.0;
        // A parent's copy of a child's report names the child's output by its handle only.
        let s2 = home.join("sessions").join("s-gc2");
        std::fs::create_dir_all(&s2).unwrap();
        std::fs::write(s2.join("log.jsonl"), format!("{{\"text\":\"see out:{}\"}}\n", &by_handle[..16])).unwrap();
        let s1 = home.join("sessions").join("s-gc1");
        let m1 = home.join("missions").join("m-gc1");
        std::fs::create_dir_all(&s1).unwrap();
        std::fs::create_dir_all(&m1).unwrap();
        std::fs::write(s1.join("log.jsonl"), format!("{{\"seq\":1,\"blob\":\"{in_log}\"}}\n")).unwrap();
        std::fs::write(s1.join("log.jsonl.damaged-1"), format!("garbage {{{{ \"x\":\"{in_damaged}")).unwrap();
        std::fs::write(
            s1.join("log2.jsonl"),
            format!("{{\"type\":\"ToolResult\",\"meta\":{{\"{}\":\"{in_raw}\"}}}}\n", loom_core::event::META_RAW_BLOB),
        )
        .unwrap();
        std::fs::write(m1.join("journal.jsonl"), format!("{{\"ref\":\"out:{in_journal}\"}}\n")).unwrap();

        let dry = e.rt.gc(false, None).await.unwrap();
        assert_eq!((dry.examined, dry.kept, dry.collected, dry.applied), (7, 6, 1, false));
        assert!(store.read_all(&BlobId(orphan.clone())).is_ok());
        let done = e.rt.gc(true, None).await.unwrap();
        // Seven bytes and the eight of its one-line index.
        assert_eq!((done.collected, done.collected_bytes), (1, 15));
        assert!(store.read_all(&BlobId(orphan)).is_err());
        for id in [&in_log, &in_journal, &in_damaged, &in_raw, &by_handle, &young] {
            assert!(store.read_all(&BlobId(id.clone())).is_ok(), "{id} was collected");
        }
        // The session directory goes: its blobs become collectable (the young one still is not).
        std::fs::remove_dir_all(&s1).unwrap();
        let after = e.rt.gc(false, None).await.unwrap();
        assert_eq!((after.examined, after.kept, after.collected), (6, 3, 3));
        let zero_age = e.rt.gc(false, Some(Duration::ZERO)).await.unwrap();
        assert_eq!(zero_age.collected, 4);
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn gc_follows_no_link_below_a_session_directory_and_names_what_it_cannot_read() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let e = env(Script::new(|_, _| finish("ok"))).await;
        let (home, store) = (e.dir.path().join("home"), e.rt.blobs().clone());
        let (in_log, outside, in_linked) =
            (old_blob(&store, "log\n"), old_blob(&store, "out\n"), old_blob(&store, "ln\n"));
        // Links below a session directory are not followed: a link to itself, two links to `.`, a dangling
        // link, and links to a directory and a file outside that name a blob.
        let s1 = home.join("sessions").join("s-gc1");
        let sub = s1.join("jobs");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(s1.join("log.jsonl"), format!("{{\"blob\":\"{in_log}\"}}\n")).unwrap();
        let out = e.dir.path().join("outside");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("names.txt"), &outside).unwrap();
        symlink("loop", sub.join("loop")).unwrap();
        symlink(".", sub.join("here")).unwrap();
        symlink(".", sub.join("again")).unwrap();
        symlink("/nonexistent-loom-target", sub.join("dangling")).unwrap();
        symlink(&out, sub.join("out")).unwrap();
        symlink(out.join("names.txt"), sub.join("names.txt")).unwrap();
        // The temp dir, which commands write, is not read at all: what is in it names nothing.
        std::fs::create_dir_all(s1.join("tmp")).unwrap();
        std::fs::write(s1.join("tmp").join("names.txt"), &outside).unwrap();
        // A session directory that is itself a link is read; a looping link beside it is nothing.
        let elsewhere = e.dir.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("log.jsonl"), format!("{{\"blob\":\"{in_linked}\"}}\n")).unwrap();
        symlink(&elsewhere, home.join("sessions").join("s-gc2")).unwrap();
        symlink("loop", home.join("sessions").join("loop")).unwrap();

        let r = e.rt.gc(true, None).await.unwrap();
        assert_eq!((r.examined, r.kept, r.collected), (3, 2, 1));
        assert!(store.read_all(&BlobId(outside)).is_err());
        assert!(store.read_all(&BlobId(in_log)).is_ok() && store.read_all(&BlobId(in_linked)).is_ok());
        // A file that cannot be read stops the collection, and the error names it (not when tests run as root).
        let locked = sub.join("locked.txt");
        std::fs::write(&locked, "x").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read(&locked).is_err() {
            let err = e.rt.gc(true, None).await.unwrap_err();
            assert!(err.starts_with(&format!("cannot read {} (", locked.display())), "{err}");
            assert!(err.contains("nothing was collected"), "{err}");
        }
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o600)).unwrap();
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn gc_passes_over_a_dangling_top_level_link_and_stops_at_one_it_cannot_follow() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let e = env(Script::new(|_, _| finish("ok"))).await;
        let (sessions, store) = (e.dir.path().join("home").join("sessions"), e.rt.blobs().clone());
        let named = old_blob(&store, "named\n");
        symlink("/nonexistent-loom-target", sessions.join("s-gone")).unwrap();
        assert_eq!(e.rt.gc(false, None).await.unwrap().collected, 1);
        // A session directory kept behind a directory that cannot be searched: the link cannot be followed.
        let locked = e.dir.path().join("locked");
        std::fs::create_dir_all(locked.join("s-gc9")).unwrap();
        std::fs::write(locked.join("s-gc9").join("log.jsonl"), &named).unwrap();
        let link = sessions.join("s-gc9");
        symlink(locked.join("s-gc9"), &link).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        // Not when tests run as root.
        if std::fs::metadata(&link).is_err() {
            let err = e.rt.gc(true, None).await.unwrap_err();
            assert!(err.starts_with(&format!("cannot read {} (", link.display())), "{err}");
            assert!(err.contains("nothing was collected"), "{err}");
            assert!(store.read_all(&BlobId(named.clone())).is_ok());
        }
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        // Readable again: its log names the blob, which stays.
        assert_eq!(e.rt.gc(true, None).await.unwrap().collected, 0);
        assert!(store.read_all(&BlobId(named)).is_ok());
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn gc_that_cannot_finish_its_scan_says_where_and_why_and_deletes_nothing() {
        let e = env(Script::new(|_, _| finish("ok"))).await;
        let (sessions, store) = (e.dir.path().join("home").join("sessions"), e.rt.blobs().clone());
        let orphan = old_blob(&store, "orphan\n");
        let big = sessions.join("s-gc1").join("log.jsonl");
        std::fs::create_dir_all(sessions.join("s-gc1")).unwrap();
        std::fs::write(&big, "x".repeat(100)).unwrap();
        let too_large = |max: u64| {
            format!(
                "cannot read {} (it is larger than {max} bytes, the most a collection reads of one file); nothing was \
                 collected. Remove it, or the session or mission it belongs to, and run it again.",
                big.display()
            )
        };
        assert_eq!(e.rt.gc_within(true, None, 64, GC_SCAN_TIME).await.unwrap_err(), too_large(64));
        // A sparse file that claims more than the real limit is refused without being read.
        std::fs::OpenOptions::new().write(true).open(&big).unwrap().set_len(GC_FILE_MAX + 1).unwrap();
        assert_eq!(e.rt.gc(true, None).await.unwrap_err(), too_large(GC_FILE_MAX));
        // Out of time before the first directory is read.
        let err = e.rt.gc_within(true, None, GC_FILE_MAX, Duration::ZERO).await.unwrap_err();
        assert!(err.starts_with(&format!("stopped at {}: ", sessions.display())), "{err}");
        assert!(err.contains("took longer than 0 seconds; nothing was collected."), "{err}");
        assert!(store.read_all(&BlobId(orphan.clone())).is_ok());
        // Within the bounds, the orphan goes.
        std::fs::remove_file(&big).unwrap();
        assert_eq!(e.rt.gc(true, None).await.unwrap().collected, 1);
        assert!(store.read_all(&BlobId(orphan)).is_err());
        e.rt.shutdown().await;
    }

    #[test]
    fn gc_scan_blocks_on_no_fifo_and_follows_no_link_put_in_place_of_an_entry() {
        use std::os::unix::fs::{symlink, OpenOptionsExt};
        let dir = tempfile::tempdir().unwrap();
        let (root, out) = (dir.path().join("sessions"), dir.path().join("outside"));
        let jobs = root.join("s-1").join("jobs");
        std::fs::create_dir_all(&jobs).unwrap();
        std::fs::create_dir_all(&out).unwrap();
        let (named, elsewhere) = ("a".repeat(64), "b".repeat(64));
        let stored: loom_core::blob::StoredIds = [named.clone(), elsewhere.clone()].into_iter().collect();
        std::fs::write(jobs.join("j1.out"), &named).unwrap();
        std::fs::write(out.join("names.txt"), &elsewhere).unwrap();
        // Under a session directory: a FIFO, a link to it, and a link to a directory outside the tree.
        let fifo = jobs.join("pipe");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        symlink(&fifo, jobs.join("pipe-link")).unwrap();
        symlink(&out, jobs.join("out")).unwrap();
        // Roots, which the scan opens itself: the FIFO and a link to it, a link that loops, and a missing directory.
        // Only the missing one is an empty tree; the others stop the scan.
        let looping = dir.path().join("looping");
        symlink("looping", &looping).unwrap();
        let roots = [fifo.clone(), jobs.join("pipe-link"), looping, dir.path().join("missions")];
        let (tx, rx) = std::sync::mpsc::channel();
        let (fifo_in, jobs_in, roots_in) = (fifo.clone(), jobs.clone(), roots.clone());
        std::thread::spawn(move || {
            let bounds = ScanBounds { file_max: GC_FILE_MAX, time: GC_SCAN_TIME, started: std::time::Instant::now() };
            let mut keep = HashSet::new();
            let scanned = scan_tree_for_ids(&root, true, &stored, &mut keep, &bounds).map(|()| keep);
            let as_roots = roots_in.map(|r| {
                let mut keep = HashSet::new();
                (scan_tree_for_ids(&r, false, &stored, &mut keep, &bounds), keep)
            });
            // Opened as if each had been listed as a regular file and replaced before the open.
            let fifo_is_file = open_unblocked(&fifo_in, false).map(|(_, m)| m.is_file()).ok();
            let refused = |n: &str| open_unblocked(&jobs_in.join(n), false).err().and_then(|e| e.raw_os_error());
            let _ = tx.send((scanned, as_roots, fifo_is_file, [refused("pipe-link"), refused("out")]));
        });
        let Ok((scanned, as_roots, fifo_is_file, refused)) = rx.recv_timeout(Duration::from_secs(30)) else {
            // A reader stuck on the FIFO gets end-of-file once a writer has come and gone, so the thread ends.
            for _ in 0..50 {
                if std::fs::OpenOptions::new().write(true).custom_flags(libc::O_NONBLOCK).open(&fifo).is_ok() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            panic!("the scan blocked on a FIFO");
        };
        assert_eq!(scanned.unwrap(), HashSet::from([named]));
        let [fifo_root, link_root, looping_root, missing_root] = as_roots;
        for ((scanned, keep), root) in [fifo_root, link_root, looping_root].into_iter().zip(&roots) {
            let err = scanned.unwrap_err();
            assert!(err.starts_with(&format!("cannot read {} (", root.display())), "{err}");
            assert!(err.contains("nothing was collected") && keep.is_empty(), "{err}");
        }
        assert_eq!(missing_root, (Ok(()), HashSet::new()));
        // A link is not followed: `O_NOFOLLOW` refuses it.
        assert_eq!((fifo_is_file, refused), (Some(false), [Some(libc::ELOOP); 2]));
    }

    #[tokio::test]
    async fn shutdown_returns_with_a_turn_in_flight() {
        let e = env(Script::new(|_, _| Action::Stall { ms: 600_000 })).await;
        e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        until("request", || !e.server.requests().is_empty()).await;
        tokio::time::timeout(Duration::from_secs(30), e.rt.shutdown()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), e.rt.shutdown()).await.unwrap();
    }

    /// Shut the runtime down while a foreground command runs (its script writes its pid to `$PID`
    /// once it is ready). Returns how long the shutdown took and the session's log as it left it.
    async fn shutdown_during_a_foreground_command(script: &str, kill_grace_s: u64) -> (Duration, Vec<Record>) {
        let dir_for_pid = tempfile::tempdir().unwrap();
        let pid_file = dir_for_pid.path().join("pid");
        let cmd = format!("PID='{}'; {script}", pid_file.display());
        let e = env_with(Script::new(move |_, _| call("bash", json!({ "command": cmd }))), false, |c| {
            c.tools.kill_grace_s = kill_grace_s
        })
        .await;
        let id = e.rt.create_session(e.new_session(Some("go"))).await.unwrap().meta.id;
        until("the command started", || std::fs::read_to_string(&pid_file).is_ok_and(|t| !t.trim().is_empty())).await;
        let pid = std::fs::read_to_string(&pid_file).unwrap().trim().to_string();
        let begun = tokio::time::Instant::now();
        tokio::time::timeout(Duration::from_secs(60), e.rt.shutdown()).await.unwrap();
        let took = begun.elapsed();
        let alive = || {
            std::process::Command::new("kill")
                .args(["-0", &pid])
                .stderr(std::process::Stdio::null())
                .status()
                .is_ok_and(|s| s.success())
        };
        let end = tokio::time::Instant::now() + Duration::from_secs(10);
        while alive() {
            assert!(tokio::time::Instant::now() < end, "the foreground command survived the shutdown");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        (took, read_records(&e.rt.inner.paths.session_log(&id)).unwrap().records)
    }

    /// The session itself recorded the cut: the command's interrupted result, then the turn's end.
    fn assert_cut_by_the_session(records: &[Record]) {
        let kinds: Vec<String> = records
            .iter()
            .map(|r| serde_json::to_value(r).unwrap()["kind"].as_str().unwrap_or("").to_string())
            .collect();
        assert_eq!(&kinds[kinds.len() - 3..], ["tool_result", "interrupted", "turn_end"], "{kinds:?}");
        let result = records.iter().rev().find_map(|r| match &r.event {
            Event::ToolResult(t) => Some(t.status),
            _ => None,
        });
        // The command's own cancellation path produced the result: its token fired.
        assert_eq!(result, Some(loom_core::event::ToolStatus::Interrupted));
        assert!(cut_by_restart(records), "the turn is not recorded as cut by the restart");
    }

    #[tokio::test]
    async fn shutdown_cancels_a_running_tool_and_records_the_turn_as_cut_by_the_restart() {
        let (_, records) = shutdown_during_a_foreground_command("echo $$ > \"$PID\"; exec sleep 600", 1).await;
        assert_cut_by_the_session(&records);
    }

    #[tokio::test]
    async fn shutdown_waits_out_the_kill_grace_of_a_command_that_ignores_term() {
        let grace = SHUTDOWN_TASK_WAIT.as_secs() + 1;
        let (took, records) =
            shutdown_during_a_foreground_command("trap '' TERM; echo $$ > \"$PID\"; sleep 600", grace).await;
        // TERM did nothing, so the command lived until its KILL, which comes after the grace: the
        // task was given that long, although it is more than `SHUTDOWN_TASK_WAIT`.
        assert!(took >= Duration::from_secs(grace), "shutdown took {took:?}");
        assert_cut_by_the_session(&records);
    }
    #[tokio::test]
    async fn fresh_children_route_profiles_and_cross_profile_forks_fail_closed() {
        let other = MockServer::start(Script::new(|_, _| finish("other child"))).await.unwrap();
        let other_url = other.base_url();
        let e = env_with_packs(
            Script::new(|_, _| finish("primary child")),
            |c| {
                let mut p = c.models["mock"].clone();
                p.base_url = other_url;
                c.models.insert("other".into(), p);
            },
            |packs| {
                let path = packs.join("core/pack.toml");
                let text = std::fs::read_to_string(&path)
                    .unwrap()
                    .replace("[roles.worker]", "[roles.worker]\nalloy_models = [\"mock\", \"other\"]");
                std::fs::write(path, text).unwrap();
            },
        )
        .await;
        let parent = e.rt.create_session(e.new_session(None)).await.unwrap().meta.id;
        let req = SpawnReq {
            role: "worker".into(),
            mode: SpawnMode::Fresh,
            brief: Brief::default(),
            budget: Budget::default(),
            call_id: CallId::from("route"),
            title: "route".into(),
            awaited: true,
            harness: false,
            prerequisite: None,
            workspace: Workspace::Shared,
        };
        let first = e.rt.inner.orch.spawn(&parent, req.clone()).await.unwrap();
        let second = e.rt.inner.orch.spawn(&parent, req.clone()).await.unwrap();
        assert_eq!(e.rt.session(&first).unwrap().meta.profile, "mock");
        assert_eq!(e.rt.session(&second).unwrap().meta.profile, "other");
        until("other model request", || !other.requests().is_empty()).await;
        // Rotation slot 2 is primary; slot 3 would inherit a different wire prefix.
        let _ = e.rt.inner.orch.spawn(&parent, req.clone()).await.unwrap();
        let mut fork = req;
        fork.mode = SpawnMode::Fork;
        let error = e.rt.inner.orch.spawn(&parent, fork).await.unwrap_err();
        assert!(error.contains("mode `fresh`"), "{error}");
        assert!(other.requests().iter().all(|r| !r.to_string().contains("You are now a separate agent")));
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn verifier_profile_requirement_is_named_profile_not_a_family_guess() {
        let e = env_with_packs(
            Script::new(|_, _| finish("ready")),
            |_| {},
            |packs| {
                let path = packs.join("core/pack.toml");
                let text = std::fs::read_to_string(&path)
                    .unwrap()
                    .replace("[roles.lead]", "[roles.lead]\nrequire_distinct_verifier_profile = true");
                std::fs::write(path, text).unwrap();
            },
        )
        .await;
        let parent = e.rt.create_session(e.new_session(None)).await.unwrap().meta.id;
        let req = SpawnReq {
            role: "verifier".into(),
            mode: SpawnMode::Fresh,
            brief: Brief::default(),
            budget: Budget::default(),
            call_id: CallId::from("verify"),
            title: "verify".into(),
            awaited: true,
            harness: true,
            prerequisite: None,
            workspace: Workspace::Shared,
        };
        assert!(e.rt.inner.orch.spawn(&parent, req).await.unwrap_err().contains("distinct named profile"));
        assert!(e.server.requests().is_empty());
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn a_failed_role_escalates_only_the_next_fresh_assignment() {
        let other = MockServer::start(Script::new(|_, _| finish("escalated"))).await.unwrap();
        let other_url = other.base_url();
        let e = env_with_packs(
            Script::new(|_, _| Reply::text("no tool").into()),
            |c| {
                let mut p = c.models["mock"].clone();
                p.base_url = other_url;
                c.models.insert("other".into(), p);
                c.agents.max_nudges = 1;
            },
            |packs| {
                let path = packs.join("core/pack.toml");
                let text = std::fs::read_to_string(&path)
                    .unwrap()
                    .replace("[roles.worker]", "[roles.worker]\nescalation_model = \"other\"");
                std::fs::write(path, text).unwrap();
            },
        )
        .await;
        let parent = e.rt.create_session(e.new_session(None)).await.unwrap().meta.id;
        let req = SpawnReq {
            role: "worker".into(),
            mode: SpawnMode::Fresh,
            brief: Brief::default(),
            budget: Budget::default(),
            call_id: CallId::from("escalate"),
            title: "escalate".into(),
            awaited: true,
            harness: false,
            prerequisite: None,
            workspace: Workspace::Shared,
        };
        let first = e.rt.inner.orch.spawn(&parent, req.clone()).await.unwrap();
        let result = e.rt.inner.orch.join(&parent, &first, &CancellationToken::new()).await.unwrap();
        assert_eq!(result.outcome, ChildOutcome::Failed);
        let next = e.rt.inner.orch.spawn(&parent, req).await.unwrap();
        assert_eq!(e.rt.session(&first).unwrap().meta.profile, "mock");
        assert_eq!(e.rt.session(&next).unwrap().meta.profile, "other");
        assert_eq!(e.records(&next).iter().filter(|r| matches!(r.event, Event::Forked(_))).count(), 0);
        e.rt.shutdown().await;
    }

    /// Spawn a worker that hands its assignment off with `ask`, then another; the profile of the second.
    async fn profile_after_hand_off(ask: &str) -> String {
        let other = MockServer::start(Script::new(|_, _| finish("escalated"))).await.unwrap();
        let other_url = other.base_url();
        let ask = ask.to_string();
        let e = env_with_packs(
            Script::new(move |_, _| {
                call("hand_off", json!({"state": "half way", "leads": ["the lexer"], "ask": ask, "why": "stuck"}))
            }),
            |c| {
                let mut p = c.models["mock"].clone();
                p.base_url = other_url;
                c.models.insert("other".into(), p);
            },
            |packs| {
                let path = packs.join("core/pack.toml");
                let text = std::fs::read_to_string(&path)
                    .unwrap()
                    .replace("[roles.worker]", "[roles.worker]\nescalation_model = \"other\"");
                std::fs::write(path, text).unwrap();
            },
        )
        .await;
        let parent = e.rt.create_session(e.new_session(None)).await.unwrap().meta.id;
        let req = SpawnReq {
            role: "worker".into(),
            mode: SpawnMode::Fresh,
            brief: Brief::default(),
            budget: Budget::default(),
            call_id: CallId::from("hand-off"),
            title: "hand off".into(),
            awaited: true,
            harness: false,
            prerequisite: None,
            workspace: Workspace::Shared,
        };
        let first = e.rt.inner.orch.spawn(&parent, req.clone()).await.unwrap();
        let result = e.rt.inner.orch.join(&parent, &first, &CancellationToken::new()).await.unwrap();
        assert_eq!(result.outcome, ChildOutcome::Returned);
        assert!(result.report.starts_with("HANDED OFF"), "{}", result.report);
        let next = e.rt.inner.orch.spawn(&parent, req).await.unwrap();
        let profile = e.rt.session(&next).unwrap().meta.profile;
        e.rt.shutdown().await;
        profile
    }

    #[tokio::test]
    async fn a_hand_off_asking_for_a_stronger_model_escalates_the_next_assignment_of_that_role() {
        assert_eq!(profile_after_hand_off("stronger_model").await, "other");
        for ask in ["fresh_eyes", "hint", "more_steps"] {
            assert_eq!(profile_after_hand_off(ask).await, "mock", "{ask}");
        }
    }

    // ---- an agent's own copy of the workspace ----

    /// The text of a request's latest tool message.
    fn last_tool_text(body: &Value) -> String {
        let messages = body["messages"].as_array();
        let last = messages.and_then(|m| m.iter().rev().find(|m| m["role"] == "tool"));
        last.and_then(|m| m["content"].as_str()).unwrap_or("").to_string()
    }

    #[tokio::test]
    async fn an_agent_in_its_own_copy_changes_the_workspace_only_when_it_is_adopted() {
        let ws_at = Arc::new(Mutex::new(None::<PathBuf>));
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let (at, log) = (ws_at.clone(), seen.clone());
        let e = env(Script::new(move |body, _| {
            if !has_tool(body, "agent_spawn") {
                return if tool_msgs(body) == 0 {
                    call("bash", json!({"command": "pwd; echo two-longer > a.txt; echo new > b.txt"}))
                } else {
                    finish("child report")
                };
            }
            match tool_msgs(body) {
                0 => call("agent_spawn", json!({"question": "CHILDMARK", "workspace": "copy"})),
                1 => {
                    // What the workspace holds after the agent has ended and before anything is adopted.
                    let ws = at.lock().unwrap().clone().unwrap();
                    let mut log = log.lock().unwrap();
                    if log.is_empty() {
                        log.push(std::fs::read_to_string(ws.join("a.txt")).unwrap_or_default());
                        log.push(format!("b.txt there: {}", ws.join("b.txt").exists()));
                        log.push(last_tool_text(body));
                    }
                    call("agent_adopt", json!({"agent": "last"}))
                }
                _ => {
                    let mut log = log.lock().unwrap();
                    if log.len() == 3 {
                        log.push(last_tool_text(body));
                    }
                    finish("lead done")
                }
            }
        }))
        .await;
        std::fs::write(e.ws.join("a.txt"), "one\n").unwrap();
        *ws_at.lock().unwrap() = Some(e.ws.clone());
        let id = e.rt.create_session(e.new_session(Some("go"))).await.unwrap().meta.id;
        until("the lead finished", || {
            e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Finished }))
        })
        .await;
        let child = e.children(&id).pop().expect("the agent");
        // Its workspace is a copy beside the loom home, and its meta says what it is a copy of.
        let copy = Paths::at(e.dir.path().join("home")).agent_copy(&child.meta.mission, &child.meta.id);
        assert_eq!(child.meta.workspace, copy.display().to_string());
        let lead_ws = e.rt.session(&id).unwrap().meta.workspace;
        assert_eq!(child.meta.copy_of.as_deref(), Some(lead_ws.as_str()));
        assert!(copy.join("a.txt").is_file());
        // It was told so, and its command ran there.
        let reqs = e.server.requests();
        let told =
            reqs.iter().find(|b| !has_tool(b, "agent_spawn") && mentions(b, "CHILDMARK")).expect("child request");
        assert!(mentions(told, "You work in your own copy of the workspace"), "{told}");
        let ran = reqs.iter().find(|b| !has_tool(b, "agent_spawn") && tool_msgs(b) == 1).expect("after its command");
        let shown = last_tool_text(ran);
        let canonical = std::fs::canonicalize(&copy).unwrap();
        assert!(shown.contains(&canonical.display().to_string()), "{shown}");
        // Before the adoption the workspace was as it had been; the lead was shown what differs.
        let log = seen.lock().unwrap().clone();
        assert_eq!(log.len(), 4, "{log:?}");
        assert_eq!(log[0], "one\n");
        assert_eq!(log[1], "b.txt there: false");
        assert!(log[2].contains("===== report of agent"), "{}", log[2]);
        assert!(log[2].contains("2 files differ from your workspace"), "{}", log[2]);
        assert!(log[2].contains("M a.txt\nA b.txt"), "{}", log[2]);
        assert!(log[2].contains("- exit 0: `pwd; echo two-longer > a.txt; echo new > b.txt`"), "{}", log[2]);
        assert!(log[3].contains("adopted 2 files from"), "{}", log[3]);
        // After it, the workspace has the agent's files.
        assert_eq!(std::fs::read_to_string(e.ws.join("a.txt")).unwrap(), "two-longer\n");
        assert_eq!(std::fs::read_to_string(e.ws.join("b.txt")).unwrap(), "new\n");
        // The copy goes when the mission is archived.
        e.rt.archive(&id, true).await.unwrap();
        assert!(!copy.exists());
        assert!(e.ws.join("b.txt").is_file());
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn attempts_fork_into_copies_and_the_harness_checks_each() {
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let log = seen.clone();
        let e = env(Script::new(move |body, _| {
            if mentions(body, "This is attempt 1 of 2") {
                return if last_role(body) == "tool" {
                    finish("A report")
                } else {
                    call("bash", json!({"command": "touch done.txt"}))
                };
            }
            if mentions(body, "This is attempt 2 of 2") {
                return finish("B report");
            }
            match tool_msgs(body) {
                0 => call("attempt", json!({"question": "make done.txt", "n": 2, "check": "test -f done.txt"})),
                1 => {
                    let text = last_tool_text(body);
                    let section = text.split("===== attempt 1 of 2: ").nth(1).unwrap_or("");
                    let winner = section.split(' ').next().unwrap_or("").to_string();
                    let mut log = log.lock().unwrap();
                    if log.is_empty() {
                        log.push(text);
                    }
                    call("agent_adopt", json!({"agent": winner}))
                }
                _ => finish("lead done"),
            }
        }))
        .await;
        std::fs::write(e.ws.join("a.txt"), "one\n").unwrap();
        let id = e.rt.create_session(e.new_session(Some("go"))).await.unwrap().meta.id;
        until("the lead finished", || {
            e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Finished }))
        })
        .await;
        let children = e.children(&id);
        assert_eq!(children.len(), 2);
        for c in &children {
            assert_eq!(c.meta.mode, Some(SpawnMode::Fork));
            assert!(c.meta.copy_of.is_some());
            assert!(c.meta.title.starts_with("attempt "), "{}", c.meta.title);
        }
        let log = seen.lock().unwrap().clone();
        let text = log.first().expect("the result of attempt");
        assert!(text.contains("2 attempts: 1 passed the check"), "{text}");
        let second = text.find("===== attempt 2 of 2: ").expect("the second section");
        assert!(text[..second].contains("check: exit 0") && text[..second].contains("passed"), "{text}");
        assert!(text[..second].contains("changed: 1 file (1 added)\nA done.txt"), "{text}");
        assert!(text[..second].contains("report:\n") && text[..second].contains("> A report"), "{text}");
        assert!(text[second..].contains("check: exit 1") && text[second..].contains("FAILED"), "{text}");
        assert!(text[second..].contains("changed: nothing"), "{text}");
        // Only the adopted attempt's file is in the workspace.
        assert!(e.ws.join("done.txt").is_file());
        // Both attempts started from the lead's request: its system message, then its conversation,
        // with the assignment after it.
        let reqs = e.server.requests();
        let lead = reqs.iter().find(|b| !mentions(b, "This is attempt") && tool_msgs(b) == 0).expect("lead request");
        for n in 1..=2 {
            let mark = format!("This is attempt {n} of 2");
            let first = reqs.iter().find(|b| mentions(b, &mark)).expect("attempt request");
            assert_eq!(first["messages"][0], lead["messages"][0]);
            let said = first["messages"][1]["content"].as_str().unwrap_or_default();
            assert!(said.starts_with("go\n") && said.contains("You work in your own copy of the workspace"), "{said}");
        }
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn a_copy_is_refused_for_a_role_that_only_reads_and_for_a_workspace_past_the_limit() {
        let e = env_with(
            Script::new(|body, _| match tool_msgs(body) {
                0 => call("agent_spawn", json!({"question": "q", "role": "verifier", "workspace": "copy"})),
                1 => call("agent_spawn", json!({"question": "q", "workspace": "copy"})),
                _ => finish("lead done"),
            }),
            false,
            |c| c.agents.copy_max_files = 2,
        )
        .await;
        for name in ["a.txt", "b.txt", "c.txt"] {
            std::fs::write(e.ws.join(name), "x\n").unwrap();
        }
        let id = e.rt.create_session(e.new_session(Some("go"))).await.unwrap().meta.id;
        until("the lead finished", || {
            e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Finished }))
        })
        .await;
        let reqs = e.server.requests();
        let first = last_tool_text(reqs.iter().find(|b| tool_msgs(b) == 1).expect("after the first refusal"));
        assert!(first.contains("A `verifier` agent only reads the workspace"), "{first}");
        let second = last_tool_text(reqs.iter().find(|b| tool_msgs(b) == 2).expect("after the second refusal"));
        assert!(second.contains("more than 2 files") && second.contains("agents.copy_max_files"), "{second}");
        // Neither left an agent, a slot or a directory behind.
        assert!(e.children(&id).is_empty());
        let copies = Paths::at(e.dir.path().join("home")).copies_dir();
        let left =
            std::fs::read_dir(&copies).map(|d| d.flatten().flat_map(|m| std::fs::read_dir(m.path())).flatten().count());
        assert_eq!(left.unwrap_or(0), 0, "{}", copies.display());
        e.rt.shutdown().await;
    }

    #[test]
    fn a_sessions_own_commands_are_read_from_its_log() {
        let rec = |seq: u64, ts_ms: u64, event: Event| Record {
            seq,
            ts_ms,
            author: Author::Harness,
            prev: String::new(),
            event,
        };
        let call_of = |id: &str, name: &str, args: Value| {
            Event::ToolCall(loom_core::event::ToolCall {
                call_id: CallId::from(id),
                req_id: "r".into(),
                name: name.into(),
                args,
                class: ToolClass::Exec,
            })
        };
        let result_of = |id: &str, name: &str, meta: Value| {
            let mut r: loom_core::event::ToolResult = serde_json::from_value(json!({
                "call_id": id, "name": name, "class": "exec", "status": "ok", "text": "t",
            }))
            .expect("a tool result");
            r.meta = meta.as_object().cloned().unwrap_or_default();
            Event::ToolResult(r)
        };
        let records = vec![
            rec(0, 10, call_of("c1", "bash", json!({"command": "make test"}))),
            rec(1, 11, result_of("c1", "bash", json!({ META_EXIT_CODE: 2 }))),
            // A command that became a job carries no end, and another tool is not a command.
            rec(2, 20, call_of("c2", "bash", json!({"command": "sleep 100"}))),
            rec(3, 21, result_of("c2", "bash", json!({ "job": "j1" }))),
            rec(4, 30, call_of("c3", "read", json!({"path": "a"}))),
            rec(5, 31, result_of("c3", "read", json!({ META_EXIT_CODE: 0 }))),
            rec(6, 40, call_of("c4", "bash", json!({"command": "kill -9 $$"}))),
            rec(7, 41, result_of("c4", "bash", json!({ META_SIGNAL: 9 }))),
        ];
        let runs = runs_of(&records);
        assert_eq!(
            runs,
            vec![
                Run { command: "make test".into(), started_ms: 10, exit_code: Some(2), output: None },
                Run { command: "kill -9 $$".into(), started_ms: 40, exit_code: None, output: None },
            ]
        );
    }

    #[test]
    fn copies_are_kept_out_of_replays_and_a_copy_cannot_write_to_its_source() {
        let base = SandboxCfg { replay_untrusted_paths: vec!["/x".into()], ..SandboxCfg::default() };
        let shared = with_copies(base.clone(), Path::new("/h-copies"), None);
        assert_eq!(shared.replay_untrusted_paths, ["/x", "/h-copies"]);
        assert_eq!(shared.protected_paths, base.protected_paths);
        let copy = with_copies(shared.clone(), Path::new("/h-copies"), Some("/ws"));
        assert_eq!(copy.replay_untrusted_paths, ["/x", "/h-copies"]);
        assert_eq!(copy.protected_paths, ["/ws"]);
    }
}
