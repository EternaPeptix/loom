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
//! - `meta.json` — [`SessionMeta`], written when the session is created; rewritten only by
//!   [`Runtime::archive`]. Writes are atomic (temporary file in the same directory, then rename).
//! - `status.json` — the latest [`Status`](crate::session::Status), rewritten atomically whenever
//!   the session publishes one.
//! - `net.jsonl` — one [`NetEntry`] per line, hash-chained (`prev`): every decision the egress proxy
//!   made for the session.
//! - `settlement.json` — a child's [`Settlement`](crate::rtools::Settlement), written atomically
//!   when its task ends with one. Read only when a delivery lost to a restart is recovered (see
//!   *Start*), so that the parent gets the whole report. A child that ended without the file (a
//!   crash between its `session_end` and the write, or a log from before the file existed) is
//!   recovered from its log instead, with the first line of its report.
//! - `tmp/` (`paths.session_tmp`) — the session's scratch directory; `jobs/` — its job table's files.
//! - `queued/` — operator rules, approvals and withdrawals handed to the session and not recorded
//!   yet, one JSON file each (`session::queue_input`); the session deletes each once recorded.
//!
//! A session directory without a readable `meta.json` is ignored (`tracing::warn!`).
//!
//! ## Active sessions
//! A session is *active* when a task is driving it (`Session::run`). The runtime keeps, per active
//! session: the sender of its inputs, its `Control`, its `Arc<Shared>`, its job table, its latest
//! status, and for a child its settlement once there is one. Sessions that are not active are known
//! from `meta.json` and `status.json` only.
//!
//! *Activating* a session = building its `Deps` (below), `Session::open`, spawning the task.
//! Activating a child first activates its parent. Activation happens:
//! - at start, for every session that is not archived and whose `status.json` says `phase ==
//!   Running`, or `last_end == Waiting`, or `open_inbox > 0`, or `last_end == Yielded` while its log
//!   holds a `job_registered` with no `job_settled` (the job's end would have started a turn; the
//!   log is read only when the session's `jobs/` directory is not empty), and for every child that
//!   has not ended, whatever it was doing (parents before children — session ids sort by creation
//!   time);
//! - on demand, by `send_message`, `resume`, `reweave`, `answer`, and when a settlement has to be
//!   delivered to a parent that is not active.
//!
//! A session whose `status.json` says `phase == Ended` is never activated. Neither is a session of
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
//!   **root** session's role has `Termination::Explicit`, for the root and all its children; `None`
//!   otherwise. `key` = `journal::load_or_create_key(paths.journal_key())`, read once at start.
//!   The orchestrator handed to `Shared` must not keep the runtime alive in a reference cycle
//!   (hold a `Weak`, and answer "The harness is shutting down." when it is gone).
//! - `ctx`: `ToolCtx{session, call_id: empty, workspace (canonical), tmp_dir: paths.session_tmp(id)
//!   (created, canonical), blobs: BlobStore::open(paths.blobs_dir()), cfg: tools config, sandbox,
//!   env, files: new FileTracker, jobs: JobTable::new(<session dir>/jobs, blobs, sender,
//!   tools.max_output_bytes), cancel: new token}`.
//!   - `sandbox`: `Sandbox::new(&cfg, workspace, tmp_dir, paths.home, Some(proxy port))` with the
//!     config's `SandboxCfg`; for a role with `read_only`, `extra_writable` is emptied and the
//!     workspace is added to `protected_paths`; every model profile's `api_key_env` name is added to
//!     `secret_env`, so commands never see it.
//!   - `env`: the session's proxy grant (`proxy.grant(id, Policy::new(&config.network))`), `env()`.
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
//! 4. `SessionStart{session, mission, parent: None, workspace, pack, role, termination,
//!    model: ModelRef{profile, model, context_window}, reasoning_replay (profile),
//!    system_prompt: pack::system_prompt(role, &pack.preamble, &PromptEnv{workspace,
//!    platform: "{OS} ({ARCH})" from std::env::consts, sandbox: sandbox.describe(),
//!    network: texts::network_sentence(mode, allow, deny, allow_private)}), tools: empty,
//!    budget, unattended (default: the role's termination is `Explicit`), title}`.
//! 5. `Session::create(deps, start, None)`, write `meta.json`, spawn the task, publish
//!    [`BusEvent::Session`]. With a `message`: `send_message`.
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
//! - a request with `harness: true` (the finish gate's verifier) is exempt from both of the last two rules.
//! - `SpawnMode::Fork`: the parent's status must have a `fork_point`, and every tool of the child
//!   role must be among the parent role's tools; otherwise `A `{role}` agent cannot be forked from
//!   this session: it needs tools this session does not have ({list}). Start it with mode `fresh`
//!   and put what it needs to know in the assignment.` The child is
//!   `Session::fork(deps, &paths.session_log(parent), fork_point, Forked{session, parent, upto_seq:
//!   fork_point, role, termination, budget, brief, contract: texts::fork_contract(role name, role
//!   prompt, role tools), allowed_tools: Some(role tools), title})`.
//! - `SpawnMode::Fresh`: `Session::create(deps, SessionStart{… as for a root, with the child's
//!   role and system prompt, parent: Some(parent), the parent's mission, workspace, model and
//!   `unattended`, budget: req.budget, title: req.title}, Some((parent,
//!   weave::render_brief(&req.brief))))`.
//! - Then: `meta.json` (`mode`, `awaited`), spawn the task (a child starts its first turn by
//!   itself), publish `BusEvent::Session`, and queue in the parent's log
//!   `parent_shared.emit(Author::Harness, Event::ChildSpawned(ChildSpawned{child, role, mode, brief,
//!   budget, call_id}))`. Return the child's id.
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
//! archived) is delivered when the lead is unarchived or by the next start. A verifier the finish
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
//! stored); a `job_settled` whose output is `blob`, credited to the call named by the `job_registered`
//! of that job (`bash`, class `Exec`). Views of runtime tools register nothing.
//! `Producer{session, call_id, tool: name, class}`. Kept as an in-memory index fed by
//! every record that passes through the sink; on a miss for a mission whose logs have not been
//! scanned since start, scan the logs of all its sessions once, then answer.
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
//! One `loom_net::Proxy` for the runtime (`config.daemon.proxy_port`). Every decision it reports is
//! appended to the session's `net.jsonl` and published as [`BusEvent::Net`]. Decisions that name no
//! session are appended to `logs/net-unattributed.jsonl`.
//!
//! ## Notifying the operator
//! For every `inbox_opened` and every `End::Fatal`. `kind` is the inbox kind in snake case
//! (`question`, `blocker`, `parked`, `finished`, `approval`) or `error`.
//! - `config.notify.command` not empty: run it (no shell) with the environment extended by
//!   `LOOM_KIND`, `LOOM_SESSION`, `LOOM_TITLE` (session title) and `LOOM_TEXT` (the item's text cut
//!   to 500 characters); stdin closed; killed after 30 s; failure is a `tracing::warn!`.
//! - empty, on macOS: `/usr/bin/osascript -e 'on run argv' -e 'display notification (item 2 of
//!   argv) with title (item 1 of argv)' -e 'end run' "loom: {kind} — {title}" "{text cut to 200}"`
//!   (the texts are arguments, never part of the script). Elsewhere: nothing.
//! - `config.notify.repeat_minutes > 0`: while a blocking item stays open, notify again every that
//!   many minutes.
//! - The text of an item opened by a tool call (a question, blocker or finish the model wrote)
//!   starts with `[From the agent, unverified] `; items the harness opened itself are unchanged.
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
//!   does (an unattended mission's go on at once).
//!   Archived sessions are listed only by `sessions(true)` and are not activated at start;
//!   `send_message`/`resume` on one are refused (`This session is archived; unarchive it first.`).
//!
//! ## Start (`Runtime::start`)
//! 1. `config.check()`; create the directories; load packs (`Packs::load(paths.packs_dir())`) and
//!    check every role's tools against `Registry::builtin().names()` plus `rtools::NAMES`; journal
//!    key; blob store; clients and limiters; proxy.
//! 2. Read every session's `meta.json` and `status.json` (missing status = default idle status).
//! 3. Activate as described under *Active sessions*. A session that cannot be opened is skipped
//!    with `tracing::error!` and a `BusEvent::Error`; a child that cannot be opened while its lead
//!    can will never run again, and is settled on its behalf: `Failed`, report
//!    `texts::unopenable_report(error)`, kept in `settlement.json`, status `Ended`/`Failed`. Before
//!    that, off the async workers, what a previous daemon left in the `jobs/` of every other session
//!    that is not archived is cleared (`loom_tools::jobs::clear_leftovers`, logged); a session to
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
//!    or `Yielded` and `open` told it of a lost job (`Session::lost_jobs() > 0`: the job's end
//!    would have started a turn). A session whose last turn ended `Waiting` or `Yielded` and to which
//!    a lost delivery is recovered (below) is not told to carry on — the delivery starts its turn —
//!    but counts as carrying on for its children.
//!
//!    A restored child that has had a turn is idle (the restart cut its turn, or it was between
//!    turns) and is *held*: it is told to carry on now when it was told of a lost job, when its
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
//!    the finish gate (known from the `child_spawned` record of a `finish` call). A settlement made
//!    during this pass is left to this recovery.
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
//! which ends every idle session cleanly. Wait up to `tools.kill_grace_s` + `SHUTDOWN_TASK_WAIT`
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
//!   recently paged sessions keep theirs.
//! - `window(id)`: `log::read_records` → `weave` → [`WindowView`] (`est_tokens` with a default
//!   `TokenEstimator` over the messages plus the tool specs' JSON).
//! - `missions()`: one per root session. `ledger(mission)`: the journal read and folded
//!   (`No ledger: this mission's lead does not keep one.` when there is no journal file and the
//!   lead's role keeps none or can no longer be looked up; a lead that keeps one but has no journal
//!   file yet has an empty ledger). The id
//!   must be the mission of a known session, checked before a path is made from it (`There is no
//!   mission {id}.`).
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
//! - stop: stopping the lead while its awaited child is mid-request settles the child `Stopped`
//!   and ends the lead's turn `Stopped`; `stop_child` on an idle child settles it;
//! - `poll`: `k` requests whose messages equal the session's stable prefix plus the vote prompt,
//!   distinct seeds, votes parsed, a failed request counted as no choice;
//! - `producer`: found through the live index and, after a restart, through the scan;
//! - inbox: a `finish` opens an item and notifies (the command's file has the kind); `answer`
//!   resolves it; an empty answer dismisses a non-blocking item without a turn and is refused for a
//!   blocking one;
//! - restart: a runtime shut down mid-turn and started again over the same home resumes an
//!   unattended session by itself (next request carries the `AFTER_RESTART` note) and leaves an
//!   attended one idle; open inbox items are back; an ended child is not activated;
//! - a read-only role's sandbox configuration protects the workspace; every session's environment
//!   names the proxy;
//! - `archive` hides, refuses messages, and survives a restart;
//! - `records` paging and `window` totals; `ledger` after a goal was set by the first message.

use crate::pack::{self, PromptEnv, RoleDef, Packs};
use crate::rtools::{self, ChildInfo, Orchestrator, Producer, Settlement, Shared, SpawnReq, Vote};
use crate::session::{queue_input, Control, Deps, End, Input, Phase, Session, Sink, Status};
use crate::texts;
use async_trait::async_trait;
use futures_util::FutureExt;
use loom_core::config::{Config, NetworkMode, Paths, SandboxCfg};
use loom_core::estimate::TokenEstimator;
use loom_core::event::{
    Author, Brief, Budget, ChildOutcome, ChildSettled, ChildSpawned, Event, Forked, InboxItem, ModelRef, NetDecision,
    Record, Seq, SessionOutcome, SessionStart, SpawnMode, Termination, ToolClass, ToolStatus, TurnEndReason, Usage,
    META_OF_BLOB,
};
use loom_core::journal::{self, Journal};
use loom_core::ledger::LedgerState;
use loom_core::log::{read_records, Durability, PageReader, SessionLog};
use loom_core::weave::{render_brief, weave, WindowItem};
use loom_core::{now_ms, BlobId, BlobStore, CallId, MissionId, SessionId};
use loom_model::{ChatRequest, Discovered, Limiter, ModelClient, ModelError, Priority, StreamEvent, ToolChoice};
use loom_net::policy::Policy;
use loom_net::proxy::Proxy;
use loom_tools::jobs::JobTable;
use loom_tools::sandbox::Sandbox;
use loom_tools::ToolCtx;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
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
}

/// `meta.json`: what a session is, fixed when it is created.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SessionMeta {
    pub id: SessionId,
    pub mission: MissionId,
    #[serde(default)]
    pub parent: Option<SessionId>,
    pub workspace: String,
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
    Session { info: Box<SessionInfo> },
    Record { session: SessionId, record: Box<Record> },
    Delta { session: SessionId, req_id: String, delta: Delta },
    Status { session: SessionId, status: Status },
    Net { session: SessionId, entry: NetEntry },
    /// A child settled (also visible as records; this is for listings).
    Settled { session: SessionId, settlement: Box<Settlement> },
    Error { session: Option<SessionId>, message: String },
    /// Never published by the runtime. The API sends it to a subscriber that fell behind and
    /// missed `missed` events; the subscriber should fetch what it shows again.
    Lagged { missed: u64 },
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

/// The stored output an event makes citable as evidence, and what produced it. A result's own
/// output; the text a `read` showed (the result is a view, `META_OF_BLOB` names the stored file text);
/// the complete output of a background job, attributed to the call that started it (`jobs` is filled by
/// `job_registered`, which states that call, and emptied by `job_settled`; only `bash` starts jobs). A
/// view of a runtime tool's output (`out_read`, `out_grep`) is not an observation and registers nothing.
fn produced_by(
    session: &SessionId,
    jobs: &mut HashMap<(SessionId, String), Producer>,
    event: &Event,
) -> Option<(BlobId, Producer)> {
    match event {
        Event::ToolResult(t) => {
            let p = Producer { session: session.clone(), call_id: t.call_id.clone(), tool: t.name.clone(), class: t.class };
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
            let p = Producer { session: session.clone(), call_id: call_id.clone(), tool: "bash".into(), class: ToolClass::Exec };
            jobs.insert((session.clone(), job_id.clone()), p);
            None
        }
        Event::JobSettled { job_id, output, .. } => {
            let p = jobs.remove(&(session.clone(), job_id.clone()))?;
            output.as_ref().map(|o| (o.id.clone(), p))
        }
        _ => None,
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
        cfg.extra_writable.clear();
        cfg.protected_paths.push(workspace.display().to_string());
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
    /// The finish gate of its parent started it, with this assignment (known from the parent's log
    /// for an agent restored from disk). Its settlement belongs to the `finish` that waits for it: it
    /// is never delivered as an agent report, and the parent's agent listing leaves it out.
    gate: Option<Brief>,
}

impl Known {
    fn new(meta: SessionMeta, status: Status) -> Known {
        let (settled_tx, _) = watch::channel(None);
        Known {
            meta,
            status,
            active: None,
            settlement: None,
            settled_tx,
            joined: false,
            restored: false,
            held: false,
            gate: None,
        }
    }

    fn finished(&self) -> bool {
        self.settlement.is_some() || self.status.phase == Phase::Ended
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
    inbox: Vec<InboxEntry>,
    producers: HashMap<(MissionId, BlobId), Producer>,
    scanned: HashSet<MissionId>,
    /// The call that started each background job, by session and job id (for the job's complete output).
    job_starts: HashMap<(SessionId, String), Producer>,
    /// Background tasks (net forwarder, notification repeaters).
    tasks: Vec<JoinHandle<()>>,
    /// Sessions whose task waits in a `join` that shutdown cancelled and that will not return.
    parked: HashSet<SessionId>,
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
    /// `open` recorded lost jobs for a session that was waiting (it has to be woken).
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
    /// Held while sessions are activated (never across an `.await`).
    activation: Mutex<()>,
    shutting: AtomicBool,
    /// The start-up pass has not looked at the leads' logs yet: a settlement made until then is left
    /// for its recovery to deliver (see `record_settlement`).
    restoring: AtomicBool,
    next_gen: AtomicU64,
    orch: Arc<dyn Orchestrator>,
    sink: Arc<dyn Sink>,
    /// Paging state per recently viewed session, least recently used first.
    pagers: Mutex<Vec<(SessionId, Arc<Mutex<PageReader>>)>>,
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
                StreamEvent::ToolCallStart { index, name } => Delta::ToolCallStart { index: *index, name: name.clone() },
                StreamEvent::ToolCallArgs { index, delta } => Delta::ToolCallArgs { index: *index, text: delta.clone() },
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
            return inner.spawn_child(parent, req);
        }
        if let Some(verifier) = inner.cut_verifier(parent, &req.role, &req.brief) {
            // The finish waits for it now: one the restart left idle goes on (an ended one has its verdict).
            inner.resume_held(&verifier);
            return Ok(verifier);
        }
        let brief = req.brief.clone();
        let child = inner.spawn_child(parent, req)?;
        if let Some(k) = inner.st().known.get_mut(&child) {
            k.gate = Some(brief);
        }
        Ok(child)
    }

    async fn join(&self, parent: &SessionId, child: &SessionId, cancel: &CancellationToken) -> Result<Settlement, String> {
        let inner = self.0.upgrade().ok_or_else(|| SHUTTING.to_string())?;
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
            return Err("Nothing has been sent to the model in this session yet, so there is nothing to vote on.".to_string());
        };
        let rt = inner.profiles.get(&profile).ok_or_else(|| format!("model profile \"{profile}\" is not configured."))?;
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
        let ids = {
            let st = inner.st();
            if let Some(p) = st.producers.get(&key) {
                return Some(p.clone());
            }
            if st.scanned.contains(mission) {
                return None;
            }
            st.known.iter().filter(|(_, k)| &k.meta.mission == mission).map(|(id, _)| id.clone()).collect::<Vec<_>>()
        };
        let paths = inner.paths.clone();
        let found = tokio::task::spawn_blocking(move || {
            let mut out: Vec<(BlobId, Producer)> = Vec::new();
            let mut jobs: HashMap<(SessionId, String), Producer> = HashMap::new();
            for id in ids {
                let Ok(report) = read_records(&paths.session_log(&id)) else { continue };
                for r in own_records(&report.records) {
                    out.extend(produced_by(&id, &mut jobs, &r.event));
                }
            }
            out
        })
        .await
        .unwrap_or_default();
        let mut st = inner.st();
        for (b, p) in found {
            let mission = st.known.get(&p.session).map(|k| k.meta.mission.clone());
            if let Some(m) = mission {
                st.producers.entry((m, b)).or_insert(p);
            }
        }
        st.scanned.insert(mission.clone());
        st.producers.get(&key).cloned()
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

    /// `child` must be an unsettled child of `parent`; the error is a sentence for the model.
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

    // ---- sink -------------------------------------------------------------------------------

    fn on_record(self: &Arc<Self>, session: &SessionId, record: &Record) {
        let mut opened: Option<(InboxItem, String)> = None;
        {
            let mut st = self.st();
            let found = st.known.get(session).map(|k| (k.meta.mission.clone(), k.meta.title.clone()));
            if let Some((mission, title)) = found {
                match &record.event {
                    Event::ToolResult(_) | Event::JobRegistered { .. } | Event::JobSettled { .. } => {
                        if let Some((blob, p)) = produced_by(session, &mut st.job_starts, &record.event) {
                            st.producers.entry((mission.clone(), blob)).or_insert(p);
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
        let (kind, session, title, text) = (kind.to_string(), session.as_str().to_string(), title.to_string(), text.to_string());
        tokio::spawn(async move { run_notify(command, kind, session, title, text).await });
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
    /// records, without which the next start would not read its log for a lost job (`has_unsettled_job`).
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
                    tracing::warn!(
                        session = id.as_str(),
                        "cleared {} command(s) a previous daemon left behind: {killed} killed, {left} left alone because their process group could not be confirmed",
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
        let cfg = sandbox_cfg_for(&self.config.sandbox, &role, &workspace, &self.config.models);
        let sandbox = Sandbox::new(&cfg, &workspace, &tmp, &self.paths.home, Some(self.proxy.port()))
            .map_err(|e| format!("The sandbox for this session cannot be set up: {e}"))?;
        let policy = Policy::new(&self.config.network)?;
        let (events_tx, job_events) = unbounded_channel();
        let jobs = Arc::new(JobTable::new(
            self.paths.session_dir(id).join("jobs"),
            self.blobs.clone(),
            events_tx,
            self.config.tools.max_output_bytes,
        ));
        let grant = self.proxy.grant(id, policy);
        let ctx = ToolCtx {
            session: id.clone(),
            call_id: CallId::from(""),
            workspace,
            tmp_dir: tmp,
            blobs: self.blobs.clone(),
            cfg: Arc::new(self.config.tools.clone()),
            sandbox: Arc::new(sandbox),
            env: Arc::new(grant.env()),
            files: Arc::new(loom_tools::files::FileTracker::new()),
            jobs: jobs.clone(),
            cancel: CancellationToken::new(),
        };
        // The mission journal is shared by the lead and all its children.
        let journal = explicit.then(|| Journal::new(self.paths.journal(&meta.mission), self.key.clone()));
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
        let replay = self
            .config
            .models
            .get(&meta.profile)
            .map(|p| p.reasoning_replay)
            .unwrap_or_default();
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
        let woken = session.lost_jobs() > 0 && matches!(status.last_end, Some(TurnEndReason::Waiting | TurnEndReason::Yielded));
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
                let title = self.st().known.get(id).map(|k| (k.meta.title.clone(), k.meta.parent.is_some(), k.meta.role.clone(), k.status.step));
                match title {
                    Some((title, is_child, role, steps)) => {
                        if !self.shutting.load(Ordering::SeqCst) {
                            self.notify("error", id, &title, &e);
                        }
                        if is_child {
                            self.mark_failed(id);
                        }
                        is_child.then(|| Settlement {
                            child: id.clone(),
                            role,
                            outcome: ChildOutcome::Failed,
                            report: texts::failed_report(&e, ""),
                            full: None,
                            payload: serde_json::Value::Null,
                            steps,
                            usage: Usage::default(),
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
        let (parent, deliver) = {
            let mut st = self.st();
            let Some(k) = st.known.get_mut(id) else { return };
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
            (k.meta.parent.clone(), deliver)
        };
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
                tracing::warn!("the settlement of {} cannot be delivered to {}: {e}", s.child.as_str(), parent.as_str());
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

    fn spawn_child(self: &Arc<Self>, parent: &SessionId, req: SpawnReq) -> Result<SessionId, String> {
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
                    return Err(format!("`{}` is not a role this session can start. Roles it can start: {list}.", req.role));
                }
            };
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
                let missing: Vec<&String> = crole.tools.iter().filter(|t| !prole.tools.contains(t)).collect();
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
            let meta = SessionMeta {
                id: child_id.clone(),
                mission: p.meta.mission.clone(),
                parent: Some(parent.clone()),
                workspace: p.meta.workspace.clone(),
                pack: p.meta.pack.clone(),
                role: crole.name.clone(),
                profile: p.meta.profile.clone(),
                model: p.meta.model.clone(),
                context_window: p.meta.context_window,
                title: req.title.clone(),
                created_ms: now_ms(),
                mode: Some(req.mode),
                awaited: req.awaited,
                unattended: p.meta.unattended,
                archived: false,
            };
            let explicit = prole.termination == Termination::Explicit;
            st.known.insert(child_id.clone(), Known::new(meta.clone(), idle_status()));
            (meta, crole, fork_point, shared, explicit)
        };
        let forget = |this: &Inner| {
            this.proxy.revoke(&child_id);
            this.st().known.remove(&child_id);
        };
        let (deps, parts) = match self.build(&meta, explicit) {
            Ok(x) => x,
            Err(e) => {
                forget(self);
                return Err(e);
            }
        };
        let created = match fork_point {
            Some(upto) => {
                let tools = crole.tools.clone();
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
        let rt = self.profiles.get(profile_name).ok_or_else(|| format!("The model profile \"{profile_name}\" is not configured."))?;
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
        let candidates: Vec<(SessionId, SessionId, SessionMeta, bool)> = {
            let st = self.st();
            st.known
                .iter()
                .filter_map(|(id, k)| {
                    let parent = k.meta.parent.clone()?;
                    let parent_ok = st.known.get(&parent).is_some_and(|p| !p.meta.archived && p.status.phase != Phase::Ended);
                    let wanted = scope(k) && !k.joined && !k.meta.archived && parent_ok;
                    wanted.then(|| (id.clone(), parent, k.meta.clone(), k.finished()))
                })
                .collect()
        };
        // First what the leads' logs say about each agent; then the deliveries.
        let mut seen: HashMap<SessionId, Spawns> = HashMap::new();
        let mut open: Vec<(SessionId, SessionId, SessionMeta, bool)> = Vec::new();
        for (id, parent, meta, ended) in candidates {
            let spawns = seen.entry(parent.clone()).or_insert_with(|| {
                read_records(&self.paths.session_log(&parent)).map(|r| Spawns::of(&r.records)).unwrap_or_default()
            });
            let gate = spawns.gate.get(&id).cloned();
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
            if !had {
                open.push((id, parent, meta, gate.is_some()));
            }
        }
        // From here on a settlement is delivered as it is made; what settled before is delivered
        // below. The claim each delivery takes under the state lock makes it one.
        self.restoring.store(false, Ordering::SeqCst);
        for (id, parent, meta, gate) in open {
            let (kept, ended) = match self.st().known.get(&id) {
                Some(k) => (k.settlement.clone(), k.status.phase == Phase::Ended || k.settlement.is_some()),
                None => continue,
            };
            if !ended {
                continue;
            }
            // What the child's task handed over when it ended. Without it (see *Files*) the child's
            // log gives the outcome and the first line of the report.
            let persisted = kept.or_else(|| {
                read_json::<Settlement>(&self.paths.session_dir(&id).join("settlement.json")).filter(|p| p.child == id)
            });
            let s = match persisted {
                Some(s) => s,
                None => {
                    let Ok(report) = read_records(&self.paths.session_log(&id)) else { continue };
                    let own = own_records(&report.records);
                    let blocked = own
                        .iter()
                        .rev()
                        .find_map(|r| match &r.event {
                            Event::TurnEnd { reason } => Some(*reason == TurnEndReason::Blocked),
                            _ => None,
                        })
                        .unwrap_or(false);
                    let end = own.iter().rev().find_map(|r| match &r.event {
                        Event::SessionEnd { outcome, detail } => Some((*outcome, detail.clone())),
                        _ => None,
                    });
                    let Some((outcome, detail)) = end else { continue };
                    let outcome = if blocked { ChildOutcome::Blocked } else { child_outcome_of(outcome) };
                    let steps = self.st().known.get(&id).map(|k| k.status.step).unwrap_or(0);
                    let text = if detail.trim().is_empty() { texts::stopped_report(steps) } else { detail };
                    Settlement {
                        child: id.clone(),
                        role: meta.role.clone(),
                        outcome,
                        report: text,
                        full: None,
                        payload: serde_json::Value::Null,
                        steps,
                        usage: Usage::default(),
                    }
                }
            };
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

    /// Whether the session's log holds a job that was registered and never settled. The log is read
    /// only when the session's jobs directory holds something. Every command leaves its files there,
    /// a foreground one as well as a background job, so this passes over only the sessions that never
    /// ran a command; for the others the log decides.
    fn has_unsettled_job(&self, id: &SessionId) -> bool {
        let jobs = self.paths.session_dir(id).join("jobs");
        if !std::fs::read_dir(jobs).is_ok_and(|mut entries| entries.next().is_some()) {
            return false;
        }
        let Ok(report) = read_records(&self.paths.session_log(id)) else { return false };
        let own = own_records(&report.records);
        let settled: HashSet<&str> = own
            .iter()
            .filter_map(|r| match &r.event {
                Event::JobSettled { job_id, .. } => Some(job_id.as_str()),
                _ => None,
            })
            .collect();
        own.iter().any(|r| matches!(&r.event, Event::JobRegistered { job_id, .. } if !settled.contains(job_id.as_str())))
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
    /// it was told of a lost job or its mission is unattended, and otherwise when its lead goes on. One
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
        let mut st = self.st();
        if let Some(k) = st.known.get_mut(id) {
            k.settlement = Some(s.clone());
            k.settled_tx.send_replace(Some(s));
            k.restored = true;
        }
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
            for (id, k) in st.known.iter_mut().filter(|(_, k)| k.meta.parent.as_ref() == Some(parent) && !k.joined) {
                let Some(given) = &k.gate else { continue };
                // One that was stopped, failed, or ended without a verdict gives nothing to take.
                let verdict = k.settlement.as_ref().is_some_and(|s| {
                    s.payload.get("accepted").is_some_and(serde_json::Value::is_boolean)
                });
                let usable = verdict || (!k.finished() && k.active.is_some());
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

/// The inbox kind in snake case, as notifications name it.
fn inbox_kind_word(item: &InboxItem) -> String {
    serde_json::to_value(item.kind).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_else(|| "question".to_string())
}

/// What a notification says about an inbox item. An item opened by a tool call (`call_id` set: a question, a
/// blocker or a finish the model wrote) starts with a fixed label saying so; one the harness opened itself
/// (`call_id` unset) is unchanged. `still_waiting` is the restart notice for an item that is still open.
fn notice_text(item: &InboxItem, still_waiting: bool) -> String {
    let label = if item.call_id.is_some() { "[From the agent, unverified] " } else { "" };
    let waiting = if still_waiting { "Still waiting: " } else { "" };
    format!("{label}{waiting}{}", item.text)
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
    pub async fn start(config: Config, paths: Paths) -> Result<Runtime, String> {
        config.check().map_err(|e| e.to_string())?;
        paths
            .ensure_private_layout()
            .map_err(|e| format!("cannot create {} as a private directory: {e}", paths.home.display()))?;
        let packs = Packs::load(&paths.packs_dir())?;
        packs.check_tools(&rtools::known_tools())?;
        let key = journal::load_or_create_key(&paths.journal_key())
            .map_err(|e| format!("cannot read or create the journal key {}: {e}", paths.journal_key().display()))?;
        let blobs = BlobStore::open(paths.blobs_dir()).map_err(|e| format!("cannot open the blob store: {e}"))?;
        let mut profiles = BTreeMap::new();
        for (name, profile) in &config.models {
            let client = ModelClient::new(name, profile.clone()).map_err(|e| e.to_string())?;
            profiles.insert(
                name.clone(),
                ProfileRt {
                    client: Arc::new(client),
                    limiter: Arc::new(Limiter::new(profile.max_concurrent)),
                    discovered: Mutex::new(None),
                },
            );
        }
        let (bus, _) = broadcast::channel(BUS_CAPACITY);
        let (net_tx, mut net_rx) = unbounded_channel();
        let audit = net_audit(paths.clone(), bus.clone());
        let proxy = Proxy::start_with(config.daemon.proxy_port, net_tx, Some(audit), Default::default())
            .await
            .map_err(|e| e.to_string())?;
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
            activation: Mutex::new(()),
            shutting: AtomicBool::new(false),
            restoring: AtomicBool::new(true),
            next_gen: AtomicU64::new(1),
            orch: Arc::new(Orch(me.clone())),
            sink: Arc::new(SinkImpl(me.clone())),
            pagers: Mutex::new(Vec::new()),
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

        inner.load_known();
        let mut restored: Vec<SessionId> = Vec::new();
        // The flag marks a session that is wanted only if a job of its was lost (its turn yielded
        // while the job ran, and the job's end would have started the next one).
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
            .filter(|(id, for_a_job)| !for_a_job || inner.has_unsettled_job(id))
            .map(|(id, _)| id)
            .collect();
        // After the candidates are chosen: the sweep removes the records `has_unsettled_job` looks for.
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
            let turn_coming = recovered.contains(&id)
                && matches!(last_end, Some(TurnEndReason::Waiting | TurnEndReason::Yielded));
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
        let profile_name = inner.config.profile(new.model.as_deref()).map_err(|e| e.to_string())?.0.to_string();
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
        let id = SessionId::generate();
        let explicit = role.termination == Termination::Explicit;
        let meta = SessionMeta {
            id: id.clone(),
            mission: MissionId::generate(),
            parent: None,
            workspace: workspace.display().to_string(),
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
        let session = match Session::create(deps, start, None) {
            Ok(s) => s,
            Err(e) => {
                forget(inner);
                return Err(e);
            }
        };
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
                Some("message") => format!("Messages go to the lead session of a mission; {} is one of its agents.", id.as_str()),
                Some("resume") => format!("Resume goes to the lead session of a mission; {} is one of its agents.", id.as_str()),
                _ => format!("Only the lead session of a mission can be archived; {} is one of its agents.", id.as_str()),
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

    pub async fn stop(&self, id: &SessionId) -> Result<(), String> {
        self.inner.check_open()?;
        if !self.inner.st().known.contains_key(id) {
            return Err(no_session(id));
        }
        self.inner.stop_one(id);
        Ok(())
    }

    pub async fn resume(&self, id: &SessionId) -> Result<(), String> {
        let meta = self.operable(id, Some("resume"))?;
        if meta.archived {
            return Err("This session is archived; unarchive it first.".to_string());
        }
        self.inner.activate(id)?;
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
                && ids.iter().any(|i| st.known.get(i).is_some_and(|k| k.active.is_some() && k.status.phase == Phase::Running))
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
            let stored = blobs.ids().map_err(|e| format!("cannot list the blob store ({e}); nothing was collected."))?;
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
        if !self.inner.send_input(&entry.session, Input::Answer { item_id: item_id.to_string(), answer: answer.to_string() }) {
            return Err(format!("Session {} is not accepting input.", entry.session.as_str()));
        }
        // An answer starts a turn (an empty one only dismisses the item): as for a message.
        if !answer.trim().is_empty() {
            self.inner.resume_cut_children(&entry.session);
        }
        Ok(())
    }

    pub fn records(&self, id: &SessionId, after: Option<Seq>, limit: usize) -> Result<Vec<Record>, String> {
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
        reader.read_page(after, limit.min(PAGE_MAX)).map_err(|e| e.to_string())
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
            let lead = self.inner.st().known.values().find(|k| &k.meta.mission == mission && k.meta.parent.is_none()).map(|k| k.meta.clone());
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
                detail: if reachable { String::new() } else { format!("{} did not answer a request for its models.", profile.base_url) },
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
        let nothing_there = |e: &std::io::Error| e.kind() == std::io::ErrorKind::NotFound || (depth > 0 && is_absent(e));
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
            let status = read_json::<Status>(&path.join("status.json")).unwrap_or_else(idle_status);
            st.known.insert(meta.id.clone(), Known::new(meta, status));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loom_core::config::{ModelProfile, SandboxMode};
    use loom_core::event::InboxKind;
    use loom_model::mock::{Action, MockServer, Reply, Script};
    use serde_json::{json, Value};
    use std::sync::atomic::AtomicUsize;

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
            .and_then(|m| m.iter().rev().find_map(|m| m["content"].as_str().filter(|c| c.starts_with("<harness-state>"))))
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
            c.notify.command = vec![
                "/bin/sh".into(),
                "-c".into(),
                format!("echo \"$LOOM_KIND $LOOM_SESSION\" >> '{}'", f.display()),
            ];
        }
        c
    }

    async fn env_with(script: Script, notify: bool, tweak: impl FnOnce(&mut Config)) -> Env {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let server = MockServer::start(script).await.unwrap();
        let nf = dir.path().join("notified.txt");
        let mut config = config_for(&server, notify.then_some(nf.as_path()));
        tweak(&mut config);
        let rt = Runtime::start(config.clone(), Paths::at(dir.path().join("home"))).await.unwrap();
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
        let e = env_with_packs(Script::new(|_, _| finish("ok")), |_| {}, |packs| {
            std::fs::create_dir_all(packs).unwrap();
            for d in [packs.parent().unwrap(), packs] {
                std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        })
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
    async fn a_blank_scope_or_reason_is_still_recorded_and_a_withdrawal_the_ledger_would_drop_is_refused() {
        let e = env(Script::new(|_, _| finish("ok"))).await;
        // No first message: the lead is idle and its mission's journal is not written yet.
        let info = e.rt.create_session(e.new_session(None)).await.unwrap();
        let (id, mission) = (info.meta.id.clone(), info.meta.mission.clone());
        let refused = "There is no rule k1 in this mission; it has no rules in force.";
        assert_eq!(e.rt.withdraw_rule(&id, "k1", "").await.unwrap_err(), refused);
        let noted = |needle: &str| {
            e.has(&id, |ev| matches!(ev, Event::HarnessNote { text, .. } if text.contains(needle)))
        };

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
        let e = env(Script::new(move |_, _| {
            if flag.load(Ordering::SeqCst) {
                Action::Stall { ms: 600_000 }
            } else {
                finish("done")
            }
        }))
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
        journal.append(&info.meta.id, true, loom_core::ledger::LedgerOp::GoalSet { text: "ship it".into() }, &|_| Ok(())).unwrap();
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
        assert!(notices[0].starts_with("1 ledger entry written by a newer loom is not shown (first: entry 2"), "{notices:?}");

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
            notices[0].starts_with("2 ledger entries written by a newer loom are not shown (first: entry 4: op `hologram_set`"),
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
        let e = env_with_packs(Script::new(|_, _| Action::Stall { ms: 600_000 }), |_| {}, |packs| {
            std::fs::create_dir_all(packs.join("gone")).unwrap();
            std::fs::write(packs.join("gone/pack.toml"), pack_toml).unwrap();
            std::fs::write(packs.join("gone/r.md"), "Role R.").unwrap();
        })
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
        let grant = e.rt.inner.proxy.grant(&id, Policy::new(&e.config.network).unwrap());
        let mut bus = e.rt.subscribe();
        let port = e.rt.proxy_port();
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
            Script::new(|body, _| if has_tool(body, "verdict") { verifier_turn(body, true) } else { finish("lead done") }),
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
    async fn rejected_finish_with_real_children_returns_the_objections_and_the_work_continues() {
        let verdicts = Arc::new(AtomicUsize::new(0));
        let v = verdicts.clone();
        let e = env_with(
            Script::new(move |body, _| {
                if !has_tool(body, "verdict") {
                    return finish("lead done");
                }
                if shown_handle(body).is_some() {
                    return verifier_turn(body, v.fetch_add(1, Ordering::SeqCst) > 0);
                }
                verifier_turn(body, false)
            }),
            false,
            |c| c.agents.verify_finish = true,
        )
        .await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let id = info.meta.id.clone();
        until("finished item", || inbox_kinds(&e).contains(&InboxKind::Finished)).await;
        let ledger = e.rt.ledger(&info.meta.mission).unwrap();
        let verdicts: Vec<Option<bool>> = ledger.state.finishes.iter().map(|f| f.accepted).collect();
        assert_eq!(verdicts, vec![Some(false), Some(true)]);
        assert_eq!(ledger.state.finishes[0].objections, vec!["no test ran".to_string()]);
        let lead_saw_objection = e.server.requests().iter().any(|b| {
            has_tool(b, "finish") && mentions(b, "did not accept it") && mentions(b, "no test ran")
        });
        assert!(lead_saw_objection);
        assert_eq!(e.children(&id).len(), 2);
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn finish_whose_verifier_cannot_be_started_delivers_nothing_and_opens_a_blocking_item() {
        let e = env_with(
            Script::new(|body, n| {
                if has_tool(body, "verdict") {
                    verifier_turn(body, true)
                } else if n == 0 {
                    call("bash", json!({"command": "cd .. && rm -rf ws"}))
                } else {
                    finish("lead done")
                }
            }),
            false,
            |c| c.agents.verify_finish = true,
        )
        .await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let id = info.meta.id.clone();
        until("blocking item", || inbox_kinds(&e).contains(&InboxKind::Blocker)).await;
        let item = e.rt.inbox().remove(0).item;
        assert!(item.blocking);
        assert!(item.text.starts_with("NOT VERIFIED - VERIFICATION COULD NOT BE RUN"), "{}", item.text);
        assert!(item.text.contains("lead done") && item.text.contains("workspace"), "{}", item.text);
        until("turn end", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { .. }))).await;
        assert!(e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Blocked })));
        assert!(!e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Finished })));
        assert!(!inbox_kinds(&e).contains(&InboxKind::Finished));
        assert!(e.server.requests().iter().all(|b| !has_tool(b, "verdict")));
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn rejection_cap_escalates_and_verification_runs_again_after_the_operator_answers() {
        let verdicts = Arc::new(AtomicUsize::new(0));
        let v = verdicts.clone();
        let said = Arc::new(AtomicUsize::new(0));
        let s = said.clone();
        let e = env_with(
            Script::new(move |body, _| {
                if !has_tool(body, "verdict") {
                    return finish(&format!("lead done {}", s.fetch_add(1, Ordering::SeqCst)));
                }
                if shown_handle(body).is_some() {
                    return verifier_turn(body, v.fetch_add(1, Ordering::SeqCst) >= 2);
                }
                verifier_turn(body, false)
            }),
            false,
            |c| c.agents.verify_finish = true,
        )
        .await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let id = info.meta.id.clone();
        until("escalation", || inbox_kinds(&e).contains(&InboxKind::Blocker)).await;
        let entry = e.rt.inbox().remove(0);
        assert!(entry.item.blocking);
        assert!(entry.item.text.starts_with("NOT VERIFIED - REJECTED 2 TIMES"), "{}", entry.item.text);
        assert!(entry.item.text.matches("- no test ran").count() == 2, "{}", entry.item.text);
        assert!(entry.item.text.contains("lead done 2"), "{}", entry.item.text);
        until("turn end", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Blocked }))).await;
        assert!(!inbox_kinds(&e).contains(&InboxKind::Finished));
        assert!(!e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Finished })));
        assert_eq!(e.children(&id).len(), 2);

        e.rt.answer(&entry.item.item_id, "Keep going: check the lexer too.").await.unwrap();
        until("finished after the answer", || inbox_kinds(&e).contains(&InboxKind::Finished)).await;
        assert_eq!(e.children(&id).len(), 3);
        let ledger = e.rt.ledger(&info.meta.mission).unwrap();
        let verdicts: Vec<Option<bool>> = ledger.state.finishes.iter().map(|f| f.accepted).collect();
        assert_eq!(verdicts, vec![Some(false), Some(false), None, Some(true)]);
        assert_eq!(ledger.state.questions.len(), 1);
        assert!(ledger.state.questions[0].answer.is_some());
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
        until("lead stopped", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Stopped }))).await;
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
        until("the worker waits", || e.has(child, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Waiting })))
            .await;
        until("the worker is idle", || e.rt.session(child).is_some_and(|s| s.status.phase == Phase::Idle)).await;
    }

    /// The stop reached `child` between turns: its `interrupted` follows a `Waiting` turn end directly.
    fn stopped_while_idle(e: &Env, child: &SessionId, reason: &str) -> bool {
        let rs = e.records(child);
        let Some(at) = rs.iter().position(|r| matches!(&r.event, Event::Interrupted { reason: why } if why == reason)) else {
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
        until("the lead waits", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Waiting }))).await;
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
        };
        orch.spawn(&id, again).await.expect("a stopped agent does not count toward max_children");
        let settled = |c: &ChildSettled| c.child == child && c.outcome == ChildOutcome::Stopped && !c.inline;
        until("the lead got the settlement", || e.has(&id, |ev| matches!(ev, Event::ChildSettled(c) if settled(c)))).await;
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
        until("the lead waits", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Waiting }))).await;
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
        assert!(stopped.text.contains(&format!("{child} was stopped; anything it had not delivered")), "{}", stopped.text);
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
                rs.iter().any(|r| matches!(&r.event, Event::ChildSettled(c)
                    if c.child == child && c.outcome == ChildOutcome::Failed && c.report.contains("internal error")))
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
        until("lead finished", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Finished }))).await;
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
        let votes = e
            .rt
            .inner
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
        e.rt.shutdown().await;
        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        let p2 = rt2.inner.orch.producer(&info.meta.mission, &blob).await.unwrap();
        assert_eq!(p2.call_id, call_id);
        rt2.shutdown().await;
    }

    /// The `out:…` handle in the header of the `n`th tool message of a request.
    fn handle_in_tool_msg(body: &Value, n: usize) -> String {
        let text = body["messages"]
            .as_array()
            .and_then(|m| m.iter().filter(|m| m["role"] == "tool").nth(n))
            .and_then(|m| m["content"].as_str())
            .unwrap_or("");
        let at = text.find("out:").unwrap_or(0);
        text[at..].chars().take_while(|c| *c == 'o' || *c == 'u' || *c == 't' || *c == ':' || c.is_ascii_hexdigit()).collect()
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
        assert!(got[0].1.contains("static: read call"), "{}", got[0].1);
        assert_eq!(got[1].0, ToolStatus::Error, "{}", got[1].1);
        assert_eq!(got[2].0, ToolStatus::Error, "{}", got[2].1);
        assert!(got[2].1.contains("is the result of `ledger`"), "{}", got[2].1);
        let read_call = e.records(&id).into_iter().find_map(|r| match r.event {
            Event::ToolResult(t) if t.name == "read" => Some(t.call_id),
            _ => None,
        });
        let attributed = e.rt.inner.st().producers.values().any(|p| p.tool == "read" && Some(&p.call_id) == read_call.as_ref());
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
        // store it, so the producer is that wait or the starting bash call. Either way it is execution.
        assert!(got[1].1.contains("execution: "), "{}", got[1].1);
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
        let reg = |call: &str| Event::JobRegistered { job_id: "j1".into(), call_id: CallId::from(call), command: "make".into() };
        assert!(produced_by(&s, &mut jobs, &reg("c0")).is_none());
        assert!(produced_by(&s, &mut jobs, &reg("c4")).is_none());
        let wait = tool_result("c5", "job_wait", ToolClass::Exec, None, json!({"job": "j1"}));
        assert!(produced_by(&s, &mut jobs, &wait).is_none());
        let settled = Event::JobSettled {
            job_id: "j1".into(),
            exit_code: Some(0),
            output: Some(loom_core::BlobRef { id: BlobId::from("dd03"), bytes: 10, lines: 2 }),
            detail: String::new(),
        };
        let p = produced_by(&s, &mut jobs, &settled).expect("the job output registers");
        assert_eq!((p.0, p.1.call_id, p.1.class, p.1.tool.as_str()), (BlobId::from("dd03"), CallId::from("c4"), ToolClass::Exec, "bash"));
        assert!(jobs.is_empty(), "a settled job is forgotten");
        // A job nothing is known about registers nothing.
        let other = Event::JobSettled { job_id: "j9".into(), exit_code: None, output: None, detail: String::new() };
        assert!(produced_by(&s, &mut jobs, &other).is_none());
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
        let answered = |r: &Record| matches!(&r.event, Event::UserMessage { text } if text.starts_with("[The operator's"));
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

    #[tokio::test]
    async fn a_question_the_model_wrote_is_notified_with_the_unverified_label() {
        let out = tempfile::tempdir().unwrap();
        let file = out.path().join("n.txt");
        let e = env_with(
            Script::new(|_, n| if n == 0 { call("ask_user", json!({"question": "which one?"})) } else { Action::Stall { ms: 600_000 } }),
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
            Script::new(|_, n| if n == 0 { call("ask_user", json!({"question": "which one?"})) } else { Action::Stall { ms: 600_000 } }),
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
        let e = env(Script::new(|_, n| {
            if n == 0 {
                call("ask_user", json!({"question": "which one?"}))
            } else {
                finish("fine")
            }
        }))
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
            ra.records(&a, None, 2_000)
                .is_ok_and(|rs| rs.iter().any(|r| matches!(r.event, Event::TurnEnd { reason: TurnEndReason::Finished })))
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
        after.store(true, Ordering::SeqCst);
        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        let rt = rt2.clone();
        until("woken and finished", || {
            rt.records(&id, None, 2_000)
                .is_ok_and(|rs| rs.iter().any(|r| matches!(r.event, Event::TurnEnd { reason: TurnEndReason::Finished })))
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
    async fn restart_wakes_a_session_that_yielded_while_its_job_ran() {
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
        let before = e.server.requests().len();
        after.store(true, Ordering::SeqCst);
        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        until("a turn after the restart", || e.server.requests().len() > before).await;
        let rs = rt2.records(&id, None, 2_000).unwrap();
        let lost = rs.iter().position(|r| matches!(&r.event, Event::JobSettled { detail, .. } if detail == texts::JOB_LOST_DETAIL));
        let turn = rs.iter().rposition(|r| matches!(r.event, Event::TurnStart { trigger: loom_core::event::Trigger::Resume }));
        assert!(lost.is_some() && lost < turn, "lost at {lost:?}, resumed at {turn:?}");
        let last = e.server.requests().pop().unwrap();
        assert!(mentions(&last, &texts::job_lost("j1", "sleep 600")));
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
        // A crash, not a graceful shutdown, leaves the command's pid record behind, owned by another daemon.
        let jobs = e.rt.paths().session_dir(&id).join("jobs");
        std::fs::create_dir_all(&jobs).unwrap();
        std::fs::write(jobs.join("j1.pid"), "999999 1\nowner 1 1.000000\n").unwrap();
        let before = e.server.requests().len();
        after.store(true, Ordering::SeqCst);
        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        until("a turn after the restart", || e.server.requests().len() > before).await;
        let rs = rt2.records(&id, None, 2_000).unwrap();
        assert!(rs.iter().any(|r| matches!(&r.event, Event::JobSettled { detail, .. } if detail == texts::JOB_LOST_DETAIL)));
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
        let jobs = paths.session_dir(&id).join("jobs");
        std::fs::create_dir_all(&jobs).unwrap();
        std::fs::write(jobs.join("j1.pid"), "999999 1\nowner 1 1.000000\n").unwrap();
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
        assert!(rs.iter().any(|r| matches!(&r.event, Event::JobSettled { detail, .. } if detail == texts::JOB_LOST_DETAIL)));
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
            rt.records(id, None, 2_000)
                .is_ok_and(|rs| rs.iter().any(|r| matches!(r.event, Event::TurnEnd { reason: TurnEndReason::Finished })))
        })
        .await;
        let reqs = e.server.requests();
        let (lead, child): (Vec<&Value>, Vec<&Value>) = reqs[before..].iter().partition(|b| has_tool(b, "agent_spawn"));
        assert!(lead.iter().any(|b| mentions(b, texts::AFTER_RESTART)), "the lead was not told about the restart");
        assert_eq!(child.len(), 1, "the worker did not run again exactly once");
        assert!(!reqs.iter().any(|b| mentions(b, "Interrupted while waiting for")), "a resumed agent was called stopped");
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
            rt.records(&id, None, 2_000)
                .is_ok_and(|rs| rs.iter().any(|r| matches!(r.event, Event::TurnEnd { reason: TurnEndReason::Finished })))
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
        let kids: Vec<SessionInfo> = rt2.sessions(true).into_iter().filter(|s| s.meta.parent.as_ref() == Some(&id)).collect();
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
        until("the lead waits for B", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Waiting }))).await;
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
            rt.records(&id, None, 2_000)
                .is_ok_and(|rs| rs.iter().any(|r| matches!(r.event, Event::TurnEnd { reason: TurnEndReason::Finished })))
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
                if go { finish("AREPORT") } else { Action::Stall { ms: 600_000 } }
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
        until("the lead waits", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Waiting }))).await;
        let b = e.children(&id).into_iter().find(|c| c.meta.title == "BMARK").unwrap().meta.id;
        until_idle(&e, &b).await;
        let a_asked = || e.server.requests().iter().any(|r| mentions(r, "AMARK") && !has_tool(r, "agent_spawn"));
        until("A is inside a request", a_asked).await;
        e.rt.shutdown().await;
        after.store(true, Ordering::SeqCst);
        // Attended: A is held. B was told of its lost job and reports; that report starts the lead's
        // turn, and A goes on with it.
        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        let rt = rt2.clone();
        until("the lead finished", || {
            rt.records(&id, None, 2_000)
                .is_ok_and(|rs| rs.iter().any(|r| matches!(r.event, Event::TurnEnd { reason: TurnEndReason::Finished })))
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
        until("the lead waits", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Waiting }))).await;
        let child = e.children(&id)[0].meta.id.clone();
        until_idle(&e, &child).await;
        e.rt.shutdown().await;
        // The worker's log is lost while the harness is down: it will never run again.
        std::fs::write(e.rt.paths().session_log(&child), "not a log\n").unwrap();
        let rt2 = Runtime::start(e.config.clone(), Paths::at(e.dir.path().join("home"))).await.unwrap();
        let rt = rt2.clone();
        until("the lead finished", || {
            rt.records(&id, None, 2_000)
                .is_ok_and(|rs| rs.iter().any(|r| matches!(r.event, Event::TurnEnd { reason: TurnEndReason::Finished })))
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
        assert_eq!((info.status.phase, info.status.outcome, info.active), (Phase::Ended, Some(SessionOutcome::Failed), false));
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
        let n = rt2.records(&id, None, 2_000).unwrap().iter().filter(|r| matches!(r.event, Event::ChildSettled(_))).count();
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
    async fn a_settlement_recovered_from_a_log_without_the_kept_report_has_its_first_line() {
        let (e, id, child, stall) = a_settlement_nobody_took().await;
        std::fs::remove_file(e.rt.inner.paths.session_dir(&child).join("settlement.json")).unwrap();
        stall.store(false, Ordering::SeqCst);
        let (rt2, c) = recovered_settlement(&e, &id).await;
        assert_eq!((&c.child, c.outcome, c.inline), (&child, ChildOutcome::Returned, false));
        assert_eq!(c.report, "Outcome: returned");
        rt2.shutdown().await;
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
        let port = e.rt.proxy_port();
        assert!(port != 0);
        let text = e.records(&id).into_iter().find_map(|r| match r.event {
            Event::ToolResult(t) if t.name == "bash" => Some(t.text),
            _ => None,
        });
        assert!(text.unwrap_or_default().contains(&format!("@127.0.0.1:{port}")));
        e.rt.shutdown().await;
    }

    #[tokio::test]
    async fn archive_hides_refuses_and_survives_restart() {
        let e = env(Script::new(|_, _| finish("ok"))).await;
        let info = e.rt.create_session(e.new_session(Some("go"))).await.unwrap();
        let id = info.meta.id.clone();
        until("turn end", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { .. }))).await;
        until("idle", || e.rt.session(&id).is_some_and(|s| s.status.phase == Phase::Idle)).await;
        e.rt.archive(&id, true).await.unwrap();
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
        until("the lead waits", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Waiting }))).await;
        let child = e.children(&id)[0].meta.id.clone();
        until_idle(&e, &child).await;
        // Archiving closes the inputs of the lead and of its agent for good.
        e.rt.archive(&id, true).await.unwrap();
        until("the agent settled", || e.rt.session(&child).is_some_and(|s| s.status.phase == Phase::Ended)).await;
        assert_eq!(e.rt.session(&child).unwrap().status.outcome, Some(SessionOutcome::Stopped));
        assert!(stopped_while_idle(&e, &child, texts::REASON_OPERATOR), "{:?}", e.kinds(&child));
        assert!(!e.has(&id, |ev| matches!(ev, Event::ChildSettled(_))), "an archived lead was given a settlement");
        // Unarchived, the lead gets the settlement, which wakes it.
        e.rt.archive(&id, false).await.unwrap();
        until("the lead finished", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Finished })))
            .await;
        let settled: Vec<Record> =
            e.records(&id).into_iter().filter(|r| matches!(&r.event, Event::ChildSettled(c) if c.child == child)).collect();
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
        until("the lead waits", || e.has(&id, |ev| matches!(ev, Event::TurnEnd { reason: TurnEndReason::Waiting }))).await;
        let child = e.children(&id)[0].meta.id.clone();
        until_idle(&e, &child).await;
        let log = e.rt.paths().session_log(&child);
        // The daemon unwinding drops its runtime: the sessions' inputs close without a shutdown.
        let Env { dir, server, rt, .. } = e;
        drop(rt);
        tokio::time::sleep(Duration::from_millis(500)).await;
        let rs = read_records(&log).unwrap().records;
        assert!(!rs.iter().any(|r| matches!(r.event, Event::SessionEnd { .. })), "the agent was settled");
        assert!(!rs.iter().any(|r| matches!(&r.event, Event::Interrupted { reason } if reason == texts::REASON_OPERATOR)));
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
        let (in_log, outside, in_linked) = (old_blob(&store, "log\n"), old_blob(&store, "out\n"), old_blob(&store, "ln\n"));
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
        let kinds: Vec<String> =
            records.iter().map(|r| serde_json::to_value(r).unwrap()["kind"].as_str().unwrap_or("").to_string()).collect();
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
}
