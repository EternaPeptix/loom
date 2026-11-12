//! The runtime: owns every session of this loom home, starts and restores them, connects parents and
//! children, and is the one thing the daemon talks to.
//!
//! CONTRACT (bodies are placeholders for the implementer; public signatures and types are fixed;
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
//!   log is read only when the session's `jobs/` directory is not empty) (parents before children —
//!   session ids sort by creation time);
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
//! - `End::Closed`: inactive.
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
//!     workspace is added to `protected_paths`.
//!   - `env`: the session's proxy grant (`proxy.grant(id, Policy::new(&config.network))`), `env()`.
//!     Every session gets a grant, also under `deny_all` (in-process fetches go through the proxy
//!     too, so the policy is what refuses them).
//! - `job_events`: the receiver of the job table's channel; `sink`: the runtime; `control`: new.
//!
//! ## Creating a root session (`create_session`)
//! 1. `workspace` must be an existing directory (canonicalised). Role: `packs.role(pack, role)`.
//!    Profile: `config.profile(model)`.
//! 2. Model facts: `client.discover()` once per profile (the first success is remembered). On
//!    `Unavailable`, carry on with the profile's `model` and `context_window` (unknown → `None`,
//!    `0` in `ModelRef`). On `Rejected`/`Config`: return its message.
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
//! - at most `agents.max_children` unsettled children per parent: otherwise `{n} agents are already
//!   running, which is the most allowed at once. Wait for one to finish (`wait`) or stop one
//!   (`agent_stop`), then start this one.`
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
//! agent finished.")` — except during shutdown, when the call does not return at all (see
//! *Shutdown*). The first successful join of a child queues
//! `parent_shared.emit(Author::Agent(child), Event::ChildSettled(ChildSettled{child, outcome,
//! report, full, usage, steps, inline: true}))`; later joins return the same settlement and queue
//! nothing.
//!
//! When a child settles and it was not `awaited`, or it was restored after a restart (nobody can be
//! waiting for it any more): send `Input::ChildSettled(settlement)` to its parent, activating the
//! parent if necessary.
//!
//! `stop_child(parent, child)`: not its child → the sentence above; already settled → `{child} has
//! already finished ({outcome word}).`; else `control.stop_turn()` and `Input::Stop`.
//! `stop_children(parent)`: the same for every unsettled child, without errors.
//! `message_child(parent, child, text)`: same two refusals; else `Input::AgentMessage{from: parent,
//! text}`.
//! `children(parent)`: every child of `parent` in creation order: `ChildInfo{id, role, title, step:
//! latest status, running: not settled}`.
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
//! `producer(mission, blob)`: the first `tool_result` record with `output.id == blob` among the
//! sessions of the mission (a session's own records only — a fork's copied records belong to its
//! parent): `Producer{session, call_id, tool: name, class}`. Kept as an in-memory index fed by
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
//!   stays blank and the note words it itself. The lead records the input at once when idle and at
//!   the next step of a running turn: a ledger entry when the mission keeps a ledger (the lead's
//!   state block then lists it), and a protected note in the lead's window. No turn is started.
//!   The answer is a [`RuleReceipt`]: the lead, whether it was in a turn (`queued`), whether the
//!   mission keeps a ledger, and the stock text when one was used.
//! - `stop(id)`: any session. Active: `control.stop_turn()` and `Input::Stop`. Not active: nothing.
//! - `resume(id)`: root only; activate; `Input::Resume` to it and to each of its unsettled children
//!   whose latest status has `last_end == Stopped` (activating them), except one that is running a
//!   turn already. Only a restart leaves a child that way: a child that is stopped settles.
//! - `reweave(id)`: activate; `Input::Reweave`.
//! - `answer(item_id, answer)`: the item must be open (`There is no open inbox item {item_id}.`);
//!   an empty answer to a blocking item is refused (`This item is waiting for an answer; write
//!   one.`); activate the session; `Input::Answer`; a non-empty answer also resumes the session's
//!   children that a restart cut, as `resume` does. (An empty answer to a non-blocking item
//!   dismisses it: the session resolves it without starting a turn.)
//! - `archive(id, archived)`: root only; refused while the session or one of its children is
//!   running a turn (`Stop the session before archiving it.`). Sets `archived` in the `meta.json`
//!   of the session and its children; archiving closes their inputs (their tasks end `Closed`).
//!   Archived sessions are listed only by `sessions(true)` and are not activated at start;
//!   `send_message`/`resume` on one are refused (`This session is archived; unarchive it first.`).
//!
//! ## Start (`Runtime::start`)
//! 1. `config.check()`; create the directories; load packs (`Packs::load(paths.packs_dir())`) and
//!    check every role's tools against `Registry::builtin().names()` plus `rtools::NAMES`; journal
//!    key; blob store; clients and limiters; proxy.
//! 2. Read every session's `meta.json` and `status.json` (missing status = default idle status).
//! 3. Activate as described under *Active sessions*. A session that cannot be opened is skipped
//!    with `tracing::error!` and a `BusEvent::Error`.
//! 4. Restored sessions with `meta.unattended` are told to carry on (`Input::Resume`) when
//!    - `open` cut a running turn (after `open`, the last own `turn_end` is `Stopped`, the latest
//!      own `interrupted` reason is `REASON_RESTART` or starts with `the session log was damaged`,
//!      and no own `turn_start` follows it), or
//!    - the last turn ended `Waiting` and the session has no unsettled child.
//!
//!    Attended or not, a restored session is told to carry on when its last turn ended `Waiting`
//!    or `Yielded` and `open` told it of a lost job (`Session::lost_jobs() > 0`: the job's end
//!    would have started a turn), and a child that a restart cut is told to carry on whenever its
//!    parent is: what the lead is told about its agents (`AFTER_RESTART`) is then what happened.
//!    A session whose last turn ended `Waiting` or `Yielded` and to which a lost delivery is
//!    recovered (below) is not told to carry on — the delivery starts its turn — but counts as
//!    carrying on for its children.
//!
//!    Children restored this way count as not `awaited` from now on.
//!
//!    A delivery lost to the restart is recovered: a child that has ended (not an awaited one that
//!    was stopped) and whose parent's log holds no `child_settled` for it is delivered to the
//!    parent as `Input::ChildSettled`, from its `settlement.json` or else from its log (see *Files*).
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
//! as interrupted while the child's report arrives by itself.
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
//!   (`No ledger: this mission's lead does not keep one.` when there is no journal file). The id
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
use crate::session::{Control, Deps, End, Input, Phase, Session, Sink, Status};
use crate::texts;
use async_trait::async_trait;
use futures_util::FutureExt;
use loom_core::config::{Config, NetworkMode, Paths, SandboxCfg};
use loom_core::estimate::TokenEstimator;
use loom_core::event::{
    Author, Budget, ChildOutcome, ChildSettled, ChildSpawned, Event, Forked, InboxItem, ModelRef, NetDecision, Record,
    Seq, SessionOutcome, SessionStart, SpawnMode, Termination, TurnEndReason, Usage,
};
use loom_core::journal::{self, Journal};
use loom_core::ledger::LedgerState;
use loom_core::log::{read_records, PageReader};
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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LedgerView {
    pub state: LedgerState,
    pub markdown: String,
}

/// What became of a rule, an approval or a withdrawal the operator sent (see [`Runtime::add_rule`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleReceipt {
    /// The lead session it was handed to.
    pub lead: SessionId,
    /// The lead was running a turn: it records this at its next step, and until then it is only
    /// queued in memory.
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
    std::fs::write(&tmp, text)?;
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
fn sandbox_cfg_for(base: &SandboxCfg, role: &RoleDef, workspace: &Path) -> SandboxCfg {
    let mut cfg = base.clone();
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
    /// The settlement was handed to a `join` (and recorded in the parent's log).
    joined: bool,
    /// Activated from disk: nobody can be waiting for this session any more.
    restored: bool,
}

impl Known {
    fn new(meta: SessionMeta, status: Status) -> Known {
        let (settled_tx, _) = watch::channel(None);
        Known { meta, status, active: None, settlement: None, settled_tx, joined: false, restored: false }
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
    next_gen: AtomicU64,
    orch: Arc<dyn Orchestrator>,
    sink: Arc<dyn Sink>,
    /// Paging state per recently viewed session, least recently used first.
    pagers: Mutex<Vec<(SessionId, Arc<Mutex<PageReader>>)>>,
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
        self.up()?.spawn_child(parent, req)
    }

    async fn join(&self, parent: &SessionId, child: &SessionId, cancel: &CancellationToken) -> Result<Settlement, String> {
        let inner = self.0.upgrade().ok_or_else(|| SHUTTING.to_string())?;
        let mut rx = {
            let st = inner.st();
            let k = st.known.get(child).filter(|k| k.meta.parent.as_ref() == Some(parent));
            let Some(k) = k else {
                return Err(format!("{} {NOT_YOURS}", child.as_str()));
            };
            if !k.meta.awaited {
                return Err(format!("{} was started in the background; its report arrives by itself.", child.as_str()));
            }
            k.settled_tx.subscribe()
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
                        // here until `shutdown` aborts it, and `open` records the cut.
                        inner.st().parked.insert(parent.clone());
                        std::future::pending::<()>().await;
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
        let shared = {
            let mut st = inner.st();
            let first = match st.known.get_mut(child) {
                Some(k) if !k.joined => {
                    k.joined = true;
                    true
                }
                _ => false,
            };
            if first {
                st.known.get(parent).and_then(|p| p.active.as_ref()).map(|a| a.shared.clone())
            } else {
                None
            }
        };
        if let Some(shared) = shared {
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
        inner.stop_one(child);
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
        for id in running {
            inner.stop_one(&id);
        }
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
        st.known
            .iter()
            .filter(|(_, k)| k.meta.parent.as_ref() == Some(parent))
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
            for id in ids {
                let Ok(report) = read_records(&paths.session_log(&id)) else { continue };
                for r in own_records(&report.records) {
                    if let Event::ToolResult(t) = &r.event {
                        if let Some(o) = &t.output {
                            out.push((
                                o.id.clone(),
                                Producer { session: id.clone(), call_id: t.call_id.clone(), tool: t.name.clone(), class: t.class },
                            ));
                        }
                    }
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
                    Event::ToolResult(t) => {
                        if let Some(o) = &t.output {
                            st.producers.entry((mission.clone(), o.id.clone())).or_insert(Producer {
                                session: session.clone(),
                                call_id: t.call_id.clone(),
                                tool: t.name.clone(),
                                class: t.class,
                            });
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
            let kind = serde_json::to_value(item.kind)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_else(|| "question".to_string());
            self.notify(&kind, session, &title, &item.text);
            if item.blocking && self.config.notify.repeat_minutes > 0 {
                self.repeat_notice(&kind, session, &title, &item);
            }
        }
        self.publish(BusEvent::Record { session: session.clone(), record: Box::new(record.clone()) });
    }

    fn on_status(&self, session: &SessionId, status: &Status) {
        {
            let mut st = self.st();
            if let Some(k) = st.known.get_mut(session) {
                k.status = status.clone();
            }
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
                inner.notify(&kind, &session, &title, &item.text);
            }
        });
        self.st().tasks.push(task);
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
        std::fs::create_dir_all(&tmp).map_err(|e| format!("cannot create {}: {e}", tmp.display()))?;
        let tmp = std::fs::canonicalize(&tmp).map_err(|e| format!("cannot resolve {}: {e}", tmp.display()))?;
        let cfg = sandbox_cfg_for(&self.config.sandbox, &role, &workspace);
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

    /// A child whose task ended without writing a `session_end` (a log fault, a panic) is over all
    /// the same. Its status says so, durably, so that a later start does not run it again beside
    /// the settlement its parent was given.
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
    /// nobody can be waiting.
    fn record_settlement(self: &Arc<Self>, id: &SessionId, s: Settlement) {
        let (parent, deliver) = {
            let mut st = self.st();
            let Some(k) = st.known.get_mut(id) else { return };
            k.settlement = Some(s.clone());
            k.settled_tx.send_replace(Some(s.clone()));
            (k.meta.parent.clone(), !k.meta.awaited || k.restored)
        };
        self.publish(BusEvent::Settled { session: id.clone(), settlement: Box::new(s.clone()) });
        if let (Some(parent), true) = (parent, deliver) {
            if !self.shutting.load(Ordering::SeqCst) {
                self.deliver(&parent, s);
            }
        }
    }

    /// Hand a settlement to its parent as input, activating the parent if need be.
    fn deliver(self: &Arc<Self>, parent: &SessionId, s: Settlement) {
        if let Err(e) = self.activate(parent) {
            tracing::warn!("the settlement of {} cannot be delivered to {}: {e}", s.child.as_str(), parent.as_str());
            return;
        }
        if !self.send_input(parent, Input::ChildSettled(s.clone())) {
            tracing::warn!("the settlement of {} was not accepted by {}", s.child.as_str(), parent.as_str());
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
                .filter(|k| k.meta.parent.as_ref() == Some(parent) && !k.finished())
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

    /// Model facts of a profile: discovery once, the first success remembered.
    async fn facts(&self, profile_name: &str) -> Result<(String, Option<u64>), String> {
        let rt = self.profiles.get(profile_name).ok_or_else(|| format!("The model profile \"{profile_name}\" is not configured."))?;
        let remembered = lock(&rt.discovered).clone();
        let found = match remembered {
            Some(d) => Some(d),
            None => match rt.client.discover().await {
                Ok(d) => {
                    *lock(&rt.discovered) = Some(d.clone());
                    Some(d)
                }
                Err(ModelError::Unavailable { .. }) => None,
                Err(e) => return Err(e.to_string()),
            },
        };
        let profile = rt.client.profile();
        Ok(match found {
            Some(d) => (d.served_model, d.context_window),
            None => (profile.model.clone(), profile.context_window),
        })
    }

    /// A delivery lost to a restart: the child ended but its parent never recorded it.
    fn recover_settlements(self: &Arc<Self>) -> HashSet<SessionId> {
        let mut delivered_to = HashSet::new();
        let candidates: Vec<(SessionId, SessionId, SessionMeta)> = {
            let st = self.st();
            st.known
                .iter()
                .filter_map(|(id, k)| {
                    let parent = k.meta.parent.clone()?;
                    let parent_ok = st.known.get(&parent).is_some_and(|p| !p.meta.archived && p.status.phase != Phase::Ended);
                    (k.status.phase == Phase::Ended
                        && !k.meta.archived
                        && parent_ok
                        && !(k.meta.awaited && k.status.outcome == Some(SessionOutcome::Stopped)))
                    .then(|| (id.clone(), parent, k.meta.clone()))
                })
                .collect()
        };
        let mut seen: HashMap<SessionId, HashSet<SessionId>> = HashMap::new();
        for (id, parent, meta) in candidates {
            let settled = seen.entry(parent.clone()).or_insert_with(|| {
                read_records(&self.paths.session_log(&parent))
                    .map(|r| {
                        own_records(&r.records)
                            .iter()
                            .filter_map(|rec| match &rec.event {
                                Event::ChildSettled(c) => Some(c.child.clone()),
                                _ => None,
                            })
                            .collect()
                    })
                    .unwrap_or_default()
            });
            if settled.contains(&id) {
                continue;
            }
            // What the child's task handed over when it ended. Without it (see *Files*) the child's
            // log gives the outcome and the first line of the report.
            let persisted = read_json::<Settlement>(&self.paths.session_dir(&id).join("settlement.json"))
                .filter(|p| p.child == id);
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
            let s = match (persisted, end) {
                (Some(s), _) => s,
                (None, Some((outcome, detail))) => {
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
                (None, None) => continue,
            };
            {
                let mut st = self.st();
                if let Some(k) = st.known.get_mut(&id) {
                    k.settlement = Some(s.clone());
                    k.settled_tx.send_replace(Some(s.clone()));
                    k.restored = true;
                }
            }
            self.deliver(&parent, s);
            delivered_to.insert(parent);
        }
        delivered_to
    }

    fn has_unsettled_child(&self, id: &SessionId) -> bool {
        self.st().known.values().any(|k| k.meta.parent.as_ref() == Some(id) && !k.finished())
    }

    /// Whether the session's log holds a job that was registered and never settled. The log is
    /// read only when the session's jobs directory holds something: a background job leaves its
    /// output file there.
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

    /// Tell the children of `lead` that a restart cut to carry on. An unsettled child's turn ends
    /// `Stopped` only that way: a child stopped by its parent or the operator settles. One that is
    /// already running the turn it was resumed with (its last turn end is still that cut) is left
    /// alone, or the second `Resume` would start a turn it did not ask for when this one ends.
    fn resume_cut_children(self: &Arc<Self>, lead: &SessionId) {
        let children: Vec<SessionId> = {
            let st = self.st();
            st.known
                .iter()
                .filter(|(_, k)| {
                    k.meta.parent.as_ref() == Some(lead)
                        && !k.finished()
                        && k.status.last_end == Some(TurnEndReason::Stopped)
                        && !(k.active.is_some() && k.status.phase == Phase::Running)
                })
                .map(|(c, _)| c.clone())
                .collect()
        };
        for child in children {
            match self.activate(&child) {
                Ok(_) => {
                    self.send_input(&child, Input::Resume);
                }
                Err(e) => tracing::warn!("child {} cannot be resumed: {e}", child.as_str()),
            }
        }
    }
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
        for dir in [paths.home.clone(), paths.sessions_dir(), paths.missions_dir(), paths.logs_dir(), paths.keys_dir()] {
            std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        }
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
                    let wanted = k.status.phase == Phase::Running
                        || k.status.last_end == Some(TurnEndReason::Waiting)
                        || k.status.open_inbox > 0;
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
                }
            }
        }
        let recovered = inner.recover_settlements();
        // The sessions told to carry on (parents come before their children).
        let mut going: HashSet<SessionId> = HashSet::new();
        for id in restored {
            let (unattended, last_end, active, parent) = {
                let st = inner.st();
                match st.known.get(&id) {
                    Some(k) => (k.meta.unattended, k.status.last_end, k.active.is_some(), k.meta.parent.clone()),
                    None => continue,
                }
            };
            if !active {
                continue;
            }
            // The settlement recovered for it starts a turn by itself.
            let turn_coming = recovered.contains(&id)
                && matches!(last_end, Some(TurnEndReason::Waiting | TurnEndReason::Yielded));
            // A session that waited on a job the restart lost is woken, attended or not: the job's
            // arrival would have woken it. An agent the restart cut goes on whenever its lead does:
            // the lead is told that its unfinished agents were resumed.
            let carry_on = (!turn_coming
                && (woken.contains(&id)
                    || (unattended
                        && (cut.contains(&id)
                            || (last_end == Some(TurnEndReason::Waiting) && !inner.has_unsettled_child(&id))))))
                || (cut.contains(&id) && parent.is_some_and(|p| going.contains(&p)));
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
        let (model, window) = inner.facts(&profile_name).await?;
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
            profile: profile_name,
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
    /// it is idle and at the next step of a running turn; until then it is only queued in memory,
    /// which the receipt says (`queued`). `ledger`: the mission keeps one; `stock`: the text put in
    /// place of a blank scope or reason.
    fn send_to_lead(
        &self,
        lead: &SessionId,
        input: Input,
        ledger: bool,
        stock: Option<&str>,
    ) -> Result<RuleReceipt, String> {
        self.inner.activate(lead)?;
        let st = self.inner.st();
        let k = st.known.get(lead).ok_or_else(|| no_session(lead))?;
        let queued = k.status.phase == Phase::Running;
        if k.active.as_ref().is_some_and(|a| a.inputs.send(input).is_ok()) {
            Ok(RuleReceipt { lead: lead.clone(), queued, ledger, stock: stock.map(str::to_string) })
        } else {
            Err(format!("Session {} is not accepting input.", lead.as_str()))
        }
    }

    /// Set a standing rule for the mission of `id` (any of its sessions; the rule goes to the lead).
    /// `Ok` means the rule was handed to the lead, not that it is recorded yet: the lead records it
    /// at once when it is idle, and at the next step of a running turn otherwise (so not while a
    /// tool call, such as an awaited agent, is still running; a daemon stop before that loses it).
    /// The receipt's `queued` says which of the two it was. Recording is a ledger entry, constraint
    /// `k<n>`, when the mission keeps a ledger (the lead's state block then lists the rule), and in
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
    /// Refused unless the mission's ledger lists that rule as in force; a mission that keeps no
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
        let mut closing: Vec<ActiveSession> = Vec::new();
        for sid in &family {
            let meta = {
                let mut st = self.inner.st();
                let Some(k) = st.known.get_mut(sid) else { continue };
                k.meta.archived = archived;
                if archived {
                    closing.extend(k.active.take());
                }
                k.meta.clone()
            };
            if let Err(e) = write_json_atomic(&self.inner.paths.session_dir(sid).join("meta.json"), &meta) {
                return Err(format!("cannot write the meta.json of {}: {e}", sid.as_str()));
            }
        }
        // Dropping the inputs ends the tasks (`Closed`).
        drop(closing);
        Ok(())
    }

    /// Garbage-collect stored outputs. Keeps every blob whose id, or `out:` handle, appears anywhere in the text
    /// of any file under the sessions and missions directories (logs, damaged-log remainders, meta, status, net
    /// audit, journals, job output), and every blob younger than `min_age` (default one hour) when the scan
    /// began. Only the rest is deleted, and only with `apply`; otherwise the report says what would be.
    /// Removing a session's directory is what makes its outputs collectable (those that another session's or a
    /// mission's files still name stay). Links below a session or mission directory are not followed. Any
    /// file that cannot be read aborts the collection before anything is deleted.
    pub async fn gc(&self, apply: bool, min_age: Option<Duration>) -> Result<loom_core::blob::SweepReport, String> {
        let blobs = self.inner.blobs.clone();
        let roots = [self.inner.paths.sessions_dir(), self.inner.paths.missions_dir()];
        let min_age = min_age.unwrap_or(loom_core::blob::DEFAULT_GC_MIN_AGE);
        tokio::task::spawn_blocking(move || {
            let started = std::time::Instant::now();
            let stored = blobs.ids().map_err(|e| format!("cannot list the blob store ({e}); nothing was collected."))?;
            let mut keep = HashSet::new();
            for root in &roots {
                scan_tree_for_ids(root, &stored, &mut keep).map_err(|(path, e)| {
                    format!("cannot read {} ({e}); nothing was collected. Fix or remove it and run it again.", path.display())
                })?;
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
            return Err("No ledger: this mission's lead does not keep one.".to_string());
        }
        let state = Journal::new(path, self.inner.key.clone()).state().map_err(|e| e.to_string())?;
        let markdown = state.render_markdown();
        Ok(LedgerView { state, markdown })
    }

    pub fn net(&self, id: &SessionId, limit: usize) -> Result<Vec<NetEntry>, String> {
        self.inner.check_open()?;
        if !self.inner.st().known.contains_key(id) {
            return Err(no_session(id));
        }
        let path = self.inner.paths.session_dir(id).join("net.jsonl");
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        };
        if let Err(b) = loom_net::netlog::verify(&text) {
            return Err(format!(
                "The egress audit log {} is damaged at {b}. Do not trust it: it was edited, truncated or written by something else. Keep a copy for review and move it aside to start a new chain.",
                path.display()
            ));
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
        inner.proxy.shutdown();
    }
}

/// Add to `keep` every stored blob that a regular file below `root` names (`scan_ids`). A missing `root` is an
/// empty tree. A link is followed only when it is an entry of `root` itself (a session or mission directory);
/// below that, links are skipped, so the walk stays in the tree and ends whatever commands left in their
/// scratch directories. What cannot be read is an error carrying its path.
fn scan_tree_for_ids(
    root: &Path,
    stored: &loom_core::blob::StoredIds,
    keep: &mut HashSet<String>,
) -> Result<(), (PathBuf, std::io::Error)> {
    use std::io::ErrorKind::NotFound;
    let mut dirs = vec![root.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            // Vanished while scanning (a session directory being removed): nothing there to keep.
            Err(e) if e.kind() == NotFound => continue,
            Err(e) => return Err((dir, e)),
        };
        for entry in entries {
            let entry = entry.map_err(|e| (dir.clone(), e))?;
            let path = entry.path();
            let kind = match entry.file_type() {
                // A dangling or looping link at the top is nothing to read.
                Ok(t) if t.is_symlink() && dir == root => match std::fs::metadata(&path) {
                    Ok(m) => m.file_type(),
                    Err(_) => continue,
                },
                Ok(t) => t,
                Err(e) if e.kind() == NotFound => continue,
                Err(e) => return Err((path, e)),
            };
            if kind.is_dir() {
                dirs.push(path);
            } else if kind.is_file() {
                let file = match std::fs::File::open(&path) {
                    Ok(f) => f,
                    Err(e) if e.kind() == NotFound => continue,
                    Err(e) => return Err((path, e)),
                };
                // Replaced since it was listed by a link to something that is not a regular file: not read.
                if file.metadata().is_ok_and(|m| m.is_file()) {
                    loom_core::blob::scan_ids(file, stored, keep).map_err(|e| (path, e))?;
                }
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
        orch.spawn(&id, req("verifier", true)).await.unwrap();
        // `chat` is not in the lead's may_spawn: only the harness may start it.
        let err = orch.spawn(&id, req("chat", false)).await.unwrap_err();
        assert!(err.contains("is not a role this session can start"), "{err}");
        orch.spawn(&id, req("chat", true)).await.unwrap();
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

    /// A lead and one unfinished worker, both cut by a restart, and the runtime started again. Before
    /// the restart the worker is inside a model request; the lead is inside its `agent_spawn` call
    /// (`awaited`) or, with the worker in the background, inside a model request of its own.
    /// Afterwards the worker delivers `CHILDREPORT` and the lead waits for it. Returns the second
    /// runtime, the lead, and the number of requests made before the restart.
    async fn restart_with_an_unfinished_child(awaited: bool, attended: bool) -> (Env, Runtime, SessionId, usize) {
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
    async fn shutdown_inside_an_awaited_agent_spawn_records_no_result_and_the_child_is_resumed() {
        let (e, rt2, id, before) = restart_with_an_unfinished_child(true, false).await;
        the_child_was_resumed_as_the_lead_is_told(&e, &rt2, &id, before).await;
        // The call the shutdown cut has no result: the weave shows it as interrupted.
        let rs = rt2.records(&id, None, 2_000).unwrap();
        assert!(!rs.iter().any(|r| matches!(&r.event, Event::ToolResult(t) if t.name == "agent_spawn")));
        let first = e.server.requests()[before..].iter().find(|b| has_tool(b, "agent_spawn")).cloned().unwrap();
        assert!(mentions(&first, "no result recorded"), "{first}");
        rt2.shutdown().await;
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
        let cfg = sandbox_cfg_for(&base, ro, Path::new("/ws"));
        assert!(cfg.extra_writable.is_empty());
        assert!(cfg.protected_paths.contains(&"/ws".to_string()));
        let rw = packs.role(None, Some("worker")).unwrap();
        assert_eq!(sandbox_cfg_for(&base, rw, Path::new("/ws")), base);
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
        // What a command can leave in its scratch directory: a link to itself, two links to `.`, a dangling
        // link, and links to a directory and a file outside that name a blob.
        let s1 = home.join("sessions").join("s-gc1");
        let tmp = s1.join("tmp");
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(s1.join("log.jsonl"), format!("{{\"blob\":\"{in_log}\"}}\n")).unwrap();
        let out = e.dir.path().join("outside");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("names.txt"), &outside).unwrap();
        symlink("loop", tmp.join("loop")).unwrap();
        symlink(".", tmp.join("here")).unwrap();
        symlink(".", tmp.join("again")).unwrap();
        symlink("/nonexistent-loom-target", tmp.join("dangling")).unwrap();
        symlink(&out, tmp.join("out")).unwrap();
        symlink(out.join("names.txt"), tmp.join("names.txt")).unwrap();
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
        let locked = tmp.join("locked.txt");
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
