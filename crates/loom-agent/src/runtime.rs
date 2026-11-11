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
//! - `net.jsonl` — one [`NetEntry`] per line: every decision the egress proxy made for the session.
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
//!   Running`, or `last_end == Waiting`, or `open_inbox > 0` (parents before children — session ids
//!   sort by creation time);
//! - on demand, by `send_message`, `resume`, `reweave`, `answer`, and when a settlement has to be
//!   delivered to a parent that is not active.
//!
//! A session whose `status.json` says `phase == Ended` is never activated.
//!
//! When a session's task ends:
//! - `End::Settled(s)`: the session becomes inactive; its proxy grant is revoked; the settlement is
//!   kept (for `join`, `children`) — see *Children*.
//! - `End::Closed`: inactive.
//! - `End::Fatal(e)`: inactive; `tracing::error!`; a [`BusEvent::Error`]; the operator is notified
//!   (kind `error`). A child is then settled on its behalf so that nothing waits for it forever:
//!   `Settlement{outcome: Failed, report: texts::failed_report(&e, ""), full: None, payload: Null,
//!   steps and usage from the last status (usage: default)}`.
//!
//! ## Set-up of one session (`Deps`)
//! - `paths`, `agents`, `context`, `admit` from the config; `client` and `limiter` of the session's
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
//! agent finished.")`. The first successful join of a child queues
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
//! appended to the session's `net.jsonl` and published as [`BusEvent::Net`].
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
//!   `Input::User`.
//! - `stop(id)`: any session. Active: `control.stop_turn()` and `Input::Stop`. Not active: nothing.
//! - `resume(id)`: root only; activate; `Input::Resume` to it and to each of its unsettled children
//!   whose latest status has `last_end == Stopped` (activating them).
//! - `reweave(id)`: activate; `Input::Reweave`.
//! - `answer(item_id, answer)`: the item must be open (`There is no open inbox item {item_id}.`);
//!   an empty answer to a blocking item is refused (`This item is waiting for an answer; write
//!   one.`); activate the session; `Input::Answer`. (An empty answer to a non-blocking item
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
//!    Children restored this way count as not `awaited` from now on.
//!
//! ## Shutdown (`Runtime::shutdown`)
//! Mark the runtime as shutting down, then `Control::shutdown()` on every active session: a running
//! turn ends `Stopped` with `interrupted{REASON_RESTART}` and a child is **not** settled, so the
//! next start resumes what was running. From the moment the runtime is marked, the orchestrator's
//! `stop_child` and `stop_children` do nothing and return `Ok` (a parent whose awaited call was cut
//! must not end its child for good), and `spawn`/`poll` answer `The harness is shutting down.`
//! Then wait up to `tools.kill_grace_s + 5` seconds for the turns to end, close every inputs
//! channel, wait up to 5 more seconds for the tasks and abort the rest, shut the proxy down. After
//! `shutdown` every public method that returns a `Result` returns `The harness is shutting down.`
//! and the listing methods keep answering from what is known.
//!
//! ## Reading
//! - `sessions(include_archived)`: newest first. `session(id)`.
//! - `records(id, after, limit)`: `log::read_page(paths.session_log(id), after, min(limit, 2_000))`.
//! - `window(id)`: `log::read_records` → `weave` → [`WindowView`] (`est_tokens` with a default
//!   `TokenEstimator` over the messages plus the tool specs' JSON).
//! - `missions()`: one per root session. `ledger(mission)`: the journal read and folded
//!   (`No ledger: this mission's lead does not keep one.` when there is no journal file).
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

use crate::rtools::Settlement;
use crate::session::Status;
use loom_core::config::{Config, Paths};
use loom_core::event::{Budget, InboxItem, NetDecision, Record, Seq, SpawnMode};
use loom_core::ledger::LedgerState;
use loom_core::weave::WindowItem;
use loom_core::{BlobStore, MissionId, SessionId};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::broadcast;

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

/// The runtime. Cheap to clone; all clones are the same runtime.
#[derive(Clone)]
pub struct Runtime {
    inner: Arc<Inner>,
}

/// Private state; its fields are the implementer's.
struct Inner {
    config: Config,
    paths: Paths,
    blobs: BlobStore,
    bus: broadcast::Sender<BusEvent>,
}

impl Runtime {
    /// Bring the runtime up over `paths` and restore what was running. See *Start*.
    pub async fn start(config: Config, paths: Paths) -> Result<Runtime, String> {
        let _ = (config, paths);
        todo!("implement per module contract")
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
        todo!("implement per module contract")
    }

    pub fn subscribe(&self) -> broadcast::Receiver<BusEvent> {
        self.inner.bus.subscribe()
    }

    pub async fn create_session(&self, new: NewSession) -> Result<SessionInfo, String> {
        let _ = new;
        todo!("implement per module contract")
    }

    pub fn sessions(&self, include_archived: bool) -> Vec<SessionInfo> {
        let _ = include_archived;
        todo!("implement per module contract")
    }

    pub fn session(&self, id: &SessionId) -> Option<SessionInfo> {
        let _ = id;
        todo!("implement per module contract")
    }

    pub async fn send_message(&self, id: &SessionId, text: &str) -> Result<(), String> {
        let _ = (id, text);
        todo!("implement per module contract")
    }

    pub async fn stop(&self, id: &SessionId) -> Result<(), String> {
        let _ = id;
        todo!("implement per module contract")
    }

    pub async fn resume(&self, id: &SessionId) -> Result<(), String> {
        let _ = id;
        todo!("implement per module contract")
    }

    pub async fn reweave(&self, id: &SessionId) -> Result<(), String> {
        let _ = id;
        todo!("implement per module contract")
    }

    pub async fn archive(&self, id: &SessionId, archived: bool) -> Result<(), String> {
        let _ = (id, archived);
        todo!("implement per module contract")
    }

    pub fn inbox(&self) -> Vec<InboxEntry> {
        todo!("implement per module contract")
    }

    pub async fn answer(&self, item_id: &str, answer: &str) -> Result<(), String> {
        let _ = (item_id, answer);
        todo!("implement per module contract")
    }

    pub fn records(&self, id: &SessionId, after: Option<Seq>, limit: usize) -> Result<Vec<Record>, String> {
        let _ = (id, after, limit);
        todo!("implement per module contract")
    }

    pub fn window(&self, id: &SessionId) -> Result<WindowView, String> {
        let _ = id;
        todo!("implement per module contract")
    }

    pub fn missions(&self) -> Vec<MissionInfo> {
        todo!("implement per module contract")
    }

    pub fn ledger(&self, mission: &MissionId) -> Result<LedgerView, String> {
        let _ = mission;
        todo!("implement per module contract")
    }

    pub fn net(&self, id: &SessionId, limit: usize) -> Result<Vec<NetEntry>, String> {
        let _ = (id, limit);
        todo!("implement per module contract")
    }

    pub async fn health(&self) -> Vec<ModelHealth> {
        todo!("implement per module contract")
    }

    /// Stop everything in a way the next start can pick up. See *Shutdown*.
    pub async fn shutdown(&self) {
        todo!("implement per module contract")
    }
}
