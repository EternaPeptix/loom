//! One session: its log, its step loop, and what it does with everything that can happen to it.
//!
//! CONTRACT (bodies are placeholders for the implementer; public signatures and types are fixed;
//! private fields and helpers are yours). `docs/DESIGN.md` §5, §8 and §9 are the base text; where this
//! file is more specific, this file wins. Every text shown to the model comes from `crate::texts`,
//! `crate::gate`, `crate::hud` or a tool — never write a new model-facing sentence here.
//!
//! A session is driven by exactly one task, which owns the [`Session`] and calls [`Session::run`].
//! Everything the session does is a record appended to its log, in the order it happened; every
//! appended record is passed to `Sink::record` right after the append. A failed append is fatal:
//! `run` returns [`End::Fatal`] with the error text and writes nothing more.
//!
//! ## Authors
//! `turn_start`, `turn_end`, `model_request`, `reweave`, `cache_break`, `interrupted`, `session_end`,
//! `job_registered`, and the `harness_note`/`inbox_opened` records this file writes: `Harness`.
//! `model_response`, `tool_call`: `Model`. `tool_result`, `job_settled`: `Tool`. `user_message`,
//! `inbox_resolved`: `User`. `child_settled`: `Agent(child)`. A note carrying an agent's message:
//! `Agent(sender)`. Records queued by tools (`Shared::take_emitted`) keep the author they were
//! queued with.
//!
//! ## Own records
//! A forked session's log starts with a copy of its parent's records. The session's *own* records
//! are those after its `forked` record (all records when there is none). Step counts, turn state,
//! budget, stall and HUD inputs are computed over own records only; the weave is computed over all.
//!
//! ## Constructors
//! - `create`: writes a new log at `deps.paths.session_log(id)` (creating the session directory and
//!   `deps.ctx.tmp_dir`) whose first record is `session_start` with `start.tools` replaced by the
//!   specs of the session's registry (`rtools::build_registry(&deps.shared)`, in registry order).
//!   When `assignment` is `Some((parent, text))`, the second record is
//!   `harness_note{Assignment, text}` authored `Agent(parent)`.
//! - `fork`: `loom_core::log::fork_file(parent_log, <own log path>, upto_seq, …)`, then appends
//!   `Event::Forked(forked)` (author `Agent(forked.parent)`).
//! - `open`: opens the existing log. If the log reports damage, appends
//!   `interrupted{reason: "the session log was damaged and was cut back to its last good record
//!   ({detail})"}`. If the own records contain a `turn_start` with no later `turn_end` and no
//!   `session_end`, appends `interrupted{REASON_RESTART}` and `turn_end{Stopped}`. Calls
//!   `deps.ctx.jobs.resume_from(n)` with the highest job number in the log's `job_registered`
//!   records (`j7` → 7).
//!
//! All three use `Durability::Always`, build the registry, and compute the state below from the
//! log, so that a session opened from its log behaves as the one that wrote it would:
//! `step` (own `model_request` records with purpose `Step`), `epoch`, `started_ms` (timestamp of
//! the own first record — `session_start` or `forked`), the last own `turn_end` reason, whether a
//! `session_end` exists, whether a `Budget` note has been given and how many steps followed it,
//! open inbox items (`inbox_opened` without a matching `inbox_resolved`).
//!
//! ## `run`
//! 1. If the session has ended (`session_end` in the log): return `End::Closed`.
//! 2. If the session is a child (`deps.shared.is_child()`) and has no own `turn_start` yet: run a
//!    turn with `Trigger::Start`.
//! 3. Loop: wait for the next of (an [`Input`], a `JobEvent` from `deps.job_events`). Handle it as
//!    described under *Idle*. When `inputs` is closed: kill the session's jobs
//!    (`jobs.kill_all(kill_grace_s)`) and return `End::Closed`.
//!
//! A turn that settles a child returns `End::Settled`; see *Settling*.
//!
//! ## Idle (no turn running)
//! - `Input::User(text)`: append `user_message{text}`. If the session has a mission journal whose
//!   ledger has no goal yet, `shared.ledger_append(true, GoalSet{text})` and append what it queued
//!   (`shared.take_emitted()`); a failure is logged with `tracing::warn!` and otherwise ignored.
//!   Start a turn (`Trigger::User`).
//! - `Input::Answer{item_id, answer}`: if no open inbox item of this session has that id, ignore.
//!   Otherwise append `inbox_resolved{item_id, answer}`; when the item has a `reference` and the
//!   session has a journal, `shared.ledger_append(true, QuestionAnswer{id: reference, answer})` and
//!   append what it queued (failure: warn, ignore); append
//!   `user_message{texts::inbox_answer(item.text, answer)}`; start a turn (`Trigger::InboxAnswer`).
//! - `Input::ChildSettled(s)`: append `child_settled{child, outcome, report, full, usage, steps,
//!   inline: false}`. Start a turn (`Trigger::ChildSettled`) only if the last turn ended `Waiting`
//!   or `Yielded`.
//! - `JobEvent::Registered(info)`: append `job_registered{job_id, call_id, command}`.
//! - `JobEvent::Settled{info, output, detail}`: append `job_settled{job_id, exit_code, output,
//!   detail}` (`exit_code` from `info.state` when it ended by exit). Then, unless the model has
//!   already been shown how the job ended — an own `tool_result` whose `meta[META_JOB]` is this id
//!   and which has `META_EXIT_CODE` or `META_SIGNAL` — append `harness_note{Arrival,
//!   texts::job_arrival(id, command, info.outcome(), detail, handle, lines, tail)}` where `tail` is
//!   the last `JOB_TAIL_LINES` lines of the stored output (`blobs.read_lines`), each cut with
//!   `texts::cut(line, JOB_TAIL_LINE_CHARS)`. When a note was appended and the last turn ended
//!   `Waiting` or `Yielded`, start a turn (`Trigger::JobSettled`).
//! - `Input::AgentMessage{from, text}`: append `harness_note{Arrival, texts::agent_message(text)}`
//!   authored `Agent(from)`. Start a turn (`Trigger::Resume`) only if the last turn ended `Waiting`.
//! - `Input::Resume`: start a turn (`Trigger::Resume`).
//! - `Input::Reweave`: run the re-weave procedure with reason `operator` (forced). No turn.
//! - `Input::Stop`: `jobs.kill_all`, `orch.stop_children(session)`. If any job or child was running,
//!   append `interrupted{REASON_OPERATOR}`. No turn.
//!
//! ## A turn
//! Install a fresh cancellation token (`Control::begin_turn`); append `turn_start{trigger}`. If the
//! previous own turn ended `Stopped`, append `harness_note{Interrupted, …}` with
//! `texts::AFTER_RESTART` when the most recent own `interrupted` record's reason is
//! `REASON_RESTART` or starts with `the session log was damaged`, else `texts::AFTER_STOP`.
//! Publish status (`Phase::Running`). Then repeat *steps* until the turn ends. Whenever the turn
//! ends, append `turn_end{reason}` and publish status (`Phase::Idle`, or `Ended` after settling).
//!
//! ### A step
//! 1. **Cancellation.** If the turn's token is cancelled (here or at any later point of the step):
//!    stop what is in flight, append `interrupted{reason}`, `jobs.kill_all`,
//!    `orch.stop_children(session)`. A child then settles `Stopped` with
//!    `texts::stopped_report(step)`; otherwise the turn ends `Stopped`. The reason is
//!    `REASON_PARENT` for a child, `REASON_OPERATOR` otherwise. A tool that was running when the
//!    token fired returns its own result, which is appended before `interrupted`; calls of the same
//!    reply that had not started get no record (the weave renders them as missing).
//! 2. **Arrivals.** Drain, without waiting, everything queued in `deps.job_events` and in the
//!    inputs channel, handling each as under *Idle* except that nothing starts a turn, `Resume` and
//!    `Stop` are ignored, and `Reweave` sets a flag that forces the re-weave in point 4. An arrival
//!    that appended a `user_message` resets the nudge count.
//! 3. **Budget** (only when the session's budget has a non-zero `max_steps` or `max_minutes`; own
//!    steps and minutes since `started_ms`): when either is reached and no `Budget` note has been
//!    given, append `harness_note{Budget, texts::budget_reached(step, minutes, can_finish)}`
//!    (`can_finish` = the registry has `finish`). When the note was given and `BUDGET_GRACE_STEPS`
//!    steps have run since, the child settles `BudgetExhausted` with
//!    `texts::budget_exhausted_report(step, minutes, last_reply)` (`last_reply` = text of the last
//!    own model response); a session that is not a child instead opens an inbox item (`Parked`,
//!    blocking, text `texts::turn_failed("The session's budget is used up.")`) and the turn ends
//!    `BudgetExhausted`.
//! 4. **Stall** (only for `Termination::Explicit` sessions with a journal; `agents.stall_steps > 0`):
//!    when the last `stall_steps` own steps contain no `ledger` record, no `tool_result` of class
//!    `Write` with status `Ok`, and no `child_spawned`/`child_settled`, and no `Stall` note was given
//!    within those steps, append `harness_note{Stall, texts::stall(stall_steps)}`.
//! 5. **Re-weave.** See below. Forced when the flag from point 2 is set.
//! 6. **Request.** `w = weave(all records)`. `PrefixGuard::check(w.epoch, &w.messages)`: on `Break`
//!    append `cache_break{req_id, first_diff_message, detail}` and carry on. Render the HUD
//!    (`hud::render`, over own records, with `jobs.list()` entries that are running,
//!    `orch.children(session)` entries that are running, the ledger when there is a journal,
//!    `BriefOpts::default()`, `agents.unviewed_min_lines`, own step count, `started_ms`, budget).
//!    Store the HUD text (`blobs.put_bytes`; a failure gives `hud: None`). Append
//!    `model_request{req_id: ids::new_request_id(), step (1-based), epoch, purpose: Step,
//!    n_messages, stable_hash: prefix::stable_hash(&w.messages), hud, est_tokens}`. Publish status
//!    with `fork_point` = the seq of the record before this `model_request`.
//!    Acquire the limiter (`deps.limiter.acquire(deps.priority, token)`; `None` = cancelled). Send
//!    `ChatRequest{messages: w.messages + weave::hud_message(hud), tools: w.tools, tool_choice:
//!    Auto, max_tokens: client.profile().max_output_tokens, seed: None, extra: empty}` with
//!    `client.complete`, forwarding every `StreamEvent` to `Sink::delta(session, req_id, …)` as it
//!    arrives.
//!    - `Err(Cancelled)`: point 1.
//!    - `Err(ContextOverflow)`: once per step, run the re-weave procedure forced with reason
//!      `overflow`; if it appended a `reweave`, go back to the start of this point (new weave, new
//!      `model_request`). Otherwise *fail* with `texts::OVERFLOW_UNFOLDABLE`.
//!    - any other error: *fail* with `texts::sentence(&error.to_string())`.
//!    - `Ok(c)`: calibrate the estimator with the characters sent (every message's `chars()`
//!      including the HUD message, plus the length of each tool spec's `to_openai()` JSON) against
//!      `c.usage.prompt_tokens` (skip when 0). Give every tool call whose id is empty or already
//!      used by a `tool_call` in this log a fresh id `call-{sortable}`. Append `model_response`
//!      (fields from the completion; `timing.queue_ms` = the permit's `waited_ms`). Publish status.
//!    *Fail* means: a child settles `Failed` with `texts::failed_report(why, last_reply)`; any other
//!    session opens an inbox item (`Parked`, blocking, text `texts::turn_failed(why)`) and the turn
//!    ends `Error`.
//! 7. **Reply handling.**
//!    - `finish` `Error` or `Aborted`: *fail* with `The model server ended the reply with an error.`
//!    - Run the complete tool calls in order (below). If the turn ended there, stop.
//!    - `finish == Length`: append `harness_note{OutputCut, texts::output_cut(completion_tokens,
//!      name of the first incomplete call if any, number of calls run)}` and go to the next step.
//!    - No complete tool call (and not `Length`): `gate::on_yield` with the reply text, the
//!      registry's names, the ledger (when there is a journal), the nudge count,
//!      `agents.max_nudges`, and the running job and child counts.
//!      `End` → the turn ends `Yielded`. `Nudge(t)` → append `harness_note{Nudge, t}`, count it,
//!      next step. `Park(t)` → a child settles `Failed` with `texts::gave_up_report(nudges,
//!      reply)`; any other session opens an inbox item (`Parked`, blocking, text `t`) and the turn
//!      ends `Parked`.
//!    - Otherwise next step. The nudge count returns to 0 whenever a tool call of the step ended
//!      with status `Ok`.
//!
//! ### Running the calls of a reply
//! For each complete call, in order: append `tool_call{call_id, req_id, name, args, class}` (`args`
//! = the arguments parsed as JSON, or the raw string as a JSON string when they do not parse;
//! `class` from the registry's spec, `State` for a name it does not have). Then:
//! - if an earlier call of this reply set an effect: the result is
//!   `loom_tools::refused(ctx, name, class, texts::not_run_after(<that call's name>), now)`;
//! - else if the name is not in the registry but is in `w.tools` (a forked session's request
//!   carries its parent's tool list): `refused(…, texts::not_in_assignment(name, role name,
//!   registry names), …)`;
//! - else `loom_tools::execute(registry, ctx, name, arguments, admission)` with a `ToolCtx` cloned
//!   from `deps.ctx` with this call's id and the turn's token, and `Admission{policy: &deps.admit,
//!   estimator}`.
//!
//! Append the `tool_result`, then every record the call queued (`shared.take_emitted()`), then take
//! the effect (`shared.take_effect()`). After the last call, apply the first effect that was set:
//! `EndTurn(reason)` ends the turn with that reason; `Settle(delivery)` settles the child (below).
//! Calls run one at a time.
//!
//! ## Settling (children)
//! Append `turn_end{reason}` and `session_end{outcome, detail}` per the table, kill the session's
//! jobs, publish status (`Phase::Ended`), and return `End::Settled(Settlement{child: id, role,
//! outcome, report, full, payload, steps: own steps, usage: sum of own responses' usage})`.
//! `Returned` → `Finished`/`Done`; `Blocked` → `Blocked`/`Done`; `BudgetExhausted` →
//! `BudgetExhausted`/`BudgetExhausted`; `Stopped` → `Stopped`/`Stopped`; `Failed` → `Error`/`Failed`.
//! `detail` is the first line of the report cut to 200 characters. For settlements this file makes
//! itself, `full` is `None` and `payload` is `Value::Null`.
//!
//! ## Re-weave procedure (`reason`: `target`, `overflow`, `operator`)
//! `est` = `estimator.tokens_for_messages(&weave(records).messages)` plus the tokens of the tool
//! specs' JSON. `limit` = `deps.context.target_tokens`, lowered to `window − reserve` when
//! `deps.context_window` is known and that is smaller (`reserve` = the profile's
//! `max_output_tokens` or 16_384, plus 4_096). Not forced and `est <= limit`: nothing to do.
//! 1. `plan = plan_reweave(records, estimator, &deps.context, false)`.
//! 2. If there is no plan, or its `after_tokens_est` is above the midpoint between
//!    `floor_tokens` and `limit`: ask for a digest — a request of the current stable messages plus
//!    one `user` message `texts::DIGEST_PROMPT`, same tools, `max_tokens: DIGEST_MAX_TOKENS`,
//!    recorded as `model_request{purpose: Digest, hud: None}` only (its reply is not appended as a
//!    record). A non-empty reply text is the digest; an error, a cancellation or an empty text gives
//!    none (a cancellation is then handled by the step). With a digest, replace the plan by
//!    `plan_reweave(records, estimator, &deps.context, true)` when that returns one.
//! 3. No plan: return without a record. Otherwise append `reweave{epoch: current + 1, upto_seq,
//!    evictions, brief: texts::reweave_brief(<ledger.brief(default) or "">), digest, reason,
//!    before_tokens: plan.before_tokens_est, after_tokens_est}`.
//!
//! ## Status
//! [`Status`] is published through `Sink::status` whenever a field changes. `prompt_tokens` and
//! `cached_tokens` are those of the latest response; `completion_tokens_total` sums own responses.
//!
//! ## Tests required (all against `loom_model::mock::MockServer`; tools run in a temp workspace
//! with `SandboxMode::None`; a collecting `Sink`; a fake `Orchestrator`)
//! - a lead turn: user message → reply with a `bash` call → reply with `finish` → records in the
//!   exact order of this contract, `turn_end{Finished}`, an inbox item, goal set in the ledger;
//! - the second request's messages start with the first request's stable messages byte for byte
//!   (compare the bodies the mock received), and the HUD is the last message of each and absent
//!   from the next;
//! - free-termination session: a text reply ends the turn `Yielded`; explicit: nudge, then park
//!   after `max_nudges`, with the inbox item; nudge count resets after a successful call;
//! - output cut with and without an incomplete call; the incomplete call is not run;
//! - several calls in one reply run in order; after an effect the rest are refused with
//!   `not_run_after`; emitted records follow their call's result;
//! - duplicate and empty call ids are replaced;
//! - a forked child: its first request starts with the parent's stable messages (byte-identical
//!   JSON), then the assignment; a tool outside its role is refused with `not_in_assignment`;
//!   `finish` settles it (`End::Settled`, `session_end`); budget note then `BudgetExhausted`;
//!   giving up after nudges settles `Failed`;
//! - a fresh child gets its assignment note and starts by itself;
//! - stop during a model reply and during a running `bash`: `interrupted`, `turn_end{Stopped}`,
//!   jobs killed; the next turn starts with the `AFTER_STOP` note;
//! - `open` on a log cut mid-turn: `interrupted{REASON_RESTART}`, and the next turn carries
//!   `AFTER_RESTART`; state (step, epoch, open inbox items) equals that of the session that wrote
//!   the log;
//! - a background job that ends while idle after `wait` resumes the session with an arrival note;
//!   a job whose end the model already saw through `job_wait` produces no note;
//! - inputs arriving mid-turn are in the next request; an inbox answer resolves the item, answers
//!   the ledger question and starts a turn;
//! - re-weave: with a small `target_tokens`, a `reweave` record appears, the epoch rises, the next
//!   request no longer carries the stubbed output, and no `cache_break` is recorded for it; the
//!   digest path (plan insufficient → digest request → text eviction) and its failure path;
//!   `ContextOverflow` from the server triggers a forced re-weave and a retry; unfoldable overflow
//!   fails the turn with an inbox item;
//! - a model error (`Rejected`) parks a lead with `turn_failed` and settles a child `Failed`;
//! - stall note after `stall_steps` steps of read-only calls, and not again until progress.

use crate::rtools::{Settlement, Shared};
use loom_core::admit::AdmitPolicy;
use loom_core::config::{AgentsCfg, Paths};
use loom_core::event::{Forked, Record, Seq, SessionOutcome, SessionStart, TurnEndReason};
use loom_core::ids::SessionId;
use loom_core::weave::ReweavePolicy;
use loom_model::assemble::StreamEvent;
use loom_model::client::ModelClient;
use loom_model::limit::{Limiter, Priority};
use loom_tools::jobs::JobEvent;
use loom_tools::ToolCtx;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio_util::sync::CancellationToken;

/// Something that happens to a session from outside.
#[derive(Clone, Debug)]
pub enum Input {
    /// The operator wrote to the session.
    User(String),
    /// The operator answered one of the session's inbox items.
    Answer { item_id: String, answer: String },
    /// A child that nobody was waiting for has settled.
    ChildSettled(Settlement),
    /// The agent that assigned this session's work sent it a message.
    AgentMessage { from: SessionId, text: String },
    /// Carry on (operator request, or recovery after a restart).
    Resume,
    /// Fold older material out of view now.
    Reweave,
    /// The operator pressed stop. The runtime also cancels the running turn through [`Control`];
    /// this input covers what is left when no turn is running.
    Stop,
}

/// Receives everything a session produces, as it happens. Calls must return quickly.
pub trait Sink: Send + Sync {
    fn record(&self, session: &SessionId, record: &Record);
    fn delta(&self, session: &SessionId, req_id: &str, event: &StreamEvent);
    fn status(&self, session: &SessionId, status: &Status);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// No turn is running; the session can be given input.
    Idle,
    Running,
    /// The session has a `session_end` record.
    Ended,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub phase: Phase,
    /// Own steps so far.
    pub step: u32,
    pub last_end: Option<TurnEndReason>,
    pub outcome: Option<SessionOutcome>,
    /// Seq of the last record that is part of the latest request's stable prefix: where a fork of
    /// this session is cut.
    pub fork_point: Option<Seq>,
    pub epoch: u32,
    pub prompt_tokens: u64,
    pub cached_tokens: u64,
    pub completion_tokens_total: u64,
    pub open_inbox: u32,
}

/// The stop switch a session shares with whoever may stop it.
#[derive(Debug, Default)]
pub struct Control {
    turn: Mutex<CancellationToken>,
}

impl Control {
    pub fn new() -> Control {
        Control::default()
    }

    /// Cancel the turn that is running now, if any. A turn started later is not affected.
    pub fn stop_turn(&self) {
        self.turn.lock().unwrap_or_else(|p| p.into_inner()).cancel();
    }

    /// Install and return the token of a new turn.
    pub(crate) fn begin_turn(&self) -> CancellationToken {
        let token = CancellationToken::new();
        *self.turn.lock().unwrap_or_else(|p| p.into_inner()) = token.clone();
        token
    }
}

/// Everything a session needs from the process around it.
pub struct Deps {
    pub paths: Paths,
    pub agents: AgentsCfg,
    pub context: ReweavePolicy,
    pub admit: AdmitPolicy,
    pub client: Arc<ModelClient>,
    pub limiter: Arc<Limiter>,
    pub priority: Priority,
    /// Context window of the served model, when known.
    pub context_window: Option<u64>,
    pub shared: Arc<Shared>,
    /// Template for tool calls: `call_id` and `cancel` are replaced for each call.
    pub ctx: ToolCtx,
    pub job_events: UnboundedReceiver<JobEvent>,
    pub sink: Arc<dyn Sink>,
    pub control: Arc<Control>,
}

/// How `run` ended.
#[derive(Clone, Debug, PartialEq)]
pub enum End {
    /// A child delivered (or failed to); the session is over.
    Settled(Settlement),
    /// The inputs channel closed, or the session had already ended.
    Closed,
    /// The log could not be written. Nothing more was recorded.
    Fatal(String),
}

pub struct Session {
    deps: Deps,
}

impl Session {
    /// A new session with a new log. See the module contract.
    pub fn create(deps: Deps, start: SessionStart, assignment: Option<(SessionId, String)>) -> Result<Session, String> {
        let _ = (deps, start, assignment);
        todo!("implement per module contract")
    }

    /// A new session whose log starts as a copy of `parent_log` up to `upto_seq`.
    pub fn fork(deps: Deps, parent_log: &Path, upto_seq: Seq, forked: Forked) -> Result<Session, String> {
        let _ = (deps, parent_log, upto_seq, forked);
        todo!("implement per module contract")
    }

    /// An existing session, from its log.
    pub fn open(deps: Deps) -> Result<Session, String> {
        let _ = deps;
        todo!("implement per module contract")
    }

    pub fn id(&self) -> &SessionId {
        &self.deps.shared.session
    }

    pub fn status(&self) -> Status {
        todo!("implement per module contract")
    }

    /// Every record of the log, in order.
    pub fn records(&self) -> &[Record] {
        todo!("implement per module contract")
    }

    /// Drive the session until it settles or `inputs` closes.
    pub async fn run(self, inputs: UnboundedReceiver<Input>) -> End {
        let _ = inputs;
        todo!("implement per module contract")
    }
}
