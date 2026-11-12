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
//! - `Input::Constraint(text)`: a standing rule from the operator. Blank text is ignored. With a
//!   journal, `shared.ledger_append(true, ConstraintAdd{text})` and append what it queued (failure:
//!   warn, carry on without an id). Append `harness_note{Constraint, texts::constraint(id, text)}`
//!   with author `User`, `id` being the new constraint's ledger id when there is one. It starts no
//!   turn: it is in view from the next request on, it is never folded out of view, and through the
//!   ledger it is in the state block of every agent of the mission.
//! - `Input::Approval{text, scope}`: the same with `ApprovalGrant{text, scope}`,
//!   `harness_note{Approval, texts::approval(id, text, scope)}`.
//! - `Input::Withdraw{id, reason}`: `shared.ledger_append(true, ConstraintRetire{id, reason})`; on
//!   success append what it queued and `harness_note{Constraint, texts::constraint_withdrawn(id,
//!   reason)}` with author `User`; on refusal (or without a journal) warn and append nothing.
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
//!
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
//! A plan is *enough* when its `after_tokens_est` is at or below the midpoint between `floor_tokens`
//! and `limit`.
//! 1. `plan = plan_reweave(records, estimator, &policy, false)` with `policy = deps.context`. While
//!    the plan is not enough and `policy.keep_recent_steps` is above `MIN_KEEP_RECENT_STEPS`, halve
//!    `keep_recent_steps` (not below the minimum) and plan again: when folding what lies outside the
//!    protected recent steps does not make room, it is the output of recent steps that fills the
//!    window, so fewer of them are protected.
//! 2. Still not enough: `text_plan = plan_reweave(records, estimator, &policy, true)`. Not forced
//!    and `text_plan` is not enough either: return without a record and without a digest request (see
//!    "Why a re-weave must be worth it"). Otherwise, when `text_plan` exists, ask for a digest — a
//!    request of the current stable messages plus one `user` message `texts::DIGEST_PROMPT`, same
//!    tools, `max_tokens: DIGEST_MAX_TOKENS`, recorded as `model_request{purpose: Digest, hud: None}`
//!    only (its reply is not appended as a record). A non-empty reply text is the digest; an error
//!    or an empty text gives none. A cancellation returns without a record (the step handles it).
//!    The plan becomes `text_plan`, with or without a digest: the ledger brief is the durable state,
//!    the digest an addition to it.
//! 3. No plan: return without a record. Otherwise append `reweave{epoch: current + 1, upto_seq,
//!    evictions, brief: texts::reweave_brief(<ledger.brief(default) or "">), digest, reason,
//!    before_tokens: plan.before_tokens_est, after_tokens_est}`.
//!
//! Why a re-weave must be worth it: every re-weave starts a new epoch, and the server's cache of
//! the conversation is lost with the old one. A re-weave that frees little is needed again one step
//! later, and again after that, each at the price of re-reading the whole context. So one that was
//! not asked for (`target`) happens only when it buys room for a long stretch of steps; otherwise
//! the context is left to grow until the window itself forces one (`overflow`).
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

use crate::gate::{self, Yield, YieldCtx};
use crate::hud::{self, HudChild, HudInput, HudJob};
use crate::rtools::{build_registry, ChildInfo, Delivery, Effect, Settlement, Shared};
use crate::texts;
use futures_util::FutureExt;
use loom_core::admit::AdmitPolicy;
use loom_core::config::{AgentsCfg, Paths};
use loom_core::estimate::TokenEstimator;
use loom_core::event::{
    Author, Budget, ChildOutcome, ChildSettled, Event, FinishReason, Forked, InboxItem, InboxKind, ModelRequest,
    ModelResponse, NoteKind, Purpose, Record, Reweave, Seq, SessionOutcome, SessionStart, Termination, Timing, ToolCall,
    ToolCallRequest, ToolClass, ToolSpec, ToolStatus, TurnEndReason, Trigger, Usage, META_EXIT_CODE, META_JOB,
    META_SIGNAL,
};
use loom_core::ids::{new_item_id, new_request_id, CallId, SessionId};
use loom_core::ledger::{BriefOpts, LedgerOp, LedgerState};
use loom_core::log::{fork_file, read_records, Durability, SessionLog};
use loom_core::message::Message;
use loom_core::now_ms;
use loom_core::prefix::{stable_hash, PrefixCheck, PrefixGuard};
use loom_core::weave::{hud_message, plan_reweave, weave, ReweavePolicy};
use loom_model::assemble::{Completion, StreamEvent};
use loom_model::client::{ModelClient, ModelError};
use loom_model::limit::{Limiter, Priority};
use loom_model::request::{ChatRequest, ToolChoice};
use loom_tools::jobs::{JobEvent, JobInfo, JobState};
use loom_tools::proc::Ended;
use loom_tools::{execute, refused, Admission, Registry, ToolCtx};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use tokio_util::sync::CancellationToken;

/// Something that happens to a session from outside.
#[derive(Clone, Debug)]
pub enum Input {
    /// The operator wrote to the session.
    User(String),
    /// The operator answered one of the session's inbox items.
    Answer { item_id: String, answer: String },
    /// The operator set a standing rule for the mission.
    Constraint(String),
    /// The operator approved something. `scope` says what the approval covers (may be empty).
    Approval { text: String, scope: String },
    /// The operator withdrew a standing rule (`id` is its ledger id, `k2`).
    Withdraw { id: String, reason: String },
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
    /// The harness is going down: a cancelled turn is recorded as cut by the restart, and a child is
    /// not settled by it.
    shutting: std::sync::atomic::AtomicBool,
}

impl Control {
    pub fn new() -> Control {
        Control::default()
    }

    /// Cancel the turn that is running now, if any. A turn started later is not affected.
    pub fn stop_turn(&self) {
        self.turn.lock().unwrap_or_else(|p| p.into_inner()).cancel();
    }

    /// Cancel the running turn because the harness is shutting down. The session records the cut as
    /// a restart (not as an operator stop), so the next start resumes it; no later turn starts.
    pub fn stop_for_shutdown(&self) {
        self.shutting.store(true, std::sync::atomic::Ordering::SeqCst);
        self.stop_turn();
    }

    fn is_shutting(&self) -> bool {
        self.shutting.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Install and return the token of a new turn.
    pub(crate) fn begin_turn(&self) -> CancellationToken {
        let token = CancellationToken::new();
        if self.is_shutting() {
            token.cancel();
        }
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

/// A failed append: the session stops writing and `run` reports it.
#[derive(Debug)]
struct Fatal(String);

type R<T> = Result<T, Fatal>;

/// What the next step of a turn is, or how the turn ends.
enum Flow {
    Next,
    End(TurnEndReason),
    Settle(Delivery),
}

/// Everything about a session that is read off its log. `absorb` is the only writer, and it sees
/// every record in log order, so a session opened from its log has the state of the one that wrote it.
#[derive(Default)]
struct State {
    /// Index in the records of the session's first own record (`session_start` or `forked`).
    own_from: usize,
    started_ms: u64,
    step: u32,
    epoch: u32,
    termination: Option<Termination>,
    budget: Budget,
    has_turn: bool,
    last_end: Option<TurnEndReason>,
    ended: Option<SessionOutcome>,
    /// Own steps counted when the `Budget` note was given.
    budget_note_step: Option<u32>,
    inbox: Vec<InboxItem>,
    last_interrupted: Option<String>,
    prompt_tokens: u64,
    cached_tokens: u64,
    usage: Usage,
    fork_point: Option<Seq>,
}

impl State {
    fn absorb(&mut self, idx: usize, rec: &Record) {
        match &rec.event {
            Event::SessionStart(s) => {
                self.own_from = idx;
                self.started_ms = rec.ts_ms;
                self.termination = Some(s.termination);
                self.budget = s.budget.clone();
            }
            Event::Forked(f) => {
                *self = State {
                    own_from: idx,
                    started_ms: rec.ts_ms,
                    epoch: self.epoch,
                    termination: Some(f.termination),
                    budget: f.budget.clone(),
                    ..State::default()
                };
            }
            Event::ModelRequest(m) if m.purpose == Purpose::Step => {
                self.step = self.step.saturating_add(1);
                self.fork_point = rec.seq.checked_sub(1);
            }
            Event::ModelResponse(r) => {
                self.prompt_tokens = r.usage.prompt_tokens;
                self.cached_tokens = r.usage.cached_tokens;
                self.usage.prompt_tokens = self.usage.prompt_tokens.saturating_add(r.usage.prompt_tokens);
                self.usage.cached_tokens = self.usage.cached_tokens.saturating_add(r.usage.cached_tokens);
                self.usage.completion_tokens = self.usage.completion_tokens.saturating_add(r.usage.completion_tokens);
                self.usage.reasoning_tokens = self.usage.reasoning_tokens.saturating_add(r.usage.reasoning_tokens);
            }
            Event::Reweave(r) => self.epoch = r.epoch,
            Event::HarnessNote { note: NoteKind::Budget, .. } => self.budget_note_step = Some(self.step),
            Event::InboxOpened(item) => self.inbox.push(item.clone()),
            Event::InboxResolved { item_id, .. } => self.inbox.retain(|i| &i.item_id != item_id),
            Event::TurnStart { .. } => self.has_turn = true,
            Event::TurnEnd { reason } => self.last_end = Some(*reason),
            Event::SessionEnd { outcome, .. } => self.ended = Some(*outcome),
            Event::Interrupted { reason } => self.last_interrupted = Some(reason.clone()),
            _ => {}
        }
    }
}

/// What an input that arrived changed.
#[derive(Default)]
struct Arrival {
    /// The turn it starts when the session is idle.
    trigger: Option<Trigger>,
    /// A `user_message` was appended.
    user: bool,
}

/// What the calls of one reply did.
#[derive(Default)]
struct Calls {
    ran: usize,
    effect: Option<Effect>,
    cancelled: bool,
}

pub struct Session {
    deps: Deps,
    log: SessionLog,
    records: Vec<Record>,
    registry: Registry,
    estimator: TokenEstimator,
    guard: PrefixGuard,
    inputs: Option<UnboundedReceiver<Input>>,
    jobs_open: bool,
    token: CancellationToken,
    nudges: u32,
    phase: Phase,
    st: State,
    published: Option<Status>,
    /// Jobs that `open` found registered and never settled, and recorded as lost.
    lost_jobs: usize,
}

/// Longest `session_end` detail.
const DETAIL_CHARS: usize = 200;

/// A re-weave never protects fewer recent steps than this.
const MIN_KEEP_RECENT_STEPS: u32 = 2;

fn fatal(e: impl std::fmt::Display) -> Fatal {
    Fatal(e.to_string())
}

/// `n` as the `u32` the schema wants.
fn to_u32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// Characters of the tool specs as they are sent.
fn tools_chars(tools: &[ToolSpec]) -> usize {
    tools.iter().map(|t| t.to_openai().to_string().len()).sum()
}

/// The newline count of a file, i.e. the lines of a running job's output so far.
fn count_lines(path: &Path) -> u64 {
    use std::io::Read;
    let Ok(mut file) = std::fs::File::open(path) else { return 0 };
    let mut buf = vec![0u8; 64 * 1024];
    let mut lines: u64 = 0;
    let mut last: Option<u8> = None;
    loop {
        match file.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let chunk = buf.get(..n).unwrap_or_default();
                lines = lines.saturating_add(chunk.iter().filter(|b| **b == b'\n').count() as u64);
                last = chunk.last().copied();
            }
        }
    }
    if last.is_some_and(|b| b != b'\n') {
        lines = lines.saturating_add(1);
    }
    lines
}

fn delivery(outcome: ChildOutcome, report: String) -> Delivery {
    Delivery { outcome, report, full: None, payload: Value::Null }
}

impl Session {
    fn bare(deps: Deps, log: SessionLog, records: Vec<Record>, registry: Registry) -> Session {
        let mut st = State::default();
        for (i, r) in records.iter().enumerate() {
            st.absorb(i, r);
        }
        let phase = if st.ended.is_some() { Phase::Ended } else { Phase::Idle };
        Session {
            deps,
            log,
            records,
            registry,
            estimator: TokenEstimator::default(),
            guard: PrefixGuard::new(),
            inputs: None,
            jobs_open: true,
            token: CancellationToken::new(),
            nudges: 0,
            phase,
            st,
            published: None,
            lost_jobs: 0,
        }
    }

    fn prepare(deps: &Deps) -> Result<Registry, String> {
        std::fs::create_dir_all(&deps.ctx.tmp_dir)
            .map_err(|e| format!("cannot create the session's temp directory {}: {e}", deps.ctx.tmp_dir.display()))?;
        build_registry(&deps.shared)
    }

    /// A new session with a new log. See the module contract.
    pub fn create(deps: Deps, start: SessionStart, assignment: Option<(SessionId, String)>) -> Result<Session, String> {
        let registry = Session::prepare(&deps)?;
        let path = deps.paths.session_log(&deps.shared.session);
        let log = SessionLog::create(&path, Durability::Always).map_err(|e| e.to_string())?;
        let mut start = start;
        start.tools = registry.specs();
        let mut session = Session::bare(deps, log, Vec::new(), registry);
        session.append(Author::Harness, Event::SessionStart(start)).map_err(|e| e.0)?;
        if let Some((parent, text)) = assignment {
            session
                .append(Author::Agent(parent), Event::HarnessNote { note: NoteKind::Assignment, text })
                .map_err(|e| e.0)?;
        }
        Ok(session)
    }

    /// A new session whose log starts as a copy of `parent_log` up to `upto_seq`.
    pub fn fork(deps: Deps, parent_log: &Path, upto_seq: Seq, forked: Forked) -> Result<Session, String> {
        let registry = Session::prepare(&deps)?;
        let path = deps.paths.session_log(&deps.shared.session);
        let log = fork_file(parent_log, &path, upto_seq, Durability::Always).map_err(|e| e.to_string())?;
        let records = read_records(&path).map_err(|e| e.to_string())?.records;
        let mut session = Session::bare(deps, log, records, registry);
        let parent = forked.parent.clone();
        session.append(Author::Agent(parent), Event::Forked(forked)).map_err(|e| e.0)?;
        Ok(session)
    }

    /// An existing session, from its log.
    pub fn open(deps: Deps) -> Result<Session, String> {
        let registry = Session::prepare(&deps)?;
        let path = deps.paths.session_log(&deps.shared.session);
        let (log, report) = SessionLog::open(&path, Durability::Always).map_err(|e| e.to_string())?;
        if report.records.is_empty() {
            return Err(format!("the session log {} holds no readable record", path.display()));
        }
        let top = report
            .records
            .iter()
            .filter_map(|r| match &r.event {
                Event::JobRegistered { job_id, .. } => job_id.strip_prefix('j').and_then(|n| n.parse::<u64>().ok()),
                _ => None,
            })
            .max();
        let mut session = Session::bare(deps, log, report.records, registry);
        if let Some(damage) = &report.damage {
            let reason =
                format!("the session log was damaged and was cut back to its last good record ({})", damage.detail);
            session.append(Author::Harness, Event::Interrupted { reason }).map_err(|e| e.0)?;
        }
        if session.has_open_turn() {
            session
                .append(Author::Harness, Event::Interrupted { reason: texts::REASON_RESTART.to_string() })
                .map_err(|e| e.0)?;
            session
                .append(Author::Harness, Event::TurnEnd { reason: TurnEndReason::Stopped })
                .map_err(|e| e.0)?;
        }
        session.record_lost_jobs()?;
        if let Some(n) = top {
            // `resume_from` only takes a lock; it never waits.
            let _ = session.deps.ctx.jobs.resume_from(n).now_or_never();
        }
        Ok(session)
    }

    /// Jobs that were running when the harness went down and were recorded as lost by `open`.
    pub fn lost_jobs(&self) -> usize {
        self.lost_jobs
    }

    /// A job registered and never settled belonged to a process that is gone: settle it in the log
    /// and tell the model, so that a session waiting on it wakes knowing.
    fn record_lost_jobs(&mut self) -> Result<(), String> {
        if self.st.ended.is_some() {
            return Ok(());
        }
        let own = self.own();
        let settled: std::collections::HashSet<&str> = own
            .iter()
            .filter_map(|r| match &r.event {
                Event::JobSettled { job_id, .. } => Some(job_id.as_str()),
                _ => None,
            })
            .collect();
        let lost: Vec<(String, String)> = own
            .iter()
            .filter_map(|r| match &r.event {
                Event::JobRegistered { job_id, command, .. } if !settled.contains(job_id.as_str()) => {
                    Some((job_id.clone(), command.clone()))
                }
                _ => None,
            })
            .collect();
        for (job_id, command) in lost {
            let note = texts::job_lost(&job_id, &command);
            let detail = texts::JOB_LOST_DETAIL.to_string();
            self.append(Author::Harness, Event::JobSettled { job_id, exit_code: None, output: None, detail })
                .map_err(|e| e.0)?;
            self.note(Author::Harness, NoteKind::Arrival, note).map_err(|e| e.0)?;
            self.lost_jobs = self.lost_jobs.saturating_add(1);
        }
        Ok(())
    }

    pub fn id(&self) -> &SessionId {
        &self.deps.shared.session
    }

    pub fn status(&self) -> Status {
        Status {
            phase: self.phase,
            step: self.st.step,
            last_end: self.st.last_end,
            outcome: self.st.ended,
            fork_point: self.st.fork_point,
            epoch: self.st.epoch,
            prompt_tokens: self.st.prompt_tokens,
            cached_tokens: self.st.cached_tokens,
            completion_tokens_total: self.st.usage.completion_tokens,
            open_inbox: to_u32(self.st.inbox.len()),
        }
    }

    /// Every record of the log, in order.
    pub fn records(&self) -> &[Record] {
        &self.records
    }

    /// Drive the session until it settles or `inputs` closes.
    pub async fn run(mut self, inputs: UnboundedReceiver<Input>) -> End {
        self.inputs = Some(inputs);
        match self.drive().await {
            Ok(end) => end,
            Err(Fatal(why)) => End::Fatal(why),
        }
    }

    // ---- the log -------------------------------------------------------------------------------

    fn append(&mut self, author: Author, event: Event) -> R<Seq> {
        let record = self.log.append(author, event).map_err(fatal)?;
        self.st.absorb(self.records.len(), &record);
        self.deps.sink.record(&self.deps.shared.session, &record);
        let seq = record.seq;
        self.records.push(record);
        Ok(seq)
    }

    /// Append what a tool or the ledger queued, in the order queued, with the authors it gave.
    fn flush_emitted(&mut self) -> R<()> {
        for (author, event) in self.deps.shared.take_emitted() {
            self.append(author, event)?;
        }
        Ok(())
    }

    fn note(&mut self, author: Author, note: NoteKind, text: String) -> R<()> {
        self.append(author, Event::HarnessNote { note, text }).map(|_| ())
    }

    fn open_inbox(&mut self, kind: InboxKind, text: String) -> R<()> {
        let item = InboxItem {
            item_id: new_item_id(),
            kind,
            text,
            options: Vec::new(),
            blocking: true,
            call_id: None,
            reference: None,
        };
        self.append(Author::Harness, Event::InboxOpened(item)).map(|_| ())
    }

    fn publish(&mut self) {
        let status = self.status();
        if self.published.as_ref() != Some(&status) {
            self.deps.sink.status(&self.deps.shared.session, &status);
            self.published = Some(status);
        }
    }

    fn own(&self) -> &[Record] {
        self.records.get(self.st.own_from..).unwrap_or_default()
    }

    /// A `turn_start` with no later `turn_end`, in a session that has not ended.
    fn has_open_turn(&self) -> bool {
        if self.st.ended.is_some() {
            return false;
        }
        let own = self.own();
        let start = own.iter().rposition(|r| matches!(r.event, Event::TurnStart { .. }));
        let end = own.iter().rposition(|r| matches!(r.event, Event::TurnEnd { .. }));
        match (start, end) {
            (Some(s), Some(e)) => s > e,
            (Some(_), None) => true,
            _ => false,
        }
    }

    /// The text of the last own model response.
    fn last_reply(&self) -> String {
        self.own()
            .iter()
            .rev()
            .find_map(|r| match &r.event {
                Event::ModelResponse(m) => Some(m.text.clone()),
                _ => None,
            })
            .unwrap_or_default()
    }

    fn grace(&self) -> Duration {
        Duration::from_secs(self.deps.ctx.cfg.kill_grace_s)
    }

    async fn running_jobs(&self) -> Vec<JobInfo> {
        self.deps.ctx.jobs.list().await.into_iter().filter(|j| j.state == JobState::Running).collect()
    }

    async fn running_children(&self) -> Vec<ChildInfo> {
        self.deps.shared.orch.children(&self.deps.shared.session).await.into_iter().filter(|c| c.running).collect()
    }

    // ---- the idle loop -------------------------------------------------------------------------

    async fn drive(&mut self) -> R<End> {
        if self.st.ended.is_some() {
            self.phase = Phase::Ended;
            self.publish();
            return Ok(End::Closed);
        }
        self.publish();
        if self.deps.shared.is_child() && !self.st.has_turn {
            if let Some(settled) = self.turn(Trigger::Start).await? {
                return Ok(End::Settled(settled));
            }
        }
        loop {
            enum Ev {
                Input(Option<Input>),
                Job(Option<JobEvent>),
            }
            let jobs_open = self.jobs_open;
            let ev = {
                let Some(rx) = self.inputs.as_mut() else { return Ok(End::Closed) };
                tokio::select! {
                    i = rx.recv() => Ev::Input(i),
                    j = self.deps.job_events.recv(), if jobs_open => Ev::Job(j),
                }
            };
            let trigger = match ev {
                Ev::Input(None) => {
                    self.deps.ctx.jobs.kill_all(self.grace()).await;
                    return Ok(End::Closed);
                }
                Ev::Input(Some(input)) => self.idle_input(input).await?,
                Ev::Job(Some(event)) => self.on_job_event(event).await?.then_some(Trigger::JobSettled),
                Ev::Job(None) => {
                    self.jobs_open = false;
                    None
                }
            };
            if let Some(trigger) = trigger {
                if let Some(settled) = self.turn(trigger).await? {
                    return Ok(End::Settled(settled));
                }
            }
        }
    }

    async fn idle_input(&mut self, input: Input) -> R<Option<Trigger>> {
        match input {
            Input::Resume => Ok(Some(Trigger::Resume)),
            Input::Reweave => {
                let token = self.deps.control.begin_turn();
                self.reweave("operator", true, &token).await?;
                Ok(None)
            }
            Input::Stop => {
                let jobs = !self.running_jobs().await.is_empty();
                let children = !self.running_children().await.is_empty();
                self.deps.ctx.jobs.kill_all(self.grace()).await;
                self.deps.shared.orch.stop_children(&self.deps.shared.session).await;
                if jobs || children {
                    self.append(Author::Harness, Event::Interrupted { reason: texts::REASON_OPERATOR.to_string() })?;
                }
                Ok(None)
            }
            other => Ok(self.arrival(other).await?.trigger),
        }
    }

    /// Record an input that is not a command. Whether it starts a turn is the caller's business.
    async fn arrival(&mut self, input: Input) -> R<Arrival> {
        let mut out = Arrival::default();
        match input {
            Input::User(text) => {
                self.append(Author::User, Event::UserMessage { text: text.clone() })?;
                self.record_goal(&text)?;
                out.trigger = Some(Trigger::User);
                out.user = true;
            }
            Input::Answer { item_id, answer } => {
                let Some(item) = self.st.inbox.iter().find(|i| i.item_id == item_id).cloned() else { return Ok(out) };
                self.append(Author::User, Event::InboxResolved { item_id, answer: answer.clone() })?;
                if let (Some(reference), true) = (&item.reference, self.deps.shared.journal.is_some()) {
                    let op = LedgerOp::QuestionAnswer { id: reference.clone(), answer: answer.clone() };
                    if let Err(e) = self.deps.shared.ledger_append(true, op) {
                        tracing::warn!(session = %self.deps.shared.session, "answer not recorded in the ledger: {e}");
                    }
                    self.flush_emitted()?;
                }
                self.append(Author::User, Event::UserMessage { text: texts::inbox_answer(&item.text, &answer) })?;
                out.trigger = Some(Trigger::InboxAnswer);
                out.user = true;
            }
            Input::Constraint(text) => {
                if text.trim().is_empty() {
                    return Ok(out);
                }
                let state = self.operator_op(LedgerOp::ConstraintAdd { text: text.clone() })?;
                let id = state.and_then(|s| s.constraints.last().map(|c| c.id.clone()));
                self.note(Author::User, NoteKind::Constraint, texts::constraint(id.as_deref(), &text))?;
            }
            Input::Approval { text, scope } => {
                if text.trim().is_empty() {
                    return Ok(out);
                }
                let state = self.operator_op(LedgerOp::ApprovalGrant { text: text.clone(), scope: scope.clone() })?;
                let id = state.and_then(|s| s.approvals.last().map(|a| a.id.clone()));
                self.note(Author::User, NoteKind::Approval, texts::approval(id.as_deref(), &text, &scope))?;
            }
            Input::Withdraw { id, reason } => {
                let op = LedgerOp::ConstraintRetire { id: id.clone(), reason: reason.clone() };
                if self.operator_op(op)?.is_some() {
                    self.note(Author::User, NoteKind::Constraint, texts::constraint_withdrawn(&id, &reason))?;
                }
            }
            Input::ChildSettled(s) => {
                let child = s.child.clone();
                let event = Event::ChildSettled(ChildSettled {
                    child: s.child,
                    outcome: s.outcome,
                    report: s.report,
                    full: s.full,
                    usage: s.usage,
                    steps: s.steps,
                    inline: false,
                });
                self.append(Author::Agent(child), event)?;
                if matches!(self.st.last_end, Some(TurnEndReason::Waiting | TurnEndReason::Yielded)) {
                    out.trigger = Some(Trigger::ChildSettled);
                }
            }
            Input::AgentMessage { from, text } => {
                self.note(Author::Agent(from), NoteKind::Arrival, texts::agent_message(&text))?;
                if self.st.last_end == Some(TurnEndReason::Waiting) {
                    out.trigger = Some(Trigger::Resume);
                }
            }
            Input::Resume | Input::Reweave | Input::Stop => {}
        }
        Ok(out)
    }

    /// Write an entry that only the operator may write. `None` when the session has no ledger or the
    /// ledger refused the entry.
    fn operator_op(&mut self, op: LedgerOp) -> R<Option<LedgerState>> {
        if self.deps.shared.journal.is_none() {
            return Ok(None);
        }
        match self.deps.shared.ledger_append(true, op) {
            Ok((_, state)) => {
                self.flush_emitted()?;
                Ok(Some(state))
            }
            Err(e) => {
                tracing::warn!(session = %self.deps.shared.session, "operator entry not recorded in the ledger: {e}");
                Ok(None)
            }
        }
    }

    /// The first user message of a mission sets its goal.
    fn record_goal(&mut self, text: &str) -> R<()> {
        if self.deps.shared.journal.is_none() {
            return Ok(());
        }
        match self.deps.shared.ledger() {
            Ok(state) if state.goal.is_none() => {
                if let Err(e) = self.deps.shared.ledger_append(true, LedgerOp::GoalSet { text: text.to_string() }) {
                    tracing::warn!(session = %self.deps.shared.session, "goal not recorded in the ledger: {e}");
                }
                self.flush_emitted()?;
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(session = %self.deps.shared.session, "ledger unreadable: {e}"),
        }
        Ok(())
    }

    /// Record a job event. True when a note was appended that should wake a waiting session.
    async fn on_job_event(&mut self, event: JobEvent) -> R<bool> {
        match event {
            JobEvent::Registered(info) => {
                self.append(
                    Author::Harness,
                    Event::JobRegistered { job_id: info.id, call_id: info.call_id, command: info.command },
                )?;
                Ok(false)
            }
            JobEvent::Settled { info, output, detail } => {
                let exit_code = match &info.state {
                    JobState::Ended(Ended::Exit(n)) => Some(*n),
                    _ => None,
                };
                self.append(
                    Author::Tool,
                    Event::JobSettled { job_id: info.id.clone(), exit_code, output: output.clone(), detail: detail.clone() },
                )?;
                let seen = self.own().iter().any(|r| match &r.event {
                    Event::ToolResult(t) => {
                        t.meta.get(META_JOB).and_then(Value::as_str) == Some(info.id.as_str())
                            && (t.meta.contains_key(META_EXIT_CODE) || t.meta.contains_key(META_SIGNAL))
                    }
                    _ => false,
                });
                if seen {
                    return Ok(false);
                }
                let (handle, lines, tail) = match &output {
                    Some(blob) => {
                        let first = blob.lines.saturating_sub(texts::JOB_TAIL_LINES).saturating_add(1);
                        let tail = match self.deps.ctx.blobs.read_lines(&blob.id, first, blob.lines) {
                            Ok(slice) => slice
                                .text
                                .lines()
                                .map(|l| texts::cut(l, texts::JOB_TAIL_LINE_CHARS))
                                .collect::<Vec<_>>()
                                .join("\n"),
                            Err(_) => String::new(),
                        };
                        (Some(blob.handle()), blob.lines, tail)
                    }
                    None => (None, 0, String::new()),
                };
                let text = texts::job_arrival(
                    &info.id,
                    &info.command,
                    &info.state.outcome(),
                    &detail,
                    handle.as_deref(),
                    lines,
                    &tail,
                );
                self.note(Author::Harness, NoteKind::Arrival, text)?;
                Ok(matches!(self.st.last_end, Some(TurnEndReason::Waiting | TurnEndReason::Yielded)))
            }
        }
    }

    // ---- a turn --------------------------------------------------------------------------------

    /// Run one turn. `Some` when it settled the (child) session.
    async fn turn(&mut self, trigger: Trigger) -> R<Option<Settlement>> {
        self.token = self.deps.control.begin_turn();
        self.nudges = 0;
        self.append(Author::Harness, Event::TurnStart { trigger })?;
        if self.st.last_end == Some(TurnEndReason::Stopped) {
            let restarted = self
                .st
                .last_interrupted
                .as_deref()
                .is_some_and(|r| r == texts::REASON_RESTART || r.starts_with("the session log was damaged"));
            let text = if restarted { texts::AFTER_RESTART } else { texts::AFTER_STOP };
            self.note(Author::Harness, NoteKind::Interrupted, text.to_string())?;
        }
        self.phase = Phase::Running;
        self.publish();
        let flow = loop {
            match self.step().await? {
                Flow::Next => {}
                other => break other,
            }
        };
        match flow {
            Flow::Next => Ok(None),
            Flow::End(reason) => {
                self.end_turn(reason)?;
                Ok(None)
            }
            Flow::Settle(d) if self.deps.shared.is_child() => Ok(Some(self.settle(d).await?)),
            Flow::Settle(d) => {
                let reason = match d.outcome {
                    ChildOutcome::Returned => TurnEndReason::Finished,
                    ChildOutcome::Blocked => TurnEndReason::Blocked,
                    ChildOutcome::Stopped => TurnEndReason::Stopped,
                    ChildOutcome::BudgetExhausted => TurnEndReason::BudgetExhausted,
                    ChildOutcome::Failed => TurnEndReason::Error,
                };
                self.end_turn(reason)?;
                Ok(None)
            }
        }
    }

    fn end_turn(&mut self, reason: TurnEndReason) -> R<()> {
        self.append(Author::Harness, Event::TurnEnd { reason })?;
        if self.deps.control.is_shutting() {
            // The published status stays `running`, which is what makes the next start restore the session.
            return Ok(());
        }
        self.phase = Phase::Idle;
        self.publish();
        Ok(())
    }

    /// End a child session: `turn_end`, `session_end`, jobs killed, and the settlement for the parent.
    async fn settle(&mut self, d: Delivery) -> R<Settlement> {
        let (reason, outcome) = match d.outcome {
            ChildOutcome::Returned | ChildOutcome::Blocked => {
                let r = if d.outcome == ChildOutcome::Returned { TurnEndReason::Finished } else { TurnEndReason::Blocked };
                (r, SessionOutcome::Done)
            }
            ChildOutcome::BudgetExhausted => (TurnEndReason::BudgetExhausted, SessionOutcome::BudgetExhausted),
            ChildOutcome::Stopped => (TurnEndReason::Stopped, SessionOutcome::Stopped),
            ChildOutcome::Failed => (TurnEndReason::Error, SessionOutcome::Failed),
        };
        let detail: String = d.report.lines().next().unwrap_or("").chars().take(DETAIL_CHARS).collect();
        self.append(Author::Harness, Event::TurnEnd { reason })?;
        self.append(Author::Harness, Event::SessionEnd { outcome, detail })?;
        self.deps.ctx.jobs.kill_all(self.grace()).await;
        self.phase = Phase::Ended;
        self.publish();
        Ok(Settlement {
            child: self.deps.shared.session.clone(),
            role: self.deps.shared.role.name.clone(),
            outcome: d.outcome,
            report: d.report,
            full: d.full,
            payload: d.payload,
            steps: self.st.step,
            usage: self.st.usage,
        })
    }

    /// The turn's token fired: record it, stop what the session started, and end the turn (or settle
    /// the child as stopped).
    async fn cancelled(&mut self) -> R<Flow> {
        let shutting = self.deps.control.is_shutting();
        let child = self.deps.shared.is_child() && !shutting;
        let reason = if shutting {
            texts::REASON_RESTART
        } else if child {
            texts::REASON_PARENT
        } else {
            texts::REASON_OPERATOR
        };
        self.append(Author::Harness, Event::Interrupted { reason: reason.to_string() })?;
        self.deps.ctx.jobs.kill_all(self.grace()).await;
        self.deps.shared.orch.stop_children(&self.deps.shared.session).await;
        if child {
            Ok(Flow::Settle(delivery(ChildOutcome::Stopped, texts::stopped_report(self.st.step))))
        } else {
            Ok(Flow::End(TurnEndReason::Stopped))
        }
    }

    /// The session cannot go on: a child settles `Failed`, anything else asks the operator.
    fn fail(&mut self, why: &str) -> R<Flow> {
        if self.deps.shared.is_child() {
            let report = texts::failed_report(why, &self.last_reply());
            Ok(Flow::Settle(delivery(ChildOutcome::Failed, report)))
        } else {
            self.open_inbox(InboxKind::Parked, texts::turn_failed(why))?;
            Ok(Flow::End(TurnEndReason::Error))
        }
    }

    // ---- a step --------------------------------------------------------------------------------

    async fn step(&mut self) -> R<Flow> {
        if self.token.is_cancelled() {
            return self.cancelled().await;
        }
        let force = self.drain_arrivals().await?;
        if let Some(flow) = self.check_budget().await? {
            return Ok(flow);
        }
        self.check_stall()?;
        let token = self.token.clone();
        if force {
            self.reweave("operator", true, &token).await?;
        } else {
            self.reweave("target", false, &token).await?;
        }
        if token.is_cancelled() {
            return self.cancelled().await;
        }

        let mut overflowed = false;
        let (req_id, completion, queue_ms, tools) = loop {
            let req_id = new_request_id();
            let w = weave(&self.records);
            if let PrefixCheck::Break { first_diff_message, detail } = self.guard.check(w.epoch, &w.messages) {
                self.append(
                    Author::Harness,
                    Event::CacheBreak { req_id: req_id.clone(), first_diff_message, detail },
                )?;
            }
            let hud_text = self.render_hud().await;
            let hud_blob = self.deps.ctx.blobs.put_bytes(hud_text.as_bytes()).ok();
            let mut messages = w.messages.clone();
            messages.push(hud_message(&hud_text));
            let sent_chars =
                messages.iter().map(Message::chars).sum::<usize>().saturating_add(tools_chars(&w.tools));
            let est_tokens = self
                .estimator
                .tokens_for_messages(&messages)
                .saturating_add(self.estimator.tokens(tools_chars(&w.tools)));
            self.append(
                Author::Harness,
                Event::ModelRequest(ModelRequest {
                    req_id: req_id.clone(),
                    step: self.st.step.saturating_add(1),
                    epoch: w.epoch,
                    purpose: Purpose::Step,
                    n_messages: to_u32(w.messages.len()),
                    stable_hash: stable_hash(&w.messages),
                    hud: hud_blob,
                    est_tokens,
                }),
            )?;
            self.publish();

            let Some(permit) = self.deps.limiter.acquire(self.deps.priority, &token).await else {
                return self.cancelled().await;
            };
            let request = ChatRequest {
                messages,
                tools: w.tools.clone(),
                tool_choice: ToolChoice::Auto,
                max_tokens: self.deps.client.profile().max_output_tokens,
                seed: None,
                extra: Map::new(),
            };
            let result = self.complete_streaming(&request, &req_id, &token).await;
            let queue_ms = permit.waited_ms;
            drop(permit);
            match result {
                Ok(c) => {
                    if c.usage.prompt_tokens > 0 {
                        self.estimator.calibrate(sent_chars, c.usage.prompt_tokens);
                    }
                    break (req_id, c, queue_ms, w.tools);
                }
                Err(ModelError::Cancelled { .. }) => return self.cancelled().await,
                Err(ModelError::ContextOverflow { .. }) => {
                    if !overflowed {
                        overflowed = true;
                        if self.reweave("overflow", true, &token).await? {
                            continue;
                        }
                        if token.is_cancelled() {
                            return self.cancelled().await;
                        }
                    }
                    return self.fail(texts::OVERFLOW_UNFOLDABLE);
                }
                Err(other) => return self.fail(&texts::sentence(&other.to_string())),
            }
        };

        let completion = self.with_fresh_ids(completion);
        self.append(
            Author::Model,
            Event::ModelResponse(ModelResponse {
                req_id: req_id.clone(),
                text: completion.text.clone(),
                reasoning: completion.reasoning.clone(),
                tool_calls: completion.tool_calls.clone(),
                finish: completion.finish,
                usage: completion.usage,
                timing: Timing { queue_ms, ..completion.timing },
                attempts: completion.attempts,
            }),
        )?;
        self.publish();
        self.handle_reply(&req_id, &completion, &tools).await
    }

    /// One request, with every stream event forwarded to the sink as it arrives.
    async fn complete_streaming(
        &self,
        request: &ChatRequest,
        req_id: &str,
        token: &CancellationToken,
    ) -> Result<Completion, ModelError> {
        let client = self.deps.client.clone();
        let sink = self.deps.sink.clone();
        let session = &self.deps.shared.session;
        let (tx, mut rx) = unbounded_channel();
        let call = client.complete(request, Some(&tx), token);
        tokio::pin!(call);
        let result = loop {
            tokio::select! {
                r = &mut call => break r,
                Some(event) = rx.recv() => sink.delta(session, req_id, &event),
            }
        };
        while let Ok(event) = rx.try_recv() {
            sink.delta(session, req_id, &event);
        }
        result
    }

    /// Calls whose id is empty or already used in this log get a fresh one.
    fn with_fresh_ids(&self, mut completion: Completion) -> Completion {
        let mut used: HashSet<String> = self
            .records
            .iter()
            .filter_map(|r| match &r.event {
                Event::ToolCall(c) => Some(c.call_id.0.clone()),
                _ => None,
            })
            .collect();
        for call in &mut completion.tool_calls {
            if call.call_id.0.is_empty() || used.contains(&call.call_id.0) {
                let fresh = format!("call-{}", new_request_id().trim_start_matches("r-"));
                call.call_id = CallId::from(fresh);
            }
            used.insert(call.call_id.0.clone());
        }
        completion
    }

    async fn render_hud(&self) -> String {
        let shared = &self.deps.shared;
        let jobs: Vec<HudJob> = self
            .running_jobs()
            .await
            .into_iter()
            .map(|j| HudJob {
                lines: count_lines(&j.out_path),
                id: j.id,
                command: j.command,
                started_ms: j.started_ms,
            })
            .collect();
        let children: Vec<HudChild> = self
            .running_children()
            .await
            .into_iter()
            .map(|c| HudChild { id: c.id.to_string(), role: c.role, title: c.title, step: c.step })
            .collect();
        let ledger = if shared.journal.is_some() {
            match shared.ledger() {
                Ok(l) => Some(l),
                Err(e) => {
                    tracing::warn!(session = %shared.session, "ledger unreadable for the state block: {e}");
                    None
                }
            }
        } else {
            None
        };
        let budget = Budget {
            max_steps: self.st.budget.max_steps.filter(|n| *n > 0),
            max_minutes: self.st.budget.max_minutes.filter(|n| *n > 0),
        };
        hud::render(&HudInput {
            now_ms: now_ms(),
            records: self.own(),
            ledger: ledger.as_ref(),
            brief: BriefOpts::default(),
            unviewed_min_lines: self.deps.agents.unviewed_min_lines,
            jobs: &jobs,
            children: &children,
            is_child: shared.is_child(),
            step: self.st.step,
            started_ms: self.st.started_ms,
            budget,
        })
    }

    /// Record what arrived while the turn was running. Nothing here starts a turn.
    async fn drain_arrivals(&mut self) -> R<bool> {
        let mut force = false;
        while let Ok(event) = self.deps.job_events.try_recv() {
            self.on_job_event(event).await?;
        }
        loop {
            let next = self.inputs.as_mut().and_then(|rx| rx.try_recv().ok());
            let Some(input) = next else { break };
            match input {
                Input::Reweave => force = true,
                Input::Resume | Input::Stop => {}
                other => {
                    if self.arrival(other).await?.user {
                        self.nudges = 0;
                    }
                }
            }
        }
        Ok(force)
    }

    async fn check_budget(&mut self) -> R<Option<Flow>> {
        let max_steps = self.st.budget.max_steps.unwrap_or(0);
        let max_minutes = self.st.budget.max_minutes.unwrap_or(0);
        if max_steps == 0 && max_minutes == 0 {
            return Ok(None);
        }
        let step = self.st.step;
        let minutes = now_ms().saturating_sub(self.st.started_ms) / 60_000;
        let reached = (max_steps > 0 && step >= max_steps) || (max_minutes > 0 && minutes >= u64::from(max_minutes));
        match self.st.budget_note_step {
            None if reached => {
                let can_finish = self.registry.get("finish").is_some();
                self.note(Author::Harness, NoteKind::Budget, texts::budget_reached(step, minutes, can_finish))?;
                Ok(None)
            }
            Some(at) if step.saturating_sub(at) >= texts::BUDGET_GRACE_STEPS => {
                if self.deps.shared.is_child() {
                    let report = texts::budget_exhausted_report(step, minutes, &self.last_reply());
                    Ok(Some(Flow::Settle(delivery(ChildOutcome::BudgetExhausted, report))))
                } else {
                    self.open_inbox(InboxKind::Parked, texts::turn_failed("The session's budget is used up."))?;
                    Ok(Some(Flow::End(TurnEndReason::BudgetExhausted)))
                }
            }
            _ => Ok(None),
        }
    }

    /// A stretch of own steps with no ledger record, file change or child activity gets one note.
    fn check_stall(&mut self) -> R<()> {
        let n = self.deps.agents.stall_steps;
        if n == 0 || self.st.termination != Some(Termination::Explicit) || self.deps.shared.journal.is_none() {
            return Ok(());
        }
        if self.st.step < n {
            return Ok(());
        }
        let first_step = self.st.step.saturating_sub(n).saturating_add(1);
        let own = self.own();
        let mut step = 0u32;
        let mut from = None;
        for (i, r) in own.iter().enumerate() {
            if matches!(&r.event, Event::ModelRequest(m) if m.purpose == Purpose::Step) {
                step = step.saturating_add(1);
                if step == first_step {
                    from = Some(i);
                    break;
                }
            }
        }
        let Some(from) = from else { return Ok(()) };
        let quiet = own.get(from..).unwrap_or_default().iter().all(|r| match &r.event {
            Event::Ledger { .. } | Event::ChildSpawned(_) | Event::ChildSettled(_) => false,
            Event::ToolResult(t) => !(t.class == ToolClass::Write && t.status == ToolStatus::Ok),
            Event::HarnessNote { note: NoteKind::Stall, .. } => false,
            _ => true,
        });
        if quiet {
            self.note(Author::Harness, NoteKind::Stall, texts::stall(n))?;
        }
        Ok(())
    }

    // ---- re-weave ------------------------------------------------------------------------------

    /// Estimated size of the request the session would send now, in tokens.
    fn estimate(&self) -> u64 {
        let w = weave(&self.records);
        self.estimator
            .tokens_for_messages(&w.messages)
            .saturating_add(self.estimator.tokens(tools_chars(&w.tools)))
    }

    /// Fold older material out of view when the request has grown past the limit (or `forced`).
    /// True when a `reweave` record was appended.
    async fn reweave(&mut self, reason: &str, forced: bool, token: &CancellationToken) -> R<bool> {
        let mut policy = self.deps.context.clone();
        let mut limit = policy.target_tokens;
        if let Some(window) = self.deps.context_window {
            let reserve = self.deps.client.profile().max_output_tokens.unwrap_or(16_384).saturating_add(4_096);
            limit = limit.min(window.saturating_sub(reserve));
        }
        if !forced && self.estimate() <= limit {
            return Ok(false);
        }
        let midpoint = policy.floor_tokens.saturating_add(limit) / 2;
        let enough = |p: &Option<loom_core::weave::ReweavePlan>| p.as_ref().is_some_and(|p| p.after_tokens_est <= midpoint);
        let mut plan = plan_reweave(&self.records, &self.estimator, &policy, false);
        while !enough(&plan) && policy.keep_recent_steps > MIN_KEEP_RECENT_STEPS {
            policy.keep_recent_steps = (policy.keep_recent_steps / 2).max(MIN_KEEP_RECENT_STEPS);
            plan = plan_reweave(&self.records, &self.estimator, &policy, false);
        }
        let mut digest = None;
        if !enough(&plan) {
            let text_plan = plan_reweave(&self.records, &self.estimator, &policy, true);
            if !forced && !enough(&text_plan) {
                return Ok(false);
            }
            if text_plan.is_some() {
                digest = self.ask_digest(token).await?;
                if token.is_cancelled() {
                    return Ok(false);
                }
                plan = text_plan;
            }
        }
        let Some(plan) = plan else { return Ok(false) };
        let ledger_brief = if self.deps.shared.journal.is_some() {
            self.deps.shared.ledger().map(|l| l.brief(&BriefOpts::default())).unwrap_or_default()
        } else {
            String::new()
        };
        self.append(
            Author::Harness,
            Event::Reweave(Reweave {
                epoch: self.st.epoch.saturating_add(1),
                upto_seq: plan.upto_seq,
                evictions: plan.evictions,
                brief: texts::reweave_brief(&ledger_brief),
                digest,
                reason: reason.to_string(),
                before_tokens: plan.before_tokens_est,
                after_tokens_est: plan.after_tokens_est,
            }),
        )?;
        self.publish();
        Ok(true)
    }

    /// Ask the model, on the existing prefix, for notes about what is about to be folded away.
    async fn ask_digest(&mut self, token: &CancellationToken) -> R<Option<String>> {
        let w = weave(&self.records);
        let req_id = new_request_id();
        self.append(
            Author::Harness,
            Event::ModelRequest(ModelRequest {
                req_id: req_id.clone(),
                step: self.st.step.saturating_add(1),
                epoch: w.epoch,
                purpose: Purpose::Digest,
                n_messages: to_u32(w.messages.len()),
                stable_hash: stable_hash(&w.messages),
                hud: None,
                est_tokens: self.estimate(),
            }),
        )?;
        let Some(permit) = self.deps.limiter.acquire(Priority::Background, token).await else { return Ok(None) };
        let mut messages = w.messages.clone();
        messages.push(Message::user(texts::DIGEST_PROMPT));
        let request = ChatRequest {
            messages,
            tools: w.tools,
            tool_choice: ToolChoice::Auto,
            max_tokens: Some(texts::DIGEST_MAX_TOKENS),
            seed: None,
            extra: Map::new(),
        };
        let result = self.deps.client.complete(&request, None, token).await;
        drop(permit);
        Ok(match result {
            Ok(c) if !c.text.trim().is_empty() => Some(c.text.trim().to_string()),
            _ => None,
        })
    }

    // ---- the reply -----------------------------------------------------------------------------

    async fn handle_reply(&mut self, req_id: &str, c: &Completion, w_tools: &[ToolSpec]) -> R<Flow> {
        if matches!(c.finish, FinishReason::Error | FinishReason::Aborted) {
            return self.fail("The model server ended the reply with an error.");
        }
        let complete: Vec<ToolCallRequest> = c.tool_calls.iter().filter(|t| t.complete).cloned().collect();
        let calls = self.run_calls(req_id, &complete, w_tools).await?;
        match calls.effect {
            Some(Effect::EndTurn(reason)) => return Ok(Flow::End(reason)),
            Some(Effect::Settle(d)) => return Ok(Flow::Settle(d)),
            None => {}
        }
        if calls.cancelled {
            return self.cancelled().await;
        }
        if c.finish == FinishReason::Length {
            let dropped = c.tool_calls.iter().find(|t| !t.complete).map(|t| t.name.as_str());
            let text = texts::output_cut(c.usage.completion_tokens, dropped, calls.ran);
            self.note(Author::Harness, NoteKind::OutputCut, text)?;
            return Ok(Flow::Next);
        }
        if !complete.is_empty() {
            return Ok(Flow::Next);
        }
        let shared = self.deps.shared.clone();
        let names = self.registry.names();
        let ledger = if shared.journal.is_some() { shared.ledger().ok() } else { None };
        let running_jobs = self.running_jobs().await.len();
        let running_children = self.running_children().await.len();
        let verdict = gate::on_yield(&YieldCtx {
            termination: self.st.termination.unwrap_or(Termination::Explicit),
            is_child: shared.is_child(),
            tools: &names,
            ledger: ledger.as_ref(),
            reply: &c.text,
            nudges: self.nudges,
            max_nudges: self.deps.agents.max_nudges,
            running_jobs,
            running_children,
        });
        match verdict {
            Yield::End => Ok(Flow::End(TurnEndReason::Yielded)),
            Yield::Nudge(text) => {
                self.note(Author::Harness, NoteKind::Nudge, text)?;
                self.nudges = self.nudges.saturating_add(1);
                Ok(Flow::Next)
            }
            Yield::Park(text) => {
                if shared.is_child() {
                    let report = texts::gave_up_report(self.nudges, &c.text);
                    Ok(Flow::Settle(delivery(ChildOutcome::Failed, report)))
                } else {
                    self.open_inbox(InboxKind::Parked, text)?;
                    Ok(Flow::End(TurnEndReason::Parked))
                }
            }
        }
    }

    /// Run the complete calls of a reply one at a time, each recorded before and after it runs.
    async fn run_calls(&mut self, req_id: &str, calls: &[ToolCallRequest], w_tools: &[ToolSpec]) -> R<Calls> {
        let mut out = Calls::default();
        let mut ender: Option<String> = None;
        for call in calls {
            if out.effect.is_none() && self.token.is_cancelled() {
                out.cancelled = true;
                break;
            }
            let tool = self.registry.get(&call.name);
            let class = tool.as_ref().map(|t| t.spec().class).unwrap_or(ToolClass::State);
            let args = serde_json::from_str::<Value>(&call.arguments)
                .unwrap_or_else(|_| Value::String(call.arguments.clone()));
            self.append(
                Author::Model,
                Event::ToolCall(ToolCall {
                    call_id: call.call_id.clone(),
                    req_id: req_id.to_string(),
                    name: call.name.clone(),
                    args,
                    class,
                }),
            )?;
            let mut ctx = self.deps.ctx.clone();
            ctx.call_id = call.call_id.clone();
            ctx.cancel = self.token.clone();
            let started = Instant::now();
            let result = if let Some(first) = &ender {
                refused(&ctx, &call.name, class, texts::not_run_after(first), started)
            } else if tool.is_none() && w_tools.iter().any(|t| t.name == call.name) {
                let message =
                    texts::not_in_assignment(&call.name, &self.deps.shared.role.name, &self.registry.names());
                refused(&ctx, &call.name, class, message, started)
            } else {
                let admission = Admission { policy: &self.deps.admit, estimator: &self.estimator };
                execute(&self.registry, &ctx, &call.name, &call.arguments, &admission).await
            };
            let ok = result.status == ToolStatus::Ok;
            self.append(Author::Tool, Event::ToolResult(result))?;
            self.flush_emitted()?;
            if let Some(effect) = self.deps.shared.take_effect() {
                if out.effect.is_none() {
                    ender = Some(call.name.clone());
                    out.effect = Some(effect);
                }
            }
            if ok {
                self.nudges = 0;
            }
            out.ran = out.ran.saturating_add(1);
        }
        Ok(out)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::rtools::testkit::{core_role, rig_with, FakeOrch, Rig};
    use loom_core::event::{Brief, ModelRef, ReasoningReplay};
    use loom_core::ids::MissionId;
    use loom_core::config::ModelProfile;
    use loom_core::log::read_records;
    use loom_model::mock::{Action, MockServer, Reply, Script};
    use loom_tools::testutil::TestEnv;
    use serde_json::json;
    use tokio::sync::mpsc::UnboundedSender;

    // ---- rig ---------------------------------------------------------------------------------

    #[derive(Default)]
    struct Collect {
        records: Mutex<Vec<Record>>,
        deltas: Mutex<Vec<(String, StreamEvent)>>,
        statuses: Mutex<Vec<Status>>,
    }

    impl Collect {
        fn records(&self) -> Vec<Record> {
            self.records.lock().unwrap().clone()
        }
        fn last_status(&self) -> Option<Status> {
            self.statuses.lock().unwrap().last().cloned()
        }
    }

    impl Sink for Collect {
        fn record(&self, _session: &SessionId, record: &Record) {
            self.records.lock().unwrap().push(record.clone());
        }
        fn delta(&self, _session: &SessionId, req_id: &str, event: &StreamEvent) {
            self.deltas.lock().unwrap().push((req_id.to_string(), event.clone()));
        }
        fn status(&self, _session: &SessionId, status: &Status) {
            self.statuses.lock().unwrap().push(status.clone());
        }
    }

    struct Fx {
        _dir: tempfile::TempDir,
        server: MockServer,
        _orch: Arc<FakeOrch>,
        sink: Arc<Collect>,
        control: Arc<Control>,
        shared: Arc<Shared>,
        ctx: ToolCtx,
        job_events: Option<UnboundedReceiver<JobEvent>>,
        spare: Vec<tokio::sync::mpsc::UnboundedSender<JobEvent>>,
        paths: Paths,
        agents: AgentsCfg,
        context: ReweavePolicy,
        window: Option<u64>,
        profile: ModelProfile,
        admit: AdmitPolicy,
        role: String,
    }

    impl Fx {
        async fn new(role: &str, child: bool, mission: bool, script: Script) -> Fx {
            let agents = AgentsCfg { verify_finish: false, ..AgentsCfg::default() };
            Fx::build(role, child, mission, agents, script).await
        }

        async fn build(role: &str, child: bool, mission: bool, agents: AgentsCfg, script: Script) -> Fx {
            let server = MockServer::start(script).await.unwrap();
            let Rig { env, orch, shared, registry: _ } = rig_with(core_role(role), child, mission, agents.clone());
            let TestEnv { dir, ctx, job_events, policy, .. } = env;
            let paths = Paths::at(dir.path().join("home"));
            let profile = ModelProfile {
                base_url: server.base_url(),
                model: "mock".into(),
                retry_window_s: 1,
                retry_max_delay_s: 1,
                stall_timeout_s: 5,
                ..ModelProfile::default()
            };
            Fx {
                _dir: dir,
                server,
                _orch: orch,
                sink: Arc::new(Collect::default()),
                control: Arc::new(Control::new()),
                shared,
                ctx,
                job_events: Some(job_events),
                spare: Vec::new(),
                paths,
                agents,
                context: ReweavePolicy::default(),
                window: None,
                profile,
                admit: policy,
                role: role.to_string(),
            }
        }

        fn deps(&mut self) -> Deps {
            let job_events = self.job_events.take().unwrap_or_else(|| {
                let (tx, rx) = unbounded_channel();
                self.spare.push(tx);
                rx
            });
            Deps {
                paths: self.paths.clone(),
                agents: self.agents.clone(),
                context: self.context.clone(),
                admit: self.admit.clone(),
                client: Arc::new(ModelClient::new("mock", self.profile.clone()).unwrap()),
                limiter: Arc::new(Limiter::new(4)),
                priority: Priority::Lead,
                context_window: self.window,
                shared: self.shared.clone(),
                ctx: self.ctx.clone(),
                job_events,
                sink: self.sink.clone(),
                control: self.control.clone(),
            }
        }

        fn start(&self, budget: Budget) -> SessionStart {
            SessionStart {
                session: SessionId::from("s-test"),
                mission: MissionId::from("m-test"),
                parent: self.shared.parent.clone(),
                workspace: self.ctx.workspace.display().to_string(),
                pack: "core".into(),
                role: self.role.clone(),
                termination: self.shared.role.termination,
                model: ModelRef { profile: "mock".into(), model: "mock".into(), context_window: 1_000_000 },
                reasoning_replay: ReasoningReplay::All,
                system_prompt: "You are a test agent.".into(),
                tools: Vec::new(),
                budget,
                unattended: false,
                title: "test".into(),
            }
        }

        fn create(&mut self) -> Session {
            self.create_with(Budget::default(), None)
        }

        fn create_with(&mut self, budget: Budget, assignment: Option<(SessionId, String)>) -> Session {
            let start = self.start(budget);
            let deps = self.deps();
            Session::create(deps, start, assignment).unwrap()
        }

        fn fork(&mut self, parent_log: &Path, upto: Seq, budget: Budget) -> Session {
            let forked = Forked {
                session: SessionId::from("s-test"),
                parent: SessionId::from("s-lead"),
                upto_seq: upto,
                role: self.role.clone(),
                termination: self.shared.role.termination,
                budget,
                brief: Brief { question: "find the thing".into(), ..Brief::default() },
                contract: "Work the brief.".into(),
                allowed_tools: None,
                title: "kid".into(),
            };
            let deps = self.deps();
            Session::fork(deps, parent_log, upto, forked).unwrap()
        }

        fn log_path(&self) -> std::path::PathBuf {
            self.paths.session_log(&SessionId::from("s-test"))
        }
    }

    fn user(text: &str) -> Input {
        Input::User(text.to_string())
    }

    /// Run a session over the given inputs, then let the channel close.
    async fn run_with(session: Session, inputs: Vec<Input>) -> End {
        let (tx, rx) = unbounded_channel();
        for i in inputs {
            tx.send(i).unwrap();
        }
        drop(tx);
        tokio::time::timeout(Duration::from_secs(90), session.run(rx)).await.expect("the session did not finish")
    }

    /// Run in the background; the caller keeps the input sender.
    fn spawn_run(session: Session) -> (UnboundedSender<Input>, tokio::task::JoinHandle<End>) {
        let (tx, rx) = unbounded_channel();
        (tx, tokio::spawn(session.run(rx)))
    }

    async fn finish_task(tx: UnboundedSender<Input>, task: tokio::task::JoinHandle<End>) -> End {
        drop(tx);
        tokio::time::timeout(Duration::from_secs(90), task).await.expect("the session did not finish").unwrap()
    }

    async fn wait_until(sink: &Collect, what: &str, f: impl Fn(&[Record]) -> bool) {
        for _ in 0..800 {
            if f(&sink.records()) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("timed out waiting for {what}");
    }

    fn kind(r: &Record) -> String {
        serde_json::to_value(r).unwrap()["kind"].as_str().unwrap().to_string()
    }

    fn kinds(rs: &[Record]) -> Vec<String> {
        rs.iter().map(kind).collect()
    }

    fn count(rs: &[Record], k: &str) -> usize {
        rs.iter().filter(|r| kind(r) == k).count()
    }

    fn notes(rs: &[Record], which: NoteKind) -> Vec<String> {
        rs.iter()
            .filter_map(|r| match &r.event {
                Event::HarnessNote { note, text } if *note == which => Some(text.clone()),
                _ => None,
            })
            .collect()
    }

    fn turn_ends(rs: &[Record]) -> Vec<TurnEndReason> {
        rs.iter()
            .filter_map(|r| match &r.event {
                Event::TurnEnd { reason } => Some(*reason),
                _ => None,
            })
            .collect()
    }

    fn results(rs: &[Record]) -> Vec<loom_core::event::ToolResult> {
        rs.iter()
            .filter_map(|r| match &r.event {
                Event::ToolResult(t) => Some(t.clone()),
                _ => None,
            })
            .collect()
    }

    fn inbox(rs: &[Record]) -> Vec<InboxItem> {
        rs.iter()
            .filter_map(|r| match &r.event {
                Event::InboxOpened(i) => Some(i.clone()),
                _ => None,
            })
            .collect()
    }

    fn bash(command: &str) -> Reply {
        Reply::tool("bash", json!({ "command": command }).to_string())
    }

    fn finish_call(answer: &str) -> Reply {
        Reply::tool("finish", json!({ "answer": answer }).to_string())
    }

    fn seq(actions: Vec<Action>) -> Script {
        Script::sequence(actions)
    }

    fn last_text(body: &Value) -> String {
        body["messages"].as_array().unwrap().last().unwrap()["content"].as_str().unwrap_or("").to_string()
    }

    fn all_text(body: &Value) -> String {
        body["messages"].as_array().unwrap().iter().map(|m| m["content"].as_str().unwrap_or("")).collect::<Vec<_>>().join("\n")
    }

    fn stable(body: &Value) -> Vec<Value> {
        let m = body["messages"].as_array().unwrap();
        m[..m.len() - 1].to_vec()
    }

    fn assert_no_cache_break(rs: &[Record]) {
        assert_eq!(count(rs, "cache_break"), 0, "unexpected cache_break: {:?}", kinds(rs));
    }

    /// A script that answers the digest prompt with `digest` (`None` = a 400) and everything else
    /// from `actions` in order.
    fn with_digest(actions: Vec<Action>, digest: Option<&'static str>) -> Script {
        let mut actions = std::collections::VecDeque::from(actions);
        Script::new(move |body, _| {
            let m = body["messages"].as_array().unwrap();
            let is_digest = m.last().and_then(|l| l["content"].as_str()).is_some_and(|c| c == texts::DIGEST_PROMPT);
            if is_digest {
                return match digest {
                    Some(t) => Reply::text(t).into(),
                    None => Action::Status { status: 400, body: "{\"error\":{\"message\":\"no\"}}".into(), retry_after_s: None },
                };
            }
            actions.pop_front().unwrap_or_else(|| Reply::text("(script exhausted)").into())
        })
    }

    // ---- a lead turn -------------------------------------------------------------------------

    fn lead_script() -> Script {
        seq(vec![bash("echo hi").into(), finish_call("all done").into()])
    }

    #[tokio::test]
    async fn lead_turn_appends_records_in_contract_order() {
        let mut fx = Fx::new("lead", false, true, lead_script()).await;
        let session = fx.create();
        let end = run_with(session, vec![user("do it")]).await;
        assert_eq!(end, End::Closed);
        let rs = fx.sink.records();
        assert_eq!(
            kinds(&rs),
            [
                "session_start", "user_message", "ledger", "turn_start", "model_request", "model_response", "tool_call",
                "tool_result", "model_request", "model_response", "tool_call", "tool_result", "ledger", "inbox_opened",
                "turn_end"
            ]
        );
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Finished]);
        assert_eq!(rs[1].author, Author::User);
        assert_eq!(rs[5].author, Author::Model);
        assert_eq!(rs[7].author, Author::Tool);
        assert_eq!(inbox(&rs)[0].kind, InboxKind::Finished);
        assert_eq!(fx.shared.ledger().unwrap().goal.as_deref(), Some("do it"));
        // What the sink was shown is what is on disk.
        let on_disk = read_records(&fx.log_path()).unwrap();
        assert!(on_disk.damage.is_none());
        assert_eq!(on_disk.records, rs);
        let status = fx.sink.last_status().unwrap();
        assert_eq!((status.phase, status.step, status.last_end), (Phase::Idle, 2, Some(TurnEndReason::Finished)));
        assert!(status.completion_tokens_total > 0);
        assert_eq!(status.open_inbox, 1);
        assert_no_cache_break(&rs);
    }

    #[tokio::test]
    async fn second_request_extends_the_first_and_the_hud_is_never_part_of_the_prefix() {
        let mut fx = Fx::new("lead", false, true, lead_script()).await;
        let session = fx.create();
        run_with(session, vec![user("do it")]).await;
        let reqs = fx.server.requests();
        assert_eq!(reqs.len(), 2);
        let (s0, s1) = (stable(&reqs[0]), stable(&reqs[1]));
        assert_eq!(&s1[..s0.len()], &s0[..], "the stable prefix must be byte-identical");
        assert!(last_text(&reqs[0]).starts_with("<harness-state>\n"));
        assert!(last_text(&reqs[1]).starts_with("<harness-state>\n"));
        for m in &s1 {
            assert!(!m["content"].as_str().unwrap_or("").contains("<harness-state>"));
        }
        assert_eq!(reqs[0]["tools"], reqs[1]["tools"]);
        let rs = fx.sink.records();
        let first = rs
            .iter()
            .find_map(|r| match &r.event {
                Event::ModelRequest(m) => Some(m.clone()),
                _ => None,
            })
            .unwrap();
        assert_eq!(first.n_messages as usize, s0.len());
        assert_eq!(first.purpose, Purpose::Step);
        let stored = String::from_utf8(fx.ctx.blobs.read_all(&first.hud.unwrap().id).unwrap()).unwrap();
        assert_eq!(format!("<harness-state>\n{stored}\n</harness-state>"), last_text(&reqs[0]));
        assert!(stored.contains("Mission state"));
    }

    #[tokio::test]
    async fn stream_events_reach_the_sink() {
        let mut fx = Fx::new("chat", false, false, seq(vec![Reply::text("hello there").into()])).await;
        let session = fx.create();
        run_with(session, vec![user("hi")]).await;
        let deltas = fx.sink.deltas.lock().unwrap().clone();
        assert!(deltas.iter().any(|(_, e)| matches!(e, StreamEvent::AttemptStart { .. })));
        let text: String = deltas
            .iter()
            .filter_map(|(_, e)| match e {
                StreamEvent::Text(t) => Some(t.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(text, "hello there");
        let rs = fx.sink.records();
        let req_id = rs.iter().find_map(|r| match &r.event {
            Event::ModelRequest(m) => Some(m.req_id.clone()),
            _ => None,
        });
        assert_eq!(deltas[0].0, req_id.unwrap());
    }

    // ---- the stop gate -----------------------------------------------------------------------

    #[tokio::test]
    async fn free_session_yields_on_text() {
        let mut fx = Fx::new("chat", false, false, seq(vec![Reply::text("just text").into()])).await;
        let session = fx.create();
        run_with(session, vec![user("hi")]).await;
        let rs = fx.sink.records();
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Yielded]);
        assert!(notes(&rs, NoteKind::Nudge).is_empty());
    }

    #[tokio::test]
    async fn explicit_session_nudges_then_parks_and_a_good_call_resets_the_count() {
        let agents = AgentsCfg { max_nudges: 2, verify_finish: false, ..AgentsCfg::default() };
        let script = seq(vec![
            Reply::text("one").into(),
            Reply::text("two").into(),
            bash("echo ok").into(),
            Reply::text("three").into(),
            Reply::text("four").into(),
            Reply::text("five").into(),
        ]);
        let mut fx = Fx::build("lead", false, true, agents, script).await;
        let session = fx.create();
        run_with(session, vec![user("go")]).await;
        let rs = fx.sink.records();
        assert_eq!(notes(&rs, NoteKind::Nudge).len(), 4);
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Parked]);
        let items = inbox(&rs);
        assert_eq!(items.len(), 1);
        assert_eq!((items[0].kind, items[0].blocking), (InboxKind::Parked, true));
        assert_eq!(fx.server.requests().len(), 6);
        assert_eq!(fx.sink.last_status().unwrap().open_inbox, 1);
        assert_no_cache_break(&rs);
    }

    // ---- output limit ------------------------------------------------------------------------

    #[tokio::test]
    async fn output_cut_without_an_incomplete_call() {
        let script = seq(vec![Reply::text("partial thought").with_finish(FinishReason::Length).into(), Reply::text("ok").into()]);
        let mut fx = Fx::new("chat", false, false, script).await;
        let session = fx.create();
        run_with(session, vec![user("go")]).await;
        let rs = fx.sink.records();
        let n = notes(&rs, NoteKind::OutputCut);
        assert_eq!(n.len(), 1);
        assert_eq!(n[0], texts::output_cut(rs.iter().find_map(|r| match &r.event {
            Event::ModelResponse(m) => Some(m.usage.completion_tokens),
            _ => None,
        }).unwrap(), None, 0));
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Yielded]);
        assert_eq!(fx.server.requests().len(), 2);
    }

    #[tokio::test]
    async fn output_cut_with_an_incomplete_call_runs_only_the_complete_ones() {
        let reply = Reply::tools([
            ("bash", json!({ "command": "echo first" }).to_string()),
            ("bash", "{\"command\": \"echo cut off".to_string()),
        ])
        .with_finish(FinishReason::Length);
        let mut fx = Fx::new("chat", false, false, seq(vec![reply.into(), Reply::text("ok").into()])).await;
        let session = fx.create();
        run_with(session, vec![user("go")]).await;
        let rs = fx.sink.records();
        assert_eq!(count(&rs, "tool_call"), 1);
        assert_eq!(count(&rs, "tool_result"), 1);
        let n = notes(&rs, NoteKind::OutputCut);
        assert_eq!(n.len(), 1);
        assert!(n[0].contains("bash"), "{}", n[0]);
        let resp = rs
            .iter()
            .find_map(|r| match &r.event {
                Event::ModelResponse(m) => Some(m.clone()),
                _ => None,
            })
            .unwrap();
        assert_eq!(resp.tool_calls.len(), 2);
        assert!(resp.tool_calls[0].complete && !resp.tool_calls[1].complete);
        let second = &fx.server.requests()[1];
        let asst = second["messages"].as_array().unwrap().iter().find(|m| m["role"] == "assistant").unwrap().clone();
        assert_eq!(asst["tool_calls"].as_array().unwrap().len(), 1);
    }

    // ---- several calls, effects ----------------------------------------------------------------

    #[tokio::test]
    async fn calls_run_in_order_and_an_effect_refuses_the_rest() {
        let reply = Reply::tools([
            ("bash", json!({ "command": "echo one" }).to_string()),
            ("note", json!({ "kind": "decision", "text": "use x", "why": "because" }).to_string()),
            ("ask_user", json!({ "question": "which one?" }).to_string()),
            ("bash", json!({ "command": "echo never" }).to_string()),
        ]);
        let mut fx = Fx::new("lead", false, true, seq(vec![reply.into()])).await;
        let session = fx.create();
        run_with(session, vec![user("go")]).await;
        let rs = fx.sink.records();
        assert_eq!(
            kinds(&rs)[5..],
            [
                "model_response", "tool_call", "tool_result", "tool_call", "tool_result", "ledger", "tool_call", "tool_result",
                "ledger", "inbox_opened", "tool_call", "tool_result", "turn_end"
            ]
        );
        let res = results(&rs);
        assert_eq!(res.len(), 4);
        assert_eq!(res[3].status, ToolStatus::Invalid);
        assert!(res[3].text.contains(&texts::not_run_after("ask_user")));
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Asked]);
        let call = rs
            .iter()
            .find_map(|r| match &r.event {
                Event::ToolCall(c) if c.name == "note" => Some(c.clone()),
                _ => None,
            })
            .unwrap();
        assert_eq!(call.args["text"], "use x");
        assert_eq!(call.class, ToolClass::State);
        // The arguments reach the log exactly as the model produced them.
        let resp_args = rs.iter().find_map(|r| match &r.event {
            Event::ModelResponse(m) => Some(m.tool_calls.iter().map(|c| c.arguments.clone()).collect::<Vec<_>>()),
            _ => None,
        });
        assert_eq!(resp_args.unwrap()[0], json!({ "command": "echo one" }).to_string());
    }

    #[tokio::test]
    async fn unparseable_arguments_are_recorded_verbatim_and_answered_by_the_tool_layer() {
        let reply = Reply::tool("bash", "{\"command\": 5}");
        let mut fx = Fx::new("chat", false, false, seq(vec![reply.into(), Reply::text("ok").into()])).await;
        let session = fx.create();
        run_with(session, vec![user("go")]).await;
        let rs = fx.sink.records();
        let res = results(&rs);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].status, ToolStatus::Invalid);
    }

    #[tokio::test]
    async fn duplicate_and_empty_call_ids_are_replaced() {
        let mut fx = Fx::new("chat", false, false, seq(vec![])).await;
        let mut session = fx.create();
        session
            .append(
                Author::Model,
                Event::ToolCall(ToolCall {
                    call_id: CallId::from("dup"),
                    req_id: "r".into(),
                    name: "bash".into(),
                    args: json!({}),
                    class: ToolClass::Exec,
                }),
            )
            .unwrap();
        let call = |id: &str| ToolCallRequest { call_id: CallId::from(id), name: "bash".into(), arguments: "{}".into(), complete: true };
        let completion = Completion {
            text: String::new(),
            reasoning: String::new(),
            tool_calls: vec![call("dup"), call(""), call("fresh"), call("fresh")],
            finish: FinishReason::ToolCalls,
            usage: Usage::default(),
            timing: Timing::default(),
            attempts: 1,
        };
        let fixed = session.with_fresh_ids(completion);
        let ids: Vec<String> = fixed.tool_calls.iter().map(|c| c.call_id.0.clone()).collect();
        assert!(ids[0].starts_with("call-") && ids[1].starts_with("call-"));
        assert_eq!(ids[2], "fresh");
        assert!(ids[3].starts_with("call-"));
        assert_eq!(ids.iter().collect::<HashSet<_>>().len(), 4);
    }

    // ---- children ----------------------------------------------------------------------------

    /// A parent lead that ran one bash call and finished; returns its log path and the seq of the
    /// first tool result (a fork point where every call has its result).
    async fn parent_log() -> (Fx, std::path::PathBuf, Seq) {
        let mut fx = Fx::new("lead", false, true, lead_script()).await;
        let session = fx.create();
        run_with(session, vec![user("parent task")]).await;
        let upto = fx
            .sink
            .records()
            .iter()
            .find(|r| matches!(r.event, Event::ToolResult(_)))
            .map(|r| r.seq)
            .unwrap();
        let path = fx.log_path();
        (fx, path, upto)
    }

    #[tokio::test]
    async fn forked_child_shares_the_parents_prefix_refuses_foreign_tools_and_finishes() {
        let (parent, path, upto) = parent_log().await;
        let script = seq(vec![
            Reply::tool("agent_spawn", json!({ "role": "worker", "task": "x" }).to_string()).into(),
            finish_call("found it").into(),
        ]);
        let mut kid = Fx::new("worker", true, true, script).await;
        let session = kid.fork(&path, upto, Budget::default());
        let end = run_with(session, vec![]).await;
        let End::Settled(s) = end else { panic!("expected a settlement, got {end:?}") };
        assert_eq!(s.outcome, ChildOutcome::Returned);
        assert!(s.report.contains("found it"));
        assert_eq!(s.steps, 2);
        assert_eq!(s.role, "worker");
        let reqs = kid.server.requests();
        let parent_second = &parent.server.requests()[1];
        let ps = stable(parent_second);
        let cs = stable(&reqs[0]);
        assert_eq!(cs[..4], ps[..4], "fork prefix must be byte-identical");
        assert_eq!(reqs[0]["tools"], parent.server.requests()[0]["tools"]);
        assert!(all_text(&reqs[0]).contains("<harness kind=\"assignment\" from=\"s-lead\">"));
        assert!(all_text(&reqs[0]).contains("find the thing"));
        let rs = kid.sink.records();
        let res = results(&rs);
        assert_eq!(res[0].status, ToolStatus::Invalid);
        assert!(res[0].text.contains("agent_spawn"));
        assert_eq!(&kinds(&rs)[rs.len() - 3..], ["tool_result", "turn_end", "session_end"]);
        assert_eq!(kid.sink.last_status().unwrap().phase, Phase::Ended);
        assert_eq!(kid.sink.last_status().unwrap().outcome, Some(SessionOutcome::Done));
        assert_no_cache_break(&rs);
    }

    #[tokio::test]
    async fn forked_child_budget_note_then_budget_exhausted() {
        let (_parent, path, upto) = parent_log().await;
        let script = seq((0..6).map(|_| bash("echo x").into()).collect());
        let mut kid = Fx::new("worker", true, true, script).await;
        let session = kid.fork(&path, upto, Budget { max_steps: Some(1), max_minutes: None });
        let End::Settled(s) = run_with(session, vec![]).await else { panic!("expected a settlement") };
        assert_eq!(s.outcome, ChildOutcome::BudgetExhausted);
        let rs = kid.sink.records();
        assert_eq!(notes(&rs, NoteKind::Budget).len(), 1);
        assert_eq!(s.steps, 3);
        assert_eq!(count(&rs, "model_request"), 3);
        assert_eq!(turn_ends(&rs).last(), Some(&TurnEndReason::BudgetExhausted));
        assert!(matches!(rs.last().unwrap().event, Event::SessionEnd { outcome: SessionOutcome::BudgetExhausted, .. }));
    }

    #[tokio::test]
    async fn fresh_child_starts_by_itself_with_its_assignment_and_gives_up_failed() {
        let agents = AgentsCfg { max_nudges: 1, verify_finish: false, ..AgentsCfg::default() };
        let script = seq(vec![Reply::text("hmm").into(), Reply::text("hmm again").into()]);
        let mut kid = Fx::build("worker", true, true, agents, script).await;
        let session = kid.create_with(Budget::default(), Some((SessionId::from("s-lead"), "Count the files.".into())));
        let End::Settled(s) = run_with(session, vec![]).await else { panic!("expected a settlement") };
        assert_eq!(s.outcome, ChildOutcome::Failed);
        assert!(s.report.contains("hmm again"));
        let rs = kid.sink.records();
        assert_eq!(&kinds(&rs)[..4], ["session_start", "harness_note", "turn_start", "model_request"]);
        assert_eq!(rs[1].author, Author::Agent(SessionId::from("s-lead")));
        assert!(all_text(&kid.server.requests()[0]).contains("<harness kind=\"assignment\" from=\"s-lead\">\nCount the files.\n</harness>"));
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Error]);
        assert!(matches!(rs.last().unwrap().event, Event::SessionEnd { outcome: SessionOutcome::Failed, .. }));
    }

    #[tokio::test]
    async fn model_error_parks_a_lead_and_fails_a_child() {
        let bad = || Action::Status { status: 400, body: "{\"error\":{\"message\":\"nope\"}}".into(), retry_after_s: None };
        let mut lead = Fx::new("lead", false, true, seq(vec![bad()])).await;
        let session = lead.create();
        run_with(session, vec![user("go")]).await;
        let rs = lead.sink.records();
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Error]);
        let items = inbox(&rs);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].kind, InboxKind::Parked);
        assert!(items[0].text.contains("nope"), "{}", items[0].text);

        let mut kid = Fx::new("worker", true, true, seq(vec![bad()])).await;
        let session = kid.create_with(Budget::default(), Some((SessionId::from("s-lead"), "Do it.".into())));
        let End::Settled(s) = run_with(session, vec![]).await else { panic!("expected a settlement") };
        assert_eq!(s.outcome, ChildOutcome::Failed);
        assert!(s.report.contains("nope"), "{}", s.report);
    }

    // ---- stop --------------------------------------------------------------------------------

    #[tokio::test]
    async fn stop_during_a_model_reply_then_the_next_turn_carries_after_stop() {
        let script = seq(vec![Reply::text("slow").with_delay_ms(20_000).into(), Reply::text("fine").into()]);
        let mut fx = Fx::new("chat", false, false, script).await;
        let session = fx.create();
        let (tx, task) = spawn_run(session);
        tx.send(user("go")).unwrap();
        wait_until(&fx.sink, "the request", |rs| count(rs, "model_request") == 1).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        fx.control.stop_turn();
        wait_until(&fx.sink, "turn end", |rs| count(rs, "turn_end") == 1).await;
        let rs = fx.sink.records();
        assert_eq!(&kinds(&rs)[rs.len() - 2..], ["interrupted", "turn_end"]);
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Stopped]);
        tx.send(user("again")).unwrap();
        wait_until(&fx.sink, "second turn end", |rs| count(rs, "turn_end") == 2).await;
        let rs = fx.sink.records();
        assert_eq!(notes(&rs, NoteKind::Interrupted), vec![texts::AFTER_STOP.to_string()]);
        assert!(all_text(&fx.server.requests()[1]).contains(texts::AFTER_STOP));
        assert_eq!(finish_task(tx, task).await, End::Closed);
        // The unanswered request ended in a user message that the next user message was merged
        // into. That only appends to the final message, which the guard counts as growth.
        assert_no_cache_break(&fx.sink.records());
    }

    #[tokio::test]
    async fn stop_during_a_running_bash_kills_the_command() {
        let script = seq(vec![bash("sleep 60").into()]);
        let mut fx = Fx::new("chat", false, false, script).await;
        let session = fx.create();
        let (tx, task) = spawn_run(session);
        tx.send(user("go")).unwrap();
        wait_until(&fx.sink, "the call", |rs| count(rs, "tool_call") == 1).await;
        tokio::time::sleep(Duration::from_millis(400)).await;
        fx.control.stop_turn();
        wait_until(&fx.sink, "turn end", |rs| count(rs, "turn_end") == 1).await;
        let rs = fx.sink.records();
        assert_eq!(&kinds(&rs)[rs.len() - 3..], ["tool_result", "interrupted", "turn_end"]);
        assert_eq!(results(&rs)[0].status, ToolStatus::Interrupted);
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Stopped]);
        assert!(fx.ctx.jobs.list().await.iter().all(|j| j.state != JobState::Running));
        assert_eq!(finish_task(tx, task).await, End::Closed);
    }

    #[tokio::test]
    async fn stopping_a_child_settles_it_stopped() {
        let script = seq(vec![Reply::text("slow").with_delay_ms(20_000).into()]);
        let mut kid = Fx::new("worker", true, true, script).await;
        let session = kid.create_with(Budget::default(), Some((SessionId::from("s-lead"), "Do it.".into())));
        let (tx, task) = spawn_run(session);
        wait_until(&kid.sink, "the request", |rs| count(rs, "model_request") == 1).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        kid.control.stop_turn();
        let end = tokio::time::timeout(Duration::from_secs(30), task).await.unwrap().unwrap();
        let End::Settled(s) = end else { panic!("expected a settlement") };
        assert_eq!(s.outcome, ChildOutcome::Stopped);
        assert_eq!(s.report, texts::stopped_report(1));
        let rs = kid.sink.records();
        let reasons: Vec<String> = rs
            .iter()
            .filter_map(|r| match &r.event {
                Event::Interrupted { reason } => Some(reason.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(reasons, vec![texts::REASON_PARENT.to_string()]);
        drop(tx);
    }

    // ---- open --------------------------------------------------------------------------------

    #[tokio::test]
    async fn open_reproduces_the_state_of_the_session_that_wrote_the_log() {
        let mut fx = Fx::new("chat", false, false, seq(vec![big(), big(), big(), Reply::text("ok").into()])).await;
        fx.context = ReweavePolicy { target_tokens: 12_000, floor_tokens: 10_000, keep_recent_steps: 1, stub_tail_lines: 3 };
        let session = fx.create();
        run_with(session, vec![user("go")]).await;
        let written = fx.sink.last_status().unwrap();
        assert!(written.epoch >= 1 && written.step == 4 && written.prompt_tokens > 0);
        let deps = fx.deps();
        let reopened = Session::open(deps).unwrap();
        let mut got = reopened.status();
        got.phase = written.phase;
        assert_eq!(got, written);
        assert_eq!(reopened.records().len(), fx.sink.records().len());
    }

    #[tokio::test]
    async fn open_on_a_log_cut_mid_turn_adds_the_restart_records_and_the_next_turn_says_so() {
        let mut fx = Fx::new("chat", false, false, seq(vec![Reply::text("welcome back").into()])).await;
        let mut session = fx.create();
        session.append(Author::User, Event::UserMessage { text: "hi".into() }).unwrap();
        session.append(Author::Harness, Event::TurnStart { trigger: Trigger::User }).unwrap();
        drop(session);
        // A torn final line as well.
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().append(true).open(fx.log_path()).unwrap();
            f.write_all(b"{\"seq\":4,\"ts_ms\":1,\"auth").unwrap();
        }
        let deps = fx.deps();
        let reopened = Session::open(deps).unwrap();
        let rs = reopened.records().to_vec();
        let tail: Vec<String> = kinds(&rs)[rs.len() - 3..].to_vec();
        assert_eq!(tail, ["interrupted", "interrupted", "turn_end"]);
        let reasons: Vec<String> = rs
            .iter()
            .filter_map(|r| match &r.event {
                Event::Interrupted { reason } => Some(reason.clone()),
                _ => None,
            })
            .collect();
        assert!(reasons[0].starts_with("the session log was damaged and was cut back to its last good record ("));
        assert_eq!(reasons[1], texts::REASON_RESTART);
        assert_eq!(reopened.status().last_end, Some(TurnEndReason::Stopped));
        run_with(reopened, vec![Input::Resume]).await;
        let rs = fx.sink.records();
        assert_eq!(notes(&rs, NoteKind::Interrupted), vec![texts::AFTER_RESTART.to_string()]);
        assert!(all_text(&fx.server.requests()[0]).contains(texts::AFTER_RESTART));
    }

    #[tokio::test]
    async fn run_on_an_ended_session_returns_closed() {
        let (_parent, path, upto) = parent_log().await;
        let mut kid = Fx::new("worker", true, true, seq(vec![finish_call("done").into()])).await;
        let session = kid.fork(&path, upto, Budget::default());
        assert!(matches!(run_with(session, vec![]).await, End::Settled(_)));
        let deps = kid.deps();
        let reopened = Session::open(deps).unwrap();
        assert_eq!(reopened.status().phase, Phase::Ended);
        assert_eq!(run_with(reopened, vec![]).await, End::Closed);
    }

    // ---- background jobs ---------------------------------------------------------------------

    #[tokio::test]
    async fn a_job_that_ends_while_waiting_resumes_the_session_with_an_arrival_note() {
        let script = seq(vec![
            Reply::tool("bash", json!({ "command": "sleep 1; echo job-output", "background": true }).to_string()).into(),
            Reply::tool("wait", json!({}).to_string()).into(),
            finish_call("done").into(),
        ]);
        let mut kid = Fx::new("worker", true, true, script).await;
        let session = kid.create_with(Budget::default(), Some((SessionId::from("s-lead"), "Run it.".into())));
        let (tx, task) = spawn_run(session);
        let end = tokio::time::timeout(Duration::from_secs(60), task).await.expect("the child did not settle").unwrap();
        let End::Settled(s) = end else { panic!("expected a settlement, got {end:?}") };
        assert_eq!(s.outcome, ChildOutcome::Returned);
        drop(tx);
        let rs = kid.sink.records();
        let arrivals = notes(&rs, NoteKind::Arrival);
        assert_eq!(arrivals.len(), 1, "{:?}", kinds(&rs));
        assert!(arrivals[0].contains("job-output"), "{}", arrivals[0]);
        assert_eq!(count(&rs, "job_registered"), 1);
        assert_eq!(count(&rs, "job_settled"), 1);
        assert!(rs.iter().any(|r| matches!(&r.event, Event::TurnStart { trigger: Trigger::JobSettled })));
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Waiting, TurnEndReason::Finished]);
    }

    #[tokio::test]
    async fn a_job_whose_end_the_model_saw_through_job_wait_produces_no_note() {
        let script = seq(vec![
            Reply::tool("bash", json!({ "command": "sleep 1; echo seen", "background": true }).to_string()).into(),
            Reply::tool("job_wait", json!({ "job": "j1", "timeout_s": 30 }).to_string()).into(),
            finish_call("done").into(),
        ]);
        let mut kid = Fx::new("worker", true, true, script).await;
        let session = kid.create_with(Budget::default(), Some((SessionId::from("s-lead"), "Run it.".into())));
        let End::Settled(_) = run_with(session, vec![]).await else { panic!("expected a settlement") };
        let rs = kid.sink.records();
        assert!(notes(&rs, NoteKind::Arrival).is_empty(), "{:?}", notes(&rs, NoteKind::Arrival));
        assert_eq!(count(&rs, "job_settled"), 1);
    }

    // ---- inputs ------------------------------------------------------------------------------

    #[tokio::test]
    async fn an_inbox_answer_resolves_the_item_answers_the_question_and_starts_a_turn() {
        let script = seq(vec![
            Reply::tool("ask_user", json!({ "question": "which branch?" }).to_string()).into(),
            finish_call("on main").into(),
        ]);
        let mut fx = Fx::new("lead", false, true, script).await;
        let session = fx.create();
        let (tx, task) = spawn_run(session);
        tx.send(user("go")).unwrap();
        wait_until(&fx.sink, "the question", |rs| !inbox(rs).is_empty() && count(rs, "turn_end") == 1).await;
        let item = inbox(&fx.sink.records())[0].clone();
        assert_eq!((item.kind, item.blocking), (InboxKind::Question, true));
        // An answer to an unknown item is ignored.
        tx.send(Input::Answer { item_id: "i-nope".into(), answer: "x".into() }).unwrap();
        tx.send(Input::Answer { item_id: item.item_id.clone(), answer: "main".into() }).unwrap();
        wait_until(&fx.sink, "second turn end", |rs| count(rs, "turn_end") == 2).await;
        let rs = fx.sink.records();
        assert_eq!(count(&rs, "inbox_resolved"), 1);
        assert!(rs.iter().any(|r| matches!(&r.event, Event::UserMessage { text } if *text == texts::inbox_answer("which branch?", "main"))));
        assert!(rs.iter().any(|r| matches!(&r.event, Event::TurnStart { trigger: Trigger::InboxAnswer })));
        let ledger = fx.shared.ledger().unwrap();
        assert!(ledger.questions.iter().all(|q| q.answer.is_some()), "{:?} // {:?} // {:?}", ledger.questions, kinds(&rs), turn_ends(&rs));
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Asked, TurnEndReason::Finished]);
        assert_eq!(fx.sink.last_status().unwrap().open_inbox, 1); // the Finished item
        finish_task(tx, task).await;
    }

    #[tokio::test]
    async fn input_arriving_mid_turn_is_in_the_next_request_without_starting_a_turn() {
        let script = seq(vec![bash("echo one").into(), Reply::text("done").into()]);
        let mut fx = Fx::new("chat", false, false, script).await;
        fx.profile.max_concurrent = 1;
        let session = fx.create();
        let (tx, task) = spawn_run(session);
        tx.send(user("first")).unwrap();
        tx.send(user("second, sent while the turn runs")).unwrap();
        wait_until(&fx.sink, "turn end", |rs| count(rs, "turn_end") >= 1).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let rs = fx.sink.records();
        assert_eq!(count(&rs, "turn_start"), 1, "{:?}", kinds(&rs));
        assert_eq!(count(&rs, "user_message"), 2);
        let reqs = fx.server.requests();
        assert!(all_text(reqs.last().unwrap()).contains("second, sent while the turn runs"));
        finish_task(tx, task).await;
    }

    #[tokio::test]
    async fn operator_rules_and_approvals_reach_the_ledger_and_stay_in_view_without_starting_a_turn() {
        let script = seq(vec![Reply::text("noted").into(), Reply::text("again").into()]);
        let mut fx = Fx::new("lead", false, true, script).await;
        let session = fx.create();
        let (tx, task) = spawn_run(session);
        tx.send(Input::Constraint("never push to main".into())).unwrap();
        tx.send(Input::Constraint("   ".into())).unwrap();
        tx.send(Input::Approval { text: "you may restart the staging database".into(), scope: "staging only".into() }).unwrap();
        tx.send(Input::Constraint("temporary rule".into())).unwrap();
        tx.send(Input::Withdraw { id: "k2".into(), reason: "no longer needed".into() }).unwrap();
        tx.send(Input::Withdraw { id: "k9".into(), reason: "no such rule".into() }).unwrap();
        wait_until(&fx.sink, "the notes", |rs| count(rs, "harness_note") == 4).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        let rs = fx.sink.records();
        assert_eq!(count(&rs, "turn_start"), 0, "operator entries start no turn: {:?}", kinds(&rs));
        assert_eq!(count(&rs, "ledger"), 4);
        let rules = notes(&rs, NoteKind::Constraint);
        assert_eq!(rules.len(), 3, "{rules:?}");
        assert!(rules[0].contains("(k1)") && rules[0].ends_with("never push to main"), "{}", rules[0]);
        assert!(rules[2].contains("k2") && rules[2].contains("no longer needed"), "{}", rules[2]);
        let approvals = notes(&rs, NoteKind::Approval);
        assert!(approvals[0].contains("(a1)") && approvals[0].contains("staging only"), "{}", approvals[0]);
        for r in rs.iter().filter(|r| matches!(r.event, Event::HarnessNote { .. })) {
            assert_eq!(r.author, Author::User);
        }
        let ledger = fx.shared.ledger().unwrap();
        assert_eq!(ledger.constraints.len(), 2);
        assert!(ledger.constraints[0].retired.is_none() && ledger.constraints[1].retired.is_some());
        assert_eq!((ledger.approvals[0].scope.as_str(), ledger.approvals[0].used_for.is_none()), ("staging only", true));
        // The next request carries them, and the state block lists the active rule.
        tx.send(user("go")).unwrap();
        wait_until(&fx.sink, "a reply", |rs| count(rs, "model_response") >= 1).await;
        let reqs = fx.server.requests();
        let text = all_text(reqs.last().unwrap());
        assert!(text.contains("<harness kind=\"constraint\">") && text.contains("never push to main"), "{text}");
        assert!(text.contains("you may restart the staging database"));
        assert!(text.contains("k1: never push to main"), "the state block lists the active rule: {text}");
        finish_task(tx, task).await;
    }

    #[tokio::test]
    async fn child_settled_agent_message_resume_and_stop_inputs() {
        let script = seq(vec![Reply::text("a").into(), Reply::text("b").into()]);
        let mut fx = Fx::new("chat", false, false, script).await;
        let session = fx.create();
        let (tx, task) = spawn_run(session);
        tx.send(user("hi")).unwrap();
        wait_until(&fx.sink, "yield", |rs| count(rs, "turn_end") == 1).await;
        // Yielded: a settled child wakes the session.
        let settlement = Settlement {
            child: SessionId::from("s-kid9"),
            role: "worker".into(),
            outcome: ChildOutcome::Returned,
            report: "kid report".into(),
            full: None,
            payload: Value::Null,
            steps: 3,
            usage: Usage::default(),
        };
        tx.send(Input::ChildSettled(settlement)).unwrap();
        wait_until(&fx.sink, "second turn", |rs| count(rs, "turn_end") == 2).await;
        // A message from the assigning agent does not wake a session that is not waiting.
        tx.send(Input::AgentMessage { from: SessionId::from("s-lead"), text: "psst".into() }).unwrap();
        tx.send(Input::Stop).unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let rs = fx.sink.records();
        assert_eq!(count(&rs, "turn_start"), 2);
        assert_eq!(count(&rs, "child_settled"), 1);
        assert_eq!(notes(&rs, NoteKind::Arrival), vec![texts::agent_message("psst")]);
        assert_eq!(count(&rs, "interrupted"), 0);
        assert!(all_text(&fx.server.requests()[1]).contains("kid report"));
        finish_task(tx, task).await;
    }

    // ---- re-weave ----------------------------------------------------------------------------

    /// About 32,000 characters in 600 lines, shown whole by the default admission policy.
    const BIG: &str = "yes aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | head -n 600";

    fn big() -> Action {
        bash(BIG).into()
    }

    fn reweave_records(rs: &[Record]) -> Vec<Reweave> {
        rs.iter()
            .filter_map(|r| match &r.event {
                Event::Reweave(w) => Some(w.clone()),
                _ => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn reweave_at_target_raises_the_epoch_and_the_next_request_drops_the_old_output() {
        let mut fx = Fx::new("chat", false, false, seq(vec![big(), big(), big(), Reply::text("ok").into()])).await;
        fx.context = ReweavePolicy { target_tokens: 12_000, floor_tokens: 10_000, keep_recent_steps: 1, stub_tail_lines: 3 };
        let session = fx.create();
        run_with(session, vec![user("go")]).await;
        let rs = fx.sink.records();
        let rw = reweave_records(&rs);
        assert!(!rw.is_empty(), "{:?}", kinds(&rs));
        assert_eq!(rw[0].epoch, 1);
        assert_eq!(rw[0].reason, "target");
        assert_eq!(rw.iter().map(|w| w.epoch).collect::<Vec<_>>(), (1..=rw.len() as u32).collect::<Vec<_>>());
        assert!(rw[0].digest.is_none());
        assert_eq!(count(&rs, "model_request"), 4);
        assert_eq!(fx.sink.last_status().unwrap().epoch, rw.len() as u32);
        let reqs = fx.server.requests();
        let line = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let lines = |n: usize| all_text(&reqs[n]).matches(line).count();
        assert!(
            lines(1) >= 600,
            "the first output is shown whole before the re-weave: lines per request {:?}, re-weaves {:?}",
            (0..reqs.len()).map(lines).collect::<Vec<_>>(),
            rw.iter().map(|w| (w.epoch, w.upto_seq, w.evictions.len(), w.before_tokens, w.after_tokens_est)).collect::<Vec<_>>()
        );
        assert!(lines(2) < 700, "after the re-weave only the newest output is whole, got {}", lines(2));
        assert_no_cache_break(&rs);
        assert!(all_text(&reqs[2]).contains(&texts::reweave_brief("")));
    }

    #[tokio::test]
    async fn reweave_protects_fewer_recent_steps_when_they_are_what_fills_the_context() {
        // Every step is inside the protected recent region, so nothing could be folded without
        // shrinking it.
        let script = seq(vec![big(), big(), big(), big(), big(), big(), Reply::text("ok").into()]);
        let mut fx = Fx::new("chat", false, false, script).await;
        fx.context = ReweavePolicy { target_tokens: 40_000, floor_tokens: 10_000, keep_recent_steps: 64, stub_tail_lines: 3 };
        let session = fx.create();
        run_with(session, vec![user("go")]).await;
        let rs = fx.sink.records();
        let rw = reweave_records(&rs);
        assert!(!rw.is_empty(), "{:?}", kinds(&rs));
        assert_eq!(rw[0].reason, "target");
        assert!(!rw[0].evictions.is_empty());
        let reqs = fx.server.requests();
        let line = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let last = all_text(reqs.last().unwrap()).matches(line).count();
        assert!(last < 4 * 600, "six outputs were produced; the last request shows {last} lines of them");
        assert!(last >= 600, "the newest output is still whole, got {last}");
        assert_no_cache_break(&rs);
    }

    #[tokio::test]
    async fn a_reweave_that_would_free_little_is_not_done() {
        // Two recent steps alone are larger than the target: folding the rest cannot make room for
        // long, so the context is left alone rather than re-woven at every step.
        let mut fx = Fx::new("chat", false, false, seq(vec![big(), big(), big(), big(), Reply::text("ok").into()])).await;
        fx.context = ReweavePolicy { target_tokens: 12_000, floor_tokens: 10_000, keep_recent_steps: 64, stub_tail_lines: 3 };
        let session = fx.create();
        run_with(session, vec![user("go")]).await;
        let rs = fx.sink.records();
        assert!(reweave_records(&rs).is_empty(), "{:?}", kinds(&rs));
        assert_eq!(count(&rs, "model_request"), 5, "no digest request either");
        assert_eq!(fx.sink.last_status().unwrap().epoch, 0);
        assert_no_cache_break(&rs);
    }

    #[tokio::test]
    async fn reweave_asks_for_a_digest_when_the_plan_is_not_enough_and_survives_its_failure() {
        for digest in [Some("lead A: check the config"), None] {
            let long = || Reply::tool("bash", json!({ "command": BIG }).to_string()).with_text("t".repeat(40_000));
            let script = with_digest(vec![long().into(), long().into(), long().into(), Reply::text("ok").into()], digest);
            let mut fx = Fx::new("chat", false, false, script).await;
            // Three steps of long text and output pass the target; folding the old output alone
            // does not make enough room, folding the old text as well does.
            fx.context = ReweavePolicy { target_tokens: 60_000, floor_tokens: 1_000, keep_recent_steps: 1, stub_tail_lines: 3 };
            let session = fx.create();
            run_with(session, vec![user("go")]).await;
            let rs = fx.sink.records();
            let rw = reweave_records(&rs);
            assert!(!rw.is_empty(), "{:?}", kinds(&rs));
            assert_eq!(rw[0].digest.as_deref(), digest);
            assert!(rw[0].evictions.iter().any(|e| matches!(e.action, loom_core::event::EvictAction::Drop)), "text was folded");
            let digests = rs.iter().filter(|r| matches!(&r.event, Event::ModelRequest(m) if m.purpose == Purpose::Digest)).count();
            assert!(digests >= 1);
            // The digest request is only a request record: no response record follows it.
            assert_eq!(count(&rs, "model_response") + digests, count(&rs, "model_request"));
            let last = fx.server.requests().last().unwrap().clone();
            assert_eq!(all_text(&last).contains("Leads from earlier work"), digest.is_some());
            assert_no_cache_break(&rs);
        }
    }

    #[tokio::test]
    async fn context_overflow_forces_a_reweave_and_a_retry() {
        let mut fx = Fx::new("chat", false, false, seq(vec![big(), big(), Reply::text("ok").into()])).await;
        fx.server.set_model("mock", Some(16_000));
        fx.context = ReweavePolicy { target_tokens: 400_000, floor_tokens: 1_000, keep_recent_steps: 1, stub_tail_lines: 3 };
        let session = fx.create();
        run_with(session, vec![user("go")]).await;
        let rs = fx.sink.records();
        let rw = reweave_records(&rs);
        assert_eq!(rw.len(), 1, "{:?}", kinds(&rs));
        assert_eq!(rw[0].reason, "overflow");
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Yielded]);
        // The overflowed request and its retry are both recorded; the step count follows requests.
        assert_eq!(count(&rs, "model_request"), 4);
        assert_eq!(count(&rs, "model_response"), 3);
        assert_no_cache_break(&rs);
    }

    #[tokio::test]
    async fn unfoldable_overflow_fails_the_turn_with_an_inbox_item() {
        let mut fx = Fx::new("chat", false, false, seq(vec![big(), Reply::text("ok").into()])).await;
        fx.server.set_model("mock", Some(10_000));
        let session = fx.create();
        run_with(session, vec![user("go")]).await;
        let rs = fx.sink.records();
        assert_eq!(reweave_records(&rs).len(), 0);
        let items = inbox(&rs);
        assert_eq!(items.len(), 1, "{:?}", kinds(&rs));
        assert_eq!(items[0].text, texts::turn_failed(texts::OVERFLOW_UNFOLDABLE));
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Error]);
    }

    #[tokio::test]
    async fn an_operator_reweave_while_idle_and_one_queued_mid_turn() {
        let mut fx = Fx::new("chat", false, false, seq(vec![big(), big(), Reply::text("ok").into(), Reply::text("ok").into()])).await;
        fx.context = ReweavePolicy { target_tokens: 400_000, floor_tokens: 1_000, keep_recent_steps: 1, stub_tail_lines: 3 };
        let session = fx.create();
        let (tx, task) = spawn_run(session);
        tx.send(user("go")).unwrap();
        wait_until(&fx.sink, "turn end", |rs| count(rs, "turn_end") == 1).await;
        tx.send(Input::Reweave).unwrap();
        wait_until(&fx.sink, "reweave", |rs| count(rs, "reweave") == 1).await;
        let rs = fx.sink.records();
        assert_eq!(reweave_records(&rs)[0].reason, "operator");
        assert_eq!(count(&rs, "turn_start"), 1);
        finish_task(tx, task).await;
    }

    // ---- stall -------------------------------------------------------------------------------

    #[tokio::test]
    async fn stall_note_after_quiet_steps_and_not_again_until_progress() {
        let agents = AgentsCfg { stall_steps: 3, verify_finish: false, ..AgentsCfg::default() };
        let mut actions: Vec<Action> = (0..5).map(|_| bash("echo hi").into()).collect();
        actions.push(finish_call("done").into());
        let mut fx = Fx::build("lead", false, true, agents, seq(actions)).await;
        let session = fx.create();
        run_with(session, vec![user("go")]).await;
        let rs = fx.sink.records();
        let n = notes(&rs, NoteKind::Stall);
        assert_eq!(n, vec![texts::stall(3)]);
        let at = rs.iter().position(|r| matches!(&r.event, Event::HarnessNote { note: NoteKind::Stall, .. })).unwrap();
        let requests_before = rs[..at].iter().filter(|r| matches!(r.event, Event::ModelRequest(_))).count();
        assert_eq!(requests_before, 3);
    }
}
