//! One session: its log, its step loop, and what it does with everything that can happen to it.
//!
//! CONTRACT (public signatures and types are fixed;
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
//! `inbox_resolved`: `User`, except the resolution of a model-unavailable notice (see *Model server
//! unavailable*): `Harness`. `child_settled`: `Agent(child)`. A note carrying an agent's message:
//! `Agent(sender)`. Records queued by tools (`Shared::take_emitted`) keep the author they were
//! queued with.
//!
//! ## Runtime admission and clocks
//! Exhausted budgets retain the serialized tool schema but admit only existing-output inspection,
//! ledger cleanup and terminal/blocker delivery. The same policy applies before speculative starts.
//! Role Exec caps count durable `exec_started` admissions over own records, including errors and
//! interrupted attempts; old results are counted when no admission record exists. Zero denies all.
//! `budget_clock` transitions persist active intervals: queue and retry waits do not count, nor idle
//! turns. A restart closes an active interval at the latest durable timestamp, so unobserved
//! time after a crash is not guessed. Old logs keep wall time until their first clock transition.
//! Candidate flags and normalized outcome fingerprints are advisory, never success or refutation.
//!
//! Session cancellation, idle stop, settlement, archive and shutdown also close every session PTY,
//! including terminals whose earlier read already returned. Open terminals are not orphaned jobs.
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
//! - `fork`: `loom_core::log::fork_file(parent_log, <own log path>, upto_seq, …)`, whose checked copy
//!   gives the session its records, then appends `Event::Forked(forked)` (author `Agent(forked.parent)`).
//!   A parent prefix that is not a sound chain fails the fork with the copy's sentence and no log.
//! - `open`: opens the existing log. If the log reports damage, appends
//!   `interrupted{reason: "the session log was damaged and was cut back to its last good record
//!   ({detail})"}`. If the own records contain a `turn_start` with no later `turn_end` and no
//!   `session_end`, appends `interrupted{REASON_RESTART}` and `turn_end{Stopped}`. Then, unless the
//!   session has ended, the jobs of the harness process that is gone are settled: every own
//!   `job_registered` with no `job_settled`, in log order, and then every job an own `tool_result`
//!   gave the model (`meta[META_JOB]`, the first such result) that has neither `job_registered` nor
//!   `job_settled` (whether or not its job table found the command among `jobs.leftovers()`): for such
//!   a job `job_registered{job_id, call_id: that result's, command: the `command` argument of that
//!   call}` is appended first (author `Harness`). A job that ended by itself while no harness watched
//!   it (`jobs.ended_while_down`) gets `job_settled{exit_code, output: its stored output, detail:
//!   texts::job_ended_while_down(what the table said about the output)}` and, unless the model saw
//!   its end, `harness_note{Arrival, texts::job_arrival(..)}` as under *Idle*.
//!   Any other is lost: `job_settled{exit_code: None, output: None, detail: texts::JOB_LOST_DETAIL}`
//!   and, unless an own `Interrupted` note follows the registration or that result (the model was
//!   then already told that jobs from before it are gone), `harness_note{Arrival,
//!   texts::job_lost(job_id, command)}`.
//!   Then the files of the leftovers and of the jobs settled here are removed (`jobs.discard`), but
//!   for a job whose output could not be stored. `pending_job_ends()` is the number of job ends the
//!   model was told of since the last own `turn_end` (a `job_settled` with its note right after it)
//!   with no `turn_start` since; the runtime starts a turn for a session that was waiting. Calls
//!   `deps.ctx.jobs.resume_from(n)` with the highest job number in the log's `job_registered`
//!   records, those just appended included (`j7` → 7). Last, unless the session has ended, the
//!   prefix guard is primed (`PrefixGuard::prime`) with the weave of the records up to the last `model_request` and that
//!   record's epoch, so that the first request after a restart is checked like any other. When the
//!   stable hash of those messages differs from the one stored on the record (the rendering of the
//!   existing log changed, e.g. with an upgrade), `cache_break{req_id: that request's,
//!   first_diff_message: 0, detail: texts::rendering_changed(..)}` is appended, unless a
//!   `cache_break` already follows that record (an earlier open reported it).
//!
//! All three use `Durability::Always`, build the registry, and compute the state below from the
//! log, so that a session opened from its log behaves as the one that wrote it would:
//! `step` (own `model_request` records with purpose `Step`), `epoch`, `started_ms` (timestamp of
//! the own first record — `session_start` or `forked`), the last own `turn_end` reason, whether a
//! `session_end` exists, whether a `Budget` note has been given and how many steps followed it,
//! open inbox items (`inbox_opened` without a matching `inbox_resolved`).
//!
//! ## `run`
//! 1. If the session has ended (`session_end` in the log): return `End::Closed`. Otherwise resolve
//!    every open model-unavailable notice (the session stopped while a request was retrying, and none
//!    is now) with `inbox_resolved{item_id, texts::UNAVAILABLE_LEFT_OPEN}`, authored `Harness`. Record,
//!    as arrivals, the operator inputs left in the session's `queued/` directory (see
//!    [`queue_input`]), oldest first. A `{stem}.{seq}.taking` file was being recorded when the
//!    harness stopped: when the record at `seq` is an operator's (author `User`) `ledger` record or
//!    `Constraint`/`Approval` note, the recording reached the log and the file is only deleted;
//!    otherwise it is recorded like the others. Each input is so recorded once, except when the
//!    harness stops between the ledger entry and its `ledger` record in the log.
//! 2. If the session is a child (`deps.shared.is_child()`) and has no own `turn_start` yet: run a
//!    turn with `Trigger::Start`.
//! 3. Loop: wait for the next of (an [`Input`], a `JobEvent` from `deps.job_events`). Handle it as
//!    described under *Idle*. When `inputs` is closed: kill the session's jobs
//!    (`jobs.kill_all_because(kill_grace_s, why)`, `why` being `texts::JOB_SHUTDOWN_DETAIL` after
//!    `Control::stop_for_shutdown` and empty otherwise), record what `deps.job_events` holds then as
//!    under *Idle* (without starting a turn), and return `End::Closed` — except a child when the harness is
//!    not shutting down (no `Control::stop_for_shutdown`; the session was archived): it settles as for
//!    an idle `Input::Stop`, with `interrupted{REASON_OPERATOR}`, so that its parent is not left
//!    waiting for it. A shutdown cuts it instead, for the next start to resume.
//!
//! A turn that settles a child returns `End::Settled`; see *Settling*.
//!
//! ## Idle (no turn running)
//! - `Input::User(text)`: append `user_message{text}`. If the session has a mission journal whose
//!   ledger has no goal yet, `shared.ledger_append(true, GoalSet{text})` and append what it queued
//!   (`shared.take_emitted()`); a failure is logged with `tracing::warn!` and otherwise ignored.
//!   Start a turn (`Trigger::User`).
//! - `Input::Answer{item_id, answer}`: if no open inbox item of this session has that id, ignore.
//!   Otherwise append `inbox_resolved{item_id, answer}`; when the item is a `Question` or `Blocker`
//!   with a `reference` and the session has a journal, `shared.ledger_append(true,
//!   QuestionAnswer{id: reference, answer})` and append what it queued (failure: warn, ignore); the
//!   references of other kinds are not question ids. A blank answer to a non-blocking item is a
//!   dismissal: the ledger answer is `texts::DISMISSED_ANSWER`, a dismissed `Question` or `Blocker`
//!   gets `harness_note{Arrival, texts::question_dismissed(item.text)}`, and nothing else happens: no
//!   user message, no turn. Any other answer: append `user_message{texts::inbox_answer(item.text,
//!   answer)}`; start a turn (`Trigger::InboxAnswer`).
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
//! - `Input::Release{reason}`: the operator closed the mission short of its goal. Blank reason is
//!   ignored. Records `OperatorRelease` in the ledger and a protected note; no turn is started.
//! - `Input::Scope{hosts, note}`: network access the operator authorized. With a journal,
//!   `shared.ledger_append(true, ScopeGrant{hosts, note})` and append what it queued (failure: warn,
//!   carry on). Append `harness_note{Approval, texts::scope_granted(hosts, note)}` with author `User`.
//!   It starts no turn. (The runtime widens the egress policy itself, not the session.)
//! - `Input::Queued{file, input}`: rename `file` to `{stem}.{seq}.taking`, `seq` being the log's
//!   next seq; then `input` as above, then delete the renamed file. When `file` is gone it was taken
//!   already (at the start of `run`), and nothing happens.
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
//! - `JobEvent::Matched(m)` (a watched job wrote lines matching its `wake_on` pattern): append
//!   `job_matched{job_id, pattern, output, from, shown, matches}` authored `Tool` (`shown`: the line
//!   numbers of `m.lines`), then `harness_note{Arrival, texts::job_matched(..)}` with those lines
//!   and the handle of the stored part. When the last turn ended `Waiting` or `Yielded`, start a
//!   turn (`Trigger::JobOutput`): a session that sleeps on a long job is woken by what the job
//!   finds, not only by its end. During a turn the note is one more arrival; after a stop
//!   (`Stopped`) it wakes nothing.
//! - `Input::AgentMessage{from, text}`: append `harness_note{Arrival, texts::agent_message(text)}`
//!   authored `Agent(from)`. Start a turn (`Trigger::Resume`) only if the last turn ended `Waiting`.
//! - `Input::Resume`: start a turn (`Trigger::Resume`).
//! - `Input::Reweave`: run the re-weave procedure with reason `operator` (forced). No turn.
//! - `Input::Stop`: a child appends `interrupted{REASON_PARENT}`, kills its jobs, stops its children
//!   and settles `Stopped` with `texts::stopped_report(step)`, so its parent is not left waiting.
//!   Anything else: `jobs.kill_all`, `orch.stop_children(session)`. When the last turn ended `Waiting`
//!   or `Yielded`, append `interrupted{REASON_OPERATOR}` and `turn_end{Stopped}`: the stop is sticky,
//!   so the settlements and job ends it causes are recorded without starting a turn, and only a user
//!   message, an inbox answer or `Resume` runs the session again. Otherwise append
//!   `interrupted{REASON_OPERATOR}` only if a job or child was running. No turn.
//!
//! ## A turn
//! Install a fresh cancellation token (`Control::begin_turn`); append `turn_start{trigger}`. If the
//! previous own turn ended `Stopped`, append `harness_note{Interrupted, …}` with
//! `texts::AFTER_RESTART` when the most recent own `interrupted` record's reason is
//! `REASON_RESTART` or starts with `the session log was damaged`, else `texts::AFTER_IDLE_STOP` when
//! that record was written while no turn was open (a stop between turns), else `texts::AFTER_STOP`
//! (no note for a turn that starts after `Control::stop_for_shutdown`: it is cut at once, and the
//! note belongs to the first turn after the restart).
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
//!    When the token was fired by `Control::stop_for_shutdown` (the harness is going down) the turn
//!    is recorded as the next `open` would record a turn cut by a restart, so that the next start
//!    resumes it: the reason is `REASON_RESTART`, the job events queued by then (jobs started in
//!    the step, jobs killed just now) are recorded as under *Idle* after `jobs.kill_all`, a child is
//!    not settled (its turn ends `Stopped` like any other session's), and the status is not
//!    published at the turn's end (`status.json` keeps `Running`, which is what makes the next
//!    start activate the session). A turn started after that call is cancelled from birth.
//! 2. **Arrivals.** Drain, without waiting, everything queued in `deps.job_events` and in the
//!    inputs channel, handling each as under *Idle* except that nothing starts a turn, `Resume` is
//!    ignored, and `Reweave` sets a flag that forces the re-weave in point 4. A `Stop` (one that
//!    arrived while a trigger was queued or between turns) cancels the turn's token and ends the
//!    draining: what was sent after it stays queued for the idle loop, after the turn has ended
//!    `Stopped` (point 1). An arrival that appended a `user_message` resets the nudge count.
//! 3. **Budget** (only when the session's budget has a non-zero `max_steps` or `max_minutes`; own
//!    steps and minutes since `started_ms`, except that a turn the operator starts (`User`,
//!    `InboxAnswer`, `Resume`) after a turn that ended `BudgetExhausted` gets a fresh budget of the
//!    configured size: the count starts at its `turn_start`, the earlier `Budget` note no longer
//!    counts, and the turn begins with `harness_note{Info, texts::budget_renewed(max_steps,
//!    max_minutes)}`): when either is reached and no `Budget` note has been
//!    given, append `harness_note{Budget, texts::budget_reached(step, minutes, can_finish,
//!    is_child)}` (`can_finish` = the registry has `finish`; `is_child` selects the wording, an
//!    assignment's budget for a child, the session's own for a root). When the note was given and
//!    `BUDGET_GRACE_STEPS` steps have run since, the child settles `BudgetExhausted` with
//!    `texts::budget_exhausted_report(step, minutes, last_reply)` (`last_reply` = text of the last
//!    own model response); a session that is not a child instead opens an inbox item (`Parked`,
//!    blocking, text `texts::turn_failed("The session's budget is used up.")`) and the turn ends
//!    `BudgetExhausted`.
//! 4. **Stall** (only for `Termination::Explicit` sessions with a journal; `agents.stall_steps > 0`):
//!    when the last `stall_steps` own steps contain no `ledger` record, no `tool_result` of class
//!    `Write` with status `Ok`, and no `child_spawned`/`child_settled`, and no `Stall` note was given
//!    within those steps, append `harness_note{Stall, texts::stall(stall_steps)}`.
//! 5. **Re-weave.** `w = weave(all records)` (a `Woven`, which planning uses as it is), computed
//!    here once and again only after a record that changes it (a `reweave`); points 5 and 6 and the
//!    digest request all use it. See below. Forced when the flag from point 2 is set.
//! 6. **Request.** `PrefixGuard::check(w.epoch, &w.messages)`: on `Break`
//!    append `cache_break{req_id, first_diff_message, detail}` and carry on. Render the HUD
//!    (`hud::render`, over own records, with `jobs.list()` entries that are running — their output
//!    lines counted on from where the previous request's count stopped —, `orch.children(session)`
//!    entries that are running, the ledger when there is a journal, `BriefOpts::default()`,
//!    `agents.unviewed_min_lines`, own steps and start time counted from where the budget was granted
//!    (see point 3), budget).
//!    Store the HUD text (`blobs.put_bytes`; a failure gives `hud: None`). Append
//!    `model_request{req_id: ids::new_request_id(), step (1-based), epoch, purpose: Step,
//!    n_messages, stable_hash: prefix::stable_hash(&w.messages), hud, est_tokens}`. Publish status
//!    with `fork_point` = the seq of the record before this `model_request`.
//!    Acquire the limiter (`deps.limiter.acquire(deps.priority, token)`; `None` = cancelled). Send
//!    `ChatRequest{messages: w.messages + weave::hud_message(hud), tools: w.tools, tool_choice:
//!    Auto, max_tokens: client.profile().max_output_tokens, seed: None, extra: empty}` with
//!    `client.complete`, forwarding every `StreamEvent` to `Sink::delta(session, req_id, …)` as it
//!    arrives, and watching it as *Model server unavailable* says.
//!    - `Err(Cancelled)`: point 1.
//!    - `Err(ContextOverflow{limit, ..})`: once per step, run the re-weave procedure forced with reason
//!      `overflow` and that `limit`; if it appended a `reweave`, go back to the start of this point (new weave, new
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
//!    - Run the complete tool calls in order (below). Then, unless `finish == Length`, the calls that
//!      have a name but are not complete (their arguments are not a JSON object) get one
//!      `harness_note{Nudge, …}` made of `texts::malformed_call(name, arguments)` for each: they are
//!      not run, and with no `tool_call` record they are not replayed to the server. If the turn
//!      ended there, stop.
//!    - `finish == Length`: when no call was complete, the reply counts as a nudge, and one past
//!      `agents.max_nudges` gives up with `texts::repeated_cut(n)`. Otherwise append
//!      `harness_note{OutputCut, texts::output_cut(completion_tokens, name of the first incomplete
//!      call if any, number of calls run)}` and go to the next step.
//!    - Malformed calls and no complete one: the reply counts as a nudge, and one past `max_nudges`
//!      gives up with `texts::repeated_malformed(n)`; otherwise next step. It never reaches the gate.
//!      *Give up*: a child settles `Failed` with `texts::failed_report(why, reply)`; any other session
//!      opens an inbox item (`Parked`, blocking, `texts::turn_failed(why)`) and the turn ends `Parked`.
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
//! Calls run one at a time, but for the early starts below.
//!
//! ### Early starts
//! With `tools.speculate` (default true) a call of a tool whose `Tool::speculative` is true can be
//! started before its turn. While the reply streams, `StreamEvent::ToolCallReady{index, ..}` starts
//! the call when every call before it in this attempt was ready and is of such a tool (the first that
//! is not, or a gap, ends early starts for the attempt), its arguments are a JSON object that
//! `loom_tools::prepare` accepts, and fewer than `MAX_EARLY` early tasks are running (those of
//! discarded calls count until they have ended). It runs (`prepare`, `Prepared::run`) in a task with
//! the id the call will keep (the server's when `with_fresh_ids` would keep it, else a fresh one), a
//! child of the turn's token and a `FileTracker` of its own; nothing of it counts until it is
//! claimed. A new attempt or a failed request cancels every early call of the request. When the reply
//! is in, its calls take the ids of the early calls they hold byte for byte (same index, name and
//! arguments) unless the log or an earlier call already has that id; the others are cancelled,
//! and the complete calls of the reply's leading run of such tools that were not started early are
//! started together. In the in-order loop, a call with an early run of the same index, name, arguments
//! and id takes that run's result (awaited; a stop interrupts it as it would a call run in place) in
//! place of `execute`: its file records move into the session's tracker, `Ran::finish` stores and
//! admits it, and its `tool_result` gets `meta[META_EARLY_MS]`. Early calls left unclaimed when the
//! loop ends are cancelled and awaited, so none outlives the step. Records and what the model sees are
//! those of running every call in place, but for timings, fresh call ids and that key. Counts (started,
//! claimed, discarded, ms saved) are logged at debug level at the end of each turn.
//!
//! ### Model server unavailable
//! Every model request of a session (a step's, a digest's) is watched through its stream events (the
//! votes of `decide`, which the runtime sends, are not). A *failure* is a `StreamEvent::Retrying`; a
//! *server event* is any event but `AttemptStart` and `Retrying`. The request's first failure is about
//! when the client's retry window starts. It is *retrying* from a failure until the next server
//! event. Its *outage* starts at its first failure, and again at a failure that ends an attempt whose
//! server events began at least `agents.unavailable_notice_s` (`after`) before it (the server was
//! answering, not unavailable). With `after` not 0, a notice is due when the request is retrying and
//! its outage started `after` back — at once on a failure that comes later than that — unless
//! `retry_window_s` is not 0 and the request's first failure plus the window is not later than that
//! time (the request then fails at its next failed attempt, and that failure is handled as usual).
//! Then the session appends `inbox_opened` (author `Harness`) of a *model-unavailable notice* —
//! `kind: Blocker`, `blocking: false`, no `call_id`, no `reference`, the only item of that shape —
//! with `texts::model_unavailable(base_url, since, last, until)`: `since` is the start of the outage,
//! `last` the latest `Retrying` reason, `until` (when `retry_window_s` is not 0) the request's first
//! failure plus the window, times by `texts::clock`. Status is published. At most one notice is
//! opened per request (so one per session at a time; a later request opens its own). When the
//! request ends, its notice is resolved:
//! `inbox_resolved{item_id, answer}` authored `Harness`, `answer` being `texts::unavailable_answered(now)`
//! for a completion, `texts::unavailable_stopped(now)` for `Cancelled` and `texts::unavailable_failed(now,
//! error)` for any other error; then the result is handled as it would be without the notice. Neither
//! record is rendered by the weave or starts a turn, and the request is never rebuilt: every attempt
//! sends the body the client encoded once.
//!
//! ## Settling (children)
//! Sync `child_completed` with the full typed settlement before `turn_end{reason}` and
//! `session_end{outcome, detail}` per the table, kill the session's
//! jobs, publish status (`Phase::Ended`), and return `End::Settled(Settlement{child: id, role,
//! outcome, report, full, payload, steps: own steps, usage: sum of own responses' usage})`.
//! `Returned` → `Finished`/`Done`; `Blocked` → `Blocked`/`Done`; `BudgetExhausted` →
//! `BudgetExhausted`/`BudgetExhausted`; `Stopped` → `Stopped`/`Stopped`; `Failed` → `Error`/`Failed`.
//! `detail` is the first line of the report cut to 200 characters. For settlements this file makes
//! itself, `full` is `None` and `payload` is `Value::Null`.
//!
//! ## Re-weave procedure (`reason`: `target`, `overflow`, `operator`)
//! `est = estimator.tokens_for_messages(&w.messages)` plus the tokens of the tool specs' JSON.
//! `size` is the size of the next request as the server counts it, when it has counted one in this
//! epoch: with `m` the latest own-or-inherited step `model_request` of epoch `w.epoch` whose
//! response reported `prompt_tokens > 0` and `n = m.n_messages`, `size = m's prompt_tokens +
//! estimator.tokens(Σ (item.chars + 2) over the items merged into w.messages[n − 1] from records
//! after m) + estimator.tokens_for_messages(&w.messages[n..])`. Before the first such response of
//! an epoch, `size = est`. `window` is `deps.context_window`; for an `overflow` re-weave it
//! is the smaller of that and the limit the server's error stated (the estimate of the refused
//! request when it stated none), so that a forced re-weave can be planned when the window is unknown
//! or set too large. `limit` = `deps.context.target_tokens`, lowered (when there is a `window`) to
//! `window − reserve` and to four fifths of `window`; the floor used is `floor_tokens` lowered to
//! half of `window`, and to half of `limit` when it is not below `limit`. `reserve` is, for a
//! profile `max_output_tokens` (`max`) below `window`,
//! `max + min(min(4_096, window / 4), window − max − 1)`: the reply asked for is always kept, so a
//! request at the trigger plus the `max_tokens` it sends fits the window, and when the reply leaves
//! little room the trigger can drop to 1 and the floor to 0. A `max_output_tokens` at or above
//! `window` cannot be honoured and counts as none; without one `reserve` is
//! `min(20_480, window / 4)`, so a small window keeps a positive trigger. For windows of 81_920
//! tokens and more the quarter of the window never cuts the 4_096 or the 20_480, and for a 1M
//! window the defaults (400k, 180k) are unchanged. Not forced and `size <= limit`: nothing to
//! do. The plan counts in the estimator's units: it is made with the floor used × `est / size`, and
//! is *enough* when its `after_tokens_est` is at or below the midpoint between the floor used and
//! `limit`, × `est / size`.
//! 1. `plan = w.plan(records, estimator, &policy, false)` (`plan_reweave` on the step's weave) with
//!    `policy = deps.context`. While
//!    the plan is not enough and `policy.keep_recent_steps` is above `MIN_KEEP_RECENT_STEPS`, halve
//!    `keep_recent_steps` (not below the minimum) and plan again: when folding what lies outside the
//!    protected recent steps does not make room, it is the output of recent steps that fills the
//!    window, so fewer of them are protected.
//! 2. Still not enough: `text_plan = w.plan(records, estimator, &policy, true)`. Not forced
//!    and `text_plan` is not enough either: return without a record and without a digest request (see
//!    "Why a re-weave must be worth it"). Otherwise, when `text_plan` exists and the re-weave is not
//!    for an `overflow` (the server has just refused this prefix, and would refuse a digest request
//!    on it as well), ask for a digest — a
//!    request of the current stable messages plus one `user` message `texts::DIGEST_PROMPT`, same
//!    tools, `max_tokens: DIGEST_MAX_TOKENS`, recorded as `model_request{purpose: Digest, hud: None}`
//!    only (its reply is not appended as a record), and sent once the limiter grants it at
//!    `deps.priority` (the step waits for it), watched as a step's request is (*Model server
//!    unavailable*) but with its stream events kept from the sink. A non-empty reply text is the
//!    digest; an error or an empty text gives none. A cancellation returns without a record (the step
//!    handles it).
//!    The plan becomes `text_plan`, with or without a digest: the ledger brief is the durable state,
//!    the digest an addition to it.
//! 3. No plan: return without a record. Otherwise append `reweave{epoch: current + 1, upto_seq,
//!    evictions, brief: texts::reweave_brief(<ledger.brief(default) or "">, <the rendered frontier, with
//!    `attempts_run` of the records, when the session has a journal>), digest, reason,
//!    before_tokens: size, after_tokens_est: size − (plan.before_tokens_est − plan.after_tokens_est)
//!    × size / est}`.
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
//! - `open` after a crash: a job that ended by itself while the harness was down is settled with its
//!   exit code and stored output, and one given to the model but never registered is registered
//!   first, also when its watcher had ended it before the crash; a job the sweep killed is lost; an
//!   idle session whose inputs a shutdown closes records the end of the jobs it killed, saying that
//!   the shutdown stopped them;
//! - inputs arriving mid-turn are in the next request; an inbox answer resolves the item, answers
//!   the ledger question and starts a turn;
//! - re-weave: with a small `target_tokens`, a `reweave` record appears, the epoch rises, the next
//!   request no longer carries the stubbed output, and no `cache_break` is recorded for it; the
//!   digest path (plan insufficient → digest request → text eviction) and its failure path;
//!   `ContextOverflow` from the server triggers a forced re-weave and a retry; unfoldable overflow
//!   fails the turn with an inbox item;
//! - a model error (`Rejected`) parks a lead with `turn_failed` and settles a child `Failed`;
//! - a request retrying (503s) past `unavailable_notice_s` opens one notice with the address and the last
//!   error, resolved by the harness when the reply arrives, which is handled as usual; the retried
//!   bodies are identical and the weave holds nothing of it; a request that gives up resolves it before
//!   the step fails; none is opened when the window ends first; a reply that streams past the notice
//!   time and then breaks starts a new outage; a stop resolves it; 0 opens none; a digest request is
//!   watched too; a notice left open is resolved when `run` starts;
//! - stall note after `stall_steps` steps of read-only calls, and not again until progress.

use crate::frontier;
use crate::gate::{self, Yield, YieldCtx};
use crate::hud::{self, HudChild, HudInput, HudJob};
use crate::rtools::{build_registry, ChildInfo, Delivery, Effect, Settlement, Shared};
use crate::texts;
use futures_util::FutureExt;
use loom_core::admit::AdmitPolicy;
use loom_core::config::{AgentsCfg, Paths};
use loom_core::estimate::TokenEstimator;
use loom_core::event::{
    Author, Budget, ChildCompleted, ChildOutcome, ChildSettled, Event, FinishReason, Forked, InboxItem, InboxKind,
    ModelRequest, ModelResponse, NoteKind, Purpose, Record, Reweave, Seq, SessionOutcome, SessionStart, StoredAction,
    Termination, Timing, ToolCall, ToolCallRequest, ToolClass, ToolSpec, ToolStatus, Trigger, TurnEndReason, Usage,
    META_DEFERRED_OBSERVATION, META_EXIT_CODE, META_JOB, META_SIGNAL,
};
use loom_core::ids::{new_item_id, new_request_id, CallId, SessionId};
use loom_core::ledger::{BriefOpts, LedgerOp, LedgerState};
use loom_core::log::{fork_file, Durability, SessionLog};
use loom_core::message::Message;
use loom_core::prefix::{stable_hash, PrefixCheck, PrefixGuard};
use loom_core::weave::{hud_message, weave, ReweavePolicy, Weave, Woven};
use loom_core::{now_ms, BlobRef};
use loom_model::assemble::{Completion, StreamEvent};
use loom_model::client::{ModelClient, ModelError};
use loom_model::limit::{Limiter, Priority};
use loom_model::request::{ChatRequest, ToolChoice};
use loom_tools::files::FileTracker;
use loom_tools::jobs::{JobEvent, JobInfo, JobState};
use loom_tools::proc::Ended;
use loom_tools::{execute, prepare, refused, Admission, Ran, Registry, ToolCtx};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use tokio::task::JoinHandle;
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
    /// The operator authorized network access to `hosts` for the mission.
    Scope { hosts: Vec<String>, note: Option<String> },
    /// The operator closed the mission short of its goal, with a reason.
    Release { reason: String },
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
    /// A `Constraint`, `Approval`, `Withdraw` or `Scope` kept on disk at `file` until it is recorded (see
    /// [`queue_input`]).
    Queued { file: PathBuf, input: Box<Input> },
}

/// One input of a session's `queued/` directory.
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum KeptInput {
    Constraint { text: String },
    Approval { text: String, scope: String },
    Withdraw { id: String, reason: String },
    Scope { hosts: Vec<String>, note: Option<String> },
    Release { reason: String },
}

impl KeptInput {
    fn into_input(self) -> Input {
        match self {
            KeptInput::Constraint { text } => Input::Constraint(text),
            KeptInput::Approval { text, scope } => Input::Approval { text, scope },
            KeptInput::Withdraw { id, reason } => Input::Withdraw { id, reason },
            KeptInput::Scope { hosts, note } => Input::Scope { hosts, note },
            KeptInput::Release { reason } => Input::Release { reason },
        }
    }
}

/// Where a session's operator inputs wait on disk until it records them.
fn queue_dir(paths: &Paths, session: &SessionId) -> PathBuf {
    paths.session_dir(session).join("queued")
}

/// Keep an operator rule, approval or withdrawal for `session` on disk until the session has
/// recorded it: a session takes inputs between steps, not while a tool call runs, and a harness that
/// stops before then must not lose one. Returns the [`Input::Queued`] to send to the session, which
/// records the input and then deletes the file; a session that starts finds what is left on disk and
/// records it first. Any other input is returned as it is.
pub fn queue_input(paths: &Paths, session: &SessionId, input: Input) -> Result<Input, String> {
    let kept = match &input {
        Input::Constraint(text) => KeptInput::Constraint { text: text.clone() },
        Input::Approval { text, scope } => KeptInput::Approval { text: text.clone(), scope: scope.clone() },
        Input::Withdraw { id, reason } => KeptInput::Withdraw { id: id.clone(), reason: reason.clone() },
        Input::Scope { hosts, note } => KeptInput::Scope { hosts: hosts.clone(), note: note.clone() },
        Input::Release { reason } => KeptInput::Release { reason: reason.clone() },
        _ => return Ok(input),
    };
    let file = write_kept(&queue_dir(paths, session), &kept).map_err(|e| {
        format!("Could not keep the input for session {} on disk ({e}); send it again.", session.as_str())
    })?;
    Ok(Input::Queued { file, input: Box::new(input) })
}

/// Write `kept` durably as the next file of `dir`; file names sort in the order they were written.
fn write_kept(dir: &Path, kept: &KeptInput) -> std::io::Result<PathBuf> {
    fn write_synced(dir: &Path, tmp: &Path, path: &Path, kept: &KeptInput) -> std::io::Result<()> {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(tmp)?;
        file.write_all(&serde_json::to_vec(kept).map_err(std::io::Error::other)?)?;
        file.sync_all()?;
        std::fs::rename(tmp, path)?;
        std::fs::File::open(dir)?.sync_all()
    }
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    loom_core::config::ensure_private_dir(dir)?;
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let name = format!("{:016}-{n:010}.json", now_ms());
    let path = dir.join(&name);
    let tmp = dir.join(format!(".{name}.tmp"));
    if let Err(e) = write_synced(dir, &tmp, &path, kept) {
        // The operator is told to send it again, so it must not be recorded later as well.
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(&path);
        return Err(e);
    }
    Ok(path)
}

/// The name a kept input's `file` takes while the session records it: `{stem}.{seq}.taking`, where
/// `seq` is the seq the first record of the recording gets.
fn taking_path(file: &Path, seq: Seq) -> PathBuf {
    let name = file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let stem = name.split('.').next().unwrap_or_default();
    file.with_file_name(format!("{stem}.{seq}.taking"))
}

/// The seq a name made by [`taking_path`] carries.
fn taking_seq(file: &Path) -> Option<Seq> {
    let name = file.file_name()?.to_str()?.strip_suffix(".taking")?;
    name.rsplit_once('.')?.1.parse().ok()
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
        *self.turn.lock().unwrap_or_else(|p| p.into_inner()) = token.clone();
        // Read after the token is installed: a shutdown that began before this point is seen here,
        // one that begins after it cancels the installed token.
        if self.is_shutting() {
            token.cancel();
        }
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
    /// Own steps and start time from which a root's budget counts: a turn the operator starts after
    /// the budget ran out begins a fresh one.
    budget_step_base: u32,
    budget_from_ms: Option<u64>,
    clock: Option<ActiveClock>,
    last_ms: u64,
    inbox: Vec<InboxItem>,
    last_interrupted: Option<String>,
    /// The latest `interrupted` was recorded while no turn was open: a stop between turns.
    stopped_idle: bool,
    /// A `turn_start` with no `turn_end` after it.
    in_turn: bool,
    prompt_tokens: u64,
    cached_tokens: u64,
    usage: Usage,
    fork_point: Option<Seq>,
    /// The latest step request (records of the parent's included: they are part of the weave).
    requested: Option<Measured>,
    /// The latest step request whose reply carried the prompt size the server counted.
    measured: Option<Measured>,
}

/// Durable intervals rather than subtracting response timings (which can overlap or never arrive).
#[derive(Default)]
struct ActiveClock {
    accrued_ms: u64,
    running_from: Option<u64>,
}

impl ActiveClock {
    fn elapsed(&self, now: u64) -> u64 {
        self.accrued_ms.saturating_add(self.running_from.map_or(0, |from| now.saturating_sub(from)))
    }
    fn set(&mut self, running: bool, at: u64) {
        if let Some(from) = self.running_from.take() {
            self.accrued_ms = self.accrued_ms.saturating_add(at.saturating_sub(from));
        }
        self.running_from = running.then_some(at);
    }
}

/// Dispatch policy shared by streamed speculative reads and normal calls. Unknown tools fail closed
/// during wrap-up; adding a new State/Terminal tool cannot silently create another probing route.
#[derive(Clone, Copy, Default)]
struct CallPolicy {
    wrapup: bool,
}

impl CallPolicy {
    fn allows(self, name: &str, args: &Value) -> bool {
        if !self.wrapup {
            return true;
        }
        match name {
            "out_read" | "out_grep" | "ledger" | "mission_state" | "security_query" | "codec_calc" | "pty_close"
            | "note" | "evidence" | "claim_update" | "finish" | "conclude" | "verdict" | "report_blocker"
            | "ask_user" | "wait" | "agent_stop" | "agent_list" | "job_kill" => true,
            "security_record" => args.get("operation").is_some_and(|op| {
                let has = |key| op.get(key).and_then(Value::as_str).is_some_and(|s| !s.trim().is_empty());
                match op.get("action").and_then(Value::as_str) {
                    Some("coverage_set") => {
                        has("asset")
                            && matches!(
                                op.get("disposition").and_then(|d| d.get("status")).and_then(Value::as_str),
                                Some("tested" | "deferred")
                            )
                    }
                    Some("hypothesis_evidence" | "hypothesis_verdict" | "fact_retract" | "rule_retract") => has("id"),
                    Some("revisit_acknowledge") => has("target"),
                    _ => false,
                }
            }),
            "step" => {
                args.get("id").and_then(Value::as_str).is_some_and(|s| !s.trim().is_empty())
                    && args.get("text").is_none()
                    && matches!(args.get("status").and_then(Value::as_str), Some("done" | "dropped"))
            }
            "job_wait" => args.get("timeout_s").and_then(Value::as_u64).is_some_and(|s| s <= 2),
            _ => false,
        }
    }
}

/// A step request as the re-weave check needs it.
#[derive(Clone, Debug, Default)]
struct Measured {
    req_id: String,
    /// Seq of the `model_request` record.
    seq: Seq,
    epoch: u32,
    n_messages: u32,
    /// What the server counted for the request; 0 until its reply is in.
    prompt_tokens: u64,
}

impl State {
    fn absorb(&mut self, idx: usize, rec: &Record) {
        match &rec.event {
            Event::SessionStart(s) => {
                self.own_from = idx;
                self.started_ms = rec.ts_ms;
                self.termination = Some(s.termination);
                self.budget = s.budget.clone();
                if s.schema >= 2 {
                    self.clock = Some(ActiveClock::default());
                }
            }
            Event::Forked(f) => {
                *self = State {
                    own_from: idx,
                    started_ms: rec.ts_ms,
                    epoch: self.epoch,
                    termination: Some(f.termination),
                    budget: f.budget.clone(),
                    clock: self.clock.take().map(|_| ActiveClock::default()),
                    requested: self.requested.take(),
                    measured: self.measured.take(),
                    ..State::default()
                };
            }
            Event::ModelRequest(m) if m.purpose == Purpose::Step => {
                self.step = self.step.saturating_add(1);
                self.fork_point = rec.seq.checked_sub(1);
                self.requested = Some(Measured {
                    req_id: m.req_id.clone(),
                    seq: rec.seq,
                    epoch: m.epoch,
                    n_messages: m.n_messages,
                    prompt_tokens: 0,
                });
            }
            Event::StoredAction(_) => {
                self.step = self.step.saturating_add(1);
                self.fork_point = rec.seq.checked_sub(1);
            }
            Event::ModelResponse(r) => {
                if let Some(q) = self.requested.as_ref().filter(|q| q.req_id == r.req_id && r.usage.prompt_tokens > 0) {
                    self.measured = Some(Measured { prompt_tokens: r.usage.prompt_tokens, ..q.clone() });
                }
                self.prompt_tokens = r.usage.prompt_tokens;
                self.cached_tokens = r.usage.cached_tokens;
                self.usage.prompt_tokens = self.usage.prompt_tokens.saturating_add(r.usage.prompt_tokens);
                self.usage.cached_tokens = self.usage.cached_tokens.saturating_add(r.usage.cached_tokens);
                self.usage.completion_tokens = self.usage.completion_tokens.saturating_add(r.usage.completion_tokens);
                self.usage.reasoning_tokens = self.usage.reasoning_tokens.saturating_add(r.usage.reasoning_tokens);
            }
            Event::Reweave(r) => self.epoch = r.epoch,
            Event::BudgetClock { running } => {
                let old_elapsed = rec.ts_ms.saturating_sub(self.budget_from_ms.unwrap_or(self.started_ms));
                let clock = self.clock.get_or_insert(ActiveClock { accrued_ms: old_elapsed, running_from: None });
                clock.set(*running, rec.ts_ms);
            }
            Event::HarnessNote { note: NoteKind::Budget, .. } => self.budget_note_step = Some(self.step),
            Event::InboxOpened(item) => self.inbox.push(item.clone()),
            Event::InboxResolved { item_id, .. } => self.inbox.retain(|i| &i.item_id != item_id),
            Event::TurnStart { trigger } => {
                self.has_turn = true;
                self.in_turn = true;
                if renews_budget(*trigger, self.last_end) {
                    self.budget_step_base = self.step;
                    self.budget_from_ms = Some(rec.ts_ms);
                    self.budget_note_step = None;
                    if self.clock.is_some() {
                        self.clock = Some(ActiveClock::default());
                    }
                }
            }
            Event::TurnEnd { reason } => {
                self.last_end = Some(*reason);
                self.in_turn = false;
                if let Some(clock) = &mut self.clock {
                    clock.set(false, rec.ts_ms);
                }
            }
            Event::SessionEnd { outcome, .. } => self.ended = Some(*outcome),
            Event::ChildCompleted(result) => {
                self.ended = Some(match result.outcome {
                    ChildOutcome::Returned | ChildOutcome::Blocked => SessionOutcome::Done,
                    ChildOutcome::BudgetExhausted => SessionOutcome::BudgetExhausted,
                    ChildOutcome::Stopped => SessionOutcome::Stopped,
                    ChildOutcome::Failed => SessionOutcome::Failed,
                });
            }
            Event::Interrupted { reason } => {
                if let Some(clock) = &mut self.clock {
                    let restart = reason == texts::REASON_RESTART || reason.starts_with("the session log was damaged");
                    clock.set(false, if restart { self.last_ms } else { rec.ts_ms });
                }
                self.last_interrupted = Some(reason.clone());
                self.stopped_idle = !self.in_turn;
            }
            _ => {}
        }
        self.last_ms = rec.ts_ms;
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

/// Most early calls that run at once; a call that is ready beyond that runs in its turn.
const MAX_EARLY: usize = 8;

/// `tool_result` meta key: the call was started early, this many milliseconds before the in-order
/// loop reached it. Not shown to the model.
pub const META_EARLY_MS: &str = "early_ms";

/// What the session's early starts came to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct EarlyCounts {
    started: u64,
    claimed: u64,
    discarded: u64,
    /// Over claimed calls: how long before the end of the reply each started, capped by its run time.
    saved_ms: u64,
}

/// The task of a call started early. Dropped before it has ended (a step that ends on a failed
/// append, or a session future dropped while a claim awaits it), it is stopped but not awaited: it
/// ends at its next await, and a blocking read it handed to a thread finishes there unobserved.
struct EarlyTask {
    handle: JoinHandle<Ran>,
    /// The call's own token.
    cancel: CancellationToken,
}

impl EarlyTask {
    fn stop(&self) {
        self.cancel.cancel();
        self.handle.abort();
    }
}

impl Drop for EarlyTask {
    fn drop(&mut self) {
        if !self.handle.is_finished() {
            self.stop();
        }
    }
}

/// One call started before its turn.
struct EarlyRun {
    name: String,
    arguments: String,
    /// Its own call id, its own token (a child of the turn's) and its own file tracker.
    ctx: ToolCtx,
    started: Instant,
    task: EarlyTask,
}

impl EarlyRun {
    fn holds(&self, call: &ToolCallRequest) -> bool {
        call.name == self.name && call.arguments == self.arguments
    }
}

/// The calls of one model request that were started early. See *Early starts* above. Dropped
/// without `discard` (a step that ends on a failed append), its tasks are stopped, not awaited.
struct Early {
    on: bool,
    policy: CallPolicy,
    registry: Registry,
    template: ToolCtx,
    turn: CancellationToken,
    /// The call ids of the session's log.
    logged: HashSet<String>,
    runs: BTreeMap<usize, EarlyRun>,
    /// Calls `0..clear` of this attempt were ready and are of tools that may start early.
    clear: usize,
    /// A call that may not start early came before: nothing more starts in this attempt.
    blocked: bool,
    /// Indexes started early in this attempt, whatever became of them.
    tried: BTreeSet<usize>,
    /// The server's ids of the calls of this attempt that were ready.
    ready_ids: HashSet<String>,
    /// When the finished reply arrived.
    reply_end: Option<Instant>,
    /// Tasks of discarded runs, still to be awaited.
    dropped: Vec<EarlyTask>,
    counts: Arc<Mutex<EarlyCounts>>,
}

impl Early {
    fn new(
        on: bool,
        registry: Registry,
        template: ToolCtx,
        turn: &CancellationToken,
        logged: HashSet<String>,
        counts: Arc<Mutex<EarlyCounts>>,
    ) -> Early {
        Early {
            on,
            policy: CallPolicy::default(),
            registry,
            template,
            turn: turn.clone(),
            logged,
            runs: BTreeMap::new(),
            clear: 0,
            blocked: false,
            tried: BTreeSet::new(),
            ready_ids: HashSet::new(),
            reply_end: None,
            dropped: Vec::new(),
            counts,
        }
    }

    fn count(&self, f: impl FnOnce(&mut EarlyCounts)) {
        f(&mut self.counts.lock().unwrap_or_else(|p| p.into_inner()));
    }

    fn may_start(&self, name: &str) -> bool {
        self.registry.get(name).is_some_and(|t| t.speculative())
    }

    /// Follow the stream: a ready call may start; a new attempt voids what the earlier ones started.
    fn on_event(&mut self, event: &StreamEvent) {
        match event {
            StreamEvent::AttemptStart { .. } => {
                for run in std::mem::take(&mut self.runs).into_values() {
                    self.drop_run(run);
                }
                self.clear = 0;
                self.blocked = false;
                self.tried.clear();
                self.ready_ids.clear();
            }
            StreamEvent::ToolCallReady { index, id, name, arguments } if self.on && !self.blocked => {
                // A call after one of a tool that may not start early must see what that call did.
                if usize::try_from(*index).ok() != Some(self.clear) || !self.may_start(name) {
                    self.blocked = true;
                    return;
                }
                // The id the call will keep (see `with_fresh_ids`): the server's, unless it is empty
                // or the log or an earlier call of this attempt has it.
                let server = id.as_deref().filter(|s| !s.is_empty());
                let kept = server.filter(|s| !self.logged.contains(*s) && self.ready_ids.insert((*s).to_string()));
                self.start(self.clear, name, arguments, kept.map(CallId::from).as_ref());
                self.clear = self.clear.saturating_add(1);
            }
            _ => {}
        }
    }

    /// Start call `index` unless it has a run, the turn is cancelled, `MAX_EARLY` tasks are running
    /// (counting those of discarded runs until they have ended), or its arguments are not a JSON
    /// object the tool accepts (its turn reports that). `id` is the call's final id when it is known.
    fn start(&mut self, index: usize, name: &str, arguments: &str, id: Option<&CallId>) {
        let tasks = self.runs.values().map(|r| &r.task).chain(&self.dropped);
        let running = tasks.filter(|t| !t.handle.is_finished()).count();
        if self.runs.contains_key(&index) || self.turn.is_cancelled() || running >= MAX_EARLY {
            return;
        }
        if !matches!(serde_json::from_str::<Value>(arguments), Ok(Value::Object(ref a)) if self.policy.allows(name, &Value::Object(a.clone())))
        {
            return;
        }
        let mut ctx = self.template.clone();
        ctx.call_id = id.cloned().unwrap_or_else(fresh_call_id);
        ctx.cancel = self.turn.child_token();
        ctx.files = Arc::new(FileTracker::new());
        let Ok(call) = prepare(&self.registry, &ctx, name, arguments) else { return };
        if !call.speculative() {
            return;
        }
        let (run_ctx, cancel) = (ctx.clone(), ctx.cancel.clone());
        let task = EarlyTask { handle: tokio::spawn(async move { call.run(&run_ctx).await }), cancel };
        let run =
            EarlyRun { name: name.to_string(), arguments: arguments.to_string(), ctx, started: Instant::now(), task };
        self.runs.insert(index, run);
        self.tried.insert(index);
        self.count(|c| c.started = c.started.saturating_add(1));
    }

    fn drop_run(&mut self, run: EarlyRun) {
        run.task.stop();
        self.dropped.push(run.task);
        self.count(|c| c.discarded = c.discarded.saturating_add(1));
    }

    /// The ids of the runs that `calls` (the finished reply) hold byte for byte, by index.
    fn ids(&self, calls: &[ToolCallRequest]) -> BTreeMap<usize, CallId> {
        let held = self.runs.iter().filter(|(i, r)| calls.get(**i).is_some_and(|c| r.holds(c)));
        held.map(|(i, r)| (*i, r.ctx.call_id.clone())).collect()
    }

    /// The reply is in, with its final ids: drop the runs it does not hold as they were started, or
    /// that follow a call of a tool that may not start early, then start the complete calls of its
    /// leading run of tools that may that were not started early, so that they run together.
    fn settle(&mut self, calls: &[ToolCallRequest]) {
        let head = calls.iter().take_while(|c| self.may_start(&c.name)).count();
        let stale: Vec<usize> = self
            .runs
            .iter()
            .filter(|(i, r)| **i >= head || !calls.get(**i).is_some_and(|c| r.holds(c) && c.call_id == r.ctx.call_id))
            .map(|(i, _)| *i)
            .collect();
        for i in stale {
            if let Some(run) = self.runs.remove(&i) {
                self.drop_run(run);
            }
        }
        if !self.on {
            return;
        }
        for (i, c) in calls.iter().enumerate().take(head) {
            if c.complete && !self.tried.contains(&i) {
                self.start(i, &c.name, &c.arguments, Some(&c.call_id));
            }
        }
    }

    /// The run of call `index` of the reply, when it was started for exactly that call.
    fn claim(&mut self, index: usize, call: &ToolCallRequest) -> Option<EarlyRun> {
        let held = self.runs.get(&index).is_some_and(|r| r.holds(call) && r.ctx.call_id == call.call_id);
        if held {
            self.runs.remove(&index)
        } else {
            None
        }
    }

    /// Cancel and forget every run left, and wait until none of their tasks is running.
    async fn discard(mut self) {
        for run in std::mem::take(&mut self.runs).into_values() {
            self.drop_run(run);
        }
        for mut task in std::mem::take(&mut self.dropped) {
            // Aborted: it ends at its next await, if it had not ended already.
            let _ = (&mut task.handle).await;
        }
    }
}

/// A call id of the session's own.
fn fresh_call_id() -> CallId {
    CallId::from(format!("call-{}", new_request_id().trim_start_matches("r-")))
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// A moment on the step's clock and on the wall clock (ms since the Unix epoch).
type Moment = (tokio::time::Instant, u64);

/// What the stream events of one model request say about the server being unavailable (see *Model
/// server unavailable*).
struct Outage {
    /// `agents.unavailable_notice_s`; zero turns the notice off.
    after: Duration,
    /// The client's retry window; `None` retries until the server answers.
    window: Option<Duration>,
    /// The request's first failed attempt (about when the client's retry window starts).
    first: Option<Moment>,
    /// The first failure of the current outage: the request's first, or the first after an attempt
    /// the server answered for at least `after`.
    since: Option<Moment>,
    /// When the server began answering since the latest failure (or since the request began); `None`
    /// while the request is retrying.
    answering: Option<tokio::time::Instant>,
    /// Why the latest attempt failed.
    last: String,
}

impl Outage {
    fn new(after: Duration, window: Option<Duration>) -> Outage {
        Outage { after, window, first: None, since: None, answering: None, last: String::new() }
    }

    fn on_event(&mut self, event: &StreamEvent) {
        match event {
            StreamEvent::Retrying { reason, .. } => {
                let now: Moment = (tokio::time::Instant::now(), now_ms());
                self.first.get_or_insert(now);
                // A server that answered for that long was not unavailable: this failure starts a new
                // outage.
                if self.answering.take().is_some_and(|began| now.0.saturating_duration_since(began) >= self.after) {
                    self.since = None;
                }
                self.since.get_or_insert(now);
                self.last.clone_from(reason);
            }
            StreamEvent::AttemptStart { .. } => {}
            // Everything else came from the server: it is answering.
            _ => {
                self.answering.get_or_insert_with(tokio::time::Instant::now);
            }
        }
    }

    /// When the notice is due: `after` past the outage's first failure, while the request is retrying
    /// (a deadline that passed while the server was answering briefly is due at the next failure).
    /// `None` when it is not retrying, when `after` is zero (the notice is off), and when the retry
    /// window has ended by then: the request fails at its next failed attempt and is handled as any
    /// failed request.
    fn due(&self) -> Option<tokio::time::Instant> {
        if self.after.is_zero() || self.answering.is_some() {
            return None;
        }
        let at = self.since?.0.checked_add(self.after)?;
        if let (Some(window), Some((first, _))) = (self.window, self.first) {
            if first.checked_add(window).is_some_and(|end| at >= end) {
                return None;
            }
        }
        Some(at)
    }
}

/// Whether `item` is a model-unavailable notice: the harness opens no other non-blocking `Blocker`
/// item, and every item a tool opens carries its call's id.
fn is_unavailable_notice(item: &InboxItem) -> bool {
    item.kind == InboxKind::Blocker && !item.blocking && item.call_id.is_none()
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
    /// Replies in a row that made no progress: nudged by the gate, cut off by the output limit with
    /// no complete call, or with only malformed calls.
    nudges: u32,
    phase: Phase,
    st: State,
    published: Option<Status>,
    line_counts: LineCounts,
    /// Weaves computed so far (see `woven`).
    #[cfg(test)]
    weaves: u32,
    early_counts: Arc<Mutex<EarlyCounts>>,
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

/// The trigger and the floor of a re-weave (see the module contract): `policy`'s, lowered for a
/// known `window` so that a request at the trigger leaves room for the reply. That room is
/// `max_output` plus 4_096, or 20_480 without one. What the harness chooses itself (the 4_096, the
/// 20_480) is at most a quarter of the window, so that a small window keeps a positive trigger and
/// floor. A `max_output` below the window is never cut, since every request asks for that much as
/// `max_tokens`: the 4_096 after it shrinks to what the window has left (`window − max − 1`), so
/// the trigger can drop to 1 and the floor to 0. A `max_output` at or above the window cannot be
/// honoured and counts as none. From a window of 81_920 tokens up the quarter of the window cuts
/// nothing.
fn reweave_bounds(policy: &ReweavePolicy, window: Option<u64>, max_output: Option<u64>) -> (u64, u64) {
    let (mut limit, mut floor) = (policy.target_tokens, policy.floor_tokens);
    if let Some(window) = window {
        let slack = 4_096_u64.min(window / 4);
        // A reply length the window cannot hold counts as none; one it can hold is kept, with the slack
        // shrunk to what is left, because `step` sends it as max_tokens.
        let reserve = match max_output {
            Some(max) if max < window => max + slack.min(window - max - 1),
            _ => 20_480_u64.min(window / 4),
        };
        // The trigger stays within four fifths of the window and the floor within half of it, so
        // that a small window can always be planned for.
        limit = limit.min(window.saturating_sub(reserve)).min(window / 5 * 4);
        floor = floor.min(window / 2);
        if floor >= limit {
            floor = limit / 2;
        }
    }
    (limit, floor)
}

/// `x × num / den`: a token count carried from units where a request measures `den` into units where
/// it measures `num`.
fn scaled(x: u64, num: u64, den: u64) -> u64 {
    let v = u128::from(x).saturating_mul(u128::from(num)) / u128::from(den.max(1));
    u64::try_from(v).unwrap_or(u64::MAX)
}

/// The lines of running jobs' output files, counted on from where the previous count stopped, so
/// that each request reads only what a file gained since the one before.
#[derive(Default)]
struct LineCounts {
    files: HashMap<String, Counted>,
    /// Bytes read so far, over all files.
    #[cfg(test)]
    read: u64,
}

/// How far one file has been counted.
#[derive(Clone, Copy, Default)]
struct Counted {
    bytes: u64,
    newlines: u64,
    last: Option<u8>,
}

impl LineCounts {
    /// The lines of job `job`'s output file at `path` so far (a final line without a newline
    /// counts). A file that shrank is counted again from its start; a file that is gone counts 0.
    fn count(&mut self, job: &str, path: &Path) -> u64 {
        use std::io::{Read, Seek, SeekFrom};
        let Ok(mut file) = std::fs::File::open(path) else {
            self.files.remove(job);
            return 0;
        };
        let len = file.metadata().map(|m| m.len()).unwrap_or(0);
        let mut c = self.files.get(job).copied().filter(|c| c.bytes <= len).unwrap_or_default();
        if c.bytes > 0 && file.seek(SeekFrom::Start(c.bytes)).is_err() {
            c = Counted::default();
        }
        // Nothing new: nothing to read.
        let mut buf = if c.bytes < len { vec![0u8; 64 * 1024] } else { Vec::new() };
        while !buf.is_empty() {
            match file.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let chunk = buf.get(..n).unwrap_or_default();
                    c.newlines = c.newlines.saturating_add(chunk.iter().filter(|b| **b == b'\n').count() as u64);
                    c.last = chunk.last().copied();
                    c.bytes = c.bytes.saturating_add(n as u64);
                    #[cfg(test)]
                    {
                        self.read = self.read.saturating_add(n as u64);
                    }
                }
            }
        }
        self.files.insert(job.to_string(), c);
        c.newlines.saturating_add(u64::from(c.last.is_some_and(|b| b != b'\n')))
    }

    /// Forget the files of jobs that are no longer running.
    fn retain(&mut self, running: &[JobInfo]) {
        self.files.retain(|id, _| running.iter().any(|j| &j.id == id));
    }
}

/// A turn the operator starts after the session's budget ran out comes with a fresh budget.
fn renews_budget(trigger: Trigger, last_end: Option<TurnEndReason>) -> bool {
    matches!(trigger, Trigger::User | Trigger::InboxAnswer | Trigger::Resume)
        && last_end == Some(TurnEndReason::BudgetExhausted)
}

fn delivery(outcome: ChildOutcome, report: String) -> Delivery {
    Delivery { outcome, report, full: None, payload: Value::Null }
}

/// A job of the harness process that ran before this one, as `open` settles it.
struct LeftJob {
    job_id: String,
    command: String,
    /// The call whose result gave the job to the model, when its registration never reached the log.
    unregistered: Option<CallId>,
    /// An own `Interrupted` note after its registration (or the result that gave it to the model) told
    /// the model that the jobs from before it are gone: when it is lost, it is settled without a note.
    told: bool,
}

/// The job ends among the own records `own` that the model was told of (a `job_settled` and the
/// arrival note right after it) since the last turn ended, with no turn started after them. Each
/// would have started a turn had the session been waiting; a restart owes it that turn.
fn pending_job_ends_in(own: &[Record]) -> usize {
    let last = own.iter().rposition(|r| matches!(r.event, Event::TurnStart { .. } | Event::TurnEnd { .. }));
    if last.is_some_and(|i| own.get(i).is_some_and(|r| matches!(r.event, Event::TurnStart { .. }))) {
        return 0;
    }
    let since = own.get(last.map_or(0, |i| i.saturating_add(1))..).unwrap_or_default();
    since
        .windows(2)
        .filter(|w| match w {
            [settled, note] => {
                matches!(settled.event, Event::JobSettled { .. })
                    && note.author == Author::Harness
                    && matches!(note.event, Event::HarnessNote { note: NoteKind::Arrival, .. })
            }
            _ => false,
        })
        .count()
}

/// Whether the next start has a job to tell the session `own` (its own records) about: a job
/// registered and never settled (it belonged to a harness process that is gone), or a job end it was
/// told of that no turn has followed ([`pending_job_ends_in`]).
pub(crate) fn has_job_news(own: &[Record]) -> bool {
    let settled: HashSet<&str> = own
        .iter()
        .filter_map(|r| match &r.event {
            Event::JobSettled { job_id, .. } => Some(job_id.as_str()),
            _ => None,
        })
        .collect();
    own.iter().any(|r| matches!(&r.event, Event::JobRegistered { job_id, .. } if !settled.contains(job_id.as_str())))
        || pending_job_ends_in(own) > 0
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
            line_counts: LineCounts::default(),
            #[cfg(test)]
            weaves: 0,
            early_counts: Arc::default(),
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
        let (log, records) = fork_file(parent_log, &path, upto_seq, Durability::Always).map_err(|e| e.to_string())?;
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
        let mut session = Session::bare(deps, log, report.records, registry);
        session.deps.shared.take_continuation();
        // A durable plan is an audit artifact, never a restart queue: the last dispatch may
        // have taken effect without a receipt. Reconcile it through a real actor callback.
        let pending: Vec<String> = session
            .own()
            .iter()
            .filter_map(|r| match &r.event {
                Event::ContinuationPlanned { plan_id, .. }
                    if !session.own().iter().any(
                        |r| matches!(&r.event, Event::ContinuationStopped { plan_id: ended, .. } if ended == plan_id),
                    ) =>
                {
                    Some(plan_id.clone())
                }
                _ => None,
            })
            .collect();
        for id in pending {
            session.stop_continuation(id, "harness restarted; stored actions were not replayed").map_err(|e| e.0)?;
        }
        if let Some(damage) = &report.damage {
            let reason =
                format!("the session log was damaged and was cut back to its last good record ({})", damage.detail);
            session.append(Author::Harness, Event::Interrupted { reason }).map_err(|e| e.0)?;
        }
        if session.has_open_turn() {
            session
                .append(Author::Harness, Event::Interrupted { reason: texts::REASON_RESTART.to_string() })
                .map_err(|e| e.0)?;
            session.append(Author::Harness, Event::TurnEnd { reason: TurnEndReason::Stopped }).map_err(|e| e.0)?;
        }
        session.record_left_jobs()?;
        // After the jobs above are registered: an id they were given is not handed out again either.
        let top = session
            .records
            .iter()
            .filter_map(|r| match &r.event {
                Event::JobRegistered { job_id, .. } => job_id.strip_prefix('j').and_then(|n| n.parse::<u64>().ok()),
                _ => None,
            })
            .max();
        if let Some(n) = top {
            // `resume_from` only takes a lock; it never waits.
            let _ = session.deps.ctx.jobs.resume_from(n).now_or_never();
        }
        session.seed_guard().map_err(|e| e.0)?;
        Ok(session)
    }

    /// Prime the prefix guard with the stable messages of the last request in the log, as they render
    /// now (the weave is a function of the log), so that the first request after a restart is checked
    /// like any other. When they no longer match the hash stored with that request (an upgrade changed
    /// the rendering), the server's cache of the session is lost: one `cache_break` says so.
    fn seed_guard(&mut self) -> R<()> {
        if self.st.ended.is_some() {
            return Ok(());
        }
        let Some(at) = self.records.iter().rposition(|r| matches!(r.event, Event::ModelRequest(_))) else {
            return Ok(());
        };
        let Some(Event::ModelRequest(sent)) = self.records.get(at).map(|r| r.event.clone()) else { return Ok(()) };
        let messages = weave(self.records.get(..=at).unwrap_or_default()).messages;
        self.guard.prime(sent.epoch, &messages);
        // Reported by an earlier open, with no request since.
        let reported = self.records.iter().skip(at).any(|r| matches!(r.event, Event::CacheBreak { .. }));
        if stable_hash(&messages) != sent.stable_hash && !reported {
            let detail = texts::rendering_changed(sent.n_messages, messages.len());
            self.append(Author::Harness, Event::CacheBreak { req_id: sent.req_id, first_diff_message: 0, detail })?;
        }
        Ok(())
    }

    /// Job ends the model was told of since the last turn ended, with no turn started after them
    /// ([`pending_job_ends_in`]): `open` records those of an earlier harness process, and a shutdown
    /// those of the jobs it killed while the session was idle. Each would have started a turn for a
    /// session that was waiting.
    pub fn pending_job_ends(&self) -> usize {
        pending_job_ends_in(self.own())
    }

    /// The jobs of the harness process that ran before this one (see the module contract, `open`):
    /// each is settled with what it left and the model is told, so that a session waiting on it wakes
    /// knowing. Then the files that process's jobs left are removed (but for those of a job whose
    /// output could not be stored, which the settlement names).
    fn record_left_jobs(&mut self) -> Result<(), String> {
        let jobs = self.deps.ctx.jobs.clone();
        let mut taken: Vec<String> = jobs.leftovers().iter().map(|l| l.id.clone()).collect();
        if self.st.ended.is_none() {
            for left in self.left_jobs() {
                let id = left.job_id.clone();
                if !self.record_left_job(left).map_err(|e| e.0)? {
                    taken.retain(|t| *t != id);
                } else if !taken.contains(&id) {
                    taken.push(id);
                }
            }
        }
        for id in &taken {
            jobs.discard(id);
        }
        Ok(())
    }

    /// The jobs `open` settles, in log order: every own `job_registered` with no `job_settled`, then
    /// every job an own result gave the model whose registration never reached the log (the harness
    /// went down first, whether the sweep found its command or its watcher had already ended it). A
    /// command the sweep found that no result names was a foreground one whose call the restart cut:
    /// the weave shows that call without a result.
    fn left_jobs(&self) -> Vec<LeftJob> {
        let own = self.own();
        let mut settled: HashSet<&str> = HashSet::new();
        let mut registered: HashSet<&str> = HashSet::new();
        for r in own {
            match &r.event {
                Event::JobSettled { job_id, .. } => settled.insert(job_id.as_str()),
                Event::JobRegistered { job_id, .. } => registered.insert(job_id.as_str()),
                _ => false,
            };
        }
        let told = own.iter().rposition(|r| matches!(r.event, Event::HarnessNote { note: NoteKind::Interrupted, .. }));
        let mut left: Vec<LeftJob> = own
            .iter()
            .enumerate()
            .filter_map(|(i, r)| match &r.event {
                Event::JobRegistered { job_id, command, .. } if !settled.contains(job_id.as_str()) => Some(LeftJob {
                    job_id: job_id.clone(),
                    command: command.clone(),
                    unregistered: None,
                    told: told.is_some_and(|t| i < t),
                }),
                _ => None,
            })
            .collect();
        for (i, r) in own.iter().enumerate() {
            let Event::ToolResult(t) = &r.event else { continue };
            let Some(id) = t.meta.get(META_JOB).and_then(Value::as_str) else { continue };
            if registered.contains(id) || settled.contains(id) || left.iter().any(|l| l.job_id == id) {
                continue;
            }
            let command = own
                .iter()
                .find_map(|r| match &r.event {
                    Event::ToolCall(c) if c.call_id == t.call_id => {
                        c.args.get("command").and_then(Value::as_str).map(str::to_string)
                    }
                    _ => None,
                })
                .unwrap_or_default();
            let unregistered = Some(t.call_id.clone());
            left.push(LeftJob { job_id: id.to_string(), command, unregistered, told: told.is_some_and(|n| i < n) });
        }
        left
    }

    /// Settle one job of an earlier harness process: with its exit status and output when it ended by
    /// itself while no harness watched it (the note says so), else as lost (no note when the model was
    /// told already). A job whose registration never reached the log is registered first. False when
    /// its output could not be stored, so that its files stay where the settlement says they are.
    fn record_left_job(&mut self, left: LeftJob) -> R<bool> {
        let LeftJob { job_id, command, unregistered, told } = left;
        if let Some(call_id) = unregistered {
            let event = Event::JobRegistered { job_id: job_id.clone(), call_id, command: command.clone() };
            self.append(Author::Harness, event)?;
        }
        let Some(end) = self.deps.ctx.jobs.ended_while_down(&job_id) else {
            let detail = texts::JOB_LOST_DETAIL.to_string();
            self.append(
                Author::Tool,
                Event::JobSettled { job_id: job_id.clone(), exit_code: None, output: None, detail },
            )?;
            if !told {
                self.note(Author::Harness, NoteKind::Arrival, texts::job_lost(&job_id, &command))?;
            }
            return Ok(true);
        };
        let detail = texts::job_ended_while_down(&end.detail);
        let stored = end.output.is_some();
        let settled = Event::JobSettled {
            job_id: job_id.clone(),
            exit_code: Some(end.exit_code),
            output: end.output.clone(),
            detail: detail.clone(),
        };
        self.append(Author::Tool, settled)?;
        if !self.end_shown(&job_id) {
            let text =
                self.job_note(&job_id, &command, &Ended::Exit(end.exit_code).outcome(), &detail, end.output.as_ref());
            self.note(Author::Harness, NoteKind::Arrival, text)?;
        }
        Ok(stored)
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
        if let Event::ChildSettled(receipt) = &event {
            if let Some(record) = self
                .own()
                .iter()
                .find(|r| matches!(&r.event, Event::ChildSettled(previous) if previous.child == receipt.child))
            {
                return Ok(record.seq);
            }
        }
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
        self.resolve_stale_notices()?;
        self.publish();
        for input in self.kept_inputs() {
            self.arrival(input).await?;
        }
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
                Ev::Input(Some(Input::Stop)) if self.deps.shared.is_child() => {
                    return Ok(End::Settled(self.stop_idle_child(texts::REASON_PARENT).await?));
                }
                // Closed for good (the session was archived, or its runtime let go of it): a child
                // settles, or its parent would wait for it for ever. A shutdown closes the inputs too,
                // but it cuts the child for the next start to resume, so nothing is settled then.
                Ev::Input(None) if self.deps.shared.is_child() && !self.deps.control.is_shutting() => {
                    return Ok(End::Settled(self.stop_idle_child(texts::REASON_OPERATOR).await?));
                }
                Ev::Input(None) => {
                    // Between turns no `interrupted` note goes with the jobs a shutdown stops: their ends say why.
                    let why = if self.deps.control.is_shutting() { texts::JOB_SHUTDOWN_DETAIL } else { "" };
                    self.deps.ctx.capabilities.ptys.close_all().await;
                    self.deps.ctx.jobs.kill_all_because(self.grace(), why).await;
                    // Nothing reads the job events after this task: what the jobs reported (killed just
                    // now, or ended before) is recorded now, or the next `open` would take them for lost.
                    while let Ok(event) = self.deps.job_events.try_recv() {
                        self.on_job_event(event).await?;
                    }
                    return Ok(End::Closed);
                }
                Ev::Input(Some(input)) => self.idle_input(input).await?,
                Ev::Job(Some(event)) => self.on_job_event(event).await?,
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
                let woven = self.woven();
                self.reweave(&woven, "operator", true, &token, None).await?;
                Ok(None)
            }
            Input::Stop => {
                let jobs = !self.running_jobs().await.is_empty();
                let children = !self.running_children().await.is_empty();
                self.deps.ctx.capabilities.ptys.close_all().await;
                self.deps.ctx.jobs.kill_all(self.grace()).await;
                self.deps.shared.orch.stop_children(&self.deps.shared.session).await;
                // Stopped stays stopped: what the stop itself causes (a child's settlement, a job's end)
                // must not wake a session that was waiting, only the operator can. The `interrupted`
                // record goes with the `Stopped` end, so the next turn's note names this stop.
                let wakeable = matches!(self.st.last_end, Some(TurnEndReason::Waiting | TurnEndReason::Yielded));
                if jobs || children || wakeable {
                    self.append(Author::Harness, Event::Interrupted { reason: texts::REASON_OPERATOR.to_string() })?;
                }
                if wakeable {
                    self.append(Author::Harness, Event::TurnEnd { reason: TurnEndReason::Stopped })?;
                    self.publish();
                }
                Ok(None)
            }
            other => Ok(self.arrival(other).await?.trigger),
        }
    }

    /// A child that is between turns was stopped, or its inputs closed: end its jobs and children and
    /// settle it `Stopped`, so that its parent is not left waiting for it. `reason` says who stopped it.
    async fn stop_idle_child(&mut self, reason: &str) -> R<Settlement> {
        self.append(Author::Harness, Event::Interrupted { reason: reason.to_string() })?;
        self.deps.ctx.capabilities.ptys.close_all().await;
        self.deps.ctx.jobs.kill_all(self.grace()).await;
        self.deps.shared.orch.stop_children(&self.deps.shared.session).await;
        self.settle(delivery(ChildOutcome::Stopped, texts::stopped_report(self.st.step))).await
    }

    /// The operator inputs left on disk by a harness that stopped before this session recorded them
    /// (see [`queue_input`]), in the order they were handed over. A file left while it was being
    /// recorded is deleted instead when its recording reached the log (see [`Session::recorded_from`]).
    /// A file that cannot be read is left where it is.
    fn kept_inputs(&self) -> Vec<Input> {
        let dir = queue_dir(&self.deps.paths, &self.deps.shared.session);
        let Ok(entries) = std::fs::read_dir(&dir) else { return Vec::new() };
        let mut files: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "json" || x == "taking"))
            .collect();
        // `{stem}.json` and `{stem}.{seq}.taking` sort by their stems, which sort by time.
        files.sort();
        files
            .into_iter()
            .filter_map(|file| {
                if taking_seq(&file).is_some_and(|seq| self.recorded_from(seq)) {
                    if let Err(e) = std::fs::remove_file(&file) {
                        tracing::warn!(session = %self.deps.shared.session, "queued input {} not deleted: {e}", file.display());
                    }
                    return None;
                }
                let kept = std::fs::read(&file).ok().and_then(|b| serde_json::from_slice::<KeptInput>(&b).ok());
                if kept.is_none() {
                    tracing::warn!(session = %self.deps.shared.session, "unreadable queued input {}", file.display());
                }
                kept.map(|k| Input::Queued { file, input: Box::new(k.into_input()) })
            })
            .collect()
    }

    /// Whether the record at `seq` begins an operator input's recording: the operator's ledger entry
    /// or note, which [`Session::record_input`] appends first. A file renamed for recording names
    /// that seq ([`taking_path`]), and nothing else writes such a record there after the rename.
    fn recorded_from(&self, seq: Seq) -> bool {
        let at = self.records.binary_search_by_key(&seq, |r| r.seq).ok().and_then(|i| self.records.get(i));
        at.is_some_and(|r| {
            r.author == Author::User
                && matches!(
                    r.event,
                    Event::Ledger { .. } | Event::HarnessNote { note: NoteKind::Constraint | NoteKind::Approval, .. }
                )
        })
    }

    /// Record an input that is not a command. Whether it starts a turn is the caller's business. An
    /// input kept on disk is recorded as the input it holds, unless its file is gone (it was taken
    /// already, e.g. when the session started). Its file is first renamed to name the seq where its
    /// records start ([`taking_path`]), and deleted once it is recorded, so that a harness that stops
    /// in between records it once: see [`Session::kept_inputs`].
    async fn arrival(&mut self, input: Input) -> R<Arrival> {
        let Input::Queued { file, input } = input else { return self.record_input(input).await };
        let marker = taking_path(&file, self.log.next_seq());
        let held = match std::fs::rename(&file, &marker) {
            Ok(()) => marker,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Arrival::default()),
            Err(e) => {
                tracing::warn!(session = %self.deps.shared.session, "queued input {} not marked: {e}", file.display());
                file
            }
        };
        let out = self.record_input(*input).await?;
        if let Err(e) = std::fs::remove_file(&held) {
            tracing::warn!(session = %self.deps.shared.session, "queued input {} not deleted: {e}", held.display());
        }
        Ok(out)
    }

    /// [`Session::arrival`] for an input that is not kept on disk.
    async fn record_input(&mut self, input: Input) -> R<Arrival> {
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
                // Published now, not with the next turn: a restart in between reads status.json.
                self.publish();
                // A blank answer to an item that is not waiting for one dismisses it.
                let dismissed = answer.trim().is_empty() && !item.blocking;
                let asked = matches!(item.kind, InboxKind::Question | InboxKind::Blocker);
                if let (Some(reference), true, true) = (&item.reference, asked, self.deps.shared.journal.is_some()) {
                    let answer = if dismissed { texts::DISMISSED_ANSWER.to_string() } else { answer.clone() };
                    let op = LedgerOp::QuestionAnswer { id: reference.clone(), answer };
                    if let Err(e) = self.deps.shared.ledger_append(true, op) {
                        tracing::warn!(session = %self.deps.shared.session, "answer not recorded in the ledger: {e}");
                    }
                    self.flush_emitted()?;
                }
                if dismissed {
                    if asked {
                        self.note(Author::Harness, NoteKind::Arrival, texts::question_dismissed(&item.text))?;
                    }
                    return Ok(out);
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
            Input::Scope { hosts, note } => {
                if hosts.is_empty() {
                    return Ok(out);
                }
                self.operator_op(LedgerOp::ScopeGrant { hosts: hosts.clone(), note: note.clone() })?;
                self.note(Author::User, NoteKind::Approval, texts::scope_granted(&hosts, note.as_deref()))?;
            }
            Input::Release { reason } => {
                if reason.trim().is_empty() {
                    return Ok(out);
                }
                // The operator ends the work short of the goal. The finish gate stops blocking (it
                // reads the ledger release); no turn is started, and the session is not forced to stop.
                self.operator_op(LedgerOp::OperatorRelease { reason: reason.clone() })?;
                self.note(Author::User, NoteKind::Approval, texts::released(&reason))?;
            }
            Input::ChildSettled(s) => {
                let child = s.child.clone();
                if self
                    .own()
                    .iter()
                    .any(|record| matches!(&record.event, Event::ChildSettled(receipt) if receipt.child == child))
                {
                    return Ok(out);
                }
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
            Input::Resume | Input::Reweave | Input::Stop | Input::Queued { .. } => {}
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
    /// Record a job event. `Some`: the turn it starts when the session is idle.
    async fn on_job_event(&mut self, event: JobEvent) -> R<Option<Trigger>> {
        let asleep = matches!(self.st.last_end, Some(TurnEndReason::Waiting | TurnEndReason::Yielded));
        match event {
            JobEvent::Registered(info) => {
                self.append(
                    Author::Harness,
                    Event::JobRegistered { job_id: info.id, call_id: info.call_id, command: info.command },
                )?;
                Ok(None)
            }
            JobEvent::Matched(m) => {
                self.append(
                    Author::Tool,
                    Event::JobMatched {
                        job_id: m.info.id.clone(),
                        pattern: m.pattern.clone(),
                        output: m.output.clone(),
                        from: m.from,
                        shown: m.lines.iter().map(|(n, _)| *n).collect(),
                        matches: m.matches,
                    },
                )?;
                let handle = m.output.as_ref().map(BlobRef::handle);
                let text = texts::job_matched(&texts::JobMatchNote {
                    id: &m.info.id,
                    command: &m.info.command,
                    pattern: &m.pattern,
                    running: m.running,
                    handle: handle.as_deref(),
                    part_lines: m.output.as_ref().map_or(0, |b| b.lines),
                    from: m.from,
                    lines: &m.lines,
                    matches: m.matches,
                    last: m.last,
                });
                self.note(Author::Harness, NoteKind::Arrival, text)?;
                Ok(asleep.then_some(Trigger::JobOutput))
            }
            JobEvent::Settled { info, output, detail } => {
                let exit_code = match &info.state {
                    JobState::Ended(Ended::Exit(n)) => Some(*n),
                    _ => None,
                };
                self.append(
                    Author::Tool,
                    Event::JobSettled {
                        job_id: info.id.clone(),
                        exit_code,
                        output: output.clone(),
                        detail: detail.clone(),
                    },
                )?;
                if self.end_shown(&info.id) {
                    return Ok(None);
                }
                let text = self.job_note(&info.id, &info.command, &info.state.outcome(), &detail, output.as_ref());
                self.note(Author::Harness, NoteKind::Arrival, text)?;
                Ok(asleep.then_some(Trigger::JobSettled))
            }
        }
    }

    /// Whether the model has been shown how job `id` ended: an own result names the job and carries
    /// its exit code or signal.
    fn end_shown(&self, id: &str) -> bool {
        self.own().iter().any(|r| match &r.event {
            Event::ToolResult(t) => {
                t.meta.get(META_JOB).and_then(Value::as_str) == Some(id)
                    && (t.meta.contains_key(META_EXIT_CODE) || t.meta.contains_key(META_SIGNAL))
            }
            _ => false,
        })
    }

    /// The arrival note of a job that ended, with the last lines of its stored output.
    fn job_note(&self, id: &str, command: &str, outcome: &str, detail: &str, output: Option<&BlobRef>) -> String {
        let (handle, lines, tail) = match output {
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
        texts::job_arrival(id, command, outcome, detail, handle.as_deref(), lines, &tail)
    }

    // ---- a turn --------------------------------------------------------------------------------

    /// Run one turn. `Some` when it settled the (child) session.
    async fn turn(&mut self, trigger: Trigger) -> R<Option<Settlement>> {
        self.token = self.deps.control.begin_turn();
        self.nudges = 0;
        let renewed = renews_budget(trigger, self.st.last_end);
        self.append(Author::Harness, Event::TurnStart { trigger })?;
        self.clock_set(true)?;
        // A turn that starts while the harness is going down is cut at once (its token is cancelled
        // from birth): the note belongs to the first turn after the restart.
        if self.st.last_end == Some(TurnEndReason::Stopped) && !self.deps.control.is_shutting() {
            let restarted = self
                .st
                .last_interrupted
                .as_deref()
                .is_some_and(|r| r == texts::REASON_RESTART || r.starts_with("the session log was damaged"));
            let text = if restarted {
                texts::AFTER_RESTART
            } else if self.st.stopped_idle {
                texts::AFTER_IDLE_STOP
            } else {
                texts::AFTER_STOP
            };
            self.note(Author::Harness, NoteKind::Interrupted, text.to_string())?;
        }
        if renewed {
            let text = texts::budget_renewed(self.st.budget.max_steps, self.st.budget.max_minutes);
            self.note(Author::Harness, NoteKind::Info, text)?;
        }
        self.phase = Phase::Running;
        self.publish();
        let flow = loop {
            match self.step().await? {
                Flow::Next => {}
                other => break other,
            }
        };
        let c = *self.early_counts.lock().unwrap_or_else(|p| p.into_inner());
        tracing::debug!(session = %self.deps.shared.session, started = c.started, claimed = c.claimed,
            discarded = c.discarded, saved_ms = c.saved_ms, "calls started early, over the session");
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
        self.discard_continuation("the turn ended before the queued plan completed")?;
        self.append(Author::Harness, Event::TurnEnd { reason })?;
        if self.deps.control.is_shutting() {
            // The published status stays `running`, which is what makes the next start restore the session.
            return Ok(());
        }
        self.phase = Phase::Idle;
        self.publish();
        Ok(())
    }

    /// Sync the complete settlement before ending the child or returning it to the parent.
    async fn settle(&mut self, d: Delivery) -> R<Settlement> {
        self.discard_continuation("the child settled before the queued plan completed")?;
        let (reason, outcome) = match d.outcome {
            ChildOutcome::Returned | ChildOutcome::Blocked => {
                let r =
                    if d.outcome == ChildOutcome::Returned { TurnEndReason::Finished } else { TurnEndReason::Blocked };
                (r, SessionOutcome::Done)
            }
            ChildOutcome::BudgetExhausted => (TurnEndReason::BudgetExhausted, SessionOutcome::BudgetExhausted),
            ChildOutcome::Stopped => (TurnEndReason::Stopped, SessionOutcome::Stopped),
            ChildOutcome::Failed => (TurnEndReason::Error, SessionOutcome::Failed),
        };
        let settlement = Settlement {
            child: self.deps.shared.session.clone(),
            role: self.deps.shared.role.name.clone(),
            outcome: d.outcome,
            report: d.report,
            full: d.full,
            payload: d.payload,
            steps: self.st.step,
            usage: self.st.usage,
        };
        self.append(
            Author::Harness,
            Event::ChildCompleted(ChildCompleted {
                child: settlement.child.clone(),
                role: settlement.role.clone(),
                outcome: settlement.outcome,
                report: settlement.report.clone(),
                full: settlement.full.clone(),
                payload: settlement.payload.clone(),
                steps: settlement.steps,
                usage: settlement.usage,
            }),
        )?;
        let detail: String = settlement.report.lines().next().unwrap_or("").chars().take(DETAIL_CHARS).collect();
        self.append(Author::Harness, Event::TurnEnd { reason })?;
        self.append(Author::Harness, Event::SessionEnd { outcome, detail })?;
        self.deps.ctx.capabilities.ptys.close_all().await;
        self.deps.ctx.jobs.kill_all(self.grace()).await;
        self.phase = Phase::Ended;
        self.publish();
        Ok(settlement)
    }

    /// The turn's token fired: record it, stop what the session started, and end the turn (or settle
    /// the child as stopped).
    async fn cancelled(&mut self) -> R<Flow> {
        self.discard_continuation("the turn was cancelled; inspect effects before resuming")?;
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
        self.deps.ctx.capabilities.ptys.close_all().await;
        self.deps.ctx.jobs.kill_all(self.grace()).await;
        if shutting {
            // The inputs are closed behind a shutdown, so nothing would read these later: what the
            // jobs reported (started, killed just now) is recorded with the cut, and the next `open`
            // finds them settled instead of lost.
            while let Ok(event) = self.deps.job_events.try_recv() {
                self.on_job_event(event).await?;
            }
        }
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
        if self.deps.shared.is_child() {
            if let Err(error) = self.deps.shared.ledger() {
                return self.fail(&format!("The current mission state cannot be read: {error}"));
            }
        }
        let force = self.drain_arrivals().await?;
        if self.token.is_cancelled() {
            return self.cancelled().await;
        }
        if let Some(flow) = self.check_budget().await? {
            return Ok(flow);
        }
        if let Some(flow) = self.run_continuation(force).await? {
            return Ok(flow);
        }
        self.check_stall()?;
        let token = self.token.clone();
        // The weave of this step, rendered again only after a record that changes it.
        let mut woven = self.woven();
        let (reason, forced) = if force { ("operator", true) } else { ("target", false) };
        if self.reweave(&woven, reason, forced, &token, None).await? {
            woven = self.woven();
        }
        if token.is_cancelled() {
            return self.cancelled().await;
        }

        let mut overflowed = false;
        let (req_id, completion, queue_ms, tools, early, observed) = loop {
            let req_id = new_request_id();
            let w = &woven.weave;
            let observed = self.deferred_observations(&w.messages);
            if let PrefixCheck::Break { first_diff_message, detail } = self.guard.check(w.epoch, &w.messages) {
                self.append(Author::Harness, Event::CacheBreak { req_id: req_id.clone(), first_diff_message, detail })?;
            }
            let hud_text = self.render_hud().await;
            let hud_blob = self.deps.ctx.blobs.put_bytes(hud_text.as_bytes()).ok();
            let mut messages = w.messages.clone();
            messages.push(hud_message(&hud_text));
            let sent_chars = messages.iter().map(Message::chars).sum::<usize>().saturating_add(tools_chars(&w.tools));
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

            self.clock_set(false)?;
            let Some(permit) = self.deps.limiter.acquire(self.deps.priority, &token).await else {
                return self.cancelled().await;
            };
            self.clock_set(true)?;
            let request = ChatRequest {
                messages,
                tools: w.tools.clone(),
                tool_choice: ToolChoice::Auto,
                max_tokens: self.deps.client.profile().max_output_tokens,
                seed: None,
                extra: Map::new(),
            };
            let result = self.complete_streaming(&request, &req_id, &token).await?;
            let queue_ms = permit.waited_ms;
            drop(permit);
            match result {
                Ok((c, early)) => {
                    if c.usage.prompt_tokens > 0 {
                        self.estimator.calibrate(sent_chars, c.usage.prompt_tokens);
                    }
                    break (req_id, c, queue_ms, request.tools, early, observed);
                }
                Err(ModelError::Cancelled { .. }) => return self.cancelled().await,
                Err(ModelError::ContextOverflow { limit, .. }) => {
                    if !overflowed {
                        overflowed = true;
                        // What the server refused bounds its window, whatever the session was told.
                        let refused_at = Some(limit.unwrap_or(est_tokens));
                        if self.reweave(&woven, "overflow", true, &token, refused_at).await? {
                            woven = self.woven();
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

        let early_ids = early.ids(&completion.tool_calls);
        let completion = self.with_fresh_ids(completion, &early_ids);
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
        if !observed.is_empty() && !matches!(completion.finish, FinishReason::Error | FinishReason::Aborted) {
            self.append(Author::Harness, Event::OutputsObserved { req_id: req_id.clone(), calls: observed })?;
        }
        self.publish();
        self.handle_reply(&req_id, &completion, &tools, early).await
    }

    fn stop_continuation(&mut self, plan_id: String, reason: &str) -> R<()> {
        self.append(Author::Harness, Event::ContinuationStopped { plan_id: plan_id.clone(), reason: reason.into() })?;
        self.note(Author::Harness, NoteKind::Info, texts::continuation_stopped(&plan_id, reason))
    }

    fn discard_continuation(&mut self, reason: &str) -> R<()> {
        if let Some(plan) = self.deps.shared.take_continuation() {
            self.stop_continuation(plan.id, reason)?;
        }
        Ok(())
    }

    /// Only a verbatim native output included in a completed actor request becomes observed.
    fn deferred_observations(&self, messages: &[Message]) -> Vec<CallId> {
        let observed: HashSet<&CallId> = self
            .records
            .iter()
            .filter_map(|r| match &r.event {
                Event::OutputsObserved { calls, .. } => Some(calls.iter()),
                _ => None,
            })
            .flatten()
            .collect();
        self.records
            .iter()
            .filter_map(|r| match &r.event {
                Event::ToolResult(t)
                    if t.meta.get(META_DEFERRED_OBSERVATION).and_then(Value::as_bool) == Some(true)
                        && !observed.contains(&t.call_id)
                        && messages.iter().any(|m| {
                            m.role == loom_core::message::Role::Tool && m.origin.contains(&r.seq) && m.content == t.text
                        }) =>
                {
                    Some(t.call_id.clone())
                }
                _ => None,
            })
            .collect()
    }

    /// Stored actions use the same permission checks, admission and tool-result path as actor calls.
    /// No semantic decision, terminal action or generated argument is delegated to this controller.
    async fn run_continuation(&mut self, force: bool) -> R<Option<Flow>> {
        let Some(mut plan) = self.deps.shared.take_continuation() else { return Ok(None) };
        let started = Instant::now();
        let source = self
            .own()
            .iter()
            .find(|r| matches!(&r.event, Event::ToolCall(c) if c.call_id == plan.source_call))
            .map(|r| r.seq);
        let interrupted = source.is_none_or(|source| {
            self.own().iter().any(|r| {
                r.seq > source
                    && match &r.event {
                        Event::UserMessage { .. } | Event::InboxResolved { .. } | Event::ChildSettled(_) => true,
                        Event::HarnessNote { note, .. } => *note != NoteKind::Info,
                        Event::ToolCall(_) => r.author != Author::Harness,
                        _ => false,
                    }
            })
        });
        let guard = if force || interrupted {
            Err("New instructions, arrivals or another actor action require reconciliation.".into())
        } else if self.st.budget_note_step.is_some() {
            Err("The assignment budget requires an actor finalization step.".into())
        } else {
            crate::continuation::mission_hash(&self.deps.shared).and_then(|hash| plan.check(&self.deps.ctx, &hash))
        };
        if let Err(reason) = guard {
            self.stop_continuation(plan.id, &reason)?;
            return Ok(None);
        }
        let Some(node) = plan.next().cloned() else {
            self.stop_continuation(plan.id, "the literal plan is exhausted")?;
            return Ok(None);
        };
        if !self.deps.shared.role.tools.contains(&node.tool) || self.registry.get(&node.tool).is_none() {
            self.stop_continuation(plan.id, "the role no longer grants the stored native tool")?;
            return Ok(None);
        }
        if self.token.is_cancelled() {
            return self.cancelled().await.map(Some);
        }
        let req_id = new_request_id();
        let call = ToolCallRequest {
            call_id: CallId::from(format!("stored-{}", req_id)),
            name: node.tool,
            arguments: node.arguments,
            complete: true,
        };
        self.note(
            Author::Harness,
            NoteKind::Info,
            texts::continuation_dispatch(&plan.id, plan.cursor.saturating_add(1)),
        )?;
        self.append(
            Author::Harness,
            Event::StoredAction(StoredAction {
                plan_id: plan.id.clone(),
                source_call: plan.source_call.clone(),
                node: to_u32(plan.cursor.saturating_add(1)),
                omitted_callback: req_id.clone(),
                call: call.clone(),
                arguments_hash: node.arguments_hash,
                predecessor: plan.previous.as_ref().map(|p| p.call_id.clone()),
                file_guards: serde_json::to_value(&node.files).map_err(|e| Fatal(e.to_string()))?,
                guard_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
            }),
        )?;
        self.publish();
        let tools = self.registry.specs();
        let early = Early::new(
            false,
            self.registry.clone(),
            self.deps.ctx.clone(),
            &self.token,
            HashSet::new(),
            self.early_counts.clone(),
        );
        let calls =
            self.run_calls_as(&req_id, std::slice::from_ref(&call), &tools, Author::Harness, true, early).await?;
        if calls.cancelled {
            return self.cancelled().await.map(Some);
        }
        let result = self.own().iter().rev().find_map(|r| match &r.event {
            Event::ToolResult(result) if result.call_id == call.call_id => Some(result.clone()),
            _ => None,
        });
        if let Some(result) = result {
            plan.advance(&result);
            if plan.next().is_some() {
                self.deps.shared.set_continuation(plan);
            } else {
                self.stop_continuation(plan.id, "the literal plan is exhausted; inspect the native receipts")?;
            }
        } else {
            self.stop_continuation(
                plan.id,
                "the dispatch has no native receipt; reconcile effects before repeating it",
            )?;
        }
        Ok(Some(Flow::Next))
    }

    /// One request, with every stream event forwarded to the sink as it arrives, and the calls it
    /// started early (see *Early starts*). A failed request leaves none running.
    async fn complete_streaming(
        &mut self,
        request: &ChatRequest,
        req_id: &str,
        token: &CancellationToken,
    ) -> R<Result<(Completion, Early), ModelError>> {
        let sink = self.deps.sink.clone();
        let session = self.deps.shared.session.clone();
        let on = self.deps.ctx.cfg.speculate;
        let logged = if on { self.logged_call_ids() } else { HashSet::new() };
        let (registry, template, counts) = (self.registry.clone(), self.deps.ctx.clone(), self.early_counts.clone());
        let mut early = Early::new(on, registry, template, token, logged, counts);
        early.policy = CallPolicy { wrapup: self.st.budget_note_step.is_some() };
        let result = self
            .complete_watched(request, token, |event| {
                sink.delta(&session, req_id, event);
                early.on_event(event);
            })
            .await?;
        Ok(match result {
            Ok(c) => {
                early.reply_end = Some(Instant::now());
                Ok((c, early))
            }
            Err(e) => {
                early.discard().await;
                Err(e)
            }
        })
    }

    /// `client.complete` for one request of this session, with every stream event handed to
    /// `on_event` as it arrives. A request that keeps retrying is reported to the operator (see
    /// *Model server unavailable*); nothing about it changes the request.
    async fn complete_watched(
        &mut self,
        request: &ChatRequest,
        token: &CancellationToken,
        mut on_event: impl FnMut(&StreamEvent),
    ) -> R<Result<Completion, ModelError>> {
        let client = self.deps.client.clone();
        let after = Duration::from_secs(self.deps.agents.unavailable_notice_s);
        let window_s = client.profile().retry_window_s;
        let mut outage = Outage::new(after, (window_s > 0).then(|| Duration::from_secs(window_s)));
        let (tx, mut rx) = unbounded_channel();
        let call = client.complete(request, Some(&tx), token);
        tokio::pin!(call);
        // The notice opened during this request; at most one, whatever happens after it.
        let mut notice: Option<String> = None;
        let result = loop {
            let due = if notice.is_none() { outage.due() } else { None };
            tokio::select! {
                biased;
                r = &mut call => break r,
                Some(event) = rx.recv() => {
                    on_event(&event);
                    self.clock_event(&event)?;
                    outage.on_event(&event);
                }
                () = tokio::time::sleep_until(due.unwrap_or_else(tokio::time::Instant::now)), if due.is_some() => {
                    notice = Some(self.open_unavailable_notice(&outage)?);
                }
            }
        };
        while let Ok(event) = rx.try_recv() {
            on_event(&event);
            self.clock_event(&event)?;
        }
        self.clock_set(true)?;
        if let Some(item_id) = notice {
            let at = texts::clock(now_ms());
            let answer = match &result {
                Ok(_) => texts::unavailable_answered(&at),
                Err(ModelError::Cancelled { .. }) => texts::unavailable_stopped(&at),
                Err(e) => texts::unavailable_failed(&at, &e.to_string()),
            };
            self.resolve_notice(item_id, answer)?;
        }
        Ok(result)
    }

    /// Tell the operator that the model server has not answered a request of this session for
    /// `agents.unavailable_notice_s`: a non-blocking `Blocker` item (see [`is_unavailable_notice`]).
    /// Returns its id.
    fn open_unavailable_notice(&mut self, outage: &Outage) -> R<String> {
        let profile = self.deps.client.profile();
        let since = outage.since.map_or_else(now_ms, |(_, ms)| ms);
        // The client's window runs from the request's first failure.
        let first = outage.first.map_or(since, |(_, ms)| ms);
        let until = (profile.retry_window_s > 0)
            .then(|| texts::clock(first.saturating_add(profile.retry_window_s.saturating_mul(1000))));
        let text = texts::model_unavailable(&profile.base_url, &texts::clock(since), &outage.last, until.as_deref());
        tracing::warn!(session = %self.deps.shared.session, base_url = %profile.base_url, last = %outage.last,
            "the model server has been unavailable for a while; the operator is told");
        let item = InboxItem {
            item_id: new_item_id(),
            kind: InboxKind::Blocker,
            text,
            options: Vec::new(),
            blocking: false,
            call_id: None,
            reference: None,
        };
        let item_id = item.item_id.clone();
        self.append(Author::Harness, Event::InboxOpened(item))?;
        self.publish();
        Ok(item_id)
    }

    /// Resolve a model-unavailable notice in the operator's place.
    fn resolve_notice(&mut self, item_id: String, answer: String) -> R<()> {
        self.append(Author::Harness, Event::InboxResolved { item_id, answer })?;
        self.publish();
        Ok(())
    }

    /// Resolve the model-unavailable notices a session left open when it stopped during a request:
    /// none of its requests is retrying now.
    fn resolve_stale_notices(&mut self) -> R<()> {
        let stale: Vec<String> =
            self.st.inbox.iter().filter(|i| is_unavailable_notice(i)).map(|i| i.item_id.clone()).collect();
        for item_id in stale {
            self.resolve_notice(item_id, texts::UNAVAILABLE_LEFT_OPEN.to_string())?;
        }
        Ok(())
    }

    /// The call ids of this session's log.
    fn logged_call_ids(&self) -> HashSet<String> {
        self.records
            .iter()
            .filter_map(|r| match &r.event {
                Event::ToolCall(c) => Some(c.call_id.0.clone()),
                _ => None,
            })
            .collect()
    }

    /// Calls whose id is empty or already used in this log get a fresh one; a call started early
    /// keeps the id it was started with (`early`, by index) unless the log or an earlier call has it.
    fn with_fresh_ids(&self, mut completion: Completion, early: &BTreeMap<usize, CallId>) -> Completion {
        let mut used = self.logged_call_ids();
        for (i, call) in completion.tool_calls.iter_mut().enumerate() {
            match early.get(&i) {
                Some(id) if !used.contains(&id.0) => call.call_id = id.clone(),
                _ if call.call_id.0.is_empty() || used.contains(&call.call_id.0) => call.call_id = fresh_call_id(),
                _ => {}
            }
            used.insert(call.call_id.0.clone());
        }
        completion
    }

    async fn render_hud(&mut self) -> String {
        let running = self.running_jobs().await;
        self.line_counts.retain(&running);
        let jobs: Vec<HudJob> = running
            .into_iter()
            .map(|j| HudJob {
                lines: self.line_counts.count(&j.id, &j.out_path),
                id: j.id,
                command: j.command,
                started_ms: j.started_ms,
            })
            .collect();
        let shared = &self.deps.shared;
        let children: Vec<HudChild> = self
            .running_children()
            .await
            .into_iter()
            .map(|c| HudChild { id: c.id.to_string(), role: c.role, title: c.title, step: c.step })
            .collect();
        let (ledger, ledger_skipped) = if shared.journal.is_some() {
            match shared.ledger_with_skipped() {
                Ok((l, skipped)) => (Some(l), skipped),
                Err(e) => {
                    tracing::warn!(session = %shared.session, "ledger unreadable for the state block: {e}");
                    (None, 0)
                }
            }
        } else {
            (None, 0)
        };
        let budget = Budget {
            max_steps: self.st.budget.max_steps.filter(|n| *n > 0),
            max_minutes: self.st.budget.max_minutes.filter(|n| *n > 0),
        };
        let mut text = hud::render(&HudInput {
            now_ms: now_ms(),
            records: self.own(),
            ledger: ledger.as_ref(),
            ledger_skipped,
            brief: BriefOpts::default(),
            unviewed_min_lines: self.deps.agents.unviewed_min_lines,
            jobs: &jobs,
            children: &children,
            is_child: shared.is_child(),
            // Counted from where the budget was granted: a root's fresh budget starts at its turn.
            step: self.st.step.saturating_sub(self.st.budget_step_base),
            started_ms: self.st.clock.as_ref().map_or(self.st.budget_from_ms.unwrap_or(self.st.started_ms), |c| {
                now_ms().saturating_sub(c.elapsed(now_ms()))
            }),
            budget,
            finish_gated: shared.role.termination == loom_core::event::Termination::Explicit
                && shared.role.tools.iter().any(|t| t == "conclude"),
            solvable: shared.role.solvable,
        });
        if shared.is_child() {
            text.push_str(if shared.role.read_only {
                "\n\nMission ledger access: read-only. Return observations through your report or verdict."
            } else {
                "\n\nMission ledger access: notes and your own claims/evidence. Mission plans, approvals and shared obligations belong to the lead."
            });
        }
        text
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
                Input::Resume => {}
                // What was sent after the stop is for the idle loop, once this turn has ended `Stopped`.
                Input::Stop => {
                    self.token.cancel();
                    break;
                }
                other => {
                    if self.arrival(other).await?.user {
                        self.nudges = 0;
                    }
                }
            }
        }
        Ok(force)
    }

    fn clock_set(&mut self, running: bool) -> R<()> {
        if self.st.clock.as_ref().is_some_and(|c| c.running_from.is_some() == running) {
            return Ok(());
        }
        self.append(Author::Harness, Event::BudgetClock { running }).map(|_| ())
    }

    fn clock_event(&mut self, event: &StreamEvent) -> R<()> {
        match event {
            StreamEvent::Retrying { .. } => self.clock_set(false),
            StreamEvent::AttemptStart { .. } => Ok(()),
            _ => self.clock_set(true),
        }
    }

    fn exec_count(&self) -> u64 {
        let mut admitted: HashSet<&CallId> = HashSet::new();
        for r in self.own() {
            match &r.event {
                Event::ExecStarted { call_id } => {
                    admitted.insert(call_id);
                }
                Event::ToolResult(t)
                    if t.class == ToolClass::Exec && !matches!(t.status, ToolStatus::Denied | ToolStatus::Invalid) =>
                {
                    admitted.insert(&t.call_id);
                }
                _ => {}
            }
        }
        u64::try_from(admitted.len()).unwrap_or(u64::MAX)
    }

    async fn check_budget(&mut self) -> R<Option<Flow>> {
        let max_steps = self.st.budget.max_steps.unwrap_or(0);
        let max_minutes = self.st.budget.max_minutes.unwrap_or(0);
        if max_steps == 0 && max_minutes == 0 {
            return Ok(None);
        }
        let step = self.st.step.saturating_sub(self.st.budget_step_base);
        let minutes = self.st.clock.as_ref().map_or_else(
            || now_ms().saturating_sub(self.st.budget_from_ms.unwrap_or(self.st.started_ms)),
            |c| c.elapsed(now_ms()),
        ) / 60_000;
        let reached = (max_steps > 0 && step >= max_steps) || (max_minutes > 0 && minutes >= u64::from(max_minutes));
        match self.st.budget_note_step {
            None if reached => {
                let can_finish = self.registry.get("finish").is_some();
                self.note(
                    Author::Harness,
                    NoteKind::Budget,
                    texts::budget_reached(step, minutes, can_finish, self.deps.shared.is_child()),
                )?;
                Ok(None)
            }
            Some(at) if self.st.step.saturating_sub(at) >= texts::BUDGET_GRACE_STEPS => {
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
            if matches!(&r.event, Event::ModelRequest(m) if m.purpose == Purpose::Step)
                || matches!(&r.event, Event::StoredAction(_))
            {
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

    /// The weave of the records as they are now, with what planning needs. Every weave a step uses
    /// is computed here, once, and again only after a record that changes it.
    fn woven(&mut self) -> Woven {
        #[cfg(test)]
        {
            self.weaves = self.weaves.saturating_add(1);
        }
        Woven::new(&self.records)
    }

    /// Estimated size of a request carrying `w`, in tokens (without the HUD).
    fn estimate(&self, w: &Weave) -> u64 {
        self.estimator.tokens_for_messages(&w.messages).saturating_add(self.estimator.tokens(tools_chars(&w.tools)))
    }

    /// Size of the request the session would send now with `w`, in tokens, as the server counts it:
    /// the size it counted for the latest request of this epoch it answered with one, plus the
    /// estimate of what `w` has beyond the `n_messages` that request carried — the items merged into
    /// its last message since (with the blank line joining each), and the messages after it. `None`
    /// before the first such answer of the epoch.
    fn measured_size(&self, w: &Weave) -> Option<u64> {
        let m = self.st.measured.as_ref().filter(|m| m.epoch == w.epoch)?;
        let n = usize::try_from(m.n_messages).unwrap_or(usize::MAX);
        let merged = n.checked_sub(1).and_then(|i| w.messages.get(i)).map_or(0, |last| {
            let item = |seq: Seq| w.items.binary_search_by_key(&seq, |i| i.seq).ok().and_then(|i| w.items.get(i));
            let since = last.origin.iter().filter(|s| **s > m.seq);
            since.fold(0usize, |sum, s| sum.saturating_add(item(*s).map_or(0, |i| i.chars)).saturating_add(2))
        });
        let added = self.estimator.tokens(merged);
        let after = self.estimator.tokens_for_messages(w.messages.get(n..).unwrap_or_default());
        Some(m.prompt_tokens.saturating_add(added).saturating_add(after))
    }

    /// Fold older material out of view when the request has grown past the limit (or `forced`).
    /// `woven` is the weave of the records as they are. `refused_at` is the window an overflow error
    /// stated (or the size of the refused request). True when a `reweave` record was appended.
    async fn reweave(
        &mut self,
        woven: &Woven,
        reason: &str,
        forced: bool,
        token: &CancellationToken,
        refused_at: Option<u64>,
    ) -> R<bool> {
        let window = match (self.deps.context_window, refused_at) {
            (Some(known), Some(refused)) => Some(known.min(refused)),
            (known, refused) => known.or(refused),
        };
        let mut policy = self.deps.context.clone();
        let (limit, floor) = reweave_bounds(&policy, window, self.deps.client.profile().max_output_tokens);
        let est = self.estimate(&woven.weave);
        let size = self.measured_size(&woven.weave).unwrap_or(est);
        if !forced && size <= limit {
            return Ok(false);
        }
        // The plan counts in the estimator's units, the check in the server's when it has counted.
        policy.floor_tokens = scaled(floor, est, size);
        let midpoint = scaled(floor.saturating_add(limit) / 2, est, size);
        let enough =
            |p: &Option<loom_core::weave::ReweavePlan>| p.as_ref().is_some_and(|p| p.after_tokens_est <= midpoint);
        let mut plan = woven.plan(&self.records, &self.estimator, &policy, false);
        while !enough(&plan) && policy.keep_recent_steps > MIN_KEEP_RECENT_STEPS {
            policy.keep_recent_steps = (policy.keep_recent_steps / 2).max(MIN_KEEP_RECENT_STEPS);
            plan = woven.plan(&self.records, &self.estimator, &policy, false);
        }
        let mut digest = None;
        if !enough(&plan) {
            let text_plan = woven.plan(&self.records, &self.estimator, &policy, true);
            if !forced && !enough(&text_plan) {
                return Ok(false);
            }
            // After an overflow the server has just refused this prefix: a digest request on it would be
            // refused as well.
            if text_plan.is_some() && refused_at.is_none() {
                digest = self.ask_digest(&woven.weave, token).await?;
                if token.is_cancelled() {
                    return Ok(false);
                }
            }
            if text_plan.is_some() {
                plan = text_plan;
            }
        }
        let Some(plan) = plan else { return Ok(false) };
        let freed = scaled(plan.before_tokens_est.saturating_sub(plan.after_tokens_est), size, est);
        let ledger = self.deps.shared.journal.as_ref().map(|_| self.deps.shared.ledger());
        let (ledger_brief, frontier_block) = match ledger {
            Some(Ok(l)) => {
                let mut f = frontier::frontier(&l, now_ms());
                f.attempts_run = frontier::attempts_run(&self.records);
                (l.brief(&BriefOpts::default()), frontier::render(&f))
            }
            _ => (String::new(), None),
        };
        self.append(
            Author::Harness,
            Event::Reweave(Reweave {
                epoch: self.st.epoch.saturating_add(1),
                upto_seq: plan.upto_seq,
                evictions: plan.evictions,
                brief: texts::reweave_brief(&ledger_brief, frontier_block.as_deref()),
                digest,
                reason: reason.to_string(),
                before_tokens: size,
                after_tokens_est: size.saturating_sub(freed),
            }),
        )?;
        self.publish();
        Ok(true)
    }

    /// Ask the model, on the existing prefix `w`, for notes about what is about to be folded away.
    /// The request waits for the limiter at the session's own priority: the step waits for it.
    async fn ask_digest(&mut self, w: &Weave, token: &CancellationToken) -> R<Option<String>> {
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
                est_tokens: self.estimate(w),
            }),
        )?;
        self.clock_set(false)?;
        let Some(permit) = self.deps.limiter.acquire(self.deps.priority, token).await else { return Ok(None) };
        self.clock_set(true)?;
        let mut messages = w.messages.clone();
        messages.push(Message::user(texts::DIGEST_PROMPT));
        let request = ChatRequest {
            messages,
            tools: w.tools.clone(),
            tool_choice: ToolChoice::Auto,
            max_tokens: Some(texts::DIGEST_MAX_TOKENS),
            seed: None,
            extra: Map::new(),
        };
        // Its events are not shown to viewers: they would read as the step's reply.
        let result = self.complete_watched(&request, token, |_| {}).await?;
        drop(permit);
        Ok(match result {
            Ok(c) if !c.text.trim().is_empty() => Some(c.text.trim().to_string()),
            _ => None,
        })
    }

    // ---- the reply -----------------------------------------------------------------------------

    async fn handle_reply(&mut self, req_id: &str, c: &Completion, w_tools: &[ToolSpec], early: Early) -> R<Flow> {
        if matches!(c.finish, FinishReason::Error | FinishReason::Aborted) {
            early.discard().await;
            return self.fail("The model server ended the reply with an error.");
        }
        let complete: Vec<ToolCallRequest> = c.tool_calls.iter().filter(|t| t.complete).cloned().collect();
        let calls = self.run_calls(req_id, &c.tool_calls, w_tools, early).await?;
        // Calls that were not cut off by the limit but whose arguments are not a JSON object are not run
        // and not replayed (the weave keeps only complete calls). The model is told why, after the
        // results of the calls that ran and whatever the turn does next.
        let malformed: Vec<String> = if c.finish == FinishReason::Length {
            Vec::new()
        } else {
            let bad = c.tool_calls.iter().filter(|t| !t.complete && !t.name.is_empty());
            bad.map(|t| texts::malformed_call(&t.name, &t.arguments)).collect()
        };
        if !malformed.is_empty() {
            self.note(Author::Harness, NoteKind::Nudge, malformed.join("\n\n"))?;
        }
        match calls.effect {
            Some(Effect::EndTurn(reason)) => return Ok(Flow::End(reason)),
            Some(Effect::Settle(d)) => return Ok(Flow::Settle(d)),
            None => {}
        }
        if calls.cancelled {
            return self.cancelled().await;
        }
        if c.finish == FinishReason::Length {
            if complete.is_empty() {
                if let Some(flow) = self.give_up_if_stuck(texts::repeated_cut, &c.text)? {
                    return Ok(flow);
                }
            }
            let dropped = c.tool_calls.iter().find(|t| !t.complete).map(|t| t.name.as_str());
            let text = texts::output_cut(c.usage.completion_tokens, dropped, calls.ran);
            self.note(Author::Harness, NoteKind::OutputCut, text)?;
            return Ok(Flow::Next);
        }
        if !malformed.is_empty() && complete.is_empty() {
            return Ok(self.give_up_if_stuck(texts::repeated_malformed, &c.text)?.unwrap_or(Flow::Next));
        }
        if !complete.is_empty() {
            return Ok(Flow::Next);
        }
        let shared = self.deps.shared.clone();
        let names = self.registry.names();
        let ledger = if shared.journal.is_some() { shared.ledger().ok() } else { None };
        let running_jobs = self.running_jobs().await.len();
        let running_children = self.running_children().await.len();
        if c.text.trim().is_empty() && !c.reasoning.trim().is_empty() {
            if let Some(flow) = self.give_up_if_stuck(texts::repeated_reasoning, &c.text)? {
                return Ok(flow);
            }
            self.note(Author::Harness, NoteKind::Nudge, texts::REASONING_ONLY.to_string())?;
            return Ok(Flow::Next);
        }
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

    /// Count a reply that made no progress as a nudge. Past `agents.max_nudges` of them in a row the
    /// session gives up: a child settles `Failed`, anything else opens a `Parked` item. `why` names the
    /// cause.
    fn give_up_if_stuck(&mut self, why: fn(u32) -> String, reply: &str) -> R<Option<Flow>> {
        if self.nudges < self.deps.agents.max_nudges {
            self.nudges = self.nudges.saturating_add(1);
            return Ok(None);
        }
        let why = why(self.nudges.saturating_add(1));
        if self.deps.shared.is_child() {
            Ok(Some(Flow::Settle(delivery(ChildOutcome::Failed, texts::failed_report(&why, reply)))))
        } else {
            self.open_inbox(InboxKind::Parked, texts::turn_failed(&why))?;
            Ok(Some(Flow::End(TurnEndReason::Parked)))
        }
    }

    /// Run the complete ones of a reply's calls one at a time, each recorded before and after it runs;
    /// a call started early is claimed in its turn (see *Early starts*).
    async fn run_calls(
        &mut self,
        req_id: &str,
        calls: &[ToolCallRequest],
        w_tools: &[ToolSpec],
        early: Early,
    ) -> R<Calls> {
        self.run_calls_as(req_id, calls, w_tools, Author::Model, false, early).await
    }

    /// [`Session::run_calls`] for calls of `author`; `deferred` marks native results of a stored
    /// action, whose output the actor has not yet seen.
    async fn run_calls_as(
        &mut self,
        req_id: &str,
        calls: &[ToolCallRequest],
        w_tools: &[ToolSpec],
        author: Author,
        deferred: bool,
        mut early: Early,
    ) -> R<Calls> {
        let mut out = Calls::default();
        let mut ender: Option<String> = None;
        early.settle(calls);
        for (index, call) in calls.iter().enumerate().filter(|(_, c)| c.complete) {
            if out.effect.is_none() && self.token.is_cancelled() {
                out.cancelled = true;
                break;
            }
            let tool = self.registry.get(&call.name);
            let class = tool.as_ref().map(|t| t.spec().class).unwrap_or(ToolClass::State);
            let args = serde_json::from_str::<Value>(&call.arguments)
                .unwrap_or_else(|_| Value::String(call.arguments.clone()));
            self.append(
                author.clone(),
                Event::ToolCall(ToolCall {
                    call_id: call.call_id.clone(),
                    req_id: req_id.to_string(),
                    name: call.name.clone(),
                    args: args.clone(),
                    class,
                }),
            )?;
            let mut ctx = self.deps.ctx.clone();
            ctx.call_id = call.call_id.clone();
            ctx.cancel = self.token.clone();
            let started = Instant::now();
            let mut result = if let Some(first) = &ender {
                refused(&ctx, &call.name, class, texts::not_run_after(first), started)
            } else if tool.is_none() && w_tools.iter().any(|t| t.name == call.name) {
                let message = texts::not_in_assignment(&call.name, &self.deps.shared.role.name, &self.registry.names());
                refused(&ctx, &call.name, class, message, started)
            } else if !(CallPolicy { wrapup: self.st.budget_note_step.is_some() }).allows(&call.name, &args) {
                refused(&ctx, &call.name, class, texts::wrapup_refused(&call.name), started)
            } else if class == ToolClass::Exec
                && self.deps.shared.role.max_exec_calls.is_some_and(|cap| self.exec_count() >= u64::from(cap))
            {
                refused(
                    &ctx,
                    &call.name,
                    class,
                    texts::exec_cap(self.deps.shared.role.max_exec_calls.unwrap_or(0)),
                    started,
                )
            } else if let Some(run) = early.claim(index, call) {
                self.claim_early(run, &early, &ctx, call).await
            } else {
                if class == ToolClass::Exec {
                    self.append(Author::Harness, Event::ExecStarted { call_id: call.call_id.clone() })?;
                }
                let admission = Admission { policy: &self.deps.admit, estimator: &self.estimator };
                execute(&self.registry, &ctx, &call.name, &call.arguments, &admission).await
            };
            if deferred {
                result.meta.insert(META_DEFERRED_OBSERVATION.into(), Value::Bool(true));
            }
            let ok = result.status == ToolStatus::Ok;
            let flag_note = self.deps.shared.role.flag_regex.as_ref().and_then(|pattern| {
                let re = regex::RegexBuilder::new(pattern).size_limit(1_000_000).build().ok()?;
                if !re.is_match(&result.text) {
                    return None;
                }
                result.output.as_ref().map(|blob| texts::flag_candidate(&blob.handle()))
            });
            self.append(Author::Tool, Event::ToolResult(result))?;
            if let Some(text) = flag_note {
                let already = self.own().iter().any(
                    |r| matches!(&r.event, Event::HarnessNote { note: NoteKind::Info, text: old } if old == &text),
                );
                if !already {
                    self.note(Author::Harness, NoteKind::Info, text)?;
                }
            }
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
        early.discard().await;
        Ok(out)
    }

    /// The result of a call that was started early, as if it had just run in place: awaited (its token
    /// is a child of the turn's, so a stop interrupts it; dropped while it waits, its task is stopped),
    /// what it saw of files counted from now on, stored and admitted now.
    async fn claim_early(
        &self,
        mut run: EarlyRun,
        early: &Early,
        ctx: &ToolCtx,
        call: &ToolCallRequest,
    ) -> loom_core::event::ToolResult {
        let reached = Instant::now();
        let admission = Admission { policy: &self.deps.admit, estimator: &self.estimator };
        let ran = match (&mut run.task.handle).await {
            Ok(ran) => ran,
            // Only a discard aborts a task, and a claimed run is never discarded; the call runs in place.
            Err(e) => {
                let session = &self.deps.shared.session;
                tracing::warn!(%session, call = %call.call_id.0, "a call started early failed ({e}); it runs again");
                early.count(|c| c.discarded = c.discarded.saturating_add(1));
                return execute(&self.registry, ctx, &call.name, &call.arguments, &admission).await;
            }
        };
        run.ctx.files.move_into(&self.deps.ctx.files);
        let before_end = early.reply_end.map_or(Duration::ZERO, |end| end.saturating_duration_since(run.started));
        early.count(|c| {
            c.claimed = c.claimed.saturating_add(1);
            c.saved_ms = c.saved_ms.saturating_add(millis(before_end.min(ran.took)));
        });
        let mut result = ran.finish(&run.ctx, &admission);
        let ahead = millis(reached.saturating_duration_since(run.started));
        result.meta.insert(META_EARLY_MS.into(), Value::from(ahead));
        result
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::rtools::testkit::{core_role, rig_with, FakeOrch, Rig};
    use loom_core::config::ModelProfile;
    use loom_core::event::{Brief, ModelRef, ReasoningReplay};
    use loom_core::ids::MissionId;
    use loom_core::log::read_records;
    use loom_model::mock::{Action, MockServer, Reply, Script};
    use loom_tools::testutil::TestEnv;
    use loom_tools::Tool;
    use serde_json::json;
    use tokio::sync::mpsc::UnboundedSender;

    include!("continuation_tests.rs");

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
            // The default lead cannot `conclude` or `request_scope`: its `finish` is not held by the goal-met
            // claim, so a test that uses `finish` only to end a turn ends it as it did before the finish gate
            // asked for a conclusion. `Fx::build` keeps the role as the core pack has it.
            let mut role_def = core_role(role);
            role_def.tools.retain(|t| t != "conclude" && t != "request_scope");
            Fx::build_with(role_def, role, child, mission, agents, script).await
        }

        async fn build(role: &str, child: bool, mission: bool, agents: AgentsCfg, script: Script) -> Fx {
            Fx::build_with(core_role(role), role, child, mission, agents, script).await
        }

        async fn build_with(
            role_def: crate::pack::RoleDef,
            role: &str,
            child: bool,
            mission: bool,
            agents: AgentsCfg,
            script: Script,
        ) -> Fx {
            let server = MockServer::start(script).await.unwrap();
            let Rig { env, orch, shared, registry: _ } = rig_with(role_def, child, mission, agents.clone());
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
                schema: loom_core::event::SCHEMA,
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
            self.try_fork(parent_log, upto, budget).unwrap()
        }

        fn try_fork(&mut self, parent_log: &Path, upto: Seq, budget: Budget) -> Result<Session, String> {
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
            Session::fork(deps, parent_log, upto, forked)
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

    // Existing contract-order assertions concern rendered/lifecycle events. Bookkeeping transitions
    // have their own replay/admission tests below and do not change those relative orders.
    fn kinds(rs: &[Record]) -> Vec<String> {
        rs.iter()
            .filter(|r| !matches!(r.event, Event::BudgetClock { .. } | Event::ExecStarted { .. }))
            .map(kind)
            .collect()
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
        body["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["content"].as_str().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n")
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
                    None => Action::Status {
                        status: 400,
                        body: "{\"error\":{\"message\":\"no\"}}".into(),
                        retry_after_s: None,
                    },
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
                "session_start",
                "user_message",
                "ledger",
                "turn_start",
                "model_request",
                "model_response",
                "tool_call",
                "tool_result",
                "model_request",
                "model_response",
                "tool_call",
                "tool_result",
                "ledger",
                "inbox_opened",
                "turn_end"
            ]
        );
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Finished]);
        assert_eq!(rs[1].author, Author::User);
        assert_eq!(rs.iter().find(|r| matches!(r.event, Event::ModelResponse(_))).unwrap().author, Author::Model);
        assert_eq!(rs.iter().find(|r| matches!(r.event, Event::ToolResult(_))).unwrap().author, Author::Tool);
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

    #[test]
    fn job_line_counts_read_only_what_the_file_gained_since_the_last_request() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("j1.out");
        let append = |text: &str| {
            std::fs::OpenOptions::new().append(true).open(&path).unwrap().write_all(text.as_bytes()).unwrap()
        };
        std::fs::write(&path, "one\ntwo\n").unwrap();
        let mut counts = LineCounts::default();
        assert_eq!((counts.count("j1", &path), counts.read), (2, 8));
        // The next request reads the new bytes only; a last line without its newline counts.
        append("three\nfo");
        assert_eq!((counts.count("j1", &path), counts.read), (4, 16));
        assert_eq!((counts.count("j1", &path), counts.read), (4, 16), "nothing new, nothing read");
        append("ur\nfive\n");
        assert_eq!((counts.count("j1", &path), counts.read), (5, 24));
        // A file that shrank is counted again from its start.
        std::fs::write(&path, "x\ny\n").unwrap();
        assert_eq!((counts.count("j1", &path), counts.read), (2, 28));
        // A file that is gone counts nothing and is forgotten; so is a job that no longer runs.
        std::fs::remove_file(&path).unwrap();
        assert_eq!(counts.count("j1", &path), 0);
        assert!(counts.files.is_empty());
        std::fs::write(&path, "z\n").unwrap();
        assert_eq!(counts.count("j1", &path), 1);
        counts.retain(&[]);
        assert!(counts.files.is_empty());
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
        let script = seq(vec![
            Reply::text("partial thought").with_finish(FinishReason::Length).into(),
            Reply::text("ok").into(),
        ]);
        let mut fx = Fx::new("chat", false, false, script).await;
        let session = fx.create();
        run_with(session, vec![user("go")]).await;
        let rs = fx.sink.records();
        let n = notes(&rs, NoteKind::OutputCut);
        assert_eq!(n.len(), 1);
        assert_eq!(
            n[0],
            texts::output_cut(
                rs.iter()
                    .find_map(|r| match &r.event {
                        Event::ModelResponse(m) => Some(m.usage.completion_tokens),
                        _ => None,
                    })
                    .unwrap(),
                None,
                0
            )
        );
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

    #[tokio::test]
    async fn repeated_output_limit_replies_park_and_progress_resets_the_count() {
        let agents = AgentsCfg { max_nudges: 2, verify_finish: false, ..AgentsCfg::default() };
        let cut = || -> Action { Reply::text("rambling").with_finish(FinishReason::Length).into() };
        let script = seq(vec![cut(), cut(), bash("echo ok").into(), cut(), cut(), cut(), cut()]);
        let mut fx = Fx::build("lead", false, true, agents.clone(), script).await;
        let session = fx.create();
        run_with(session, vec![user("go")]).await;
        let rs = fx.sink.records();
        assert_eq!(fx.server.requests().len(), 6, "{:?}", kinds(&rs));
        assert_eq!(notes(&rs, NoteKind::OutputCut).len(), 4);
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Parked]);
        assert_eq!(inbox(&rs)[0].text, texts::turn_failed(&texts::repeated_cut(3)));

        let mut kid = Fx::build("worker", true, true, agents, seq((0..5).map(|_| cut()).collect())).await;
        let session = kid.create_with(Budget::default(), Some((SessionId::from("s-lead"), "Do it.".into())));
        let End::Settled(s) = run_with(session, vec![]).await else { panic!("expected a settlement") };
        assert_eq!(s.outcome, ChildOutcome::Failed);
        assert!(s.report.contains(&texts::repeated_cut(3)), "{}", s.report);
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
                "model_response",
                "tool_call",
                "tool_result",
                "tool_call",
                "tool_result",
                "ledger",
                "tool_call",
                "tool_result",
                "ledger",
                "inbox_opened",
                "tool_call",
                "tool_result",
                "turn_end"
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
    async fn a_malformed_call_is_not_run_not_replayed_and_never_reaches_the_gate() {
        let bad = "{\"command\": \"ls";
        let script = seq(vec![Reply::tool("bash", bad).into(), finish_call("done").into()]);
        let mut fx = Fx::new("lead", false, true, script).await;
        let session = fx.create();
        run_with(session, vec![user("go")]).await;
        let rs = fx.sink.records();
        assert_eq!(count(&rs, "tool_call"), 1, "only finish was called: {:?}", kinds(&rs));
        let n = notes(&rs, NoteKind::Nudge);
        assert_eq!(n.len(), 1, "{n:?}");
        assert!(n[0].contains("`bash`") && n[0].contains("not a valid JSON object"), "{}", n[0]);
        assert!(n[0].contains("EOF while parsing") && n[0].contains("line 1 column"), "{}", n[0]);
        assert!(n[0].contains(bad) && n[0].contains("Send the call again"), "{}", n[0]);
        assert!(!n[0].contains("without a tool call"));
        let reqs = fx.server.requests();
        assert_eq!(reqs.len(), 2);
        assert!(all_text(&reqs[1]).contains(&n[0]));
        for m in reqs[1]["messages"].as_array().unwrap() {
            assert!(m.get("tool_calls").is_none(), "the malformed call must not be replayed: {m}");
        }
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Finished]);
    }

    #[tokio::test]
    async fn a_malformed_call_beside_a_valid_one_leaves_the_valid_one_running() {
        let reply = Reply::tools([
            ("bash", json!({ "command": "echo fine" }).to_string()),
            ("bash", "[1, 2]".to_string()),
            ("bash", "{nope".to_string()),
        ]);
        let mut fx = Fx::new("chat", false, false, seq(vec![reply.into(), Reply::text("ok").into()])).await;
        let session = fx.create();
        run_with(session, vec![user("go")]).await;
        let rs = fx.sink.records();
        assert_eq!(count(&rs, "tool_call"), 1);
        assert_eq!(results(&rs)[0].status, ToolStatus::Ok);
        let n = notes(&rs, NoteKind::Nudge);
        assert_eq!(n.len(), 1);
        assert!(n[0].contains("hold an array, not an object") && n[0].contains("key must be a string"), "{}", n[0]);
        let second = &fx.server.requests()[1];
        let asst = second["messages"].as_array().unwrap().iter().find(|m| m["role"] == "assistant").unwrap().clone();
        assert_eq!(asst["tool_calls"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn malformed_replies_in_a_row_park_a_lead_and_fail_a_child() {
        let agents = AgentsCfg { max_nudges: 2, verify_finish: false, ..AgentsCfg::default() };
        let script = || seq((0..5).map(|_| Reply::tool("bash", "{\"command\": ").into()).collect());
        let mut fx = Fx::build("lead", false, true, agents.clone(), script()).await;
        let session = fx.create();
        run_with(session, vec![user("go")]).await;
        let rs = fx.sink.records();
        assert_eq!(fx.server.requests().len(), 3);
        // Every malformed reply is explained, the last one too, before the session gives up.
        assert_eq!(notes(&rs, NoteKind::Nudge).len(), 3);
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Parked]);
        let items = inbox(&rs);
        assert_eq!((items.len(), items[0].kind, items[0].blocking), (1, InboxKind::Parked, true));
        assert_eq!(items[0].text, texts::turn_failed(&texts::repeated_malformed(3)));
        assert_eq!(count(&rs, "tool_call"), 0);

        let mut kid = Fx::build("worker", true, true, agents, script()).await;
        let session = kid.create_with(Budget::default(), Some((SessionId::from("s-lead"), "Do it.".into())));
        let End::Settled(s) = run_with(session, vec![]).await else { panic!("expected a settlement") };
        assert_eq!(s.outcome, ChildOutcome::Failed);
        assert!(s.report.contains(&texts::repeated_malformed(3)), "{}", s.report);
    }

    #[tokio::test]
    async fn malformed_cut_and_text_only_replies_share_one_count() {
        let agents = AgentsCfg { max_nudges: 2, verify_finish: false, ..AgentsCfg::default() };
        let script = seq(vec![
            Reply::tool("bash", "{nope").into(),
            Reply::text("thinking").into(),
            Reply::text("rambling").with_finish(FinishReason::Length).into(),
            Reply::text("never asked").into(),
        ]);
        let mut fx = Fx::build("lead", false, true, agents, script).await;
        let session = fx.create();
        run_with(session, vec![user("go")]).await;
        let rs = fx.sink.records();
        assert_eq!(fx.server.requests().len(), 3, "{:?}", kinds(&rs));
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Parked]);
        assert_eq!(inbox(&rs)[0].text, texts::turn_failed(&texts::repeated_cut(3)));
    }

    #[tokio::test]
    async fn a_malformed_call_beside_a_turn_ending_one_is_still_explained() {
        let reply = Reply::tools([("bash", "{nope".to_string()), ("finish", json!({ "answer": "done" }).to_string())]);
        let mut fx = Fx::new("lead", false, true, seq(vec![reply.into()])).await;
        let session = fx.create();
        run_with(session, vec![user("go")]).await;
        let rs = fx.sink.records();
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Finished]);
        assert_eq!(count(&rs, "tool_call"), 1);
        let n = notes(&rs, NoteKind::Nudge);
        assert_eq!(n.len(), 1);
        assert!(n[0].contains("`bash`") && n[0].contains("Send the call again"), "{}", n[0]);
        // The note follows the finish call's result and comes before the turn ends.
        let at = |k: &str| rs.iter().position(|r| kind(r) == k).unwrap();
        let note = rs.iter().position(|r| matches!(r.event, Event::HarnessNote { note: NoteKind::Nudge, .. })).unwrap();
        assert!(at("tool_result") < note && note < at("turn_end"), "{:?}", kinds(&rs));
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
        let call = |id: &str| ToolCallRequest {
            call_id: CallId::from(id),
            name: "bash".into(),
            arguments: "{}".into(),
            complete: true,
        };
        let completion = Completion {
            text: String::new(),
            reasoning: String::new(),
            tool_calls: vec![call("dup"), call(""), call("fresh"), call("fresh")],
            finish: FinishReason::ToolCalls,
            usage: Usage::default(),
            timing: Timing::default(),
            attempts: 1,
        };
        let fixed = session.with_fresh_ids(completion.clone(), &BTreeMap::new());
        let ids: Vec<String> = fixed.tool_calls.iter().map(|c| c.call_id.0.clone()).collect();
        assert!(ids[0].starts_with("call-") && ids[1].starts_with("call-"));
        assert_eq!(ids[2], "fresh");
        assert!(ids[3].starts_with("call-"));
        assert_eq!(ids.iter().collect::<HashSet<_>>().len(), 4);

        // A call started early keeps the id it was started with, whatever the server sent.
        let early = BTreeMap::from([(2, CallId::from("call-early"))]);
        let fixed = session.with_fresh_ids(completion.clone(), &early);
        let ids: Vec<String> = fixed.tool_calls.iter().map(|c| c.call_id.0.clone()).collect();
        assert_eq!(ids[2], "call-early");
        // The server's id at index 2 is no longer taken, so the one at index 3 is kept.
        assert_eq!(ids[3], "fresh");
        assert_eq!(ids.iter().collect::<HashSet<_>>().len(), 4);

        // Unless the log or an earlier call already has it: then the call is given an id as if it had
        // not started early (and the early run, which it no longer matches, is dropped).
        let early = BTreeMap::from([(1, CallId::from("dup")), (3, CallId::from("fresh"))]);
        let fixed = session.with_fresh_ids(completion, &early);
        let ids: Vec<String> = fixed.tool_calls.iter().map(|c| c.call_id.0.clone()).collect();
        assert!(ids[1].starts_with("call-") && ids[3].starts_with("call-"), "{ids:?}");
        assert_eq!(ids[2], "fresh");
        assert_eq!(ids.iter().collect::<HashSet<_>>().len(), 4);
    }

    // ---- early starts ------------------------------------------------------------------------

    /// What probe calls did: per call, its path and how many replies were recorded and how many stream
    /// events the sink had been given when it began; how many were running, and the most at once.
    #[derive(Clone, Default)]
    struct Witness {
        began: Arc<Mutex<Vec<(String, usize, usize)>>>,
        live: Arc<std::sync::atomic::AtomicUsize>,
        peak: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Witness {
        fn paths(&self) -> Vec<String> {
            self.began.lock().unwrap().iter().map(|(p, _, _)| p.clone()).collect()
        }
        fn live(&self) -> usize {
            self.live.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    /// Counts a probe call as running until it is dropped, however it ends.
    struct Alive(Arc<std::sync::atomic::AtomicUsize>);

    impl Drop for Alive {
        fn drop(&mut self) {
            self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// The real `read`, telling the witness when each call begins; with `hold`, a call waits for its
    /// cancellation instead of reading.
    struct Probe {
        sink: Option<Arc<Collect>>,
        witness: Witness,
        hold: bool,
    }

    #[async_trait::async_trait]
    impl Tool for Probe {
        fn spec(&self) -> ToolSpec {
            loom_tools::fstools::Read.spec()
        }
        fn speculative(&self) -> bool {
            true
        }
        async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> loom_tools::ToolOutput {
            use std::sync::atomic::Ordering::SeqCst;
            let now = self.witness.live.fetch_add(1, SeqCst) + 1;
            let _alive = Alive(self.witness.live.clone());
            self.witness.peak.fetch_max(now, SeqCst);
            let replies = self.sink.as_ref().map_or(0, |s| count(&s.records(), "model_response"));
            let deltas = self.sink.as_ref().map_or(0, |s| s.deltas.lock().unwrap().len());
            self.witness.began.lock().unwrap().push((args["path"].as_str().unwrap_or("").to_string(), replies, deltas));
            if self.hold {
                ctx.cancel.cancelled().await;
                return loom_tools::ToolOutput::error("held until cancelled");
            }
            loom_tools::fstools::Read.run(ctx, args).await
        }
    }

    fn read_call(path: &str) -> (String, String) {
        ("read".to_string(), json!({ "path": path }).to_string())
    }

    fn other_call(name: &str, args: Value) -> (String, String) {
        (name.to_string(), args.to_string())
    }

    /// A `chat` session over `a.txt`, `b.txt`, `c.txt`, whose `read` is a probe, run on `script` for
    /// one user message.
    async fn early_run(speculate: bool, script: Vec<Action>) -> (Fx, Witness, Arc<Mutex<EarlyCounts>>) {
        let mut fx = Fx::new("chat", false, false, seq(script)).await;
        fx.ctx.cfg = Arc::new(loom_core::config::ToolsCfg { speculate, ..(*fx.ctx.cfg).clone() });
        for (file, text) in [("a.txt", "alpha\n"), ("b.txt", "beta\n"), ("c.txt", "gamma\n")] {
            std::fs::write(fx.ctx.workspace.join(file), text).unwrap();
        }
        let witness = Witness::default();
        let mut session = fx.create();
        session.registry.add(Arc::new(Probe { sink: Some(fx.sink.clone()), witness: witness.clone(), hold: false }));
        let counts = session.early_counts.clone();
        run_with(session, vec![user("go")]).await;
        (fx, witness, counts)
    }

    fn counts_of(counts: &Arc<Mutex<EarlyCounts>>) -> (u64, u64, u64) {
        let c = *counts.lock().unwrap();
        (c.started, c.claimed, c.discarded)
    }

    fn early_marks(rs: &[Record]) -> Vec<bool> {
        results(rs).iter().map(|r| r.meta.contains_key(META_EARLY_MS)).collect()
    }

    /// Request and call ids, in order of first appearance.
    fn ids_of(rs: &[Record]) -> Vec<String> {
        let mut ids = Vec::new();
        for r in rs {
            match &r.event {
                Event::ModelRequest(m) => ids.push(m.req_id.clone()),
                Event::ModelResponse(m) => ids.extend(m.tool_calls.iter().map(|c| c.call_id.0.clone())),
                _ => {}
            }
        }
        ids
    }

    /// `text` with what differs between two runs of one script made alike: the temp directory, the
    /// ids (numbered by first appearance) and the run time a command's header states.
    fn alike(fx: &Fx, ids: &[String], text: &str) -> Value {
        let mut text = text.replace(&fx.ctx.workspace.parent().unwrap().display().to_string(), "#root");
        for (n, id) in ids.iter().enumerate() {
            text = text.replace(id.as_str(), &format!("#id{n}"));
        }
        let text = regex::Regex::new(r" · [0-9.]+s · ").unwrap().replace_all(&text, " · #s · ");
        serde_json::from_str(&text).unwrap()
    }

    /// The records, alike between runs, without times, hashes, the HUD and the early-start key.
    fn comparable(fx: &Fx) -> Vec<Value> {
        let rs = fx.sink.records();
        let ids = ids_of(&rs);
        rs.iter()
            .map(|r| {
                let mut v = serde_json::to_value(r).unwrap();
                let o = v.as_object_mut().unwrap();
                for k in ["ts_ms", "prev", "duration_ms", "timing", "hud", "stable_hash"] {
                    o.remove(k);
                }
                if let Some(meta) = o.get_mut("meta").and_then(Value::as_object_mut) {
                    meta.remove(META_EARLY_MS);
                }
                alike(fx, &ids, &v.to_string())
            })
            .collect()
    }

    /// What the model is shown from the records, alike between runs.
    fn woven(fx: &Fx) -> Value {
        let rs = fx.sink.records();
        alike(fx, &ids_of(&rs), &serde_json::to_string(&weave(&rs).messages).unwrap())
    }

    #[tokio::test]
    async fn reads_start_while_the_reply_streams_and_nothing_recorded_changes() {
        // The bash call's arguments come in three pieces, 60 ms apart, after a pause.
        let bash = other_call("bash", json!({ "command": "echo reads-start-while-the-reply-streams-in" }));
        let reply = || {
            Reply::tools([read_call("a.txt"), read_call("b.txt"), bash.clone()])
                .with_pause_before_call(2, 400)
                .with_delay_ms(60)
        };
        let script = || vec![reply().into(), Reply::text("done").into()];
        let (on, seen_on, counts_on) = early_run(true, script()).await;
        let (off, seen_off, counts_off) = early_run(false, script()).await;
        // Pieces of the bash call's arguments among the first `upto` stream events the sink was given.
        let bash_pieces = |fx: &Fx, upto: usize| {
            let deltas = fx.sink.deltas.lock().unwrap();
            deltas.iter().take(upto).filter(|(_, e)| matches!(e, StreamEvent::ToolCallArgs { index: 2, .. })).count()
        };
        let whole = bash_pieces(&on, usize::MAX);
        assert_eq!((whole, bash_pieces(&off, usize::MAX)), (3, 3));
        // Both reads began while the bash call was still streaming in, so before the reply was complete
        // and recorded; without early starts, after it was recorded.
        assert_eq!(seen_on.paths(), ["a.txt", "b.txt"]);
        for (path, replies, deltas) in seen_on.began.lock().unwrap().iter() {
            assert_eq!(*replies, 0, "{path}");
            assert!(bash_pieces(&on, *deltas) < whole, "{path} began once the bash call had streamed in");
        }
        assert_eq!(seen_off.paths(), ["a.txt", "b.txt"]);
        assert!(seen_off.began.lock().unwrap().iter().all(|(_, replies, _)| *replies == 1));
        assert_eq!(counts_of(&counts_on), (2, 2, 0));
        assert_eq!(counts_of(&counts_off), (0, 0, 0));
        let rs = on.sink.records();
        assert_eq!(early_marks(&rs), [true, true, false]);
        assert!(early_marks(&off.sink.records()).iter().all(|m| !m));
        // The records and what the model sees are those of the run without early starts.
        assert_eq!(comparable(&on), comparable(&off));
        assert_eq!(woven(&on), woven(&off));
        let calls: Vec<ToolCall> = rs
            .iter()
            .filter_map(|r| match &r.event {
                Event::ToolCall(c) => Some(c.clone()),
                _ => None,
            })
            .collect();
        let res = results(&rs);
        for (call, result) in calls.iter().zip(&res) {
            assert_eq!(call.call_id, result.call_id);
            // The server's id, which the call keeps without early starts too.
            assert!(call.call_id.0.starts_with("chatcmpl-tool-"), "{}", call.call_id.0);
        }
        assert!(res[0].text.contains("alpha") && res[1].text.contains("beta"), "{}", res[0].text);
        assert_no_cache_break(&rs);
        assert_no_cache_break(&off.sink.records());
        // What the early reads saw counts once they are claimed.
        for f in ["a.txt", "b.txt"] {
            assert_eq!(on.ctx.files.check(&on.ctx.workspace.join(f)).unwrap(), loom_tools::files::Freshness::Current);
        }
    }

    #[tokio::test]
    async fn a_retry_voids_the_early_calls_of_the_broken_attempt() {
        let write = other_call("write", json!({ "path": "a.txt", "content": "changed\n" }));
        let after = || vec![Reply::tools([write.clone()]).into(), Reply::text("ok").into()];
        // The first attempt breaks just after the second call has begun, which makes the first ready.
        let broken = Action::DropAfter { reply: Reply::tools([read_call("a.txt"), read_call("c.txt")]), chunks: 4 };
        let mut script = vec![broken, Reply::tools([read_call("b.txt")]).into()];
        script.extend(after());
        let (fx, witness, counts) = early_run(true, script).await;
        assert!(witness.paths().contains(&"a.txt".to_string()), "a.txt was read early: {:?}", witness.paths());
        assert_eq!(counts_of(&counts), (2, 1, 1));
        let rs = fx.sink.records();
        let resp = rs.iter().find_map(|r| match &r.event {
            Event::ModelResponse(m) => Some(m.clone()),
            _ => None,
        });
        assert_eq!(resp.unwrap().attempts, 2);
        let calls: Vec<String> = rs
            .iter()
            .filter_map(|r| match &r.event {
                Event::ToolCall(c) => Some(format!("{} {}", c.name, c.args)),
                _ => None,
            })
            .collect();
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert!(calls[0].starts_with("read") && calls[0].contains("b.txt"), "{calls:?}");
        let res = results(&rs);
        assert_eq!(res[1].status, ToolStatus::Error);
        assert_eq!(std::fs::read_to_string(fx.ctx.workspace.join("a.txt")).unwrap(), "alpha\n");
        let a = fx.ctx.workspace.join("a.txt");
        assert_eq!(fx.ctx.files.check(&a).unwrap(), loom_tools::files::Freshness::Unread);
        // Refused exactly as in a session that never read a.txt.
        let mut script = vec![Reply::tools([read_call("b.txt")]).into()];
        script.extend(after());
        let (plain, _, _) = early_run(true, script).await;
        assert_eq!(results(&plain.sink.records())[1].text, res[1].text);
    }

    #[tokio::test]
    async fn a_call_after_one_that_may_not_start_early_waits_for_its_turn() {
        let bash = other_call("bash", json!({ "command": "echo x" }));
        let write = other_call("write", json!({ "path": "new.txt", "content": "n\n" }));
        // The first read is ready while the reply streams, but it must see what bash did.
        let reply = Reply::tools([bash, read_call("a.txt"), read_call("b.txt")]).with_delay_ms(20);
        let (fx, _, counts) = early_run(true, vec![reply.into(), Reply::text("ok").into()]).await;
        assert_eq!(counts_of(&counts), (0, 0, 0));
        assert_eq!(early_marks(&fx.sink.records()), [false, false, false]);
        let reply = Reply::tools([read_call("a.txt"), write, read_call("b.txt")]).with_delay_ms(20);
        let (fx, _, counts) = early_run(true, vec![reply.into(), Reply::text("ok").into()]).await;
        assert_eq!(counts_of(&counts), (1, 1, 0));
        assert_eq!(early_marks(&fx.sink.records()), [true, false, false]);
    }

    #[tokio::test]
    async fn an_early_call_the_finished_reply_holds_differently_is_dropped_and_runs_in_place() {
        // The first call's arguments get one more character after the second call has begun.
        let reply = || Reply::tools([read_call("a.txt"), read_call("b.txt")]).with_late_args(0, " ").with_delay_ms(20);
        let (on, witness, counts) = early_run(true, vec![reply().into(), Reply::text("ok").into()]).await;
        let (off, _, _) = early_run(false, vec![reply().into(), Reply::text("ok").into()]).await;
        // a.txt early and dropped, then in place; b.txt with the rest of the reply's reads.
        assert_eq!(counts_of(&counts), (2, 1, 1));
        assert_eq!(early_marks(&on.sink.records()), [false, true]);
        assert_eq!(witness.paths().iter().filter(|p| *p == "a.txt").count(), 2, "{:?}", witness.paths());
        let rs = on.sink.records();
        let args = rs.iter().find_map(|r| match &r.event {
            Event::ModelResponse(m) => Some(m.tool_calls[0].arguments.clone()),
            _ => None,
        });
        assert_eq!(args.unwrap(), format!("{} ", json!({ "path": "a.txt" })));
        assert_eq!(comparable(&on), comparable(&off));
    }

    #[tokio::test]
    async fn unknown_tools_and_invalid_arguments_are_not_started_early_and_answer_as_before() {
        let reply = || {
            Reply::tools([
                other_call("read", json!({})),
                read_call("a.txt"),
                other_call("nosuch", json!({ "x": 1 })),
                other_call("glob", json!({ "pattern": "*" })),
                other_call("bash", json!({ "command": "echo x" })),
            ])
            .with_delay_ms(20)
        };
        let (on, _, counts) = early_run(true, vec![reply().into(), Reply::text("ok").into()]).await;
        let (off, _, _) = early_run(false, vec![reply().into(), Reply::text("ok").into()]).await;
        // Only the valid read: the invalid one is answered in its turn, and nothing after the unknown
        // tool starts early.
        assert_eq!(counts_of(&counts), (1, 1, 0));
        let rs = on.sink.records();
        assert_eq!(early_marks(&rs), [false, true, false, false, false]);
        let res = results(&rs);
        assert_eq!((res[0].status, res[2].status), (ToolStatus::Invalid, ToolStatus::Invalid));
        assert!(res[2].text.contains("There is no tool named `nosuch`"), "{}", res[2].text);
        assert_eq!(comparable(&on), comparable(&off));
    }

    #[tokio::test]
    async fn a_stop_while_the_reply_streams_ends_its_early_calls_with_the_turn() {
        let calls = [read_call("a.txt"), read_call("b.txt"), other_call("bash", json!({ "command": "echo x" }))];
        let reply = Reply::tools(calls).with_pause_before_call(2, 20_000);
        let mut fx = Fx::new("chat", false, false, seq(vec![reply.into()])).await;
        let witness = Witness::default();
        let mut session = fx.create();
        session.registry.add(Arc::new(Probe { sink: None, witness: witness.clone(), hold: true }));
        let counts = session.early_counts.clone();
        let (tx, task) = spawn_run(session);
        tx.send(user("go")).unwrap();
        for _ in 0..800 {
            if witness.live() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(witness.paths(), ["a.txt"], "the first read runs while the reply streams");
        fx.control.stop_turn();
        wait_until(&fx.sink, "turn end", |rs| count(rs, "turn_end") == 1).await;
        assert_eq!(witness.live(), 0, "no early call outlives the turn");
        let rs = fx.sink.records();
        assert_eq!(&kinds(&rs)[kinds(&rs).len() - 2..], ["interrupted", "turn_end"]);
        assert_eq!(count(&rs, "tool_call") + count(&rs, "tool_result"), 0);
        assert_eq!(counts_of(&counts), (1, 0, 1));
        assert_eq!(finish_task(tx, task).await, End::Closed);
    }

    /// The early calls of one request, over a registry whose `read` is a probe that holds until it is
    /// cancelled, in a session whose log has the call id `logged`.
    fn held_early(witness: &Witness) -> (Early, Arc<Mutex<EarlyCounts>>, TestEnv) {
        let env = loom_tools::testutil::env();
        let mut registry = Registry::new();
        registry.add(Arc::new(Probe { sink: None, witness: witness.clone(), hold: true }));
        let counts = Arc::default();
        let logged = HashSet::from(["logged".to_string()]);
        let early = Early::new(true, registry, env.ctx.clone(), &CancellationToken::new(), logged, Arc::clone(&counts));
        (early, counts, env)
    }

    fn ready(index: u32) -> StreamEvent {
        ready_as(index, None)
    }

    /// `read` of `f{index}` is ready, with the server's id `id`.
    fn ready_as(index: u32, id: Option<&str>) -> StreamEvent {
        let arguments = json!({ "path": format!("f{index}") }).to_string();
        StreamEvent::ToolCallReady { index, id: id.map(str::to_string), name: "read".into(), arguments }
    }

    /// Wait, four seconds at most, until `f` holds.
    async fn until(f: impl Fn() -> bool) {
        for _ in 0..800 {
            if f() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    #[tokio::test]
    async fn a_new_attempt_voids_what_the_earlier_one_started() {
        let witness = Witness::default();
        let (mut early, counts, _env) = held_early(&witness);
        early.on_event(&StreamEvent::AttemptStart { attempt: 1 });
        early.on_event(&ready(0));
        let first = early.runs[&0].ctx.call_id.clone();
        early.on_event(&StreamEvent::AttemptStart { attempt: 2 });
        assert!(early.runs.is_empty());
        assert_eq!(counts_of(&counts), (1, 0, 1));
        // The new attempt starts again from its own first call, under a new id.
        early.on_event(&ready(0));
        assert_ne!(early.runs[&0].ctx.call_id, first);
        early.discard().await;
        assert_eq!(witness.live(), 0);
        assert_eq!(counts_of(&counts), (2, 0, 2));
    }

    #[tokio::test]
    async fn at_most_eight_early_calls_run_at_once() {
        let witness = Witness::default();
        let (mut early, counts, _env) = held_early(&witness);
        for i in 0..10 {
            early.on_event(&ready(i));
        }
        assert_eq!(early.runs.keys().copied().collect::<Vec<_>>(), (0..8).collect::<Vec<_>>());
        until(|| witness.live() == 8).await;
        assert_eq!(witness.peak.load(std::sync::atomic::Ordering::SeqCst), 8);
        // Once one has ended, a call that is ready next starts.
        early.runs[&0].ctx.cancel.cancel();
        until(|| early.runs[&0].task.handle.is_finished()).await;
        early.on_event(&ready(10));
        assert!(early.runs.contains_key(&10));
        assert_eq!(counts_of(&counts), (9, 0, 0));
        early.discard().await;
        assert_eq!(witness.live(), 0);
        assert_eq!(counts_of(&counts), (9, 0, 9));
    }

    #[tokio::test]
    async fn early_calls_a_new_attempt_dropped_count_until_they_have_ended() {
        let witness = Witness::default();
        let (mut early, counts, _env) = held_early(&witness);
        for i in 0..8 {
            early.on_event(&ready(i));
        }
        until(|| witness.live() == 8).await;
        // The new attempt stops them, but none has ended before the runtime gets to it.
        early.on_event(&StreamEvent::AttemptStart { attempt: 2 });
        early.on_event(&ready(0));
        assert!(early.runs.is_empty());
        until(|| early.dropped.iter().all(|t| t.handle.is_finished())).await;
        early.on_event(&ready(1));
        assert_eq!(early.runs.keys().copied().collect::<Vec<_>>(), [1]);
        early.discard().await;
        assert_eq!(witness.live(), 0);
        assert_eq!(counts_of(&counts), (9, 0, 9));
    }

    #[tokio::test]
    async fn an_early_call_starts_under_the_id_it_will_keep() {
        let witness = Witness::default();
        let (mut early, _, _env) = held_early(&witness);
        for (i, id) in [Some("s0"), Some("logged"), Some("s0"), None, Some("")].into_iter().enumerate() {
            early.on_event(&ready_as(u32::try_from(i).unwrap(), id));
        }
        let ids: Vec<String> = early.runs.values().map(|r| r.ctx.call_id.0.clone()).collect();
        // The server's id, unless the log or an earlier call of the attempt has it, or there is none.
        assert_eq!(ids.len(), 5);
        assert_eq!(ids[0], "s0");
        assert!(ids[1..].iter().all(|id| id.starts_with("call-")), "{ids:?}");
        assert_eq!(ids.iter().collect::<HashSet<_>>().len(), 5);
        // A new attempt may use the server's id again.
        early.on_event(&StreamEvent::AttemptStart { attempt: 2 });
        until(|| early.dropped.iter().all(|t| t.handle.is_finished())).await;
        early.on_event(&ready_as(0, Some("s0")));
        assert_eq!(early.runs[&0].ctx.call_id.0, "s0");
        early.discard().await;
    }

    #[tokio::test]
    async fn a_claim_given_up_while_it_waits_stops_the_early_call() {
        let witness = Witness::default();
        let (mut early, _, env) = held_early(&witness);
        early.on_event(&ready(0));
        until(|| witness.live() == 1).await;
        let run = early.runs.remove(&0).unwrap();
        let call = ToolCallRequest {
            call_id: run.ctx.call_id.clone(),
            name: "read".into(),
            arguments: run.arguments.clone(),
            complete: true,
        };
        let mut fx = Fx::new("chat", false, false, seq(vec![])).await;
        let session = fx.create();
        // The claim waits on a call that holds until it is cancelled; the session's future is dropped
        // (as when the runtime shuts down) and the turn's token is never cancelled.
        let claim = session.claim_early(run, &early, &env.ctx, &call);
        assert!(tokio::time::timeout(Duration::from_millis(50), claim).await.is_err());
        until(|| witness.live() == 0).await;
        assert_eq!(witness.live(), 0, "the early call was left running");
    }

    #[test]
    fn no_runtime_tool_starts_early() {
        let rig = crate::rtools::testkit::rig("lead", false, true);
        for name in crate::rtools::NAMES {
            assert!(!crate::rtools::tool(name, &rig.shared).unwrap().speculative(), "{name}");
        }
    }

    // ---- children ----------------------------------------------------------------------------

    /// A parent lead that ran one bash call and finished; returns its log path and the seq of the
    /// first tool result (a fork point where every call has its result).
    async fn parent_log() -> (Fx, std::path::PathBuf, Seq) {
        let mut fx = Fx::new("lead", false, true, lead_script()).await;
        let session = fx.create();
        run_with(session, vec![user("parent task")]).await;
        let upto = fx.sink.records().iter().find(|r| matches!(r.event, Event::ToolResult(_))).map(|r| r.seq).unwrap();
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
        assert_eq!(&kinds(&rs)[kinds(&rs).len() - 4..], ["tool_result", "child_completed", "turn_end", "session_end"]);
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
    async fn a_fork_from_a_parent_whose_prefix_does_not_chain_is_refused_and_leaves_no_log() {
        let (_parent, path, upto) = parent_log().await;
        // The parent's message altered in place: the record after it no longer chains to it.
        let text = std::fs::read_to_string(&path).unwrap();
        let altered = text.replacen("parent task", "parent tasK", 1);
        assert_ne!(altered, text);
        std::fs::write(&path, altered).unwrap();
        let mut kid = Fx::new("worker", true, true, seq(vec![finish_call("found it").into()])).await;
        let Err(e) = kid.try_fork(&path, upto, Budget::default()) else { panic!("the fork went through") };
        assert!(e.contains("cannot be forked") && e.contains("does not chain to the record before it"), "{e}");
        assert!(e.contains("Start the agent with mode `fresh`"), "{e}");
        assert!(!kid.log_path().exists());
        assert!(kid.sink.records().is_empty());
    }

    #[tokio::test]
    async fn a_root_whose_budget_ran_out_gets_a_fresh_budget_when_the_operator_writes() {
        let script = seq((0..10).map(|_| bash("echo x").into()).collect());
        let mut fx = Fx::new("lead", false, true, script).await;
        let session = fx.create_with(Budget { max_steps: Some(1), max_minutes: None }, None);
        let (tx, task) = spawn_run(session);
        tx.send(user("go")).unwrap();
        wait_until(&fx.sink, "the budget end", |rs| count(rs, "turn_end") == 1).await;
        assert_eq!(turn_ends(&fx.sink.records()), vec![TurnEndReason::BudgetExhausted]);
        assert_eq!(fx.server.requests().len(), 3);
        tx.send(user("keep going")).unwrap();
        wait_until(&fx.sink, "the second budget end", |rs| count(rs, "turn_end") == 2).await;
        let rs = fx.sink.records();
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::BudgetExhausted; 2]);
        assert_eq!(notes(&rs, NoteKind::Budget).len(), 2, "the new budget gets its own note");
        assert_eq!(fx.server.requests().len(), 6, "the second turn ran its own three steps");
        assert_eq!(inbox(&rs).len(), 2);
        // The model is told that the budget was renewed, right at the start of the second turn.
        assert_eq!(notes(&rs, NoteKind::Info), vec![texts::budget_renewed(Some(1), None)]);
        let second = rs.iter().rposition(|r| kind(r) == "turn_start").unwrap();
        assert!(
            matches!(
                rs.iter().skip(second + 1).find(|r| !matches!(r.event, Event::BudgetClock { .. })).map(|r| &r.event),
                Some(Event::HarnessNote { note: NoteKind::Info, .. })
            ),
            "{:?}",
            kinds(&rs)
        );
        assert!(all_text(&fx.server.requests()[3]).contains(&texts::budget_renewed(Some(1), None)));
        // The state block carries no running count; it warns only when the budget is nearly used,
        // measured from the turn that granted it. Fresh (step 0 of 1): no warning; over it (step 2 of 1):
        // a warning; renewed (step 0 of 1 again): the warning is gone.
        let huds: Vec<String> = fx.server.requests().iter().map(last_text).collect();
        assert!(!huds[0].contains("nearly used"), "{}", huds[0]);
        assert!(huds[2].contains("nearly used"), "{}", huds[2]);
        assert!(!huds[3].contains("nearly used"), "{}", huds[3]);
        // Reopened from the log, the session counts the same way.
        finish_task(tx, task).await;
        let reopened = Session::open(fx.deps()).unwrap();
        assert_eq!(reopened.st.budget_step_base, 3);
    }

    #[tokio::test]
    async fn fresh_and_forked_children_receive_live_operator_state_independently_of_the_brief() {
        let (_parent, path, upto) = parent_log().await;
        for fork in [false, true] {
            let mut kid = Fx::new("worker", true, true, seq(vec![finish_call("done").into()])).await;
            let journal = kid.shared.journal.as_ref().unwrap().clone();
            let operator = SessionId::from("s-lead");
            let goal = format!("{} GOAL_END", "operator goal ".repeat(80));
            let constraint = format!("{} CONSTRAINT_END", "standing rule ".repeat(80));
            let approval = format!("{} APPROVAL_END", "scoped permission ".repeat(80));
            for op in [
                LedgerOp::GoalSet { text: goal.clone() },
                LedgerOp::ConstraintAdd { text: constraint.clone() },
                LedgerOp::ApprovalGrant { text: approval.clone(), scope: "staging reads only".into() },
            ] {
                journal.append(&operator, true, op, &|_| Ok(())).unwrap();
            }
            let mut session = if fork {
                kid.fork(&path, upto, Budget::default())
            } else {
                kid.create_with(Budget::default(), Some((operator.clone(), "A deliberately minimal brief.".into())))
            };
            let first = session.render_hud().await;
            for text in [&goal, &constraint, &approval] {
                assert!(first.contains(text), "protected text must be complete in the HUD: {first}");
            }
            journal
                .append(&operator, true, LedgerOp::ConstraintAdd { text: "NEW_LIVE_RULE: do not push".into() }, &|_| {
                    Ok(())
                })
                .unwrap();
            let current = session.render_hud().await;
            assert!(current.contains("NEW_LIVE_RULE: do not push"));
            assert!(current.contains("Mission ledger access: notes and your own claims/evidence"));
            assert!(matches!(run_with(session, vec![]).await, End::Settled(_)));
            let request = &kid.server.requests()[0];
            let text = all_text(request);
            for protected in [&goal, &constraint, &approval] {
                assert!(text.contains(protected));
            }
            assert!(text.contains("NEW_LIVE_RULE: do not push"));
        }
    }

    #[tokio::test]
    async fn child_refuses_to_act_when_mission_state_cannot_be_verified() {
        let mut kid = Fx::new("worker", true, true, seq(vec![finish_call("must not run").into()])).await;
        let session = kid.create_with(Budget::default(), Some((SessionId::from("s-lead"), "inspect".into())));
        let path = kid.shared.journal.as_ref().unwrap().path();
        std::fs::write(path, "tampered\n").unwrap();
        let End::Settled(result) = run_with(session, vec![]).await else { panic!("settlement expected") };
        assert_eq!(result.outcome, ChildOutcome::Failed);
        assert!(result.report.contains("current mission state cannot be read"));
        assert!(kid.server.requests().is_empty());
    }

    #[tokio::test]
    async fn completed_child_outbox_is_terminal_before_session_end_is_written() {
        let mut kid = Fx::new("worker", true, true, seq(vec![])).await;
        let mut session = kid.create_with(Budget::default(), Some((SessionId::from("s-lead"), "inspect".into())));
        session.st.step = 4;
        session.st.usage =
            Usage { prompt_tokens: 1234, cached_tokens: 456, completion_tokens: 78, reasoning_tokens: 9 };
        let full = kid.ctx.blobs.put_bytes(b"complete long answer\n").unwrap();
        let result = session
            .settle(Delivery {
                outcome: ChildOutcome::Returned,
                report: "A complete report\nwith several lines".into(),
                full: Some(full),
                payload: json!({"accepted": false, "objections": ["unchecked output"], "opened": ["out:abcd"]}),
            })
            .await
            .unwrap();
        drop(session);
        let log = read_records(&kid.log_path()).unwrap();
        let (position, completed) = log
            .records
            .iter()
            .enumerate()
            .find_map(|(i, r)| match &r.event {
                Event::ChildCompleted(result) => Some((i, result.clone())),
                _ => None,
            })
            .unwrap();
        assert_eq!(completed.report, result.report);
        assert_eq!(completed.full, result.full);
        assert_eq!(completed.payload, result.payload);
        assert_eq!(completed.usage, result.usage);
        assert_eq!(completed.steps, result.steps);
        let text = std::fs::read_to_string(kid.log_path()).unwrap();
        std::fs::write(kid.log_path(), format!("{}\n", text.lines().take(position + 1).collect::<Vec<_>>().join("\n")))
            .unwrap();
        let reopened = Session::open(kid.deps()).unwrap();
        assert_eq!(reopened.status().phase, Phase::Ended);
        assert_eq!(reopened.status().outcome, Some(SessionOutcome::Done));
        assert_eq!(count(reopened.records(), "interrupted"), 0);
        assert_eq!(run_with(reopened, vec![]).await, End::Closed);
        assert!(kid.server.requests().is_empty());
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
        assert!(all_text(&kid.server.requests()[0])
            .contains("<harness kind=\"assignment\" from=\"s-lead\">\nCount the files.\n</harness>"));
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Error]);
        assert!(matches!(rs.last().unwrap().event, Event::SessionEnd { outcome: SessionOutcome::Failed, .. }));
    }

    #[tokio::test]
    async fn model_error_parks_a_lead_and_fails_a_child() {
        let bad =
            || Action::Status { status: 400, body: "{\"error\":{\"message\":\"nope\"}}".into(), retry_after_s: None };
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

    /// The bodies a script was sent, each with the wall-clock time it arrived.
    type Seen = Arc<Mutex<Vec<(u64, Value)>>>;

    /// A script that answers the first `down` requests with 503 and then plays `actions`, keeping
    /// every body it is sent.
    fn down_then(down: usize, actions: Vec<Action>) -> (Script, Seen) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let kept = seen.clone();
        let mut actions = std::collections::VecDeque::from(actions);
        let script = Script::new(move |body, n| {
            kept.lock().unwrap().push((now_ms(), body.clone()));
            if n < down {
                let body = r#"{"error":{"message":"the model is loading"}}"#.to_string();
                return Action::Status { status: 503, body, retry_after_s: None };
            }
            actions.pop_front().unwrap_or_else(|| Reply::text("(script exhausted)").into())
        });
        (script, seen)
    }

    /// Every `inbox_resolved` of `rs`: author, item id, answer.
    fn resolutions(rs: &[Record]) -> Vec<(Author, String, String)> {
        rs.iter()
            .filter_map(|r| match &r.event {
                Event::InboxResolved { item_id, answer } => Some((r.author.clone(), item_id.clone(), answer.clone())),
                _ => None,
            })
            .collect()
    }

    /// A fixture whose requests retry for `window_s` (0 = until the server answers) and whose sessions
    /// report a request that has retried for `notice_s`.
    async fn retrying_fx(script: Script, notice_s: u64, window_s: u64) -> Fx {
        let mut fx = Fx::new("chat", false, false, script).await;
        fx.profile.retry_window_s = window_s;
        fx.agents.unavailable_notice_s = notice_s;
        fx
    }

    #[tokio::test]
    async fn a_request_retrying_past_the_notice_time_opens_one_notice_that_closes_itself_when_the_reply_comes() {
        let (script, _) = down_then(3, vec![bash("echo hi").into(), Reply::text("done").into()]);
        let mut fx = retrying_fx(script, 1, 0).await;
        let session = fx.create();
        run_with(session, vec![user("go")]).await;
        let rs = fx.sink.records();
        let items = inbox(&rs);
        assert_eq!(items.len(), 1, "{:?}", kinds(&rs));
        let item = &items[0];
        assert_eq!((item.kind, item.blocking), (InboxKind::Blocker, false));
        assert!(item.call_id.is_none() && item.reference.is_none());
        let opening = format!("The model server at {} has been unavailable since ", fx.server.base_url());
        assert!(item.text.starts_with(&opening), "{}", item.text);
        assert!(item.text.contains("the model is loading"), "{}", item.text);
        assert!(item.text.contains("until the server answers"), "{}", item.text);
        // Resolved by the harness once the reply was in, before the reply was recorded.
        let k = kinds(&rs);
        let at = |what: &str| k.iter().position(|x| x == what).unwrap();
        assert!(at("model_request") < at("inbox_opened") && at("inbox_opened") < at("inbox_resolved"), "{k:?}");
        assert!(at("inbox_resolved") < at("model_response"), "{k:?}");
        let resolved = resolutions(&rs);
        assert_eq!(resolved.len(), 1);
        assert_eq!((&resolved[0].0, &resolved[0].1), (&Author::Harness, &item.item_id));
        let answer = &resolved[0].2;
        assert!(answer.starts_with("Answered automatically: the model server answered again at "), "{answer}");
        // The reply was handled as usual, and nothing else started a turn or is left open.
        assert_eq!(results(&rs).len(), 1);
        assert_eq!(count(&rs, "turn_start"), 1);
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Yielded]);
        assert_eq!(fx.sink.last_status().unwrap().open_inbox, 0);
        // The model's context holds nothing of it.
        let woven = serde_json::to_string(&weave(&rs).messages).unwrap();
        let next = serde_json::to_string(fx.server.requests().last().unwrap()).unwrap();
        for text in [woven, next] {
            assert!(!text.contains("has been unavailable since") && !text.contains("Answered automatically"), "{text}");
            assert!(!text.contains(&fx.server.base_url()), "{text}");
        }
        assert_no_cache_break(&rs);
    }

    #[tokio::test]
    async fn a_request_whose_attempts_keep_breaking_after_some_output_is_reported_too() {
        let broken = || Action::DropAfter { reply: Reply::text("x".repeat(200)), chunks: 2 };
        let mut fx = retrying_fx(seq(vec![broken(), broken(), broken(), Reply::text("done").into()]), 1, 0).await;
        let session = fx.create();
        run_with(session, vec![user("go")]).await;
        let rs = fx.sink.records();
        let items = inbox(&rs);
        assert_eq!(items.len(), 1, "{:?}", kinds(&rs));
        assert!(items[0].text.contains("mid-stream"), "{}", items[0].text);
        assert_eq!(resolutions(&rs).len(), 1);
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Yielded]);
    }

    #[tokio::test]
    async fn a_long_reply_after_an_early_failure_opens_no_notice() {
        let refused = Action::Status { status: 503, body: "loading".into(), retry_after_s: None };
        // The reply begins about 0.6 s after the failure, well before the notice is due at 2 s, and
        // streams for about three seconds, past that time.
        let slow = Reply::text("y".repeat(24 * 30)).with_delay_ms(100);
        let mut fx = retrying_fx(seq(vec![refused, slow.into()]), 2, 0).await;
        let session = fx.create();
        run_with(session, vec![user("go")]).await;
        let rs = fx.sink.records();
        assert!(inbox(&rs).is_empty(), "{:?}", kinds(&rs));
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Yielded]);
    }

    #[tokio::test]
    async fn a_reply_that_streams_past_the_notice_time_and_then_breaks_starts_a_new_outage() {
        let refused = || Action::Status { status: 503, body: "loading".into(), retry_after_s: None };
        // About 3.2 s of text, then the connection breaks.
        let long = Action::DropAfter { reply: Reply::text("z".repeat(24 * 32)).with_delay_ms(100), chunks: 33 };
        let (script, seen) =
            down_then(0, vec![refused(), long, refused(), refused(), refused(), Reply::text("done").into()]);
        let mut fx = retrying_fx(script, 2, 0).await;
        // Retries a second apart after the break: 1 s, 2 s, 3 s, then the reply at about 4 s.
        fx.profile.retry_max_delay_s = 1;
        let session = fx.create();
        run_with(session, vec![user("go")]).await;
        let rs = fx.sink.records();
        let items = inbox(&rs);
        assert_eq!(items.len(), 1, "{:?}", kinds(&rs));
        // Not at the break, although the request's first failure lay more than 2 s back by then: two
        // seconds after it, while the server was still refusing.
        let opened = rs.iter().find(|r| kind(r) == "inbox_opened").expect("a notice").ts_ms;
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 6);
        let times: Vec<u64> = seen.iter().map(|s| s.0).collect();
        assert!(opened > times[2], "the notice opened at the break: {opened} vs {times:?}");
        assert!(!items[0].text.contains(&texts::clock(seen[0].0)), "{}", items[0].text);
        assert_eq!(resolutions(&rs).len(), 1);
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Yielded]);
    }

    #[tokio::test]
    async fn the_retried_request_is_sent_unchanged_after_the_notice_opened() {
        let (script, seen) = down_then(3, vec![Reply::text("done").into()]);
        let mut fx = retrying_fx(script, 1, 0).await;
        let session = fx.create();
        run_with(session, vec![user("go")]).await;
        let rs = fx.sink.records();
        let opened = rs.iter().find(|r| kind(r) == "inbox_opened").expect("a notice").ts_ms;
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 4, "three refusals and the reply");
        assert!(seen.iter().any(|(t, _)| *t < opened), "an attempt before the notice");
        assert!(seen.iter().any(|(t, _)| *t > opened), "an attempt after the notice");
        let first = serde_json::to_vec(&seen[0].1).unwrap();
        for (_, body) in &seen[1..] {
            assert_eq!(serde_json::to_vec(body).unwrap(), first);
        }
    }

    #[tokio::test]
    async fn a_request_that_gives_up_resolves_its_notice_and_the_step_fails_as_before() {
        let (script, _) = down_then(usize::MAX, Vec::new());
        let mut fx = retrying_fx(script, 1, 2).await;
        let session = fx.create();
        run_with(session, vec![user("go")]).await;
        let rs = fx.sink.records();
        let items = inbox(&rs);
        assert_eq!(items.len(), 2, "{:?}", kinds(&rs));
        let (notice, parked) = (&items[0], &items[1]);
        assert_eq!((notice.kind, notice.blocking), (InboxKind::Blocker, false));
        assert!(notice.text.contains("until about ") && notice.text.contains("the request fails"), "{}", notice.text);
        let resolved = resolutions(&rs);
        assert_eq!(resolved.len(), 1);
        assert_eq!((&resolved[0].0, &resolved[0].1), (&Author::Harness, &notice.item_id));
        let answer = &resolved[0].2;
        assert!(answer.starts_with("Answered automatically: the request ended without a reply at "), "{answer}");
        assert!(answer.contains("the model is loading"), "{answer}");
        // The failure is handled as it always was: a blocking parked item, and the turn ends in error.
        assert_eq!((parked.kind, parked.blocking), (InboxKind::Parked, true));
        assert!(parked.text.contains("the model is loading"), "{}", parked.text);
        let k = kinds(&rs);
        assert_eq!(&k[k.len() - 4..], ["inbox_opened", "inbox_resolved", "inbox_opened", "turn_end"]);
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Error]);
        assert_eq!(fx.sink.last_status().unwrap().open_inbox, 1);
    }

    #[tokio::test]
    async fn no_notice_is_opened_when_the_retry_window_ends_first() {
        let (script, seen) = down_then(usize::MAX, Vec::new());
        // The notice would be due as the window ends; the request fails at the attempt after that.
        let mut fx = retrying_fx(script, 1, 1).await;
        let session = fx.create();
        run_with(session, vec![user("go")]).await;
        let rs = fx.sink.records();
        assert!(seen.lock().unwrap().len() >= 3, "the request retried past the notice time");
        let items = inbox(&rs);
        assert_eq!(items.len(), 1, "{:?}", kinds(&rs));
        assert_eq!((items[0].kind, items[0].blocking), (InboxKind::Parked, true));
        assert!(items[0].text.contains("the model is loading"), "{}", items[0].text);
        assert!(resolutions(&rs).is_empty());
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Error]);
    }

    #[tokio::test]
    async fn no_notice_is_opened_when_unavailable_notice_s_is_zero() {
        let (script, seen) = down_then(3, vec![Reply::text("done").into()]);
        let mut fx = retrying_fx(script, 0, 0).await;
        let session = fx.create();
        run_with(session, vec![user("go")]).await;
        let rs = fx.sink.records();
        assert_eq!(seen.lock().unwrap().len(), 4, "the request retried past where a notice would open");
        assert!(inbox(&rs).is_empty() && resolutions(&rs).is_empty(), "{:?}", kinds(&rs));
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Yielded]);
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
        assert_eq!(&kinds(&rs)[kinds(&rs).len() - 2..], ["interrupted", "turn_end"]);
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
    async fn a_stop_while_the_request_retries_resolves_its_notice() {
        let (script, _) = down_then(usize::MAX, Vec::new());
        let mut fx = retrying_fx(script, 1, 0).await;
        let session = fx.create();
        let (tx, task) = spawn_run(session);
        tx.send(user("go")).unwrap();
        wait_until(&fx.sink, "the notice", |rs| count(rs, "inbox_opened") == 1).await;
        fx.control.stop_turn();
        wait_until(&fx.sink, "turn end", |rs| count(rs, "turn_end") == 1).await;
        let rs = fx.sink.records();
        let k = kinds(&rs);
        assert_eq!(&k[k.len() - 3..], ["inbox_resolved", "interrupted", "turn_end"]);
        let resolved = resolutions(&rs);
        assert_eq!((&resolved[0].0, &resolved[0].1), (&Author::Harness, &inbox(&rs)[0].item_id));
        let answer = &resolved[0].2;
        let stopped = "Answered automatically: the step that was waiting for the model server was stopped";
        assert!(answer.starts_with(stopped), "{answer}");
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Stopped]);
        assert_eq!(fx.sink.last_status().unwrap().open_inbox, 0);
        assert_eq!(finish_task(tx, task).await, End::Closed);
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
        assert_eq!(&kinds(&rs)[kinds(&rs).len() - 3..], ["tool_result", "interrupted", "turn_end"]);
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

    #[tokio::test]
    async fn an_idle_stop_is_sticky_until_the_operator_writes_again() {
        let script = seq(vec![
            Reply::tool("bash", json!({ "command": "sleep 60", "background": true }).to_string()).into(),
            Reply::tool("wait", json!({}).to_string()).into(),
            finish_call("done").into(),
        ]);
        let mut fx = Fx::new("lead", false, true, script).await;
        let session = fx.create();
        let (tx, task) = spawn_run(session);
        tx.send(user("go")).unwrap();
        wait_until(&fx.sink, "waiting", |rs| turn_ends(rs) == vec![TurnEndReason::Waiting]).await;
        tx.send(Input::Stop).unwrap();
        wait_until(&fx.sink, "the stop", |rs| turn_ends(rs).len() == 2).await;
        let settlement = Settlement {
            child: SessionId::from("s-kid9"),
            role: "worker".into(),
            outcome: ChildOutcome::Stopped,
            report: "stopped".into(),
            full: None,
            payload: Value::Null,
            steps: 1,
            usage: Usage::default(),
        };
        tx.send(Input::ChildSettled(settlement)).unwrap();
        wait_until(&fx.sink, "the job end and the settlement", |rs| {
            count(rs, "job_settled") == 1 && count(rs, "child_settled") == 1
        })
        .await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let rs = fx.sink.records();
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Waiting, TurnEndReason::Stopped]);
        assert_eq!(count(&rs, "turn_start"), 1, "nothing may start a turn after the stop: {:?}", kinds(&rs));
        assert_eq!(fx.sink.last_status().unwrap().last_end, Some(TurnEndReason::Stopped));
        assert_eq!(fx.server.requests().len(), 2);
        // The operator writing again runs the session.
        tx.send(user("carry on")).unwrap();
        wait_until(&fx.sink, "the next turn", |rs| count(rs, "turn_end") == 3).await;
        let rs = fx.sink.records();
        assert_eq!(turn_ends(&rs).last(), Some(&TurnEndReason::Finished));
        assert_eq!(notes(&rs, NoteKind::Interrupted), vec![texts::AFTER_IDLE_STOP.to_string()]);
        finish_task(tx, task).await;
    }

    #[tokio::test]
    async fn stopping_an_idle_child_settles_it_stopped() {
        let script = seq(vec![
            Reply::tool("bash", json!({ "command": "sleep 60", "background": true }).to_string()).into(),
            Reply::tool("wait", json!({}).to_string()).into(),
        ]);
        let mut kid = Fx::new("worker", true, true, script).await;
        let session = kid.create_with(Budget::default(), Some((SessionId::from("s-lead"), "Run it.".into())));
        let (tx, task) = spawn_run(session);
        wait_until(&kid.sink, "waiting", |rs| turn_ends(rs) == vec![TurnEndReason::Waiting]).await;
        tx.send(Input::Stop).unwrap();
        let end = tokio::time::timeout(Duration::from_secs(30), task).await.expect("the child did not settle").unwrap();
        let End::Settled(s) = end else { panic!("expected a settlement, got {end:?}") };
        assert_eq!(s.outcome, ChildOutcome::Stopped);
        assert_eq!(s.report, texts::stopped_report(2));
        let rs = kid.sink.records();
        assert!(matches!(rs.last().unwrap().event, Event::SessionEnd { outcome: SessionOutcome::Stopped, .. }));
        assert!(kid.ctx.jobs.list().await.iter().all(|j| j.state != JobState::Running));
        drop(tx);
    }

    #[tokio::test]
    async fn an_idle_child_whose_inputs_close_settles_unless_the_harness_is_shutting_down() {
        let script = || {
            seq(vec![
                Reply::tool("bash", json!({ "command": "sleep 60", "background": true }).to_string()).into(),
                Reply::tool("wait", json!({}).to_string()).into(),
            ])
        };
        let mut kid = Fx::new("worker", true, true, script()).await;
        let session = kid.create_with(Budget::default(), Some((SessionId::from("s-lead"), "Run it.".into())));
        let (tx, task) = spawn_run(session);
        wait_until(&kid.sink, "waiting", |rs| turn_ends(rs) == vec![TurnEndReason::Waiting]).await;
        let end = finish_task(tx, task).await;
        let End::Settled(s) = end else { panic!("expected a settlement, got {end:?}") };
        assert_eq!((s.outcome, s.report), (ChildOutcome::Stopped, texts::stopped_report(2)));
        let rs = kid.sink.records();
        assert!(rs
            .iter()
            .any(|r| matches!(&r.event, Event::Interrupted { reason } if reason == texts::REASON_OPERATOR)));
        assert!(matches!(rs.last().unwrap().event, Event::SessionEnd { outcome: SessionOutcome::Stopped, .. }));
        assert!(kid.ctx.jobs.list().await.iter().all(|j| j.state != JobState::Running));

        // Closed by a shutdown: cut, for the next start to resume.
        let mut kid = Fx::new("worker", true, true, script()).await;
        let session = kid.create_with(Budget::default(), Some((SessionId::from("s-lead"), "Run it.".into())));
        let (tx, task) = spawn_run(session);
        wait_until(&kid.sink, "waiting", |rs| turn_ends(rs) == vec![TurnEndReason::Waiting]).await;
        kid.control.stop_for_shutdown();
        assert_eq!(finish_task(tx, task).await, End::Closed);
        assert_eq!(count(&kid.sink.records(), "session_end"), 0);
    }

    #[tokio::test]
    async fn an_idle_stop_with_nothing_running_is_what_the_next_turn_is_told_about() {
        let script = seq(vec![Reply::text("first").into(), Reply::text("second").into()]);
        let mut fx = Fx::new("chat", false, false, script).await;
        let mut session = fx.create();
        // An old restart cut, long settled: it must not be mistaken for the reason of the next stop.
        session.append(Author::Harness, Event::Interrupted { reason: texts::REASON_RESTART.to_string() }).unwrap();
        let (tx, task) = spawn_run(session);
        tx.send(user("hi")).unwrap();
        wait_until(&fx.sink, "the yield", |rs| count(rs, "turn_end") == 1).await;
        tx.send(Input::Stop).unwrap();
        tx.send(user("again")).unwrap();
        wait_until(&fx.sink, "the next turn", |rs| count(rs, "turn_end") == 3).await;
        let rs = fx.sink.records();
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Yielded, TurnEndReason::Stopped, TurnEndReason::Yielded]);
        let stop =
            rs.iter().position(|r| matches!(r.event, Event::TurnEnd { reason: TurnEndReason::Stopped })).unwrap();
        assert!(matches!(&rs[stop - 1].event, Event::Interrupted { reason } if reason == texts::REASON_OPERATOR));
        // Nothing was running: the next turn is not told that a call was interrupted.
        assert_eq!(notes(&rs, NoteKind::Interrupted), vec![texts::AFTER_IDLE_STOP.to_string()]);
        assert!(!texts::AFTER_IDLE_STOP.contains("interrupted"));
        // A session opened from the log reads the stop the same way.
        assert_eq!(finish_task(tx, task).await, End::Closed);
        assert!(Session::open(fx.deps()).unwrap().st.stopped_idle);
    }

    #[tokio::test]
    async fn a_stop_that_lands_while_a_trigger_is_queued_is_honoured() {
        let mut fx = Fx::new("chat", false, false, seq(vec![Reply::text("after the stop").into()])).await;
        let session = fx.create();
        // The stop is queued behind the message that starts the turn, and another message behind it.
        run_with(session, vec![user("go"), Input::Stop, user("again")]).await;
        let rs = fx.sink.records();
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Stopped, TurnEndReason::Yielded], "{:?}", kinds(&rs));
        assert_eq!(count(&rs, "interrupted"), 1);
        let reqs = fx.server.requests();
        assert_eq!(reqs.len(), 1, "only the message sent after the stop costs a request");
        assert!(all_text(&reqs[0]).contains("again") && all_text(&reqs[0]).contains(texts::AFTER_STOP));
        // A resume sent after the stop runs the session as well.
        let mut fx = Fx::new("chat", false, false, seq(vec![Reply::text("resumed").into()])).await;
        let session = fx.create();
        run_with(session, vec![user("go"), Input::Stop, Input::Resume]).await;
        let rs = fx.sink.records();
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Stopped, TurnEndReason::Yielded], "{:?}", kinds(&rs));
        assert!(rs.iter().any(|r| matches!(r.event, Event::TurnStart { trigger: Trigger::Resume })));
        assert_eq!(fx.server.requests().len(), 1);
    }

    // ---- open --------------------------------------------------------------------------------

    #[tokio::test]
    async fn open_reproduces_the_state_of_the_session_that_wrote_the_log() {
        let mut fx = Fx::new("chat", false, false, seq(vec![big(), big(), big(), Reply::text("ok").into()])).await;
        fx.context =
            ReweavePolicy { target_tokens: 12_000, floor_tokens: 10_000, keep_recent_steps: 1, stub_tail_lines: 3 };
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
    async fn a_reopened_session_checks_its_first_request_against_the_one_before_the_restart() {
        let mut fx =
            Fx::new("chat", false, false, seq(vec![Reply::text("first").into(), Reply::text("second").into()])).await;
        let session = fx.create();
        run_with(session, vec![user("hi")]).await;
        let reopened = Session::open(fx.deps()).unwrap();
        assert_eq!(count(reopened.records(), "cache_break"), 0);
        // Primed: a first request that changed what was sent before the restart would be a break.
        let mut changed = weave(reopened.records()).messages;
        changed[0] = Message::system("another system prompt");
        let mut probe = reopened.guard.clone();
        assert!(matches!(probe.check(0, &changed), PrefixCheck::Break { first_diff_message: 0, .. }));
        // The log is unchanged, so the real first request extends the last one.
        run_with(reopened, vec![user("again")]).await;
        assert_eq!(fx.server.requests().len(), 2);
        assert_no_cache_break(&fx.sink.records());
    }

    #[tokio::test]
    async fn a_log_that_renders_differently_after_a_restart_gets_one_cache_break() {
        let mut fx = Fx::new("chat", false, false, seq(vec![Reply::text("after").into()])).await;
        let mut session = fx.create();
        session.append(Author::User, Event::UserMessage { text: "hi".into() }).unwrap();
        session.append(Author::Harness, Event::TurnStart { trigger: Trigger::User }).unwrap();
        let sent = weave(session.records()).messages;
        // What an older build sent for these records hashed differently.
        let request = ModelRequest {
            req_id: "r-old".into(),
            step: 1,
            epoch: 0,
            purpose: Purpose::Step,
            n_messages: to_u32(sent.len()),
            stable_hash: "0".repeat(64),
            hud: None,
            est_tokens: 0,
        };
        session.append(Author::Harness, Event::ModelRequest(request)).unwrap();
        let reply = ModelResponse {
            req_id: "r-old".into(),
            text: "hello".into(),
            reasoning: String::new(),
            tool_calls: Vec::new(),
            finish: FinishReason::Stop,
            usage: Usage::default(),
            timing: Timing::default(),
            attempts: 1,
        };
        session.append(Author::Model, Event::ModelResponse(reply)).unwrap();
        session.append(Author::Harness, Event::TurnEnd { reason: TurnEndReason::Yielded }).unwrap();
        drop(session);
        let reopened = Session::open(fx.deps()).unwrap();
        let breaks: Vec<Record> = reopened.records().iter().filter(|r| kind(r) == "cache_break").cloned().collect();
        assert_eq!(breaks.len(), 1);
        let Event::CacheBreak { req_id, first_diff_message, detail } = &breaks[0].event else {
            panic!("a cache_break")
        };
        assert_eq!((req_id.as_str(), *first_diff_message), ("r-old", 0));
        assert_eq!(detail, &texts::rendering_changed(to_u32(sent.len()), sent.len()));
        assert!(detail.contains("changed across the restart"));
        // Reported once: opening again with no request since adds nothing.
        drop(reopened);
        let again = Session::open(fx.deps()).unwrap();
        assert_eq!(count(again.records(), "cache_break"), 1);
        // The session carries on, and its next request extends the prefix as it renders now.
        run_with(again, vec![user("more")]).await;
        assert_eq!(count(&read_records(&fx.log_path()).unwrap().records, "cache_break"), 1);
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
    async fn a_notice_left_open_when_the_session_stopped_is_resolved_when_it_runs_again() {
        let mut fx = Fx::new("chat", false, false, seq(vec![])).await;
        let mut session = fx.create();
        let item = |id: &str, kind: InboxKind, blocking: bool, text: String| InboxItem {
            item_id: id.into(),
            kind,
            text,
            options: Vec::new(),
            blocking,
            call_id: None,
            reference: None,
        };
        let text = texts::model_unavailable("http://127.0.0.1:9/v1", "then", "refused", None);
        session.append(Author::Harness, Event::InboxOpened(item("i-down", InboxKind::Blocker, false, text))).unwrap();
        // An item waiting for the operator stays open.
        let parked = item("i-parked", InboxKind::Parked, true, texts::turn_failed("It broke."));
        session.append(Author::Harness, Event::InboxOpened(parked)).unwrap();
        drop(session);
        let reopened = Session::open(fx.deps()).unwrap();
        assert_eq!(reopened.status().open_inbox, 2);
        assert_eq!(run_with(reopened, vec![]).await, End::Closed);
        let rs = read_records(&fx.log_path()).unwrap().records;
        let left_open = texts::UNAVAILABLE_LEFT_OPEN.to_string();
        assert_eq!(resolutions(&rs), vec![(Author::Harness, "i-down".to_string(), left_open)]);
        assert_eq!(count(&rs, "turn_start"), 0);
        assert_eq!(fx.sink.last_status().unwrap().open_inbox, 1);
        assert!(fx.server.requests().is_empty());
    }

    #[tokio::test]
    async fn open_settles_unsettled_jobs_and_notes_those_the_model_was_not_told_about() {
        let mut fx = Fx::new("chat", false, false, seq(vec![])).await;
        let mut session = fx.create();
        let job = |id: &str, command: &str| Event::JobRegistered {
            job_id: id.into(),
            call_id: CallId::from("c1"),
            command: command.into(),
        };
        // j1 is from before a restart the model was told about; j2 was running when the harness went down.
        session.append(Author::Harness, Event::TurnStart { trigger: Trigger::User }).unwrap();
        session.append(Author::Harness, job("j1", "make old")).unwrap();
        session.append(Author::Harness, Event::Interrupted { reason: texts::REASON_RESTART.into() }).unwrap();
        session.append(Author::Harness, Event::TurnEnd { reason: TurnEndReason::Stopped }).unwrap();
        session.append(Author::Harness, Event::TurnStart { trigger: Trigger::Resume }).unwrap();
        session.note(Author::Harness, NoteKind::Interrupted, "told about the restart".into()).unwrap();
        session.append(Author::Harness, job("j2", "sleep 600")).unwrap();
        session.append(Author::Harness, Event::TurnEnd { reason: TurnEndReason::Waiting }).unwrap();
        drop(session);
        let before = fx.sink.records().len();
        let reopened = Session::open(fx.deps()).unwrap();
        assert_eq!(reopened.pending_job_ends(), 1);
        assert_eq!(reopened.status().last_end, Some(TurnEndReason::Waiting));
        let added = reopened.records()[before..].to_vec();
        assert_eq!(kinds(&added), ["job_settled", "job_settled", "harness_note"]);
        for (r, id) in added.iter().zip(["j1", "j2"]) {
            assert_eq!(r.author, Author::Tool);
            assert!(
                matches!(&r.event, Event::JobSettled { job_id, exit_code: None, output: None, detail }
                if job_id == id && detail == texts::JOB_LOST_DETAIL),
                "{r:?}"
            );
        }
        assert_eq!(notes(&added, NoteKind::Arrival), vec![texts::job_lost("j2", "sleep 600")]);
        let len = reopened.records().len();
        drop(reopened);
        // Settled once: the next open has nothing to add, and the turn the note asks for is still owed.
        let again = Session::open(fx.deps()).unwrap();
        assert_eq!((again.pending_job_ends(), again.records().len()), (1, len));
    }

    impl Fx {
        fn jobs_dir(&self) -> PathBuf {
            self.ctx.tmp_dir.parent().unwrap().join("home/jobs")
        }

        /// The job table the next daemon builds over the session's jobs directory: it sweeps what the
        /// previous daemon left there.
        fn restart_jobs(&mut self) {
            let (tx, rx) = unbounded_channel();
            self.job_events = Some(rx);
            let (dir, blobs, max) = (self.jobs_dir(), self.ctx.blobs.clone(), self.ctx.cfg.max_output_bytes);
            self.ctx.jobs = Arc::new(loom_tools::jobs::JobTable::new(dir, blobs, tx, max));
        }
    }

    /// What a command `id` of a previous daemon left in `dir` after it had ended: its pid record (naming
    /// a process that is gone), its output and its status file.
    fn left_behind(dir: &Path, id: &str, out: &str, status: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(format!("{id}.pid")), "999999 1\nowner 1 1.000000\n").unwrap();
        std::fs::write(dir.join(format!("{id}.out")), out).unwrap();
        std::fs::write(dir.join(format!("{id}.status")), status).unwrap();
    }

    /// The `bash` call `call` that started `command` as job `id`, and its result, which gives the job
    /// to the model.
    fn give_job(session: &mut Session, call: &str, id: &str, command: &str) {
        let args = json!({ "command": command, "background": true });
        let (call_id, class) = (CallId::from(call), ToolClass::Exec);
        let c = ToolCall { call_id, req_id: "r-1".into(), name: "bash".into(), args, class };
        session.append(Author::Model, Event::ToolCall(c)).unwrap();
        let result = loom_core::event::ToolResult {
            call_id: CallId::from(call),
            name: "bash".into(),
            status: ToolStatus::Ok,
            text: format!("started as job {id}"),
            output: None,
            cut: false,
            class: ToolClass::Exec,
            meta: [(META_JOB.to_string(), json!(id))].into_iter().collect(),
            duration_ms: 1,
        };
        session.append(Author::Tool, Event::ToolResult(result)).unwrap();
    }

    #[tokio::test]
    async fn open_settles_jobs_that_finished_while_the_harness_was_down_with_their_status_and_output() {
        let mut fx = Fx::new("chat", false, false, seq(vec![])).await;
        let mut session = fx.create();
        // j1 was registered. j2 was given to the model by its call's result, but the harness went down
        // before its registration reached the log. j3 was a foreground command, never a job.
        session.append(Author::Harness, Event::TurnStart { trigger: Trigger::User }).unwrap();
        let registered =
            Event::JobRegistered { job_id: "j1".into(), call_id: CallId::from("c1"), command: "make test".into() };
        session.append(Author::Harness, registered).unwrap();
        give_job(&mut session, "c2", "j2", "make all");
        session.append(Author::Harness, Event::TurnEnd { reason: TurnEndReason::Waiting }).unwrap();
        drop(session);
        // All three ended while no harness was there to see it.
        let dir = fx.jobs_dir();
        left_behind(&dir, "j1", "built\nfailed\n", "3\n");
        left_behind(&dir, "j2", "all done\n", "0\n");
        left_behind(&dir, "j3", "half", "0\n");
        fx.restart_jobs();
        let before = fx.sink.records().len();
        let reopened = Session::open(fx.deps()).unwrap();
        let added = reopened.records()[before..].to_vec();
        assert_eq!(kinds(&added), ["job_settled", "harness_note", "job_registered", "job_settled", "harness_note"]);
        let Event::JobSettled { job_id, exit_code, output, detail } = &added[0].event else { panic!("{:?}", added[0]) };
        assert_eq!((job_id.as_str(), *exit_code, detail.clone()), ("j1", Some(3), texts::job_ended_while_down("")));
        let blob = output.clone().expect("stored");
        assert_eq!(fx.ctx.blobs.read_all(&blob.id).unwrap(), b"built\nfailed\n");
        assert_eq!(added[0].author, Author::Tool);
        let arrivals = notes(&added, NoteKind::Arrival);
        assert!(
            arrivals[0].starts_with("Background job j1 ended: exit 3. It finished while the harness was down"),
            "{}",
            arrivals[0]
        );
        assert!(arrivals[0].contains("make test") && arrivals[0].contains("failed"), "{}", arrivals[0]);
        assert_eq!(added[2].author, Author::Harness);
        assert!(
            matches!(&added[2].event, Event::JobRegistered { job_id, call_id, command }
            if job_id == "j2" && *call_id == CallId::from("c2") && command == "make all"),
            "{:?}",
            added[2]
        );
        assert!(
            matches!(&added[3].event, Event::JobSettled { job_id, exit_code: Some(0), output: Some(_), .. } if job_id == "j2")
        );
        assert!(
            arrivals[1].starts_with("Background job j2 ended: exit 0.") && arrivals[1].contains("all done"),
            "{}",
            arrivals[1]
        );
        // A session that was waiting is woken for them.
        assert_eq!(reopened.pending_job_ends(), 2);
        // Taken: their files are gone, the foreground command's too, and no id with files is handed out again.
        for id in ["j1", "j2", "j3"] {
            for ext in ["pid", "out", "status"] {
                assert!(!dir.join(format!("{id}.{ext}")).exists(), "{id}.{ext}");
            }
        }
        assert_eq!(fx.ctx.jobs.allocate().await.unwrap().0, "j4");
        let len = reopened.records().len();
        drop(reopened);
        fx.restart_jobs();
        let again = Session::open(fx.deps()).unwrap();
        assert_eq!((again.pending_job_ends(), again.records().len()), (2, len));
    }

    #[tokio::test]
    async fn open_registers_and_settles_a_job_its_watcher_ended_before_either_record_reached_the_log() {
        let mut fx = Fx::new("chat", false, false, seq(vec![])).await;
        let mut session = fx.create();
        // j2 was given to the model before a restart it was told about; j3 and j4 in the turn that waits.
        session.append(Author::Harness, Event::TurnStart { trigger: Trigger::User }).unwrap();
        give_job(&mut session, "c2", "j2", "make old");
        session.append(Author::Harness, Event::Interrupted { reason: texts::REASON_RESTART.into() }).unwrap();
        session.append(Author::Harness, Event::TurnEnd { reason: TurnEndReason::Stopped }).unwrap();
        session.append(Author::Harness, Event::TurnStart { trigger: Trigger::Resume }).unwrap();
        session.note(Author::Harness, NoteKind::Interrupted, "told about the restart".into()).unwrap();
        give_job(&mut session, "c3", "j3", "make all");
        give_job(&mut session, "c4", "j4", "make docs");
        session.append(Author::Harness, Event::TurnEnd { reason: TurnEndReason::Waiting }).unwrap();
        drop(session);
        // j3 ended while the harness was still up: its watcher removed its pid record, so the next table's
        // sweep does not find it. Nothing is left of j2 and j4.
        let dir = fx.jobs_dir();
        left_behind(&dir, "j3", "all done\n", "0\n");
        std::fs::remove_file(dir.join("j3.pid")).unwrap();
        fx.restart_jobs();
        assert!(fx.ctx.jobs.leftovers().is_empty());
        let before = fx.sink.records().len();
        let reopened = Session::open(fx.deps()).unwrap();
        let added = reopened.records()[before..].to_vec();
        let (registered, settled, note) = ("job_registered", "job_settled", "harness_note");
        assert_eq!(kinds(&added), [registered, settled, registered, settled, note, registered, settled, note]);
        assert!(
            matches!(&added[0].event, Event::JobRegistered { job_id, call_id, command }
            if job_id == "j2" && *call_id == CallId::from("c2") && command == "make old"),
            "{:?}",
            added[0]
        );
        assert!(
            matches!(&added[1].event, Event::JobSettled { job_id, exit_code: None, detail, .. }
            if job_id == "j2" && detail == texts::JOB_LOST_DETAIL),
            "{:?}",
            added[1]
        );
        assert!(
            matches!(&added[2].event, Event::JobRegistered { job_id, call_id, command }
            if job_id == "j3" && *call_id == CallId::from("c3") && command == "make all"),
            "{:?}",
            added[2]
        );
        let Event::JobSettled { exit_code: Some(0), output: Some(blob), .. } = &added[3].event else {
            panic!("{:?}", added[3])
        };
        assert_eq!(fx.ctx.blobs.read_all(&blob.id).unwrap(), b"all done\n");
        let arrivals = notes(&added, NoteKind::Arrival);
        let ended = "Background job j3 ended: exit 0. It finished while the harness was down";
        assert!(arrivals[0].starts_with(ended), "{arrivals:?}");
        let lost = matches!(&added[6].event, Event::JobSettled { job_id, exit_code: None, .. } if job_id == "j4");
        assert!(lost, "{:?}", added[6]);
        assert_eq!(arrivals[1], texts::job_lost("j4", "make docs"));
        // The session that waits for them is woken; j2 was covered by the note on the earlier restart.
        assert_eq!(reopened.pending_job_ends(), 2);
        assert!(["out", "status"].iter().all(|x| !dir.join(format!("j3.{x}")).exists()));
        // j4 left no file, but its registration is in the log now: its id is not handed out again.
        assert_eq!(fx.ctx.jobs.allocate().await.unwrap().0, "j5");
    }

    #[tokio::test]
    async fn open_reports_a_job_still_running_at_the_restart_as_lost_once_the_sweep_has_killed_it() {
        let mut fx = Fx::new("chat", false, false, seq(vec![])).await;
        let mut session = fx.create();
        session.append(Author::Harness, Event::TurnStart { trigger: Trigger::User }).unwrap();
        let registered =
            Event::JobRegistered { job_id: "j1".into(), call_id: CallId::from("c1"), command: "sleep 300".into() };
        session.append(Author::Harness, registered).unwrap();
        session.append(Author::Harness, Event::TurnEnd { reason: TurnEndReason::Waiting }).unwrap();
        drop(session);
        // Its command still runs, under the record of the previous daemon.
        let dir = fx.jobs_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let env = [("PATH", "/usr/bin:/bin")].iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let spec = loom_tools::proc::Spawn {
            script: "sleep 300".into(),
            cwd: fx.ctx.workspace.clone(),
            env,
            out_path: dir.join("j1.out"),
            exit_path: dir.join("j1.status"),
        };
        let mut running = loom_tools::proc::spawn(&fx.ctx.sandbox, &spec).unwrap();
        running.disarm();
        let record = std::fs::read_to_string(dir.join("j1.pid")).unwrap();
        let kept: String = record.lines().filter(|l| !l.starts_with("owner ")).map(|l| format!("{l}\n")).collect();
        std::fs::write(dir.join("j1.pid"), format!("{kept}owner 1 1.000000\n")).unwrap();
        fx.restart_jobs();
        let before = fx.sink.records().len();
        let reopened = Session::open(fx.deps()).unwrap();
        // The sweep killed it: what it would have done is unknown.
        let mut killed = false;
        for _ in 0..400 {
            if running.poll().is_some() {
                killed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(killed, "the previous daemon's command was not killed");
        let added = reopened.records()[before..].to_vec();
        assert_eq!(kinds(&added), ["job_settled", "harness_note"]);
        assert!(
            matches!(&added[0].event, Event::JobSettled { job_id, exit_code: None, output: None, detail }
            if job_id == "j1" && detail == texts::JOB_LOST_DETAIL),
            "{:?}",
            added[0]
        );
        assert_eq!(notes(&added, NoteKind::Arrival), vec![texts::job_lost("j1", "sleep 300")]);
        assert_eq!(reopened.pending_job_ends(), 1);
        for ext in ["pid", "out", "status"] {
            assert!(!dir.join(format!("j1.{ext}")).exists(), "j1.{ext}");
        }
    }

    #[tokio::test]
    async fn a_turn_that_begins_during_shutdown_is_cut_without_the_restart_note() {
        let mut fx = Fx::new("chat", false, false, seq(vec![Reply::text("welcome back").into()])).await;
        let mut session = fx.create();
        session.append(Author::User, Event::UserMessage { text: "hi".into() }).unwrap();
        session.append(Author::Harness, Event::TurnStart { trigger: Trigger::User }).unwrap();
        drop(session);
        let reopened = Session::open(fx.deps()).unwrap();
        // A message is still queued when the harness goes down.
        fx.control.stop_for_shutdown();
        // The runtime runs each session in an owning task. Join it before opening the next writer.
        let (tx, task) = spawn_run(reopened);
        tx.send(user("one more thing")).unwrap();
        assert_eq!(finish_task(tx, task).await, End::Closed);
        let rs = fx.sink.records();
        assert_eq!(&kinds(&rs)[kinds(&rs).len() - 4..], ["user_message", "turn_start", "interrupted", "turn_end"]);
        assert!(notes(&rs, NoteKind::Interrupted).is_empty());
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Stopped, TurnEndReason::Stopped]);
        assert!(fx.server.requests().is_empty());
        // What the runtime reads at the next start: a session that was running.
        assert_eq!(fx.sink.last_status().unwrap().phase, Phase::Running);
        // After the restart the note is given, once.
        fx.control = Arc::new(Control::new());
        let restarted = Session::open(fx.deps()).unwrap();
        run_with(restarted, vec![Input::Resume]).await;
        assert_eq!(notes(&fx.sink.records(), NoteKind::Interrupted), vec![texts::AFTER_RESTART.to_string()]);
    }

    #[tokio::test]
    async fn a_turn_cut_by_shutdown_records_its_jobs_and_does_not_settle_a_child() {
        let script = seq(vec![
            Reply::tool("bash", json!({ "command": "sleep 600", "background": true }).to_string()).into(),
            Reply::text("slow").with_delay_ms(20_000).into(),
        ]);
        let mut kid = Fx::new("worker", true, true, script).await;
        let session = kid.create_with(Budget::default(), Some((SessionId::from("s-lead"), "Run it.".into())));
        let (tx, task) = spawn_run(session);
        wait_until(&kid.sink, "the second request", |rs| count(rs, "model_request") == 2).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        kid.control.stop_for_shutdown();
        // Not settled: the child is resumed by the next start.
        assert_eq!(finish_task(tx, task).await, End::Closed);
        let rs = kid.sink.records();
        let reasons: Vec<String> = rs
            .iter()
            .filter_map(|r| match &r.event {
                Event::Interrupted { reason } => Some(reason.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(reasons, vec![texts::REASON_RESTART.to_string()]);
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Stopped]);
        assert_eq!(count(&rs, "session_end"), 0);
        // The job killed with the turn is settled in the log, before the turn's end.
        let settled = rs.iter().position(|r| matches!(r.event, Event::JobSettled { .. })).expect("job_settled");
        let end = rs.iter().position(|r| matches!(r.event, Event::TurnEnd { .. })).unwrap();
        assert!(settled < end, "{:?}", kinds(&rs));
        assert!(notes(&rs, NoteKind::Arrival).iter().any(|n| n.contains("Background job j1 ended: killed")));
        assert_eq!(kid.sink.last_status().unwrap().phase, Phase::Running);
        // Nothing is left for the next open to report as lost.
        kid.control = Arc::new(Control::new());
        assert_eq!(Session::open(kid.deps()).unwrap().pending_job_ends(), 0);
    }

    #[tokio::test]
    async fn an_idle_session_closed_by_a_shutdown_records_how_the_jobs_it_killed_ended() {
        let script = seq(vec![
            Reply::tool("bash", json!({ "command": "echo started; sleep 600", "background": true }).to_string()).into(),
            Reply::text("it is running").into(),
        ]);
        let mut fx = Fx::new("chat", false, false, script).await;
        let session = fx.create();
        let (tx, task) = spawn_run(session);
        tx.send(user("start it")).unwrap();
        wait_until(&fx.sink, "the turn yields", |rs| count(rs, "turn_end") == 1 && count(rs, "job_registered") == 1)
            .await;
        // The command has written its first line before the shutdown stops it.
        let out = fx.jobs_dir().join("j1.out");
        for _ in 0..400 {
            if std::fs::read_to_string(&out).is_ok_and(|t| t.contains("started")) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        fx.control.stop_for_shutdown();
        assert_eq!(finish_task(tx, task).await, End::Closed);
        let rs = fx.sink.records();
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Yielded]);
        let settled = rs.iter().find_map(|r| match &r.event {
            Event::JobSettled { job_id, exit_code, output, detail } => {
                Some((job_id.clone(), *exit_code, output.clone(), detail.clone()))
            }
            _ => None,
        });
        let (job_id, exit_code, output, detail) = settled.expect("the killed job is settled in the log");
        assert_eq!((job_id.as_str(), exit_code, detail.as_str()), ("j1", None, texts::JOB_SHUTDOWN_DETAIL));
        assert_eq!(fx.ctx.blobs.read_all(&output.expect("stored").id).unwrap(), b"started\n");
        // The note says what stopped it: no `interrupted` record goes with a shutdown between turns.
        let killed = format!("Background job j1 ended: killed. {}", texts::JOB_SHUTDOWN_DETAIL);
        let arrivals = notes(&rs, NoteKind::Arrival);
        assert!(arrivals.iter().any(|n| n.starts_with(&killed)), "{arrivals:?}");
        // The next open finds nothing lost, and owes the yielded session the turn the job's end would have started.
        fx.control = Arc::new(Control::new());
        let before = fx.sink.records().len();
        let reopened = Session::open(fx.deps()).unwrap();
        assert_eq!(reopened.records().len(), before);
        assert_eq!(reopened.pending_job_ends(), 1);
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
        let dir = tempfile::tempdir().unwrap();
        let release = dir.path().join("release");
        // Bounded, so that a failed run leaves no loop behind.
        let command = format!(
            "i=0; while [ ! -f '{}' ] && [ $i -lt 1200 ]; do sleep 0.1; i=$((i+1)); done; echo job-output",
            release.display()
        );
        let script = seq(vec![
            Reply::tool("bash", json!({ "command": command, "background": true }).to_string()).into(),
            Reply::tool("wait", json!({}).to_string()).into(),
            finish_call("done").into(),
        ]);
        let mut kid = Fx::new("worker", true, true, script).await;
        let session = kid.create_with(Budget::default(), Some((SessionId::from("s-lead"), "Run it.".into())));
        let (tx, task) = spawn_run(session);
        // The job ends only once the turn is waiting, however slow the machine is.
        wait_until(&kid.sink, "the turn waits", |rs| count(rs, "turn_end") == 1).await;
        std::fs::write(&release, "").unwrap();
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
    async fn a_watched_job_that_writes_a_matching_line_wakes_a_waiting_session() {
        let dir = tempfile::tempdir().unwrap();
        let release = dir.path().join("release");
        // Bounded, so that a failed run leaves no loop behind. The job goes on after the line.
        let command = format!(
            "echo scanning; i=0; while [ ! -f '{}' ] && [ $i -lt 1200 ]; do sleep 0.1; i=$((i+1)); done; echo 'FOUND key=abc'; sleep 120",
            release.display()
        );
        let script = seq(vec![
            Reply::tool("bash", json!({ "command": command, "background": true, "wake_on": "^FOUND" }).to_string())
                .into(),
            Reply::tool("wait", json!({}).to_string()).into(),
            Reply::tool("job_kill", json!({ "job": "j1" }).to_string()).into(),
            finish_call("done").into(),
        ]);
        let mut kid = Fx::new("worker", true, true, script).await;
        let session = kid.create_with(Budget::default(), Some((SessionId::from("s-lead"), "Run it.".into())));
        let (tx, task) = spawn_run(session);
        // The line is written only once the turn is waiting, however slow the machine is.
        wait_until(&kid.sink, "the turn waits", |rs| count(rs, "turn_end") == 1).await;
        assert_eq!(count(&kid.sink.records(), "job_matched"), 0);
        std::fs::write(&release, "").unwrap();
        let end = tokio::time::timeout(Duration::from_secs(60), task).await.expect("the child did not settle").unwrap();
        let End::Settled(s) = end else { panic!("expected a settlement, got {end:?}") };
        assert_eq!(s.outcome, ChildOutcome::Returned);
        drop(tx);
        let rs = kid.sink.records();
        // The match started the second turn while the job was still running: its end came later, by job_kill.
        let ks = kinds(&rs);
        let at = |kind: &str| ks.iter().position(|k| *k == kind).unwrap_or_else(|| panic!("no {kind} in {ks:?}"));
        assert!(at("job_matched") < at("job_settled"), "{ks:?}");
        assert!(rs.iter().any(|r| matches!(&r.event, Event::TurnStart { trigger: Trigger::JobOutput })));
        assert!(!rs.iter().any(|r| matches!(&r.event, Event::TurnStart { trigger: Trigger::JobSettled })));
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Waiting, TurnEndReason::Finished]);
        let matched = rs.iter().find_map(|r| match &r.event {
            Event::JobMatched { job_id, pattern, output, shown, matches, .. } => {
                Some((job_id.clone(), pattern.clone(), output.clone(), shown.clone(), *matches))
            }
            _ => None,
        });
        let (job, pattern, output, shown, matches) = matched.expect("job_matched");
        assert_eq!((job.as_str(), pattern.as_str(), shown, matches), ("j1", "^FOUND", vec![2], 1));
        let handle = output.expect("the part is stored").handle();
        let arrivals = notes(&rs, NoteKind::Arrival);
        let note = arrivals.iter().find(|n| n.contains("matching /^FOUND/")).expect("the note of the match");
        assert!(
            note.starts_with("Background job j1 is still running and has written 1 line matching /^FOUND/."),
            "{note}"
        );
        assert!(
            note.contains(&format!(
                "That part of its output is stored as {handle} (2 lines, from byte 0 of what the job has written)"
            )),
            "{note}"
        );
        assert!(note.contains("\n> 2: FOUND key=abc\n"), "{note}");
        assert!(
            note.contains("job_wait(\"j1\") returns everything the job has written since you last looked"),
            "{note}"
        );
    }

    #[tokio::test]
    async fn a_match_during_a_turn_is_an_arrival_and_starts_no_turn() {
        // The job writes its line at once; the turn is busy in job_wait when the report comes.
        let script = seq(vec![
            Reply::tool(
                "bash",
                json!({ "command": "echo 'panic: boom'; sleep 120", "background": true, "wake_on": "(?i)panic" })
                    .to_string(),
            )
            .into(),
            Reply::tool("job_wait", json!({ "job": "j1", "timeout_s": 4 }).to_string()).into(),
            Reply::tool("job_kill", json!({ "job": "j1" }).to_string()).into(),
            finish_call("done").into(),
        ]);
        let mut kid = Fx::new("worker", true, true, script).await;
        let session = kid.create_with(Budget::default(), Some((SessionId::from("s-lead"), "Run it.".into())));
        let End::Settled(_) = run_with(session, vec![]).await else { panic!("expected a settlement") };
        let rs = kid.sink.records();
        assert_eq!(count(&rs, "job_matched"), 1, "{:?}", kinds(&rs));
        let arrivals = notes(&rs, NoteKind::Arrival);
        assert!(
            arrivals.iter().any(|n| n.contains("matching /(?i)panic/") && n.contains("> 1: panic: boom")),
            "{arrivals:?}"
        );
        assert_eq!(count(&rs, "turn_start"), 1);
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Finished]);
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
        assert!(rs.iter().any(
            |r| matches!(&r.event, Event::UserMessage { text } if *text == texts::inbox_answer("which branch?", "main"))
        ));
        assert!(rs.iter().any(|r| matches!(&r.event, Event::TurnStart { trigger: Trigger::InboxAnswer })));
        let ledger = fx.shared.ledger().unwrap();
        assert!(
            ledger.questions.iter().all(|q| q.answer.is_some()),
            "{:?} // {:?} // {:?}",
            ledger.questions,
            kinds(&rs),
            turn_ends(&rs)
        );
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Asked, TurnEndReason::Finished]);
        assert_eq!(fx.sink.last_status().unwrap().open_inbox, 1); // the Finished item
        finish_task(tx, task).await;
    }

    #[tokio::test]
    async fn dismissing_a_non_blocking_item_resolves_it_without_a_turn() {
        let mut fx =
            Fx::new("lead", false, true, seq(vec![finish_call("first").into(), finish_call("second").into()])).await;
        let session = fx.create();
        let (tx, task) = spawn_run(session);
        tx.send(user("go")).unwrap();
        wait_until(&fx.sink, "the finished item", |rs| !inbox(rs).is_empty() && count(rs, "turn_end") == 1).await;
        let item = inbox(&fx.sink.records())[0].clone();
        assert_eq!((item.kind, item.blocking), (InboxKind::Finished, false));
        tx.send(Input::Answer { item_id: item.item_id.clone(), answer: "  ".into() }).unwrap();
        // A real message behind the dismissal: by the time its turn has run, the dismissal has been
        // handled, so any request it caused would be in the log before this one.
        tx.send(user("next")).unwrap();
        wait_until(&fx.sink, "the second turn", |rs| count(rs, "turn_end") == 2).await;
        let rs = fx.sink.records();
        assert_eq!(count(&rs, "inbox_resolved"), 1);
        assert_eq!(count(&rs, "turn_start"), 2);
        let reqs = fx.server.requests();
        assert_eq!(reqs.len(), 2, "the dismissal must not cost a request");
        assert!(!all_text(&reqs[1]).contains("The operator's answer"), "{}", all_text(&reqs[1]));
        assert_eq!(rs.iter().filter(|r| matches!(&r.event, Event::UserMessage { .. })).count(), 2);
        assert!(notes(&rs, NoteKind::Arrival).is_empty(), "a finished item is dismissed without a note");
        finish_task(tx, task).await;
    }

    #[tokio::test]
    async fn dismissing_a_question_closes_it_in_the_ledger_and_tells_the_model() {
        let mut fx = Fx::new("lead", false, true, seq(vec![])).await;
        let mut session = fx.create();
        fx.shared.ledger_append(false, LedgerOp::QuestionAsk { text: "which?".into(), blocking: false }).unwrap();
        let item = InboxItem {
            item_id: "i-q".into(),
            kind: InboxKind::Question,
            text: "which?".into(),
            options: Vec::new(),
            blocking: false,
            call_id: None,
            reference: Some("q1".into()),
        };
        session.append(Author::Harness, Event::InboxOpened(item)).unwrap();
        let arrival = session.arrival(Input::Answer { item_id: "i-q".into(), answer: String::new() }).await.unwrap();
        assert_eq!(arrival.trigger, None);
        assert!(!arrival.user);
        let questions = fx.shared.ledger().unwrap().questions;
        assert_eq!(questions[0].answer.as_deref(), Some(texts::DISMISSED_ANSWER));
        let rs = fx.sink.records();
        assert_eq!(notes(&rs, NoteKind::Arrival), vec![texts::question_dismissed("which?")]);
        assert_eq!(count(&rs, "user_message"), 0);
        assert!(session.st.inbox.is_empty());
        // The status is out before any turn: a restart reads it and must not see the item open.
        assert_eq!(fx.sink.last_status().unwrap().open_inbox, 0);
    }

    #[tokio::test]
    async fn a_written_answer_to_a_finished_item_starts_a_turn_and_is_not_a_ledger_answer() {
        let mut fx = Fx::new("lead", false, true, seq(vec![Reply::text("ok").into()])).await;
        let mut session = fx.create();
        fx.shared.ledger_append(false, LedgerOp::QuestionAsk { text: "which?".into(), blocking: false }).unwrap();
        let item = InboxItem {
            item_id: "i-fin".into(),
            kind: InboxKind::Finished,
            text: "done".into(),
            options: Vec::new(),
            blocking: false,
            call_id: None,
            reference: Some("q1".into()),
        };
        session.append(Author::Harness, Event::InboxOpened(item)).unwrap();
        let arrival = session
            .arrival(Input::Answer { item_id: "i-fin".into(), answer: "thanks, now do more".into() })
            .await
            .unwrap();
        assert_eq!(arrival.trigger, Some(Trigger::InboxAnswer));
        assert!(arrival.user);
        assert!(
            fx.shared.ledger().unwrap().questions.iter().all(|q| q.answer.is_none()),
            "a Finished item answers no question"
        );
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
        tx.send(Input::Approval { text: "you may restart the staging database".into(), scope: "staging only".into() })
            .unwrap();
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
        assert_eq!(
            (ledger.approvals[0].scope.as_str(), ledger.approvals[0].used_for.is_none()),
            ("staging only", true)
        );
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
    async fn a_rule_kept_on_disk_is_recorded_once_even_after_the_harness_stopped_first() {
        let mut fx = Fx::new("lead", false, true, seq(vec![])).await;
        drop(fx.create());
        let id = SessionId::from("s-test");
        let queue = queue_dir(&fx.paths, &id);
        // Handed over while the lead was in a tool call, then lost from memory with the harness.
        let lost = queue_input(&fx.paths, &id, Input::Constraint("never push to main".into())).unwrap();
        let Input::Queued { file, .. } = &lost else { panic!("a rule is kept on disk") };
        assert!(file.exists());
        // Other inputs are not kept.
        assert!(matches!(queue_input(&fx.paths, &id, user("hi")).unwrap(), Input::User(_)));
        // The session started from its log records it before anything else, and deletes the file.
        let (tx, task) = spawn_run(Session::open(fx.deps()).unwrap());
        wait_until(&fx.sink, "the rule", |rs| notes(rs, NoteKind::Constraint).len() == 1).await;
        assert!(!file.exists());
        // The same input arriving late over the channel is not recorded again; a new one is, and its
        // file goes once it is.
        tx.send(lost.clone()).unwrap();
        let approval = Input::Approval { text: "you may restart staging".into(), scope: "staging".into() };
        tx.send(queue_input(&fx.paths, &id, approval).unwrap()).unwrap();
        wait_until(&fx.sink, "the approval", |rs| notes(rs, NoteKind::Approval).len() == 1).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        let rs = fx.sink.records();
        assert_eq!(notes(&rs, NoteKind::Constraint).len(), 1, "{:?}", kinds(&rs));
        let ledger = fx.shared.ledger().unwrap();
        assert_eq!((ledger.constraints.len(), ledger.approvals.len()), (1, 1));
        assert_eq!(count(&rs, "turn_start"), 0);
        assert_eq!(std::fs::read_dir(&queue).unwrap().count(), 0, "nothing is left on disk");
        finish_task(tx, task).await;
    }

    #[test]
    fn a_kept_input_is_private_and_its_directory_is_tightened() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path().join("home"));
        let id = SessionId::from("s-test");
        let queue = queue_dir(&paths, &id);
        // Left looser by an earlier version.
        std::fs::create_dir_all(&queue).unwrap();
        std::fs::set_permissions(&queue, std::fs::Permissions::from_mode(0o755)).unwrap();
        let kept = queue_input(&paths, &id, Input::Constraint("never push to main".into())).unwrap();
        let Input::Queued { file, .. } = &kept else { panic!("a rule is kept on disk") };
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(file), 0o600);
        assert_eq!(mode(&queue), 0o700);
    }

    #[tokio::test]
    async fn a_rule_left_on_disk_while_it_was_being_recorded_is_recorded_once() {
        let mut fx = Fx::new("lead", false, true, seq(vec![])).await;
        let mut session = fx.create();
        let id = SessionId::from("s-test");
        let queue = queue_dir(&fx.paths, &id);
        let take = |session: &Session, input: Input| {
            let Input::Queued { file, .. } = queue_input(&fx.paths, &id, input).unwrap() else { panic!("kept") };
            let marker = taking_path(&file, session.log.next_seq());
            std::fs::rename(&file, &marker).unwrap();
            marker
        };
        // The harness stopped after recording this rule and before deleting its file ...
        let rule = take(&session, Input::Constraint("never push to main".into()));
        session.record_input(Input::Constraint("never push to main".into())).await.unwrap();
        // ... and before recording this approval, after something else took the seq it named.
        let approval = Input::Approval { text: "you may restart staging".into(), scope: "staging".into() };
        let pending = take(&session, approval);
        session.note(Author::Harness, NoteKind::Info, "the harness went down".into()).unwrap();
        assert_eq!(taking_seq(&rule), Some(taking_seq(&pending).unwrap() - 2));
        drop(session);
        let (tx, task) = spawn_run(Session::open(fx.deps()).unwrap());
        wait_until(&fx.sink, "the approval", |rs| notes(rs, NoteKind::Approval).len() == 1).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        let rs = fx.sink.records();
        assert_eq!(notes(&rs, NoteKind::Constraint).len(), 1, "{:?}", kinds(&rs));
        let ledger = fx.shared.ledger().unwrap();
        assert_eq!((ledger.constraints.len(), ledger.approvals.len()), (1, 1));
        assert_eq!(std::fs::read_dir(&queue).unwrap().count(), 0, "nothing is left on disk");
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
        tx.send(Input::ChildSettled(settlement.clone())).unwrap();
        wait_until(&fx.sink, "second turn", |rs| count(rs, "turn_end") == 2).await;
        // A replayed delivery must neither append a receipt nor wake another turn.
        tx.send(Input::ChildSettled(settlement)).unwrap();
        // A message from the assigning agent does not wake a session that is not waiting.
        tx.send(Input::AgentMessage { from: SessionId::from("s-lead"), text: "psst".into() }).unwrap();
        tx.send(Input::Stop).unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let rs = fx.sink.records();
        assert_eq!(count(&rs, "turn_start"), 2);
        assert_eq!(count(&rs, "child_settled"), 1);
        assert_eq!(notes(&rs, NoteKind::Arrival), vec![texts::agent_message("psst")]);
        // The stop of a yielded session is recorded, so that nothing it causes wakes the session.
        assert_eq!(count(&rs, "interrupted"), 1);
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Yielded, TurnEndReason::Yielded, TurnEndReason::Stopped]);
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
        fx.context =
            ReweavePolicy { target_tokens: 12_000, floor_tokens: 10_000, keep_recent_steps: 1, stub_tail_lines: 3 };
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
            rw.iter()
                .map(|w| (w.epoch, w.upto_seq, w.evictions.len(), w.before_tokens, w.after_tokens_est))
                .collect::<Vec<_>>()
        );
        assert!(lines(2) < 700, "after the re-weave only the newest output is whole, got {}", lines(2));
        assert_no_cache_break(&rs);
        assert!(all_text(&reqs[2]).contains(&texts::reweave_brief("", None)));
    }

    #[tokio::test]
    async fn the_reweave_check_uses_the_prompt_size_the_server_reported() {
        // The server counts a token per character of the request, more than the estimator can be
        // calibrated to (it counts at least 1.5 characters a token), so the estimate trails it.
        let mut answered = 0;
        let script = Script::new(move |body, _| {
            let counted = body["messages"].to_string().len() + body["tools"].to_string().len();
            let usage = Usage { prompt_tokens: counted as u64, completion_tokens: 10, ..Usage::default() };
            answered += 1;
            let reply = if answered <= 8 { bash(BIG) } else { Reply::text("ok") };
            reply.with_usage(usage).into()
        });
        let mut fx = Fx::new("chat", false, false, script).await;
        let target = 150_000;
        fx.context =
            ReweavePolicy { target_tokens: target, floor_tokens: 1_000, keep_recent_steps: 1, stub_tail_lines: 3 };
        let session = fx.create();
        run_with(session, vec![user("go")]).await;
        let rs = read_records(&fx.log_path()).unwrap().records;
        let rw = reweave_records(&rs);
        assert!(!rw.is_empty(), "{:?}", kinds(&rs));
        assert_eq!(rw[0].reason, "target");
        // Started by the size the server counted ...
        assert!(rw[0].before_tokens > target, "{}", rw[0].before_tokens);
        assert!(rw[0].after_tokens_est < rw[0].before_tokens);
        // ... where the estimate, tool specs included, had not reached the target yet.
        let first = rs.iter().position(|r| matches!(r.event, Event::Reweave(_))).unwrap();
        let w = weave(&rs[..first]);
        let most = TokenEstimator::with_ratio(1.5);
        let estimate = most.tokens_for_messages(&w.messages) + most.tokens(tools_chars(&w.tools));
        assert!(estimate < target, "{estimate}");
        assert_no_cache_break(&rs);
    }

    #[tokio::test]
    async fn the_measured_size_counts_only_what_was_merged_into_the_last_message_since() {
        let mut fx = Fx::new("chat", false, false, seq(vec![Reply::text("first").into()])).await;
        let mut session = fx.create();
        // A long paste, which the server has counted already.
        session.append(Author::User, Event::UserMessage { text: "u ".repeat(10_000) }).unwrap();
        let w = session.woven().weave;
        let n = w.messages.len();
        let request = ModelRequest {
            req_id: "r-1".into(),
            step: 1,
            epoch: 0,
            purpose: Purpose::Step,
            n_messages: to_u32(n),
            stable_hash: stable_hash(&w.messages),
            hud: None,
            est_tokens: 0,
        };
        session.append(Author::Harness, Event::ModelRequest(request)).unwrap();
        // Cut off before any text: nothing renders, so later notes merge into the last user message.
        let reply = ModelResponse {
            req_id: "r-1".into(),
            text: String::new(),
            reasoning: "x".repeat(5_000),
            tool_calls: Vec::new(),
            finish: FinishReason::Length,
            usage: Usage { prompt_tokens: 50_000, ..Usage::default() },
            timing: Timing::default(),
            attempts: 1,
        };
        session.append(Author::Model, Event::ModelResponse(reply)).unwrap();
        let w = session.woven().weave;
        assert_eq!(session.measured_size(&w), Some(50_000), "nothing new");
        let note = "n".repeat(3_000);
        session.note(Author::Harness, NoteKind::OutputCut, note.clone()).unwrap();
        let w = session.woven().weave;
        assert_eq!(w.messages.len(), n, "merged into the last message the request carried");
        let item = w.items.last().unwrap().chars;
        assert!(item > note.len());
        // The server's count plus the note and the blank line before it, not the whole message again.
        let added = session.estimator.tokens(item + 2);
        assert_eq!(session.measured_size(&w), Some(50_000 + added));
        assert!(session.estimator.tokens(w.messages[n - 1].chars()) > added + 4_000);
        // Another epoch has not been counted yet.
        let mut later = w.clone();
        later.epoch = 1;
        assert_eq!(session.measured_size(&later), None);
    }

    #[tokio::test]
    async fn a_re_weave_the_servers_count_starts_is_planned_and_recorded_in_its_units() {
        fn answered(session: &mut Session, req_id: &str, text: &str, prompt_tokens: u64) {
            let w = weave(session.records());
            let request = ModelRequest {
                req_id: req_id.into(),
                step: 1,
                epoch: 0,
                purpose: Purpose::Step,
                n_messages: to_u32(w.messages.len()),
                stable_hash: stable_hash(&w.messages),
                hud: None,
                est_tokens: 0,
            };
            session.append(Author::Harness, Event::ModelRequest(request)).unwrap();
            let reply = ModelResponse {
                req_id: req_id.into(),
                text: text.into(),
                reasoning: String::new(),
                tool_calls: Vec::new(),
                finish: FinishReason::Stop,
                usage: Usage { prompt_tokens, ..Usage::default() },
                timing: Timing::default(),
                attempts: 1,
            };
            session.append(Author::Model, Event::ModelResponse(reply)).unwrap();
        }
        let mut fx = Fx::new("chat", false, false, seq(vec![])).await;
        fx.context =
            ReweavePolicy { target_tokens: 400_000, floor_tokens: 300_000, keep_recent_steps: 1, stub_tail_lines: 3 };
        let mut session = fx.create();
        // One receipt per child (a replayed delivery is not appended again), so two children report.
        let report = |kid: &SessionId, text: &str| {
            let report = text.repeat(30_000);
            let usage = Usage::default();
            let settled = ChildSettled {
                child: kid.clone(),
                outcome: ChildOutcome::Returned,
                report,
                full: None,
                usage,
                steps: 1,
                inline: false,
            };
            Event::ChildSettled(settled)
        };
        session.append(Author::User, Event::UserMessage { text: "go".into() }).unwrap();
        answered(&mut session, "r-1", "a", 10_000);
        let (kid1, kid2) = (SessionId::from("s-kid-1"), SessionId::from("s-kid-2"));
        session.append(Author::Agent(kid1.clone()), report(&kid1, "first ")).unwrap();
        answered(&mut session, "r-2", "b", 500_000);
        session.append(Author::Agent(kid2.clone()), report(&kid2, "second")).unwrap();
        answered(&mut session, "r-3", "c", 1_000_000);
        let woven = session.woven();
        // Counted by the estimator, the log is below the floor: a plan in its units folds nothing ...
        let est = session.estimate(&woven.weave);
        assert!(est < 300_000);
        assert!(woven.plan(session.records(), &session.estimator, &fx.context, true).is_none());
        // ... while the server counts it far above the target, and the plan is made for that.
        let size = session.measured_size(&woven.weave).unwrap();
        assert!(size > 1_000_000);
        assert!(session.reweave(&woven, "target", false, &CancellationToken::new(), None).await.unwrap());
        let rw = reweave_records(session.records());
        assert_eq!(rw.len(), 1);
        assert_eq!(rw[0].evictions.len(), 2, "both reports are folded");
        assert_eq!(rw[0].before_tokens, size, "the size that started it");
        assert!(rw[0].after_tokens_est < 400_000, "{}", rw[0].after_tokens_est);
    }

    #[tokio::test]
    async fn reweave_protects_fewer_recent_steps_when_they_are_what_fills_the_context() {
        // Every step is inside the protected recent region, so nothing could be folded without
        // shrinking it.
        let script = seq(vec![big(), big(), big(), big(), big(), big(), Reply::text("ok").into()]);
        let mut fx = Fx::new("chat", false, false, script).await;
        fx.context =
            ReweavePolicy { target_tokens: 40_000, floor_tokens: 10_000, keep_recent_steps: 64, stub_tail_lines: 3 };
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
        let mut fx =
            Fx::new("chat", false, false, seq(vec![big(), big(), big(), big(), Reply::text("ok").into()])).await;
        fx.context =
            ReweavePolicy { target_tokens: 12_000, floor_tokens: 10_000, keep_recent_steps: 64, stub_tail_lines: 3 };
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
            let script =
                with_digest(vec![long().into(), long().into(), long().into(), Reply::text("ok").into()], digest);
            let mut fx = Fx::new("chat", false, false, script).await;
            // Three steps of long text and output pass the target; folding the old output alone
            // does not make enough room, folding the old text as well does.
            fx.context =
                ReweavePolicy { target_tokens: 60_000, floor_tokens: 1_000, keep_recent_steps: 1, stub_tail_lines: 3 };
            let session = fx.create();
            run_with(session, vec![user("go")]).await;
            let rs = fx.sink.records();
            let rw = reweave_records(&rs);
            assert!(!rw.is_empty(), "{:?}", kinds(&rs));
            assert_eq!(rw[0].digest.as_deref(), digest);
            assert!(
                rw[0].evictions.iter().any(|e| matches!(e.action, loom_core::event::EvictAction::Drop)),
                "text was folded"
            );
            let digests = rs
                .iter()
                .filter(|r| matches!(&r.event, Event::ModelRequest(m) if m.purpose == Purpose::Digest))
                .count();
            assert!(digests >= 1);
            // The digest request is only a request record: no response record follows it.
            assert_eq!(count(&rs, "model_response") + digests, count(&rs, "model_request"));
            let last = fx.server.requests().last().unwrap().clone();
            assert_eq!(all_text(&last).contains("Leads from earlier work"), digest.is_some());
            assert_no_cache_break(&rs);
        }
    }

    #[tokio::test]
    async fn the_reweave_brief_carries_the_frontier_only_when_the_session_has_a_ledger() {
        for mission in [true, false] {
            let long = || Reply::tool("bash", json!({ "command": BIG }).to_string()).with_text("t".repeat(40_000));
            let script = with_digest(vec![long().into(), long().into(), long().into(), Reply::text("ok").into()], None);
            let mut fx = Fx::new("chat", false, mission, script).await;
            fx.context =
                ReweavePolicy { target_tokens: 60_000, floor_tokens: 1_000, keep_recent_steps: 1, stub_tail_lines: 3 };
            if mission {
                let journal = fx.shared.journal.as_ref().unwrap().clone();
                use loom_core::ledger::{EvidenceInput, EvidenceKind};
                let me = SessionId::from("s-lead");
                let ops = [
                    LedgerOp::ClaimAdd { text: "the parser drops the last token".into() },
                    LedgerOp::EvidenceAdd(EvidenceInput {
                        claim: "c1".into(),
                        kind: EvidenceKind::Execution,
                        supports: true,
                        session: "s-lead".into(),
                        call_id: "call-0".into(),
                        blob: None,
                        lines: None,
                        quote: None,
                        note: "ran it".into(),
                        attested: true,
                    }),
                    LedgerOp::ClaimUpdate {
                        id: "c1".into(),
                        status: loom_core::ledger::ClaimStatus::Supported,
                        note: String::new(),
                    },
                    LedgerOp::DeadEnd { what: "tried mmap".into(), why: "segfaults".into() },
                ];
                for op in ops {
                    journal.append(&me, true, op, &|_| Ok(())).unwrap();
                }
            }
            let session = fx.create();
            run_with(session, vec![user("go")]).await;
            let rw = reweave_records(&fx.sink.records());
            assert!(!rw.is_empty());
            let brief = &rw[0].brief;
            let paragraph = "a failed attempt rules out that attempt, not the approach";
            assert_eq!(brief.contains(paragraph), mission, "{brief}");
            assert_eq!(brief.contains("Where the work stands:"), mission, "{brief}");
            if mission {
                assert!(brief.contains("- Established: 1 (c1); latest c1: the parser drops the last token"), "{brief}");
                assert!(brief.contains("- Set aside without evidence: 1 (x1)"), "{brief}");
                assert!(brief.contains("- Attempts run in this session: "), "{brief}");
                assert!(brief.contains("The mission ledger at this point:"), "{brief}");
            }
        }
    }

    #[tokio::test]
    async fn a_step_renders_its_weave_once_and_again_only_after_a_reweave() {
        let long = || Reply::tool("bash", json!({ "command": BIG }).to_string()).with_text("t".repeat(40_000));
        let script =
            with_digest(vec![long().into(), long().into(), long().into(), Reply::text("ok").into()], Some("lead A"));
        let mut fx = Fx::new("chat", false, false, script).await;
        fx.context =
            ReweavePolicy { target_tokens: 60_000, floor_tokens: 1_000, keep_recent_steps: 1, stub_tail_lines: 3 };
        let mut session = fx.create();
        session.append(Author::User, Event::UserMessage { text: "go".into() }).unwrap();
        assert!(session.turn(Trigger::User).await.unwrap().is_none());
        let rs = session.records().to_vec();
        let requests =
            |p: Purpose| rs.iter().filter(|r| matches!(&r.event, Event::ModelRequest(m) if m.purpose == p)).count();
        let (steps, digests, reweaves) =
            (requests(Purpose::Step), requests(Purpose::Digest), reweave_records(&rs).len());
        assert!(reweaves >= 1 && digests >= 1, "{:?}", kinds(&rs));
        // The check, every plan, the digest request and the request share one weave per step; only
        // a re-weave makes another.
        assert_eq!(session.weaves as usize, steps + reweaves);
    }

    #[tokio::test]
    async fn the_digest_request_waits_at_the_sessions_own_priority() {
        let mut fx = Fx::new("chat", false, false, seq(vec![Reply::text("leads").into()])).await;
        let mut session = fx.create();
        let limiter = Arc::new(Limiter::new(1));
        session.deps.limiter = limiter.clone();
        assert_eq!(session.deps.priority, Priority::Lead);
        let never = CancellationToken::new();
        let held = limiter.acquire(Priority::Lead, &never).await.unwrap();
        // A child's request waits for the slot first, and keeps it once it has it.
        let child = {
            let limiter = limiter.clone();
            tokio::spawn(async move {
                let _permit = limiter.acquire(Priority::Child, &CancellationToken::new()).await;
                std::future::pending::<()>().await;
            })
        };
        while limiter.waiting() < 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let w = session.woven().weave;
        let digest = session.ask_digest(&w, &never);
        tokio::pin!(digest);
        tokio::select! {
            _ = &mut digest => panic!("the digest request did not wait for the limiter"),
            _ = async { while limiter.waiting() < 2 { tokio::time::sleep(Duration::from_millis(5)).await } } => {}
        }
        // The lead's own step is waiting for the digest: it goes before the child.
        drop(held);
        let got =
            tokio::time::timeout(Duration::from_secs(10), digest).await.expect("the digest waited behind the child");
        assert_eq!(got.unwrap().as_deref(), Some("leads"));
        child.abort();
    }

    #[tokio::test]
    async fn a_digest_request_that_keeps_retrying_is_reported_like_a_step_request() {
        let (script, _) = down_then(3, vec![Reply::text("leads").into()]);
        let mut fx = retrying_fx(script, 1, 0).await;
        let mut session = fx.create();
        let w = session.woven().weave;
        let got = session.ask_digest(&w, &CancellationToken::new()).await.unwrap();
        assert_eq!(got.as_deref(), Some("leads"));
        let rs = session.records().to_vec();
        assert_eq!(&kinds(&rs)[kinds(&rs).len() - 3..], ["model_request", "inbox_opened", "inbox_resolved"]);
        assert!(inbox(&rs)[0].text.contains("the model is loading"), "{}", inbox(&rs)[0].text);
        let answer = &resolutions(&rs)[0].2;
        assert!(answer.starts_with("Answered automatically: the model server answered again at "), "{answer}");
        // Its stream is not shown to viewers.
        assert!(fx.sink.deltas.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn context_overflow_forces_a_reweave_and_a_retry() {
        let mut fx = Fx::new("chat", false, false, seq(vec![big(), big(), Reply::text("ok").into()])).await;
        fx.server.set_model("mock", Some(16_000));
        fx.context =
            ReweavePolicy { target_tokens: 400_000, floor_tokens: 1_000, keep_recent_steps: 1, stub_tail_lines: 3 };
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
    async fn a_small_window_is_folded_at_its_trigger_before_the_server_refuses_it() {
        let mut fx =
            Fx::new("chat", false, false, seq(vec![big(), big(), big(), big(), big(), Reply::text("ok").into()])).await;
        fx.server.set_model("mock", Some(32_000));
        fx.window = Some(32_000);
        // The configured floor (180k) is far above this window.
        fx.context =
            ReweavePolicy { target_tokens: 400_000, floor_tokens: 180_000, keep_recent_steps: 1, stub_tail_lines: 3 };
        let session = fx.create();
        run_with(session, vec![user("go")]).await;
        let rs = fx.sink.records();
        let rw = reweave_records(&rs);
        assert!(!rw.is_empty(), "{:?}", kinds(&rs));
        // The room kept for the reply is a quarter of this window, so the trigger (24k) lies below the
        // window and the context is folded before the server refuses it.
        assert_eq!(rw[0].reason, "target");
        assert_eq!(count(&rs, "model_request"), count(&rs, "model_response"), "no request was refused");
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Yielded]);
        assert!(inbox(&rs).is_empty());
    }

    #[tokio::test]
    async fn a_small_window_re_weaves_instead_of_failing_when_it_overflows() {
        let mut fx =
            Fx::new("chat", false, false, seq(vec![big(), big(), big(), big(), big(), Reply::text("ok").into()])).await;
        // The session is told twice the window the server enforces, so the server refuses first.
        fx.server.set_model("mock", Some(32_000));
        fx.window = Some(64_000);
        // The configured floor (180k) is far above both windows.
        fx.context =
            ReweavePolicy { target_tokens: 400_000, floor_tokens: 180_000, keep_recent_steps: 1, stub_tail_lines: 3 };
        let session = fx.create();
        run_with(session, vec![user("go")]).await;
        let rs = fx.sink.records();
        let rw = reweave_records(&rs);
        assert!(!rw.is_empty(), "{:?}", kinds(&rs));
        assert!(rw.iter().all(|w| w.reason == "overflow"), "{rw:?}");
        assert!(count(&rs, "model_request") > count(&rs, "model_response"), "a request was refused");
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Yielded]);
        assert!(inbox(&rs).is_empty());
    }

    #[test]
    fn the_reply_reserve_is_at_most_a_quarter_of_the_window() {
        let policy = ReweavePolicy::default();
        // 16k: 4k are kept for the reply, so the trigger and the floor stay positive.
        assert_eq!(reweave_bounds(&policy, Some(16_000), None), (12_000, 8_000));
        // The default bounds (400k and 180k) are clamped to a 32k window, which `Config::check` accepts.
        let (limit, floor) = reweave_bounds(&policy, Some(32_768), None);
        assert!(limit < 32_768 && floor < limit, "{limit} {floor}");
        // A configured reply length is honoured whole; only the slack after it shrinks.
        assert_eq!(reweave_bounds(&policy, Some(16_000), Some(4_000)), (8_000, 4_000));
        // One the window cannot hold is no reply length the session can honour: it counts as none,
        // not as a trigger of 0 that would re-weave at every step.
        assert_eq!(reweave_bounds(&policy, Some(16_000), Some(32_768)), (12_000, 8_000));
        // One the window can hold is kept even when little is left after it: the request still fits.
        assert_eq!(reweave_bounds(&policy, Some(16_000), Some(14_000)), (1, 0));
        assert_eq!(reweave_bounds(&policy, Some(32_768), Some(30_000)), (1, 0));
        for (window, max) in
            [(16_000, Some(4_000)), (16_000, Some(14_000)), (32_768, Some(30_000)), (65_536, Some(32_768))]
        {
            let (limit, _) = reweave_bounds(&policy, Some(window), max);
            assert!(limit + max.unwrap_or(0) <= window, "window {window} max {max:?}");
        }
        // A request at the trigger leaves room for the reply it asks for, and the 4_096 after it.
        let (limit, floor) = reweave_bounds(&policy, Some(65_536), Some(32_768));
        assert_eq!((limit, floor), (28_672, 14_336));
        assert!(limit + 32_768 + 4_096 <= 65_536);
        // From 81_920 tokens up the whole reserve (the reply or 16_384, plus 4_096) is kept, as it
        // always was.
        let whole = |w: u64, reply: u64| {
            let limit = 400_000u64.min(w - reply - 4_096).min(w / 5 * 4);
            let floor = 180_000u64.min(w / 2);
            (limit, if floor >= limit { limit / 2 } else { floor })
        };
        for w in [81_920, 82_000, 131_072, 200_000, 1_000_000] {
            assert_eq!(reweave_bounds(&policy, Some(w), None), whole(w, 16_384), "window {w}");
            assert_eq!(reweave_bounds(&policy, Some(w), Some(32_768)), whole(w, 32_768), "window {w}");
        }
        assert_eq!(reweave_bounds(&policy, Some(131_072), Some(32_768)), (94_208, 65_536));
        assert_eq!(reweave_bounds(&policy, Some(82_000), Some(32_768)).0, 45_136);
        assert_eq!(reweave_bounds(&policy, Some(1_000_000), None), (400_000, 180_000));
        assert_eq!(reweave_bounds(&policy, None, None), (400_000, 180_000));
        // Below it the reserve shrinks with the window instead of swallowing it.
        let (limit, floor) = reweave_bounds(&policy, Some(40_000), None);
        assert_eq!((limit, floor), (30_000, 20_000));
    }

    #[tokio::test]
    async fn an_overflow_re_weaves_by_the_servers_limit_when_the_window_is_unknown() {
        let mut fx =
            Fx::new("chat", false, false, seq(vec![big(), big(), big(), big(), big(), Reply::text("ok").into()])).await;
        fx.server.set_model("mock", Some(32_000));
        // No window known to the session, and the default policy, whose floor (180k) is far above it.
        fx.window = None;
        fx.context = ReweavePolicy::default();
        let session = fx.create();
        run_with(session, vec![user("go")]).await;
        let rs = fx.sink.records();
        let rw = reweave_records(&rs);
        assert!(!rw.is_empty(), "{:?}", kinds(&rs));
        assert!(rw.iter().all(|w| w.reason == "overflow" && w.digest.is_none()));
        // No digest is asked for on a prefix the server has just refused.
        assert!(!rs.iter().any(|r| matches!(&r.event, Event::ModelRequest(m) if m.purpose == Purpose::Digest)));
        assert_eq!(turn_ends(&rs), vec![TurnEndReason::Yielded]);
        assert!(inbox(&rs).is_empty());
    }

    #[tokio::test]
    async fn an_operator_reweave_while_idle_and_one_queued_mid_turn() {
        let mut fx =
            Fx::new("chat", false, false, seq(vec![big(), big(), Reply::text("ok").into(), Reply::text("ok").into()]))
                .await;
        fx.context =
            ReweavePolicy { target_tokens: 400_000, floor_tokens: 1_000, keep_recent_steps: 1, stub_tail_lines: 3 };
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
        // A lead without `conclude`: its closing `finish` is not refused for an unconcluded goal.
        let mut role = core_role("lead");
        role.tools.retain(|t| t != "conclude" && t != "request_scope");
        let mut fx = Fx::build_with(role, "lead", false, true, agents, seq(actions)).await;
        let session = fx.create();
        run_with(session, vec![user("go")]).await;
        let rs = fx.sink.records();
        let n = notes(&rs, NoteKind::Stall);
        assert_eq!(n, vec![texts::stall(3)]);
        let at = rs.iter().position(|r| matches!(&r.event, Event::HarnessNote { note: NoteKind::Stall, .. })).unwrap();
        let requests_before = rs[..at].iter().filter(|r| matches!(r.event, Event::ModelRequest(_))).count();
        assert_eq!(requests_before, 3);
    }
    #[test]
    fn runtime_wrapup_policy_closes_new_work_but_preserves_cleanup() {
        let policy = CallPolicy { wrapup: true };
        for name in [
            "bash",
            "web_fetch",
            "read",
            "grep",
            "write",
            "plan",
            "claim",
            "agent_spawn",
            "agent_fanout",
            "verify",
            "decide",
            "future_state_tool",
        ] {
            assert!(!policy.allows(name, &json!({})), "{name}");
        }
        for name in [
            "out_read",
            "out_grep",
            "evidence",
            "claim_update",
            "report_blocker",
            "finish",
            "verdict",
            "ledger",
            "agent_stop",
            "job_kill",
        ] {
            assert!(policy.allows(name, &json!({})), "{name}");
        }
        assert!(!policy.allows("step", &json!({"text":"new work"})));
        assert!(!policy.allows("step", &json!({"id":"p1", "status":"doing"})));
        assert!(policy.allows("step", &json!({"id":"p1", "status":"dropped"})));
        assert!(!policy.allows("job_wait", &json!({})));
        assert!(policy.allows("job_wait", &json!({"timeout_s":2})));
        assert!(policy.allows("security_record", &json!({"operation":{"action":"coverage_set", "asset":"a1", "disposition":{"status":"deferred", "reason":"budget"}}})));
        assert!(!policy.allows("security_record", &json!({"operation":{"action":"asset_upsert", "asset":"new"}})));
        assert!(!policy.allows("security_record", &json!({"operation":{"action":"batch", "operations":[]}})));
    }

    #[test]
    fn durable_clock_excludes_waits_renewals_and_restart_downtime() {
        let mut state = State { started_ms: 1000, ..State::default() };
        let apply = |s: &mut State, ms, event| {
            s.absorb(0, &Record { seq: 0, ts_ms: ms, author: Author::Harness, prev: String::new(), event })
        };
        apply(&mut state, 1000, Event::BudgetClock { running: true });
        apply(&mut state, 2000, Event::BudgetClock { running: false });
        apply(&mut state, 9000, Event::BudgetClock { running: true });
        assert_eq!(state.clock.as_ref().unwrap().elapsed(10000), 2000);
        apply(&mut state, 10000, Event::HarnessNote { note: NoteKind::Info, text: "checkpoint".into() });
        apply(&mut state, 90000, Event::Interrupted { reason: texts::REASON_RESTART.into() });
        assert_eq!(state.clock.as_ref().unwrap().elapsed(100000), 2000);
        apply(&mut state, 100000, Event::TurnEnd { reason: TurnEndReason::BudgetExhausted });
        apply(&mut state, 110000, Event::TurnStart { trigger: Trigger::User });
        apply(&mut state, 110000, Event::BudgetClock { running: true });
        assert_eq!(state.clock.as_ref().unwrap().elapsed(111000), 1000);
        let fork = Forked {
            session: SessionId::from("s-child"),
            parent: SessionId::from("s-parent"),
            upto_seq: 0,
            role: "worker".into(),
            termination: Termination::Explicit,
            budget: Budget::default(),
            brief: Brief::default(),
            contract: String::new(),
            allowed_tools: None,
            title: String::new(),
        };
        apply(&mut state, 120000, Event::Forked(fork));
        assert_eq!(
            state.clock.as_ref().unwrap().elapsed(130000),
            0,
            "a fresh fork starts paused, without inheriting parent time or charging scheduler delay"
        );
    }

    #[tokio::test]
    async fn wrapup_blocks_speculative_reads_and_keeps_the_wire_schema() {
        let mut fx = Fx::new("chat", false, false, seq(vec![])).await;
        let witness = Witness::default();
        let mut session = fx.create();
        session.registry.add(Arc::new(Probe { sink: Some(fx.sink.clone()), witness: witness.clone(), hold: false }));
        session.st.budget_note_step = Some(0);
        let token = CancellationToken::new();
        let mut early = Early::new(
            true,
            session.registry.clone(),
            session.deps.ctx.clone(),
            &token,
            HashSet::new(),
            session.early_counts.clone(),
        );
        early.policy = CallPolicy { wrapup: true };
        early.on_event(&StreamEvent::AttemptStart { attempt: 1 });
        early.on_event(&StreamEvent::ToolCallReady {
            index: 0,
            id: None,
            name: "read".into(),
            arguments: json!({"path":"a.txt"}).to_string(),
        });
        assert!(early.runs.is_empty());
        let specs = session.woven().weave.tools;
        let call = ToolCallRequest {
            call_id: CallId::from("blocked-read"),
            name: "read".into(),
            arguments: json!({"path":"a.txt"}).to_string(),
            complete: true,
        };
        session.run_calls("req", &[call], &specs, early).await.unwrap();
        assert_eq!(results(session.records()).last().unwrap().status, ToolStatus::Invalid);
        assert!(results(session.records()).last().unwrap().text.contains("Budget wrap-up active"));
        assert_eq!(session.woven().weave.tools, specs);
    }

    #[tokio::test]
    async fn role_exec_cap_survives_reopen_and_flag_alert_is_advisory() {
        let mut role = core_role("chat");
        role.max_exec_calls = Some(1);
        role.flag_regex = Some(r"FLAG\{[^}]+\}".into());
        let script = seq(vec![
            bash("printf 'FLAG{candidate}\\n'").into(),
            bash("touch should-not-exist").into(),
            Reply::text("done").into(),
        ]);
        let mut fx = Fx::build_with(role, "chat", false, false, AgentsCfg::default(), script).await;
        run_with(fx.create(), vec![user("go")]).await;
        assert!(!fx.ctx.workspace.join("should-not-exist").exists());
        let rs = fx.sink.records();
        assert_eq!(rs.iter().filter(|r| matches!(r.event, Event::ExecStarted { .. })).count(), 1);
        assert!(notes(&rs, NoteKind::Info).iter().any(|s| s.contains("unverified candidate")));
        let session = Session::open(fx.deps()).unwrap();
        assert_eq!(session.exec_count(), 1);
        assert_eq!(session.st.clock.as_ref().unwrap().running_from, None);
    }

    #[tokio::test]
    async fn reasoning_only_replies_get_a_specific_bounded_nudge() {
        let script = seq(vec![Reply::text("").with_reasoning("private thought").into(); 3]);
        let mut fx = Fx::new("worker", true, true, script).await;
        fx.agents.max_nudges = 1;
        let end = run_with(fx.create(), vec![]).await;
        assert!(matches!(end, End::Settled(ref s) if s.outcome == ChildOutcome::Failed));
        assert!(notes(&fx.sink.records(), NoteKind::Nudge).iter().any(|n| n == texts::REASONING_ONLY));
        assert_eq!(fx.server.requests().len(), 2);
        assert!(!notes(&fx.sink.records(), NoteKind::Nudge).join(" ").contains("private thought"));
    }

    #[tokio::test]
    async fn a_real_limiter_wait_is_excluded_and_replayed_from_durable_intervals() {
        let mut fx = Fx::new("chat", false, false, seq(vec![Reply::text("done").into()])).await;
        let mut session = fx.create();
        session.deps.limiter = Arc::new(Limiter::new(1));
        let token = CancellationToken::new();
        let held = session.deps.limiter.acquire(Priority::Lead, &token).await.unwrap();
        let (tx, task) = spawn_run(session);
        tx.send(user("go")).unwrap();
        wait_until(&fx.sink, "paused queue", |rs| {
            rs.iter().any(|r| matches!(r.event, Event::BudgetClock { running: false }))
        })
        .await;
        tokio::time::sleep(Duration::from_millis(120)).await;
        drop(held);
        finish_task(tx, task).await;
        let rs = fx.sink.records();
        let turn_start = rs.iter().find(|r| matches!(r.event, Event::TurnStart { .. })).unwrap().ts_ms;
        let turn_end = rs.iter().find(|r| matches!(r.event, Event::TurnEnd { .. })).unwrap().ts_ms;
        let reopened = Session::open(fx.deps()).unwrap();
        let active = reopened.st.clock.as_ref().unwrap().elapsed(now_ms());
        assert!(turn_end.saturating_sub(turn_start).saturating_sub(active) >= 100);
        assert_eq!(reopened.st.clock.as_ref().unwrap().running_from, None);
    }

    #[tokio::test]
    async fn retry_intervals_are_paused_without_recording_reasoning() {
        let (script, _) = down_then(3, vec![Reply::text("done").into()]);
        let mut fx = retrying_fx(script, 0, 0).await;
        run_with(fx.create(), vec![user("go")]).await;
        let rs = fx.sink.records();
        let turn_start = rs.iter().find(|r| matches!(r.event, Event::TurnStart { .. })).unwrap().ts_ms;
        let turn_end = rs.iter().find(|r| matches!(r.event, Event::TurnEnd { .. })).unwrap().ts_ms;
        let reopened = Session::open(fx.deps()).unwrap();
        let active = reopened.st.clock.as_ref().unwrap().elapsed(now_ms());
        assert!(turn_end.saturating_sub(turn_start).saturating_sub(active) >= 1000);
        assert!(rs.iter().filter(|r| matches!(r.event, Event::BudgetClock { running: false })).count() >= 2);
    }
    #[tokio::test]
    async fn a_free_role_can_recover_from_reasoning_only_with_a_visible_answer() {
        let mut fx = Fx::new(
            "chat",
            false,
            false,
            seq(vec![Reply::text("").with_reasoning("hidden").into(), Reply::text("visible answer").into()]),
        )
        .await;
        run_with(fx.create(), vec![user("go")]).await;
        assert_eq!(fx.server.requests().len(), 2);
        assert_eq!(notes(&fx.sink.records(), NoteKind::Nudge), [texts::REASONING_ONLY]);
        assert_eq!(turn_ends(&fx.sink.records()), [TurnEndReason::Yielded]);
    }
    #[tokio::test]
    async fn idle_stop_and_archive_close_terminals_whose_reads_already_returned() {
        for stop in [true, false] {
            let mut fx = Fx::new("chat", false, false, seq(vec![])).await;
            loom_tools::pty::PtyOpen
                .run(&fx.ctx, json!({"command":"exec sleep 60", "timeout_s":1}).as_object().unwrap())
                .await;
            assert_eq!(fx.ctx.capabilities.ptys.ids().len(), 1);
            let session = fx.create();
            let (tx, task) = spawn_run(session);
            if stop {
                tx.send(Input::Stop).unwrap();
                for _ in 0..100 {
                    if fx.ctx.capabilities.ptys.ids().is_empty() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                assert!(fx.ctx.capabilities.ptys.ids().is_empty());
            }
            assert_eq!(finish_task(tx, task).await, End::Closed);
            assert!(fx.ctx.capabilities.ptys.ids().is_empty());
        }
    }

    #[tokio::test]
    async fn stopping_a_model_request_also_closes_idle_terminals() {
        let mut fx = Fx::new("chat", false, false, seq(vec![Action::Stall { ms: 600_000 }])).await;
        loom_tools::pty::PtyOpen
            .run(&fx.ctx, json!({"command":"exec sleep 60", "timeout_s":1}).as_object().unwrap())
            .await;
        let session = fx.create();
        let (tx, task) = spawn_run(session);
        tx.send(user("go")).unwrap();
        wait_until(&fx.sink, "model request", |rs| rs.iter().any(|r| matches!(r.event, Event::ModelRequest(_)))).await;
        fx.control.stop_turn();
        tx.send(Input::Stop).unwrap();
        wait_until(&fx.sink, "stopped", |rs| turn_ends(rs).contains(&TurnEndReason::Stopped)).await;
        assert!(fx.ctx.capabilities.ptys.ids().is_empty());
        assert_eq!(finish_task(tx, task).await, End::Closed);
    }
}
