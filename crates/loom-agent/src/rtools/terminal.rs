//! Tools that end a turn or a session: `finish`, `verdict`, `ask_user`, `report_blocker`, `wait`.
//!
//! CONTRACT (the `run` bodies are placeholders for the implementer; specs and types are fixed).
//!
//! These tools decide nothing by themselves about the loop: they record, then leave an
//! [`Effect`](super::Effect) in `Shared` for the step loop. A tool that returns an error leaves no
//! effect. Nothing here panics. `S` below is `self.0` (the `Shared`).
//!
//! ## `finish`
//! `answer` must contain non-whitespace (else error ``finish needs an `answer`: the result, written
//! for someone who has not seen your work. Nothing was delivered.``).
//! `quotes` elements are objects `{handle, start, end, text}`; an element of another shape is an
//! error naming its position and the four fields. They are checked with `gate::check_quotes(&ctx.blobs,
//! …)`; `Err(text)` → error `{text}\nNothing was delivered. Correct the quotes and call finish again.`
//! Refused, in a lead and in a child session alike, while a background job of this session (`ctx.jobs`)
//! or a child agent (`S.orch.children`) is running: the error names them and says what to do with the
//! tools this role has (`wait`, `job_kill`, `agent_stop`). No effect is set and nothing is recorded.
//!
//! **In a child session** (`S.is_child()`): store the answer when it is longer than
//! `REPORT_MAX_CHARS` characters (`ctx.blobs.put_bytes`, handle via `BlobRef::handle`), render
//! `gate::render_report(ReportInput { outcome: Returned, answer, quotes: &verified, not_established,
//! max_chars: REPORT_MAX_CHARS, full_handle })`, then `S.set_effect(Effect::Settle(Delivery {
//! outcome: Returned, report, full, payload: {"quotes": [{"handle","start","end","text"}…]} }))`.
//! Output: ok, outcome `delivered`, message `Your result was delivered. This session is finished.`
//!
//! **In a lead session** (not a child):
//! 1. `S.ledger()`; `gate::check_finish_lead(&state, answer)`; `Err(text)` → error `text`.
//! 2. `S.ledger_append(false, FinishClaim { summary: answer, evidence })`; `fid` is the new finish id.
//! 3. Verification is required when `S.role.verify_finish && S.agents.verify_finish`. When it is not,
//!    deliver with the note `not verified`. When it is, the result is delivered as `Finished` only after
//!    a verifier child returned `accepted: true`; every other outcome fails closed (step 5).
//!    - the rejections counted are those of the finishes after the latest accepted finish and after the
//!      latest finish whose escalation the operator has answered (`rejection_floor`). When they reach
//!      `MAX_FINISH_REJECTIONS`: escalate, no verifier is spawned.
//!    - the verifier is `S.role.verifier` (resolved at pack load), spawned with `SpawnReq { harness:
//!      true, … }` (not limited by `may_spawn` or `max_children`), brief from [`finish_brief`].
//!    - cancelled while spawning or joining: error `Interrupted while the result was being verified;
//!      nothing was delivered. Call finish again to resume.` The orchestrator answering
//!      `SHUTTING_DOWN` is treated the same way (error, nothing recorded): the turn is being cut and
//!      the finish is made, and verified, again after the restart.
//!    - `accepted: true` → `FinishVerdict` recorded, deliver with `verified by {child}`.
//!    - `accepted: false` → `FinishVerdict` recorded; error text with the objections and the report, no
//!      effect (the lead deals with them and calls finish again).
//!    - any other spawn or join error, or no verdict in the payload: escalate (a verifier that ended
//!      without a verdict has its report, cut at `REPORT_MAX_CHARS`, added to the item and the result).
//! 4. Deliver: `InboxItem { kind: Finished, text: "{answer}{support}\n\n[{note}]", blocking: false, … }`
//!    where `support` is the lead's `not_established` and its harness-checked quotes, then
//!    `Effect::EndTurn(Finished)`; ok, outcome `finished — {note}`.
//! 5. Escalate: a blocking ledger question `Finish {fid} was not delivered: NOT VERIFIED …` and a
//!    blocking `Blocker` inbox item whose text says why and contains the answer labelled NOT VERIFIED
//!    (`NOT VERIFIED - REJECTED n TIMES` with every rejection's objections, or `NOT VERIFIED -
//!    VERIFICATION COULD NOT BE RUN` with the reason); `Effect::EndTurn(Blocked)`. Answering the item
//!    restarts the rejection count.
//!
//! ## `verdict` (verifier role)
//! Refused outside a child session: ``verdict` belongs to a verifier working on an assignment.``
//! - `accepted: false` needs at least one non-empty objection; `accepted: true` must have none
//!   (``accepted: true cannot come with objections — either they are objections, or it is accepted``).
//! - `opened` must not be empty: ``List in `opened` the outputs you examined (their out:… handles).
//!   A verdict that examined nothing is not a verdict.``
//! - every handle in `opened` must resolve (`ctx.blobs.resolve`) and must be an output this session
//!   itself produced or opened: some `tool_result` record in `S.log_path` has that blob as `output`
//!   or names it in `meta[META_OF_BLOB]`. Otherwise: ``You listed {handle} as examined, but this
//!   session never opened it. Open it with out_read, or take it off the list.``
//! - when the assignment (the `Assignment` note in `S.log_path`) names stored outputs (`out:…`), `opened`
//!   must include at least one of them.
//!
//! Then `S.set_effect(Effect::Settle(Delivery { outcome: Returned, report, full: None, payload:
//! {"accepted": bool, "objections": [...], "opened": [...]} }))` with `report`:
//! `Verdict: accepted` or `Verdict: not accepted`, then `Objections:` and one `- ` line each (when
//! any), then `Examined: {handles joined by ", "}`. Output: ok, outcome `verdict delivered`.
//!
//! ## `ask_user`
//! Refused in a child session: `Only the lead can ask the operator. Say what you need in your
//! result (`not_established`), or call report_blocker if you cannot continue.`
//! `blocking: false` needs a non-empty `meanwhile` (else error saying so).
//! `S.ledger_append(false, QuestionAsk { text: question, blocking })` when the session has a journal
//! (a rule refusal is returned as the error); `qid` = the new question id. Emit `InboxOpened(InboxItem
//! { item_id: new_item_id(), kind: Question, text: question, options, blocking, call_id:
//! Some(ctx.call_id), reference: qid })`.
//! - blocking: `S.set_effect(Effect::EndTurn(Asked))`; ok, outcome `asked — waiting for the operator`,
//!   message `The question is in the operator's inbox. This turn ends here; you will be resumed with
//!   the answer.`
//! - not blocking: no effect; ok, outcome `asked`, message `The question is in the operator's inbox.
//!   The answer will arrive as a message. Meanwhile: {meanwhile}`
//!
//! ## `report_blocker`
//! `what`, `tried`, `needs` must each contain non-whitespace. Text:
//! `Blocked ({class}): {what}\nTried: {tried}\nNeeds: {needs}`.
//! - child session: `S.set_effect(Effect::Settle(Delivery { outcome: Blocked, report: text, full:
//!   None, payload: null }))`; ok, outcome `blocker reported`, message `The blocker was reported to
//!   the agent that assigned this work. This session is finished.`
//! - lead session: `QuestionAsk { text, blocking: true }` in the ledger when there is a journal; emit
//!   `InboxOpened(InboxItem { kind: Blocker, blocking: true, text, reference: qid, … })`;
//!   `S.set_effect(Effect::EndTurn(Blocked))`; ok, outcome `blocker reported — waiting for the
//!   operator`, message `The blocker is in the operator's inbox. This turn ends here; you will be
//!   resumed when the operator replies.`
//!
//! ## `wait`
//! Running things: `ctx.jobs.list()` entries still running, and `S.orch.children(&S.session)` entries
//! with `running`. When there are none: error `Nothing is running: no background job and no agent
//! to wait for. Carry on with the work, or end with {the terminating tools this role has other than
//! wait, as `a`, `b` or `c`}.` Otherwise `S.set_effect(Effect::EndTurn(Waiting))`; ok, outcome
//! `waiting`, message `Waiting for: {job j1 (command cut to 60 chars), … ; agent s-… (role), …}. You
//! will be resumed as soon as one of them ends.`
//!
//! Tests required (fake `Orchestrator` with scripted spawn/join results; temp journal; calls made
//! through `loom_tools::execute`): for `finish` — empty answer, malformed quote element, failed
//! quote, child delivery (effect, report text, payload, long answer stored), refusal while a job or a
//! child agent is running (lead and child), lead with open items refused, lead accepted with
//! verification (verdict recorded, inbox item, effect), lead rejected (no effect, objections listed,
//! finish recorded as not accepted), third finish after two rejections escalated (not delivered) and
//! verified again after the operator's answer, the rejection count restarting at an accepted finish
//! but not at a question the lead wrote, verifier ending without a verdict and spawn failure (both
//! escalated, nothing delivered), shutdown and cancellation (error, nothing recorded);
//! `verdict` — each refusal, the settle effect and payload; `ask_user` — blocking and not, child
//! refusal, missing `meanwhile`, ledger question recorded and referenced; `report_blocker` — child
//! and lead; `wait` — nothing running, a running job, a running child.

use super::{Delivery, Effect, Shared, SpawnReq, MAX_FINISH_REJECTIONS, REPORT_MAX_CHARS, SHUTTING_DOWN};
use crate::gate::{self, Quote, ReportInput, VerifiedQuote};
use crate::pack::RoleDef;
use async_trait::async_trait;
use loom_core::event::{
    Author, Brief, Budget, ChildOutcome, Event, InboxItem, InboxKind, NoteKind, SpawnMode, ToolClass, ToolSpec,
    ToolStatus, TurnEndReason, META_OF_BLOB,
};
use loom_core::ids::new_item_id;
use loom_core::ledger::{ClaimStatus, Evidence, LedgerOp, LedgerState};
use loom_core::log::read_records;
use loom_core::{BlobId, BlobRef};
use loom_tools::jobs::JobState;
use loom_tools::params::{opt, req, spec};
use loom_tools::{Body, Tool, ToolCtx, ToolOutput};
use std::collections::HashSet;
use serde_json::{json, Map, Value};
use std::sync::Arc;

pub struct Finish(pub Arc<Shared>);
pub struct Verdict(pub Arc<Shared>);
pub struct AskUser(pub Arc<Shared>);
pub struct ReportBlocker(pub Arc<Shared>);
pub struct Wait(pub Arc<Shared>);

/// The schema of one quote, shared by `finish` and the agent tools.
pub fn quote_items() -> Value {
    json!({
        "type": "object",
        "properties": {
            "handle": { "type": "string", "description": "The stored output, for example out:7f3a9c1e." },
            "start": { "type": "integer", "description": "First line of the quoted text." },
            "end": { "type": "integer", "description": "Last line of the quoted text." },
            "text": { "type": "string", "description": "The text, copied exactly from those lines." }
        },
        "required": ["handle", "start", "end", "text"],
        "additionalProperties": false
    })
}

/// The assignment given to the verifier of a lead's `finish`.
///
/// - `question`: `Try to refute that this mission is finished as its lead describes.`
/// - `context`: `Goal (set by the operator):\n{goal}`, then `Constraints:` with one `- ` line per
///   active constraint (omitted when none), then `The lead's summary of the result:\n{answer}`, then
///   `What the lead says it did not establish:` when it stated something, then
///   `Lines the lead quotes as support:` with one line per quote `- {handle} lines {start}-{end}:
///   {text cut to 300 characters}` (omitted when none), then `Evidence the lead names for the result:`
///   with one line per record of `evidence` (the ids given to `finish`; omitted when none), then
///   `Claims recorded as supported:` with one line per supported claim `- {id}: {text}`, each followed
///   by its evidence records, indented (omitted when none).
///   An evidence line has the form the `verify` tool uses: `- {id} ({supports|undermines}) {handle}
///   lines {a}-{b}: {quote cut to 300 characters} — {note}`, so the assignment names the stored
///   output of every piece of evidence the result rests on.
/// - `returns`: `A verdict, delivered by calling verdict.`
/// - `stop_when`: `You have checked the summary against the goal, each constraint, and the outputs
///   it relies on.`
/// - every other field `None`.
pub fn finish_brief(
    ledger: &LedgerState,
    answer: &str,
    quotes: &[crate::gate::VerifiedQuote],
    not_established: Option<&str>,
    evidence: &[String],
) -> Brief {
    let goal = ledger.goal.as_deref().unwrap_or("(no goal recorded)");
    let mut parts = vec![format!("Goal (set by the operator):\n{goal}")];

    let constraints: Vec<String> =
        ledger.constraints.iter().filter(|c| c.retired.is_none()).map(|c| format!("- {}", c.text)).collect();
    if !constraints.is_empty() {
        parts.push(format!("Constraints:\n{}", constraints.join("\n")));
    }

    parts.push(format!("The lead's summary of the result:\n{answer}"));

    if let Some(text) = not_established.map(str::trim).filter(|t| !t.is_empty()) {
        parts.push(format!("What the lead says it did not establish:\n{text}"));
    }

    if !quotes.is_empty() {
        let lines: Vec<String> = quotes
            .iter()
            .map(|q| format!("- {} lines {}-{}: {}", handle_of(&q.blob), q.start, q.end, cut_chars(&q.text, 300)))
            .collect();
        parts.push(format!("Lines the lead quotes as support:\n{}", lines.join("\n")));
    }

    let record = |id: &String| ledger.evidence.iter().find(|e| &e.id == id);
    let named: Vec<String> = evidence.iter().filter_map(record).map(evidence_line).collect();
    if !named.is_empty() {
        parts.push(format!("Evidence the lead names for the result:\n{}", named.join("\n")));
    }

    let mut supported: Vec<String> = Vec::new();
    for c in ledger.claims.iter().filter(|c| c.status == ClaimStatus::Supported) {
        supported.push(format!("- {}: {}", c.id, c.text));
        supported.extend(c.evidence.iter().filter_map(record).map(|e| format!("  {}", evidence_line(e))));
    }
    if !supported.is_empty() {
        parts.push(format!("Claims recorded as supported:\n{}", supported.join("\n")));
    }

    Brief {
        question: "Try to refute that this mission is finished as its lead describes.".to_string(),
        returns: Some("A verdict, delivered by calling verdict.".to_string()),
        stop_when: Some(
            "You have checked the summary against the goal, each constraint, and the outputs it relies on.".to_string(),
        ),
        context: Some(parts.join("\n\n")),
        ..Brief::default()
    }
}

/// The handle (`out:…`) the model uses for a stored output.
fn handle_of(id: &BlobId) -> String {
    format!("out:{}", id.0.chars().take(16).collect::<String>())
}

/// One ledger evidence record as a verifier is shown it: which way it points, the stored output and
/// lines it rests on, the quoted text and the note.
fn evidence_line(e: &Evidence) -> String {
    let i = &e.input;
    let side = if i.supports { "supports" } else { "undermines" };
    let handle = i.blob.as_ref().map(handle_of).unwrap_or_else(|| "no stored output".to_string());
    let range = i.lines.map(|(a, b)| format!(" lines {a}-{b}")).unwrap_or_default();
    let quote = cut_chars(i.quote.as_deref().unwrap_or(""), 300);
    format!("- {} ({side}) {handle}{range}: {quote} \u{2014} {}", e.id, i.note)
}

/// `s` cut to `max` characters, with `…` appended when something was removed.
fn cut_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

fn outcome_word(o: ChildOutcome) -> &'static str {
    match o {
        ChildOutcome::Returned => "returned",
        ChildOutcome::Blocked => "blocked",
        ChildOutcome::BudgetExhausted => "budget exhausted",
        ChildOutcome::Stopped => "stopped",
        ChildOutcome::Failed => "failed",
    }
}

fn str_arg<'a>(args: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Value::as_str)
}

fn strings_of(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

const QUOTE_SHAPE: &str = "{handle, start, end, text}";

/// Parse the `quotes` argument; an element of another shape is an error naming its position.
fn parse_quotes(args: &Map<String, Value>) -> Result<Vec<Quote>, String> {
    let Some(list) = args.get("quotes") else { return Ok(Vec::new()) };
    let Some(list) = list.as_array() else {
        return Err(format!("`quotes` must be a list of objects {QUOTE_SHAPE}. Nothing was delivered."));
    };
    let mut out = Vec::new();
    for (idx, v) in list.iter().enumerate() {
        let pos = idx.saturating_add(1);
        let quote = v.as_object().and_then(|o| {
            Some(Quote {
                handle: o.get("handle")?.as_str()?.to_string(),
                start: o.get("start")?.as_u64()?,
                end: o.get("end")?.as_u64()?,
                text: o.get("text")?.as_str()?.to_string(),
            })
        });
        match quote {
            Some(q) => out.push(q),
            None => {
                return Err(format!(
                    "quote {pos} is not an object with the four fields {QUOTE_SHAPE} (handle and text are strings, start and end are line numbers). Nothing was delivered."
                ))
            }
        }
    }
    Ok(out)
}

fn quotes_json(quotes: &[VerifiedQuote]) -> Value {
    Value::Array(
        quotes
            .iter()
            .map(|q| json!({"handle": handle_of(&q.blob), "start": q.start, "end": q.end, "text": q.text}))
            .collect(),
    )
}

fn inbox(kind: InboxKind, text: String, options: Vec<String>, blocking: bool, ctx: &ToolCtx, reference: Option<String>) -> Event {
    Event::InboxOpened(InboxItem {
        item_id: new_item_id(),
        kind,
        text,
        options,
        blocking,
        call_id: Some(ctx.call_id.clone()),
        reference,
    })
}

/// Record a question in the ledger when the session has a journal; returns its id.
fn record_question(s: &Shared, text: &str, blocking: bool) -> Result<Option<String>, String> {
    if s.journal.is_none() {
        return Ok(None);
    }
    let (_, state) = s.ledger_append(false, LedgerOp::QuestionAsk { text: text.to_string(), blocking })?;
    Ok(state.questions.last().map(|q| q.id.clone()))
}

/// `a`, `b` or `c`.
fn or_list(names: &[String]) -> String {
    let quoted: Vec<String> = names.iter().map(|n| format!("`{n}`")).collect();
    match quoted.split_last() {
        None => String::new(),
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} or {last}", rest.join(", ")),
    }
}

impl Finish {
    /// A child hands its answer to the agent that assigned the work.
    fn finish_child(&self, ctx: &ToolCtx, answer: &str, verified: &[VerifiedQuote], not_established: Option<&str>) -> ToolOutput {
        let full: Option<BlobRef> = if answer.chars().count() > REPORT_MAX_CHARS {
            match ctx.blobs.put_bytes(answer.as_bytes()) {
                Ok(b) => Some(b),
                Err(e) => {
                    return ToolOutput::error(format!(
                        "The full answer could not be stored ({e}); this is a harness fault. Nothing was delivered. Call finish again."
                    ))
                }
            }
        } else {
            None
        };
        let full_handle = full.as_ref().map(BlobRef::handle).unwrap_or_default();
        let report = gate::render_report(&ReportInput {
            outcome: ChildOutcome::Returned,
            answer,
            quotes: verified,
            not_established,
            max_chars: REPORT_MAX_CHARS,
            full_handle: &full_handle,
        });
        self.0.set_effect(Effect::Settle(Delivery {
            outcome: ChildOutcome::Returned,
            report,
            full,
            payload: json!({ "quotes": quotes_json(verified) }),
        }));
        ToolOutput::ok("delivered", Body::Message("Your result was delivered. This session is finished.".into()))
    }

    /// What this session still has running: its background jobs, and its child agents.
    async fn running_work(&self, ctx: &ToolCtx) -> (Vec<String>, Vec<String>) {
        let s = &self.0;
        let jobs = ctx
            .jobs
            .list()
            .await
            .into_iter()
            .filter(|j| j.state == JobState::Running)
            .map(|j| {
                let command = j.command.split_whitespace().collect::<Vec<_>>().join(" ");
                format!("job {} ({})", j.id, cut_chars(&command, 60))
            })
            .collect();
        let agents = s
            .orch
            .children(&s.session)
            .await
            .into_iter()
            .filter(|c| c.running)
            .map(|c| format!("agent {} ({})", c.id, c.role))
            .collect();
        (jobs, agents)
    }

    /// The lead's result goes through the ledger gate and, when required, an independent verifier. When
    /// verification is required, the result is delivered as finished only after the verifier accepted it.
    async fn finish_lead(
        &self,
        ctx: &ToolCtx,
        args: &Map<String, Value>,
        answer: &str,
        verified: &[VerifiedQuote],
        not_established: Option<&str>,
    ) -> ToolOutput {
        let s = &self.0;
        let state = match s.ledger() {
            Ok(st) => st,
            Err(e) => return ToolOutput::error(e),
        };
        if let Err(text) = gate::check_finish_lead(&state, answer) {
            return ToolOutput::error(text);
        }
        let evidence = strings_of(args.get("evidence"));
        let claim = LedgerOp::FinishClaim { summary: answer.to_string(), evidence: evidence.clone() };
        let after = match s.ledger_append(false, claim) {
            Ok((_, after)) => after,
            Err(e) => return ToolOutput::error(e),
        };
        let Some(fid) = after.finishes.last().map(|f| f.id.clone()) else {
            return ToolOutput::error(
                "The finish was not recorded in the ledger; this is a harness fault. Nothing was delivered. Call finish again.",
            );
        };
        let support = support_text(not_established, verified);

        let mut note = "not verified".to_string();
        if s.role.verify_finish && s.agents.verify_finish {
            // `state` is the ledger before this finish: only earlier finishes count or restart the count.
            let floor = rejection_floor(&state);
            let rejections: Vec<(String, Vec<String>)> = state
                .finishes
                .iter()
                .filter(|f| f.accepted == Some(false) && finish_number(&f.id) > floor)
                .map(|f| (f.id.clone(), f.objections.clone()))
                .collect();
            if rejections.len() >= usize::try_from(MAX_FINISH_REJECTIONS).unwrap_or(usize::MAX) {
                return self.escalate(ctx, &fid, Unverified::Rejected(rejections), answer, &support);
            }
            let Some(role) = s.role.verifier.clone() else {
                let why = format!("the role `{}` has no verifier role in its pack", s.role.name);
                return self.escalate(ctx, &fid, Unverified::NotRun { why, report: None }, answer, &support);
            };
            let req = SpawnReq {
                role,
                mode: SpawnMode::Fresh,
                brief: finish_brief(&state, answer, verified, not_established, &evidence),
                budget: Budget { max_steps: Some(s.agents.child_max_steps), max_minutes: Some(s.agents.child_max_minutes) },
                call_id: ctx.call_id.clone(),
                title: format!("verify finish {fid}"),
                awaited: true,
                harness: true,
            };
            let settled = match s.orch.spawn(&s.session, req).await {
                Ok(child) => s.orch.join(&s.session, &child, &ctx.cancel).await.map(|st| (child, st)),
                Err(e) => Err(e),
            };
            match settled {
                Err(e) => {
                    if ctx.cancel.is_cancelled() {
                        return ToolOutput::error(
                            "Interrupted while the result was being verified; nothing was delivered. Call finish again to resume.",
                        );
                    }
                    // A restart is not something for the operator to decide: the turn is being cut, and
                    // the finish is made (and verified) again when the session is resumed.
                    if e == SHUTTING_DOWN {
                        return ToolOutput::error(
                            "The harness is shutting down, so the result could not be verified; nothing was delivered. Call finish again.",
                        );
                    }
                    return self.escalate(ctx, &fid, Unverified::NotRun { why: e, report: None }, answer, &support);
                }
                Ok((child, settled)) => match settled.payload.get("accepted").and_then(Value::as_bool) {
                    Some(true) => {
                        let op = LedgerOp::FinishVerdict {
                            claim: fid.clone(),
                            accepted: true,
                            objections: Vec::new(),
                            verifier: Some(child.clone()),
                        };
                        if let Err(e) = s.ledger_append(false, op) {
                            return ToolOutput::error(e);
                        }
                        note = format!("verified by {child}");
                    }
                    Some(false) => {
                        let objections = strings_of(settled.payload.get("objections"));
                        let op = LedgerOp::FinishVerdict {
                            claim: fid.clone(),
                            accepted: false,
                            objections: objections.clone(),
                            verifier: Some(child.clone()),
                        };
                        if let Err(e) = s.ledger_append(false, op) {
                            return ToolOutput::error(e);
                        }
                        let mut text = format!("An independent verifier ({child}) examined the result and did not accept it.");
                        for o in &objections {
                            text.push_str(&format!("\n- {o}"));
                        }
                        text.push_str(&format!(
                            "\n\n{}\n\nThe mission is not finished. Deal with each objection — fix it, or show with evidence that it is wrong — then call finish again.",
                            settled.report
                        ));
                        let mut out = ToolOutput::ok("not accepted", Body::Raw(text.into_bytes()));
                        out.status = ToolStatus::Error;
                        return out;
                    }
                    None => {
                        let why = format!(
                            "the verifier ({child}) ended as {} without giving a verdict",
                            outcome_word(settled.outcome)
                        );
                        let report = Some(settled.report.trim()).filter(|r| !r.is_empty()).map(cut_report);
                        return self.escalate(ctx, &fid, Unverified::NotRun { why, report }, answer, &support);
                    }
                },
            }
        }

        s.emit(Author::Harness, inbox(InboxKind::Finished, format!("{answer}{support}\n\n[{note}]"), Vec::new(), false, ctx, Some(fid)));
        s.set_effect(Effect::EndTurn(TurnEndReason::Finished));
        ToolOutput::ok(format!("finished — {note}"), Body::Message("The result was delivered to the operator.".into()))
    }

    /// The result could not be verified: nothing is delivered as finished. A blocking item carries the
    /// answer labelled NOT VERIFIED, and the turn ends until the operator answers it.
    fn escalate(&self, ctx: &ToolCtx, fid: &str, why: Unverified, answer: &str, support: &str) -> ToolOutput {
        let s = &self.0;
        let (label, mut detail, short, report) = match why {
            Unverified::Rejected(rejections) => {
                let n = rejections.len();
                let mut detail = format!(
                    "An independent verifier rejected the lead's finish {n} times, so the harness stopped asking it. Objections:"
                );
                for (i, (id, objections)) in rejections.iter().enumerate() {
                    detail.push_str(&format!("\nRejection {} ({id}):", i.saturating_add(1)));
                    for o in objections {
                        detail.push_str(&format!("\n- {o}"));
                    }
                }
                (format!("NOT VERIFIED - REJECTED {n} TIMES"), detail, format!("the verifier rejected it {n} times"), None)
            }
            Unverified::NotRun { why, report } => (
                "NOT VERIFIED - VERIFICATION COULD NOT BE RUN".to_string(),
                format!("Verification could not be run: {why}"),
                format!("verification could not be run: {why}"),
                report,
            ),
        };
        // What the verifier itself reported (what blocked it, what it tried), for the operator and the lead.
        let report = report.map(|r| format!("\n\nThe verifier's report:\n{r}")).unwrap_or_default();
        detail.push_str(&report);
        let text = format!(
            "{label}\n\n{detail}\n\nThe lead's answer (NOT VERIFIED; it was not delivered as finished):\n{answer}{support}\n\nAnswer this item to tell the lead how to go on. Its next finish is verified again."
        );
        // The ledger question names the finish, which is how later finishes know where the count restarts.
        let qid = match record_question(s, &escalation_question(fid, &label), true) {
            Ok(q) => q,
            Err(e) => return ToolOutput::error(e),
        };
        s.emit(Author::Harness, inbox(InboxKind::Blocker, text, Vec::new(), true, ctx, qid));
        s.set_effect(Effect::EndTurn(TurnEndReason::Blocked));
        ToolOutput::ok(
            "not verified — waiting for the operator",
            Body::Message(format!(
                "The result could not be verified ({short}) and was NOT delivered as finished. It is in the operator's inbox, labelled NOT VERIFIED. This turn ends here; you will be resumed when the operator answers, and your next finish will be verified again.{report}"
            )),
        )
    }
}

/// Why a finish that needs verification was not delivered.
enum Unverified {
    /// Rejected by the verifier `MAX_FINISH_REJECTIONS` times since the count last restarted: the finish
    /// id and objections of each rejection.
    Rejected(Vec<(String, Vec<String>)>),
    /// The verifier could not be started or joined, or it ended without a verdict (`report` is then what
    /// it reported instead).
    NotRun { why: String, report: Option<String> },
}

/// The refusal of `finish` while work this session started is still running. It names only tools the
/// role has, and says what to do about an agent that no tool of the session can end.
fn running_refusal(role: &RoleDef, jobs: &[String], agents: &[String]) -> String {
    let has = |tool: &str| role.tools.iter().any(|t| t == tool);
    let running: Vec<&str> = jobs.iter().chain(agents).map(String::as_str).collect();
    let mut text = format!(
        "finish was refused: work started by this session is still running: {}. Nothing was delivered.",
        running.join(", ")
    );
    let mut ways: Vec<&str> = Vec::new();
    if has("wait") {
        ways.push("wait for it to report (`wait`)");
    }
    if !jobs.is_empty() && has("job_kill") {
        ways.push("end a job with `job_kill`");
    }
    if !agents.is_empty() && has("agent_stop") {
        ways.push("end an agent with `agent_stop`");
    }
    if ways.is_empty() {
        text.push_str(" Call finish again when it has ended.");
    } else {
        text.push_str(&format!(" To go on: {}; then call finish again.", ways.join(", or ")));
    }
    if !agents.is_empty() {
        text.push_str(
            " An agent takes a moment to end after it is stopped. One that stays listed and never reports is idle, which happens after a harness restart: it cannot be stopped from here, and the operator has to resume it.",
        );
        let tell: Vec<String> = ["ask_user", "report_blocker"].into_iter().filter(|t| has(t)).map(String::from).collect();
        if !tell.is_empty() {
            text.push_str(&format!(" Tell the operator with {}.", or_list(&tell)));
        }
    }
    text
}

/// A verifier's report as the operator and the lead are shown it: whole, or cut with a visible marker.
fn cut_report(report: &str) -> String {
    let total = report.chars().count();
    if total <= REPORT_MAX_CHARS {
        return report.to_string();
    }
    let head: String = report.chars().take(REPORT_MAX_CHARS).collect();
    format!("{head}\n[report cut at {REPORT_MAX_CHARS} of {total} characters]")
}

/// The number in a finish id (`f3` is 3); 0 for anything else.
fn finish_number(id: &str) -> usize {
    id.strip_prefix('f').and_then(|n| n.parse().ok()).unwrap_or(0)
}

/// What follows `Finish {fid} ` in the ledger question of an escalation.
const ESCALATION_MARK: &str = "was not delivered";

/// The blocking ledger question an escalation of finish `fid` is recorded as.
fn escalation_question(fid: &str, label: &str) -> String {
    format!("Finish {fid} {ESCALATION_MARK}: {label}. The answer and the reason are in the inbox item; reply to say how the lead should go on.")
}

/// The finish id a ledger question names, when its text has the form of [`escalation_question`].
fn escalated_finish(question: &str) -> Option<&str> {
    let (fid, rest) = question.strip_prefix("Finish ")?.split_once(' ')?;
    rest.starts_with(ESCALATION_MARK).then_some(fid)
}

/// The number of the latest finish in `state` at which the count of rejections restarts (0 when none):
/// rejections of finishes up to that one no longer count towards `MAX_FINISH_REJECTIONS`. It is the
/// later of
/// - the latest accepted finish: what was rejected before it has been dealt with;
/// - the latest finish whose escalation the operator has answered. An escalation is a blocking ledger
///   question written by [`escalation_question`]; it counts only when the finish it names exists and has
///   no verdict, which is what an escalated finish looks like. A question the lead writes with `ask_user`
///   therefore restarts nothing by naming a finish that does not exist yet or that the verifier judged.
fn rejection_floor(state: &LedgerState) -> usize {
    let accepted = state.finishes.iter().filter(|f| f.accepted == Some(true)).map(|f| finish_number(&f.id));
    let answered = state
        .questions
        .iter()
        .filter(|q| q.blocking && q.answer.is_some())
        .filter_map(|q| escalated_finish(&q.text))
        .filter(|fid| state.finishes.iter().any(|f| f.id == *fid && f.accepted.is_none()))
        .map(finish_number);
    accepted.chain(answered).max().unwrap_or(0)
}

/// What the lead stated it did not establish and the quotes the harness checked, as paragraphs to
/// append to the answer (empty when there are none).
fn support_text(not_established: Option<&str>, quotes: &[VerifiedQuote]) -> String {
    let mut out = String::new();
    if let Some(text) = not_established.map(str::trim).filter(|t| !t.is_empty()) {
        out.push_str(&format!("\n\nNot established (stated by the lead):\n{text}"));
    }
    if !quotes.is_empty() {
        out.push_str("\n\nQuoted support (checked against the stored output):");
        for q in quotes {
            out.push_str(&format!("\n- {} lines {}-{}: {}", handle_of(&q.blob), q.start, q.end, q.text));
        }
    }
    out
}

/// Every stored output this session produced or opened: the `output` and `of_blob` of its tool results.
fn outputs_seen(log_path: &std::path::Path) -> HashSet<BlobId> {
    let mut seen = HashSet::new();
    let Ok(report) = read_records(log_path) else { return seen };
    for record in report.records {
        if let Event::ToolResult(r) = record.event {
            if let Some(out) = r.output {
                seen.insert(out.id);
            }
            if let Some(of) = r.meta.get(META_OF_BLOB).and_then(Value::as_str) {
                seen.insert(BlobId(of.to_string()));
            }
        }
    }
    seen
}

/// The stored outputs (`out:…` handles, as written) that this session's assignment names and that exist.
fn assigned_outputs(log_path: &std::path::Path, blobs: &loom_core::BlobStore) -> Vec<(String, BlobId)> {
    let mut out: Vec<(String, BlobId)> = Vec::new();
    let Ok(report) = read_records(log_path) else { return out };
    for record in report.records {
        let Event::HarnessNote { note: NoteKind::Assignment, text } = record.event else { continue };
        for (at, _) in text.match_indices("out:") {
            let hex: String =
                text.get(at.saturating_add(4)..).unwrap_or("").chars().take_while(char::is_ascii_hexdigit).take(64).collect();
            if hex.len() < 8 {
                continue;
            }
            let handle = format!("out:{hex}");
            if let Ok(id) = blobs.resolve(&handle) {
                if !out.iter().any(|(_, seen)| *seen == id) {
                    out.push((handle, id));
                }
            }
        }
    }
    out
}

#[async_trait]
impl Tool for Finish {
    fn spec(&self) -> ToolSpec {
        spec(
            "finish",
            "Deliver the result and end the work. This is the only way a result is delivered. `answer` is the result, written for someone who has not seen your work. `quotes` are the exact lines of stored output that support it; each is checked against the stored output and refused if it does not match. `not_established` says what you could not determine or did not check. If the harness refuses the call, it says what is still open; deal with that and call finish again.",
            ToolClass::Terminal,
            &[
                req("answer", "string", "The result: what was done or found, and how it was confirmed."),
                opt("quotes", "array", "Supporting lines of stored output, copied exactly.").with("items", quote_items()),
                opt("not_established", "string", "What you could not determine, and what you did not check."),
                opt("evidence", "array", "Ids of ledger evidence records (e1, e2) the result rests on.").items("string"),
            ],
        )
    }
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let answer = match str_arg(args, "answer") {
            Some(a) if !a.trim().is_empty() => a,
            _ => {
                return ToolOutput::error(
                    "finish needs an `answer`: the result, written for someone who has not seen your work. Nothing was delivered.",
                )
            }
        };
        let quotes = match parse_quotes(args) {
            Ok(q) => q,
            Err(e) => return ToolOutput::error(e),
        };
        let verified = match gate::check_quotes(&ctx.blobs, &quotes) {
            Ok(v) => v,
            Err(text) => {
                return ToolOutput::error(format!("{text}\nNothing was delivered. Correct the quotes and call finish again."))
            }
        };
        let (jobs, agents) = self.running_work(ctx).await;
        if !jobs.is_empty() || !agents.is_empty() {
            return ToolOutput::error(running_refusal(&self.0.role, &jobs, &agents));
        }
        if self.0.is_child() {
            self.finish_child(ctx, answer, &verified, str_arg(args, "not_established"))
        } else {
            self.finish_lead(ctx, args, answer, &verified, str_arg(args, "not_established")).await
        }
    }
}

#[async_trait]
impl Tool for Verdict {
    fn spec(&self) -> ToolSpec {
        spec(
            "verdict",
            "Deliver your verdict on the claim you were asked to check, and end. `accepted` is true only if you tried to break the claim and could not. Each objection is one specific, checkable statement of what is wrong or unproven, naming the output and lines that show it. `opened` lists the handles of the outputs you actually examined; the harness compares it with the record of what you opened.",
            ToolClass::Terminal,
            &[
                req("accepted", "boolean", "true only if the claim survived your attempts to refute it."),
                opt("objections", "array", "What is wrong or unproven. Required when accepted is false.").items("string"),
                req("opened", "array", "Handles (out:…) of the outputs you examined.").items("string"),
            ],
        )
    }
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let s = &self.0;
        if !s.is_child() {
            return ToolOutput::error("`verdict` belongs to a verifier working on an assignment.");
        }
        let accepted = args.get("accepted").and_then(Value::as_bool).unwrap_or(false);
        let objections: Vec<String> =
            strings_of(args.get("objections")).into_iter().map(|o| o.trim().to_string()).filter(|o| !o.is_empty()).collect();
        if !accepted && objections.is_empty() {
            return ToolOutput::error(
                "accepted: false needs at least one objection: one specific, checkable statement of what is wrong or unproven.",
            );
        }
        if accepted && !objections.is_empty() {
            return ToolOutput::error(
                "accepted: true cannot come with objections — either they are objections, or it is accepted",
            );
        }
        let opened = strings_of(args.get("opened"));
        if opened.is_empty() {
            return ToolOutput::error(
                "List in `opened` the outputs you examined (their out:… handles). A verdict that examined nothing is not a verdict.",
            );
        }

        let seen = outputs_seen(&s.log_path);
        for handle in &opened {
            let known = ctx.blobs.resolve(handle).ok().is_some_and(|id| seen.contains(&id));
            if !known {
                return ToolOutput::error(format!(
                    "You listed {handle} as examined, but this session never opened it. Open it with out_read, or take it off the list."
                ));
            }
        }

        let assigned = assigned_outputs(&s.log_path, &ctx.blobs);
        let opened_ids: HashSet<BlobId> = opened.iter().filter_map(|h| ctx.blobs.resolve(h).ok()).collect();
        if !assigned.is_empty() && !assigned.iter().any(|(_, id)| opened_ids.contains(id)) {
            let named: Vec<&str> = assigned.iter().map(|(h, _)| h.as_str()).collect();
            return ToolOutput::error(format!(
                "Your assignment names outputs to examine ({}), but none of them is in `opened`. Open the evidence first (out_read), then call verdict again with the handles you opened.",
                named.join(", ")
            ));
        }

        let mut report = format!("Verdict: {}", if accepted { "accepted" } else { "not accepted" });
        if !objections.is_empty() {
            report.push_str("\nObjections:");
            for o in &objections {
                report.push_str(&format!("\n- {o}"));
            }
        }
        report.push_str(&format!("\nExamined: {}", opened.join(", ")));
        s.set_effect(Effect::Settle(Delivery {
            outcome: ChildOutcome::Returned,
            report,
            full: None,
            payload: json!({ "accepted": accepted, "objections": objections, "opened": opened }),
        }));
        ToolOutput::ok("verdict delivered", Body::Message("Your verdict was delivered. This session is finished.".into()))
    }
}

#[async_trait]
impl Tool for AskUser {
    fn spec(&self) -> ToolSpec {
        spec(
            "ask_user",
            "Ask the operator a question. The operator may be away for hours, so ask only what you cannot find out or decide yourself, and ask it so that a one-line reply settles it. With `blocking: true` the turn ends until the answer arrives. With `blocking: false` you keep working and the answer arrives later as a message; say in `meanwhile` what you will do until then.",
            ToolClass::Terminal,
            &[
                req("question", "string", "The question, with everything needed to answer it."),
                opt("options", "array", "Possible answers, when the question is a choice.").items("string"),
                opt("blocking", "boolean", "Whether work cannot continue without the answer.").default(json!(true)),
                opt("meanwhile", "string", "What you will work on while waiting. Required when blocking is false."),
            ],
        )
    }
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let s = &self.0;
        if s.is_child() {
            return ToolOutput::error(
                "Only the lead can ask the operator. Say what you need in your result (`not_established`), or call report_blocker if you cannot continue.",
            );
        }
        let Some(question) = str_arg(args, "question").filter(|q| !q.trim().is_empty()) else {
            return ToolOutput::error("ask_user needs a `question`, with everything needed to answer it.");
        };
        let blocking = args.get("blocking").and_then(Value::as_bool).unwrap_or(true);
        let meanwhile = str_arg(args, "meanwhile").map(str::trim).filter(|m| !m.is_empty());
        if !blocking && meanwhile.is_none() {
            return ToolOutput::error(
                "With `blocking: false` you must say in `meanwhile` what you will work on until the answer arrives. Add it, or ask with `blocking: true`.",
            );
        }
        let qid = match record_question(s, question, blocking) {
            Ok(q) => q,
            Err(e) => return ToolOutput::error(e),
        };
        s.emit(
            Author::Harness,
            inbox(InboxKind::Question, question.to_string(), strings_of(args.get("options")), blocking, ctx, qid),
        );
        if blocking {
            s.set_effect(Effect::EndTurn(TurnEndReason::Asked));
            return ToolOutput::ok(
                "asked — waiting for the operator",
                Body::Message(
                    "The question is in the operator's inbox. This turn ends here; you will be resumed with the answer.".into(),
                ),
            );
        }
        ToolOutput::ok(
            "asked",
            Body::Message(format!(
                "The question is in the operator's inbox. The answer will arrive as a message. Meanwhile: {}",
                meanwhile.unwrap_or_default()
            )),
        )
    }
}

#[async_trait]
impl Tool for ReportBlocker {
    fn spec(&self) -> ToolSpec {
        spec(
            "report_blocker",
            "Report that the work cannot continue because of something outside your control, and end. Use it only after you have tried what is within your reach: say in `tried` what you tried and what happened. Running low on patience, a long task, or an error you have not yet investigated are not blockers.",
            ToolClass::Terminal,
            &[
                req("class", "string", "The kind of blocker.").one_of(&["needs_approval", "needs_input", "environment", "impossible"]),
                req("what", "string", "What is blocking the work."),
                req("tried", "string", "What you tried, and what happened each time."),
                req("needs", "string", "What would unblock it, and from whom."),
            ],
        )
    }
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let s = &self.0;
        let mut fields: Vec<&str> = Vec::new();
        for key in ["what", "tried", "needs"] {
            match str_arg(args, key).filter(|t| !t.trim().is_empty()) {
                Some(t) => fields.push(t),
                None => {
                    return ToolOutput::error(format!(
                        "report_blocker needs `{key}` to contain text: what is blocking, what you tried, and what would unblock it."
                    ))
                }
            }
        }
        let class = str_arg(args, "class").unwrap_or("environment");
        let [what, tried, needs] = fields[..] else {
            return ToolOutput::error("report_blocker needs `what`, `tried` and `needs`.");
        };
        let text = format!("Blocked ({class}): {what}\nTried: {tried}\nNeeds: {needs}");

        if s.is_child() {
            s.set_effect(Effect::Settle(Delivery { outcome: ChildOutcome::Blocked, report: text, full: None, payload: Value::Null }));
            return ToolOutput::ok(
                "blocker reported",
                Body::Message("The blocker was reported to the agent that assigned this work. This session is finished.".into()),
            );
        }
        let qid = match record_question(s, &text, true) {
            Ok(q) => q,
            Err(e) => return ToolOutput::error(e),
        };
        s.emit(Author::Harness, inbox(InboxKind::Blocker, text, Vec::new(), true, ctx, qid));
        s.set_effect(Effect::EndTurn(TurnEndReason::Blocked));
        ToolOutput::ok(
            "blocker reported — waiting for the operator",
            Body::Message(
                "The blocker is in the operator's inbox. This turn ends here; you will be resumed when the operator replies.".into(),
            ),
        )
    }
}

#[async_trait]
impl Tool for Wait {
    fn spec(&self) -> ToolSpec {
        spec(
            "wait",
            "End the turn until a background job or an agent you started ends; you are then resumed with its result. Use it when there is nothing useful to do until then. It is refused when nothing is running.",
            ToolClass::Terminal,
            &[opt("reason", "string", "What you are waiting for, in a few words.")],
        )
    }
    async fn run(&self, ctx: &ToolCtx, _args: &Map<String, Value>) -> ToolOutput {
        let s = &self.0;
        let jobs: Vec<String> = ctx
            .jobs
            .list()
            .await
            .into_iter()
            .filter(|j| j.state == JobState::Running)
            .map(|j| {
                let command = j.command.split_whitespace().collect::<Vec<_>>().join(" ");
                format!("job {} ({})", j.id, cut_chars(&command, 60))
            })
            .collect();
        let agents: Vec<String> = s
            .orch
            .children(&s.session)
            .await
            .into_iter()
            .filter(|c| c.running)
            .map(|c| format!("agent {} ({})", c.id, c.role))
            .collect();
        if jobs.is_empty() && agents.is_empty() {
            let enders: Vec<String> = s
                .role
                .tools
                .iter()
                .filter(|t| matches!(t.as_str(), "finish" | "verdict" | "ask_user" | "report_blocker"))
                .cloned()
                .collect();
            let tail = if enders.is_empty() {
                "Carry on with the work.".to_string()
            } else {
                format!("Carry on with the work, or end with {}.", or_list(&enders))
            };
            return ToolOutput::error(format!("Nothing is running: no background job and no agent to wait for. {tail}"));
        }
        let mut groups = Vec::new();
        if !jobs.is_empty() {
            groups.push(jobs.join(", "));
        }
        if !agents.is_empty() {
            groups.push(agents.join(", "));
        }
        s.set_effect(Effect::EndTurn(TurnEndReason::Waiting));
        ToolOutput::ok(
            "waiting",
            Body::Message(format!("Waiting for: {}. You will be resumed as soon as one of them ends.", groups.join(" ; "))),
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::rtools::testkit::{core_role, rig, rig_with, Rig};
    use crate::rtools::ChildInfo;
    use loom_core::event::{ToolResult, ToolStatus as Status};
    use loom_core::ledger::{EvidenceInput, EvidenceKind};
    use loom_core::log::{Durability, SessionLog};

    fn map(v: Value) -> Map<String, Value> {
        v.as_object().cloned().unwrap()
    }

    fn lead() -> Rig {
        rig("lead", false, true)
    }

    fn effect(r: &Rig) -> Option<Effect> {
        r.shared.take_effect()
    }

    fn inbox_items(r: &Rig) -> Vec<InboxItem> {
        r.shared
            .take_emitted()
            .into_iter()
            .filter_map(|(_, e)| if let Event::InboxOpened(i) = e { Some(i) } else { None })
            .collect()
    }

    fn accepted_payload() -> Value {
        json!({"accepted": true, "objections": [], "opened": ["out:aa"]})
    }

    fn rejected_payload() -> Value {
        json!({"accepted": false, "objections": ["no test ran", "line 4 is wrong"], "opened": ["out:aa"]})
    }

    // ---- finish ----

    #[tokio::test]
    async fn finish_needs_an_answer() {
        let r = lead();
        let res = r.call("finish", json!({"answer": "  \n"})).await;
        assert_eq!(res.status, Status::Error);
        assert!(res.text.contains("finish needs an `answer`"), "{}", res.text);
        assert!(res.text.contains("Nothing was delivered."));
        assert!(effect(&r).is_none());
    }

    #[tokio::test]
    async fn finish_names_a_malformed_quote_element() {
        let r = lead();
        let args = map(json!({"answer": "done", "quotes": [{"handle": "out:aa", "start": 1, "end": 1, "text": "x"}, "oops"]}));
        let out = Finish(r.shared.clone()).run(&r.env.ctx, &args).await;
        assert_eq!(out.status, Status::Error);
        let Body::Message(m) = out.body else { panic!("message expected") };
        assert!(m.contains("quote 2") && m.contains("{handle, start, end, text}"), "{m}");
        assert!(effect(&r).is_none());
    }

    #[tokio::test]
    async fn finish_refuses_a_quote_that_does_not_match() {
        let r = lead();
        let h = r.output("alpha\nbeta\n", "bash", ToolClass::Exec);
        let res = r.call("finish", json!({"answer": "done", "quotes": [{"handle": h, "start": 1, "end": 2, "text": "gamma"}]})).await;
        assert_eq!(res.status, Status::Error);
        assert!(res.text.contains("does not occur"), "{}", res.text);
        assert!(res.text.contains("Nothing was delivered. Correct the quotes and call finish again."));
        assert!(effect(&r).is_none());
        assert!(r.shared.ledger().unwrap().finishes.is_empty());
    }

    #[tokio::test]
    async fn child_finish_settles_with_report_and_payload() {
        let r = rig("worker", true, false);
        let h = r.output("alpha\nbeta\ngamma\n", "bash", ToolClass::Exec);
        let res = r
            .call(
                "finish",
                json!({"answer": "It is beta.", "quotes": [{"handle": h, "start": 2, "end": 2, "text": "beta"}], "not_established": "gamma"}),
            )
            .await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        assert!(res.text.contains("delivered") && res.text.contains("Your result was delivered. This session is finished."));
        let Some(Effect::Settle(d)) = effect(&r) else { panic!("settle expected") };
        assert_eq!(d.outcome, ChildOutcome::Returned);
        assert!(d.full.is_none());
        assert!(d.report.starts_with("Outcome: returned\nAnswer:\nIt is beta."), "{}", d.report);
        assert!(d.report.contains("lines 2-2: beta") && d.report.contains("Not established (stated by the agent):\ngamma"));
        assert_eq!(d.payload, json!({"quotes": [{"handle": h, "start": 2, "end": 2, "text": "beta"}]}));
        assert!(inbox_items(&r).is_empty());
    }

    #[tokio::test]
    async fn child_finish_stores_a_long_answer() {
        let r = rig("worker", true, false);
        let answer = "x".repeat(REPORT_MAX_CHARS + 5);
        let res = r.call("finish", json!({"answer": answer})).await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        let Some(Effect::Settle(d)) = effect(&r) else { panic!("settle expected") };
        let full = d.full.expect("full answer stored");
        assert_eq!(r.env.ctx.blobs.read_lines(&full.id, 1, 1).unwrap().text.trim_end(), answer);
        assert!(d.report.contains(&full.handle()), "{}", d.report);
        assert!(d.report.contains("report cut at"));
    }

    #[tokio::test]
    async fn lead_finish_with_open_items_is_refused() {
        let r = lead();
        r.model_op(LedgerOp::ClaimAdd { text: "the parser is fixed".into() });
        let res = r.call("finish", json!({"answer": "all done"})).await;
        assert_eq!(res.status, Status::Error);
        assert!(res.text.contains("still has open items"), "{}", res.text);
        assert!(effect(&r).is_none());
        assert!(r.shared.ledger().unwrap().finishes.is_empty());
        assert!(r.orch.calls().is_empty());
    }

    #[tokio::test]
    async fn lead_finish_verified_is_delivered() {
        let r = lead();
        r.user_op(LedgerOp::GoalSet { text: "fix the parser".into() });
        r.user_op(LedgerOp::ConstraintAdd { text: "do not touch the lexer".into() });
        r.orch.settle("s-kid1", ChildOutcome::Returned, "looked fine", accepted_payload());
        let h = r.output("alpha\nbeta\n", "bash", ToolClass::Exec);
        let res = r
            .call("finish", json!({"answer": "Parser fixed.", "quotes": [{"handle": h, "start": 1, "end": 1, "text": "alpha"}]}))
            .await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        assert!(res.text.contains("finished — verified by s-kid1"), "{}", res.text);
        assert!(res.text.contains("The result was delivered to the operator."));
        assert_eq!(r.orch.calls(), vec!["spawn verifier".to_string(), "join s-kid1".to_string()]);

        let spawned = r.orch.spawned.lock().unwrap().clone();
        let req = &spawned[0].1;
        assert!(req.awaited && req.harness && req.mode == SpawnMode::Fresh);
        assert_eq!(req.role, "verifier");
        assert_eq!(req.title, "verify finish f1");
        assert_eq!(req.budget.max_steps, Some(r.shared.agents.child_max_steps));
        let ctx_text = req.brief.context.clone().unwrap();
        assert!(ctx_text.contains("Goal (set by the operator):\nfix the parser"), "{ctx_text}");
        assert!(ctx_text.contains("Constraints:\n- do not touch the lexer"));
        assert!(ctx_text.contains("The lead's summary of the result:\nParser fixed."));
        assert!(ctx_text.contains(&format!("- {h} lines 1-1: alpha")));

        let st = r.shared.ledger().unwrap();
        assert_eq!(st.finishes.len(), 1);
        assert_eq!(st.finishes[0].accepted, Some(true));
        assert_eq!(effect(&r), Some(Effect::EndTurn(TurnEndReason::Finished)));
        let items = inbox_items(&r);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].kind, InboxKind::Finished);
        assert_eq!(
            items[0].text,
            format!("Parser fixed.\n\nQuoted support (checked against the stored output):\n- {h} lines 1-1: alpha\n\n[verified by s-kid1]")
        );
        assert_eq!(items[0].reference.as_deref(), Some("f1"));
        assert!(!items[0].blocking);
        assert_eq!(items[0].call_id, Some(r.env.ctx.call_id.clone()));
    }

    #[tokio::test]
    async fn lead_finish_rejected_returns_objections_and_sets_no_effect() {
        let r = lead();
        r.orch.settle("s-kid1", ChildOutcome::Returned, "I could not reproduce the fix.", rejected_payload());
        let res = r.call("finish", json!({"answer": "Parser fixed."})).await;
        assert_eq!(res.status, Status::Error);
        assert!(res.text.contains("not accepted"), "{}", res.text);
        assert!(res.text.contains("An independent verifier (s-kid1) examined the result and did not accept it.\n- no test ran\n- line 4 is wrong\n\nI could not reproduce the fix.\n\nThe mission is not finished."), "{}", res.text);
        assert!(effect(&r).is_none());
        assert!(inbox_items(&r).is_empty());
        let st = r.shared.ledger().unwrap();
        assert_eq!(st.finishes[0].accepted, Some(false));
        assert_eq!(st.finishes[0].objections, vec!["no test ran".to_string(), "line 4 is wrong".to_string()]);
    }

    fn spawn_count(r: &Rig) -> usize {
        r.orch.calls().iter().filter(|c| c.starts_with("spawn")).count()
    }

    #[tokio::test]
    async fn third_finish_after_two_rejections_is_escalated_and_verified_again_after_the_answer() {
        let r = lead();
        r.orch.settle("s-kid1", ChildOutcome::Returned, "no", rejected_payload());
        r.orch.settle("s-kid2", ChildOutcome::Returned, "no", rejected_payload());
        for _ in 0..2 {
            let res = r.call("finish", json!({"answer": "Parser fixed."})).await;
            assert_eq!(res.status, Status::Error, "{}", res.text);
        }
        assert_eq!(spawn_count(&r), 2);
        r.shared.take_emitted();
        let res = r.call("finish", json!({"answer": "Parser fixed.", "not_established": "the lexer"})).await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        assert!(res.text.contains("NOT delivered as finished") && res.text.contains("rejected it 2 times"), "{}", res.text);
        assert_eq!(spawn_count(&r), 2);
        assert_eq!(effect(&r), Some(Effect::EndTurn(TurnEndReason::Blocked)));
        let items = inbox_items(&r);
        assert_eq!(items.len(), 1);
        assert_eq!((items[0].kind, items[0].blocking), (InboxKind::Blocker, true));
        let t = &items[0].text;
        assert!(t.starts_with("NOT VERIFIED - REJECTED 2 TIMES"), "{t}");
        assert!(t.contains("Rejection 1 (f1):\n- no test ran\n- line 4 is wrong\nRejection 2 (f2):\n- no test ran"), "{t}");
        assert!(t.contains("(NOT VERIFIED; it was not delivered as finished):\nParser fixed."), "{t}");
        assert!(t.contains("Not established (stated by the lead):\nthe lexer"), "{t}");
        assert_eq!(items[0].reference.as_deref(), Some("q1"));
        let st = r.shared.ledger().unwrap();
        assert_eq!(st.finishes.len(), 3);
        assert_eq!(st.finishes[2].accepted, None);
        assert!(st.questions[0].blocking && st.questions[0].text.starts_with("Finish f3 "));

        // Until the operator answers, the open question keeps finish closed.
        let res = r.call("finish", json!({"answer": "Parser fixed."})).await;
        assert_eq!(res.status, Status::Error, "{}", res.text);
        assert!(effect(&r).is_none());

        // After the answer the rejections no longer count: the next finish is verified again.
        r.user_op(LedgerOp::QuestionAnswer { id: "q1".into(), answer: "go on".into() });
        r.orch.settle("s-kid3", ChildOutcome::Returned, "fine", accepted_payload());
        let res = r.call("finish", json!({"answer": "Parser fixed."})).await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        assert!(res.text.contains("finished — verified by s-kid3"), "{}", res.text);
        assert_eq!(spawn_count(&r), 3);
        assert_eq!(effect(&r), Some(Effect::EndTurn(TurnEndReason::Finished)));
    }

    #[tokio::test]
    async fn verifier_ending_without_a_verdict_is_escalated_not_delivered() {
        let r = lead();
        r.orch.settle("s-kid1", ChildOutcome::BudgetExhausted, "ran out", Value::Null);
        let res = r.call("finish", json!({"answer": "Parser fixed."})).await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        assert!(res.text.contains("could not be verified") && res.text.contains("ended as budget exhausted"), "{}", res.text);
        assert_eq!(effect(&r), Some(Effect::EndTurn(TurnEndReason::Blocked)));
        let items = inbox_items(&r);
        assert_eq!(items.len(), 1);
        assert_eq!((items[0].kind, items[0].blocking), (InboxKind::Blocker, true));
        assert!(items[0].text.starts_with("NOT VERIFIED - VERIFICATION COULD NOT BE RUN"), "{}", items[0].text);
        assert!(items[0].text.contains("Verification could not be run: the verifier (s-kid1) ended as budget exhausted without giving a verdict"));
        assert!(items[0].text.contains("(NOT VERIFIED; it was not delivered as finished):\nParser fixed."));
        // What the verifier reported instead of a verdict reaches the operator and the lead.
        assert!(items[0].text.contains("without giving a verdict\n\nThe verifier's report:\nran out\n\nThe lead's answer"), "{}", items[0].text);
        assert!(res.text.contains("The verifier's report:\nran out"), "{}", res.text);
        assert_eq!(r.shared.ledger().unwrap().finishes[0].accepted, None);
    }

    #[tokio::test]
    async fn a_long_verifier_report_is_cut_with_a_visible_marker() {
        let r = lead();
        let long = "é".repeat(REPORT_MAX_CHARS + 7);
        r.orch.settle("s-kid1", ChildOutcome::Blocked, &long, Value::Null);
        let res = r.call("finish", json!({"answer": "Parser fixed."})).await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        let items = inbox_items(&r);
        let marker = format!("\n[report cut at {REPORT_MAX_CHARS} of {} characters]", REPORT_MAX_CHARS + 7);
        assert!(items[0].text.contains(&format!("{}{marker}", "é".repeat(REPORT_MAX_CHARS))), "marker missing");
        assert!(!items[0].text.contains(&long));
        assert_eq!(cut_report("short"), "short");
    }

    #[tokio::test]
    async fn spawn_failure_is_escalated_not_delivered() {
        let r = lead();
        r.orch.spawn_script.lock().unwrap().push_back(Err("Too many agents are running.".into()));
        let res = r.call("finish", json!({"answer": "Parser fixed."})).await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        assert!(res.text.contains("verification could not be run: Too many agents are running."), "{}", res.text);
        assert_eq!(effect(&r), Some(Effect::EndTurn(TurnEndReason::Blocked)));
        let items = inbox_items(&r);
        assert_eq!(items.len(), 1);
        assert_ne!(items[0].kind, InboxKind::Finished);
        assert!(items[0].blocking);
        assert!(items[0].text.contains("Verification could not be run: Too many agents are running."), "{}", items[0].text);
        assert!(items[0].text.contains("NOT VERIFIED") && items[0].text.contains("Parser fixed."));
    }

    #[tokio::test]
    async fn a_spawn_refused_by_the_shutdown_records_nothing_and_is_verified_on_the_next_finish() {
        let r = lead();
        r.orch.spawn_script.lock().unwrap().push_back(Err(SHUTTING_DOWN.into()));
        let res = r.call("finish", json!({"answer": "Parser fixed."})).await;
        assert_eq!(res.status, Status::Error, "{}", res.text);
        assert!(res.text.contains("The harness is shutting down") && res.text.contains("nothing was delivered. Call finish again."), "{}", res.text);
        assert!(effect(&r).is_none());
        assert!(inbox_items(&r).is_empty());
        let st = r.shared.ledger().unwrap();
        assert!(st.questions.is_empty());
        assert_eq!(st.finishes[0].accepted, None);
        // After the restart the same finish goes to a verifier.
        r.orch.settle("s-kid1", ChildOutcome::Returned, "fine", accepted_payload());
        let res = r.call("finish", json!({"answer": "Parser fixed."})).await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        assert!(res.text.contains("finished — verified by s-kid1"), "{}", res.text);
    }

    #[tokio::test]
    async fn a_question_the_lead_wrote_does_not_restart_the_rejection_count() {
        let r = lead();
        r.orch.settle("s-kid1", ChildOutcome::Returned, "no", rejected_payload());
        r.orch.settle("s-kid2", ChildOutcome::Returned, "no", rejected_payload());
        let res = r.call("finish", json!({"answer": "Parser fixed."})).await;
        assert_eq!(res.status, Status::Error, "{}", res.text);
        // Questions in the escalation's own words: one names a finish that does not exist, one the
        // finish about to be made, one a finish the verifier judged. The operator answers all three.
        for (i, named) in ["f99", "f3", "f1"].iter().enumerate() {
            let question = escalation_question(named, "NOT VERIFIED - REJECTED 2 TIMES");
            let res = r.call("ask_user", json!({"question": question})).await;
            assert_eq!(res.status, Status::Ok, "{}", res.text);
            r.user_op(LedgerOp::QuestionAnswer { id: format!("q{}", i + 1), answer: "go on".into() });
        }
        assert_eq!(effect(&r), Some(Effect::EndTurn(TurnEndReason::Asked)));
        let res = r.call("finish", json!({"answer": "Parser fixed."})).await;
        assert_eq!(res.status, Status::Error, "{}", res.text);
        assert_eq!(spawn_count(&r), 2);
        r.shared.take_emitted();
        // Both rejections still count: the third finish is escalated, not verified again.
        let res = r.call("finish", json!({"answer": "Parser fixed."})).await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        assert_eq!(spawn_count(&r), 2);
        assert_eq!(effect(&r), Some(Effect::EndTurn(TurnEndReason::Blocked)));
        let items = inbox_items(&r);
        assert!(items[0].text.starts_with("NOT VERIFIED - REJECTED 2 TIMES"), "{}", items[0].text);
    }

    #[tokio::test]
    async fn rejections_before_an_accepted_finish_no_longer_count() {
        let r = lead();
        r.orch.settle("s-kid1", ChildOutcome::Returned, "no", rejected_payload());
        r.orch.settle("s-kid2", ChildOutcome::Returned, "fine", accepted_payload());
        r.orch.settle("s-kid3", ChildOutcome::Returned, "no", rejected_payload());
        r.orch.settle("s-kid4", ChildOutcome::Returned, "fine", accepted_payload());
        let res = r.call("finish", json!({"answer": "Parser fixed."})).await;
        assert_eq!(res.status, Status::Error, "{}", res.text);
        let res = r.call("finish", json!({"answer": "Parser fixed."})).await;
        assert!(res.text.contains("finished — verified by s-kid2"), "{}", res.text);
        assert_eq!(effect(&r), Some(Effect::EndTurn(TurnEndReason::Finished)));
        // The operator sends a follow-up; its first finish is rejected.
        let res = r.call("finish", json!({"answer": "Lexer fixed too."})).await;
        assert_eq!(res.status, Status::Error, "{}", res.text);
        assert!(effect(&r).is_none());
        // One rejection since the accepted finish: the next one is verified, not escalated.
        let res = r.call("finish", json!({"answer": "Lexer fixed too."})).await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        assert!(res.text.contains("finished — verified by s-kid4"), "{}", res.text);
        assert_eq!(spawn_count(&r), 4);
        let verdicts: Vec<Option<bool>> = r.shared.ledger().unwrap().finishes.iter().map(|f| f.accepted).collect();
        assert_eq!(verdicts, vec![Some(false), Some(true), Some(false), Some(true)]);
    }

    #[tokio::test]
    async fn finish_without_required_verification_still_says_not_verified() {
        let r = rig_with(core_role("lead"), false, true, loom_core::config::AgentsCfg { verify_finish: false, ..Default::default() });
        let res = r.call("finish", json!({"answer": "Parser fixed."})).await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        assert!(res.text.contains("finished — not verified"), "{}", res.text);
        assert_eq!(spawn_count(&r), 0);
        assert_eq!(effect(&r), Some(Effect::EndTurn(TurnEndReason::Finished)));
    }

    #[tokio::test]
    async fn finish_carries_not_established_and_quotes_to_the_verifier_and_the_operator() {
        let r = lead();
        r.orch.settle("s-kid1", ChildOutcome::Returned, "fine", accepted_payload());
        let res = r.call("finish", json!({"answer": "Parser fixed.", "not_established": "the lexer was not run"})).await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        let spawned = r.orch.spawned.lock().unwrap().clone();
        let ctx_text = spawned[0].1.brief.context.clone().unwrap();
        assert!(ctx_text.contains("What the lead says it did not establish:\nthe lexer was not run"), "{ctx_text}");
        let items = inbox_items(&r);
        assert_eq!(
            items[0].text,
            "Parser fixed.\n\nNot established (stated by the lead):\nthe lexer was not run\n\n[verified by s-kid1]"
        );
    }

    #[tokio::test]
    async fn finish_is_refused_while_a_job_is_running() {
        let r = lead();
        let started = r.call("bash", json!({"command": "sleep 30", "background": true})).await;
        assert_eq!(started.status, Status::Ok, "{}", started.text);
        let res = r.call("finish", json!({"answer": "Parser fixed."})).await;
        assert_eq!(res.status, Status::Error, "{}", res.text);
        assert!(res.text.contains("job j1 (sleep 30)") && res.text.contains("job_kill") && res.text.contains("wait"), "{}", res.text);
        assert!(!res.text.contains("agent_stop"), "{}", res.text);
        assert!(effect(&r).is_none());
        assert!(r.shared.ledger().unwrap().finishes.is_empty());
        assert_eq!(spawn_count(&r), 0);
        let killed = r.call("job_kill", json!({"job": "j1"})).await;
        assert_eq!(killed.status, Status::Ok, "{}", killed.text);
        r.orch.settle("s-kid1", ChildOutcome::Returned, "fine", accepted_payload());
        let res = r.call("finish", json!({"answer": "Parser fixed."})).await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
    }

    #[tokio::test]
    async fn child_finish_is_refused_while_its_job_is_running() {
        let r = rig("worker", true, false);
        let started = r.call("bash", json!({"command": "sleep 30", "background": true})).await;
        assert_eq!(started.status, Status::Ok, "{}", started.text);
        let res = r.call("finish", json!({"answer": "It is beta."})).await;
        assert_eq!(res.status, Status::Error, "{}", res.text);
        assert!(res.text.contains("finish was refused") && res.text.contains("job j1 (sleep 30)"), "{}", res.text);
        assert!(res.text.contains("Nothing was delivered."), "{}", res.text);
        assert!(res.text.contains("To go on: wait for it to report (`wait`), or end a job with `job_kill`; then call finish again."), "{}", res.text);
        assert!(effect(&r).is_none());
        let killed = r.call("job_kill", json!({"job": "j1"})).await;
        assert_eq!(killed.status, Status::Ok, "{}", killed.text);
        let res = r.call("finish", json!({"answer": "It is beta."})).await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        assert!(matches!(effect(&r), Some(Effect::Settle(_))));
    }

    #[tokio::test]
    async fn finish_is_refused_while_a_child_agent_is_running() {
        let r = lead();
        r.orch.running_child("s-kid9", "worker");
        let res = r.call("finish", json!({"answer": "Parser fixed."})).await;
        assert_eq!(res.status, Status::Error, "{}", res.text);
        assert!(res.text.contains("agent s-kid9 (worker)") && res.text.contains("agent_stop"), "{}", res.text);
        assert!(!res.text.contains("job_kill"), "{}", res.text);
        // An agent left idle by a restart cannot be ended with a tool; the refusal says who can.
        assert!(res.text.contains("the operator has to resume it. Tell the operator with `ask_user` or `report_blocker`."), "{}", res.text);
        assert!(effect(&r).is_none());
        assert!(r.shared.ledger().unwrap().finishes.is_empty());
        assert_eq!(spawn_count(&r), 0);
    }

    #[test]
    fn the_running_work_refusal_names_only_tools_the_role_has() {
        let mut role = core_role("lead");
        let (jobs, agents) = (vec!["job j1 (make)".to_string()], vec!["agent s-kid1 (worker)".to_string()]);
        let all = running_refusal(&role, &jobs, &agents);
        assert!(
            all.contains("still running: job j1 (make), agent s-kid1 (worker). Nothing was delivered. To go on: wait for it to report (`wait`), or end a job with `job_kill`, or end an agent with `agent_stop`; then call finish again."),
            "{all}"
        );
        role.tools.retain(|t| !matches!(t.as_str(), "wait" | "job_kill" | "agent_stop" | "report_blocker"));
        let bare = running_refusal(&role, &jobs, &agents);
        assert!(bare.contains("Nothing was delivered. Call finish again when it has ended."), "{bare}");
        assert!(!bare.contains("`wait`") && !bare.contains("job_kill") && !bare.contains("agent_stop"), "{bare}");
        assert!(bare.ends_with("Tell the operator with `ask_user`."), "{bare}");
        role.tools.retain(|t| t != "ask_user");
        assert!(running_refusal(&role, &jobs, &agents).ends_with("the operator has to resume it."));
        assert!(!running_refusal(&role, &jobs, &[]).contains("operator"));
    }

    #[tokio::test]
    async fn cancellation_while_verifying_delivers_nothing() {
        let r = lead();
        *r.orch.hang_all.lock().unwrap() = true;
        let args = map(json!({"answer": "Parser fixed."}));
        let tool = Finish(r.shared.clone());
        let ctx = r.env.ctx.clone();
        let canceller = {
            let cancel = ctx.cancel.clone();
            async move {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                cancel.cancel();
            }
        };
        let (out, ()) = tokio::join!(tool.run(&ctx, &args), canceller);
        assert_eq!(out.status, Status::Error);
        let Body::Message(m) = out.body else { panic!("message expected") };
        assert!(m.starts_with("Interrupted while the result was being verified; nothing was delivered."), "{m}");
        assert!(effect(&r).is_none());
        assert!(inbox_items(&r).is_empty());
    }

    // ---- verdict ----

    /// A verifier session whose log shows it produced one output and read a view of another.
    fn verifier_with_log() -> (Rig, String, String) {
        let r = rig("verifier", true, false);
        let produced = r.env.ctx.blobs.put_bytes(b"produced\n").unwrap();
        let viewed = r.env.ctx.blobs.put_bytes(b"viewed\n").unwrap();
        let view_text = r.env.ctx.blobs.put_bytes(b"a view\n").unwrap();
        let mut log = SessionLog::create(&r.shared.log_path, Durability::Batch).unwrap();
        let result = |output: Option<BlobRef>, meta: Map<String, Value>| {
            Event::ToolResult(ToolResult {
                call_id: "c1".into(),
                name: "bash".into(),
                status: Status::Ok,
                text: "x".into(),
                output,
                cut: false,
                class: ToolClass::Exec,
                meta,
                duration_ms: 1,
            })
        };
        log.append(Author::Tool, result(Some(produced.clone()), Map::new())).unwrap();
        log.append(Author::Tool, result(Some(view_text), map(json!({ META_OF_BLOB: viewed.id.as_str() })))).unwrap();
        (r, produced.handle(), viewed.handle())
    }

    #[tokio::test]
    async fn verdict_is_refused_outside_a_child_session() {
        let r = lead();
        let out = Verdict(r.shared.clone()).run(&r.env.ctx, &map(json!({"accepted": true, "opened": ["out:aa"]}))).await;
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.body, Body::Message("`verdict` belongs to a verifier working on an assignment.".into()));
    }

    #[tokio::test]
    async fn verdict_refusals() {
        let (r, produced, _) = verifier_with_log();
        let res = r.call("verdict", json!({"accepted": false, "opened": [produced]})).await;
        assert_eq!(res.status, Status::Error);
        assert!(res.text.contains("accepted: false needs at least one objection"), "{}", res.text);
        let res = r.call("verdict", json!({"accepted": false, "objections": ["  "], "opened": [produced]})).await;
        assert!(res.text.contains("needs at least one objection"), "{}", res.text);
        let res = r.call("verdict", json!({"accepted": true, "objections": ["x"], "opened": [produced]})).await;
        assert!(res.text.contains("accepted: true cannot come with objections"), "{}", res.text);
        let res = r.call("verdict", json!({"accepted": true, "opened": []})).await;
        assert!(res.text.contains("A verdict that examined nothing is not a verdict."), "{}", res.text);
        let res = r.call("verdict", json!({"accepted": true, "opened": ["out:deadbeef00"]})).await;
        assert!(res.text.contains("You listed out:deadbeef00 as examined, but this session never opened it."), "{}", res.text);
        // Stored, but not by this session.
        let other = r.env.ctx.blobs.put_bytes(b"someone else's\n").unwrap().handle();
        let res = r.call("verdict", json!({"accepted": true, "opened": [other]})).await;
        assert!(res.text.contains("never opened it. Open it with out_read, or take it off the list."), "{}", res.text);
        assert!(effect(&r).is_none());
    }

    #[tokio::test]
    async fn verdict_settles_with_payload() {
        let (r, produced, viewed) = verifier_with_log();
        let res = r
            .call("verdict", json!({"accepted": false, "objections": ["no test ran"], "opened": [produced, viewed]}))
            .await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        assert!(res.text.contains("verdict delivered"));
        let Some(Effect::Settle(d)) = effect(&r) else { panic!("settle expected") };
        assert_eq!(d.outcome, ChildOutcome::Returned);
        assert_eq!(d.report, format!("Verdict: not accepted\nObjections:\n- no test ran\nExamined: {produced}, {viewed}"));
        assert_eq!(d.payload, json!({"accepted": false, "objections": ["no test ran"], "opened": [produced, viewed]}));

        let res = r.call("verdict", json!({"accepted": true, "opened": [produced]})).await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        let Some(Effect::Settle(d)) = effect(&r) else { panic!("settle expected") };
        assert_eq!(d.report, format!("Verdict: accepted\nExamined: {produced}"));
        assert_eq!(d.payload["accepted"], json!(true));
    }

    #[tokio::test]
    async fn verdict_must_open_the_evidence_its_assignment_names() {
        let (r, produced, viewed) = verifier_with_log();
        let (mut log, _) = SessionLog::open(&r.shared.log_path, Durability::Batch).unwrap();
        let text = format!("Question: Try to refute it.\n\nContext: Lines the lead quotes:\n- {viewed} lines 1-1: viewed");
        log.append(Author::Agent("s-lead".into()), Event::HarnessNote { note: NoteKind::Assignment, text }).unwrap();
        // The verifier opened something it produced itself, but not the evidence it was pointed at.
        let res = r.call("verdict", json!({"accepted": true, "opened": [produced]})).await;
        assert_eq!(res.status, Status::Error, "{}", res.text);
        assert!(res.text.contains("Your assignment names outputs to examine") && res.text.contains(&viewed), "{}", res.text);
        assert!(res.text.contains("Open the evidence first"), "{}", res.text);
        assert!(effect(&r).is_none());
        // Naming one of them (which it really viewed) is enough.
        let res = r.call("verdict", json!({"accepted": true, "opened": [produced, viewed]})).await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        assert!(matches!(effect(&r), Some(Effect::Settle(_))));
    }

    // ---- ask_user ----

    #[tokio::test]
    async fn blocking_question_ends_the_turn_and_is_recorded() {
        let r = lead();
        let res = r.call("ask_user", json!({"question": "Which database?", "options": ["pg", "sqlite"]})).await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        assert!(res.text.contains("asked — waiting for the operator"));
        assert!(res.text.contains("This turn ends here; you will be resumed with the answer."));
        assert_eq!(effect(&r), Some(Effect::EndTurn(TurnEndReason::Asked)));
        let items = inbox_items(&r);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].kind, InboxKind::Question);
        assert_eq!(items[0].options, vec!["pg".to_string(), "sqlite".to_string()]);
        assert!(items[0].blocking);
        assert_eq!(items[0].reference.as_deref(), Some("q1"));
        let st = r.shared.ledger().unwrap();
        assert_eq!(st.questions.len(), 1);
        assert!(st.questions[0].blocking && st.questions[0].text == "Which database?");
    }

    #[tokio::test]
    async fn non_blocking_question_needs_meanwhile_and_keeps_going() {
        let r = lead();
        let res = r.call("ask_user", json!({"question": "Which database?", "blocking": false})).await;
        assert_eq!(res.status, Status::Error);
        assert!(res.text.contains("meanwhile"), "{}", res.text);
        assert!(r.shared.ledger().unwrap().questions.is_empty());

        let res = r.call("ask_user", json!({"question": "Which database?", "blocking": false, "meanwhile": "write the schema"})).await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        assert!(res.text.contains("asked"));
        assert!(res.text.contains("The answer will arrive as a message. Meanwhile: write the schema"), "{}", res.text);
        assert!(effect(&r).is_none());
        let items = inbox_items(&r);
        assert!(!items[0].blocking);
        assert_eq!(items[0].reference.as_deref(), Some("q1"));
        assert!(!r.shared.ledger().unwrap().questions[0].blocking);
    }

    #[tokio::test]
    async fn child_cannot_ask_the_operator() {
        let r = rig("worker", true, false);
        let out = AskUser(r.shared.clone()).run(&r.env.ctx, &map(json!({"question": "Which?"}))).await;
        assert_eq!(out.status, Status::Error);
        let Body::Message(m) = out.body else { panic!("message expected") };
        assert!(m.starts_with("Only the lead can ask the operator."), "{m}");
        assert!(effect(&r).is_none());
        assert!(inbox_items(&r).is_empty());
    }

    #[tokio::test]
    async fn question_without_a_mission_still_reaches_the_inbox() {
        let r = rig("lead", false, false);
        let res = r.call("ask_user", json!({"question": "Which?"})).await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        let items = inbox_items(&r);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].reference, None);
    }

    // ---- report_blocker ----

    #[tokio::test]
    async fn child_blocker_settles_blocked() {
        let r = rig("worker", true, false);
        let res = r
            .call("report_blocker", json!({"class": "environment", "what": "no network", "tried": "curl, retry", "needs": "proxy access"}))
            .await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        assert!(res.text.contains("blocker reported"));
        let Some(Effect::Settle(d)) = effect(&r) else { panic!("settle expected") };
        assert_eq!(d.outcome, ChildOutcome::Blocked);
        assert_eq!(d.report, "Blocked (environment): no network\nTried: curl, retry\nNeeds: proxy access");
        assert_eq!(d.payload, Value::Null);
        assert!(d.full.is_none());
        assert!(inbox_items(&r).is_empty());
    }

    #[tokio::test]
    async fn lead_blocker_opens_a_blocking_inbox_item() {
        let r = lead();
        let res = r
            .call("report_blocker", json!({"class": "needs_input", "what": "no key", "tried": "env, config", "needs": "an API key"}))
            .await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        assert!(res.text.contains("blocker reported — waiting for the operator"));
        assert_eq!(effect(&r), Some(Effect::EndTurn(TurnEndReason::Blocked)));
        let items = inbox_items(&r);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].kind, InboxKind::Blocker);
        assert!(items[0].blocking);
        assert_eq!(items[0].text, "Blocked (needs_input): no key\nTried: env, config\nNeeds: an API key");
        assert_eq!(items[0].reference.as_deref(), Some("q1"));
        assert!(r.shared.ledger().unwrap().questions[0].blocking);
    }

    #[tokio::test]
    async fn blocker_fields_must_have_text() {
        let r = lead();
        let res = r.call("report_blocker", json!({"class": "impossible", "what": "x", "tried": " ", "needs": "y"})).await;
        assert_eq!(res.status, Status::Error);
        assert!(res.text.contains("`tried`"), "{}", res.text);
        assert!(effect(&r).is_none());
    }

    // ---- wait ----

    #[tokio::test]
    async fn wait_with_nothing_running_is_refused() {
        let r = lead();
        let res = r.call("wait", json!({})).await;
        assert_eq!(res.status, Status::Error);
        assert!(
            res.text.contains("Nothing is running: no background job and no agent to wait for. Carry on with the work, or end with `finish`, `ask_user` or `report_blocker`."),
            "{}",
            res.text
        );
        assert!(effect(&r).is_none());
    }

    #[tokio::test]
    async fn wait_names_a_running_job() {
        let r = lead();
        let started = r.call("bash", json!({"command": "sleep 30", "background": true})).await;
        assert_eq!(started.status, Status::Ok, "{}", started.text);
        let res = r.call("wait", json!({"reason": "the job"})).await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        assert!(res.text.contains("waiting"));
        assert!(res.text.contains("Waiting for: job j1 (sleep 30). You will be resumed as soon as one of them ends."), "{}", res.text);
        assert_eq!(effect(&r), Some(Effect::EndTurn(TurnEndReason::Waiting)));
        let killed = r.call("job_kill", json!({"job": "j1"})).await;
        assert_eq!(killed.status, Status::Ok, "{}", killed.text);
        // An ended job is not waited for.
        let res = r.call("wait", json!({})).await;
        assert_eq!(res.status, Status::Error, "{}", res.text);
    }

    #[tokio::test]
    async fn wait_names_a_running_child_and_ignores_finished_ones() {
        let r = lead();
        r.orch.running_child("s-kid1", "worker");
        r.orch.children.lock().unwrap().push(ChildInfo {
            id: "s-old".into(),
            role: "worker".into(),
            title: "done".into(),
            step: 9,
            running: false,
        });
        let res = r.call("wait", json!({})).await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        assert!(res.text.contains("Waiting for: agent s-kid1 (worker). You will be resumed"), "{}", res.text);
        assert!(!res.text.contains("s-old"));
        assert_eq!(effect(&r), Some(Effect::EndTurn(TurnEndReason::Waiting)));
    }

    #[test]
    fn helpers_cut_and_join() {
        let cut = cut_chars(&"a".repeat(80), 60);
        assert_eq!(cut.chars().count(), 61);
        assert_eq!(or_list(&["a".into(), "b".into(), "c".into()]), "`a`, `b` or `c`");
        assert_eq!(or_list(&["a".into(), "b".into()]), "`a` or `b`");
        assert_eq!(or_list(&["a".into()]), "`a`");
    }

    #[test]
    fn brief_lists_supported_claims_and_cuts_long_quotes() {
        let claim = |id: &str, text: &str, status| loom_core::ledger::Claim {
            id: id.into(),
            text: text.into(),
            status,
            note: String::new(),
            evidence: vec![],
        };
        let st = LedgerState {
            claims: vec![claim("c1", "it works", ClaimStatus::Supported), claim("c2", "open one", ClaimStatus::Open)],
            ..LedgerState::default()
        };
        let q = VerifiedQuote { blob: BlobId("ab".repeat(32)), start: 3, end: 4, text: "z".repeat(400) };
        let b = finish_brief(&st, "done", &[q], None, &[]);
        assert_eq!(b.question, "Try to refute that this mission is finished as its lead describes.");
        assert_eq!(b.returns.as_deref(), Some("A verdict, delivered by calling verdict."));
        assert!(b.hypothesis.is_none() && b.scope.is_none() && b.do_not.is_none());
        let c = b.context.unwrap();
        assert!(c.contains(&format!("- out:{} lines 3-4: {}…", "ab".repeat(8), "z".repeat(300))), "{c}");
        assert!(c.contains("Claims recorded as supported:\n- c1: it works"));
        assert!(!c.contains("open one") && !c.contains("Constraints:") && !c.contains("Evidence the lead names"));
    }

    #[test]
    fn brief_names_the_stored_output_of_every_piece_of_evidence() {
        let evidence = |id: &str, blob: Option<&str>, supports: bool| Evidence {
            id: id.into(),
            input: EvidenceInput {
                claim: "c1".into(),
                kind: EvidenceKind::Execution,
                supports,
                session: "s-test".into(),
                call_id: "call-0".into(),
                blob: blob.map(|b| BlobId(b.repeat(32))),
                lines: blob.map(|_| (2, 3)),
                quote: blob.map(|_| "line two".to_string()),
                note: "shows it".into(),
                attested: true,
            },
            n: 1,
        };
        let st = LedgerState {
            claims: vec![loom_core::ledger::Claim {
                id: "c1".into(),
                text: "it works".into(),
                status: ClaimStatus::Supported,
                note: String::new(),
                evidence: vec!["e1".into(), "e3".into()],
            }],
            evidence: vec![evidence("e1", Some("ab"), true), evidence("e2", Some("cd"), false), evidence("e3", None, true)],
            ..LedgerState::default()
        };
        // `e9` is not a record of this ledger and is left out.
        let c = finish_brief(&st, "done", &[], None, &["e2".to_string(), "e9".to_string()]).context.unwrap();
        let (ab, cd) = ("ab".repeat(8), "cd".repeat(8));
        assert!(
            c.contains(&format!("Evidence the lead names for the result:\n- e2 (undermines) out:{cd} lines 2-3: line two \u{2014} shows it\n\n")),
            "{c}"
        );
        assert!(
            c.ends_with(&format!(
                "Claims recorded as supported:\n- c1: it works\n  - e1 (supports) out:{ab} lines 2-3: line two \u{2014} shows it\n  - e3 (supports) no stored output:  \u{2014} shows it"
            )),
            "{c}"
        );
    }

    #[tokio::test]
    async fn finish_gives_the_verifier_the_handles_of_the_evidence_it_rests_on() {
        let r = lead();
        r.model_op(LedgerOp::ClaimAdd { text: "the parser is fixed".into() });
        let h = r.output("line one\nline two\n", "bash", ToolClass::Exec);
        r.model_op(LedgerOp::EvidenceAdd(EvidenceInput {
            claim: "c1".into(),
            kind: EvidenceKind::Execution,
            supports: true,
            session: "s-test".into(),
            call_id: "call-0".into(),
            blob: Some(r.env.ctx.blobs.resolve(&h).unwrap()),
            lines: Some((2, 2)),
            quote: Some("line two".into()),
            note: "the test passes".into(),
            attested: true,
        }));
        r.model_op(LedgerOp::ClaimUpdate { id: "c1".into(), status: ClaimStatus::Supported, note: String::new() });
        r.orch.settle("s-kid1", ChildOutcome::Returned, "fine", accepted_payload());
        // No quotes: the assignment still names the stored output, through the ledger evidence.
        let res = r.call("finish", json!({"answer": "Parser fixed.", "evidence": ["e1"]})).await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        let spawned = r.orch.spawned.lock().unwrap().clone();
        let ctx_text = spawned[0].1.brief.context.clone().unwrap();
        let line = format!("- e1 (supports) {h} lines 2-2: line two \u{2014} the test passes");
        assert!(ctx_text.contains(&format!("Evidence the lead names for the result:\n{line}")), "{ctx_text}");
        assert!(ctx_text.contains(&format!("Claims recorded as supported:\n- c1: the parser is fixed\n  {line}")), "{ctx_text}");
    }
}
