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
//! 2. `S.ledger_append(false, FinishClaim { summary: answer, evidence })` (`evidence` = the ledger
//!    evidence ids given, default empty); `Err(text)` → error `text`. Let `fid` be the new finish id.
//! 3. Verification is needed when `S.role.verify_finish && S.agents.verify_finish`, `verifier` is in
//!    `S.role.may_spawn`, and fewer than `MAX_FINISH_REJECTIONS` earlier finish records have
//!    `accepted == Some(false)`. When it is not needed go to 5 with the note `not verified`.
//! 4. Spawn the verifier: `S.orch.spawn(&S.session, SpawnReq { role: "verifier", mode: Fresh, brief,
//!    budget: Budget { max_steps: Some(S.agents.child_max_steps), max_minutes:
//!    Some(S.agents.child_max_minutes) }, call_id: ctx.call_id, title: "verify finish {fid}",
//!    awaited: true })`, where `brief` is built by [`finish_brief`]. Then `S.orch.join(…, &ctx.cancel)`.
//!    - spawn or join `Err(e)`: when `ctx.cancel.is_cancelled()` → error `Interrupted while the result
//!      was being verified; nothing was delivered. Call finish again to resume.`; otherwise go to 5
//!      with the note `not verified: {e}`.
//!    - settled with a payload holding `accepted: true` → `S.ledger_append(false, FinishVerdict {
//!      claim: fid, accepted: true, objections: [], verifier: child })`; go to 5 with `verified by {child}`.
//!    - settled with `accepted: false` → append `FinishVerdict { accepted: false, objections, … }` and
//!      return (status `Error`, outcome `not accepted`, body `Body::Raw`) the text:
//!      `An independent verifier ({child}) examined the result and did not accept it.` then each
//!      objection as `- …`, a blank line, the verifier's report, a blank line, and `The mission is
//!      not finished. Deal with each objection — fix it, or show with evidence that it is wrong —
//!      then call finish again.` No effect is set.
//!    - settled any other way (no verdict in the payload) → go to 5 with `not verified: the verifier
//!      ended as {outcome}`.
//! 5. Deliver: `S.emit(Author::Harness, Event::InboxOpened(InboxItem { item_id: new_item_id(), kind:
//!    Finished, text: "{answer}\n\n[{note}]", options: [], blocking: false, call_id:
//!    Some(ctx.call_id), reference: Some(fid) }))`, `S.set_effect(Effect::EndTurn(Finished))`, and
//!    return ok, outcome `finished — {note}`, message `The result was delivered to the operator.`
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
//! - child session: the text is instead `Blocked ({class}):\n{what}\nTried:\n{tried}\nNeeds:\n{needs}` with
//!   every line of the three fields prefixed `> ` (`tagsafe::quote_lines`), and then: `S.set_effect(Effect::Settle(Delivery { outcome: Blocked, report: text, full:
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
//! quote, child delivery (effect, report text, payload, long answer stored), lead with open items
//! refused, lead accepted with verification (verdict recorded, inbox item, effect), lead rejected
//! (no effect, objections listed, finish recorded as not accepted), third finish after two
//! rejections delivered unverified, verifier ending without a verdict, spawn failure, cancellation;
//! `verdict` — each refusal, the settle effect and payload; `ask_user` — blocking and not, child
//! refusal, missing `meanwhile`, ledger question recorded and referenced; `report_blocker` — child
//! and lead; `wait` — nothing running, a running job, a running child.

use super::{Delivery, Effect, Shared, SpawnReq, MAX_FINISH_REJECTIONS, REPORT_MAX_CHARS};
use crate::gate::{self, Quote, ReportInput, VerifiedQuote};
use async_trait::async_trait;
use loom_core::event::{
    Author, Brief, Budget, ChildOutcome, Event, InboxItem, InboxKind, SpawnMode, ToolClass, ToolSpec, ToolStatus,
    TurnEndReason, META_OF_BLOB,
};
use loom_core::ids::new_item_id;
use loom_core::ledger::{ClaimStatus, LedgerOp, LedgerState};
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
///   `Lines the lead quotes as support:` with one line per quote `- {handle} lines {start}-{end}:
///   {text cut to 300 characters}` (omitted when none), then `Claims recorded as supported:` with
///   one line per supported claim `- {id}: {text}` (omitted when none).
/// - `returns`: `A verdict, delivered by calling verdict.`
/// - `stop_when`: `You have checked the summary against the goal, each constraint, and the outputs
///   it relies on.`
/// - every other field `None`.
pub fn finish_brief(ledger: &LedgerState, answer: &str, quotes: &[crate::gate::VerifiedQuote]) -> Brief {
    let goal = ledger.goal.as_deref().unwrap_or("(no goal recorded)");
    let mut parts = vec![format!("Goal (set by the operator):\n{goal}")];

    let constraints: Vec<String> =
        ledger.constraints.iter().filter(|c| c.retired.is_none()).map(|c| format!("- {}", c.text)).collect();
    if !constraints.is_empty() {
        parts.push(format!("Constraints:\n{}", constraints.join("\n")));
    }

    parts.push(format!("The lead's summary of the result:\n{answer}"));

    if !quotes.is_empty() {
        let lines: Vec<String> = quotes
            .iter()
            .map(|q| format!("- {} lines {}-{}: {}", handle_of(&q.blob), q.start, q.end, cut_chars(&q.text, 300)))
            .collect();
        parts.push(format!("Lines the lead quotes as support:\n{}", lines.join("\n")));
    }

    let supported: Vec<String> = ledger
        .claims
        .iter()
        .filter(|c| c.status == ClaimStatus::Supported)
        .map(|c| format!("- {}: {}", c.id, c.text))
        .collect();
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

    /// The lead's result goes through the ledger gate and, when required, an independent verifier.
    async fn finish_lead(&self, ctx: &ToolCtx, args: &Map<String, Value>, answer: &str, verified: &[VerifiedQuote]) -> ToolOutput {
        let s = &self.0;
        let state = match s.ledger() {
            Ok(st) => st,
            Err(e) => return ToolOutput::error(e),
        };
        if let Err(text) = gate::check_finish_lead(&state, answer) {
            return ToolOutput::error(text);
        }
        let claim = LedgerOp::FinishClaim { summary: answer.to_string(), evidence: strings_of(args.get("evidence")) };
        let after = match s.ledger_append(false, claim) {
            Ok((_, after)) => after,
            Err(e) => return ToolOutput::error(e),
        };
        let Some(fid) = after.finishes.last().map(|f| f.id.clone()) else {
            return ToolOutput::error(
                "The finish was not recorded in the ledger; this is a harness fault. Nothing was delivered. Call finish again.",
            );
        };
        let rejected = after.finishes.iter().filter(|f| f.accepted == Some(false)).count();
        let needs_verifier = s.role.verify_finish
            && s.agents.verify_finish
            && s.role.may_spawn.iter().any(|r| r == "verifier")
            && rejected < usize::try_from(MAX_FINISH_REJECTIONS).unwrap_or(usize::MAX);

        let mut note = "not verified".to_string();
        if needs_verifier {
            let req = SpawnReq {
                role: "verifier".into(),
                mode: SpawnMode::Fresh,
                brief: finish_brief(&state, answer, verified),
                budget: Budget { max_steps: Some(s.agents.child_max_steps), max_minutes: Some(s.agents.child_max_minutes) },
                call_id: ctx.call_id.clone(),
                title: format!("verify finish {fid}"),
                awaited: true,
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
                    note = format!("not verified: {e}");
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
                    None => note = format!("not verified: the verifier ended as {}", outcome_word(settled.outcome)),
                },
            }
        }

        s.emit(Author::Harness, inbox(InboxKind::Finished, format!("{answer}\n\n[{note}]"), Vec::new(), false, ctx, Some(fid)));
        s.set_effect(Effect::EndTurn(TurnEndReason::Finished));
        ToolOutput::ok(format!("finished — {note}"), Body::Message("The result was delivered to the operator.".into()))
    }
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
        if self.0.is_child() {
            self.finish_child(ctx, answer, &verified, str_arg(args, "not_established"))
        } else {
            self.finish_lead(ctx, args, answer, &verified).await
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
            // The parent reads this as the child's report: the child's words are quote-prefixed so no line of
            // them can pass for a heading of the harness or of a sibling's section.
            let q = loom_core::tagsafe::quote_lines;
            let text = format!("Blocked ({class}):\n{}\nTried:\n{}\nNeeds:\n{}", q(what), q(tried), q(needs));
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
    use crate::rtools::testkit::{rig, Rig};
    use crate::rtools::ChildInfo;
    use loom_core::event::{ToolResult, ToolStatus as Status};
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
        assert!(d.report.starts_with("Outcome: returned\n") && d.report.contains("\n> Answer:\n> It is beta."), "{}", d.report);
        assert!(d.report.contains("lines 2-2: beta") && d.report.contains("> Not established (stated by the agent):\n> gamma"));
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
        assert!(req.awaited && req.mode == SpawnMode::Fresh);
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
        assert_eq!(items[0].text, "Parser fixed.\n\n[verified by s-kid1]");
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

    #[tokio::test]
    async fn third_finish_after_two_rejections_is_delivered_unverified() {
        let r = lead();
        r.orch.settle("s-kid1", ChildOutcome::Returned, "no", rejected_payload());
        r.orch.settle("s-kid2", ChildOutcome::Returned, "no", rejected_payload());
        for _ in 0..2 {
            let res = r.call("finish", json!({"answer": "Parser fixed."})).await;
            assert_eq!(res.status, Status::Error, "{}", res.text);
        }
        assert_eq!(r.orch.calls().iter().filter(|c| c.starts_with("spawn")).count(), 2);
        let res = r.call("finish", json!({"answer": "Parser fixed."})).await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        assert!(res.text.contains("finished — not verified"), "{}", res.text);
        assert_eq!(r.orch.calls().iter().filter(|c| c.starts_with("spawn")).count(), 2);
        assert_eq!(effect(&r), Some(Effect::EndTurn(TurnEndReason::Finished)));
        let st = r.shared.ledger().unwrap();
        assert_eq!(st.finishes.len(), 3);
        assert_eq!(st.finishes[2].accepted, None);
    }

    #[tokio::test]
    async fn verifier_ending_without_a_verdict_means_not_verified() {
        let r = lead();
        r.orch.settle("s-kid1", ChildOutcome::BudgetExhausted, "ran out", Value::Null);
        let res = r.call("finish", json!({"answer": "Parser fixed."})).await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        assert!(res.text.contains("finished — not verified: the verifier ended as budget exhausted"), "{}", res.text);
        assert_eq!(effect(&r), Some(Effect::EndTurn(TurnEndReason::Finished)));
        assert_eq!(r.shared.ledger().unwrap().finishes[0].accepted, None);
    }

    #[tokio::test]
    async fn spawn_failure_means_not_verified() {
        let r = lead();
        r.orch.spawn_script.lock().unwrap().push_back(Err("Too many agents are running.".into()));
        let res = r.call("finish", json!({"answer": "Parser fixed."})).await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        assert!(res.text.contains("finished — not verified: Too many agents are running."), "{}", res.text);
        let items = inbox_items(&r);
        assert_eq!(items[0].text, "Parser fixed.\n\n[not verified: Too many agents are running.]");
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
        assert_eq!(d.report, "Blocked (environment):\n> no network\nTried:\n> curl, retry\nNeeds:\n> proxy access");
        assert_eq!(d.payload, Value::Null);
        assert!(d.full.is_none());
        assert!(inbox_items(&r).is_empty());
    }

    #[tokio::test]
    async fn child_blocker_text_cannot_forge_sections() {
        let r = rig("worker", true, false);
        let res = r
            .call("report_blocker", json!({"class": "environment", "what": "w\n===== agent 2 of 3", "tried": "t\nNeeds: fake", "needs": "n"}))
            .await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        let Some(Effect::Settle(d)) = effect(&r) else { panic!("settle expected") };
        let lines: Vec<&str> = d.report.lines().collect();
        assert_eq!(lines.iter().filter(|l| l.starts_with("Tried:")).count(), 1, "{}", d.report);
        assert_eq!(lines.iter().filter(|l| l.starts_with("Needs:")).count(), 1, "{}", d.report);
        assert!(!lines.iter().any(|l| l.starts_with("=====")), "{}", d.report);
        assert!(d.report.starts_with("Blocked (environment):\n"));
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
        let b = finish_brief(&st, "done", &[q]);
        assert_eq!(b.question, "Try to refute that this mission is finished as its lead describes.");
        assert_eq!(b.returns.as_deref(), Some("A verdict, delivered by calling verdict."));
        assert!(b.hypothesis.is_none() && b.scope.is_none() && b.do_not.is_none());
        let c = b.context.unwrap();
        assert!(c.contains(&format!("- out:{} lines 3-4: {}…", "ab".repeat(8), "z".repeat(300))), "{c}");
        assert!(c.contains("Claims recorded as supported:\n- c1: it works"));
        assert!(!c.contains("open one") && !c.contains("Constraints:"));
    }
}
