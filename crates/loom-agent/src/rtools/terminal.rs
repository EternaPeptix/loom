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
//! quote, child delivery (effect, report text, payload, long answer stored), lead with open items
//! refused, lead accepted with verification (verdict recorded, inbox item, effect), lead rejected
//! (no effect, objections listed, finish recorded as not accepted), third finish after two
//! rejections delivered unverified, verifier ending without a verdict, spawn failure, cancellation;
//! `verdict` — each refusal, the settle effect and payload; `ask_user` — blocking and not, child
//! refusal, missing `meanwhile`, ledger question recorded and referenced; `report_blocker` — child
//! and lead; `wait` — nothing running, a running job, a running child.

use super::Shared;
use async_trait::async_trait;
use loom_core::event::{Brief, ToolClass, ToolSpec};
use loom_core::ledger::LedgerState;
use loom_tools::params::{opt, req, spec};
use loom_tools::{Tool, ToolCtx, ToolOutput};
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
    let _ = (ledger, answer, quotes);
    todo!("implement per module contract")
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
        let _ = (ctx, args, &self.0);
        todo!("implement per module contract")
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
        let _ = (ctx, args, &self.0);
        todo!("implement per module contract")
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
        let _ = (ctx, args, &self.0);
        todo!("implement per module contract")
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
        let _ = (ctx, args, &self.0);
        todo!("implement per module contract")
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
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let _ = (ctx, args, &self.0);
        todo!("implement per module contract")
    }
}
