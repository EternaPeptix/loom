//! Ledger tools: `plan`, `step`, `note`, `claim`, `claim_update`, `evidence`, `ledger`.
//!
//! CONTRACT (the `run` bodies are placeholders for the implementer; specs and types are fixed).
//!
//! Every write goes through `Shared::ledger_append(false, op)`. When it returns `Err(text)` the tool
//! returns `ToolOutput::error(text)` — the text is already a complete message for the model (ledger
//! rule refusals name what is wrong and how to fix it). On success the output is
//! `ToolOutput::ok(outcome, Body::Message(text))` as given per tool below. Nothing here panics.
//!
//! A helper `plan_lines(state) -> String` renders the plan, one step per line, as
//! `[x] p1 text — note` (done), `[>] p2 text` (doing), `[ ] p3 text` (todo), `[-] p4 text — note`
//! (dropped); `(no plan)` when empty.
//!
//! - `plan`: `PlanSet { steps }` (each step trimmed; an empty step is refused before the append with
//!   a sentence naming its position). Outcome `plan set`; text `plan_lines`.
//! - `step`: with `text` and no `id` → `PlanAdd { text }`, outcome `step added`. With `id` and
//!   `status` → `PlanUpdate { id, status, note, evidence }`, outcome `step {id} {status}`. Any other
//!   combination is refused: `Give `id` and `status` to update a step, or `text` alone to add one.`
//!   Text: `plan_lines`.
//! - `note`: `kind` `decision` → `Decision { text, reason: why }`, outcome `decision {id} recorded`;
//!   `dead_end` → `DeadEnd { what: text, why }`, outcome `dead end {id} recorded`. Text: one line
//!   echoing the id and the text.
//! - `claim`: `ClaimAdd { text }`. Outcome `claim {id} open`. Text: ``{id}: {text}`` and the line
//!   `Attach evidence with `evidence`, then set its status with `claim_update`.`
//! - `claim_update`: `ClaimUpdate { id, status, note }`. Outcome `claim {id} {status}`.
//! - `evidence`:
//!   1. `gate::check_quotes(&ctx.blobs, &[Quote { handle, start, end, text: quote }])`; on `Err(text)`
//!      → error `{text}\nNothing was attached.`
//!   2. `shared.orch.producer(mission, blob)`; `None` → error ``{handle} was not produced by a tool
//!      call of this mission, so it cannot be used as evidence. Evidence is a quote from the output
//!      of a command you ran or a file you read.``
//!      A producer of class `State` or `Terminal` is refused: ``{handle} is the result of `{tool}`,
//!      which is a message from the harness or from another agent, not an observation. Quote the
//!      output of the command or file read that shows it (an agent's report names the handles).``
//!   3. `EvidenceAdd(EvidenceInput { claim, kind, supports, session, call_id, blob: Some, lines:
//!      Some((start, end)) as verified, quote, note, attested: true })` where `kind` is `Execution`
//!      when the producer's class is `Exec`, else `Static`.
//!
//!   Outcome `evidence {id} attached to {claim}`. Text: `{id} ({supports|undermines}; {execution|static}:
//!   {tool} call in {session}) attached to {claim}.` and, when the claim is still `Open`, the line
//!   `The claim is still open — set its status with `claim_update`.`
//! - `ledger`: `ToolOutput::ok("ledger", Body::Raw(state.render_markdown().into_bytes()))`.
//!
//! The id in each outcome is read from the returned state (the last item of the kind).
//!
//! Tests required (use a fake `Orchestrator`, a temp journal with a random key, and
//! `loom_tools::execute` so that argument handling is covered): each tool's success text and the
//! `ledger` record emitted through `Shared::take_emitted`; each refusal path (ledger rule refusal
//! passed through verbatim, bad `step` combinations, empty plan step, evidence with a wrong quote,
//! an unknown handle, an output with no producer); `evidence` kind by producer class; a session
//! without a mission gets `NO_MISSION` from every tool.

use super::Shared;
use async_trait::async_trait;
use loom_core::event::{ToolClass, ToolSpec};
use loom_tools::params::{opt, req, spec};
use loom_tools::{Tool, ToolCtx, ToolOutput};
use serde_json::{json, Map, Value};
use std::sync::Arc;

pub struct Plan(pub Arc<Shared>);
pub struct Step(pub Arc<Shared>);
pub struct Note(pub Arc<Shared>);
pub struct Claim(pub Arc<Shared>);
pub struct ClaimUpdate(pub Arc<Shared>);
pub struct Evidence(pub Arc<Shared>);
pub struct Ledger(pub Arc<Shared>);

#[async_trait]
impl Tool for Plan {
    fn spec(&self) -> ToolSpec {
        spec(
            "plan",
            "Set the plan for the mission: an ordered list of steps, each one concrete enough to be checked off. This replaces the current plan. Use `step` to update a single step as you go.",
            ToolClass::State,
            &[req("steps", "array", "The steps, in order. One sentence each.").items("string")],
        )
    }
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let _ = (ctx, args, &self.0);
        todo!("implement per module contract")
    }
}

#[async_trait]
impl Tool for Step {
    fn spec(&self) -> ToolSpec {
        spec(
            "step",
            "Update one plan step, or add a step. To update, give `id` and `status`. Marking a step `done` needs `note` (what showed that it is done) or `evidence` ids; `dropped` needs `note` (why). To add a step at the end of the plan, give `text` alone.",
            ToolClass::State,
            &[
                opt("id", "string", "The step to update, for example p2."),
                opt("status", "string", "The step's new status.").one_of(&["todo", "doing", "done", "dropped"]),
                opt("note", "string", "What showed the step is done, or why it was dropped."),
                opt("evidence", "array", "Ids of evidence records (e1, e2) that show the step is done.").items("string"),
                opt("text", "string", "The text of a new step to add."),
            ],
        )
    }
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let _ = (ctx, args, &self.0);
        todo!("implement per module contract")
    }
}

#[async_trait]
impl Tool for Note {
    fn spec(&self) -> ToolSpec {
        spec(
            "note",
            "Record a decision or a dead end so that it stays known for the rest of the mission. A decision: `text` is what was decided and `why` is the reason. A dead end: `text` is what was tried and `why` is what showed it does not work. Recorded dead ends are shown back to you so the same thing is not tried twice.",
            ToolClass::State,
            &[
                req("kind", "string", "What is being recorded.").one_of(&["decision", "dead_end"]),
                req("text", "string", "What was decided, or what was tried."),
                req("why", "string", "The reason, or what showed that it does not work."),
            ],
        )
    }
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let _ = (ctx, args, &self.0);
        todo!("implement per module contract")
    }
}

#[async_trait]
impl Tool for Claim {
    fn spec(&self) -> ToolSpec {
        spec(
            "claim",
            "State something you intend to establish as fact: a finding, a root cause, 'the fix works'. The claim stays open until you attach evidence to it with `evidence` and set its status with `claim_update`. Returns the claim's id.",
            ToolClass::State,
            &[req("text", "string", "The claim, as one checkable statement.")],
        )
    }
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let _ = (ctx, args, &self.0);
        todo!("implement per module contract")
    }
}

#[async_trait]
impl Tool for ClaimUpdate {
    fn spec(&self) -> ToolSpec {
        spec(
            "claim_update",
            "Set the status of a claim. `supported` requires at least one supporting evidence record attached to the claim. `refuted` and `withdrawn` require `note`.",
            ToolClass::State,
            &[
                req("id", "string", "The claim, for example c1."),
                req("status", "string", "The claim's new status.").one_of(&["supported", "refuted", "withdrawn"]),
                opt("note", "string", "What settled it, or why it is withdrawn."),
            ],
        )
    }
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let _ = (ctx, args, &self.0);
        todo!("implement per module contract")
    }
}

#[async_trait]
impl Tool for Evidence {
    fn spec(&self) -> ToolSpec {
        spec(
            "evidence",
            "Attach evidence to a claim: text copied exactly from the stored output of a command you ran or a file you read. The harness checks that the quoted text occurs in the lines you name, and refuses evidence that does not check. `handle` is the out:… id shown in the header of the result.",
            ToolClass::State,
            &[
                req("claim", "string", "The claim this bears on, for example c1."),
                req("handle", "string", "The stored output the quote is from, for example out:7f3a9c1e."),
                req("start", "integer", "First line of the quoted text in that output.").min(1),
                req("end", "integer", "Last line of the quoted text in that output.").min(1),
                req("quote", "string", "The text, copied exactly from those lines."),
                req("note", "string", "One sentence: what this shows about the claim."),
                opt("supports", "boolean", "false when the quote counts against the claim.").default(json!(true)),
            ],
        )
    }
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let _ = (ctx, args, &self.0);
        todo!("implement per module contract")
    }
}

#[async_trait]
impl Tool for Ledger {
    fn spec(&self) -> ToolSpec {
        spec(
            "ledger",
            "Show the complete mission ledger: goal, constraints, plan, claims with their evidence, decisions, dead ends, open obligations and questions.",
            ToolClass::Read,
            &[],
        )
    }
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let _ = (ctx, args, &self.0);
        todo!("implement per module contract")
    }
}
