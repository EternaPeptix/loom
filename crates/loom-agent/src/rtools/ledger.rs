//! Ledger tools: `plan`, `step`, `note`, `claim`, `claim_update`, `evidence`, `ledger`, `reflect`.
//!
//! CONTRACT.
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
//! - `reflect`: `ruled_out`, `next_route`, `would_change` → `Reflection { ruled_out, next_route,
//!   would_change }`. Outcome `reflection {id} recorded`; text one line echoing the id and `next_route`.
//!   A structured self-check for when progress stalls: what is ruled out, the best next route, and the
//!   evidence that would change the conclusion. Each field must say something true, not a ritual glyph.
//! - `claim`: `ClaimAdd { text }`. Outcome `claim {id} open`. Text: ``{id}: {text}`` and the line
//!   `Attach evidence with `evidence`, then set its status with `claim_update`.`
//! - `claim_update`: `ClaimUpdate { id, status, note }`. Outcome `claim {id} {status}`. When the claim moves INTO
//!   `supported` from another status, the text gains the line `Established: {id}. Results established in this
//!   mission so far: {n} ({ids, at most 8, then …}).` (`texts::result_banked`), counted from the ledger after
//!   the write. Nothing else is recorded; a refutation or withdrawal gets no such line. (`claim` always
//!   creates an open claim, so it never banks.)
//! - `evidence`:
//!   1. `gate::check_quotes(&ctx.blobs, &[Quote { handle, start, end, text: quote }])`; on `Err(text)`
//!      → error `{text}\nNothing was attached.` `quote` may be left out (or blank): the quote is then
//!      by lines, the lines `start`-`end` as the stored output has them (`gate`). This refusal and the
//!      next carry `meta[META_REFUSAL] = REFUSAL_QUOTE` (what a scorecard counts as a step spent on a
//!      quote).
//!   2. `rtools::observed_producer` (the rule `finish` applies to its quotes as well):
//!      `shared.orch.producer(mission, blob)`; `None` → error ``{handle} was not produced by a tool
//!      call of this mission, so it cannot be used as evidence. Evidence is a quote from the output
//!      of a command you ran or a file you read.``
//!      Only an observation is evidence. A producer that is a runtime tool (any of `NAMES`: `ledger`
//!      and `log_search` play the model's own words back, the agent tools return another agent's)
//!      or of class `State`, `Terminal` or `Write` (the diff of the model's own `write` or `edit`) is
//!      refused: ``{handle} is the result of `{tool}`, which is a message from the harness or from
//!      another agent, or your own words played back, not an observation. Quote the output of the
//!      command or file read that shows it instead (an agent's report names the handles).``
//!      A view (`out_read`, `out_grep`) stores nothing of its own: a quote taken from one cites the
//!      output it views, and is judged by what produced that output. A file `read` is the exception
//!      that proves it: the header of its result names the handle of the text it stored, and the
//!      runtime registers that blob as produced by the `read` call (class `Read`, so static evidence);
//!      the complete output of a background job is registered as produced by the call that started it.
//!   3. `EvidenceAdd(EvidenceInput { claim, kind, supports, session, call_id, blob: Some, lines:
//!      Some((start, end)) as verified, quote: the verified text, note, attested: true })` where `kind`
//!      is `Execution` when the producer's class is `Exec`, else `Static`. The verified text has no
//!      line-number prefixes; a fragment is recorded as the complete line or lines it lies on, and `lines`
//!      are their numbers (on lines longer than `observe::QUOTE_RECORD_CHARS` characters, a window of them
//!      around the fragment, `…` marking what was left out).
//!
//!   Outcome `evidence {id} attached to {claim}`. Text: `{id} ({supports|undermines}; {execution|static}:
//!   {tool} call in {session}) attached to {claim}.` and, when the claim is still `Open`, the line
//!   `The claim is still open — set its status with `claim_update`.` After a quote by lines, what was
//!   recorded follows, since nothing compared the line numbers with a text and a miscounted range shows
//!   nowhere else: `Recorded from {handle}, lines {start}-{end}, as stored:`, each line of the text as
//!   `| {line}`, and `If these are not the lines you meant, attach the right ones.` A quote given with
//!   its text is not played back: the model wrote it.
//! - `ledger`: `ToolOutput::ok("ledger", Body::Raw(state.render_markdown().into_bytes()))`.
//!
//! The id in each outcome is read from the returned state (the last item of the kind).
//!
//! Tests required (use a fake `Orchestrator`, a temp journal with a random key, and
//! `loom_tools::execute` so that argument handling is covered): each tool's success text and the
//! `ledger` record emitted through `Shared::take_emitted`; each refusal path (ledger rule refusal
//! passed through verbatim, bad `step` combinations, empty plan step, `reflect` with a blank field, evidence with a wrong quote,
//! an unknown handle, an output with no producer, the output of `ledger` and of `log_search` cited
//! directly and as a view shows it, the diff of an `edit`); `evidence` kind by producer class, also
//! when the quote is copied from a view of a command's output; evidence by lines: what is recorded and
//! played back, its refusals, and the producer rule applying to it as well; a session without a mission
//! gets `NO_MISSION` from every tool.

use super::{observed_producer, Shared, NO_MISSION};
use crate::gate::{check_quotes, Quote};
use crate::{frontier, texts};
use async_trait::async_trait;
use loom_core::event::{ToolClass, ToolSpec, META_REFUSAL, REFUSAL_QUOTE};
use loom_core::ledger::{ClaimStatus, EvidenceInput, EvidenceKind, LedgerOp, LedgerState, StepStatus};
use loom_tools::params::{opt, req, spec};
use loom_tools::{Body, Tool, ToolCtx, ToolOutput};
use serde_json::{json, Map, Value};
use std::sync::Arc;

/// A non-empty string argument.
fn str_arg<'a>(args: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
}

/// An enum from its snake_case wire name.
fn parse_enum<T: serde::de::DeserializeOwned>(word: &str) -> Option<T> {
    serde_json::from_value(Value::String(word.to_string())).ok()
}

/// The plan, one step per line.
fn plan_lines(state: &LedgerState) -> String {
    if state.plan.is_empty() {
        return "(no plan)".to_string();
    }
    let mut lines = Vec::new();
    for step in &state.plan {
        let mark = match step.status {
            StepStatus::Done => "[x]",
            StepStatus::Doing => "[>]",
            StepStatus::Todo => "[ ]",
            StepStatus::Dropped => "[-]",
        };
        let mut line = format!("{mark} {} {}", step.id, step.text);
        if !step.note.is_empty() && matches!(step.status, StepStatus::Done | StepStatus::Dropped) {
            line.push_str(" — ");
            line.push_str(&step.note);
        }
        lines.push(line);
    }
    lines.join("\n")
}

pub struct Plan(pub Arc<Shared>);
pub struct Step(pub Arc<Shared>);
pub struct Note(pub Arc<Shared>);
pub struct Claim(pub Arc<Shared>);
pub struct ClaimUpdate(pub Arc<Shared>);
pub struct Evidence(pub Arc<Shared>);
pub struct Ledger(pub Arc<Shared>);
pub struct Reflect(pub Arc<Shared>);

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
    async fn run(&self, _ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let Some(steps) = args.get("steps").and_then(Value::as_array) else {
            return ToolOutput::error("`steps` must be a list of sentences, one per plan step.");
        };
        let mut texts = Vec::new();
        for (i, step) in steps.iter().enumerate() {
            let text = step.as_str().unwrap_or("").trim();
            if text.is_empty() {
                return ToolOutput::error(format!(
                    "Step {} of the plan is empty. Give every step a sentence saying what is to be done; nothing was recorded.",
                    i.saturating_add(1)
                ));
            }
            texts.push(text.to_string());
        }
        match self.0.ledger_append(false, LedgerOp::PlanSet { steps: texts }) {
            Ok((_, state)) => ToolOutput::ok("plan set", Body::Message(plan_lines(&state))),
            Err(text) => ToolOutput::error(text),
        }
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
    async fn run(&self, _ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let (outcome, op) = match (str_arg(args, "id"), str_arg(args, "status"), str_arg(args, "text")) {
            (None, None, Some(text)) => ("step added".to_string(), LedgerOp::PlanAdd { text: text.trim().to_string() }),
            (Some(id), Some(status), None) => {
                let Some(parsed) = parse_enum::<StepStatus>(status) else {
                    return ToolOutput::error("`status` must be one of todo, doing, done, dropped.");
                };
                let evidence = args
                    .get("evidence")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
                    .unwrap_or_default();
                (
                    format!("step {id} {status}"),
                    LedgerOp::PlanUpdate {
                        id: id.to_string(),
                        status: parsed,
                        note: str_arg(args, "note").unwrap_or("").trim().to_string(),
                        evidence,
                    },
                )
            }
            _ => return ToolOutput::error("Give `id` and `status` to update a step, or `text` alone to add one."),
        };
        match self.0.ledger_append(false, op) {
            Ok((_, state)) => ToolOutput::ok(outcome, Body::Message(plan_lines(&state))),
            Err(text) => ToolOutput::error(text),
        }
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
    async fn run(&self, _ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let text = str_arg(args, "text").unwrap_or("").to_string();
        let why = str_arg(args, "why").unwrap_or("").to_string();
        let dead_end = str_arg(args, "kind") == Some("dead_end");
        let op =
            if dead_end { LedgerOp::DeadEnd { what: text, why } } else { LedgerOp::Decision { text, reason: why } };
        match self.0.ledger_append(false, op) {
            Ok((_, state)) => {
                if dead_end {
                    let (id, what) =
                        state.dead_ends.last().map(|d| (d.id.as_str(), d.what.as_str())).unwrap_or(("", ""));
                    ToolOutput::ok(format!("dead end {id} recorded"), Body::Message(format!("{id}: {what}")))
                } else {
                    let (id, what) =
                        state.decisions.last().map(|d| (d.id.as_str(), d.text.as_str())).unwrap_or(("", ""));
                    ToolOutput::ok(format!("decision {id} recorded"), Body::Message(format!("{id}: {what}")))
                }
            }
            Err(text) => ToolOutput::error(text),
        }
    }
}

#[async_trait]
impl Tool for Reflect {
    fn spec(&self) -> ToolSpec {
        spec(
            "reflect",
            "Record a structured reflection while you work: what you have ruled out and why, the single best next route you can see, and the evidence that would change your conclusion. Use it when progress stalls or the picture is unclear. Each field must say something true — a reflection that names real content moves the work forward; a ritual glyph does not.",
            ToolClass::State,
            &[
                req("ruled_out", "string", "What you have ruled out, and why. One or two sentences."),
                req("next_route", "string", "The single best next route you can see, and why."),
                req("would_change", "string", "The evidence that, if you saw it, would change your conclusion about this mission — and what you would do with it."),
            ],
        )
    }
    async fn run(&self, _ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let ruled_out = str_arg(args, "ruled_out").unwrap_or("").to_string();
        let next_route = str_arg(args, "next_route").unwrap_or("").to_string();
        let would_change = str_arg(args, "would_change").unwrap_or("").to_string();
        match self.0.ledger_append(false, LedgerOp::Reflection { ruled_out, next_route, would_change }) {
            Ok((_, state)) => {
                let (id, route) =
                    state.reflections.last().map(|r| (r.id.as_str(), r.next_route.as_str())).unwrap_or(("", ""));
                ToolOutput::ok(format!("reflection {id} recorded"), Body::Message(format!("{id}: {route}")))
            }
            Err(text) => ToolOutput::error(text),
        }
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
    async fn run(&self, _ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let text = str_arg(args, "text").unwrap_or("").to_string();
        match self.0.ledger_append(false, LedgerOp::ClaimAdd { text }) {
            Ok((_, state)) => {
                let (id, text) = state.claims.last().map(|c| (c.id.as_str(), c.text.as_str())).unwrap_or(("", ""));
                ToolOutput::ok(
                    format!("claim {id} open"),
                    Body::Message(format!(
                        "{id}: {text}\nAttach evidence with `evidence`, then set its status with `claim_update`."
                    )),
                )
            }
            Err(text) => ToolOutput::error(text),
        }
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
    async fn run(&self, _ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let id = str_arg(args, "id").unwrap_or("").to_string();
        let status = str_arg(args, "status").unwrap_or("");
        let Some(parsed) = parse_enum::<ClaimStatus>(status) else {
            return ToolOutput::error("`status` must be one of supported, refuted, withdrawn.");
        };
        let note = str_arg(args, "note").unwrap_or("").trim().to_string();
        let was_supported =
            self.0.ledger().is_ok_and(|s| s.claims.iter().any(|c| c.id == id && c.status == ClaimStatus::Supported));
        match self.0.ledger_append(false, LedgerOp::ClaimUpdate { id: id.clone(), status: parsed, note }) {
            Ok((_, state)) => {
                let text = state.claims.iter().find(|c| c.id == id).map(|c| c.text.as_str()).unwrap_or("");
                let mut message = format!("{id} is {status}: {text}");
                if parsed == ClaimStatus::Supported && !was_supported {
                    let established = frontier::frontier(&state, 0).established;
                    message.push('\n');
                    message.push_str(&texts::result_banked(&id, established.len(), &frontier::id_list(&established)));
                }
                ToolOutput::ok(format!("claim {id} {status}"), Body::Message(message))
            }
            Err(text) => ToolOutput::error(text),
        }
    }
}

#[async_trait]
impl Tool for Evidence {
    fn spec(&self) -> ToolSpec {
        spec(
            "evidence",
            "Attach evidence to a claim: lines of the stored output of a command you ran or a file you read. Two ways. By line numbers: give `handle`, `start` and `end` and leave `quote` out; the harness takes those lines from the stored output (at most 20) and shows you what it recorded. Do this when you have the numbers from `out_read`, `out_grep` or `read`. By text: also give `quote`, copied exactly; the harness looks for it within the lines you name (the range may be wider than the text) and refuses it if it does not occur. Quote whole lines, or at least 8 non-space characters of a line; line numbers copied along with the text must be the output's own. `handle` is the out:… id shown in the header of the result.",
            ToolClass::State,
            &[
                req("claim", "string", "The claim this bears on, for example c1."),
                req("handle", "string", "The stored output the quote is from, for example out:7f3a9c1e."),
                req("start", "integer", "First line of the quote in that output.").min(1),
                req("end", "integer", "Last line of the quote in that output.").min(1),
                opt("quote", "string", "Leave out to quote lines start-end whole, as stored. Or the text, copied exactly from within those lines."),
                req("note", "string", "One sentence: what this shows about the claim."),
                opt("supports", "boolean", "false when the quote counts against the claim.").default(json!(true)),
            ],
        )
    }
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let shared = &self.0;
        let Some(mission) = shared.mission.as_ref() else { return ToolOutput::error(NO_MISSION) };
        let claim = str_arg(args, "claim").unwrap_or("").to_string();
        let handle = str_arg(args, "handle").unwrap_or("").to_string();
        let start = args.get("start").and_then(Value::as_u64).unwrap_or(0);
        let end = args.get("end").and_then(Value::as_u64).unwrap_or(0);
        let quote = str_arg(args, "quote").unwrap_or("").to_string();
        let note = str_arg(args, "note").unwrap_or("").trim().to_string();
        let supports = args.get("supports").and_then(Value::as_bool).unwrap_or(true);
        // Without its text the quote is the lines named: the result then shows what was recorded.
        let by_lines = quote.trim().is_empty();

        // A refusal over the quote says so in the record: a scorecard counts the steps spent on quotes.
        let quote_refused = |text: String| ToolOutput::error(text).with_meta(META_REFUSAL, json!(REFUSAL_QUOTE));
        let q = Quote { handle: handle.clone(), start, end, text: quote };
        let verified = match check_quotes(&ctx.blobs, &[q]) {
            Ok(v) => v,
            Err(text) => return quote_refused(format!("{text}\nNothing was attached.")),
        };
        let Some(v) = verified.into_iter().next() else {
            return ToolOutput::error(
                "The quote could not be checked, so nothing was attached. Check `handle`, `start` and `end`.",
            );
        };
        // Only observations are evidence.
        let producer = match observed_producer(shared, mission, &handle, &v.blob).await {
            Ok(p) => p,
            Err(text) => return quote_refused(text),
        };
        let kind = if producer.class == ToolClass::Exec { EvidenceKind::Execution } else { EvidenceKind::Static };
        let recorded = by_lines.then(|| recorded_lines(&handle, v.start, v.end, &v.text));
        let input = EvidenceInput {
            claim: claim.clone(),
            kind,
            supports,
            session: producer.session.clone(),
            call_id: producer.call_id.clone(),
            blob: Some(v.blob.clone()),
            lines: Some((v.start, v.end)),
            quote: Some(v.text),
            note,
            attested: true,
        };
        match shared.ledger_append(false, LedgerOp::EvidenceAdd(input)) {
            Ok((_, state)) => {
                let id = state.evidence.last().map(|e| e.id.as_str()).unwrap_or("");
                let side = if supports { "supports" } else { "undermines" };
                let kind_word = if kind == EvidenceKind::Execution { "execution" } else { "static" };
                let mut text = format!(
                    "{id} ({side}; {kind_word}: {} call in {}) attached to {claim}.",
                    producer.tool, producer.session
                );
                if state.claims.iter().any(|c| c.id == claim && c.status == ClaimStatus::Open) {
                    text.push_str("\nThe claim is still open — set its status with `claim_update`.");
                }
                if let Some(recorded) = recorded {
                    text.push('\n');
                    text.push_str(&recorded);
                }
                ToolOutput::ok(format!("evidence {id} attached to {claim}"), Body::Message(text))
            }
            Err(text) => ToolOutput::error(text),
        }
    }
}

/// What a quote by lines recorded, for the model to compare with what it meant: nothing checked its
/// line numbers against a text, so a miscounted range shows here and nowhere else.
fn recorded_lines(handle: &str, start: u64, end: u64, text: &str) -> String {
    let mut out = format!("Recorded from {handle}, lines {start}-{end}, as stored:");
    for line in text.split('\n') {
        out.push_str("\n| ");
        out.push_str(line);
    }
    out.push_str("\nIf these are not the lines you meant, attach the right ones.");
    out
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
    async fn run(&self, _ctx: &ToolCtx, _args: &Map<String, Value>) -> ToolOutput {
        match self.0.ledger() {
            Ok(state) => ToolOutput::ok("ledger", Body::Raw(state.render_markdown().into_bytes())),
            Err(text) => ToolOutput::error(text),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::super::testkit::{rig, Rig};
    use super::super::NO_MISSION;
    use loom_core::event::{Event, ToolClass, ToolStatus};
    use loom_core::ledger::LedgerOp;
    use serde_json::{json, Value};

    async fn ok(rig: &Rig, name: &str, args: Value) -> String {
        let r = rig.call(name, args).await;
        assert_eq!(r.status, ToolStatus::Ok, "{name} failed: {}", r.text);
        r.text
    }

    async fn refused(rig: &Rig, name: &str, args: Value) -> String {
        let r = rig.call(name, args).await;
        assert_eq!(r.status, ToolStatus::Error, "{name} should be refused: {}", r.text);
        r.text
    }

    fn ledger_records(rig: &Rig) -> Vec<u64> {
        rig.shared
            .take_emitted()
            .into_iter()
            .filter_map(|(_, e)| match e {
                Event::Ledger { n, .. } => Some(n),
                _ => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn plan_and_step_render_and_emit() {
        let rig = rig("lead", false, true);
        let t = ok(&rig, "plan", json!({"steps": ["  read the code ", "fix it"]})).await;
        assert!(t.contains("plan set"), "{t}");
        assert!(t.contains("[ ] p1 read the code\n[ ] p2 fix it"), "{t}");
        assert_eq!(ledger_records(&rig), vec![1]);

        let t = ok(&rig, "step", json!({"id": "p1", "status": "doing"})).await;
        assert!(t.contains("step p1 doing"), "{t}");
        assert!(t.contains("[>] p1 read the code"), "{t}");
        let t = ok(&rig, "step", json!({"id": "p1", "status": "done", "note": "read all of it"})).await;
        assert!(t.contains("[x] p1 read the code — read all of it"), "{t}");
        let t = ok(&rig, "step", json!({"text": "ship it"})).await;
        assert!(t.contains("step added"), "{t}");
        assert!(t.contains("[ ] p3 ship it"), "{t}");
        let t = ok(&rig, "step", json!({"id": "p2", "status": "dropped", "note": "not needed"})).await;
        assert!(t.contains("[-] p2 fix it — not needed"), "{t}");
        assert_eq!(ledger_records(&rig).len(), 4);
    }

    #[tokio::test]
    async fn plan_and_step_refusals() {
        let rig = rig("lead", false, true);
        let t = refused(&rig, "plan", json!({"steps": ["one", "  ", "three"]})).await;
        assert!(t.contains("Step 2 of the plan is empty"), "{t}");
        assert!(rig.shared.take_emitted().is_empty());
        ok(&rig, "plan", json!({"steps": ["one"]})).await;

        let want = "Give `id` and `status` to update a step, or `text` alone to add one.";
        assert!(refused(&rig, "step", json!({})).await.contains(want));
        assert!(refused(&rig, "step", json!({"id": "p1"})).await.contains(want));
        assert!(refused(&rig, "step", json!({"status": "done"})).await.contains(want));
        assert!(refused(&rig, "step", json!({"id": "p1", "status": "done", "text": "x"})).await.contains(want));

        // A ledger rule refusal comes through verbatim.
        let rule = rig.shared.ledger_append(
            false,
            LedgerOp::PlanUpdate {
                id: "p1".into(),
                status: loom_core::ledger::StepStatus::Done,
                note: String::new(),
                evidence: vec![],
            },
        );
        let rule = rule.expect_err("rule refusal");
        rig.shared.take_emitted();
        let t = refused(&rig, "step", json!({"id": "p1", "status": "done"})).await;
        assert!(t.contains(&rule), "{t} vs {rule}");
        assert!(rig.shared.take_emitted().is_empty());
    }

    #[tokio::test]
    async fn note_records_decisions_and_dead_ends() {
        let rig = rig("lead", false, true);
        let t = ok(&rig, "note", json!({"kind": "decision", "text": "use sqlite", "why": "no server"})).await;
        assert!(t.contains("decision d1 recorded"), "{t}");
        assert!(t.contains("d1: use sqlite"), "{t}");
        let t = ok(&rig, "note", json!({"kind": "dead_end", "text": "tried mmap", "why": "segfaults"})).await;
        assert!(t.contains("dead end x1 recorded"), "{t}");
        assert!(t.contains("x1: tried mmap"), "{t}");
        assert_eq!(ledger_records(&rig), vec![1, 2]);
        let state = rig.shared.ledger().unwrap();
        assert_eq!(state.decisions[0].reason, "no server");
        assert_eq!(state.dead_ends[0].why, "segfaults");
        assert!(refused(&rig, "note", json!({"kind": "decision", "text": "  ", "why": "x"})).await.len() > 5);
        // A refusal names the parameter as this tool has it: a dead end's `text`, a decision's `why`.
        let t = refused(&rig, "note", json!({"kind": "dead_end", "text": "  ", "why": "x"})).await;
        assert!(t.contains("The `text` of the dead end is empty."), "{t}");
        let t = refused(&rig, "note", json!({"kind": "decision", "text": "x", "why": "  "})).await;
        assert!(t.contains("The `why` of the decision is empty."), "{t}");
    }

    #[tokio::test]
    async fn reflect_records_a_structured_reflection() {
        let rig = rig("lead", false, true);
        let t = ok(
            &rig,
            "reflect",
            json!({"ruled_out": "mmap is out, it segfaults under load", "next_route": "instrument the C path", "would_change": "a clean run of the target"}),
        )
        .await;
        assert!(t.contains("reflection r1 recorded"), "{t}");
        assert!(t.contains("r1: instrument the C path"), "{t}");
        assert_eq!(ledger_records(&rig), vec![1]);
        let state = rig.shared.ledger().unwrap();
        assert_eq!(state.reflections[0].ruled_out, "mmap is out, it segfaults under load");
        assert_eq!(state.reflections[0].would_change, "a clean run of the target");
        let t = refused(&rig, "reflect", json!({"ruled_out": " ", "next_route": "x", "would_change": "y"})).await;
        assert!(t.contains("The `ruled_out` of the reflection is empty."), "{t}");
    }

    #[tokio::test]
    async fn claim_flow_with_evidence_and_update() {
        let rig = rig("lead", false, true);
        let t = ok(&rig, "claim", json!({"text": "the bug is in parse"})).await;
        assert!(t.contains("claim c1 open"), "{t}");
        assert!(t.contains("c1: the bug is in parse"), "{t}");
        assert!(t.contains("Attach evidence with `evidence`, then set its status with `claim_update`."), "{t}");

        let r = refused(&rig, "claim_update", json!({"id": "c1", "status": "supported"})).await;
        assert!(!r.is_empty());

        let h = rig.output("alpha\nthe parser panics here\nomega\n", "bash", ToolClass::Exec);
        let t = ok(
            &rig,
            "evidence",
            json!({"claim": "c1", "handle": h, "start": 2, "end": 2, "quote": "parser panics", "note": "shows the panic"}),
        )
        .await;
        assert!(t.contains("evidence e1 attached to c1"), "{t}");
        assert!(t.contains("e1 (supports; execution: bash call in s-test) attached to c1."), "{t}");
        assert!(t.contains("The claim is still open — set its status with `claim_update`."), "{t}");

        let t = ok(&rig, "claim_update", json!({"id": "c1", "status": "supported"})).await;
        assert!(t.contains("claim c1 supported"), "{t}");
        assert!(t.contains("Established: c1. Results established in this mission so far: 1 (c1)."), "{t}");

        // A second piece of evidence on a settled claim has no "still open" line.
        let t = ok(
            &rig,
            "evidence",
            json!({"claim": "c1", "handle": h, "start": 1, "end": 3, "quote": "omega", "note": "tail", "supports": false}),
        )
        .await;
        assert!(t.contains("e2 (undermines; execution:"), "{t}");
        assert!(!t.contains("still open"), "{t}");
        assert_eq!(ledger_records(&rig), vec![1, 2, 3, 4]);

        let t = refused(&rig, "claim_update", json!({"id": "c1", "status": "refuted"})).await;
        assert!(t.contains("note") || t.contains("Note"), "{t}");
    }

    #[tokio::test]
    async fn supported_claim_is_banked_once_and_refutation_is_not() {
        let rig = rig("lead", false, true);
        for text in ["first", "second", "third"] {
            ok(&rig, "claim", json!({"text": text})).await;
        }
        let h = rig.output("alpha\nbeta\n", "bash", ToolClass::Exec);
        for c in ["c1", "c2", "c3"] {
            ok(&rig, "evidence", json!({"claim": c, "handle": h, "start": 1, "end": 1, "quote": "alpha", "note": "n"}))
                .await;
        }
        let t = ok(&rig, "claim_update", json!({"id": "c1", "status": "supported"})).await;
        assert!(
            t.contains(
                "c1 is supported: first\nEstablished: c1. Results established in this mission so far: 1 (c1).\n"
            ),
            "{t}"
        );
        let t = ok(&rig, "claim_update", json!({"id": "c2", "status": "refuted", "note": "no"})).await;
        assert!(t.contains("c2 is refuted: second\n") && !t.contains("Established"), "{t}");
        let t = ok(&rig, "claim_update", json!({"id": "c3", "status": "supported"})).await;
        assert!(t.contains("Established: c3. Results established in this mission so far: 2 (c1, c3)."), "{t}");
        // Already supported: no second banking line.
        let t = ok(&rig, "claim_update", json!({"id": "c3", "status": "supported", "note": "again"})).await;
        assert!(t.contains("c3 is supported: third\n") && !t.contains("Established"), "{t}");
        // Out of supported and back in: banked again.
        ok(&rig, "claim_update", json!({"id": "c3", "status": "withdrawn", "note": "x"})).await;
        let t = ok(&rig, "claim_update", json!({"id": "c3", "status": "supported"})).await;
        assert!(t.contains("Established: c3."), "{t}");
    }

    #[tokio::test]
    async fn evidence_kind_follows_producer_class() {
        let rig = rig("lead", false, true);
        ok(&rig, "claim", json!({"text": "c"})).await;
        let h = rig.output("line one\n", "read", ToolClass::Read);
        let t = ok(
            &rig,
            "evidence",
            json!({"claim": "c1", "handle": h, "start": 1, "end": 1, "quote": "line one", "note": "n"}),
        )
        .await;
        assert!(t.contains("static: read call in s-test"), "{t}");
        let state = rig.shared.ledger().unwrap();
        let e = &state.evidence[0].input;
        assert_eq!(e.kind, loom_core::ledger::EvidenceKind::Static);
        assert!(e.attested);
        assert_eq!(e.lines, Some((1, 1)));
        assert_eq!(e.call_id.as_str(), "call-0");
    }

    #[tokio::test]
    async fn evidence_by_lines_records_the_stored_lines_and_plays_them_back() {
        let rig = rig("lead", false, true);
        ok(&rig, "claim", json!({"text": "the suite fails"})).await;
        let h = rig.output(
            "running 3 tests\n\n  test a ... FAILED   \n  left: 1, right: 2\n\ndone\n",
            "bash",
            ToolClass::Exec,
        );
        // No `quote`: the lines are taken from the stored output, blank ends left out, indentation kept.
        let t = ok(&rig, "evidence", json!({"claim": "c1", "handle": h, "start": 2, "end": 5, "note": "the failure"}))
            .await;
        assert!(t.contains("e1 (supports; execution: bash call in s-test) attached to c1."), "{t}");
        let played = format!(
            "Recorded from {h}, lines 3-4, as stored:\n|   test a ... FAILED\n|   left: 1, right: 2\nIf these are not the lines you meant, attach the right ones."
        );
        assert!(t.contains(&played), "{t}");
        let state = rig.shared.ledger().unwrap();
        let e = &state.evidence[0].input;
        assert_eq!(e.lines, Some((3, 4)));
        assert_eq!(e.quote.as_deref(), Some("  test a ... FAILED\n  left: 1, right: 2"));
        assert!(e.attested);
        assert_eq!(e.kind, loom_core::ledger::EvidenceKind::Execution);
        // A blank or null `quote` is the same; a quote given with its text is not played back.
        let t = ok(
            &rig,
            "evidence",
            json!({"claim": "c1", "handle": h, "start": 6, "end": 6, "quote": "  ", "note": "the end"}),
        )
        .await;
        assert!(t.contains(&format!("Recorded from {h}, lines 6-6, as stored:\n| done\n")), "{t}");
        let t = ok(
            &rig,
            "evidence",
            json!({"claim": "c1", "handle": h, "start": 1, "end": 6, "quote": "running 3 tests", "note": "the start"}),
        )
        .await;
        assert!(!t.contains("Recorded from"), "{t}");

        // Its refusals: the range is taken at its word, and nothing is attached. The record says a quote
        // was the reason, as it does for a quote given with text that does not occur.
        let t = refused(&rig, "evidence", json!({"claim": "c1", "handle": h, "start": 5, "end": 9, "note": "n"})).await;
        assert!(t.contains("end 9 is past its end") && t.contains("\nNothing was attached."), "{t}");
        for args in [
            json!({"claim": "c1", "handle": h, "start": 5, "end": 9, "note": "n"}),
            json!({"claim": "c1", "handle": h, "start": 1, "end": 6, "quote": "no such text here", "note": "n"}),
        ] {
            let r = rig.call("evidence", args).await;
            assert_eq!(r.meta.get(loom_core::event::META_REFUSAL), Some(&json!(loom_core::event::REFUSAL_QUOTE)));
        }
        // A refusal for another reason (an unknown claim) is not one over a quote.
        let r = rig.call("evidence", json!({"claim": "c9", "handle": h, "start": 6, "end": 6, "note": "n"})).await;
        assert_eq!(r.status, ToolStatus::Error, "{}", r.text);
        assert!(!r.meta.contains_key(loom_core::event::META_REFUSAL));
        let t = refused(&rig, "evidence", json!({"claim": "c1", "handle": h, "start": 5, "end": 5, "note": "n"})).await;
        assert!(t.contains("are blank"), "{t}");
        // The producer rule holds for it as for any quote: only an observation is evidence.
        let own = rig.output("the model's own words\n", "ledger", ToolClass::Read);
        let t =
            refused(&rig, "evidence", json!({"claim": "c1", "handle": own, "start": 1, "end": 1, "note": "n"})).await;
        assert!(t.contains("is the result of `ledger`"), "{t}");
        assert_eq!(rig.shared.ledger().unwrap().evidence.len(), 3);
    }

    #[tokio::test]
    async fn evidence_refusals() {
        let rig = rig("lead", false, true);
        ok(&rig, "claim", json!({"text": "c"})).await;
        let h = rig.output("hello world\n", "bash", ToolClass::Exec);

        let t = refused(
            &rig,
            "evidence",
            json!({"claim": "c1", "handle": h, "start": 1, "end": 1, "quote": "not there", "note": "n"}),
        )
        .await;
        assert!(t.contains("does not occur"), "{t}");
        assert!(t.contains("\nNothing was attached.\n"), "{t}");

        let t = refused(
            &rig,
            "evidence",
            json!({"claim": "c1", "handle": "out:deadbeefdeadbeef", "start": 1, "end": 1, "quote": "x", "note": "n"}),
        )
        .await;
        assert!(t.contains("\nNothing was attached.\n"), "{t}");

        // Stored but never produced by a tool call of the mission.
        let blob = rig.env.ctx.blobs.put_bytes(b"orphan text\n").unwrap();
        let t = refused(
            &rig,
            "evidence",
            json!({"claim": "c1", "handle": blob.handle(), "start": 1, "end": 1, "quote": "orphan text", "note": "n"}),
        )
        .await;
        assert!(t.contains("was not produced by a tool call of this mission"), "{t}");

        for (tool, class) in [("agent_spawn", ToolClass::State), ("finish", ToolClass::Terminal)] {
            let h = rig.output(&format!("report from {tool}\n"), tool, class);
            let t = refused(
                &rig,
                "evidence",
                json!({"claim": "c1", "handle": h, "start": 1, "end": 1, "quote": format!("report from {tool}"), "note": "n"}),
            )
            .await;
            assert!(t.contains(&format!("is the result of `{tool}`")), "{t}");
        }

        // Unknown claim: the ledger's refusal is passed through.
        let t = refused(
            &rig,
            "evidence",
            json!({"claim": "c9", "handle": h, "start": 1, "end": 1, "quote": "hello world", "note": "n"}),
        )
        .await;
        assert!(t.contains("c1"), "{t}");
        assert!(rig.shared.take_emitted().len() == 1, "only the claim was recorded");
    }

    /// The 1-based line of `blob` holding `needle`.
    fn line_of(rig: &Rig, blob: &loom_core::BlobRef, needle: &str) -> u64 {
        let text = String::from_utf8(rig.env.ctx.blobs.read_all(&blob.id).unwrap()).unwrap();
        let at = text.lines().position(|l| l.contains(needle)).expect("needle in output");
        at as u64 + 1
    }

    #[tokio::test]
    async fn the_models_own_words_are_not_evidence() {
        let rig = rig("lead", false, true);
        ok(&rig, "claim", json!({"text": "All 212 tests pass"})).await;
        let quote = "All 212 tests pass";

        // The ledger rendered back.
        let r = rig.call("ledger", json!({})).await;
        let blob = r.output.clone().unwrap();
        let n = line_of(&rig, &blob, quote);
        let h = blob.handle();
        let ev = |handle: &str, n: u64, quote: &str| json!({"claim": "c1", "handle": handle, "start": n, "end": n, "quote": quote, "note": "n"});
        let t = refused(&rig, "evidence", ev(&h, n, quote)).await;
        assert!(t.contains("is the result of `ledger`") && t.contains("not an observation"), "{t}");

        // A view of it stores nothing of its own, so the line copied from the view, number and all, can
        // only be cited under the handle of the ledger output, and is still the ledger's.
        let views = [("out_read", json!({"handle": h})), ("out_grep", json!({"handle": h, "pattern": "212 tests"}))];
        for (tool, args) in views {
            let view = rig.call(tool, args).await;
            assert_eq!(view.status, ToolStatus::Ok, "{}", view.text);
            assert!(view.output.is_none(), "{tool} stored an output of its own");
            let shown = view.text.lines().find(|l| l.contains(quote)).expect("the claim in the view");
            assert!(shown.starts_with(&n.to_string()), "{tool} shows the line with its number: {shown}");
            let t = refused(&rig, "evidence", ev(&h, n, shown)).await;
            assert!(t.contains("is the result of `ledger`"), "{tool}: {t}");
        }

        // The diff of the model's own edit shows what it wrote, not something it observed.
        std::fs::write(rig.env.ctx.workspace.join("notes.txt"), "first line\n").unwrap();
        ok(&rig, "read", json!({"path": "notes.txt"})).await;
        let r = rig.call("edit", json!({"path": "notes.txt", "old": "first line", "new": quote})).await;
        assert_eq!(r.status, ToolStatus::Ok, "{}", r.text);
        let blob = r.output.clone().unwrap();
        let t = refused(&rig, "evidence", ev(&blob.handle(), line_of(&rig, &blob, quote), quote)).await;
        assert!(t.contains("is the result of `edit`") && t.contains("not an observation"), "{t}");

        // A search of the session log finds the model's words and the claim's.
        let mut log =
            loom_core::log::SessionLog::create(&rig.shared.log_path, loom_core::log::Durability::Batch).unwrap();
        let said: loom_core::event::Event = serde_json::from_value(json!({
            "kind": "model_response", "req_id": "r1", "text": quote, "reasoning": "", "finish": "stop"
        }))
        .unwrap();
        log.append(loom_core::event::Author::Model, said).unwrap();
        let r = rig.call("log_search", json!({"pattern": "212"})).await;
        assert_eq!(r.status, ToolStatus::Ok, "{}", r.text);
        let blob = r.output.clone().unwrap();
        let n = line_of(&rig, &blob, "you: All 212");
        let h = blob.handle();
        let t = refused(
            &rig,
            "evidence",
            json!({"claim": "c1", "handle": h, "start": n, "end": n, "quote": quote, "note": "n"}),
        )
        .await;
        assert!(t.contains("is the result of `log_search`"), "{t}");
        assert!(rig.shared.ledger().unwrap().evidence.is_empty());
    }

    #[tokio::test]
    async fn a_view_of_a_command_output_is_evidence_of_that_command() {
        let rig = rig("lead", false, true);
        ok(&rig, "claim", json!({"text": "c"})).await;
        let h = rig.output("running 212 tests\ntest result: ok. 212 passed\n", "bash", ToolClass::Exec);
        // What each view shows of line 2, copied as shown, is a quote of the command's output.
        let views = [("out_read", json!({"handle": h})), ("out_grep", json!({"handle": h, "pattern": "result"}))];
        for (tool, args) in views {
            let view = rig.call(tool, args).await;
            assert_eq!(view.status, ToolStatus::Ok, "{}", view.text);
            let shown = view.text.lines().find(|l| l.contains("test result")).expect("line 2 in the view");
            assert!(shown.starts_with('2'), "{tool} shows the line with its number: {shown}");
            let t = ok(
                &rig,
                "evidence",
                json!({"claim": "c1", "handle": h, "start": 2, "end": 2, "quote": shown, "note": "n"}),
            )
            .await;
            assert!(t.contains("execution: bash call in s-test"), "{tool}: {t}");
        }
        let state = rig.shared.ledger().unwrap();
        assert_eq!(state.evidence.len(), 2);
        for e in &state.evidence {
            assert_eq!(e.input.kind, loom_core::ledger::EvidenceKind::Execution);
            assert_eq!(e.input.call_id.as_str(), "call-0");
            assert_eq!(e.input.quote.as_deref(), Some("test result: ok. 212 passed"));
        }
    }

    #[tokio::test]
    async fn evidence_quotes_check_line_numbers_and_length() {
        let rig = rig("lead", false, true);
        ok(&rig, "claim", json!({"text": "c"})).await;
        let h = rig.output("0 of 40 tests passed\nsecond line here\nok\n", "bash", ToolClass::Exec);
        let ev = |start: u64, end: u64, quote: &str| json!({"claim": "c1", "handle": h, "start": start, "end": end, "quote": quote, "note": "n"});
        let t = refused(&rig, "evidence", ev(1, 1, "40: tests passed")).await;
        assert!(t.contains("the text is on line 1") && t.contains("not line 40"), "{t}");
        let t = refused(&rig, "evidence", ev(1, 3, "pass")).await;
        assert!(t.contains("at least 8 non-space characters"), "{t}");
        assert!(rig.shared.ledger().unwrap().evidence.is_empty());
        ok(&rig, "evidence", ev(1, 1, "1\ttests passed")).await;
        ok(&rig, "evidence", ev(3, 3, "ok")).await;
        let state = rig.shared.ledger().unwrap();
        // A fragment is recorded as the whole line it lies on.
        assert_eq!(state.evidence[0].input.quote.as_deref(), Some("0 of 40 tests passed"));
        assert_eq!(state.evidence[1].input.quote.as_deref(), Some("ok"));
    }

    #[tokio::test]
    async fn an_evidence_fragment_cannot_start_inside_a_token() {
        let rig = rig("lead", false, true);
        ok(&rig, "claim", json!({"text": "c"})).await;
        let h = rig.output("test result: FAILED. 5 passed; 10 failed; 0 ignored\n", "bash", ToolClass::Exec);
        let ev = |quote: &str| json!({"claim": "c1", "handle": h, "start": 1, "end": 1, "quote": quote, "note": "n"});
        let t = refused(&rig, "evidence", ev("0 failed; 0 ignored")).await;
        assert!(t.contains("occurs on line 1") && t.contains("only inside a longer word or number"), "{t}");
        assert!(rig.shared.ledger().unwrap().evidence.is_empty());
    }

    #[tokio::test]
    async fn an_evidence_fragment_of_a_long_line_is_recorded_as_a_window_around_it() {
        let rig = rig("lead", false, true);
        ok(&rig, "claim", json!({"text": "c"})).await;
        let fragment = "versions before 2.4.1 are affected";
        let line = format!("{}{fragment}, {}", "lorem ".repeat(150), "ipsum ".repeat(5_000));
        let h = rig.output(&format!("{}\n", line.trim_end()), "web_fetch", ToolClass::Read);
        ok(&rig, "evidence", json!({"claim": "c1", "handle": h, "start": 1, "end": 1, "quote": fragment, "note": "n"}))
            .await;
        let state = rig.shared.ledger().unwrap();
        let quote = state.evidence[0].input.quote.clone().unwrap_or_default();
        assert!(quote.contains(fragment) && quote.starts_with('…') && quote.ends_with('…'), "{quote}");
        assert!(quote.chars().count() <= loom_core::observe::QUOTE_RECORD_CHARS, "{quote}");
        assert_eq!(state.evidence[0].input.lines, Some((1, 1)));
    }

    #[tokio::test]
    async fn refusal_sentences_name_tools_that_exist() {
        let rig = rig("lead", false, true);
        let known = crate::rtools::known_tools();
        for name in ["step", "claim", "claim_update", "evidence"] {
            assert!(known.iter().any(|k| k == name), "{name} is not a tool");
        }
        ok(&rig, "plan", json!({"steps": ["a"]})).await;
        ok(&rig, "claim", json!({"text": "c"})).await;
        let mut sentences = vec![
            refused(&rig, "step", json!({"id": "p1", "status": "done"})).await,
            refused(&rig, "step", json!({"id": "p1", "status": "done", "evidence": ["e9"]})).await,
            refused(&rig, "claim_update", json!({"id": "c1", "status": "supported"})).await,
            refused(
                &rig,
                "evidence",
                json!({"claim": "c9", "handle": "x", "start": 1, "end": 1, "quote": "q", "note": "n"}),
            )
            .await,
            refused(&rig, "note", json!({"kind": "dead_end", "text": "  ", "why": "x"})).await,
            refused(&rig, "note", json!({"kind": "decision", "text": "x", "why": "  "})).await,
        ];
        let h = rig.output("some output line\n", "bash", ToolClass::Exec);
        sentences.push(
            refused(
                &rig,
                "evidence",
                json!({"claim": "c9", "handle": h, "start": 1, "end": 1, "quote": "some output", "note": "n"}),
            )
            .await,
        );
        for text in sentences {
            for dead in ["plan_update", "evidence_add", "claim_add", "obligation_open", "obligation_settle"] {
                assert!(!text.contains(dead), "{dead} is not a tool: {text}");
            }
            for word in text.split('`').skip(1).step_by(2) {
                let word = word.trim();
                // Ids of ledger records in the sentence (e9, c1, p2) are data, not names.
                if word.len() < 4 && word.chars().skip(1).all(|c| c.is_ascii_digit()) {
                    continue;
                }
                let params = ["note", "evidence", "start", "end", "quote", "handle", "id", "status", "text", "why"];
                let known_word = known.iter().any(|k| k == word) || params.contains(&word);
                assert!(known_word || word.starts_with("out:"), "`{word}` is not a tool or parameter: {text}");
            }
        }
    }

    #[tokio::test]
    async fn ledger_tool_returns_markdown() {
        let rig = rig("lead", false, true);
        ok(&rig, "claim", json!({"text": "renders in markdown"})).await;
        let state = rig.shared.ledger().unwrap();
        let r = rig.call("ledger", json!({})).await;
        assert_eq!(r.status, ToolStatus::Ok);
        assert!(r.text.contains("generated from the mission journal"), "{}", r.text);
        assert!(r.text.contains("renders in markdown"));
        let bytes = rig.env.ctx.blobs.read_all(&r.output.unwrap().id).unwrap();
        assert_eq!(String::from_utf8(bytes).unwrap(), state.render_markdown());
    }

    #[tokio::test]
    async fn child_reads_mission_state_and_only_writes_its_own_claims() {
        let rig = rig("worker", true, true);
        rig.user_op(LedgerOp::GoalSet { text: "keep the operator's mission".into() });
        rig.user_op(LedgerOp::ConstraintAdd { text: "do not deploy".into() });
        rig.user_op(LedgerOp::ApprovalGrant { text: "inspect staging".into(), scope: "staging reads".into() });
        let journal = rig.shared.journal.as_ref().unwrap();
        journal
            .append(
                &loom_core::ids::SessionId::from("s-lead"),
                false,
                LedgerOp::ClaimAdd { text: "the lead's claim".into() },
                &|_| Ok(()),
            )
            .unwrap();
        let view = ok(&rig, "ledger", json!({})).await;
        for text in ["keep the operator's mission", "do not deploy", "inspect staging", "the lead's claim"] {
            assert!(view.contains(text), "missing {text}: {view}");
        }
        let before = journal.read().unwrap();
        let protected = [
            (false, LedgerOp::PlanSet { steps: vec!["replace the mission plan".into()] }),
            (false, LedgerOp::ApprovalUse { id: "a1".into(), used_for: "deploy".into() }),
            (true, LedgerOp::GoalSet { text: "replace the mission".into() }),
            (true, LedgerOp::ConstraintAdd { text: "pretend operator instruction".into() }),
            (true, LedgerOp::ApprovalGrant { text: "pretend permission".into(), scope: "all".into() }),
        ];
        for (from_user, op) in protected {
            assert!(rig.shared.ledger_append(from_user, op).is_err());
        }
        assert!(refused(&rig, "claim_update", json!({"id": "c1", "status": "withdrawn", "note": "not mine"}))
            .await
            .contains("another session"));
        let h = rig.output("observed result\n", "bash", ToolClass::Exec);
        let quote = |claim: &str| json!({"claim": claim, "handle": h, "start": 1, "end": 1, "quote": "observed result", "note": "observed directly"});
        assert!(refused(&rig, "evidence", quote("c1")).await.contains("another session"));
        assert_eq!(journal.read().unwrap(), before, "refused writes must leave the journal unchanged");

        ok(&rig, "note", json!({"kind": "decision", "text": "inspect the failing test", "why": "narrow the cause"}))
            .await;
        ok(&rig, "claim", json!({"text": "the child observed a result"})).await;
        ok(&rig, "evidence", quote("c2")).await;
        ok(&rig, "claim_update", json!({"id": "c2", "status": "supported"})).await;
        let state = rig.shared.ledger().unwrap();
        assert_eq!(state.claims[0].status, loom_core::ledger::ClaimStatus::Open);
        assert_eq!(state.claims[1].status, loom_core::ledger::ClaimStatus::Supported);
        assert_eq!(state.evidence[0].input.session, rig.shared.session);
        assert!(state.evidence[0].input.attested);
        let entries = journal.read().unwrap();
        assert!(entries[before.len()..].iter().all(|e| e.session == rig.shared.session && !e.from_user));
    }

    #[tokio::test]
    async fn verifier_can_read_but_cannot_write_mission_state() {
        let rig = rig("verifier", true, true);
        rig.user_op(LedgerOp::GoalSet { text: "verify this mission".into() });
        let before = rig.shared.journal.as_ref().unwrap().read().unwrap();
        assert!(ok(&rig, "ledger", json!({})).await.contains("verify this mission"));
        for op in [
            LedgerOp::ClaimAdd { text: "my finding".into() },
            LedgerOp::Decision { text: "accept".into(), reason: "looks right".into() },
            LedgerOp::DeadEnd { what: "try again".into(), why: "failed".into() },
        ] {
            assert!(rig.shared.ledger_append(false, op).unwrap_err().contains("read-only"));
        }
        assert_eq!(rig.shared.journal.as_ref().unwrap().read().unwrap(), before);
        assert!(rig.shared.take_emitted().is_empty());
    }

    #[tokio::test]
    async fn no_mission_is_reported_by_every_tool() {
        let rig = rig("lead", false, false);
        let h = rig.output("x\n", "bash", ToolClass::Exec);
        let calls = [
            ("plan", json!({"steps": ["a"]})),
            ("step", json!({"text": "a"})),
            ("note", json!({"kind": "decision", "text": "a", "why": "b"})),
            ("claim", json!({"text": "a"})),
            ("claim_update", json!({"id": "c1", "status": "withdrawn", "note": "n"})),
            ("evidence", json!({"claim": "c1", "handle": h, "start": 1, "end": 1, "quote": "x", "note": "n"})),
            ("ledger", json!({})),
        ];
        for (name, args) in calls {
            let t = refused(&rig, name, args).await;
            assert!(t.contains(NO_MISSION), "{name}: {t}");
        }
        assert!(rig.shared.take_emitted().is_empty());
    }
}
