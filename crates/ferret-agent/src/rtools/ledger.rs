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
//! - `plan`: `steps` are strings or objects `{step|text|content|description, status?, activeForm?, id?}`
//!   (`activeForm` and `id` are accepted and ignored). `status` is `pending|todo`, `in_progress|doing`,
//!   `completed|done` or `cancelled|dropped` (case and `-` ignored); any other value is refused before
//!   anything is written, naming the accepted values. Each step is trimmed; an empty step is refused with a
//!   sentence naming its position. When the given texts equal the current plan's step texts (same count,
//!   same order) the plan is kept, with its ids, notes and evidence, and only steps whose status differs
//!   are updated with `PlanUpdate` (a step given no status is left as it is). Outcome `plan updated`; text
//!   `Plan unchanged; step p2 → doing, p1 → done.` (or `Plan unchanged; no step changed status.`) then
//!   `plan_lines`. Otherwise `PlanSet { steps }` replaces the plan (outcome `plan set`), then each step
//!   given a status other than todo is updated; text `plan_lines`, preceded by `Plan set; step p1 → done.`
//!   when any status was applied. The ledger refuses `done` and `dropped` without a note, so a step
//!   moved to either keeps its existing note, or gets `marked done in `plan`` / `dropped in `plan``.
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
//! - `claim`: `ClaimAdd { text, assets: Vec::new() }`. Outcome `claim {id} open`. Text: ``{id}: {text}`` and the line
//!   `Attach evidence with `evidence`, then set its status with `claim` and `id`.`
//! - `claim_update`: `ClaimUpdate { id, status, note }`. Outcome `claim {id} {status}`. When the claim moves INTO
//!   `supported` from another status, the text gains the line `Established: {id}. Results established in this
//!   mission so far: {n} ({ids, at most 8, then …}).` (`texts::result_banked`), counted from the ledger after
//!   the write. Nothing else is recorded; a refutation or withdrawal gets no such line. (`claim` always
//!   creates an open claim, so it never banks.)
//! - `evidence`:
//!   1. `gate::check_quotes_noted(ctx, &[Quote { handle, start, end, text: quote }])`: the quote is found by
//!      its text, with no line numbers needed. More than one place → refused with each listed as
//!      `line {n}: {line}` (at most 10, each cut at 200 characters) and "Add `start` to say which."; `start`
//!      alone then names the line the text begins on. No exact match but one place once whitespace runs are
//!      collapsed and line ends count as a space → taken as the whole lines it lies on, and the result adds
//!      `matched lines {a}-{b} ignoring spacing.` (only an output of the
//!      session's mission; another mission's is refused as a handle that names nothing); on `Err(text)`
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
//!      Some((start, end)) as verified, quote: the verified text, note, attested: true, tool:
//!      Some(producer.tool), grade: Some(producer.grade) })` where `kind` is `Execution` when the producer's
//!      grade is `Run` and its class is `Exec`, else `Static`. The class alone does not decide: `dep_scan`,
//!      `bin_decompile` and `bin_xrefs` are `Exec` tools whose output is analysis, so a quote of it is static
//!      evidence and meets no rule that asks for a run. The verified text has no
//!      line-number prefixes; a fragment is recorded as the complete line or lines it lies on, and `lines`
//!      are their numbers (on lines longer than `observe::QUOTE_RECORD_CHARS` characters, a window of them
//!      around the fragment, `…` marking what was left out).
//!
//!   Outcome `evidence {id} attached to {claim}`. Text: `{id} ({supports|undermines}; {grade}: {tool} call
//!   in {session}) attached to {claim}.` (`{grade}` is `run`, `analysis`, `read` or `reference`); when the
//!   grade is `analysis` or `reference`, the line `texts::evidence_not_a_run(grade, tool)`; when the claim is
//!   still `Open`, the line `The claim is still open — set its status with `claim` and `id`.` After a quote by lines,
//!   what was
//!   recorded follows, since nothing compared the line numbers with a text and a miscounted range shows
//!   nowhere else: `Recorded from {handle}, lines {start}-{end}, as stored:`, each line of the text as
//!   `| {line}`, and `If these are not the lines you meant, attach the right ones.` A quote given with
//!   its text is not played back: the model wrote it.
//! - `ledger`: `ToolOutput::ok("ledger", Body::Raw(state.render_markdown().into_bytes()))`.
//!
//! The id in each outcome is read from the returned state (the last item of the kind).
//!
//! Tests required (use a fake `Orchestrator`, a temp journal with a random key, and
//! `ferret_tools::execute` so that argument handling is covered): each tool's success text and the
//! `ledger` record emitted through `Shared::take_emitted`; each refusal path (ledger rule refusal
//! passed through verbatim, bad `step` combinations, empty plan step, `reflect` with a blank field, evidence with a wrong quote,
//! an unknown handle, an output with no producer, the output of `ledger` and of `log_search` cited
//! directly and as a view shows it, the diff of an `edit`); `evidence` kind by producer class, also
//! when the quote is copied from a view of a command's output; evidence by lines: what is recorded and
//! played back, its refusals, and the producer rule applying to it as well; a session without a mission
//! gets `NO_MISSION` from every tool. Grades: a quote of a producer graded `Analysis` (as `dep_scan`'s) is
//! recorded `Static` with `tool` and `grade` set, and the result says `analysis:` and carries the not-a-run
//! line; `Reference` likewise; a `Run` producer is recorded `Execution`; a producer of class `Exec` whose grade
//! is not `Run` is never recorded `Execution`; a `read` producer gets no not-a-run line.

use super::{observed_producer, Shared, NO_MISSION};
use crate::gate::{check_quotes_noted, Quote};
use crate::{frontier, texts};
use async_trait::async_trait;
use ferret_core::event::{EvidenceGrade, ToolClass, ToolSpec, META_REFUSAL, REFUSAL_QUOTE};
use ferret_core::ids::MissionId;
use ferret_core::ledger::{ClaimStatus, EvidenceInput, EvidenceKind, LedgerOp, LedgerState, StepStatus};
use ferret_tools::params::{opt, req, spec};
use ferret_tools::{Body, Tool, ToolCtx, ToolOutput};
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

fn step_text(step: &Value) -> &str {
    if let Some(s) = step.as_str() {
        return s.trim();
    }
    if let Some(obj) = step.as_object() {
        for key in ["step", "text", "content", "description"] {
            if let Some(s) = obj.get(key).and_then(Value::as_str) {
                let trimmed = s.trim();
                if !trimmed.is_empty() {
                    return trimmed;
                }
            }
        }
    }
    ""
}

/// A step status as the `plan` tool takes it: ferret's names and the TodoWrite / Codex ones.
fn plan_status(word: &str) -> Option<StepStatus> {
    match word.trim().to_ascii_lowercase().replace('-', "_").as_str() {
        "pending" | "todo" => Some(StepStatus::Todo),
        "in_progress" | "doing" => Some(StepStatus::Doing),
        "completed" | "done" => Some(StepStatus::Done),
        "cancelled" | "dropped" => Some(StepStatus::Dropped),
        _ => None,
    }
}

fn status_word(status: StepStatus) -> &'static str {
    match status {
        StepStatus::Todo => "todo",
        StepStatus::Doing => "doing",
        StepStatus::Done => "done",
        StepStatus::Dropped => "dropped",
    }
}

/// The update that moves step `id` to `status`. The ledger refuses `done` and `dropped` without a note, so a
/// step that has none gets a short one saying where the status came from.
fn plan_update(id: &str, status: StepStatus, current_note: &str) -> LedgerOp {
    let note = if !current_note.trim().is_empty() {
        current_note.to_string()
    } else {
        match status {
            StepStatus::Done => "marked done in `plan`".to_string(),
            StepStatus::Dropped => "dropped in `plan`".to_string(),
            StepStatus::Todo | StepStatus::Doing => String::new(),
        }
    };
    LedgerOp::PlanUpdate { id: id.to_string(), status, note, evidence: Vec::new() }
}

/// One item of a `plan` call.
struct PlanItem {
    id: Option<String>,
    text: String,
    status: Option<StepStatus>,
    note: String,
    evidence: Vec<String>,
}

/// The update that moves step `id` to `status` with what the call said: `note` and `evidence` apply to
/// `done` and `dropped` only; with neither, the step keeps its note or gets the fallback of `plan_update`.
fn item_update(id: &str, status: StepStatus, item: &PlanItem, current_note: &str) -> LedgerOp {
    if !matches!(status, StepStatus::Done | StepStatus::Dropped) || (item.note.is_empty() && item.evidence.is_empty()) {
        return plan_update(id, status, current_note);
    }
    LedgerOp::PlanUpdate { id: id.to_string(), status, note: item.note.clone(), evidence: item.evidence.clone() }
}

#[async_trait]
impl Tool for Plan {
    fn spec(&self) -> ToolSpec {
        spec(
            "plan",
            "Set the plan for the mission: an ordered list of steps, each one concrete enough to be checked off. This replaces the current plan, unless the step texts are the same as the current plan's (then the plan is kept and only the statuses you give are applied) or begin with all of them (then the new ones are added at the end). To update steps, send items with `id` and `status` only (for example {id: p2, status: completed, note: ...}); the other steps stay as they are. Marking a step completed needs `note` (what showed that it is done) or `evidence` ids; cancelled needs `note` (why).",
            ToolClass::State,
            &[req(
                "steps",
                "array",
                "The steps, in order. Plain strings or {step|text|content, status?, note?, evidence?} objects, one sentence each; or {id, status, note?, evidence?} objects to update steps by id. `status` is pending, in_progress, completed or cancelled. `note` and `evidence` (ids such as e1) go with completed or cancelled.",
            )
            .with("items", json!({"anyOf": [{"type": "string"}, {"type": "object"}]}))],
        )
    }
    async fn run(&self, _ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let Some(steps) = args.get("steps").and_then(Value::as_array) else {
            return ToolOutput::error("`steps` must be a list of sentences, one per plan step.");
        };
        let mut items: Vec<PlanItem> = Vec::new();
        for (i, step) in steps.iter().enumerate() {
            let position = i.saturating_add(1);
            let text = step_text(step).to_string();
            let obj = step.as_object();
            let id = obj.and_then(|o| o.get("id")).and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty());
            if text.is_empty() && id.is_none() {
                return ToolOutput::error(format!(
                    "Step {position} of the plan is empty. Give every step a sentence saying what is to be done; nothing was recorded.",
                ));
            }
            let status = match obj.and_then(|o| o.get("status")) {
                None | Some(Value::Null) => None,
                Some(v) => match v.as_str().and_then(plan_status) {
                    Some(parsed) => Some(parsed),
                    None => {
                        return ToolOutput::error(format!(
                            "Step {position} of the plan has the status {v}, which is not one of pending, in_progress, completed, cancelled (or todo, doing, done, dropped). Nothing was recorded; send the plan again with one of those."
                        ));
                    }
                },
            };
            let note = obj.and_then(|o| o.get("note")).and_then(Value::as_str).unwrap_or("").trim().to_string();
            let evidence = obj
                .and_then(|o| o.get("evidence"))
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
                .unwrap_or_default();
            items.push(PlanItem { id: id.map(str::to_string), text, status, note, evidence });
        }
        let by_id = items.iter().filter(|it| it.text.is_empty()).count();
        if by_id > 0 && by_id < items.len() {
            return ToolOutput::error(
                "Some items of `steps` give only an `id` and others give text. To update steps, give every item an `id` and a `status` and no text; to set the plan, give every item its text. Nothing was recorded.",
            );
        }
        if by_id > 0 {
            return self.update_by_id(&items);
        }
        let texts: Vec<String> = items.iter().map(|it| it.text.clone()).collect();
        let current = self.0.ledger().ok();
        // The current plan is the last block of the ledger's step list: a `PlanSet` keeps the steps it
        // replaced (dropped) and appends its own.
        let tail_matches = |state: &LedgerState, k: usize| {
            state.plan.len().checked_sub(k).is_some_and(|skip| {
                state.plan.iter().skip(skip).zip(&texts).all(|(step, text)| step.text.trim() == text)
            })
        };
        let same_plan = current.as_ref().is_some_and(|state| tail_matches(state, texts.len()));
        // Append: the given texts begin with the plan's (the longest tail that does), and add more. A tail
        // of dropped steps only is a replaced plan, not the current one.
        let appended = if same_plan {
            None
        } else {
            current.as_ref().and_then(|state| {
                (1..texts.len()).rev().find(|k| {
                    tail_matches(state, *k)
                        && state.plan.iter().rev().take(*k).any(|p| !matches!(p.status, StepStatus::Dropped))
                })
            })
        };
        let (kept, outcome, mut state, mut head) = match current {
            Some(state) if same_plan => (true, "plan updated", state, "Plan unchanged".to_string()),
            Some(mut state) if appended.is_some() => {
                let k = appended.unwrap_or(0);
                for text in texts.iter().skip(k) {
                    match self.0.ledger_append(false, LedgerOp::PlanAdd { text: text.clone() }) {
                        Ok((_, next)) => state = next,
                        Err(text) => return ToolOutput::error(text),
                    }
                }
                let added = texts.len().saturating_sub(k);
                (true, "plan extended", state, format!("Plan kept; {added} step(s) added"))
            }
            _ => match self.0.ledger_append(false, LedgerOp::PlanSet { steps: texts }) {
                Ok((_, state)) => (false, "plan set", state, "Plan set".to_string()),
                Err(text) => return ToolOutput::error(text),
            },
        };
        let mut changes = Vec::new();
        let first = state.plan.len().saturating_sub(items.len());
        for (i, item) in items.iter().enumerate() {
            let Some(wanted) = item.status else { continue };
            let Some(step) = state.plan.get(first.saturating_add(i)) else { continue };
            if step.status == wanted && item.note.is_empty() && item.evidence.is_empty() {
                continue;
            }
            let (id, note) = (step.id.clone(), step.note.clone());
            match self.0.ledger_append(false, item_update(&id, wanted, item, &note)) {
                Ok((_, next)) => {
                    state = next;
                    changes.push(format!("{id} → {}", status_word(wanted)));
                }
                Err(text) => {
                    let applied = if changes.is_empty() {
                        String::new()
                    } else {
                        format!(" Already applied: {}.", changes.join(", "))
                    };
                    return ToolOutput::error(format!("{text}{applied}"));
                }
            }
        }
        if changes.is_empty() {
            if !kept {
                return ToolOutput::ok(outcome, Body::Message(plan_lines(&state)));
            }
            head.push_str("; no step changed status.");
        } else {
            head.push_str(&format!("; step {}.", changes.join(", ")));
        }
        ToolOutput::ok(outcome, Body::Message(format!("{head}\n{}", plan_lines(&state))))
    }
}

impl Plan {
    /// Items that give an `id` and no text update those steps only; every other step is left as it is.
    fn update_by_id(&self, items: &[PlanItem]) -> ToolOutput {
        let Ok(mut state) = self.0.ledger() else { return ToolOutput::error(NO_MISSION) };
        let known: Vec<String> = state.plan.iter().map(|p| p.id.clone()).collect();
        for (i, item) in items.iter().enumerate() {
            let position = i.saturating_add(1);
            let id = item.id.as_deref().unwrap_or("");
            if !known.iter().any(|k| k == id) {
                let list = if known.is_empty() { "there are none".to_string() } else { known.join(", ") };
                return ToolOutput::error(format!(
                    "Item {position} of `steps` names step {id}, which is not in the plan (steps: {list}). Nothing was recorded.",
                ));
            }
            if item.status.is_none() {
                return ToolOutput::error(format!(
                    "Item {position} of `steps` gives `id` {id} without a `status`. To update a step, give its `id` and `status`. Nothing was recorded.",
                ));
            }
        }
        let mut changes = Vec::new();
        for item in items {
            let (Some(id), Some(wanted)) = (item.id.as_deref(), item.status) else { continue };
            let Some(step) = state.plan.iter().find(|p| p.id == id) else { continue };
            if step.status == wanted && item.note.is_empty() && item.evidence.is_empty() {
                continue;
            }
            let note = step.note.clone();
            match self.0.ledger_append(false, item_update(id, wanted, item, &note)) {
                Ok((_, next)) => {
                    state = next;
                    changes.push(format!("{id} → {}", status_word(wanted)));
                }
                Err(text) => {
                    let applied = if changes.is_empty() {
                        String::new()
                    } else {
                        format!(" Already applied: {}.", changes.join(", "))
                    };
                    return ToolOutput::error(format!("{text}{applied}"));
                }
            }
        }
        let head = if changes.is_empty() {
            "Plan unchanged; no step changed status.".to_string()
        } else {
            format!("Plan updated; step {}.", changes.join(", "))
        };
        ToolOutput::ok("plan updated", Body::Message(format!("{head}\n{}", plan_lines(&state))))
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
                opt("evidence", "array", "Ids of evidence records (e1, e2) that show the step is done.")
                    .items("string"),
                opt("text", "string", "The text of a new step to add."),
            ],
        )
    }
    async fn run(&self, _ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let (outcome, op) = match (str_arg(args, "id"), str_arg(args, "status"), str_arg(args, "text")) {
            (None, None, Some(text)) => ("step added".to_string(), LedgerOp::PlanAdd { text: text.trim().to_string() }),
            (Some(id), Some(status), _) => {
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
                req(
                    "would_change",
                    "string",
                    "The evidence that, if you saw it, would change your conclusion about this mission — and what you would do with it.",
                ),
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
            "State something you intend to establish as fact (a finding, a root cause, 'the fix works') with `text`; you may attach evidence and set its status in the same call by passing `handle` (with `quote` or `start`/`end`) and optional `status`/`note`, otherwise it stays open until you call `evidence` and then `claim` again. To attach evidence, copy the exact text from an output you were shown into `quote`; line numbers are not needed. Settle an existing claim with `id` and `status` (`supported` needs evidence attached; `refuted` and `withdrawn` need `note`). Returns the claim's id.",
            ToolClass::State,
            &[
                opt("text", "string", "The claim, as one checkable statement (a new claim)."),
                opt("id", "string", "An existing claim to settle, for example c1; give it with `status` and no `text`."),
                opt("handle", "string", "Optional stored output handle (for example out:7f3a9c1e) to attach as evidence right away."),
                opt("start", "integer", "First line of the quote in that output; only when the quote appears more than once (or with `end` and no `quote`).").min(1),
                opt("end", "integer", "Last line of the quote in that output; only when the quote appears more than once (or with `start` and no `quote`).").min(1),
                opt("quote", "string", "The exact text, copied from an output you were shown; line numbers are not needed. Leave out to take lines start-end whole, as stored."),
                opt("status", "string", "Optional status to set immediately after attaching evidence.").one_of(&["supported", "refuted", "withdrawn"]),
                opt("note", "string", "One sentence explaining what the evidence shows, or why the claim is refuted/withdrawn."),
                opt("assets", "array", "Optional: the assets (ids or locators of the security state) a new claim is about. The hosts of host, service and endpoint assets are the hosts the claim names.").items("string"),
            ],
        )
    }
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let shared = &self.0;
        let Some(mission) = shared.mission.as_ref() else { return ToolOutput::error(NO_MISSION) };
        let id = str_arg(args, "id");
        let text_given = args.get("text").is_some_and(Value::is_string);
        let has_text = str_arg(args, "text").is_some();
        match (id, has_text) {
            (Some(_), true) => {
                return ToolOutput::error(
                    "Give `text` to record a new claim, or `id` and `status` to settle an existing one, not both. To change what a claim says, record a new claim and withdraw this one.",
                );
            }
            (None, false) if !text_given => {
                return ToolOutput::error(
                    "Give `text` to record a new claim, or `id` and `status` to settle an existing one.",
                );
            }
            (Some(_), false) => {
                if let Some(key) = ["handle", "start", "end", "quote"]
                    .into_iter()
                    .find(|k| args.get(*k).is_some_and(|v| !v.is_null() && v.as_str() != Some("")))
                {
                    return ToolOutput::error(format!(
                        "`claim` with `id` only settles a claim, so `{key}` is not accepted with it. To change what a claim says, record a new claim and withdraw this one.",
                    ));
                }
                return ClaimUpdate(shared.clone()).run(ctx, args).await;
            }
            _ => {}
        }
        let text = str_arg(args, "text").unwrap_or("").to_string();
        if text.trim().is_empty() {
            return match shared.ledger_append(false, LedgerOp::ClaimAdd { text, assets: Vec::new() }) {
                Ok(_) => unreachable!("empty claim text must be refused by ledger"),
                Err(err) => ToolOutput::error(err),
            };
        }

        let handle = str_arg(args, "handle");
        let start = args.get("start").and_then(Value::as_u64).unwrap_or(0);
        let end = args.get("end").and_then(Value::as_u64).unwrap_or(0);
        let quote = str_arg(args, "quote").unwrap_or("");
        let note = str_arg(args, "note").unwrap_or("").trim().to_string();
        let parsed_status = match str_arg(args, "status") {
            None => None,
            Some(raw) => {
                let Some(parsed) = parse_enum::<ClaimStatus>(raw) else {
                    return ToolOutput::error("`status` must be one of supported, refuted, withdrawn.");
                };
                if parsed == ClaimStatus::Supported && handle.is_none() {
                    return ToolOutput::error(
                        "Setting status to supported requires `handle` (with `quote` or `start`/`end`) to attach supporting evidence.",
                    );
                }
                if matches!(parsed, ClaimStatus::Refuted | ClaimStatus::Withdrawn) && note.is_empty() {
                    return ToolOutput::error("Setting status to refuted or withdrawn requires a non-empty `note`.");
                }
                Some((parsed, raw.to_string()))
            }
        };

        if handle.is_none() && (!quote.trim().is_empty() || start > 0 || end > 0) {
            return ToolOutput::error("Give `handle` when attaching a quote with `claim`.");
        }

        // Validate quote and producer BEFORE writing ClaimAdd so a bad handle/quote leaves zero stray claims.
        let mut obs = if let Some(h) = handle {
            let supports = !matches!(parsed_status, Some((ClaimStatus::Refuted, _)));
            let ev_note = if note.is_empty() { text.trim() } else { note.as_str() };
            match verify_observation(
                shared,
                ctx,
                mission,
                "",
                h,
                start,
                end,
                quote,
                ev_note,
                supports,
                "Nothing was recorded.",
            )
            .await
            {
                Ok(v) => Some((h.to_string(), supports, v)),
                Err(out) => return *out,
            }
        } else {
            None
        };

        let assets: Vec<String> = match args.get("assets") {
            Some(Value::Array(a)) => {
                a.iter().filter_map(|v| v.as_str()).map(|v| v.trim().to_string()).filter(|v| !v.is_empty()).collect()
            }
            _ => Vec::new(),
        };
        let (_, mut state) = match shared.ledger_append(false, LedgerOp::ClaimAdd { text, assets }) {
            Ok(ok) => ok,
            Err(err) => return ToolOutput::error(err),
        };
        let (claim_id, claim_text) = state.claims.last().map(|c| (c.id.clone(), c.text.clone())).unwrap_or_default();

        let mut extra_lines = Vec::new();
        if let Some((_, supports, ref mut v)) = obs {
            v.input.claim = claim_id.clone();
            let ev_input = v.input.clone();
            let (_, ev_state) = match shared.ledger_append(false, LedgerOp::EvidenceAdd(ev_input)) {
                Ok(ok) => ok,
                Err(err) => return ToolOutput::error(err),
            };
            state = ev_state;
            let ev_id = state.evidence.last().map(|e| e.id.as_str()).unwrap_or("");
            let side = if supports { "supports" } else { "undermines" };
            extra_lines.push(format!(
                "{ev_id} ({side}; {}: {} call in {}) attached to {claim_id}.",
                v.grade.as_str(),
                v.tool,
                v.session
            ));
            if let Some(line) = texts::evidence_not_a_run(v.grade, &v.tool) {
                extra_lines.push(line);
            }
        }

        if let Some((parsed, status_word)) = parsed_status {
            let (_, upd_state) = match shared
                .ledger_append(false, LedgerOp::ClaimUpdate { id: claim_id.clone(), status: parsed, note })
            {
                Ok(ok) => ok,
                Err(err) => return ToolOutput::error(err),
            };
            state = upd_state;
            let mut msg = format!("{claim_id} is {status_word}: {claim_text}");
            for line in extra_lines {
                msg.push('\n');
                msg.push_str(&line);
            }
            if parsed == ClaimStatus::Supported {
                let established = frontier::frontier(&state, 0).established;
                msg.push('\n');
                msg.push_str(&texts::result_banked(&claim_id, established.len(), &frontier::id_list(&established)));
            }
            if let Some((_, _, v)) = &obs {
                if let Some(spacing) = &v.spacing {
                    msg.push('\n');
                    msg.push_str(spacing);
                    msg.push('.');
                }
                if let Some(recorded) = &v.recorded {
                    msg.push('\n');
                    msg.push_str(recorded);
                }
            }
            return ToolOutput::ok(format!("claim {claim_id} {status_word}"), Body::Message(msg));
        }

        let mut msg = format!("{claim_id}: {claim_text}");
        for line in extra_lines {
            msg.push('\n');
            msg.push_str(&line);
        }
        if obs.is_some() {
            msg.push_str("\nThe claim is still open — set its status with `claim` and `id`.");
            if let Some((_, _, v)) = &obs {
                if let Some(spacing) = &v.spacing {
                    msg.push('\n');
                    msg.push_str(spacing);
                    msg.push('.');
                }
                if let Some(recorded) = &v.recorded {
                    msg.push('\n');
                    msg.push_str(recorded);
                }
            }
        } else {
            msg.push_str("\nAttach evidence with `evidence`, then set its status with `claim` and `id`.");
        }
        ToolOutput::ok(format!("claim {claim_id} open"), Body::Message(msg))
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

struct VerifiedObservation {
    input: EvidenceInput,
    grade: EvidenceGrade,
    tool: String,
    session: String,
    recorded: Option<String>,
    /// Which lines were taken when the quote matched ignoring spacing.
    spacing: Option<String>,
}

fn quote_refused(text: String) -> ToolOutput {
    ToolOutput::error(text).with_meta(META_REFUSAL, json!(REFUSAL_QUOTE))
}

#[allow(clippy::too_many_arguments)]
async fn verify_observation(
    shared: &Shared,
    ctx: &ToolCtx,
    mission: &MissionId,
    claim_id: &str,
    handle: &str,
    start: u64,
    end: u64,
    quote: &str,
    note: &str,
    supports: bool,
    fail_suffix: &str,
) -> Result<VerifiedObservation, Box<ToolOutput>> {
    // Without its text the quote is the lines named: the result then shows what was recorded.
    let by_lines = quote.trim().is_empty();
    if start == 0 && end == 0 && by_lines {
        return Err(Box::new(quote_refused(format!(
            "Give `quote`, or both `start` and `end` line numbers.\n{fail_suffix}"
        ))));
    }
    let q = Quote { handle: handle.to_string(), start, end, text: quote.to_string() };
    let verified = match check_quotes_noted(ctx, &[q]).await {
        Ok(v) => v,
        Err(text) => return Err(Box::new(quote_refused(format!("{text}\n{fail_suffix}")))),
    };
    let Some((v, spacing)) = verified.into_iter().next() else {
        return Err(Box::new(ToolOutput::error(
            "The quote could not be checked, so nothing was attached. Check `handle`, `start` and `end`.",
        )));
    };
    // Only observations are evidence.
    let producer = match observed_producer(shared, mission, handle, &v.blob).await {
        Ok(p) => p,
        Err(text) => return Err(Box::new(quote_refused(text))),
    };
    // Only a run is execution evidence; an Exec tool whose output is analysis (dep_scan) is not one.
    let run = producer.grade == EvidenceGrade::Run && producer.class == ToolClass::Exec;
    let kind = if run { EvidenceKind::Execution } else { EvidenceKind::Static };
    let recorded = by_lines.then(|| recorded_lines(handle, v.start, v.end, &v.text));
    let input = EvidenceInput {
        claim: claim_id.to_string(),
        kind,
        supports,
        session: producer.session.clone(),
        call_id: producer.call_id.clone(),
        blob: Some(v.blob),
        lines: Some((v.start, v.end)),
        quote: Some(v.text),
        note: note.to_string(),
        attested: true,
        tool: Some(producer.tool.clone()),
        grade: Some(producer.grade),
    };
    Ok(VerifiedObservation {
        input,
        grade: producer.grade,
        tool: producer.tool,
        session: producer.session.to_string(),
        recorded,
        spacing,
    })
}

#[async_trait]
impl Tool for Evidence {
    fn spec(&self) -> ToolSpec {
        spec(
            "evidence",
            "Attach evidence to a claim from the output of a command you ran or a file you read. Copy the exact text from an output you were shown into `quote`; line numbers are not needed. Quote whole lines, or at least 8 non-space characters of a line. The harness finds the text and records the line or lines it is on; differences in spacing are forgiven when the text is found in one place. If the text occurs more than once, the call is refused with every place listed, and you add `start` to say which. `handle` is the out:… id shown in the header of that result. Only when you want whole lines as stored, leave `quote` out and give `handle`, `start` and `end`; the harness takes those lines (at most 40) and shows you what it recorded.",
            ToolClass::State,
            &[
                req("claim", "string", "The claim this bears on, for example c1."),
                req("handle", "string", "The stored output the quote is from, for example out:7f3a9c1e."),
                opt("start", "integer", "First line of the quote in that output; only when the quote appears more than once (or with `end` and no `quote`).").min(1),
                opt("end", "integer", "Last line of the quote in that output; only when the quote appears more than once (or with `start` and no `quote`).").min(1),
                opt("quote", "string", "The exact text, copied from an output you were shown; line numbers are not needed. Leave out to take lines start-end whole, as stored."),
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

        let obs = match verify_observation(
            shared,
            ctx,
            mission,
            &claim,
            &handle,
            start,
            end,
            &quote,
            &note,
            supports,
            "Nothing was attached.",
        )
        .await
        {
            Ok(v) => v,
            Err(out) => return *out,
        };
        match shared.ledger_append(false, LedgerOp::EvidenceAdd(obs.input)) {
            Ok((_, state)) => {
                let id = state.evidence.last().map(|e| e.id.as_str()).unwrap_or("");
                let side = if supports { "supports" } else { "undermines" };
                let mut text = format!(
                    "{id} ({side}; {}: {} call in {}) attached to {claim}.",
                    obs.grade.as_str(),
                    obs.tool,
                    obs.session
                );
                if let Some(line) = texts::evidence_not_a_run(obs.grade, &obs.tool) {
                    text.push('\n');
                    text.push_str(&line);
                }
                if state.claims.iter().any(|c| c.id == claim && c.status == ClaimStatus::Open) {
                    text.push_str("\nThe claim is still open — set its status with `claim` and `id`.");
                }
                if let Some(spacing) = obs.spacing {
                    text.push('\n');
                    text.push_str(&spacing);
                    text.push('.');
                }
                if let Some(recorded) = obs.recorded {
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
    use crate::texts;
    use ferret_core::event::{Event, EvidenceGrade, ToolClass, ToolStatus};
    use ferret_core::ledger::{EvidenceKind, LedgerOp};
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
    async fn plan_same_texts_keep_ids_and_apply_statuses() {
        let rig = rig("lead", false, true);
        ok(&rig, "plan", json!({"steps": ["read", "fix", "ship"]})).await;
        ok(&rig, "step", json!({"id": "p3", "status": "doing"})).await;
        let t = ok(
            &rig,
            "plan",
            json!({"steps": [
                {"content": "read", "status": "completed", "activeForm": "Reading", "id": "7"},
                {"description": " fix ", "status": "in_progress"},
                {"text": "ship", "status": "doing"},
            ]}),
        )
        .await;
        assert!(t.contains("plan updated"), "{t}");
        assert!(t.contains("Plan unchanged; step p1 → done, p2 → doing."), "{t}");
        assert!(t.contains("[x] p1 read — marked done in `plan`\n[>] p2 fix\n[>] p3 ship"), "{t}");
        // Resent with nothing new: nothing changes, and a plain-string resend leaves statuses alone.
        let t = ok(&rig, "plan", json!({"steps": ["read", "fix", "ship"]})).await;
        assert!(t.contains("Plan unchanged; no step changed status."), "{t}");
        assert!(t.contains("[x] p1 read"), "{t}");
        let state = rig.shared.ledger().unwrap();
        assert_eq!(state.plan.iter().map(|p| p.id.as_str()).collect::<Vec<_>>(), ["p1", "p2", "p3"]);
    }

    #[tokio::test]
    async fn plan_changed_text_sets_new_plan_with_statuses() {
        let rig = rig("lead", false, true);
        ok(&rig, "plan", json!({"steps": ["read", "fix"]})).await;
        ok(&rig, "step", json!({"id": "p1", "status": "done", "note": "read it"})).await;
        let t = ok(
            &rig,
            "plan",
            json!({"steps": [
                {"content": "read", "status": "completed"},
                {"content": "fix it properly", "status": "pending"},
                {"content": "ship", "status": "in_progress"},
            ]}),
        )
        .await;
        assert!(t.contains("plan set"), "{t}");
        // The old plan's steps stay listed (p2 dropped as replaced); numbering continues.
        assert!(t.contains("Plan set; step p3 → done, p5 → doing."), "{t}");
        assert!(t.contains("[x] p1 read — read it\n[-] p2 fix — replaced by a new plan\n"), "{t}");
        assert!(t.contains("[x] p3 read — marked done in `plan`\n[ ] p4 fix it properly\n[>] p5 ship"), "{t}");
    }

    #[tokio::test]
    async fn plan_refuses_an_unknown_status_and_takes_plain_strings() {
        let rig = rig("lead", false, true);
        let t = refused(&rig, "plan", json!({"steps": ["a", {"content": "b", "status": "blocked"}]})).await;
        assert!(t.contains("Step 2") && t.contains("pending, in_progress, completed, cancelled"), "{t}");
        assert!(t.contains("Nothing was recorded"), "{t}");
        assert!(rig.shared.ledger().unwrap().plan.is_empty());
        let t = ok(&rig, "plan", json!({"steps": ["a", "b"]})).await;
        assert!(t.contains("plan set") && t.contains("[ ] p1 a\n[ ] p2 b"), "{t}");
        assert!(!t.contains("Plan set;"), "{t}");
        let t = ok(&rig, "plan", json!({"steps": [{"text": "a", "status": "cancelled"}, "c"]})).await;
        assert!(t.contains("[-] p3 a — dropped in `plan`\n[ ] p4 c"), "{t}");
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
        assert!(refused(&rig, "step", json!({"id": "p1", "text": "x"})).await.contains(want));
        assert!(refused(&rig, "step", json!({"status": "done"})).await.contains(want));
        assert!(refused(&rig, "step", json!({"status": "done", "text": "x"})).await.contains(want));

        // A ledger rule refusal comes through verbatim.
        let rule = rig.shared.ledger_append(
            false,
            LedgerOp::PlanUpdate {
                id: "p1".into(),
                status: ferret_core::ledger::StepStatus::Done,
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
        assert!(t.contains("Attach evidence with `evidence`, then set its status with `claim` and `id`."), "{t}");

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
        assert!(t.contains("e1 (supports; run: bash call in s-test) attached to c1."), "{t}");
        assert!(t.contains("The claim is still open — set its status with `claim` and `id`."), "{t}");

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
        assert!(t.contains("e2 (undermines; run:"), "{t}");
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
    async fn claim_with_id_settles_a_claim_like_claim_update_and_refuses_ambiguous_calls() {
        let rig = rig("lead", false, true);
        ok(&rig, "claim", json!({"text": "first"})).await;
        let h = rig.output("alpha\nbeta\n", "bash", ToolClass::Exec);
        ok(&rig, "evidence", json!({"claim": "c1", "handle": h, "start": 1, "end": 1, "quote": "alpha", "note": "n"}))
            .await;
        let r = refused(&rig, "claim", json!({"id": "c1", "text": "x", "status": "supported"})).await;
        assert!(r.contains("not both"), "{r}");
        let r = refused(&rig, "claim", json!({})).await;
        assert!(r.contains("Give `text`"), "{r}");
        let r = refused(&rig, "claim", json!({"id": "c1", "status": "supported", "quote": "q"})).await;
        assert!(r.contains("only settles a claim"), "{r}");
        let t = ok(&rig, "claim", json!({"id": "c1", "status": "supported"})).await;
        assert!(t.contains("c1 is supported: first\nEstablished: c1."), "{t}");
        let t = ok(&rig, "claim", json!({"id": "c1", "status": "withdrawn", "note": "x"})).await;
        assert!(t.contains("c1 is withdrawn"), "{t}");
    }

    #[tokio::test]
    async fn plan_updates_by_id_with_note_and_evidence_and_refuses_a_mixed_list() {
        let rig = rig("lead", false, true);
        ok(&rig, "plan", json!({"steps": ["read", "fix", "ship"]})).await;
        let t = ok(
            &rig,
            "plan",
            json!({"steps": [{"id": "p1", "status": "done", "note": "read it"}, {"id": "p2", "status": "doing"}]}),
        )
        .await;
        assert!(t.contains("Plan updated; step p1 → done, p2 → doing."), "{t}");
        assert!(t.contains("[x] p1 read — read it\n[>] p2 fix\n[ ] p3 ship"), "{t}");
        let r = refused(&rig, "plan", json!({"steps": [{"id": "p9", "status": "done", "note": "n"}]})).await;
        assert!(r.contains("p9") && r.contains("Nothing was recorded"), "{r}");
        let r = refused(&rig, "plan", json!({"steps": [{"id": "p1", "status": "done"}, "more"]})).await;
        assert!(!r.is_empty(), "{r}");
        // Appending when the old texts are a prefix keeps the ids.
        let t = ok(&rig, "plan", json!({"steps": ["read", "fix", "ship", "tell"]})).await;
        assert!(t.contains("[ ] p4 tell") && t.contains("[x] p1 read"), "{t}");
        // A status without a note gets the fallback note, as before.
        let t = ok(&rig, "plan", json!({"steps": [{"id": "p3", "status": "dropped"}]})).await;
        assert!(t.contains("[-] p3 ship — dropped in `plan`"), "{t}");
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
        assert!(t.contains("read: read call in s-test"), "{t}");
        let state = rig.shared.ledger().unwrap();
        let e = &state.evidence[0].input;
        assert_eq!(e.kind, ferret_core::ledger::EvidenceKind::Static);
        assert!(e.attested);
        assert_eq!(e.lines, Some((1, 1)));
        assert_eq!(e.call_id.as_str(), "call-0");
    }

    #[tokio::test]
    async fn evidence_is_graded_by_what_the_producer_did() {
        let rig = rig("lead", false, true);
        ok(&rig, "claim", json!({"text": "c"})).await;
        let args =
            |h: &str| json!({"claim": "c1", "handle": h, "start": 1, "end": 1, "quote": "line one", "note": "n"});
        let cases = [
            ("dep_scan", ToolClass::Exec, EvidenceGrade::Analysis, "analysis"),
            ("cve_lookup", ToolClass::Exec, EvidenceGrade::Reference, "reference"),
        ];
        for (tool, class, grade, word) in cases {
            let h = rig.output_graded("line one\n", tool, class, grade);
            let t = ok(&rig, "evidence", args(&h)).await;
            assert!(t.contains(&format!("supports; {word}: {tool} call in s-test")), "{t}");
            let line = texts::evidence_not_a_run(grade, tool).expect("a line for a non-run");
            assert!(t.contains(&line), "{t}");
            // The not-a-run line comes before the claim-still-open line.
            let (a, b) = (t.find(&line).unwrap_or(0), t.find("still open").unwrap_or(0));
            assert!(a < b, "{t}");
        }
        let state = rig.shared.ledger().unwrap();
        for (e, (tool, _, grade, _)) in state.evidence.iter().zip(cases) {
            assert_eq!(e.input.kind, EvidenceKind::Static, "an Exec producer graded {grade:?} is never Execution");
            assert_eq!(e.input.tool.as_deref(), Some(tool));
            assert_eq!(e.input.grade, Some(grade));
        }

        // A run is Execution and gets no extra line; a read gets none either.
        let h = rig.output_graded("line one\n", "bash", ToolClass::Exec, EvidenceGrade::Run);
        let t = ok(&rig, "evidence", args(&h)).await;
        assert!(t.contains("supports; run: bash call in s-test"), "{t}");
        assert!(!t.contains("not a run"), "{t}");
        let h = rig.output("line one\n", "read", ToolClass::Read);
        let t = ok(&rig, "evidence", args(&h)).await;
        assert!(t.contains("supports; read: read call in s-test"), "{t}");
        assert!(!t.contains("not a run"), "{t}");
        let state = rig.shared.ledger().unwrap();
        assert_eq!(state.evidence[2].input.kind, EvidenceKind::Execution);
        assert_eq!(state.evidence[2].input.grade, Some(EvidenceGrade::Run));
        assert_eq!(state.evidence[3].input.kind, EvidenceKind::Static);
        assert_eq!(state.evidence[3].input.grade, Some(EvidenceGrade::Read));
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
        assert!(t.contains("e1 (supports; run: bash call in s-test) attached to c1."), "{t}");
        let played = format!(
            "Recorded from {h}, lines 3-4, as stored:\n|   test a ... FAILED\n|   left: 1, right: 2\nIf these are not the lines you meant, attach the right ones."
        );
        assert!(t.contains(&played), "{t}");
        let state = rig.shared.ledger().unwrap();
        let e = &state.evidence[0].input;
        assert_eq!(e.lines, Some((3, 4)));
        assert_eq!(e.quote.as_deref(), Some("  test a ... FAILED\n  left: 1, right: 2"));
        assert!(e.attested);
        assert_eq!(e.kind, ferret_core::ledger::EvidenceKind::Execution);
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
        let t = refused(&rig, "evidence", json!({"claim": "c1", "handle": h, "start": 7, "end": 9, "note": "n"})).await;
        assert!(t.contains("start 7 is past its end") && t.contains("\nNothing was attached."), "{t}");
        for args in [
            json!({"claim": "c1", "handle": h, "start": 7, "end": 9, "note": "n"}),
            json!({"claim": "c1", "handle": h, "start": 1, "end": 6, "quote": "no such text here", "note": "n"}),
        ] {
            let r = rig.call("evidence", args).await;
            assert_eq!(r.meta.get(ferret_core::event::META_REFUSAL), Some(&json!(ferret_core::event::REFUSAL_QUOTE)));
        }
        // A refusal for another reason (an unknown claim) is not one over a quote.
        let r = rig.call("evidence", json!({"claim": "c9", "handle": h, "start": 6, "end": 6, "note": "n"})).await;
        assert_eq!(r.status, ToolStatus::Error, "{}", r.text);
        assert!(!r.meta.contains_key(ferret_core::event::META_REFUSAL));
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

        // Stored, and not an output of this mission at all: the sentence of a handle that names nothing, and
        // nothing of the output (not even that its range is past its end) is said.
        let foreign = rig.env.ctx.blobs.put_bytes(b"another mission's text\n").unwrap();
        let t = refused(
            &rig,
            "evidence",
            json!({"claim": "c1", "handle": foreign.handle(), "start": 1, "end": 1, "quote": "x", "note": "n"}),
        )
        .await;
        assert!(t.contains("no output of this mission has the handle") && !t.contains("another mission"), "{t}");
        let t = refused(
            &rig,
            "evidence",
            json!({"claim": "c1", "handle": foreign.handle(), "start": 9, "end": 9, "quote": "x", "note": "n"}),
        )
        .await;
        assert!(t.contains("no output of this mission has the handle") && !t.contains("lines"), "{t}");

        // Stored but never produced by a tool call of the mission.
        let blob = rig.env.ctx.blobs.put_bytes(b"orphan text\n").unwrap();
        rig.orch.in_scope(&blob.id);
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
    fn line_of(rig: &Rig, blob: &ferret_core::BlobRef, needle: &str) -> u64 {
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
            ferret_core::log::SessionLog::create(&rig.shared.log_path, ferret_core::log::Durability::Batch).unwrap();
        let said: ferret_core::event::Event = serde_json::from_value(json!({
            "kind": "model_response", "req_id": "r1", "text": quote, "reasoning": "", "finish": "stop"
        }))
        .unwrap();
        log.append(ferret_core::event::Author::Model, said).unwrap();
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
            assert!(t.contains("run: bash call in s-test"), "{tool}: {t}");
        }
        let state = rig.shared.ledger().unwrap();
        assert_eq!(state.evidence.len(), 2);
        for e in &state.evidence {
            assert_eq!(e.input.kind, ferret_core::ledger::EvidenceKind::Execution);
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
        assert!(quote.chars().count() <= ferret_core::observe::QUOTE_RECORD_CHARS, "{quote}");
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
                &ferret_core::ids::SessionId::from("s-lead"),
                false,
                LedgerOp::ClaimAdd { text: "the lead's claim".into(), assets: Vec::new() },
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
        assert_eq!(state.claims[0].status, ferret_core::ledger::ClaimStatus::Open);
        assert_eq!(state.claims[1].status, ferret_core::ledger::ClaimStatus::Supported);
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
            LedgerOp::ClaimAdd { text: "my finding".into(), assets: Vec::new() },
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

    #[tokio::test]
    async fn plan_accepts_todowrite_objects_and_step_updates_when_text_also_passed() {
        let rig = rig("lead", false, true);
        let t = ok(
            &rig,
            "plan",
            json!({
                "steps": [
                    "plain first step",
                    {"step": "  second via step key  "},
                    {"text": "third via text key"},
                    {"content": "fourth via content key", "status": "todo"}
                ]
            }),
        )
        .await;
        assert!(t.contains("[ ] p1 plain first step"), "{t}");
        assert!(t.contains("[ ] p2 second via step key"), "{t}");
        assert!(t.contains("[ ] p3 third via text key"), "{t}");
        assert!(t.contains("[ ] p4 fourth via content key"), "{t}");

        let bad = refused(&rig, "plan", json!({"steps": ["ok", {"step": "   ", "text": ""}, 42]})).await;
        assert!(bad.contains("Step 2 of the plan is empty"), "{bad}");

        // Providing id, status, and text together updates id (using note if provided, keeping original step text).
        let upd = ok(
            &rig,
            "step",
            json!({"id": "p1", "status": "done", "text": "ignored replacement", "note": "finished step 1"}),
        )
        .await;
        assert!(upd.contains("step p1 done"), "{upd}");
        assert!(upd.contains("[x] p1 plain first step — finished step 1"), "{upd}");
        assert!(!upd.contains("ignored replacement"), "{upd}");
    }

    #[tokio::test]
    async fn claim_can_attach_evidence_and_set_status_atomically() {
        let rig = rig("lead", false, true);
        let h_run = rig.output("compiling...\n3 tests passed\n", "bash", ToolClass::Exec);
        let h_edit = rig.output("--- a/x.rs\n+++ b/x.rs\n", "edit", ToolClass::Write);

        // Bad handle/quote leaves ZERO stray claims in the ledger and emits REFUSAL_QUOTE.
        let r_bad_quote = rig
            .call(
                "claim",
                json!({
                    "text": "should not leak",
                    "handle": h_run,
                    "quote": "missing text xyz",
                    "status": "supported"
                }),
            )
            .await;
        assert_eq!(r_bad_quote.status, ToolStatus::Error);
        assert_eq!(
            r_bad_quote.meta.get(ferret_core::event::META_REFUSAL),
            Some(&json!(ferret_core::event::REFUSAL_QUOTE))
        );
        assert!(rig.shared.ledger().unwrap().claims.is_empty());

        let r_bad_prod = rig
            .call(
                "claim",
                json!({
                    "text": "diff claim",
                    "handle": h_edit,
                    "quote": "+++ b/x.rs",
                    "status": "supported"
                }),
            )
            .await;
        assert_eq!(r_bad_prod.status, ToolStatus::Error);
        assert_eq!(
            r_bad_prod.meta.get(ferret_core::event::META_REFUSAL),
            Some(&json!(ferret_core::event::REFUSAL_QUOTE))
        );
        assert!(rig.shared.ledger().unwrap().claims.is_empty());

        // `status: "supported"` without `handle` leaves zero stray claims.
        let r_no_handle = refused(&rig, "claim", json!({"text": "no evidence", "status": "supported"})).await;
        assert!(r_no_handle.contains("requires `handle`"), "{r_no_handle}");
        assert!(rig.shared.ledger().unwrap().claims.is_empty());

        // Valid handle + quote + status: "supported" (even omitting `note` and line numbers) succeeds atomically.
        let t1 = ok(
            &rig,
            "claim",
            json!({
                "text": "the test suite passes",
                "handle": h_run,
                "quote": "3 tests passed",
                "status": "supported"
            }),
        )
        .await;
        assert!(t1.contains("claim c1 supported"), "{t1}");
        assert!(t1.contains("e1 (supports; run: bash call in"), "{t1}");
        assert!(t1.contains("Established: c1."), "{t1}");

        // Valid handle + by-lines without status attaches evidence and leaves the claim open.
        let t2 = ok(
            &rig,
            "claim",
            json!({
                "text": "build started cleanly",
                "handle": h_run,
                "start": 1,
                "end": 1,
                "note": "compiler output line"
            }),
        )
        .await;
        assert!(t2.contains("claim c2 open"), "{t2}");
        assert!(t2.contains("e2 (supports; run: bash call in"), "{t2}");
        assert!(t2.contains("still open"), "{t2}");
        assert!(t2.contains("Recorded from"), "{t2}");

        let state = rig.shared.ledger().unwrap();
        assert_eq!(state.claims.len(), 2);
        assert_eq!(state.claims[0].status, ferret_core::ledger::ClaimStatus::Supported);
        assert_eq!(state.claims[1].status, ferret_core::ledger::ClaimStatus::Open);
        assert_eq!(state.evidence.len(), 2);
        assert_eq!(state.evidence[0].input.claim, "c1");
        assert_eq!(state.evidence[0].input.lines, Some((2, 2)));
        assert_eq!(state.evidence[1].input.claim, "c2");
    }

    #[tokio::test]
    async fn evidence_accepts_omitted_line_numbers_for_unique_quotes() {
        let rig = rig("lead", false, true);
        ok(&rig, "claim", json!({"text": "finds unique and catches ambiguous or missing"})).await;
        let h = rig.output(
            "first line alpha\nrepeated match here\nsecond unique beta\nrepeated match here\n",
            "bash",
            ToolClass::Exec,
        );

        // Unique quote without start/end resolves automatically.
        let t = ok(
            &rig,
            "evidence",
            json!({"claim": "c1", "handle": h, "quote": "second unique beta", "note": "found uniquely"}),
        )
        .await;
        assert!(t.contains("e1 (supports; run: bash call"), "{t}");
        let state = rig.shared.ledger().unwrap();
        assert_eq!(state.evidence[0].input.lines, Some((3, 3)));

        // Ambiguous quote without start/end is refused with REFUSAL_QUOTE.
        let r_amb = rig
            .call("evidence", json!({"claim": "c1", "handle": h, "quote": "repeated match here", "note": "ambiguous"}))
            .await;
        assert_eq!(r_amb.status, ToolStatus::Error);
        assert_eq!(r_amb.meta.get(ferret_core::event::META_REFUSAL), Some(&json!(ferret_core::event::REFUSAL_QUOTE)));

        // Missing quote without start/end is refused with REFUSAL_QUOTE.
        let r_miss = rig
            .call("evidence", json!({"claim": "c1", "handle": h, "quote": "absent substring", "note": "missing"}))
            .await;
        assert_eq!(r_miss.status, ToolStatus::Error);
        assert_eq!(r_miss.meta.get(ferret_core::event::META_REFUSAL), Some(&json!(ferret_core::event::REFUSAL_QUOTE)));

        // Omitting both quote and line numbers is cleanly refused with REFUSAL_QUOTE.
        let r_empty = rig.call("evidence", json!({"claim": "c1", "handle": h, "note": "nothing quoted"})).await;
        assert_eq!(r_empty.status, ToolStatus::Error);
        assert_eq!(r_empty.meta.get(ferret_core::event::META_REFUSAL), Some(&json!(ferret_core::event::REFUSAL_QUOTE)));
        assert!(r_empty.text.contains("Give `quote`, or both `start` and `end` line numbers."), "{}", r_empty.text);
    }

    #[tokio::test]
    async fn an_ambiguous_quote_lists_every_place_and_start_picks_one() {
        let rig = rig("lead", false, true);
        ok(&rig, "claim", json!({"text": "c"})).await;
        let long = format!("repeated match here {}", "z".repeat(300));
        let h = rig.output(
            &format!("first line alpha\nrepeated match here\nsecond unique beta\nrepeated match here\n{long}\n"),
            "bash",
            ToolClass::Exec,
        );
        let t =
            refused(&rig, "evidence", json!({"claim": "c1", "handle": h, "quote": "repeated match here", "note": "n"}))
                .await;
        assert!(t.contains("occurs 3 times"), "{t}");
        assert!(t.contains("\nline 2: repeated match here\n"), "{t}");
        assert!(t.contains("\nline 4: repeated match here\n"), "{t}");
        let cut = format!("line 5: repeated match here {}…", "z".repeat(200 - "repeated match here ".len()));
        assert!(t.contains(&cut), "{t}");
        assert!(t.contains("Add `start` to say which."), "{t}");
        assert!(rig.shared.ledger().unwrap().evidence.is_empty());
        // `start` alone says which; no `end` needed.
        ok(
            &rig,
            "evidence",
            json!({"claim": "c1", "handle": h, "quote": "repeated match here", "start": 4, "note": "n"}),
        )
        .await;
        assert_eq!(rig.shared.ledger().unwrap().evidence[0].input.lines, Some((4, 4)));
    }

    #[tokio::test]
    async fn a_quote_matching_once_ignoring_spacing_is_taken_and_says_which_lines() {
        let rig = rig("lead", false, true);
        ok(&rig, "claim", json!({"text": "c"})).await;
        let h = rig.output(
            "header\n\n  test a ...   FAILED\n    left: 1,\n    right: 2\nfooter\n",
            "bash",
            ToolClass::Exec,
        );
        let t = ok(
            &rig,
            "evidence",
            json!({"claim": "c1", "handle": h, "quote": "test a ... FAILED left: 1, right: 2", "note": "n"}),
        )
        .await;
        assert!(t.contains("matched lines 3-5 ignoring spacing."), "{t}");
        let e = &rig.shared.ledger().unwrap().evidence[0].input;
        assert_eq!(e.lines, Some((3, 5)));
        assert_eq!(e.quote.as_deref(), Some("  test a ...   FAILED\n    left: 1,\n    right: 2"));
        // Ignoring spacing, two places is still ambiguous.
        let h2 = rig.output("alpha   beta gamma\nalpha beta   gamma\n", "bash", ToolClass::Exec);
        let t =
            refused(&rig, "evidence", json!({"claim": "c1", "handle": h2, "quote": "alpha beta gamma", "note": "n"}))
                .await;
        assert!(t.contains("line 1:") && t.contains("line 2:") && t.contains("Add `start`"), "{t}");
    }

    #[tokio::test]
    async fn a_quote_only_call_on_a_whole_bash_output_records_the_right_lines() {
        let rig = rig("lead", false, true);
        ok(&rig, "claim", json!({"text": "c"})).await;
        let h =
            rig.output("$ make test\ncompiling\nerror: boom at parse.rs:12\nmore\nFAILED\n", "bash", ToolClass::Exec);
        let t = ok(
            &rig,
            "evidence",
            json!({"claim": "c1", "handle": h, "quote": "error: boom at parse.rs:12\nmore", "note": "n"}),
        )
        .await;
        assert!(t.contains("run: bash call"), "{t}");
        let e = &rig.shared.ledger().unwrap().evidence[0].input;
        assert_eq!(e.lines, Some((3, 4)));
        assert_eq!(e.quote.as_deref(), Some("error: boom at parse.rs:12\nmore"));
        assert!(!t.contains("ignoring spacing"), "{t}");
    }

    #[test]
    fn evidence_and_claim_lead_with_quoting_by_text() {
        use ferret_tools::Tool as _;
        let rig = rig("lead", false, true);
        for spec in [super::Evidence(rig.shared.clone()).spec(), super::Claim(rig.shared.clone()).spec()] {
            assert!(spec.description.contains("line numbers are not needed"), "{}", spec.description);
            assert!(!spec.description.contains("out_read"), "{}", spec.description);
        }
    }
}
