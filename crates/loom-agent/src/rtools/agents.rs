//! Tools that start and steer other agents: `agent_spawn`, `agent_fanout`, `agent_message`,
//! `agent_stop`, `decide`, `verify`.
//!
//! CONTRACT (the `run` bodies are placeholders for the implementer; specs and types are fixed).
//!
//! Everything goes through `S.orch` (`S` = `self.0`, the `Shared`); every `Err(text)` from it is
//! returned as `ToolOutput::error(text)` unless stated otherwise. Nothing here panics.
//!
//! ## Assignments
//! [`assignment`] turns one JSON object into `(role, Brief)`:
//! - keys: `role`, `question`, `hypothesis`, `scope`, `do_not`, `return`, `stop_when`, `context`; any
//!   other key is an error naming it and listing these;
//! - every value must be a string (else an error naming the key and what was received);
//! - `question` is required and must contain non-whitespace;
//! - `role` defaults to the first entry of `S.role.may_spawn`. When `may_spawn` is empty: `This role
//!   cannot start agents.` When the role is not in `may_spawn`: ``This role can start: a, b. `x` is
//!   not one of them.``
//! - strings are kept exactly as given; an optional field that is empty or whitespace becomes `None`.
//!
//! Budgets: `max_steps` / `max_minutes` default to `S.agents.child_max_steps` / `child_max_minutes`
//! and are lowered to those values when larger (the result then carries the header fact `budget
//! lowered to {steps} steps / {minutes} min`).
//!
//! The title of a child is its question cut to 80 characters.
//!
//! ## `agent_spawn`
//! One assignment from the call's own arguments (the same keys, plus `mode`, `max_steps`,
//! `max_minutes`, `background`). `mode` `fork` → `SpawnMode::Fork`, else `Fresh`.
//! - `background: false` (default): spawn with `awaited: true`, then `join` with `ctx.cancel`.
//!   On join `Err` when `ctx.cancel.is_cancelled()`: `S.orch.stop_child` and error `Interrupted
//!   while waiting for agent {id}; it was stopped.` Result: body `Body::Raw(settlement.report)`,
//!   outcome `agent {id} {outcome}` (`returned`, `blocked`, `budget_exhausted`, `stopped`, `failed`),
//!   header facts `{role}` and `{steps} steps`; status `Ok` when the outcome is `Returned`, `Error`
//!   otherwise.
//! - `background: true`: spawn with `awaited: false`; ok, outcome `agent {id} started`, message
//!   `Agent {id} ({role}) is working. Its report will arrive as a harness message when it ends. Call
//!   `wait` when you have nothing else to do until then.`
//!
//! ## `agent_fanout`
//! `agents` is a list of 2 to `S.agents.max_children` assignment objects (fewer than 2: `Use
//! agent_spawn for a single assignment.`). Every element is checked with [`assignment`] before
//! anything is started; errors are reported together, each prefixed `agents[{i}]: ` (1-based).
//! With `running` = the number of running children: when `running + n > max_children` → `This would
//! make {running + n} agents running at once; the limit is {max}. Send at most {max - running} in one
//! call.`
//! All are spawned `awaited: true`, in order. If a spawn fails, the ones already started are stopped
//! and the error is returned with `No agent was left running.` appended. Then all are joined
//! concurrently. On cancellation: stop all, error `Interrupted while waiting for {n} agents; they
//! were stopped.` Result body (`Body::Raw`), for each agent in the order given:
//! `===== agent {i} of {n}: {id} ({role}) — {outcome}, {steps} steps =====`, the report, a blank line.
//! Outcome `{n} agents: {a} returned[, {b} blocked][, …]` (outcomes with a zero count omitted, in the
//! order returned, blocked, budget_exhausted, stopped, failed). Status `Ok` when at least one
//! returned, else `Error`.
//!
//! ## `agent_message`
//! `S.orch.message_child(&S.session, &agent, text)`; ok, outcome `sent`, message `Delivered to {agent}.`
//!
//! ## `agent_stop`
//! Exactly one of `agent` and `all: true` (else an error saying so). `agent` → `stop_child`; outcome
//! `stopped`, message `{agent} was stopped; anything it had not delivered is in its record but was
//! not reported.` `all` → `stop_children`; outcome `stopped`, message `All running agents were stopped.`
//!
//! ## `decide`
//! `options` must hold 2 to 6 non-empty strings. `S.orch.poll(&S.session, question, options, k,
//! &ctx.cancel)`. Result (ok, `Body::Message`):
//! `{k} independent votes on: {question}`, then per option `{i}. {option} — {count}`, then `no valid
//! choice — {count}` when non-zero, then `Reasons:` and one line per vote `- [{i}] {reason cut to 300
//! characters}` (`[-]` for a vote without a valid option), then the line `This is advice from copies
//! of you with the same information, not new evidence. Record what you decide with `note`.`
//! Outcome `option {i} leads ({count} of {k})`, or `split` when the highest count is shared.
//!
//! ## `verify`
//! Exactly one of `claim` (a ledger claim id) and `statement` (else an error saying so).
//! `verifier` must be in `S.role.may_spawn` (else `This role cannot start a verifier.`).
//! With `claim`: read `S.ledger()`; an unknown id is an error listing the claim ids. The brief:
//! - `question`: `Try to refute this claim: {text}`
//! - `context` (claim form only): `Evidence recorded for it:` and per evidence record of the claim
//!   `- {id} ({supports|undermines}) {handle} lines {a}-{b}: {quote cut to 300 characters} — {note}`;
//!   `No evidence is recorded for it.` when there is none. With `handles` given (either form), a
//!   further paragraph `Outputs to examine: {handles joined by ", "}`.
//! - `returns`: `A verdict, delivered by calling verdict.`
//!
//! Spawn role `verifier`, `Fresh`, default budget, `awaited: true`; join as in `agent_spawn`.
//! Result body `Body::Raw(report)`; outcome `verdict: accepted` / `verdict: not accepted` from
//! `payload.accepted`, or `no verdict ({outcome})` when the payload has none (status `Error`).
//! When the claim form was used, a last line is appended to the body: `The verdict is not recorded
//! on {id}; set the claim's status yourself with `claim_update`.`
//!
//! Tests required (fake `Orchestrator` recording every call and scripted per call; calls made
//! through `loom_tools::execute`): `assignment` — every rule; `agent_spawn` — awaited result for
//! each outcome, background start, budget lowering, role refusals, cancellation stops the child;
//! `agent_fanout` — element errors collected, limit refusal, spawn failure stops the started ones,
//! ordering of the combined report, outcome line, cancellation; `agent_message`; `agent_stop` both
//! forms and the refusal; `decide` — tally, split, invalid votes, option count refusals; `verify` —
//! both forms, unknown claim, evidence listing, verdict outcomes, missing payload.

use super::{Settlement, Shared, SpawnReq};
use async_trait::async_trait;
use loom_core::event::{Brief, Budget, ChildOutcome, SpawnMode, ToolClass, ToolSpec, ToolStatus};
use loom_core::SessionId;
use loom_tools::params::{opt, req, spec, Param};
use loom_tools::{Body, Tool, ToolCtx, ToolOutput};
use serde_json::{json, Map, Value};
use std::sync::Arc;

pub struct AgentSpawn(pub Arc<Shared>);
pub struct AgentFanout(pub Arc<Shared>);
pub struct AgentMessage(pub Arc<Shared>);
pub struct AgentStop(pub Arc<Shared>);
pub struct Decide(pub Arc<Shared>);
pub struct Verify(pub Arc<Shared>);

/// Read one assignment object. See the module contract.
pub fn assignment(shared: &Shared, object: &Map<String, Value>) -> Result<(String, Brief), String> {
    const KEYS: [&str; 8] = ["role", "question", "hypothesis", "scope", "do_not", "return", "stop_when", "context"];
    if let Some(key) = object.keys().find(|k| !KEYS.contains(&k.as_str())) {
        return Err(format!("`{key}` is not a field of an assignment. The fields are: {}.", KEYS.join(", ")));
    }
    let mut strings: Map<String, Value> = Map::new();
    for (key, value) in object {
        match value {
            Value::String(_) => {
                strings.insert(key.clone(), value.clone());
            }
            other => {
                return Err(format!("`{key}` must be a string; received {}. Give it as text.", describe(other)));
            }
        }
    }
    let text = |key: &str| strings.get(key).and_then(Value::as_str).map(str::to_string);
    let optional = |key: &str| text(key).filter(|t| !t.trim().is_empty());
    let question = match text("question") {
        Some(q) if !q.trim().is_empty() => q,
        _ => return Err("`question` is required and must say what the agent has to find out or do.".into()),
    };
    let may = &shared.role.may_spawn;
    if may.is_empty() {
        return Err("This role cannot start agents.".into());
    }
    let role = match optional("role") {
        None => may.first().cloned().unwrap_or_default(),
        Some(r) if may.contains(&r) => r,
        Some(r) => return Err(format!("This role can start: {}. `{r}` is not one of them.", may.join(", "))),
    };
    let brief = Brief {
        question,
        hypothesis: optional("hypothesis"),
        scope: optional("scope"),
        do_not: optional("do_not"),
        returns: optional("return"),
        stop_when: optional("stop_when"),
        context: optional("context"),
    };
    Ok((role, brief))
}

fn describe(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

fn cut(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

fn outcome_word(o: ChildOutcome) -> &'static str {
    match o {
        ChildOutcome::Returned => "returned",
        ChildOutcome::Blocked => "blocked",
        ChildOutcome::BudgetExhausted => "budget_exhausted",
        ChildOutcome::Stopped => "stopped",
        ChildOutcome::Failed => "failed",
    }
}

/// The budget for a spawn: the call's numbers, lowered to the configured ceiling. The second value
/// is the header fact to show when something was lowered.
fn budget_for(shared: &Shared, args: &Map<String, Value>) -> (Budget, Option<String>) {
    let number = |key: &str| args.get(key).and_then(Value::as_u64).and_then(|n| u32::try_from(n).ok());
    let (max_steps, max_minutes) = (shared.agents.child_max_steps, shared.agents.child_max_minutes);
    let steps = number("max_steps").unwrap_or(max_steps);
    let minutes = number("max_minutes").unwrap_or(max_minutes);
    let lowered = steps > max_steps || minutes > max_minutes;
    let budget = Budget { max_steps: Some(steps.min(max_steps)), max_minutes: Some(minutes.min(max_minutes)) };
    let fact = lowered.then(|| format!("budget lowered to {max_steps} steps / {max_minutes} min"));
    (budget, fact)
}

fn request(ctx: &ToolCtx, role: String, mode: SpawnMode, brief: Brief, budget: Budget, awaited: bool) -> SpawnReq {
    let title = cut(&brief.question, 80);
    SpawnReq { role, mode, brief, budget, call_id: ctx.call_id.clone(), title, awaited }
}

fn str_arg<'a>(args: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Value::as_str)
}

/// Join one awaited child; a cancellation stops it and becomes the call's error.
async fn join_one(shared: &Shared, ctx: &ToolCtx, id: &SessionId) -> Result<Settlement, ToolOutput> {
    match shared.orch.join(&shared.session, id, &ctx.cancel).await {
        Ok(settlement) => Ok(settlement),
        Err(text) => {
            if ctx.cancel.is_cancelled() {
                let _ = shared.orch.stop_child(&shared.session, id).await;
                Err(ToolOutput::error(format!("Interrupted while waiting for agent {id}; it was stopped.")))
            } else {
                Err(ToolOutput::error(text))
            }
        }
    }
}

/// The arguments that describe one assignment, shared by `agent_spawn` and (as the item schema) by
/// `agent_fanout`.
fn assignment_params() -> Vec<Param> {
    vec![
        req("question", "string", "One sentence: what the agent must find out or do."),
        opt("role", "string", "The agent's role. Defaults to the first role you may start."),
        opt("hypothesis", "string", "What you currently believe the answer is, if anything."),
        opt("scope", "string", "The files, commands or systems the agent should work with, and why they matter."),
        opt("do_not", "string", "What the agent must leave alone: neighbouring work, things already settled."),
        opt("return", "string", "What the result must contain."),
        opt("stop_when", "string", "The condition under which the agent has done enough."),
        opt("context", "string", "Anything else the agent needs to know. A fresh agent starts with only this assignment."),
    ]
}

#[async_trait]
impl Tool for AgentSpawn {
    fn spec(&self) -> ToolSpec {
        let mut params = assignment_params();
        params.extend([
            opt("mode", "string", "fresh: the agent starts with only the assignment. fork: it starts with everything you have seen so far.")
                .one_of(&["fresh", "fork"])
                .default(json!("fresh")),
            opt("max_steps", "integer", "The most model steps the agent may take.").min(1),
            opt("max_minutes", "integer", "The longest the agent may run.").min(1),
            opt("background", "boolean", "true to keep working while the agent runs; its report then arrives later as a message.")
                .default(json!(false)),
        ]);
        spec(
            "agent_spawn",
            "Give one bounded assignment to another agent and get its report. The agent has its own context and the same workspace. Its report is text written by a model: it comes with quoted lines of stored output (handles you can open with out_read), and anything not quoted is unverified. By default the call returns when the agent has finished.",
            ToolClass::State,
            &params,
        )
    }
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let shared = &*self.0;
        let fields: Map<String, Value> = args
            .iter()
            .filter(|(k, _)| !matches!(k.as_str(), "mode" | "max_steps" | "max_minutes" | "background"))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let (role, brief) = match assignment(shared, &fields) {
            Ok(a) => a,
            Err(e) => return ToolOutput::error(e),
        };
        let mode = if str_arg(args, "mode") == Some("fork") { SpawnMode::Fork } else { SpawnMode::Fresh };
        let background = args.get("background").and_then(Value::as_bool).unwrap_or(false);
        let (budget, lowered) = budget_for(shared, args);
        let req = request(ctx, role.clone(), mode, brief, budget, !background);
        let id = match shared.orch.spawn(&shared.session, req).await {
            Ok(id) => id,
            Err(e) => return ToolOutput::error(e),
        };
        if background {
            let mut out = ToolOutput::ok(
                format!("agent {id} started"),
                Body::Message(format!(
                    "Agent {id} ({role}) is working. Its report will arrive as a harness message when it ends. Call `wait` when you have nothing else to do until then."
                )),
            );
            if let Some(fact) = lowered {
                out = out.with_more(fact);
            }
            return out;
        }
        let settlement = match join_one(shared, ctx, &id).await {
            Ok(s) => s,
            Err(out) => return out,
        };
        let mut out = ToolOutput::ok(
            format!("agent {id} {}", outcome_word(settlement.outcome)),
            Body::Raw(settlement.report.clone().into_bytes()),
        )
        .with_more(settlement.role.clone())
        .with_more(format!("{} steps", settlement.steps));
        if let Some(fact) = lowered {
            out = out.with_more(fact);
        }
        if settlement.outcome != ChildOutcome::Returned {
            out.status = ToolStatus::Error;
        }
        out
    }
}

#[async_trait]
impl Tool for AgentFanout {
    fn spec(&self) -> ToolSpec {
        let items = loom_tools::params::object(&assignment_params());
        spec(
            "agent_fanout",
            "Give several independent assignments to agents that work at the same time, and get all their reports in one result. Use it when the pieces do not depend on each other. Each element of `agents` is one assignment with the same fields as agent_spawn.",
            ToolClass::State,
            &[
                req("agents", "array", "The assignments, one object each.").with("items", items),
                opt("max_steps", "integer", "The most model steps each agent may take.").min(1),
                opt("max_minutes", "integer", "The longest each agent may run.").min(1),
            ],
        )
    }
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let shared = &*self.0;
        let Some(items) = args.get("agents").and_then(Value::as_array) else {
            return ToolOutput::error("`agents` must be a list of assignment objects.");
        };
        if items.len() < 2 {
            return ToolOutput::error("Use agent_spawn for a single assignment.");
        }
        let mut parsed = Vec::new();
        let mut errors = Vec::new();
        for (i, item) in items.iter().enumerate() {
            let number = i.saturating_add(1);
            let result = match item.as_object() {
                Some(object) => assignment(shared, object),
                None => Err(format!("must be an assignment object; received {}.", describe(item))),
            };
            match result {
                Ok(a) => parsed.push(a),
                Err(e) => errors.push(format!("agents[{number}]: {e}")),
            }
        }
        if !errors.is_empty() {
            return ToolOutput::error(errors.join("\n"));
        }
        let n = parsed.len();
        let max = usize::try_from(shared.agents.max_children).unwrap_or(usize::MAX);
        let running = shared.orch.children(&shared.session).await.iter().filter(|c| c.running).count();
        if running.saturating_add(n) > max {
            return ToolOutput::error(format!(
                "This would make {} agents running at once; the limit is {max}. Send at most {} in one call.",
                running.saturating_add(n),
                max.saturating_sub(running)
            ));
        }
        let (budget, lowered) = budget_for(shared, args);
        let mut started: Vec<SessionId> = Vec::new();
        for (role, brief) in parsed {
            let req = request(ctx, role, SpawnMode::Fresh, brief, budget.clone(), true);
            match shared.orch.spawn(&shared.session, req).await {
                Ok(id) => started.push(id),
                Err(e) => {
                    for id in &started {
                        let _ = shared.orch.stop_child(&shared.session, id).await;
                    }
                    return ToolOutput::error(format!("{e} No agent was left running."));
                }
            }
        }
        let joins = started.iter().map(|id| shared.orch.join(&shared.session, id, &ctx.cancel));
        let results = futures_util::future::join_all(joins).await;
        if ctx.cancel.is_cancelled() && results.iter().any(Result::is_err) {
            for id in &started {
                let _ = shared.orch.stop_child(&shared.session, id).await;
            }
            return ToolOutput::error(format!("Interrupted while waiting for {n} agents; they were stopped."));
        }
        let mut body = String::new();
        let mut counts = [0usize; 5];
        let order = [
            ChildOutcome::Returned,
            ChildOutcome::Blocked,
            ChildOutcome::BudgetExhausted,
            ChildOutcome::Stopped,
            ChildOutcome::Failed,
        ];
        for (i, (id, result)) in started.iter().zip(results).enumerate() {
            let (role, outcome, steps, report) = match result {
                Ok(s) => (s.role, s.outcome, s.steps, s.report),
                Err(text) => (String::from("unknown"), ChildOutcome::Failed, 0, text),
            };
            if let Some(slot) = order.iter().position(|o| *o == outcome).and_then(|p| counts.get_mut(p)) {
                *slot += 1;
            }
            body.push_str(&format!(
                "===== agent {} of {n}: {id} ({role}) \u{2014} {}, {steps} steps =====\n{report}\n\n",
                i.saturating_add(1),
                outcome_word(outcome)
            ));
        }
        let parts: Vec<String> = order
            .iter()
            .zip(counts)
            .filter(|(_, c)| *c > 0)
            .map(|(o, c)| format!("{c} {}", outcome_word(*o)))
            .collect();
        let mut out = ToolOutput::ok(format!("{n} agents: {}", parts.join(", ")), Body::Raw(body.into_bytes()));
        if let Some(fact) = lowered {
            out = out.with_more(fact);
        }
        if counts.first().copied().unwrap_or(0) == 0 {
            out.status = ToolStatus::Error;
        }
        out
    }
}

#[async_trait]
impl Tool for AgentMessage {
    fn spec(&self) -> ToolSpec {
        spec(
            "agent_message",
            "Send a message to an agent you started with background: true, for example to correct its course or add information. It reads the message at its next step.",
            ToolClass::State,
            &[req("agent", "string", "The agent's id (s-…)."), req("text", "string", "The message.")],
        )
    }
    async fn run(&self, _ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let shared = &*self.0;
        let (Some(agent), Some(text)) = (str_arg(args, "agent"), str_arg(args, "text")) else {
            return ToolOutput::error("Give `agent` (the agent's id) and `text` (the message), both as strings.");
        };
        match shared.orch.message_child(&shared.session, &SessionId::from(agent), text).await {
            Ok(()) => ToolOutput::ok("sent", Body::Message(format!("Delivered to {agent}."))),
            Err(e) => ToolOutput::error(e),
        }
    }
}

#[async_trait]
impl Tool for AgentStop {
    fn spec(&self) -> ToolSpec {
        spec(
            "agent_stop",
            "Stop an agent you started, or all of them. A stopped agent delivers no report.",
            ToolClass::State,
            &[
                opt("agent", "string", "The agent's id (s-…)."),
                opt("all", "boolean", "true to stop every agent you started.").default(json!(false)),
            ],
        )
    }
    async fn run(&self, _ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let shared = &*self.0;
        let agent = str_arg(args, "agent").filter(|a| !a.trim().is_empty());
        let all = args.get("all").and_then(Value::as_bool).unwrap_or(false);
        match (agent, all) {
            (Some(agent), false) => match shared.orch.stop_child(&shared.session, &SessionId::from(agent)).await {
                Ok(()) => ToolOutput::ok(
                    "stopped",
                    Body::Message(format!(
                        "{agent} was stopped; anything it had not delivered is in its record but was not reported."
                    )),
                ),
                Err(e) => ToolOutput::error(e),
            },
            (None, true) => {
                shared.orch.stop_children(&shared.session).await;
                ToolOutput::ok("stopped", Body::Message("All running agents were stopped.".into()))
            }
            _ => ToolOutput::error("Give exactly one of `agent` (an agent's id) and `all: true`."),
        }
    }
}

#[async_trait]
impl Tool for Decide {
    fn spec(&self) -> ToolSpec {
        spec(
            "decide",
            "Get independent second opinions on a choice between named options. Several copies of you, each with everything you have seen so far, choose separately and give a reason; you get the tally. Use it when a decision is close and being wrong is costly. It is advice, not evidence.",
            ToolClass::State,
            &[
                req("question", "string", "The decision to make."),
                req("options", "array", "Two to six options to choose between.").items("string"),
                opt("k", "integer", "How many independent votes.").min(3).max(9).default(json!(5)),
            ],
        )
    }
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let shared = &*self.0;
        let Some(question) = str_arg(args, "question").filter(|q| !q.trim().is_empty()) else {
            return ToolOutput::error("`question` is required: state the decision to make.");
        };
        let options: Option<Vec<String>> = args.get("options").and_then(Value::as_array).and_then(|list| {
            list.iter().map(|v| v.as_str().filter(|t| !t.trim().is_empty()).map(str::to_string)).collect()
        });
        let Some(options) = options.filter(|o| (2..=6).contains(&o.len())) else {
            return ToolOutput::error("`options` must be 2 to 6 non-empty strings. Name the choices you are weighing.");
        };
        let k = args.get("k").and_then(Value::as_u64).and_then(|n| u32::try_from(n).ok()).unwrap_or(5);
        let votes = match shared.orch.poll(&shared.session, question, &options, k, &ctx.cancel).await {
            Ok(v) => v,
            Err(e) => return ToolOutput::error(e),
        };
        if votes.is_empty() {
            return ToolOutput::error("No votes came back. Decide yourself, or call decide again.");
        }
        let total = votes.len();
        let mut counts = vec![0usize; options.len()];
        let mut invalid = 0usize;
        for vote in &votes {
            match vote.option.and_then(|i| i.checked_sub(1)).and_then(|i| counts.get_mut(i)) {
                Some(c) => *c += 1,
                None => invalid += 1,
            }
        }
        let mut text = format!("{total} independent votes on: {question}\n");
        for (i, (option, count)) in options.iter().zip(&counts).enumerate() {
            text.push_str(&format!("{}. {option} \u{2014} {count}\n", i.saturating_add(1)));
        }
        if invalid > 0 {
            text.push_str(&format!("no valid choice \u{2014} {invalid}\n"));
        }
        text.push_str("Reasons:\n");
        for vote in &votes {
            let label = match vote.option.filter(|i| (1..=options.len()).contains(i)) {
                Some(i) => i.to_string(),
                None => "-".to_string(),
            };
            text.push_str(&format!("- [{label}] {}\n", cut(&vote.reason, 300)));
        }
        text.push_str("This is advice from copies of you with the same information, not new evidence. Record what you decide with `note`.");
        let best = counts.iter().copied().max().unwrap_or(0);
        let leaders: Vec<usize> = counts.iter().enumerate().filter(|(_, c)| **c == best).map(|(i, _)| i).collect();
        let outcome = match (best, leaders.as_slice()) {
            (0, _) => "no valid votes".to_string(),
            (_, [only]) => format!("option {} leads ({best} of {total})", only.saturating_add(1)),
            _ => "split".to_string(),
        };
        ToolOutput::ok(outcome, Body::Message(text))
    }
}

#[async_trait]
impl Tool for Verify {
    fn spec(&self) -> ToolSpec {
        spec(
            "verify",
            "Have a claim independently attacked before you rely on it. A verifier that has not seen your work and cannot change the workspace tries to refute the claim and returns a verdict with its objections. Give `claim` (the id of a ledger claim, whose attached evidence is passed along) or `statement` (the claim as text).",
            ToolClass::State,
            &[
                opt("claim", "string", "The id of a ledger claim, for example c1."),
                opt("statement", "string", "The claim as text, when it is not in the ledger."),
                opt("handles", "array", "Stored outputs (out:…) the verifier should examine.").items("string"),
            ],
        )
    }
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let shared = &*self.0;
        let claim_id = str_arg(args, "claim").filter(|c| !c.trim().is_empty());
        let statement = str_arg(args, "statement").filter(|c| !c.trim().is_empty());
        if claim_id.is_some() == statement.is_some() {
            return ToolOutput::error("Give exactly one of `claim` (a ledger claim id) and `statement` (the claim as text).");
        }
        if !shared.role.may_spawn.iter().any(|r| r == "verifier") {
            return ToolOutput::error("This role cannot start a verifier.");
        }
        let handles: Vec<String> = args
            .get("handles")
            .and_then(Value::as_array)
            .map(|l| l.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        let (text, mut context) = match (claim_id, statement) {
            (Some(id), _) => {
                let state = match shared.ledger() {
                    Ok(s) => s,
                    Err(e) => return ToolOutput::error(e),
                };
                let Some(claim) = state.claims.iter().find(|c| c.id == id) else {
                    let ids: Vec<&str> = state.claims.iter().map(|c| c.id.as_str()).collect();
                    let known = if ids.is_empty() {
                        "There are no claims yet.".to_string()
                    } else {
                        format!("The claims are: {}.", ids.join(", "))
                    };
                    return ToolOutput::error(format!("There is no claim `{id}`. {known}"));
                };
                let lines: Vec<String> = claim
                    .evidence
                    .iter()
                    .filter_map(|eid| state.evidence.iter().find(|e| &e.id == eid))
                    .map(|e| {
                        let i = &e.input;
                        let side = if i.supports { "supports" } else { "undermines" };
                        let handle = i
                            .blob
                            .as_ref()
                            .map(|b| format!("out:{}", cut(&b.0, 16)))
                            .unwrap_or_else(|| "no stored output".into());
                        let range = i.lines.map(|(a, b)| format!(" lines {a}-{b}")).unwrap_or_default();
                        let quote = cut(i.quote.as_deref().unwrap_or(""), 300);
                        format!("- {} ({side}) {handle}{range}: {quote} \u{2014} {}", e.id, i.note)
                    })
                    .collect();
                let context = if lines.is_empty() {
                    "No evidence is recorded for it.".to_string()
                } else {
                    format!("Evidence recorded for it:\n{}", lines.join("\n"))
                };
                (claim.text.clone(), Some(context))
            }
            (None, statement) => (statement.unwrap_or_default().to_string(), None),
        };
        if !handles.is_empty() {
            let examine = format!("Outputs to examine: {}", handles.join(", "));
            context = Some(match context {
                Some(c) => format!("{c}\n\n{examine}"),
                None => examine,
            });
        }
        let brief = Brief {
            question: format!("Try to refute this claim: {text}"),
            context,
            returns: Some("A verdict, delivered by calling verdict.".into()),
            ..Brief::default()
        };
        let budget =
            Budget { max_steps: Some(shared.agents.child_max_steps), max_minutes: Some(shared.agents.child_max_minutes) };
        let req = request(ctx, "verifier".into(), SpawnMode::Fresh, brief, budget, true);
        let id = match shared.orch.spawn(&shared.session, req).await {
            Ok(id) => id,
            Err(e) => return ToolOutput::error(e),
        };
        let settlement = match join_one(shared, ctx, &id).await {
            Ok(s) => s,
            Err(out) => return out,
        };
        let mut report = settlement.report.clone();
        if let Some(id) = claim_id {
            report.push_str(&format!(
                "\n\nThe verdict is not recorded on {id}; set the claim's status yourself with `claim_update`."
            ));
        }
        let mut out = match settlement.payload.get("accepted").and_then(Value::as_bool) {
            Some(a) => ToolOutput::ok(
                if a { "verdict: accepted" } else { "verdict: not accepted" },
                Body::Raw(report.into_bytes()),
            ),
            None => {
                let mut o = ToolOutput::ok(
                    format!("no verdict ({})", outcome_word(settlement.outcome)),
                    Body::Raw(report.into_bytes()),
                );
                o.status = ToolStatus::Error;
                o
            }
        };
        out = out.with_more(settlement.role).with_more(format!("{} steps", settlement.steps));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::super::testkit::{core_role, rig, rig_with, Rig};
    use super::super::Vote;
    use super::*;
    use loom_core::config::AgentsCfg;
    use loom_core::ledger::{EvidenceInput, EvidenceKind, LedgerOp};
    use loom_core::{BlobId, CallId};
    use std::time::Duration;

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().cloned().unwrap_or_default()
    }

    fn lead() -> Rig {
        rig("lead", false, true)
    }

    fn spawned(rig: &Rig) -> Vec<SpawnReq> {
        rig.orch.spawned.lock().unwrap().iter().map(|(_, r)| r.clone()).collect()
    }

    async fn cancel_soon(rig: &Rig) {
        let token = rig.env.ctx.cancel.clone();
        tokio::time::sleep(Duration::from_millis(50)).await;
        token.cancel();
    }

    // ---- assignment ----

    #[test]
    fn assignment_reads_all_fields_and_keeps_text() {
        let r = lead();
        let (role, brief) = assignment(
            &r.shared,
            &obj(json!({"role":"verifier","question":"  Why?  ","hypothesis":"h","scope":"s","do_not":"d","return":"r","stop_when":"w","context":"c"})),
        )
        .unwrap();
        assert_eq!(role, "verifier");
        assert_eq!(brief.question, "  Why?  ");
        assert_eq!(brief.returns.as_deref(), Some("r"));
        assert_eq!(brief.stop_when.as_deref(), Some("w"));
        assert_eq!(brief.context.as_deref(), Some("c"));
        assert_eq!(brief.hypothesis.as_deref(), Some("h"));
        assert_eq!(brief.scope.as_deref(), Some("s"));
        assert_eq!(brief.do_not.as_deref(), Some("d"));
    }

    #[test]
    fn assignment_defaults_role_and_blanks_become_none() {
        let r = lead();
        let (role, brief) = assignment(&r.shared, &obj(json!({"question":"q","scope":"  ","context":""}))).unwrap();
        assert_eq!(role, "worker");
        assert_eq!(brief.scope, None);
        assert_eq!(brief.context, None);
    }

    #[test]
    fn assignment_rejects_bad_input() {
        let r = lead();
        let e = assignment(&r.shared, &obj(json!({"question":"q","bogus":"x"}))).unwrap_err();
        assert!(e.contains("`bogus`") && e.contains("question") && e.contains("stop_when"), "{e}");
        let e = assignment(&r.shared, &obj(json!({"question":"q","scope":3}))).unwrap_err();
        assert!(e.contains("`scope`") && e.contains("number"), "{e}");
        let e = assignment(&r.shared, &obj(json!({"scope":"x"}))).unwrap_err();
        assert!(e.contains("`question` is required"), "{e}");
        let e = assignment(&r.shared, &obj(json!({"question":" \n "}))).unwrap_err();
        assert!(e.contains("`question` is required"), "{e}");
        let e = assignment(&r.shared, &obj(json!({"question":"q","role":"lead"}))).unwrap_err();
        assert_eq!(e, "This role can start: worker, verifier. `lead` is not one of them.");
    }

    #[test]
    fn assignment_refuses_when_role_starts_nobody() {
        let r = rig("worker", true, true);
        let e = assignment(&r.shared, &obj(json!({"question":"q"}))).unwrap_err();
        assert_eq!(e, "This role cannot start agents.");
    }

    // ---- agent_spawn ----

    #[tokio::test]
    async fn spawn_awaited_for_each_outcome() {
        let cases = [
            (ChildOutcome::Returned, "returned", ToolStatus::Ok),
            (ChildOutcome::Blocked, "blocked", ToolStatus::Error),
            (ChildOutcome::BudgetExhausted, "budget_exhausted", ToolStatus::Error),
            (ChildOutcome::Stopped, "stopped", ToolStatus::Error),
            (ChildOutcome::Failed, "failed", ToolStatus::Error),
        ];
        for (outcome, word, status) in cases {
            let r = lead();
            r.orch.settle("s-kid1", outcome, "the report", Value::Null);
            let res = r.call("agent_spawn", json!({"question":"Find it"})).await;
            assert_eq!(res.status, status, "{word}");
            assert!(res.text.contains(&format!("agent s-kid1 {word}")), "{}", res.text);
            assert!(res.text.contains("worker") && res.text.contains("7 steps"), "{}", res.text);
            assert!(res.text.contains("the report"), "{}", res.text);
            let sp = spawned(&r);
            assert!(sp[0].awaited);
            assert_eq!(sp[0].mode, SpawnMode::Fresh);
            assert_eq!(sp[0].title, "Find it");
            assert_eq!(r.orch.calls(), vec!["spawn worker".to_string(), "join s-kid1".to_string()]);
        }
    }

    #[tokio::test]
    async fn spawn_fork_and_title_cut() {
        let r = lead();
        let q = "é".repeat(100);
        r.call("agent_spawn", json!({"question":q,"mode":"fork"})).await;
        let sp = spawned(&r);
        assert_eq!(sp[0].mode, SpawnMode::Fork);
        assert_eq!(sp[0].title.chars().count(), 80);
    }

    #[tokio::test]
    async fn spawn_background_starts_without_join() {
        let r = lead();
        let res = r.call("agent_spawn", json!({"question":"q","background":true})).await;
        assert_eq!(res.status, ToolStatus::Ok);
        assert!(res.text.contains("agent s-kid1 started"), "{}", res.text);
        assert!(res.text.contains("Agent s-kid1 (worker) is working. Its report will arrive as a harness message when it ends."), "{}", res.text);
        assert!(!spawned(&r)[0].awaited);
        assert_eq!(r.orch.calls(), vec!["spawn worker".to_string()]);
    }

    #[tokio::test]
    async fn spawn_budget_default_and_lowering() {
        let r = lead();
        let cfg = AgentsCfg::default();
        let res = r.call("agent_spawn", json!({"question":"q"})).await;
        assert!(!res.text.contains("budget lowered"));
        assert_eq!(spawned(&r)[0].budget, Budget { max_steps: Some(cfg.child_max_steps), max_minutes: Some(cfg.child_max_minutes) });

        let res = r.call("agent_spawn", json!({"question":"q","max_steps":1,"max_minutes":1})).await;
        assert!(!res.text.contains("budget lowered"));
        assert_eq!(spawned(&r)[1].budget, Budget { max_steps: Some(1), max_minutes: Some(1) });

        let res = r.call("agent_spawn", json!({"question":"q","max_steps":cfg.child_max_steps + 50})).await;
        let fact = format!("budget lowered to {} steps / {} min", cfg.child_max_steps, cfg.child_max_minutes);
        assert!(res.text.contains(&fact), "{}", res.text);
        assert_eq!(spawned(&r)[2].budget.max_steps, Some(cfg.child_max_steps));
    }

    #[tokio::test]
    async fn spawn_role_refusals() {
        let r = rig("worker", true, true);
        // The worker has no agent tools in its registry, so call the tool directly.
        let tool = AgentSpawn(r.shared.clone());
        let out = tool.run(&r.env.ctx, &obj(json!({"question":"q"}))).await;
        assert_eq!(out.status, ToolStatus::Error);
        assert_eq!(out.body, Body::Message("This role cannot start agents.".into()));
        assert!(r.orch.calls().is_empty());

        let r = lead();
        let res = r.call("agent_spawn", json!({"question":"q","role":"chat"})).await;
        assert_eq!(res.status, ToolStatus::Error);
        assert!(res.text.contains("This role can start: worker, verifier. `chat` is not one of them."), "{}", res.text);
        assert!(r.orch.calls().is_empty());
    }

    #[tokio::test]
    async fn spawn_refused_by_orchestrator() {
        let r = lead();
        r.orch.spawn_script.lock().unwrap().push_back(Err("Too many agents are running.".into()));
        let res = r.call("agent_spawn", json!({"question":"q"})).await;
        assert_eq!(res.status, ToolStatus::Error);
        assert!(res.text.contains("Too many agents are running."));
    }

    #[tokio::test]
    async fn spawn_cancellation_stops_child() {
        let r = lead();
        *r.orch.hang_all.lock().unwrap() = true;
        let (res, ()) = tokio::join!(r.call("agent_spawn", json!({"question":"q"})), cancel_soon(&r));
        assert_eq!(res.status, ToolStatus::Error);
        assert!(res.text.contains("Interrupted while waiting for agent s-kid1; it was stopped."), "{}", res.text);
        assert_eq!(r.orch.calls(), vec!["spawn worker", "join s-kid1", "stop s-kid1"]);
    }

    // ---- agent_fanout ----

    fn two() -> Value {
        json!([{"question":"first"},{"question":"second","role":"verifier"}])
    }

    #[tokio::test]
    async fn fanout_needs_two() {
        let r = lead();
        let res = r.call("agent_fanout", json!({"agents":[{"question":"a"}]})).await;
        assert_eq!(res.status, ToolStatus::Error);
        assert!(res.text.contains("Use agent_spawn for a single assignment."), "{}", res.text);
        assert!(r.orch.calls().is_empty());
    }

    #[tokio::test]
    async fn fanout_collects_element_errors_before_starting() {
        let r = lead();
        let res = r
            .call("agent_fanout", json!({"agents":[{"question":"ok"},{"scope":"x"},{"question":"q","zzz":"1"},{"question":"q","role":"nope"}]}))
            .await;
        assert_eq!(res.status, ToolStatus::Error);
        assert!(res.text.contains("agents[2]: `question` is required"), "{}", res.text);
        assert!(res.text.contains("agents[3]: `zzz`"), "{}", res.text);
        assert!(res.text.contains("agents[4]: This role can start"), "{}", res.text);
        assert!(!res.text.contains("agents[1]"), "{}", res.text);
        assert!(r.orch.calls().is_empty());
    }

    #[tokio::test]
    async fn fanout_limit_counts_running_children() {
        let r = lead();
        let max = AgentsCfg::default().max_children;
        for i in 0..max.saturating_sub(1) {
            r.orch.running_child(&format!("s-run{i}"), "worker");
        }
        let res = r.call("agent_fanout", json!({"agents":two()})).await;
        assert_eq!(res.status, ToolStatus::Error);
        assert!(
            res.text.contains(&format!("This would make {} agents running at once; the limit is {max}. Send at most 1 in one call.", max + 1)),
            "{}",
            res.text
        );
        assert!(r.orch.calls().is_empty());
    }

    #[tokio::test]
    async fn fanout_spawn_failure_stops_started() {
        let r = lead();
        r.orch.spawn_script.lock().unwrap().extend([Ok(()), Err("No capacity.".to_string())]);
        let res = r.call("agent_fanout", json!({"agents":two()})).await;
        assert_eq!(res.status, ToolStatus::Error);
        assert!(res.text.contains("No capacity. No agent was left running."), "{}", res.text);
        assert_eq!(r.orch.calls(), vec!["spawn worker", "spawn verifier", "stop s-kid1"]);
    }

    #[tokio::test]
    async fn fanout_reports_in_order_with_outcome_line() {
        let r = lead();
        r.orch.settle("s-kid1", ChildOutcome::Blocked, "stuck", Value::Null);
        r.orch.settle("s-kid2", ChildOutcome::Returned, "done two", Value::Null);
        r.orch.settle("s-kid3", ChildOutcome::Returned, "done three", Value::Null);
        let res = r
            .call("agent_fanout", json!({"agents":[{"question":"a"},{"question":"b"},{"question":"c"}]}))
            .await;
        assert_eq!(res.status, ToolStatus::Ok);
        assert!(res.text.contains("3 agents: 2 returned, 1 blocked"), "{}", res.text);
        let h1 = res.text.find("===== agent 1 of 3: s-kid1 (worker) \u{2014} blocked, 7 steps =====").unwrap();
        let h2 = res.text.find("===== agent 2 of 3: s-kid2 (worker) \u{2014} returned, 7 steps =====").unwrap();
        let h3 = res.text.find("===== agent 3 of 3: s-kid3 (worker) \u{2014} returned, 7 steps =====").unwrap();
        assert!(h1 < h2 && h2 < h3);
        assert!(res.text.find("stuck").unwrap() < res.text.find("done two").unwrap());
        assert!(spawned(&r).iter().all(|s| s.awaited));
        let calls = r.orch.calls();
        assert_eq!(&calls[..3], ["spawn worker", "spawn worker", "spawn worker"]);
        assert_eq!(calls.iter().filter(|c| c.starts_with("join")).count(), 3);
    }

    #[tokio::test]
    async fn fanout_without_a_return_is_an_error() {
        let r = lead();
        r.orch.settle("s-kid1", ChildOutcome::Failed, "x", Value::Null);
        r.orch.settle("s-kid2", ChildOutcome::Stopped, "y", Value::Null);
        let res = r.call("agent_fanout", json!({"agents":two()})).await;
        assert_eq!(res.status, ToolStatus::Error);
        assert!(res.text.contains("2 agents: 1 stopped, 1 failed"), "{}", res.text);
    }

    #[tokio::test]
    async fn fanout_cancellation_stops_all() {
        let r = lead();
        *r.orch.hang_all.lock().unwrap() = true;
        let (res, ()) = tokio::join!(r.call("agent_fanout", json!({"agents":two()})), cancel_soon(&r));
        assert_eq!(res.status, ToolStatus::Error);
        assert!(res.text.contains("Interrupted while waiting for 2 agents; they were stopped."), "{}", res.text);
        let calls = r.orch.calls();
        assert!(calls.contains(&"stop s-kid1".to_string()) && calls.contains(&"stop s-kid2".to_string()), "{calls:?}");
    }

    // ---- agent_message / agent_stop ----

    #[tokio::test]
    async fn message_delivers_or_relays_refusal() {
        let r = lead();
        let res = r.call("agent_message", json!({"agent":"s-kid1","text":"hello"})).await;
        assert_eq!(res.status, ToolStatus::Ok);
        assert!(res.text.contains("sent") && res.text.contains("Delivered to s-kid1."), "{}", res.text);
        assert_eq!(r.orch.calls(), vec!["message s-kid1: hello"]);
        *r.orch.refuse.lock().unwrap() = Some("s-kid1 is not running.".into());
        let res = r.call("agent_message", json!({"agent":"s-kid1","text":"again"})).await;
        assert_eq!(res.status, ToolStatus::Error);
        assert!(res.text.contains("s-kid1 is not running."));
    }

    #[tokio::test]
    async fn stop_one_all_and_refusal() {
        let r = lead();
        let res = r.call("agent_stop", json!({"agent":"s-kid1"})).await;
        assert_eq!(res.status, ToolStatus::Ok);
        assert!(res.text.contains("s-kid1 was stopped; anything it had not delivered is in its record but was not reported."), "{}", res.text);
        let res = r.call("agent_stop", json!({"all":true})).await;
        assert!(res.text.contains("All running agents were stopped."), "{}", res.text);
        assert_eq!(r.orch.calls(), vec!["stop s-kid1", "stop_all"]);
        for args in [json!({}), json!({"agent":"s-kid1","all":true}), json!({"all":false})] {
            let res = r.call("agent_stop", args).await;
            assert_eq!(res.status, ToolStatus::Error);
            assert!(res.text.contains("exactly one of"), "{}", res.text);
        }
        assert_eq!(r.orch.calls().len(), 2);
        *r.orch.refuse.lock().unwrap() = Some("Not your agent.".into());
        let res = r.call("agent_stop", json!({"agent":"s-x"})).await;
        assert_eq!(res.status, ToolStatus::Error);
        assert!(res.text.contains("Not your agent."));
    }

    // ---- decide ----

    fn vote(option: Option<usize>, reason: &str) -> Vote {
        Vote { option, reason: reason.into() }
    }

    #[tokio::test]
    async fn decide_tally_and_leader() {
        let r = lead();
        *r.orch.votes.lock().unwrap() = Some(Ok(vec![
            vote(Some(2), "b is safer"),
            vote(Some(2), "agree"),
            vote(Some(1), "a is faster"),
            vote(None, "could not choose"),
            vote(Some(9), "out of range"),
        ]));
        let res = r.call("decide", json!({"question":"Which?","options":["a","b"]})).await;
        assert_eq!(res.status, ToolStatus::Ok);
        let t = &res.text;
        assert!(t.contains("option 2 leads (2 of 5)"), "{t}");
        assert!(t.contains("5 independent votes on: Which?"), "{t}");
        assert!(t.contains("1. a \u{2014} 1") && t.contains("2. b \u{2014} 2"), "{t}");
        assert!(t.contains("no valid choice \u{2014} 2"), "{t}");
        assert!(t.contains("Reasons:") && t.contains("- [2] b is safer") && t.contains("- [-] could not choose") && t.contains("- [-] out of range"), "{t}");
        assert!(t.contains("This is advice from copies of you with the same information, not new evidence. Record what you decide with `note`."), "{t}");
        assert_eq!(r.orch.calls(), vec!["poll 5: Which?"]);
    }

    #[tokio::test]
    async fn decide_split_and_reason_cut() {
        let r = lead();
        let long = "x".repeat(400);
        *r.orch.votes.lock().unwrap() = Some(Ok(vec![vote(Some(1), &long), vote(Some(2), "y"), vote(Some(3), "z")]));
        let res = r.call("decide", json!({"question":"Q","options":["a","b","c"],"k":3})).await;
        assert!(res.text.contains("split"), "{}", res.text);
        assert!(res.text.contains(&format!("- [1] {}\n", "x".repeat(300))), "{}", res.text);
        assert!(!res.text.contains(&"x".repeat(301)));
        assert!(!res.text.contains("no valid choice"));
        assert_eq!(r.orch.calls(), vec!["poll 3: Q"]);
    }

    #[tokio::test]
    async fn decide_refuses_bad_option_lists() {
        let r = lead();
        for options in [json!(["only"]), json!(["a", ""]), json!(["a", "b", "c", "d", "e", "f", "g"]), json!([])] {
            let res = r.call("decide", json!({"question":"Q","options":options})).await;
            assert_eq!(res.status, ToolStatus::Error);
        }
        assert!(r.orch.calls().is_empty());
    }

    #[tokio::test]
    async fn decide_relays_poll_failure() {
        let r = lead();
        *r.orch.votes.lock().unwrap() = Some(Err("The model is unavailable.".into()));
        let res = r.call("decide", json!({"question":"Q","options":["a","b"]})).await;
        assert_eq!(res.status, ToolStatus::Error);
        assert!(res.text.contains("The model is unavailable."));
    }

    // ---- verify ----

    fn with_claim(r: &Rig, with_evidence: bool) {
        r.model_op(LedgerOp::ClaimAdd { text: "The cache is never stale".into() });
        if with_evidence {
            let handle = r.output("line one\nline two\nline three", "bash", ToolClass::Exec);
            assert!(handle.starts_with("out:"));
            let id = r.orch.producers.lock().unwrap().keys().next().cloned().unwrap_or_else(|| BlobId("none".into()));
            r.model_op(LedgerOp::EvidenceAdd(EvidenceInput {
                claim: "c1".into(),
                kind: EvidenceKind::Execution,
                supports: true,
                session: SessionId::from("s-test"),
                call_id: CallId::from("call-0"),
                blob: Some(id),
                lines: Some((2, 3)),
                quote: Some("line two\nline three".into()),
                note: "shows both".into(),
                attested: true,
            }));
        }
    }

    #[tokio::test]
    async fn verify_claim_with_evidence_and_handles() {
        let r = lead();
        with_claim(&r, true);
        r.orch.settle("s-kid1", ChildOutcome::Returned, "They held up.", json!({"accepted":true,"objections":[]}));
        let res = r.call("verify", json!({"claim":"c1","handles":["out:aaa","out:bbb"]})).await;
        assert_eq!(res.status, ToolStatus::Ok);
        assert!(res.text.contains("verdict: accepted"), "{}", res.text);
        assert!(res.text.contains("The verdict is not recorded on c1; set the claim's status yourself with `claim_update`."), "{}", res.text);
        let sp = spawned(&r);
        assert_eq!(sp[0].role, "verifier");
        assert_eq!(sp[0].mode, SpawnMode::Fresh);
        assert!(sp[0].awaited);
        assert_eq!(sp[0].brief.question, "Try to refute this claim: The cache is never stale");
        assert_eq!(sp[0].brief.returns.as_deref(), Some("A verdict, delivered by calling verdict."));
        let ctx = sp[0].brief.context.clone().unwrap();
        assert!(ctx.starts_with("Evidence recorded for it:\n- e1 (supports) out:"), "{ctx}");
        assert!(ctx.contains(" lines 2-3: line two\nline three \u{2014} shows both"), "{ctx}");
        assert!(ctx.ends_with("\n\nOutputs to examine: out:aaa, out:bbb"), "{ctx}");
    }

    #[tokio::test]
    async fn verify_claim_without_evidence() {
        let r = lead();
        with_claim(&r, false);
        r.orch.settle("s-kid1", ChildOutcome::Returned, "Refuted.", json!({"accepted":false}));
        let res = r.call("verify", json!({"claim":"c1"})).await;
        assert_eq!(res.status, ToolStatus::Ok);
        assert!(res.text.contains("verdict: not accepted"), "{}", res.text);
        assert_eq!(spawned(&r)[0].brief.context.as_deref(), Some("No evidence is recorded for it."));
    }

    #[tokio::test]
    async fn verify_statement_form() {
        let r = lead();
        r.orch.settle("s-kid1", ChildOutcome::Returned, "Fine.", json!({"accepted":true}));
        let res = r.call("verify", json!({"statement":"2+2=4"})).await;
        assert!(res.text.contains("verdict: accepted"), "{}", res.text);
        assert!(!res.text.contains("is not recorded on"), "{}", res.text);
        let b = spawned(&r)[0].brief.clone();
        assert_eq!(b.question, "Try to refute this claim: 2+2=4");
        assert_eq!(b.context, None);
        r.orch.settle("s-kid2", ChildOutcome::Returned, "Fine.", json!({"accepted":true}));
        let res = r.call("verify", json!({"statement":"x","handles":["out:1"]})).await;
        assert!(res.status == ToolStatus::Ok);
        assert_eq!(spawned(&r)[1].brief.context.as_deref(), Some("Outputs to examine: out:1"));
    }

    #[tokio::test]
    async fn verify_unknown_claim_lists_ids() {
        let r = lead();
        let res = r.call("verify", json!({"claim":"c9"})).await;
        assert_eq!(res.status, ToolStatus::Error);
        assert!(res.text.contains("no claims"), "{}", res.text);
        with_claim(&r, false);
        let res = r.call("verify", json!({"claim":"c9"})).await;
        assert!(res.text.contains("`c9`") && res.text.contains("c1"), "{}", res.text);
        assert!(r.orch.calls().is_empty());
    }

    #[tokio::test]
    async fn verify_argument_and_role_refusals() {
        let r = lead();
        for args in [json!({}), json!({"claim":"c1","statement":"x"})] {
            let res = r.call("verify", args).await;
            assert_eq!(res.status, ToolStatus::Error);
            assert!(res.text.contains("exactly one of"), "{}", res.text);
        }
        let mut role = core_role("lead");
        role.may_spawn = vec!["worker".into()];
        let r = rig_with(role, false, true, AgentsCfg::default());
        let res = r.call("verify", json!({"statement":"x"})).await;
        assert_eq!(res.status, ToolStatus::Error);
        assert!(res.text.contains("This role cannot start a verifier."), "{}", res.text);
        assert!(r.orch.calls().is_empty());
    }

    #[tokio::test]
    async fn verify_missing_payload_is_no_verdict() {
        let r = lead();
        r.orch.settle("s-kid1", ChildOutcome::BudgetExhausted, "ran out", Value::Null);
        let res = r.call("verify", json!({"statement":"x"})).await;
        assert_eq!(res.status, ToolStatus::Error);
        assert!(res.text.contains("no verdict (budget_exhausted)"), "{}", res.text);
        assert!(res.text.contains("ran out"));
    }

    #[tokio::test]
    async fn verify_cancellation_stops_verifier() {
        let r = lead();
        *r.orch.hang_all.lock().unwrap() = true;
        let (res, ()) = tokio::join!(r.call("verify", json!({"statement":"x"})), cancel_soon(&r));
        assert_eq!(res.status, ToolStatus::Error);
        assert!(res.text.contains("Interrupted while waiting for agent s-kid1; it was stopped."), "{}", res.text);
        assert!(r.orch.calls().contains(&"stop s-kid1".to_string()));
    }
}
