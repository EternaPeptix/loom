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

use super::Shared;
use async_trait::async_trait;
use loom_core::event::{Brief, ToolClass, ToolSpec};
use loom_tools::params::{opt, req, spec, Param};
use loom_tools::{Tool, ToolCtx, ToolOutput};
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
    let _ = (shared, object);
    todo!("implement per module contract")
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
        let _ = (ctx, args, &self.0);
        todo!("implement per module contract")
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
        let _ = (ctx, args, &self.0);
        todo!("implement per module contract")
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
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let _ = (ctx, args, &self.0);
        todo!("implement per module contract")
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
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let _ = (ctx, args, &self.0);
        todo!("implement per module contract")
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
        let _ = (ctx, args, &self.0);
        todo!("implement per module contract")
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
        let _ = (ctx, args, &self.0);
        todo!("implement per module contract")
    }
}
