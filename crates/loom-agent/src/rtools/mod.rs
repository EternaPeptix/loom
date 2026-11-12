//! Runtime-owned tools: the ones that change mission state, start other agents, or end a turn.
//!
//! They implement `loom_tools::Tool` like every other tool and go through the same pipeline
//! (`loom_tools::execute`), so argument checking, refusals and result records are identical. What
//! makes them different is that each instance is bound to one session through [`Shared`].
//!
//! - [`ledger`]   `plan`, `step`, `note`, `claim`, `claim_update`, `evidence`, `ledger`
//! - [`misc`]     `pin`, `log_search`
//! - [`terminal`] `finish`, `verdict`, `ask_user`, `report_blocker`, `wait`
//! - [`agents`]   `agent_spawn`, `agent_fanout`, `agent_message`, `agent_stop`, `decide`, `verify`
//!
//! ## How a runtime tool acts on its session
//! A tool never writes the session log. It returns its `ToolOutput` and leaves two things in
//! [`Shared`] for the step loop, which reads them right after the call returns:
//! - **emitted events** ([`Shared::emit`]): records to append after the call's `tool_result`
//!   (`ledger`, `pin`, `inbox_opened`, `child_spawned`, …), in the order emitted;
//! - **an effect** ([`Shared::set_effect`]): the turn ends, or this (child) session settles.
//!
//! Everything a tool does to the mission ledger goes through [`Shared::ledger_append`], which
//! writes the sealed journal and emits the matching `ledger` record.
//!
//! This file is complete; the sub-modules carry their own contracts.

pub mod agents;
pub mod ledger;
pub mod misc;
pub mod terminal;
#[cfg(test)]
pub(crate) mod testkit;

use crate::pack::RoleDef;
use async_trait::async_trait;
use loom_core::config::AgentsCfg;
use loom_core::event::{
    Author, Brief, Budget, ChildOutcome, Event, SpawnMode, ToolClass, TurnEndReason, Usage,
};
use loom_core::journal::{Journal, JournalError};
use loom_core::ledger::{Entry, LedgerOp, LedgerState};
use loom_core::{BlobId, BlobRef, CallId, MissionId, SessionId};
use loom_tools::Registry;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;

/// A child's answer longer than this is cut in the report its parent sees (the whole answer is stored).
pub const REPORT_MAX_CHARS: usize = 12_000;
/// How many times a verifier may reject a lead's `finish` before the next one is delivered unverified.
pub const MAX_FINISH_REJECTIONS: u32 = 2;

/// What a tool asks the step loop to do once its result is recorded.
#[derive(Clone, Debug, PartialEq)]
pub enum Effect {
    /// End the turn: `finish` accepted (lead), `ask_user`, `report_blocker` (lead), `wait`.
    EndTurn(TurnEndReason),
    /// This child session is done: deliver the settlement to its parent and end the session.
    Settle(Delivery),
}

/// What a child hands back when it ends itself.
#[derive(Clone, Debug, PartialEq)]
pub struct Delivery {
    pub outcome: ChildOutcome,
    /// The text the parent is shown (already rendered by `gate::render_report`).
    pub report: String,
    /// The complete answer when `report` was cut.
    pub full: Option<BlobRef>,
    /// Machine-readable result: for `verdict` `{"accepted":bool,"objections":[…]}`; for `finish`
    /// `{"quotes":[…]}`; otherwise `null`.
    pub payload: Value,
}

/// A child's end as its parent (and anything waiting on it) receives it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Settlement {
    pub child: SessionId,
    pub role: String,
    pub outcome: ChildOutcome,
    pub report: String,
    pub full: Option<BlobRef>,
    pub payload: Value,
    pub steps: u32,
    pub usage: Usage,
}

/// A request to start a child session.
#[derive(Clone, Debug, PartialEq)]
pub struct SpawnReq {
    pub role: String,
    pub mode: SpawnMode,
    pub brief: Brief,
    pub budget: Budget,
    /// The call that asked for it.
    pub call_id: CallId,
    pub title: String,
    /// The calling tool will `join` this child and return its report as the call's result. The
    /// runtime then records the settlement in the parent's log as `inline` and does not start a
    /// parent turn for it. When false, the settlement is delivered to the parent as an
    /// `agent-report` message and resumes the parent if it is waiting.
    pub awaited: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChildInfo {
    pub id: SessionId,
    pub role: String,
    pub title: String,
    pub step: u32,
    pub running: bool,
}

/// One independent answer to a `decide` question.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vote {
    /// 1-based option number; `None` when the reply named no valid option.
    pub option: Option<usize>,
    pub reason: String,
}

/// What produced a stored output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Producer {
    pub session: SessionId,
    pub call_id: CallId,
    pub tool: String,
    pub class: ToolClass,
}

/// What a session's tools may ask of the runtime that owns all sessions. Every error is a sentence
/// for the model.
#[async_trait]
pub trait Orchestrator: Send + Sync {
    /// Start a child of `parent`. Refuses when `parent` is itself a child, when the role may not be
    /// spawned by the parent's role, or when the parent already has `max_children` running.
    async fn spawn(&self, parent: &SessionId, req: SpawnReq) -> Result<SessionId, String>;
    /// Wait until an `awaited` child has settled and take its settlement. Returns `Err` when
    /// `cancel` fires first (the child keeps running until it is stopped), when the child is not a
    /// child of `parent`, or when it was not spawned as `awaited`. Works whether the child settles
    /// before or after this call.
    async fn join(&self, parent: &SessionId, child: &SessionId, cancel: &CancellationToken) -> Result<Settlement, String>;
    /// Stop one child (it settles as `stopped`).
    async fn stop_child(&self, parent: &SessionId, child: &SessionId) -> Result<(), String>;
    /// Stop every running child of `parent`.
    async fn stop_children(&self, parent: &SessionId);
    /// Deliver a message from `parent` to a running child.
    async fn message_child(&self, parent: &SessionId, child: &SessionId, text: &str) -> Result<(), String>;
    async fn children(&self, parent: &SessionId) -> Vec<ChildInfo>;
    /// Ask `k` independent copies of `session` (same context up to its current step, different
    /// seeds, no tools executed) to choose between `options`.
    async fn poll(
        &self,
        session: &SessionId,
        question: &str,
        options: &[String],
        k: u32,
        cancel: &CancellationToken,
    ) -> Result<Vec<Vote>, String>;
    /// Find the tool call whose stored output is `blob`, among the sessions of `mission`.
    async fn producer(&self, mission: &MissionId, blob: &BlobId) -> Option<Producer>;
}

#[derive(Default)]
struct Slots {
    emitted: Vec<(Author, Event)>,
    effect: Option<Effect>,
}

/// One session's handle for its runtime tools. Created by the runtime, shared by `Arc`.
pub struct Shared {
    pub session: SessionId,
    pub mission: Option<MissionId>,
    pub parent: Option<SessionId>,
    pub role: RoleDef,
    /// The mission journal; `None` for sessions without a mission (the `chat` role).
    pub journal: Option<Journal>,
    /// This session's log file, for `log_search`.
    pub log_path: PathBuf,
    pub agents: AgentsCfg,
    pub orch: Arc<dyn Orchestrator>,
    slots: Mutex<Slots>,
}

impl Shared {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session: SessionId,
        mission: Option<MissionId>,
        parent: Option<SessionId>,
        role: RoleDef,
        journal: Option<Journal>,
        log_path: PathBuf,
        agents: AgentsCfg,
        orch: Arc<dyn Orchestrator>,
    ) -> Shared {
        Shared { session, mission, parent, role, journal, log_path, agents, orch, slots: Mutex::new(Slots::default()) }
    }

    pub fn is_child(&self) -> bool {
        self.parent.is_some()
    }

    fn slots(&self) -> std::sync::MutexGuard<'_, Slots> {
        self.slots.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Queue a record to be appended after the current call's result.
    pub fn emit(&self, author: Author, event: Event) {
        self.slots().emitted.push((author, event));
    }

    pub fn take_emitted(&self) -> Vec<(Author, Event)> {
        std::mem::take(&mut self.slots().emitted)
    }

    /// Ask the loop to end the turn or settle the session. A later call replaces an earlier one.
    pub fn set_effect(&self, effect: Effect) {
        self.slots().effect = Some(effect);
    }

    pub fn take_effect(&self) -> Option<Effect> {
        self.slots().effect.take()
    }

    /// The folded ledger. The error is a sentence for the model.
    pub fn ledger(&self) -> Result<LedgerState, String> {
        let journal = self.journal.as_ref().ok_or_else(|| NO_MISSION.to_string())?;
        journal.state().map_err(|e| journal_sentence(&e))
    }

    /// Append one op to the mission journal as this session and emit the `ledger` record. A rule
    /// refusal comes back verbatim (it is already addressed to the model).
    pub fn ledger_append(&self, from_user: bool, op: LedgerOp) -> Result<(Entry, LedgerState), String> {
        let journal = self.journal.as_ref().ok_or_else(|| NO_MISSION.to_string())?;
        let summary = LedgerState::summarize(&op);
        let (entry, state) = journal.append(&self.session, from_user, op, &|_| Ok(())).map_err(|e| journal_sentence(&e))?;
        let author = if from_user { Author::User } else { Author::Model };
        self.emit(author, Event::Ledger { n: entry.n, summary });
        Ok((entry, state))
    }
}

pub const NO_MISSION: &str = "This session has no mission ledger, so there is nothing to record against.";

fn journal_sentence(e: &JournalError) -> String {
    match e {
        JournalError::Rule(text) => text.clone(),
        JournalError::NewerVersion { .. } => {
            "This mission's journal was written by a newer loom than this one, so nothing was recorded. Ask the operator to upgrade loom, then repeat the call.".to_string()
        }
        other => format!(
            "The mission journal could not be used ({other}). This is a harness fault, not a problem with the call; nothing was recorded."
        ),
    }
}

/// The runtime tool called `name`, bound to `shared`; `None` when `name` is not a runtime tool.
pub fn tool(name: &str, shared: &Arc<Shared>) -> Option<Arc<dyn loom_tools::Tool>> {
    let s = shared.clone();
    Some(match name {
        "plan" => Arc::new(ledger::Plan(s)),
        "step" => Arc::new(ledger::Step(s)),
        "note" => Arc::new(ledger::Note(s)),
        "claim" => Arc::new(ledger::Claim(s)),
        "claim_update" => Arc::new(ledger::ClaimUpdate(s)),
        "evidence" => Arc::new(ledger::Evidence(s)),
        "ledger" => Arc::new(ledger::Ledger(s)),
        "pin" => Arc::new(misc::Pin(s)),
        "log_search" => Arc::new(misc::LogSearch(s)),
        "finish" => Arc::new(terminal::Finish(s)),
        "verdict" => Arc::new(terminal::Verdict(s)),
        "ask_user" => Arc::new(terminal::AskUser(s)),
        "report_blocker" => Arc::new(terminal::ReportBlocker(s)),
        "wait" => Arc::new(terminal::Wait(s)),
        "agent_spawn" => Arc::new(agents::AgentSpawn(s)),
        "agent_fanout" => Arc::new(agents::AgentFanout(s)),
        "agent_message" => Arc::new(agents::AgentMessage(s)),
        "agent_stop" => Arc::new(agents::AgentStop(s)),
        "decide" => Arc::new(agents::Decide(s)),
        "verify" => Arc::new(agents::Verify(s)),
        _ => return None,
    })
}

/// The session's tools, in the order of the role's tool list: built-in tools from
/// `Registry::builtin()`, runtime tools from [`tool`]. A name that is neither is an error.
pub fn build_registry(shared: &Arc<Shared>) -> Result<Registry, String> {
    let builtin = Registry::builtin();
    let mut registry = Registry::new();
    for name in &shared.role.tools {
        match builtin.get(name).or_else(|| tool(name, shared)) {
            Some(t) => registry.add(t),
            None => {
                return Err(format!(
                    "role `{}` of pack `{}` lists the tool `{name}`, which does not exist",
                    shared.role.name, shared.role.pack
                ))
            }
        }
    }
    Ok(registry)
}

/// Every tool name a role may list.
pub fn known_tools() -> Vec<String> {
    let mut names = Registry::builtin().names();
    names.extend(NAMES.iter().map(|n| n.to_string()));
    names
}

/// The names [`tool`] knows.
pub const NAMES: &[&str] = &[
    "plan", "step", "note", "claim", "claim_update", "evidence", "ledger", "pin", "log_search", "finish", "verdict",
    "ask_user", "report_blocker", "wait", "agent_spawn", "agent_fanout", "agent_message", "agent_stop", "decide",
    "verify",
];
