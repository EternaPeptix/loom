//! Runtime-owned tools: the ones that change mission state, start other agents, or end a turn.
//!
//! They implement `loom_tools::Tool` like every other tool and go through the same pipeline
//! (`loom_tools::execute`), so argument checking, refusals and result records are identical. What
//! makes them different is that each instance is bound to one session through [`Shared`].
//!
//! - [`ledger`]   `plan`, `step`, `note`, `claim`, `claim_update`, `evidence`, `ledger`, `reflect`
//! - [`misc`]     `pin`, `log_search`
//! - [`scope`]    `request_scope`
//! - [`terminal`] `finish`, `verdict`, `ask_user`, `ask_for`, `hand_off`, `report_blocker`, `wait`, `conclude`
//! - [`agents`]   `agent_spawn`, `agent_fanout`, `attempt`, `agent_adopt`, `agent_message`, `agent_stop`,
//!   `decide`, `verify`
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
pub mod continuation;
pub mod ledger;
pub mod misc;
pub mod scope;
pub mod security;
pub mod terminal;
#[cfg(test)]
pub(crate) mod testkit;

use crate::pack::RoleDef;
use async_trait::async_trait;
use loom_core::config::AgentsCfg;
use loom_core::event::{Author, Brief, Budget, ChildOutcome, Event, SpawnMode, ToolClass, TurnEndReason, Usage};
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
/// How many rejections of a lead's `finish`, counted since the latest accepted finish, make the harness record
/// that a finish was rejected that many times and that the session continues. It never asks the operator.
pub const MAX_FINISH_REJECTIONS: u32 = 2;
/// How many rejections of a lead's `finish`, counted since the latest accepted finish, at which the mission is
/// treated as stalled: when no new attested execution evidence was recorded after the previous rejection, the
/// operator is opened one non-blocking inbox item (nothing is asked, the session keeps working). Fires at most
/// once per stall; an accepted finish resets the count.
pub const STUCK_FINISH_REJECTIONS: u32 = MAX_FINISH_REJECTIONS;
/// What an [`Orchestrator`] answers once the runtime is shutting down. It is not a failure of the request:
/// the turn that made it is being cut and is resumed after the restart.
pub const SHUTTING_DOWN: &str = "The harness is shutting down.";

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
    /// Started by the harness itself for the finish gate: not counted against `max_children` and not
    /// limited to the parent role's `may_spawn`. Tools the model calls always set this to false.
    pub harness: bool,
    /// Explicit security-state prerequisites, checked against the actual child role by the runtime.
    pub prerequisite: Option<DispatchPrerequisite>,
    /// Where the child works.
    pub workspace: Workspace,
}

/// Where a child works.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Workspace {
    /// In its parent's workspace, beside the parent and its other agents.
    #[default]
    Shared,
    /// In its own copy of the parent's workspace, made when it starts (`loom_tools::workcopy`).
    /// Nothing it changes reaches the parent's workspace unless the parent adopts it.
    Copy,
}

/// A child's own copy of the workspace, as its parent may look at it.
#[derive(Clone, Debug)]
pub struct ChildCopy {
    /// The child, by its full id.
    pub agent: SessionId,
    /// The copy. Canonical.
    pub dir: PathBuf,
    /// What it was made from.
    pub manifest: loom_tools::workcopy::Manifest,
    /// The child has not settled.
    pub running: bool,
    /// The commands the child itself ran with `bash` to their end, oldest first, from its log.
    pub runs: Vec<Run>,
    /// For a command the parent has the harness run in the copy: it may write to the copy and to
    /// the parent's scratch directory, not to the workspace the copy was made from.
    pub sandbox: Arc<loom_tools::sandbox::Sandbox>,
}

/// One command a child ran to its end, as its log recorded it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run {
    pub command: String,
    /// When the call was recorded, before the command started.
    pub started_ms: u64,
    /// `None` when it did not end by exiting (a signal, a timeout, an interruption).
    pub exit_code: Option<i64>,
    /// The handle of its stored output.
    pub output: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchPrerequisite {
    pub asset: String,
    pub credential: String,
}

/// Resolve an explicit dispatch prerequisite in this mission. A credential for another asset or an
/// expired observation cannot satisfy the gate; this does not grant scope or promise a login works.
pub fn validate_dispatch_prerequisite(
    shared: &Shared,
    required: bool,
    requested: Option<&DispatchPrerequisite>,
    now_ms: u64,
) -> Result<Option<DispatchPrerequisite>, String> {
    let Some(requested) = requested else {
        return if required {
            Err("This role requires explicit asset and credential IDs. Record an evidence-linked credential for the target asset, then pass both IDs when dispatching it.".into())
        } else {
            Ok(None)
        };
    };
    let state = shared.ledger()?;
    let asset = state.security.resolve(&requested.asset)?;
    if !state.security.assets.contains_key(&asset) {
        return Err("The dispatch asset must be an asset record; query security assets and use its ID.".into());
    }
    let id = state.security.resolve(&requested.credential)?;
    let credential = state.security.credentials.get(&id).ok_or_else(|| {
        "The dispatch credential must be a credential record; query security state and use its ID.".to_string()
    })?;
    if credential.input.asset != asset {
        return Err(
            "This credential belongs to another asset. Supply a credential recorded for this exact target asset."
                .into(),
        );
    }
    if credential.input.expires_ms.is_some_and(|t| t <= now_ms) {
        return Err(
            "The credential observation expired. Revalidate and record current evidence before dispatching this role."
                .into(),
        );
    }
    if credential.input.evidence.is_empty()
        || credential.input.evidence.iter().any(|id| !state.evidence.iter().any(|e| &e.id == id && e.input.attested))
    {
        return Err("The credential lacks attested mission evidence. Record an observed credential before dispatching this role.".into());
    }
    Ok(Some(DispatchPrerequisite { asset, credential: id }))
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
    /// spawned by the parent's role, or when the parent already has `max_children` running. A request
    /// with `harness: true` (the finish gate's verifier) is exempt from the last two: it needs only a
    /// role of the parent's pack. While the runtime shuts down the answer is [`SHUTTING_DOWN`].
    async fn spawn(&self, parent: &SessionId, req: SpawnReq) -> Result<SessionId, String>;
    /// Wait until an `awaited` child has settled and take its settlement. Returns `Err` when
    /// `cancel` fires first (the child keeps running until it is stopped), when the child is not a
    /// child of `parent`, or when it was not spawned as `awaited`. Works whether the child settles
    /// before or after this call.
    async fn join(
        &self,
        parent: &SessionId,
        child: &SessionId,
        cancel: &CancellationToken,
    ) -> Result<Settlement, String>;
    /// Stop one child (it settles as `stopped`).
    async fn stop_child(&self, parent: &SessionId, child: &SessionId) -> Result<(), String>;
    /// Stop every running child of `parent`.
    async fn stop_children(&self, parent: &SessionId);
    /// Deliver a message from `parent` to a running child.
    async fn message_child(&self, parent: &SessionId, child: &SessionId, text: &str) -> Result<(), String>;
    async fn children(&self, parent: &SessionId) -> Vec<ChildInfo>;
    /// Actual child role, including harness verifiers omitted from the running-work list. Used to
    /// authenticate mechanical evidence ownership; never inferred from a child's report text.
    async fn child_role(&self, parent: &SessionId, child: &SessionId) -> Option<String> {
        self.children(parent).await.into_iter().find(|c| &c.id == child).map(|c| c.role)
    }
    /// Normalize a child reference for status reporting. Implementations must still enforce ownership
    /// at their action boundaries; scripted orchestrators may use exact IDs unchanged.
    async fn resolve_child(&self, _parent: &SessionId, child: &SessionId) -> Result<SessionId, String> {
        Ok(child.clone())
    }
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
    /// The working copy of a child that was started with `Workspace::Copy`; `None` for a child that
    /// shares its parent's workspace. `Err` when `child` is not a child of `parent`, or the record of
    /// what its copy was made from cannot be read.
    async fn child_copy(&self, _parent: &SessionId, _child: &SessionId) -> Result<Option<ChildCopy>, String> {
        Ok(None)
    }
}

#[derive(Default)]
struct Slots {
    emitted: Vec<(Author, Event)>,
    effect: Option<Effect>,
    continuation: Option<crate::continuation::Plan>,
    /// Refusals of the lead's `finish` without new execution evidence since the last rejection. In-memory only.
    stuck_refusals: u32,
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

    /// Count one refusal of the lead's `finish` (the goal pre-gate, or the open-items gate) that happened
    /// without new attested execution evidence since the last verifier rejection (`false` for `fresh`).
    /// The count resets to zero when fresh evidence appears. Not a persistent record: after a restart the
    /// count starts at zero.
    fn record_finish_refusal(&self, fresh: bool) -> u32 {
        let mut slots = self.slots();
        if fresh {
            slots.stuck_refusals = 0;
            return 0;
        }
        slots.stuck_refusals = slots.stuck_refusals.saturating_add(1);
        slots.stuck_refusals
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

    pub fn set_continuation(&self, plan: crate::continuation::Plan) {
        self.slots().continuation = Some(plan);
    }

    pub fn take_continuation(&self) -> Option<crate::continuation::Plan> {
        self.slots().continuation.take()
    }

    /// The folded ledger. The error is a sentence for the model.
    pub fn ledger(&self) -> Result<LedgerState, String> {
        let journal = self.journal.as_ref().ok_or_else(|| NO_MISSION.to_string())?;
        journal.state().map_err(|e| journal_sentence(&e))
    }

    /// The ledger, and how many of its entries this build could not read (sealed by a newer loom) and so
    /// left out of it.
    pub fn ledger_with_skipped(&self) -> Result<(LedgerState, u64), String> {
        let journal = self.journal.as_ref().ok_or_else(|| NO_MISSION.to_string())?;
        let read = journal.read_report().map_err(|e| journal_sentence(&e))?;
        Ok((LedgerState::fold(&read.entries), read.unknown))
    }

    /// Append one op to the mission journal as this session and emit the `ledger` record. A rule
    /// refusal comes back verbatim (it is already addressed to the model).
    pub fn ledger_append(&self, from_user: bool, op: LedgerOp) -> Result<(Entry, LedgerState), String> {
        let journal = self.journal.as_ref().ok_or_else(|| NO_MISSION.to_string())?;
        if self.is_child() && from_user {
            return Err(
                "Operator instructions and approvals must be recorded through the mission lead, not a child session."
                    .to_string(),
            );
        }
        // Security records are authorized by `security_record` itself (an independent read-only judge may
        // close a hypothesis); every other op is refused to a read-only role.
        if self.role.read_only && !from_user && !matches!(op, LedgerOp::Security(_)) {
            return Err("This role has read-only access to the mission ledger. Return observations through its report or verdict.".to_string());
        }
        let summary = LedgerState::summarize(&op);
        let checked_op = op.clone();
        let (entry, state) = journal.append(&self.session, from_user, op, &|state| {
            if !self.is_child() { return Ok(()); }
            let claim = match &checked_op {
                LedgerOp::Decision { .. }
                | LedgerOp::DeadEnd { .. }
                | LedgerOp::Reflection { .. }
                | LedgerOp::ClaimAdd { .. }
                | LedgerOp::Security(_) => return Ok(()),
                LedgerOp::ClaimUpdate { id, .. } => id,
                LedgerOp::EvidenceAdd(input) => &input.claim,
                _ => return Err("A child may record notes and its own claims and evidence. Mission plans, approvals and other shared obligations belong to the lead.".to_string()),
            };
            // This runs under the journal's append lock, on the state it holds, so creation order
            // cannot race another writer when resolving the claim id to its originating session
            // (the journal is not read again here: a read takes the same lock).
            let own = claim.strip_prefix('c').and_then(|n| n.parse::<usize>().ok()).and_then(|n| n.checked_sub(1))
                .and_then(|i| state.claim_sessions.get(i)).is_some_and(|s| *s == self.session);
            if own { Ok(()) } else { Err(format!("Claim {claim} belongs to another session. Add evidence and update status only on claims created by this child; return other observations to the lead.")) }
        }).map_err(|e| journal_sentence(&e))?;
        let author = if from_user { Author::User } else { Author::Model };
        self.emit(author, Event::Ledger { n: entry.n, summary });
        Ok((entry, state))
    }
}

pub const NO_MISSION: &str = "This session has no mission ledger, so there is nothing to record against.";

fn journal_sentence(e: &JournalError) -> String {
    match e {
        JournalError::Rule(text) => text.clone(),
        JournalError::NewerVersion { .. } => format!(
            "Nothing was recorded: {e}. Every tool that writes to the ledger, ask_user included, will keep failing the same way, so do not repeat the call. Tell the operator in your reply that loom must be upgraded before this mission can continue."
        ),
        JournalError::Unconfirmed { .. } => format!(
            "The mission journal reported an error after the entry was written and the write could not be undone, so the entry may or may not be recorded ({e}). This is a harness fault, not a problem with the call. Look for the entry in the ledger (the `ledger` tool shows it) before repeating the call, so that it is not recorded twice."
        ),
        other => format!(
            "The mission journal could not be used ({other}). This is a harness fault, not a problem with the call; nothing was recorded."
        ),
    }
}

/// The producer of the stored output `blob` (cited as `handle`) when it is an observation, so that a quote
/// from it may be recorded as support: the output of a command run or a file read. Refused, with a sentence
/// for the model, when no tool call of the mission produced it, or when the producer is a runtime tool (the
/// ledger or a log search play the model's own words back, the agent tools return another agent's) or of
/// class `State`, `Terminal` or `Write` (the diff of the model's own `write` or `edit`). A view stores
/// nothing of its own and is judged by the output it views.
pub(crate) async fn observed_producer(
    shared: &Shared,
    mission: &MissionId,
    handle: &str,
    blob: &BlobId,
) -> Result<Producer, String> {
    let Some(producer) = shared.orch.producer(mission, blob).await else {
        return Err(format!(
            "{handle} was not produced by a tool call of this mission, so it cannot be used as evidence. Evidence is a quote from the output of a command you ran or a file you read."
        ));
    };
    let not_observed = matches!(producer.class, ToolClass::State | ToolClass::Terminal | ToolClass::Write);
    if not_observed || NAMES.contains(&producer.tool.as_str()) {
        return Err(format!(
            "{handle} is the result of `{}`, which is a message from the harness or from another agent, or your own words played back, not an observation. Quote the output of the command or file read that shows it instead (an agent's report names the handles).",
            producer.tool
        ));
    }
    Ok(producer)
}

/// The runtime tool called `name`, bound to `shared`; `None` when `name` is not a runtime tool.
pub fn tool(name: &str, shared: &Arc<Shared>) -> Option<Arc<dyn loom_tools::Tool>> {
    let s = shared.clone();
    Some(match name {
        "plan" => Arc::new(ledger::Plan(s)),
        "guarded_plan" => Arc::new(continuation::GuardedPlan(s)),
        "step" => Arc::new(ledger::Step(s)),
        "note" => Arc::new(ledger::Note(s)),
        "claim" => Arc::new(ledger::Claim(s)),
        "claim_update" => Arc::new(ledger::ClaimUpdate(s)),
        "evidence" => Arc::new(ledger::Evidence(s)),
        "ledger" => Arc::new(ledger::Ledger(s)),
        "reflect" => Arc::new(ledger::Reflect(s)),
        "security_record" => Arc::new(security::SecurityRecord(s)),
        "security_query" => Arc::new(security::SecurityQuery(s)),
        "security_ingest" => Arc::new(security::SecurityIngest(s)),
        "pin" => Arc::new(misc::Pin(s)),
        "log_search" => Arc::new(misc::LogSearch(s)),
        "finish" => Arc::new(terminal::Finish(s)),
        "verdict" => Arc::new(terminal::Verdict(s)),
        "ask_user" => Arc::new(terminal::AskUser(s)),
        "ask_for" => Arc::new(terminal::AskFor(s)),
        "hand_off" => Arc::new(terminal::HandOff(s)),
        "report_blocker" => Arc::new(terminal::ReportBlocker(s)),
        "wait" => Arc::new(terminal::Wait(s)),
        "request_scope" => Arc::new(scope::RequestScope(s)),
        "conclude" => Arc::new(terminal::Conclude(s)),
        "agent_spawn" => Arc::new(agents::AgentSpawn(s)),
        "agent_fanout" => Arc::new(agents::AgentFanout(s)),
        "attempt" => Arc::new(agents::Attempt(s)),
        "agent_adopt" => Arc::new(agents::AgentAdopt(s)),
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
    "guarded_plan",
    "plan",
    "step",
    "note",
    "claim",
    "claim_update",
    "evidence",
    "ledger",
    "reflect",
    "security_record",
    "security_query",
    "security_ingest",
    "pin",
    "log_search",
    "finish",
    "verdict",
    "ask_user",
    "ask_for",
    "hand_off",
    "report_blocker",
    "wait",
    "conclude",
    "agent_spawn",
    "agent_fanout",
    "attempt",
    "agent_adopt",
    "agent_message",
    "agent_stop",
    "decide",
    "verify",
    "request_scope",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_dispatch_requires_a_matching_unexpired_attested_record() {
        use crate::rtools::testkit::rig;
        use loom_core::ledger::{EvidenceInput, EvidenceKind};
        use loom_core::security_state::{AssetInput, AssetKind, CredentialInput, SecurityOp};
        let r = rig("lead", false, true);
        assert!(validate_dispatch_prerequisite(&r.shared, true, None, 100).is_err());
        assert_eq!(validate_dispatch_prerequisite(&r.shared, false, None, 100).unwrap(), None);
        r.model_op(LedgerOp::ClaimAdd { text: "fixture credential observed".into() });
        r.model_op(LedgerOp::EvidenceAdd(EvidenceInput {
            claim: "c1".into(),
            kind: EvidenceKind::Execution,
            supports: true,
            session: "s-test".into(),
            call_id: "call-fixture".into(),
            blob: None,
            lines: None,
            quote: None,
            note: "dummy fixture observation".into(),
            attested: true,
        }));
        let mut ids = Vec::new();
        for locator in ["first.test", "second.test"] {
            let asset = AssetInput {
                kind: AssetKind::Host,
                locator: locator.into(),
                evidence: vec!["e1".into()],
                mandatory: true,
                parent: None,
            };
            ids.push(asset.id().unwrap());
            r.model_op(LedgerOp::Security(SecurityOp::AssetUpsert { asset }));
        }
        let credential = CredentialInput {
            asset: ids[0].clone(),
            principal: "dummy".into(),
            secret_handle: "out:0123456789abcdef".into(),
            evidence: vec!["e1".into()],
            unlocks: vec![],
            expires_ms: Some(200),
        };
        let state = r.model_op(LedgerOp::Security(SecurityOp::CredentialAdd { credential }));
        let id = state.security.credentials.keys().next().unwrap().clone();
        let mut request = DispatchPrerequisite { asset: ids[0].clone(), credential: id };
        assert!(validate_dispatch_prerequisite(&r.shared, true, Some(&request), 100).is_ok());
        assert!(validate_dispatch_prerequisite(&r.shared, true, Some(&request), 200).unwrap_err().contains("expired"));
        request.asset = ids[1].clone();
        assert!(validate_dispatch_prerequisite(&r.shared, true, Some(&request), 100)
            .unwrap_err()
            .contains("another asset"));
    }

    #[test]
    fn journal_sentences_are_distinct_and_say_what_to_do() {
        assert_eq!(journal_sentence(&JournalError::Rule("Do X instead.".into())), "Do X instead.");

        let tampered = journal_sentence(&JournalError::Tampered { n: 2, detail: "the seal does not match".into() });
        assert!(tampered.contains("harness fault") && tampered.contains("nothing was recorded"), "{tampered}");

        // A journal from a newer loom: retrying or asking through ask_user cannot work.
        let detail = "op `hologram_set`: unknown variant `hologram_set`".to_string();
        let newer = journal_sentence(&JournalError::NewerVersion { n: 2, detail });
        assert!(newer.starts_with("Nothing was recorded") && newer.contains("newer loom"), "{newer}");
        assert!(newer.contains("entry 2") && newer.contains("`hologram_set`"), "{newer}");
        assert!(newer.contains("ask_user") && newer.contains("do not repeat the call"), "{newer}");
        assert!(newer.contains("Tell the operator in your reply"), "{newer}");
        assert!(!newer.contains("harness fault") && !newer.contains("then repeat"), "{newer}");

        // A write that could be neither confirmed nor undone must not claim that nothing was recorded.
        let unconfirmed = journal_sentence(&JournalError::Unconfirmed {
            path: "journal.jsonl".into(),
            n: 3,
            source: std::io::Error::other("sync failed"),
            undo: std::io::Error::other("truncate failed"),
        });
        assert!(unconfirmed.contains("may or may not be recorded") && unconfirmed.contains("entry 3"), "{unconfirmed}");
        assert!(unconfirmed.contains("before repeating the call"), "{unconfirmed}");
        assert!(!unconfirmed.contains("nothing was recorded"), "{unconfirmed}");
    }
}
