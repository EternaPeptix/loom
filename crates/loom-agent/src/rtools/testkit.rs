//! Test rig for the runtime tools: a scripted [`Orchestrator`] and a session bound to a temporary
//! directory. Complete; implementers use it as is and may add helpers at the end.

#![allow(dead_code, clippy::expect_used, clippy::unwrap_used)]

use super::{build_registry, ChildCopy, ChildInfo, Orchestrator, Producer, Settlement, Shared, SpawnReq, Vote};
use crate::pack::{Packs, RoleDef};
use async_trait::async_trait;
use loom_core::config::AgentsCfg;
use loom_core::event::{ChildOutcome, ToolClass, ToolResult, Usage};
use loom_core::journal::Journal;
use loom_core::ledger::{LedgerOp, LedgerState};
use loom_core::{BlobId, BlobRef, CallId, MissionId, SessionId};
use loom_tools::testutil::{env, TestEnv};
use loom_tools::{execute, Admission, Registry};
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;

/// Records every call as a line (`spawn worker`, `join s-kid1`, `stop s-kid1`, `stop_all`,
/// `message s-kid1: text`, `poll 5: question`) and answers from what the test scripted.
#[derive(Default)]
pub struct FakeOrch {
    pub calls: Mutex<Vec<String>>,
    /// Every accepted spawn, in order.
    pub spawned: Mutex<Vec<(SessionId, SpawnReq)>>,
    /// Results for the next spawns; when empty a spawn succeeds as `s-kid{n}` (n counts from 1).
    pub spawn_script: Mutex<VecDeque<Result<(), String>>>,
    /// Settlements by child; a child with none settles as `Returned` with report `report of {id}`.
    pub settlements: Mutex<HashMap<SessionId, Settlement>>,
    /// Children whose `join` waits until the cancel token fires, then fails.
    pub hang: Mutex<Vec<SessionId>>,
    /// When set, every `join` waits for cancellation.
    pub hang_all: Mutex<bool>,
    /// Controlled verifier latency for contract-change regression tests; zero by default.
    pub join_delay_ms: std::sync::atomic::AtomicU64,
    pub children: Mutex<Vec<ChildInfo>>,
    pub votes: Mutex<Option<Result<Vec<Vote>, String>>>,
    pub producers: Mutex<HashMap<BlobId, Producer>>,
    /// Error returned by `stop_child` / `message_child` when set.
    pub refuse: Mutex<Option<String>>,
    /// Copies by child; a child with none works in its parent's workspace.
    pub copies: Mutex<HashMap<SessionId, Result<ChildCopy, String>>>,
    /// What `box_access` answers; unset means no box is configured.
    pub boxed: Mutex<Option<Result<Arc<loom_tools::boxctl::MissionBox>, String>>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl FakeOrch {
    pub fn calls(&self) -> Vec<String> {
        lock(&self.calls).clone()
    }
    fn record(&self, line: String) {
        lock(&self.calls).push(line);
    }
    /// Script how `child` settles.
    pub fn settle(&self, child: &str, outcome: ChildOutcome, report: &str, payload: Value) {
        let id = SessionId::from(child);
        lock(&self.settlements).insert(
            id.clone(),
            Settlement {
                child: id,
                role: "worker".into(),
                outcome,
                report: report.into(),
                full: None,
                payload,
                steps: 7,
                usage: Usage::default(),
            },
        );
    }
    /// Declare which tool call produced a stored output.
    pub fn produced(&self, blob: &BlobRef, session: &str, call: &str, tool: &str, class: ToolClass) {
        lock(&self.producers).insert(
            blob.id.clone(),
            Producer { session: SessionId::from(session), call_id: CallId::from(call), tool: tool.into(), class },
        );
    }
    pub fn running_child(&self, id: &str, role: &str) {
        lock(&self.children).push(ChildInfo {
            id: SessionId::from(id),
            role: role.into(),
            title: format!("work of {id}"),
            step: 3,
            running: true,
        });
    }
}

#[async_trait]
impl Orchestrator for FakeOrch {
    async fn spawn(&self, _parent: &SessionId, req: SpawnReq) -> Result<SessionId, String> {
        self.record(format!("spawn {}", req.role));
        if let Some(Err(e)) = lock(&self.spawn_script).pop_front() {
            return Err(e);
        }
        let mut spawned = lock(&self.spawned);
        let id = SessionId::from(format!("s-kid{}", spawned.len() + 1));
        spawned.push((id.clone(), req));
        Ok(id)
    }

    async fn join(
        &self,
        _parent: &SessionId,
        child: &SessionId,
        cancel: &CancellationToken,
    ) -> Result<Settlement, String> {
        self.record(format!("join {child}"));
        let delay = self.join_delay_ms.load(std::sync::atomic::Ordering::Relaxed);
        if delay > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        }
        let hangs = *lock(&self.hang_all) || lock(&self.hang).contains(child);
        if hangs {
            cancel.cancelled().await;
            return Err(format!("The wait for {child} was interrupted."));
        }
        let scripted = lock(&self.settlements).get(child).cloned();
        let role = lock(&self.spawned).iter().find(|(id, _)| id == child).map(|(_, r)| r.role.clone());
        Ok(match scripted {
            Some(mut s) => {
                if let Some(role) = role {
                    s.role = role;
                }
                s
            }
            None => Settlement {
                child: child.clone(),
                role: role.unwrap_or_else(|| "worker".into()),
                outcome: ChildOutcome::Returned,
                report: format!("report of {child}"),
                full: None,
                payload: Value::Null,
                steps: 7,
                usage: Usage::default(),
            },
        })
    }

    async fn stop_child(&self, _parent: &SessionId, child: &SessionId) -> Result<(), String> {
        self.record(format!("stop {child}"));
        match lock(&self.refuse).clone() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    async fn stop_children(&self, _parent: &SessionId) {
        self.record("stop_all".into());
    }

    async fn message_child(&self, _parent: &SessionId, child: &SessionId, text: &str) -> Result<(), String> {
        self.record(format!("message {child}: {text}"));
        match lock(&self.refuse).clone() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    async fn children(&self, _parent: &SessionId) -> Vec<ChildInfo> {
        lock(&self.children).clone()
    }

    async fn poll(
        &self,
        _session: &SessionId,
        question: &str,
        _options: &[String],
        k: u32,
        _cancel: &CancellationToken,
    ) -> Result<Vec<Vote>, String> {
        self.record(format!("poll {k}: {question}"));
        lock(&self.votes).clone().unwrap_or_else(|| Ok(Vec::new()))
    }

    async fn producer(&self, _mission: &MissionId, blob: &BlobId) -> Option<Producer> {
        lock(&self.producers).get(blob).cloned()
    }

    async fn box_access(&self, _session: &SessionId) -> Result<Arc<loom_tools::boxctl::MissionBox>, String> {
        match lock(&self.boxed).clone() {
            Some(answer) => answer,
            None => Err(super::boxtools::NO_BOX.to_string()),
        }
    }

    async fn child_copy(&self, _parent: &SessionId, child: &SessionId) -> Result<Option<ChildCopy>, String> {
        self.record(format!("copy {child}"));
        lock(&self.copies).get(child).cloned().transpose()
    }
}

/// One session with its runtime tools, over a temporary directory.
pub struct Rig {
    pub env: TestEnv,
    pub orch: Arc<FakeOrch>,
    pub shared: Arc<Shared>,
    pub registry: Registry,
}

/// A role of the built-in core pack.
pub fn core_role(name: &str) -> RoleDef {
    Packs::builtin().expect("built-in pack").role(None, Some(name)).expect("role").clone()
}

/// A session `s-test` in role `role` of the core pack. `child` gives it the parent `s-lead`;
/// `mission` gives it mission `m-test` with a journal (random key) under the temporary directory.
pub fn rig(role: &str, child: bool, mission: bool) -> Rig {
    rig_with(core_role(role), child, mission, AgentsCfg::default())
}

pub fn rig_with(role: RoleDef, child: bool, mission: bool, agents: AgentsCfg) -> Rig {
    let env = env();
    let orch = Arc::new(FakeOrch::default());
    let home = env.dir.path().join("home");
    let journal = mission.then(|| {
        let key = loom_core::journal::load_or_create_key(&home.join("keys/journal.key")).expect("journal key");
        Journal::new(home.join("missions/m-test/journal.jsonl"), key)
    });
    if mission {
        std::fs::create_dir_all(home.join("missions/m-test")).expect("mission dir");
    }
    let log_path = home.join("sessions/s-test/log.jsonl");
    std::fs::create_dir_all(home.join("sessions/s-test")).expect("session dir");
    let shared = Arc::new(Shared::new(
        SessionId::from("s-test"),
        mission.then(|| MissionId::from("m-test")),
        child.then(|| SessionId::from("s-lead")),
        role,
        journal,
        log_path,
        agents,
        orch.clone(),
    ));
    let registry = build_registry(&shared).expect("registry for the role");
    Rig { env, orch, shared, registry }
}

impl Rig {
    /// Run a call the way the runtime does: through `execute`, arguments as JSON text.
    pub async fn call(&self, name: &str, args: Value) -> ToolResult {
        let admission = Admission { policy: &self.env.policy, estimator: &self.env.estimator };
        let result = execute(&self.registry, &self.env.ctx, name, &args.to_string(), &admission).await;
        // As the runtime does for every recorded result: the call that stored an output produced it.
        // (A view such as `out_read` stores nothing; it leaves the output it views with its producer.)
        if let Some(out) = &result.output {
            lock(&self.orch.producers).entry(out.id.clone()).or_insert(Producer {
                session: self.shared.session.clone(),
                call_id: result.call_id.clone(),
                tool: result.name.clone(),
                class: result.class,
            });
        }
        result
    }

    /// Write an op to the mission journal as the operator (`from_user`), bypassing the tools.
    pub fn user_op(&self, op: LedgerOp) -> LedgerState {
        let journal = self.shared.journal.as_ref().expect("mission journal");
        let (_, state) =
            journal.append(&SessionId::from("s-operator"), true, op, &|_| Ok(())).expect("operator ledger op");
        self.shared.take_emitted();
        state
    }

    /// Write an op to the mission journal as the model, bypassing the tools.
    pub fn model_op(&self, op: LedgerOp) -> LedgerState {
        // A read-only role cannot write the ledger through its own session: its fixtures are written
        // as another (lead) session, which is also what a real mission has.
        let state = if self.shared.role.read_only {
            let journal = self.shared.journal.as_ref().expect("mission journal");
            journal.append(&SessionId::from("s-lead"), false, op, &|_| Ok(())).expect("fixture ledger op").1
        } else {
            self.shared.ledger_append(false, op).expect("model ledger op").1
        };
        self.shared.take_emitted();
        state
    }

    /// Store `text` as a tool output and declare `tool` (of `class`) as the call that produced it.
    /// Returns the handle (`out:…`).
    pub fn output(&self, text: &str, tool: &str, class: ToolClass) -> String {
        let blob = self.env.ctx.blobs.put_bytes(text.as_bytes()).expect("store output");
        self.orch.produced(&blob, "s-test", "call-0", tool, class);
        blob.handle()
    }
}

/// The registry of a role that has the three box tools (and the job tools that follow their jobs).
pub fn box_registry() -> Registry {
    box_rig().registry
}

/// A session `s-test` whose role is the core worker with the box tools added; its box is not configured.
pub fn box_rig() -> Rig {
    let mut role = core_role("worker");
    role.tools = ["box_exec", "box_get", "box_reset", "job_wait", "job_kill", "out_read"].iter().map(|s| s.to_string()).collect();
    rig_with(role, false, false, AgentsCfg::default())
}
