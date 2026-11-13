//! An opt-in, bounded chain of literal native actions. Guards never generate arguments.

use loom_core::event::{ToolClass, ToolResult, ToolStatus, META_EXIT_CODE};
use loom_core::{sha256_hex, CallId};
use loom_tools::{check_arguments, Registry, ToolCtx};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::io::Read;

pub const MAX_NODES: usize = 8;
const MAX_GUARDS: usize = 32;
const MAX_PLAN_BYTES: usize = 65_536;
const MAX_GUARD_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Guard {
    Start,
    PreviousSuccess,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeInput {
    pub tool: String,
    pub arguments: Map<String, Value>,
    pub guard: Guard,
    #[serde(default)]
    pub unchanged: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanInput {
    pub nodes: Vec<NodeInput>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FileGuard {
    pub given: String,
    pub resolved: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Node {
    pub tool: String,
    pub arguments: String,
    pub arguments_hash: String,
    pub guard: Guard,
    pub files: Vec<FileGuard>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Receipt {
    pub call_id: CallId,
    pub successful: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Plan {
    pub id: String,
    pub source_call: CallId,
    pub nodes: Vec<Node>,
    pub cursor: usize,
    pub previous: Option<Receipt>,
    pub mission_hash: String,
}

fn hash_file(ctx: &ToolCtx, given: &str) -> Result<(String, String), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = ctx.sandbox.check_read(&ctx.sandbox.resolve(given))?;
    if !std::fs::metadata(&path).map_err(|e| format!("Cannot guard {given}: {e}."))?.is_file() {
        return Err(format!("The guard {given} must name a regular file."));
    }
    // A path can change to a FIFO between metadata and open. Nonblocking open plus the
    // descriptor check rejects it without hanging the session's cancellation/budget loop.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&path)
        .map_err(|e| format!("Cannot guard {given}: {e}."))?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err(format!("The guard {given} must name a regular file."));
    }
    let mut bytes = Vec::new();
    file.take(MAX_GUARD_BYTES + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_GUARD_BYTES {
        return Err(format!("The guard {given} exceeds the 16 MiB prototype limit."));
    }
    Ok((path.to_string_lossy().into_owned(), sha256_hex(&bytes)))
}

pub fn mission_hash(shared: &crate::rtools::Shared) -> Result<String, String> {
    if shared.journal.is_none() {
        return Ok("no-mission".to_string());
    }
    let ledger = shared.ledger()?;
    let bytes =
        serde_json::to_vec(&(&ledger.goal, &ledger.constraints, &ledger.approvals)).map_err(|e| e.to_string())?;
    Ok(sha256_hex(&bytes))
}

impl Plan {
    pub fn prepare(input: PlanInput, ctx: &ToolCtx, allowed: &[String], mission_hash: String) -> Result<Self, String> {
        if input.nodes.is_empty() || input.nodes.len() > MAX_NODES {
            return Err("Give between 1 and 8 literal action nodes.".into());
        }
        if serde_json::to_vec(&input).map_err(|e| e.to_string())?.len() > MAX_PLAN_BYTES {
            return Err("The plan exceeds the 64 KiB prototype limit.".into());
        }
        let builtin = Registry::builtin();
        let mut guards = 0usize;
        let mut nodes = Vec::new();
        for (index, node) in input.nodes.into_iter().enumerate() {
            if (index == 0 && node.guard != Guard::Start) || (index > 0 && node.guard != Guard::PreviousSuccess) {
                return Err("Use guard `start` for the first node and `previous_success` for every successor.".into());
            }
            if !allowed.contains(&node.tool) {
                return Err(format!("The role does not grant `{}`; the plan was not queued.", node.tool));
            }
            let tool = builtin.get(&node.tool).ok_or_else(|| "Only built-in observation, file and process tools may be stored; state, agent and terminal tools require the actor.".to_string())?;
            if !matches!(tool.spec().class, ToolClass::Read | ToolClass::Nav | ToolClass::Write | ToolClass::Exec) {
                return Err("This built-in tool is not eligible for stored execution.".into());
            }
            let arguments = serde_json::to_string(&node.arguments).map_err(|e| e.to_string())?;
            check_arguments(&tool.spec(), &arguments)?;
            guards = guards.saturating_add(node.unchanged.len());
            if guards > MAX_GUARDS {
                return Err("A plan may guard at most 32 files in total.".into());
            }
            let mut files = Vec::new();
            for given in node.unchanged {
                let (resolved, sha256) = hash_file(ctx, &given)?;
                files.push(FileGuard { given, resolved, sha256 });
            }
            let arguments_hash =
                sha256_hex(serde_json::to_string(&(&node.tool, &arguments)).map_err(|e| e.to_string())?.as_bytes());
            nodes.push(Node { tool: node.tool, arguments, arguments_hash, guard: node.guard, files });
        }
        Ok(Self {
            id: format!("gp-{}", ctx.call_id),
            source_call: ctx.call_id.clone(),
            nodes,
            cursor: 0,
            previous: None,
            mission_hash,
        })
    }

    pub fn next(&self) -> Option<&Node> {
        self.nodes.get(self.cursor)
    }

    pub fn check(&self, ctx: &ToolCtx, current_mission_hash: &str) -> Result<(), String> {
        if self.mission_hash != current_mission_hash {
            return Err("Mission goal, constraints or approvals changed.".into());
        }
        let node = self.next().ok_or_else(|| "The stored plan is exhausted.".to_string())?;
        if node.guard == Guard::PreviousSuccess && !self.previous.as_ref().is_some_and(|r| r.successful) {
            return Err("The predecessor has no successful completed native receipt.".into());
        }
        for file in &node.files {
            let (resolved, hash) = hash_file(ctx, &file.given)?;
            if resolved != file.resolved || hash != file.sha256 {
                return Err(format!("The guarded input {} changed.", file.given));
            }
        }
        Ok(())
    }

    pub fn advance(&mut self, result: &ToolResult) {
        let successful = result.status == ToolStatus::Ok
            && (result.class != ToolClass::Exec || result.meta.get(META_EXIT_CODE).and_then(Value::as_i64) == Some(0));
        self.previous = Some(Receipt { call_id: result.call_id.clone(), successful });
        self.cursor = self.cursor.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loom_tools::testutil::env;
    use serde_json::json;

    fn plan(value: Value, ctx: &ToolCtx) -> Plan {
        Plan::prepare(serde_json::from_value(value).unwrap(), ctx, &["bash".into(), "read".into()], "mission".into())
            .unwrap()
    }

    #[test]
    fn literal_arguments_and_file_guards_are_immutable() {
        let e = env();
        std::fs::write(e.ctx.workspace.join("input"), "old").unwrap();
        let p = plan(
            json!({"nodes":[{"tool":"bash","arguments":{"command":"printf unchanged"},"guard":"start","unchanged":["input"]}]}),
            &e.ctx,
        );
        assert_eq!(p.next().unwrap().arguments, r#"{"command":"printf unchanged"}"#);
        assert!(p.check(&e.ctx, "mission").is_ok());
        std::fs::write(e.ctx.workspace.join("input"), "new").unwrap();
        assert!(p.check(&e.ctx, "mission").unwrap_err().contains("changed"));
        assert!(p.check(&e.ctx, "new mission").is_err());
    }

    #[test]
    fn file_guards_reject_fifos_and_retargeted_symlinks() {
        let e = env();
        let fifo = e.ctx.workspace.join("pipe");
        assert!(std::process::Command::new("mkfifo").arg(&fifo).status().unwrap().success());
        assert!(hash_file(&e.ctx, "pipe").unwrap_err().contains("regular file"));
        std::fs::write(e.ctx.workspace.join("a"), "same bytes").unwrap();
        std::fs::write(e.ctx.workspace.join("b"), "same bytes").unwrap();
        let link = e.ctx.workspace.join("link");
        std::os::unix::fs::symlink(e.ctx.workspace.join("a"), &link).unwrap();
        let p = plan(
            json!({"nodes":[{"tool":"bash","arguments":{"command":"true"},"guard":"start","unchanged":["link"]}]}),
            &e.ctx,
        );
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(e.ctx.workspace.join("b"), &link).unwrap();
        assert!(p.check(&e.ctx, "mission").unwrap_err().contains("changed"));
    }

    #[test]
    fn no_permissions_or_runtime_tools_are_added_by_a_plan() {
        let e = env();
        for tool in ["finish", "agent_spawn", "plan", "web_fetch"] {
            let input =
                serde_json::from_value(json!({"nodes":[{"tool":tool,"arguments":{},"guard":"start"}]})).unwrap();
            assert!(Plan::prepare(input, &e.ctx, &[tool.into()], "m".into()).is_err());
        }
        let input =
            serde_json::from_value(json!({"nodes":[{"tool":"bash","arguments":{"command":"true"},"guard":"start"}]}))
                .unwrap();
        assert!(Plan::prepare(input, &e.ctx, &[], "m".into()).is_err());
    }

    #[test]
    fn successors_require_an_actual_completed_receipt() {
        let e = env();
        let mut p = plan(
            json!({"nodes":[{"tool":"bash","arguments":{"command":"true"},"guard":"start"},{"tool":"read","arguments":{"path":"x"},"guard":"previous_success"}]}),
            &e.ctx,
        );
        let mut receipt = ToolResult {
            call_id: "actual".into(),
            name: "bash".into(),
            status: ToolStatus::Ok,
            text: "running".into(),
            output: None,
            cut: false,
            class: ToolClass::Exec,
            meta: Map::new(),
            duration_ms: 1,
        };
        p.advance(&receipt);
        assert!(p.check(&e.ctx, "mission").is_err());
        p.cursor = 0;
        receipt.meta.insert(META_EXIT_CODE.into(), json!(0));
        p.advance(&receipt);
        assert!(p.check(&e.ctx, "mission").is_ok());
        p.cursor = 0;
        receipt.status = ToolStatus::Error;
        p.advance(&receipt);
        assert!(p.check(&e.ctx, "mission").is_err());
    }
}
