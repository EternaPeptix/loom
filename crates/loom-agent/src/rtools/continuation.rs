//! Explicit, role-granted admission of a literal continuation plan.

use super::Shared;
use crate::continuation::{mission_hash, Plan, PlanInput};
use async_trait::async_trait;
use loom_core::event::{Author, Event, ToolClass, ToolSpec};
use loom_tools::{params, Body, Tool, ToolCtx, ToolOutput};
use serde_json::{json, Map, Value};
use std::sync::Arc;

pub struct GuardedPlan(pub Arc<Shared>);

#[async_trait]
impl Tool for GuardedPlan {
    fn spec(&self) -> ToolSpec {
        params::spec(
            "guarded_plan",
            "Prototype: queue up to 8 already-decided literal built-in actions. The first node uses guard start; successors require previous_success. unchanged lists regular input files to snapshot and recheck before that node. New instructions, changed standing rules/inputs, failed or incomplete receipts return control to you. Arguments are never generated or edited by the controller. Terminal, ledger and agent tools cannot be stored. Inspect every output before citing it.",
            ToolClass::State,
            &[params::req("nodes", "array", "Ordered literal nodes: tool, arguments object, guard (start or previous_success), unchanged file paths.").with("items", json!({
                "type":"object", "required":["tool","arguments","guard"], "additionalProperties":false,
                "properties":{
                    "tool":{"type":"string"}, "arguments":{"type":"object"},
                    "guard":{"type":"string","enum":["start","previous_success"]},
                    "unchanged":{"type":"array","items":{"type":"string"}}
                }
            }))],
        )
    }

    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let input: PlanInput = match serde_json::from_value(Value::Object(args.clone())) {
            Ok(input) => input,
            Err(e) => {
                return ToolOutput::error(format!("The plan is not a literal action chain: {e}. Nothing was queued."))
            }
        };
        let fingerprint = match mission_hash(&self.0) {
            Ok(hash) => hash,
            Err(e) => return ToolOutput::error(e),
        };
        let plan = match Plan::prepare(input, ctx, &self.0.role.tools, fingerprint) {
            Ok(plan) => plan,
            Err(e) => return ToolOutput::error(format!("{e} Nothing was queued.")),
        };
        let serialized = match serde_json::to_value(&plan) {
            Ok(value) => value,
            Err(e) => return ToolOutput::error(format!("The plan could not be recorded: {e}. Nothing was queued.")),
        };
        let id = plan.id.clone();
        let count = plan.nodes.len();
        if let Some(previous) = self.0.take_continuation() {
            self.0.emit(
                Author::Harness,
                Event::ContinuationStopped { plan_id: previous.id, reason: "replaced by a newly authored plan".into() },
            );
        }
        self.0.emit(
            Author::Harness,
            Event::ContinuationPlanned { plan_id: id.clone(), source_call: plan.source_call.clone(), plan: serialized },
        );
        self.0.set_continuation(plan);
        ToolOutput::ok("plan queued", Body::Message(format!("Stored plan {id}: {count} literal actions. Each dispatch rechecks guards and uses the normal tool pipeline. Queuing does not establish that an action is correct or that its output has been read.")))
    }
}
