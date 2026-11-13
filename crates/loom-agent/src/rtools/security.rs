//! Typed mission security state tools.
//!
//! CONTRACT. `security_record { operation }` parses a deny-unknown-fields `SecurityOp`, resolves
//! security-ID prefixes/aliases, checks actual session capabilities, then appends one sealed op.
//! The lead opens/prioritizes hypotheses. Only an independent child with `read_only` and `verdict`
//! may close one, and only its original lead may reprioritize it. The core checks all evidence and
//! coverage invariants under the journal lock. Batches have the same authorization as individual ops.
//!
//! `security_query` returns JSON for state/assets/coverage/revisit/hypotheses/facts/why/what_if/
//! resolve/path_suggest. Hypothetical changes never write. Rule evaluation reports its bounds and
//! incomplete closures. Path suggestions are bounded heuristics, not confirmed attack paths.
//!
//! `security_ingest` reads an existing observed blob (<=2 MiB, <=500 discovered assets), not model
//! text. It requires attested mission evidence referring to that exact blob, parses a documented
//! scanner format, and appends one atomic batch of asset observations. Every candidate is parsed
//! and validated before any append; malformed/unsupported formats fail with no partial import.
//! External/entity-bearing XML DTDs are refused (the inert nmaprun declaration is accepted). Scanner
//! labels never become confirmed vulnerabilities or scope grants.

mod scanners;

use super::{observed_producer, Shared};
use async_trait::async_trait;
use loom_core::event::{ToolClass, ToolSpec};
use loom_core::ledger::LedgerOp;
use loom_core::security_state::{Fact, SecurityOp, SecurityState};
use loom_tools::params::{opt, req, spec};
use loom_tools::{Body, Tool, ToolCtx, ToolOutput};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::sync::Arc;

pub struct SecurityRecord(pub Arc<Shared>);
pub struct SecurityQuery(pub Arc<Shared>);
pub struct SecurityIngest(pub Arc<Shared>);

fn decode<T: DeserializeOwned>(value: Option<&Value>, name: &str) -> Result<T, String> {
    serde_json::from_value(value.cloned().unwrap_or(Value::Null))
        .map_err(|e| format!("Correct `{name}` before retrying: {e}. Nothing was recorded."))
}

fn output(value: &impl Serialize) -> ToolOutput {
    match serde_json::to_vec_pretty(value) {
        Ok(bytes) => ToolOutput::ok("security state", Body::Raw(bytes)),
        Err(_) => {
            ToolOutput::error("The security state could not be serialized; report this harness fault to the operator.")
        }
    }
}

fn authorize(shared: &Shared, state: &SecurityState, op: &SecurityOp) -> Result<(), String> {
    let lead = !shared.is_child();
    let judge = shared.is_child() && shared.role.read_only && shared.role.tools.iter().any(|t| t == "verdict");
    match op {
        SecurityOp::Batch { operations } => {
            for op in operations {
                authorize(shared, state, op)?;
            }
        }
        SecurityOp::HypothesisOpen { .. } if !lead => {
            return Err("Only the mission lead may open a hypothesis; send the proposed hypothesis to the lead.".into())
        }
        SecurityOp::HypothesisPriority { id, .. }
            if !lead || state.hypotheses.get(id).is_some_and(|h| h.owner != shared.session) =>
        {
            return Err(
                "Only the hypothesis's original lead may change its priority; send the proposed change to that lead."
                    .into(),
            );
        }
        SecurityOp::HypothesisVerdict { id, .. }
            if !judge || state.hypotheses.get(id).is_some_and(|h| h.owner == shared.session) =>
        {
            return Err("A hypothesis verdict requires an independent read-only child with the verdict tool; ask the mission verifier to review it.".into());
        }
        _ => {}
    }
    Ok(())
}

fn resolve_op(state: &SecurityState, op: &mut SecurityOp) -> Result<(), String> {
    let resolve = |s: &mut String| -> Result<(), String> {
        // Full content IDs may be introduced earlier in this batch. Core validation still requires
        // the referenced record to exist at the exact point of use, under the journal lock.
        if s.len() == 67 && ["as-", "cr-", "fh-", "cs-", "hy-", "rl-", "ft-", "ru-"].iter().any(|p| s.starts_with(p)) {
            return Ok(());
        }
        *s = state.resolve(s)?;
        Ok(())
    };
    match op {
        SecurityOp::Batch { operations } => {
            // Full canonical IDs allow forward references to earlier ops in an atomic scanner batch.
            // Core validation resolves the staged batch; aliases/prefixes refer to current records.
            for op in operations {
                resolve_op(state, op)?;
            }
        }
        SecurityOp::AssetUpsert { asset } => {
            if let Some(p) = &mut asset.parent {
                if !p.starts_with("as-") || p.len() != 67 {
                    resolve(p)?;
                }
            }
        }
        SecurityOp::CredentialAdd { credential } => resolve(&mut credential.asset)?,
        SecurityOp::FootholdAdd { foothold } => resolve(&mut foothold.asset)?,
        SecurityOp::CoverageSet { asset, .. } => resolve(asset)?,
        SecurityOp::HypothesisPriority { id, .. }
        | SecurityOp::HypothesisEvidence { id, .. }
        | SecurityOp::HypothesisVerdict { id, .. }
        | SecurityOp::FactRetract { id, .. }
        | SecurityOp::RuleRetract { id, .. } => resolve(id)?,
        SecurityOp::AliasAdd { target, .. } => resolve(target)?,
        SecurityOp::RelationAdd { relation } => {
            resolve(&mut relation.from)?;
            resolve(&mut relation.to)?;
        }
        _ => {}
    }
    Ok(())
}

fn resolve_secrets(ctx: &ToolCtx, op: &mut SecurityOp) -> Result<(), String> {
    match op {
        SecurityOp::CredentialAdd { credential } => {
            let id = ctx.blobs.resolve(&credential.secret_handle).map_err(|_| {
                "Use an existing stored out: handle for the credential secret; no secret material was recorded."
                    .to_string()
            })?;
            credential.secret_handle = format!("out:{id}");
        }
        SecurityOp::Batch { operations } => {
            for op in operations {
                resolve_secrets(ctx, op)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[async_trait]
impl Tool for SecurityRecord {
    fn spec(&self) -> ToolSpec {
        spec("security_record", "Record typed evidence-linked security observations. operation.action is asset_upsert, credential_add (secret_handle only), foothold_add, condition_unlock, blocked_on, coverage_set, crash_record, hypothesis_open, hypothesis_priority, hypothesis_evidence, hypothesis_verdict, relation_add, fact_assert, fact_retract, rule_install, rule_retract, alias_add, or batch. Use security_query to inspect exact IDs. Assets: {action:asset_upsert,asset:{kind:host|service|endpoint|file|identity,locator:string,evidence:[e1],mandatory:true,parent?:assetID}}. Coverage: {action:coverage_set,asset:ID,disposition:{status:tested,evidence:[e1]}}, or {status:deferred,reason:string}. Facts: {action:fact_assert,fact:{predicate:string,args:[string]},evidence:[e1]}. Rules: {action:rule_install,rule:{name:string,head:{predicate:string,args:[?x]},body:[{atom:{predicate:string,args:[?x]},negated:false}]}}. Every evidence ID must already exist and be attested. These observations never authorize network access.", ToolClass::State,
            &[req("operation", "object", "A SecurityOp object with action and its typed fields.")])
    }
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let mut op: SecurityOp = match decode(args.get("operation"), "operation") {
            Ok(op) => op,
            Err(e) => return ToolOutput::error(e),
        };
        let state = match self.0.ledger() {
            Ok(s) => s,
            Err(e) => return ToolOutput::error(e),
        };
        if let Err(e) = resolve_op(&state.security, &mut op)
            .and_then(|_| resolve_secrets(ctx, &mut op))
            .and_then(|_| authorize(&self.0, &state.security, &op))
        {
            return ToolOutput::error(e);
        }
        // Shared::ledger_append serializes all structural validation and writes under the journal lock.
        match self.0.ledger_append(false, LedgerOp::Security(op)) {
            Ok((entry, state)) => output(&json!({"entry":entry.n,"state":state.security})),
            Err(e) => ToolOutput::error(e),
        }
    }
}

#[async_trait]
impl Tool for SecurityQuery {
    fn spec(&self) -> ToolSpec {
        spec("security_query", "Read durable security state. why needs fact; what_if accepts assumed facts and retracted base/rule IDs without changing the journal. path_suggest returns at most three bounded investigation hints over explicit relations, excluding expired edges; it does not establish exploitability or authorize a target. Rule closure complete=false means some conclusions are unknown.", ToolClass::State, &[
            req("view", "string", "The view.").one_of(&["state","assets","coverage","revisit","hypotheses","facts","why","what_if","resolve","path_suggest"]),
            opt("target", "string", "Exact ID, alias, or unambiguous prefix for resolve."),
            opt("fact", "object", "Ground {predicate,args} to explain."),
            opt("assume", "array", "Ground facts for what_if.").items("object"),
            opt("retract", "array", "Base fact or rule IDs to omit hypothetically.").items("string"),
            opt("from", "string", "Start asset for path_suggest."), opt("to", "string", "Goal asset for path_suggest."),
            opt("now_ms", "integer", "Expiry evaluation time, default current UTC milliseconds.").min(0),
        ])
    }
    async fn run(&self, _ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let ledger = match self.0.ledger() {
            Ok(s) => s,
            Err(e) => return ToolOutput::error(e),
        };
        let state = ledger.security;
        let view = args.get("view").and_then(Value::as_str).unwrap_or("state");
        let value = match view {
            "state" => return output(&state),
            "assets" => return output(&state.assets),
            "coverage" => json!({"mandatory_open":state.mandatory_open(),"assets":state.assets}),
            "revisit" => {
                let now_ms = args.get("now_ms").and_then(Value::as_u64).unwrap_or_else(loom_core::now_ms);
                json!({"unlocked_routes":state.newly_unlocked_at(now_ms),"now_ms":now_ms,
                    "blocked":state.blocked,"conditions":state.unlocked})
            }
            "hypotheses" => return output(&state.hypotheses),
            "facts" => return output(&state.projection()),
            "why" => {
                let fact: Fact = match decode(args.get("fact"), "fact") {
                    Ok(f) => f,
                    Err(e) => return ToolOutput::error(e),
                };
                let projection = state.projection();
                json!({"explanation":projection.why(&fact),"complete":projection.complete,"limitation":projection.limitation})
            }
            "what_if" => {
                let assume: Vec<Fact> = match decode(Some(args.get("assume").unwrap_or(&json!([]))), "assume") {
                    Ok(v) => v,
                    Err(e) => return ToolOutput::error(e),
                };
                if assume.len() > 128 || assume.iter().any(|f| f.validate().is_err()) {
                    return ToolOutput::error("Give at most 128 valid ground facts for a hypothetical query.");
                }
                let mut retract: Vec<String> = match decode(Some(args.get("retract").unwrap_or(&json!([]))), "retract")
                {
                    Ok(v) => v,
                    Err(e) => return ToolOutput::error(e),
                };
                if retract.len() > 128 {
                    return ToolOutput::error("Retract at most 128 IDs in a hypothetical query.");
                }
                for id in &mut retract {
                    match state.resolve(id) {
                        Ok(v) => *id = v,
                        Err(e) => return ToolOutput::error(e),
                    }
                }
                return output(&state.what_if(&assume, &retract));
            }
            "resolve" => match state.resolve(args.get("target").and_then(Value::as_str).unwrap_or("")) {
                Ok(id) => json!({"id":id}),
                Err(e) => return ToolOutput::error(e),
            },
            "path_suggest" => {
                let from = match state.resolve(args.get("from").and_then(Value::as_str).unwrap_or("")) {
                    Ok(v) => v,
                    Err(e) => return ToolOutput::error(e),
                };
                let to = match state.resolve(args.get("to").and_then(Value::as_str).unwrap_or("")) {
                    Ok(v) => v,
                    Err(e) => return ToolOutput::error(e),
                };
                let now_ms = args.get("now_ms").and_then(Value::as_u64).unwrap_or_else(loom_core::now_ms);
                json!({"paths":state.path_suggest(&from,&to,now_ms),"now_ms":now_ms,
                    "limitation":"At most three simple paths, eight hops, and 10000 search expansions. Investigation hints; no exploitability claim."})
            }
            _ => return ToolOutput::error("Choose a supported security_query view from its tool schema."),
        };
        output(&value)
    }
}

#[async_trait]
impl Tool for SecurityIngest {
    fn spec(&self) -> ToolSpec {
        spec("security_ingest", "Import asset observations from an existing scanner-output blob. Supply attested evidence IDs citing that exact output; record evidence first. Supported formats: nmap XML, nuclei JSONL, ffuf JSON, netexec JSON, BloodHound JSON. Scanner hits remain unverified observations and grant no scope. No scans or network requests are performed.", ToolClass::State, &[
            req("format", "string", "Scanner format.").one_of(&["nmap","nuclei","ffuf","netexec","bloodhound"]),
            req("handle", "string", "Existing observed out: handle of scanner output."),
            req("evidence", "array", "Attested evidence IDs citing the scanner output.").items("string"),
        ])
    }
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let ledger = match self.0.ledger() {
            Ok(s) => s,
            Err(e) => return ToolOutput::error(e),
        };
        let Some(mission) = self.0.mission.as_ref() else {
            return ToolOutput::error(super::NO_MISSION);
        };
        let handle = args.get("handle").and_then(Value::as_str).unwrap_or("");
        let blob = match ctx.blobs.resolve(handle) {
            Ok(b) => b,
            Err(e) => return ToolOutput::error(format!("Open a valid scanner output handle first: {e}.")),
        };
        if let Err(e) = observed_producer(&self.0, mission, handle, &blob).await {
            return ToolOutput::error(e);
        }
        let evidence: Vec<String> = match decode(args.get("evidence"), "evidence") {
            Ok(v) => v,
            Err(e) => return ToolOutput::error(e),
        };
        if evidence.is_empty()
            || evidence.len() > 128
            || evidence.iter().any(|id| {
                !ledger.evidence.iter().any(|e| &e.id == id && e.input.attested && e.input.blob.as_ref() == Some(&blob))
            })
        {
            return ToolOutput::error(
                "Cite one to 128 attested evidence IDs referring to this exact scanner output blob.",
            );
        }
        match ctx.blobs.meta(&blob) {
            Ok(meta) if meta.bytes <= 2 * 1024 * 1024 => {}
            Ok(_) => {
                return ToolOutput::error("Scanner imports are limited to 2 MiB; split the output before importing it.")
            }
            Err(e) => return ToolOutput::error(format!("The scanner output could not be read: {e}.")),
        }
        let bytes = match ctx.blobs.read_all(&blob) {
            Ok(b) => b,
            Err(e) => return ToolOutput::error(format!("Read the scanner output again before importing it: {e}.")),
        };
        if bytes.len() > 2 * 1024 * 1024 {
            return ToolOutput::error("The scanner output exceeds 2 MiB; nothing was imported.");
        }
        let format = args.get("format").and_then(Value::as_str).unwrap_or("");
        let assets = match scanners::parse(format, &bytes, &evidence) {
            Ok(v) => v,
            Err(e) => return ToolOutput::error(e),
        };
        let count = assets.len();
        let operations = assets.into_iter().map(|asset| SecurityOp::AssetUpsert { asset }).collect();
        match self.0.ledger_append(false, LedgerOp::Security(SecurityOp::Batch { operations })) {
            Ok((entry, state)) => output(
                &json!({"entry":entry.n,"parsed_assets":count,"canonical_assets":state.security.assets.len(),"scope_granted":false}),
            ),
            Err(e) => ToolOutput::error(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::testkit::{core_role, rig_with, Rig};
    use super::*;
    use loom_core::config::AgentsCfg;
    use loom_core::event::ToolStatus as Status;
    use loom_core::ledger::{EvidenceInput, EvidenceKind};
    use loom_core::security_state::{stable_id, HypothesisStatus};

    fn rig(role: &str, child: bool, mission: bool) -> Rig {
        let mut role = core_role(role);
        role.tools.extend(["security_record".into(), "security_query".into(), "security_ingest".into()]);
        rig_with(role, child, mission, AgentsCfg::default())
    }
    fn evidence(r: &Rig, handle: &str) {
        r.model_op(LedgerOp::ClaimAdd { text: "scanner output observed".into() });
        let blob = r.env.ctx.blobs.resolve(handle).unwrap();
        r.model_op(LedgerOp::EvidenceAdd(EvidenceInput {
            claim: "c1".into(),
            kind: EvidenceKind::Execution,
            supports: true,
            session: "s-source".into(),
            call_id: "call-source".into(),
            blob: Some(blob),
            lines: None,
            quote: None,
            note: "synthetic scanner fixture".into(),
            attested: true,
        }));
    }

    #[tokio::test]
    async fn lead_cannot_self_judge_and_child_cannot_own_priority() {
        let r = rig("lead", false, true);
        let open = r
            .call("security_record", json!({"operation":{"action":"hypothesis_open","text":"candidate","priority":7}}))
            .await;
        assert_eq!(open.status, Status::Ok, "{}", open.text);
        let id = stable_id("hy", &["candidate"]);
        let verdict=r.call("security_record",json!({"operation":{"action":"hypothesis_verdict","id":id,"status":"supported","note":"self review","evidence":["e1"],"counterevidence":[]}})).await;
        assert_eq!(verdict.status, Status::Error);
        assert!(verdict.text.contains("independent"));
        let child = rig("worker", true, true);
        let open = child
            .call("security_record", json!({"operation":{"action":"hypothesis_open","text":"candidate","priority":7}}))
            .await;
        assert_eq!(open.status, Status::Error);
        assert!(child.shared.ledger().unwrap().security.hypotheses.is_empty());
        let judge = rig("verifier", true, true);
        let h = judge.output("synthetic evidence", "bash", ToolClass::Exec);
        evidence(&judge, &h);
        judge
            .shared
            .journal
            .as_ref()
            .unwrap()
            .append(
                &"s-lead".into(),
                false,
                LedgerOp::Security(SecurityOp::HypothesisOpen { text: "candidate".into(), priority: 7 }),
                &|_| Ok(()),
            )
            .unwrap();
        let verdict=judge.call("security_record",json!({"operation":{"action":"hypothesis_verdict","id":id,"status":"supported","note":"independent observed review","evidence":["e1"],"counterevidence":[]}})).await;
        assert_eq!(verdict.status, Status::Ok, "{}", verdict.text);
        assert_eq!(
            judge.shared.ledger().unwrap().security.hypotheses.get(&id).unwrap().status,
            HypothesisStatus::Supported
        );
        let priority = judge
            .call("security_record", json!({"operation":{"action":"hypothesis_priority","id":id,"priority":99}}))
            .await;
        assert_eq!(priority.status, Status::Error);
        judge.model_op(LedgerOp::EvidenceAdd(EvidenceInput {
            claim: "c1".into(),
            kind: EvidenceKind::Execution,
            supports: false,
            session: "s-source".into(),
            call_id: "call-counter".into(),
            blob: None,
            lines: None,
            quote: None,
            note: "opposing fixture observation".into(),
            attested: true,
        }));
        let counter = judge
            .call(
                "security_record",
                json!({"operation":{"action":"hypothesis_evidence","id":id,
            "evidence":[],"counterevidence":["e2"]}}),
            )
            .await;
        assert_eq!(counter.status, Status::Ok, "{}", counter.text);
        assert_eq!(judge.shared.ledger().unwrap().security.hypotheses.get(&id).unwrap().status, HypothesisStatus::Open);
        let ignored = judge
            .call(
                "security_record",
                json!({"operation":{"action":"hypothesis_verdict","id":id,
            "status":"supported","note":"counterevidence ignored","evidence":["e1"],"counterevidence":[]}}),
            )
            .await;
        assert_eq!(ignored.status, Status::Error);
        assert!(ignored.text.contains("counterevidence"));
    }

    #[tokio::test]
    async fn ingest_requires_exact_observed_blob_evidence_and_is_atomic() {
        let r = rig("lead", false, true);
        let good = r.output(r#"{"results":[{"url":"https://example.test/"}]}"#, "bash", ToolClass::Exec);
        evidence(&r, &good);
        let bad = r.output("{bad json}", "bash", ToolClass::Exec);
        let res = r.call("security_ingest", json!({"format":"ffuf","handle":bad,"evidence":["e1"]})).await;
        assert_eq!(res.status, Status::Error);
        assert!(res.text.contains("exact scanner output"));
        let res = r.call("security_ingest", json!({"format":"ffuf","handle":good,"evidence":["e1"]})).await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        assert_eq!(r.shared.ledger().unwrap().security.assets.len(), 1);
        assert!(r.shared.ledger().unwrap().scope_grants.is_empty());
        let before = r.shared.ledger().unwrap().entries;
        let res = r
            .call(
                "security_record",
                json!({"operation":{"action":"batch","operations":[
                    {"action":"asset_upsert","asset":{"kind":"host","locator":"new.test","evidence":["e1"]}},
                    {"action":"fact_assert","fact":{"predicate":"bad","args":["?variable"]},"evidence":["e1"]}
                ]}}),
            )
            .await;
        assert_eq!(res.status, Status::Error);
        assert_eq!(r.shared.ledger().unwrap().entries, before);
        assert_eq!(r.shared.ledger().unwrap().security.assets.len(), 1);
        let nmap = r.output(r#"<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host></nmaprun>"#,
            "bash",ToolClass::Exec);
        evidence(&r, &nmap);
        let res = r.call("security_ingest", json!({"format":"nmap","handle":nmap,"evidence":["e2"]})).await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        let state = r.shared.ledger().unwrap();
        assert_eq!(state.security.assets.len(), 3);
        assert_eq!(state.security.relations.len(), 1);
    }

    #[tokio::test]
    async fn credentials_require_existing_handles_and_deduplicate_canonical_handles() {
        let r = rig("lead", false, true);
        let observed = r.output("fixture account observed", "bash", ToolClass::Exec);
        evidence(&r, &observed);
        let asset = loom_core::security_state::AssetInput {
            kind: loom_core::security_state::AssetKind::Host,
            locator: "fixture.test".into(),
            evidence: vec!["e1".into()],
            mandatory: true,
            parent: None,
        };
        let id = asset.id().unwrap();
        r.model_op(LedgerOp::Security(SecurityOp::AssetUpsert { asset }));
        let invalid = r
            .call(
                "security_record",
                json!({"operation":{"action":"credential_add","credential":{
            "asset":id,"principal":"dummy","secret_handle":"raw-secret-must-not-persist","evidence":["e1"]}}}),
            )
            .await;
        assert_eq!(invalid.status, Status::Error);
        assert!(r.shared.ledger().unwrap().security.credentials.is_empty());
        let secret = r.output("dummy fixture secret", "read", ToolClass::Read);
        let full = format!("out:{}", r.env.ctx.blobs.resolve(&secret).unwrap());
        for handle in [&secret, &full] {
            let added = r
                .call(
                    "security_record",
                    json!({"operation":{"action":"credential_add","credential":{
                "asset":id,"principal":"dummy","secret_handle":handle,"evidence":["e1"]}}}),
                )
                .await;
            assert_eq!(added.status, Status::Ok, "{}", added.text);
        }
        let state = r.shared.ledger().unwrap();
        assert_eq!(state.security.credentials.len(), 1);
        let json = serde_json::to_string(&state.security).unwrap();
        assert!(!json.contains("dummy fixture secret"));
        assert!(!json.contains("raw-secret-must-not-persist"));
    }

    #[tokio::test]
    async fn queries_do_not_append_and_missionless_tools_refuse() {
        let r = rig("lead", false, true);
        let before = r.shared.ledger().unwrap().entries;
        let res =
            r.call("security_query", json!({"view":"what_if","assume":[{"predicate":"seen","args":["dummy"]}]})).await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        assert_eq!(r.shared.ledger().unwrap().entries, before);
        let r = rig("lead", false, false);
        for (name, args) in [
            ("security_query", json!({"view":"state"})),
            ("security_record", json!({"operation":{"action":"hypothesis_open","text":"x","priority":1}})),
            ("security_ingest", json!({"format":"ffuf","handle":"out:123456789abc","evidence":["e1"]})),
        ] {
            let res = r.call(name, args).await;
            assert_eq!(res.status, Status::Error);
            assert!(res.text.contains(super::super::NO_MISSION));
        }
    }
}
