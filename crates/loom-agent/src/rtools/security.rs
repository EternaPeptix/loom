//! Typed mission security state tools.
//!
//! CONTRACT. `security_record { operation }` (or unwrapped top-level `{ action, … }` when
//! `operation` is absent and `action` is present) reads `operation` with `shapes::read` (near misses
//! read where unambiguous, each with a note; early role refusals; exact-shape guidance on a refusal),
//! then resolves security-ID prefixes/aliases, checks actual session capabilities, synthesizes any
//! inline `out:<handle>` (or `{handle, start?, end?, quote?}`) evidence references into attested
//! `EvidenceAdd` records after shape/auth/preflight checks pass, then appends one sealed op. The lead opens/prioritizes hypotheses. Only an independent child with `read_only` and `verdict`
//! may close one, and only its original lead may reprioritize it. The core checks all evidence and
//! coverage invariants under the journal lock. Batches have the same authorization as individual ops.
//! A credential's `secret_handle` is opened with `loom_tools::outputs::open` (only an output of the
//! session's mission): any failure is ``Use an existing stored out: handle for the credential secret; no
//! secret material was recorded.``, whether the handle names nothing or another mission's output, and the
//! recorded handle is `out:{full id}`.
//! A batch element that fails ID resolution, secret-handle resolution or authorization is refused with
//! "Operation {i} of {n} in the batch ({action}): {error}", as the core names one that fails validation.
//! The asset in a `cred` or `auth` condition (`blocked_on`, `condition_unlock`, a credential's or
//! foothold's `unlocks`) is resolved from an alias or prefix to the full asset ID, because routes are
//! revisited by exact match; a value that is not an ID or alias is kept, and one that starts with `as-`
//! and matches nothing is refused.
//!
//! The caller passed to `shapes` is built from the session: `Standing::Lead` when it has no parent,
//! `Standing::Judge` when it is a child whose role is `read_only` and has the `verdict` tool,
//! `Standing::Child` otherwise; `tools` is the role's tool list. The tool description is
//! `shapes::description` of that caller. On success the result is the JSON object
//! `{"entry": n, "normalized": [notes…], "recorded": {…}, "removed": {…}, "counts": {…}, "more": "…"}`,
//! with `normalized` present only when a note was made. It names what this write changed, never the
//! whole state (after a scanner import that ran to tens of thousands of tokens at every write):
//! - *touched*: for each id-keyed collection of `SecurityState` (`assets`, `credentials`,
//!   `footholds`, `condition_evidence`, `blocked`, `revisited`, `crashes`, `vector_attempts`,
//!   `hypotheses`, `relations`, `facts`, `rules`, `aliases`), the keys whose value differs between the
//!   state read before the append and the state the append returned, new keys included; of
//!   `unlocked`, the conditions added; and `died` and `retraction_limitation` when they differ (a
//!   retraction's conclusions that no longer hold). A write by another session between the two reads
//!   shows up too.
//! - *addressed*: the ids the operation names or creates whatever the state held: the keys of every
//!   collection of a `SecurityState::default()` to which the (resolved) operation was applied, kept when
//!   the state after the append has them. An addressed id that was not touched is listed under
//!   `unchanged` (`{collection: [ids]}`), so a repeated write (an asset already known under its
//!   canonical locator, a hypothesis already open) still names its id; `unchanged` is omitted when empty.
//! - `recorded`: `{collection: {id: record}}` of the touched entries (`unlocked`: the list of added
//!   conditions; `died`: the list; `retraction_limitation`: the text), each in full, when their JSON
//!   together, pretty-printed as the result is, is at most `RECORDED_CHARS` (8 000) characters;
//!   otherwise `{collection: {"count": k, "ids": [first 20 ids, each cut to 80 characters]}}` for each
//!   collection touched (`unlocked` and `died`: the count only). Collections with nothing touched are
//!   left out.
//! - `removed`: `{collection: [ids]}` of keys present before and gone after; omitted when empty.
//! - `counts`: `{collection: number of entries}` after the write, for each non-empty collection.
//! - `more`: `The rest of the security state is unchanged by this write; read it with security_query
//!   (view: state, assets, coverage, revisit, hypotheses or facts).`
//!
//! Tests: a single upsert returns that asset in full and the counts, not the other assets; a batch
//! over the size bound returns counts and ids, and stays near the bound with long keys and many
//! conditions; a repeated hypothesis_open and an upsert of a known asset under another spelling name
//! the id under `unchanged`; a fact retraction reports `died`; a hypothesis_open returns the new hypothesis id; a
//! retraction returns the fact it deactivated (a retraction keeps the record, so `removed` stays empty; it
//! lists ids a write deletes, tested on the report itself).
//!
//! When the read operation was expanded by N4d (a single hypothesis_open carrying evidence) and
//! the append fails, the error gets the sentence " The evidence given with hypothesis_open was being
//! attached by a second operation in the same atomic append; nothing was recorded." appended.
//!
//! `security_query` returns JSON for state/assets/coverage/revisit/hypotheses/facts/why/what_if/
//! resolve/path_suggest. Hypothetical changes never write. Rule evaluation reports its bounds and
//! incomplete closures. Path suggestions are bounded heuristics, not confirmed attack paths.
//!
//! `security_ingest` reads an existing observed blob (<=2 MiB, <=500 discovered assets), not model
//! text. Its `handle` is opened with `loom_tools::outputs::open` (a refusal is `Unopened::sentence`), then
//! must pass `rtools::observed_producer`. It requires attested mission evidence referring to that exact blob, parses a documented
//! scanner format, and appends one atomic batch of asset observations (quarantined lifecycle/token
//! URLs and queryless static assets import with `mandatory = false`, ordered after application/API
//! endpoints). Every candidate is parsed
//! and validated before any append; malformed/unsupported formats fail with no partial import.
//! External/entity-bearing XML DTDs are refused (the inert nmaprun declaration is accepted). Scanner
//! labels never become confirmed vulnerabilities or scope grants.

mod scanners;
mod shapes;

use super::{observed_producer, Shared};
use crate::gate::{check_quotes, Quote};
use async_trait::async_trait;
use loom_core::event::{EvidenceGrade, ToolClass, ToolSpec};
use loom_core::ledger::{ClaimStatus, Entry, EvidenceInput, EvidenceKind, LedgerOp, LedgerState};
use loom_core::observe::{MIN_PARTIAL_QUOTE_CHARS, REF_QUOTE_MAX_CHARS, REF_QUOTE_MAX_LINES};
use loom_core::security_state::{Condition, ConditionKind, CoverageDisposition, Fact, SecurityOp, SecurityState};
use loom_core::{BlobId, MissionId};
use loom_tools::outputs;
use loom_tools::params::{opt, req, spec};
use loom_tools::{Body, Tool, ToolCtx, ToolOutput};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
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
        SecurityOp::CredentialAdd { credential } => {
            resolve(&mut credential.asset)?;
            resolve_conditions(state, &mut credential.unlocks)?;
        }
        SecurityOp::FootholdAdd { foothold } => {
            resolve(&mut foothold.asset)?;
            resolve_conditions(state, &mut foothold.unlocks)?;
        }
        SecurityOp::ConditionUnlock { conditions, .. } | SecurityOp::BlockedOn { conditions, .. } => {
            resolve_conditions(state, conditions)?;
        }
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

/// A cred or auth condition's value is an asset ID, matched exactly when routes are revisited: an alias or
/// prefix is resolved to the full ID. A value that is not an ID or alias is kept; one that looks like a
/// mistyped asset ID (`as-…`) is refused.
fn resolve_conditions(state: &SecurityState, conditions: &mut [Condition]) -> Result<(), String> {
    for condition in conditions {
        if !matches!(condition.kind, ConditionKind::Cred | ConditionKind::Auth) {
            continue;
        }
        match state.resolve(&condition.value) {
            Ok(id) if id.starts_with("as-") => condition.value = id,
            Err(e) if condition.value.starts_with("as-") && condition.value.len() != 67 => return Err(e),
            _ => {}
        }
    }
    Ok(())
}

const SECRET_HANDLE_REFUSAL: &str =
    "Use an existing stored out: handle for the credential secret; no secret material was recorded.";

/// Open every credential `secret_handle` of `op` (an output of this mission) and record it as `out:{full id}`.
fn resolve_secrets<'a>(
    ctx: &'a ToolCtx,
    op: &'a mut SecurityOp,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
    Box::pin(async move {
        match op {
            SecurityOp::CredentialAdd { credential } => {
                let id = outputs::open(ctx, &credential.secret_handle)
                    .await
                    .map_err(|_| SECRET_HANDLE_REFUSAL.to_string())?;
                credential.secret_handle = format!("out:{id}");
            }
            SecurityOp::Batch { operations } => {
                for op in operations {
                    resolve_secrets(ctx, op).await?;
                }
            }
            _ => {}
        }
        Ok(())
    })
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InlineEvidenceSpec {
    handle: String,
    #[serde(default)]
    start: Option<u64>,
    #[serde(default)]
    end: Option<u64>,
    #[serde(default)]
    quote: Option<String>,
    #[serde(default)]
    note: Option<String>,
}

struct PendingInline {
    elem_index: Option<(usize, usize, &'static str)>,
    loc_name: String,
    spec: InlineEvidenceSpec,
    input: EvidenceInput,
}

fn unique_inline_prefix(operation: &Value) -> String {
    let raw = operation.to_string();
    let mut prefix = String::from("out:__loom_inline_");
    while raw.contains(&prefix) {
        prefix.push('_');
    }
    prefix
}

/// Extract `{ "handle": ..., "start"?, "end"?, "quote"? }` objects inside `evidence`/`counterevidence`
/// arrays into `specs` and replace them with placeholder strings before `shapes::read`.
fn extract_inline_objects(val: &mut Value, prefix: &str, specs: &mut Vec<InlineEvidenceSpec>) {
    let Some(obj) = val.as_object_mut() else { return };
    for key in ["evidence", "counterevidence"] {
        if let Some(Value::Array(items)) = obj.get_mut(key) {
            for item in items.iter_mut() {
                let has_handle = item.as_object().is_some_and(|o| o.get("handle").is_some_and(Value::is_string));
                if has_handle {
                    if let Ok(spec) = serde_json::from_value::<InlineEvidenceSpec>(item.clone()) {
                        let idx = specs.len();
                        specs.push(spec);
                        *item = Value::String(format!("{prefix}{idx}__"));
                    }
                }
            }
        }
    }
    for key in ["asset", "credential", "foothold", "relation", "disposition", "attempt", "hypothesis"] {
        if let Some(child) = obj.get_mut(key) {
            extract_inline_objects(child, prefix, specs);
        }
    }
    for key in ["operations", "ops", "items"] {
        if let Some(Value::Array(items)) = obj.get_mut(key) {
            for child in items.iter_mut() {
                extract_inline_objects(child, prefix, specs);
            }
        }
    }
}

fn visit_single_op_evidence_mut(op: &mut SecurityOp, mut f: impl FnMut(bool, &mut Vec<String>)) {
    match op {
        SecurityOp::AssetUpsert { asset } => f(false, &mut asset.evidence),
        SecurityOp::CredentialAdd { credential } => f(false, &mut credential.evidence),
        SecurityOp::FootholdAdd { foothold } => f(false, &mut foothold.evidence),
        SecurityOp::ConditionUnlock { evidence, .. } => f(false, evidence),
        SecurityOp::CoverageSet { disposition: CoverageDisposition::Tested { evidence }, .. } => f(false, evidence),
        SecurityOp::CrashRecord { attempt, .. } => f(false, &mut attempt.evidence),
        SecurityOp::HypothesisEvidence { evidence, counterevidence, .. }
        | SecurityOp::HypothesisVerdict { evidence, counterevidence, .. } => {
            f(false, evidence);
            f(true, counterevidence);
        }
        SecurityOp::RelationAdd { relation } => f(false, &mut relation.evidence),
        SecurityOp::FactAssert { evidence, .. } => f(false, evidence),
        _ => {}
    }
}

fn has_inline_evidence(op: &mut SecurityOp) -> bool {
    let mut found = false;
    match op {
        SecurityOp::Batch { operations } => {
            for elem in operations {
                visit_single_op_evidence_mut(elem, |_, list| {
                    if list.iter().any(|s| s.starts_with("out:")) {
                        found = true;
                    }
                });
            }
        }
        single => visit_single_op_evidence_mut(single, |_, list| {
            if list.iter().any(|s| s.starts_with("out:")) {
                found = true;
            }
        }),
    }
    found
}

/// Choose a token-boundary prefix from an oversized line (`> REF_QUOTE_MAX_CHARS`) so `check_quotes`
/// accepts it verbatim without exceeding the quote-by-lines character limit.
fn extract_long_line_fragment(line: &str) -> String {
    let chars: Vec<(usize, char)> = line.char_indices().collect();
    let mut non_ws = 0usize;
    let mut best_end = None;
    for (i, &(byte_idx, ch)) in chars.iter().enumerate() {
        if !ch.is_whitespace() {
            non_ws = non_ws.saturating_add(1);
        }
        if non_ws >= MIN_PARTIAL_QUOTE_CHARS {
            let next_non_alnum = chars.get(i + 1).is_none_or(|&(_, next)| !next.is_alphanumeric());
            if !ch.is_alphanumeric() || next_non_alnum {
                let end = byte_idx.saturating_add(ch.len_utf8());
                best_end = Some(end);
                if i >= 120 {
                    break;
                }
            }
        }
    }
    match best_end {
        Some(end) => line.get(..end).unwrap_or(line).to_string(),
        None => line.to_string(),
    }
}

fn build_inline_quote(ctx: &ToolCtx, blob: &BlobId, spec: &InlineEvidenceSpec) -> Result<Quote, String> {
    let total = ctx
        .blobs
        .meta(blob)
        .map_err(|e| format!("The stored output {} could not be read ({e}); try again.", spec.handle))?
        .lines;
    if spec.start.is_some() || spec.end.is_some() || spec.quote.is_some() {
        let text = spec.quote.clone().unwrap_or_default();
        let start = spec.start.unwrap_or(1);
        let end = match spec.end {
            Some(e) => e,
            None => {
                if text.trim().is_empty() {
                    start
                } else {
                    total.max(start)
                }
            }
        };
        return Ok(Quote { handle: spec.handle.clone(), start, end, text });
    }
    if total == 0 {
        return Ok(Quote { handle: spec.handle.clone(), start: 1, end: 1, text: String::new() });
    }
    let mut chunk_start = 1u64;
    let mut first_nonblank: Option<u64> = None;
    while chunk_start <= total && chunk_start <= 2_000 {
        let chunk_end = chunk_start.saturating_add(REF_QUOTE_MAX_LINES - 1).min(total);
        let slice = ctx
            .blobs
            .read_lines(blob, chunk_start, chunk_end)
            .map_err(|e| format!("The stored output {} could not be read ({e}); try again.", spec.handle))?;
        if let Some(rel) = slice.text.lines().position(|l| !l.trim().is_empty()) {
            first_nonblank = Some(chunk_start.saturating_add(rel as u64));
            break;
        }
        chunk_start = chunk_end.saturating_add(1);
    }
    let Some(first_nb) = first_nonblank else {
        return Ok(Quote {
            handle: spec.handle.clone(),
            start: 1,
            end: total.min(REF_QUOTE_MAX_LINES),
            text: String::new(),
        });
    };
    let span_end = first_nb.saturating_add(REF_QUOTE_MAX_LINES - 1).min(total);
    let slice = ctx
        .blobs
        .read_lines(blob, first_nb, span_end)
        .map_err(|e| format!("The stored output {} could not be read ({e}); try again.", spec.handle))?;
    let lines: Vec<&str> = slice.text.lines().map(str::trim_end).collect();
    let Some(first_line) = lines.first().copied() else {
        return Ok(Quote { handle: spec.handle.clone(), start: first_nb, end: first_nb, text: String::new() });
    };
    if first_line.chars().count() > REF_QUOTE_MAX_CHARS {
        return Ok(Quote {
            handle: spec.handle.clone(),
            start: first_nb,
            end: first_nb,
            text: extract_long_line_fragment(first_line),
        });
    }
    let mut acc_chars = 0usize;
    let mut last_nb = 0usize;
    for (idx, line) in lines.iter().enumerate() {
        let next_chars = if idx == 0 {
            line.chars().count()
        } else {
            acc_chars.saturating_add(1).saturating_add(line.chars().count())
        };
        if next_chars > REF_QUOTE_MAX_CHARS {
            break;
        }
        acc_chars = next_chars;
        if !line.is_empty() {
            last_nb = idx;
        }
    }
    let end = first_nb.saturating_add(last_nb as u64);
    Ok(Quote { handle: spec.handle.clone(), start: first_nb, end, text: String::new() })
}

fn pick_target_claim(shared: &Shared, state: &LedgerState) -> Result<Option<String>, String> {
    let judge_evidence = shared.is_child()
        && shared.role.read_only
        && shared.role.tools.iter().any(|t| t == "evidence")
        && shared.role.tools.iter().any(|t| t == "verdict");
    if shared.role.read_only && !judge_evidence {
        return Err(
            "This role has read-only access to the mission ledger. Return observations through its report or verdict."
                .into(),
        );
    }
    if !shared.is_child() || judge_evidence {
        let picked = state
            .claims
            .iter()
            .rev()
            .find(|c| c.status == ClaimStatus::Open)
            .or_else(|| state.claims.last())
            .map(|c| c.id.clone());
        if picked.is_none() && judge_evidence {
            return Err(
                "No claim exists in the ledger yet; the mission lead must add a claim before a read-only verifier \
                 can attach evidence."
                    .into(),
            );
        }
        return Ok(picked);
    }
    let own = |only_open: bool| {
        state.claims.iter().enumerate().rev().find_map(|(i, c)| {
            let owned = state.claim_sessions.get(i).is_some_and(|s| *s == shared.session);
            (owned && (!only_open || c.status == ClaimStatus::Open)).then(|| c.id.clone())
        })
    };
    Ok(own(true).or_else(|| own(false)))
}

fn format_batch_err(elem_index: Option<(usize, usize, &'static str)>, msg: String) -> String {
    match elem_index {
        Some((i, n, action)) => format!("Operation {i} of {n} in the batch ({action}): {msg}"),
        None => msg,
    }
}

fn parse_inline_spec(raw: &str, prefix: &str, specs: &[InlineEvidenceSpec]) -> InlineEvidenceSpec {
    if let Some(idx) =
        raw.strip_prefix(prefix).and_then(|rest| rest.strip_suffix("__")).and_then(|n| n.parse::<usize>().ok())
    {
        if let Some(spec) = specs.get(idx) {
            return spec.clone();
        }
    }
    InlineEvidenceSpec { handle: raw.to_string(), start: None, end: None, quote: None, note: None }
}

async fn resolve_one_inline(
    shared: &Shared,
    mission: &MissionId,
    ctx: &ToolCtx,
    spec: &InlineEvidenceSpec,
    is_counterevidence: bool,
) -> Result<EvidenceInput, String> {
    let blob = outputs::open(ctx, &spec.handle).await.map_err(|e| e.sentence(&spec.handle))?;
    let producer = observed_producer(shared, mission, &spec.handle, &blob).await?;
    let quote = build_inline_quote(ctx, &blob, spec)?;
    let mut verified = check_quotes(ctx, &[quote]).await?;
    let v = verified.pop().ok_or_else(|| {
        "The quote could not be checked, so nothing was attached. Check `handle`, `start` and `end`.".to_string()
    })?;
    let grade = if producer.grade == EvidenceGrade::Run && producer.class != ToolClass::Exec {
        EvidenceGrade::Read
    } else {
        producer.grade
    };
    let kind = if grade == EvidenceGrade::Run { EvidenceKind::Execution } else { EvidenceKind::Static };
    let note = spec.note.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).unwrap_or_else(|| {
        format!("Observed {} output from {} ({}).", grade.as_str(), producer.tool, spec.handle.trim())
    });
    Ok(EvidenceInput {
        claim: String::new(),
        kind,
        supports: !is_counterevidence,
        session: producer.session,
        call_id: producer.call_id,
        blob: Some(v.blob),
        lines: Some((v.start, v.end)),
        quote: Some(v.text),
        note,
        attested: true,
        tool: Some(producer.tool),
        grade: Some(grade),
    })
}

struct InlineContext<'a> {
    shared: &'a Shared,
    mission: &'a MissionId,
    ctx: &'a ToolCtx,
    prefix: &'a str,
    specs: &'a [InlineEvidenceSpec],
}

struct RawInlineItem {
    elem_index: Option<(usize, usize, &'static str)>,
    loc_name: String,
    is_counter: bool,
    spec: InlineEvidenceSpec,
}

async fn synthesize_inline_evidence(
    ic: &InlineContext<'_>,
    state: &LedgerState,
    op: &mut SecurityOp,
    expanded: bool,
    notes: &mut Vec<String>,
) -> Result<(), String> {
    if !has_inline_evidence(op) {
        return Ok(());
    }
    let mut pending: Vec<PendingInline> = Vec::new();
    let collect_list = |elem_index: Option<(usize, usize, &'static str)>,
                        loc_name: &str,
                        is_counter: bool,
                        list: &[String],
                        out: &mut Vec<RawInlineItem>| {
        for raw in list {
            if raw.starts_with("out:") {
                out.push(RawInlineItem {
                    elem_index,
                    loc_name: loc_name.to_string(),
                    is_counter,
                    spec: parse_inline_spec(raw, ic.prefix, ic.specs),
                });
            }
        }
    };
    let mut raw_items = Vec::new();
    match &mut *op {
        SecurityOp::Batch { operations } if !expanded => {
            let n = operations.len();
            for (idx, elem) in operations.iter_mut().enumerate() {
                let i = idx.saturating_add(1);
                let elem_index = Some((i, n, elem.action()));
                let loc_name = format!("operation {i} of the batch");
                visit_single_op_evidence_mut(elem, |is_counter, list| {
                    collect_list(elem_index, &loc_name, is_counter, list, &mut raw_items);
                });
            }
        }
        SecurityOp::Batch { operations } => {
            for elem in operations.iter_mut() {
                visit_single_op_evidence_mut(elem, |is_counter, list| {
                    collect_list(None, "the operation", is_counter, list, &mut raw_items);
                });
            }
        }
        single => {
            visit_single_op_evidence_mut(single, |is_counter, list| {
                collect_list(None, "the operation", is_counter, list, &mut raw_items);
            });
        }
    }
    let first_elem = raw_items.first().and_then(|item| item.elem_index);
    let target_claim = pick_target_claim(ic.shared, state).map_err(|e| format_batch_err(first_elem, e))?;
    for item in raw_items {
        let input = resolve_one_inline(ic.shared, ic.mission, ic.ctx, &item.spec, item.is_counter)
            .await
            .map_err(|e| format_batch_err(item.elem_index, e))?;
        pending.push(PendingInline { elem_index: item.elem_index, loc_name: item.loc_name, spec: item.spec, input });
    }
    // Preflight all synthesized records and the SecurityOp against a cloned LedgerState so a core
    // validation failure never leaves stray ClaimAdd / EvidenceAdd entries in the real journal.
    let mut staged = state.clone();
    let auto_claim_op = LedgerOp::ClaimAdd { text: "Observed mission output for security evidence.".into() };
    let staged_claim_id = match &target_claim {
        Some(id) => id.clone(),
        None => {
            staged.validate(&auto_claim_op, false).map_err(|e| format_batch_err(first_elem, e))?;
            staged.apply(&Entry {
                n: staged.entries.saturating_add(1),
                ts_ms: 0,
                session: ic.shared.session.clone(),
                from_user: false,
                op: auto_claim_op.clone(),
                mac: String::new(),
            });
            staged
                .claims
                .last()
                .map(|c| c.id.clone())
                .ok_or_else(|| "Could not synthesize observation claim.".to_string())?
        }
    };
    let mut staged_ids = Vec::with_capacity(pending.len());
    for item in &pending {
        let mut ev = item.input.clone();
        ev.claim = staged_claim_id.clone();
        let ev_op = LedgerOp::EvidenceAdd(ev);
        staged.validate(&ev_op, false).map_err(|e| format_batch_err(item.elem_index, e))?;
        staged.apply(&Entry {
            n: staged.entries.saturating_add(1),
            ts_ms: 0,
            session: ic.shared.session.clone(),
            from_user: false,
            op: ev_op,
            mac: String::new(),
        });
        let e_id = staged
            .evidence
            .last()
            .map(|e| e.id.clone())
            .ok_or_else(|| "Could not synthesize evidence record.".to_string())?;
        staged_ids.push(e_id);
    }
    let mut staged_op = op.clone();
    replace_inline_slots(&mut staged_op, &staged_ids);
    if let Err(e) = staged.validate(&LedgerOp::Security(staged_op), false) {
        if expanded {
            return Err(format!(
                "{e} The evidence given with hypothesis_open was being attached by a second operation in the same \
                 atomic append; nothing was recorded."
            ));
        }
        return Err(e);
    }

    // Commit to the real journal now that all validation checks have passed.
    let claim_id = match target_claim {
        Some(id) => id,
        None => {
            let (_, after_claim) = ic.shared.ledger_append(false, auto_claim_op)?;
            after_claim.claims.last().map(|c| c.id.clone()).unwrap_or(staged_claim_id)
        }
    };
    let mut actual_ids = Vec::with_capacity(pending.len());
    for mut item in pending {
        item.input.claim = claim_id.clone();
        let (_, after_ev) = ic.shared.ledger_append(false, LedgerOp::EvidenceAdd(item.input))?;
        let e_id = after_ev
            .evidence
            .last()
            .map(|e| e.id.clone())
            .ok_or_else(|| "Could not record synthesized evidence.".to_string())?;
        notes.push(format!("In {}, synthesized evidence {e_id} from {}.", item.loc_name, item.spec.handle.trim()));
        actual_ids.push(e_id);
    }
    replace_inline_slots(op, &actual_ids);
    Ok(())
}

fn replace_inline_slots(op: &mut SecurityOp, ids: &[String]) {
    let mut iter = ids.iter();
    let mut replace_in = |list: &mut Vec<String>| {
        for slot in list.iter_mut() {
            if slot.starts_with("out:") {
                if let Some(id) = iter.next() {
                    *slot = id.clone();
                }
            }
        }
    };
    match op {
        SecurityOp::Batch { operations } => {
            for elem in operations {
                visit_single_op_evidence_mut(elem, |_, list| replace_in(list));
            }
        }
        single => visit_single_op_evidence_mut(single, |_, list| replace_in(list)),
    }
}

#[async_trait]
impl Tool for SecurityRecord {
    fn spec(&self) -> ToolSpec {
        let caller = shapes::Caller { standing: standing(&self.0), tools: &self.0.role.tools };
        spec(
            "security_record",
            &shapes::description(&caller),
            ToolClass::State,
            &[req("operation", "object", "A SecurityOp object with action and its typed fields.")],
        )
    }
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let Some(mission) = self.0.mission.as_ref() else {
            return ToolOutput::error(super::NO_MISSION);
        };
        let state = match self.0.ledger() {
            Ok(s) => s,
            Err(e) => return ToolOutput::error(e),
        };
        let before = state.security.clone();
        let caller = shapes::Caller { standing: standing(&self.0), tools: &self.0.role.tools };
        let (mut operation, top_level_note) = match args.get("operation") {
            Some(op) => (op.clone(), None),
            None if args.contains_key("action") => {
                (Value::Object(args.clone()), Some("Read top-level arguments as `operation`.".to_string()))
            }
            None => (Value::Null, None),
        };
        let prefix = unique_inline_prefix(&operation);
        let mut inline_specs = Vec::new();
        extract_inline_objects(&mut operation, &prefix, &mut inline_specs);
        let read = match shapes::read(&caller, &state.security, &operation) {
            Ok(read) => read,
            Err(e) => return ToolOutput::error(e),
        };
        // A single hypothesis_open that carried evidence was read as a two-operation batch (N4d).
        let expanded = matches!(read.op, SecurityOp::Batch { .. })
            && operation.get("action").and_then(Value::as_str) != Some("batch");
        let mut notes: Vec<String> = top_level_note.into_iter().collect();
        notes.extend(read.notes);
        let mut op = read.op;
        let prepare = |op: &mut SecurityOp| resolve_op(&state.security, op);
        let authorized = |op: &SecurityOp| authorize(&self.0, &state.security, op);
        // A batch element that fails is named, the way the core names one that fails validation.
        let prepared = match &mut op {
            SecurityOp::Batch { operations } => {
                let n = operations.len();
                let mut result = Ok(());
                for (i, element) in operations.iter_mut().enumerate() {
                    let step = match prepare(element) {
                        Ok(()) => match resolve_secrets(ctx, element).await {
                            Ok(()) => authorized(element),
                            Err(e) => Err(e),
                        },
                        Err(e) => Err(e),
                    };
                    if let Err(e) = step {
                        result = Err(format!(
                            "Operation {} of {n} in the batch ({}): {e}",
                            i.saturating_add(1),
                            element.action()
                        ));
                        break;
                    }
                }
                result
            }
            single => match prepare(single) {
                Ok(()) => match resolve_secrets(ctx, single).await {
                    Ok(()) => authorized(single),
                    Err(e) => Err(e),
                },
                Err(e) => Err(e),
            },
        };
        if let Err(e) = prepared {
            return ToolOutput::error(e);
        }
        let inline_ctx = InlineContext { shared: &self.0, mission, ctx, prefix: &prefix, specs: &inline_specs };
        if let Err(e) = synthesize_inline_evidence(&inline_ctx, &state, &mut op, expanded, &mut notes).await {
            return ToolOutput::error(e);
        }
        // Shared::ledger_append serializes all structural validation and writes under the journal lock.
        let applied = op.clone();
        match self.0.ledger_append(false, LedgerOp::Security(op)) {
            Ok((entry, state)) => {
                // The ids the operation names or creates, whatever the state held.
                let mut addressed = SecurityState::default();
                addressed.apply(&applied, entry.n, &entry.session);
                let mut result = Map::new();
                result.insert("entry".into(), json!(entry.n));
                if !notes.is_empty() {
                    result.insert("normalized".into(), json!(notes));
                }
                result.extend(touched_report(&before, &state.security, &addressed));
                output(&result)
            }
            Err(e) if expanded => ToolOutput::error(format!(
                "{e} The evidence given with hypothesis_open was being attached by a second operation in the same \
                 atomic append; nothing was recorded."
            )),
            Err(e) => ToolOutput::error(e),
        }
    }
}

/// The most characters of full records `security_record` returns; past it, counts and the first ids.
const RECORDED_CHARS: usize = 8_000;
/// Ids named per collection when the touched records are too many to return in full.
const RECORDED_IDS: usize = 20;
/// The id-keyed collections of `SecurityState` whose touched entries a write reports.
const KEYED: [&str; 13] = [
    "assets",
    "credentials",
    "footholds",
    "condition_evidence",
    "blocked",
    "revisited",
    "crashes",
    "vector_attempts",
    "hypotheses",
    "relations",
    "facts",
    "rules",
    "aliases",
];

/// The longest id, in characters, the counts-and-ids form names.
const RECORDED_ID_CHARS: usize = 80;

/// `s` cut to at most `max` characters, on a character boundary.
fn cut_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// Characters of `recorded` as the result prints it (pretty JSON).
fn pretty_chars(recorded: &Map<String, Value>) -> usize {
    serde_json::to_string_pretty(recorded).map(|t| t.chars().count()).unwrap_or(usize::MAX)
}

/// What a write changed, as the result fields `recorded`, `unchanged`, `removed`, `counts` and `more` (see
/// CONTRACT): per collection the keys whose value differs between `before` and `after`, the addressed ids
/// (`addressed` is a default state the operation was applied to) that the write left as they were, the ids
/// that are gone, and the size of each non-empty collection after the write.
fn touched_report(before: &SecurityState, after: &SecurityState, addressed: &SecurityState) -> Map<String, Value> {
    let (before, after) = (json!(before), json!(after));
    let empty = Map::new();
    let mut touched: Map<String, Value> = Map::new();
    let mut removed: Map<String, Value> = Map::new();
    let mut counts: Map<String, Value> = Map::new();
    let mut unchanged: Map<String, Value> = Map::new();
    let addressed = json!(addressed);
    for name in KEYED {
        let old = before.get(name).and_then(Value::as_object).unwrap_or(&empty);
        let new = after.get(name).and_then(Value::as_object).unwrap_or(&empty);
        let changed: Map<String, Value> =
            new.iter().filter(|(id, v)| old.get(*id) != Some(v)).map(|(id, v)| (id.clone(), v.clone())).collect();
        if !changed.is_empty() {
            touched.insert(name.into(), Value::Object(changed));
        }
        let gone: Vec<Value> = old.keys().filter(|id| !new.contains_key(*id)).map(|id| json!(id)).collect();
        if !gone.is_empty() {
            removed.insert(name.into(), Value::Array(gone));
        }
        if !new.is_empty() {
            counts.insert(name.into(), json!(new.len()));
        }
        let same: Vec<Value> = addressed
            .get(name)
            .and_then(Value::as_object)
            .map(|a| {
                a.keys().filter(|id| new.contains_key(*id) && touched.get(name).is_none_or(|t| t.get(*id).is_none()))
            })
            .into_iter()
            .flatten()
            .map(|id| json!(id))
            .collect();
        if !same.is_empty() {
            unchanged.insert(name.into(), Value::Array(same));
        }
    }
    let old = before.get("unlocked").and_then(Value::as_array).cloned().unwrap_or_default();
    let new = after.get("unlocked").and_then(Value::as_array).cloned().unwrap_or_default();
    let added: Vec<Value> = new.iter().filter(|c| !old.contains(c)).cloned().collect();
    if !added.is_empty() {
        touched.insert("unlocked".into(), Value::Array(added));
    }
    if !new.is_empty() {
        counts.insert("unlocked".into(), json!(new.len()));
    }
    for name in ["died", "retraction_limitation"] {
        let new = after.get(name).filter(|v| !v.is_null() && v.as_array().is_none_or(|a| !a.is_empty()));
        if let Some(new) = new.filter(|v| before.get(name) != Some(*v)) {
            touched.insert(name.into(), new.clone());
        }
    }
    let recorded: Map<String, Value> = if pretty_chars(&touched) <= RECORDED_CHARS {
        touched
    } else {
        // Counts and ids; `unlocked`, `died` and the limitation text are named by count or a short cut.
        let form = |with_ids: bool| -> Map<String, Value> {
            touched
                .iter()
                .map(|(name, records)| {
                    let count = match records {
                        Value::Object(m) => m.len(),
                        Value::Array(a) => a.len(),
                        _ => 1,
                    };
                    let keyed = KEYED.contains(&name.as_str());
                    let ids: Vec<Value> = match records {
                        Value::Object(m) if with_ids && keyed => {
                            m.keys().take(RECORDED_IDS).map(|id| json!(cut_chars(id, RECORDED_ID_CHARS))).collect()
                        }
                        _ => Vec::new(),
                    };
                    let entry =
                        if keyed && with_ids { json!({"count": count, "ids": ids}) } else { json!({"count": count}) };
                    (name.clone(), entry)
                })
                .collect()
        };
        let full = form(true);
        if pretty_chars(&full) <= RECORDED_CHARS {
            full
        } else {
            form(false)
        }
    };
    let mut report = Map::new();
    report.insert("recorded".into(), Value::Object(recorded));
    if !unchanged.is_empty() {
        report.insert("unchanged".into(), Value::Object(unchanged));
    }
    if !removed.is_empty() {
        report.insert("removed".into(), Value::Object(removed));
    }
    report.insert("counts".into(), Value::Object(counts));
    report.insert(
        "more".into(),
        json!(
            "The rest of the security state is unchanged by this write; read it with security_query (view: state, \
             assets, coverage, revisit, hypotheses or facts)."
        ),
    );
    report
}

/// The session's standing for hypotheses: the lead, a read-only child with the verdict tool, or another child.
fn standing(shared: &Shared) -> shapes::Standing {
    if !shared.is_child() {
        shapes::Standing::Lead
    } else if shared.role.read_only && shared.role.tools.iter().any(|t| t == "verdict") {
        shapes::Standing::Judge
    } else {
        shapes::Standing::Child
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
        let blob = match outputs::open(ctx, handle).await {
            Ok(b) => b,
            Err(e) => return ToolOutput::error(e.sentence(handle)),
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
    /// The JSON object a tool result carries after its header lines.
    fn body_json(text: &str) -> Value {
        let start = text.find("{\n").unwrap();
        serde_json::Deserializer::from_str(&text[start..]).into_iter::<Value>().next().unwrap().unwrap()
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
            tool: None,
            grade: None,
        }));
    }

    #[tokio::test]
    async fn near_misses_are_read_and_listed_under_normalized() {
        let r = rig("lead", false, true);
        let h = r.output("synthetic evidence", "bash", ToolClass::Exec);
        evidence(&r, &h);
        let host = r
            .call(
                "security_record",
                json!({"operation":{"action":"asset_upsert","asset":{"kind":"host","locator":"127.0.0.1:19727",
                    "evidence":["e1"]}}}),
            )
            .await;
        assert_eq!(host.status, Status::Ok, "{}", host.text);
        let body = body_json(&host.text);
        assert_eq!(body["normalized"].as_array().map(Vec::len), Some(1), "{body}");
        assert!(body["normalized"][0]
            .as_str()
            .unwrap()
            .starts_with("In the operation, the host was recorded as `127.0.0.1`"));
        assert_eq!(r.shared.ledger().unwrap().security.assets.values().next().unwrap().locator, "127.0.0.1");
        // An exact operation has no `normalized` key.
        let exact = r
            .call(
                "security_record",
                json!({"operation":{"action":"asset_upsert","asset":{"kind":"host","locator":"10.0.0.5",
                    "evidence":["e1"]}}}),
            )
            .await;
        assert_eq!(exact.status, Status::Ok, "{}", exact.text);
        assert!(body_json(&exact.text).get("normalized").is_none());
        // A hypothesis opened with evidence is two operations in one append.
        let open = r
            .call(
                "security_record",
                json!({"operation":{"action":"hypothesis_open","hypothesis":{"statement":"candidate","priority":"high",
                    "evidence":["e1"]}}}),
            )
            .await;
        assert_eq!(open.status, Status::Ok, "{}", open.text);
        let id = stable_id("hy", &["candidate"]);
        let state = r.shared.ledger().unwrap().security;
        assert_eq!(state.hypotheses.get(&id).map(|h| (h.priority, h.evidence.clone())), Some((5, vec!["e1".into()])));
        // When the second operation fails the whole append fails and the error says so.
        let failed = r
            .call(
                "security_record",
                json!({"operation":{"action":"hypothesis_open","text":"other","priority":2,"evidence":["e404"]}}),
            )
            .await;
        assert_eq!(failed.status, Status::Error);
        assert!(failed.text.contains("e404"), "{}", failed.text);
        assert!(
            failed.text.contains(
                " The evidence given with hypothesis_open was being attached by a second operation in the same atomic \
             append; nothing was recorded."
            ),
            "{}",
            failed.text
        );
        assert!(!r.shared.ledger().unwrap().security.hypotheses.contains_key(&stable_id("hy", &["other"])));
        // A failing batch element is named.
        let batch = r
            .call(
                "security_record",
                json!({"operation":{"action":"batch","ops":[
                    {"action":"asset_upsert","asset":{"kind":"host","locator":"10.0.0.9","evidence":["e1"]}},
                    {"action":"asset_upsert","asset":{"kind":"host","locator":"10.0.0.10","evidence":["e404"]}}]}}),
            )
            .await;
        assert_eq!(batch.status, Status::Error);
        assert!(batch.text.contains("Operation 2 of 2 in the batch (asset_upsert): "), "{}", batch.text);
        assert!(r.shared.ledger().unwrap().security.assets.len() == 2);
    }

    fn upsert(locator: &str) -> Value {
        json!({"action":"asset_upsert","asset":{"kind":"host","locator":locator,"evidence":["e1"]}})
    }

    #[tokio::test]
    async fn a_single_upsert_returns_that_asset_and_the_counts_not_the_other_assets() {
        let r = rig("lead", false, true);
        let h = r.output("synthetic evidence", "bash", ToolClass::Exec);
        evidence(&r, &h);
        for locator in ["10.0.0.1", "10.0.0.2"] {
            let res = r.call("security_record", json!({ "operation": upsert(locator) })).await;
            assert_eq!(res.status, Status::Ok, "{}", res.text);
        }
        let res = r.call("security_record", json!({"operation": upsert("10.0.0.3")})).await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        let body = body_json(&res.text);
        let assets = body["recorded"]["assets"].as_object().unwrap();
        assert_eq!(assets.len(), 1, "{body}");
        assert_eq!(assets.values().next().unwrap()["locator"], "10.0.0.3");
        assert_eq!(body["counts"]["assets"], 3, "{body}");
        assert!(body.get("state").is_none() && body.get("removed").is_none(), "{body}");
        assert!(body["more"].as_str().unwrap().starts_with("The rest of the security state is unchanged"), "{body}");
        assert!(!res.text.contains("10.0.0.1") && !res.text.contains("10.0.0.2"), "{}", res.text);
    }

    #[tokio::test]
    async fn a_batch_over_the_size_bound_returns_counts_and_ids() {
        let r = rig("lead", false, true);
        let h = r.output("synthetic evidence", "bash", ToolClass::Exec);
        evidence(&r, &h);
        let ops: Vec<Value> = (0..60).map(|i| upsert(&format!("10.1.0.{i}"))).collect();
        let res = r.call("security_record", json!({"operation":{"action":"batch","ops":ops}})).await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        let body = body_json(&res.text);
        assert_eq!(body["recorded"]["assets"]["count"], 60, "{body}");
        let ids = body["recorded"]["assets"]["ids"].as_array().unwrap();
        assert_eq!(ids.len(), RECORDED_IDS);
        assert!(ids.iter().all(|id| r.shared.ledger().unwrap().security.assets.contains_key(id.as_str().unwrap())));
        assert_eq!(body["counts"]["assets"], 60, "{body}");
        assert!(res.text.chars().count() < RECORDED_CHARS, "{}", res.text.chars().count());
    }

    #[tokio::test]
    async fn a_hypothesis_open_returns_the_new_hypothesis_id() {
        let r = rig("lead", false, true);
        let res = r
            .call(
                "security_record",
                json!({"operation":{"action":"hypothesis_open","hypothesis":{"statement":"candidate","priority":"high"}}}),
            )
            .await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        let body = body_json(&res.text);
        let id = stable_id("hy", &["candidate"]);
        assert_eq!(body["recorded"]["hypotheses"][&id]["id"], json!(id), "{body}");
        assert_eq!(body["counts"]["hypotheses"], 1, "{body}");
    }

    #[tokio::test]
    async fn a_retraction_reports_the_fact_it_deactivated() {
        let r = rig("lead", false, true);
        let h = r.output("synthetic evidence", "bash", ToolClass::Exec);
        evidence(&r, &h);
        let asserted = r
            .call(
                "security_record",
                json!({"operation":{"action":"fact_assert","fact":{"predicate":"seen","args":["dummy"]},"evidence":["e1"]}}),
            )
            .await;
        assert_eq!(asserted.status, Status::Ok, "{}", asserted.text);
        let id = r.shared.ledger().unwrap().security.facts.keys().next().unwrap().clone();
        let res =
            r.call("security_record", json!({"operation":{"action":"fact_retract","id":id,"reason":"mistaken"}})).await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        let body = body_json(&res.text);
        assert_eq!(body["recorded"]["facts"][&id]["active"], false, "{body}");
        assert_eq!(body["counts"]["facts"], 1, "{body}");
    }

    #[test]
    fn touched_report_lists_removed_ids_and_added_conditions() {
        let mut before = SecurityState::default();
        before.aliases.insert("web".into(), "as-1".into());
        before.aliases.insert("db".into(), "as-2".into());
        before.revisited.insert("r1".into(), 3);
        let mut after = before.clone();
        after.aliases.remove("db");
        after.revisited.insert("r1".into(), 4);
        after.unlocked.insert(Condition { kind: ConditionKind::Cred, value: "admin".into() });
        let report = touched_report(&before, &after, &SecurityState::default());
        assert_eq!(report["removed"]["aliases"], json!(["db"]), "{report:?}");
        assert_eq!(report["recorded"]["revisited"], json!({"r1": 4}), "{report:?}");
        assert_eq!(report["recorded"]["unlocked"].as_array().map(Vec::len), Some(1), "{report:?}");
        assert!(report["recorded"].get("aliases").is_none(), "{report:?}");
        assert_eq!((report["counts"]["aliases"].clone(), report["counts"]["unlocked"].clone()), (json!(1), json!(1)));
    }

    #[tokio::test]
    async fn condition_assets_resolve_and_every_batch_failure_is_named() {
        let r = rig("lead", false, true);
        let h = r.output("synthetic evidence", "bash", ToolClass::Exec);
        evidence(&r, &h);
        let host = r
            .call(
                "security_record",
                json!({"operation":{"action":"asset_upsert","asset":{"kind":"host","locator":"10.0.0.5",
                    "evidence":["e1"]}}}),
            )
            .await;
        assert_eq!(host.status, Status::Ok, "{}", host.text);
        let full = r.shared.ledger().unwrap().security.assets.keys().next().unwrap().clone();
        // A prefix in a cred condition is stored as the full asset ID, which is what a later unlock compares.
        let blocked = |value: &str| json!({"operation":{"action":"blocked_on","target":"c1","conditions":[{"kind":"cred","value":value}]}});
        let ok = r.call("security_record", blocked(&full[..12])).await;
        assert_eq!(ok.status, Status::Ok, "{}", ok.text);
        let stored = r.shared.ledger().unwrap().security.blocked.get("c1").unwrap().conditions[0].value.clone();
        assert_eq!(stored, full);
        // A mistyped asset ID is refused instead of waiting for an unlock that cannot come.
        let bad = r.call("security_record", blocked("as-zzzzzzzz")).await;
        assert_eq!(bad.status, Status::Error);
        assert!(bad.text.contains("No security record matches `as-zzzzzzzz`"), "{}", bad.text);
        // A value that is not an ID is kept.
        assert_eq!(r.call("security_record", blocked("admin-session")).await.status, Status::Ok);
        // A resolution failure inside a batch names the element.
        let batch = r
            .call(
                "security_record",
                json!({"operation":{"action":"batch","operations":[
                    {"action":"coverage_set","asset":full,"disposition":{"status":"deferred","reason":"budget"}},
                    {"action":"coverage_set","asset":"a1","disposition":{"status":"deferred","reason":"budget"}}]}}),
            )
            .await;
        assert_eq!(batch.status, Status::Error);
        assert!(
            batch.text.contains("Operation 2 of 2 in the batch (coverage_set): Use an exact ID or alias"),
            "{}",
            batch.text
        );
        // So does a failing secret handle, and a nested batch.
        let secret = r
            .call(
                "security_record",
                json!({"operation":{"action":"batch","operations":[
                    {"action":"coverage_set","asset":full,"disposition":{"status":"deferred","reason":"budget"}},
                    {"action":"credential_add","credential":{"asset":full,"principal":"root","evidence":["e1"],
                        "secret_handle":"out:nothere"}}]}}),
            )
            .await;
        assert!(
            secret.text.contains("Operation 2 of 2 in the batch (credential_add): Use an existing stored out:"),
            "{}",
            secret.text
        );
        let nested = r
            .call(
                "security_record",
                json!({"operation":{"action":"batch","operations":[
                    {"action":"coverage_set","asset":full,"disposition":{"status":"deferred","reason":"budget"}},
                    {"action":"batch","operations":[
                        {"action":"coverage_set","asset":full,"disposition":{"status":"deferred","reason":"budget"}}]}]}}),
            )
            .await;
        assert!(
            nested.text.contains("Operation 2 of 2 in the batch (batch): Nested security batches"),
            "{}",
            nested.text
        );
        // A child's early refusal inside a batch is named too.
        let child = rig("worker", true, true);
        let denied = child
            .call(
                "security_record",
                json!({"operation":{"action":"batch","operations":[
                    {"action":"alias_add","alias":"web","target":"as-0000"},
                    {"action":"hypothesis_priority","id":"hy-0000","priority":3}]}}),
            )
            .await;
        assert_eq!(denied.status, Status::Error);
        assert!(denied.text.contains("Operation 2 of 2 in the batch (hypothesis_priority): Only"), "{}", denied.text);
    }

    #[tokio::test]
    async fn the_description_follows_the_session_standing() {
        let lead = SecurityRecord(rig("lead", false, true).shared.clone()).spec().description;
        let child = SecurityRecord(rig("worker", true, true).shared.clone()).spec().description;
        let judge = SecurityRecord(rig("verifier", true, true).shared.clone()).spec().description;
        assert!(lead.contains("{action:hypothesis_open,") && !lead.contains("status:supported|refuted"));
        assert!(!child.contains("{action:hypothesis_open,") && child.contains("the mission lead's"));
        assert!(judge.contains("status:supported|refuted"));
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
            tool: None,
            grade: None,
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
        // A stored output of another mission is refused with the same sentence as a handle that names nothing.
        let foreign = r.env.ctx.blobs.put_bytes(b"another mission's secret\n").unwrap().handle();
        let refused = r
            .call(
                "security_record",
                json!({"operation":{"action":"credential_add","credential":{
            "asset":id,"principal":"dummy","secret_handle":foreign,"evidence":["e1"]}}}),
            )
            .await;
        assert_eq!(refused.status, Status::Error);
        assert!(refused.text.contains(SECRET_HANDLE_REFUSAL), "{}", refused.text);
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

    #[tokio::test]
    async fn a_fact_retraction_reports_the_conclusions_that_died() {
        let r = rig("lead", false, true);
        let h = r.output("synthetic evidence", "bash", ToolClass::Exec);
        evidence(&r, &h);
        let rule = r
            .call(
                "security_record",
                json!({"operation":{"action":"rule_install","rule":{"name":"v","head":{"predicate":"viable","args":["?x"]},
                    "body":[{"atom":{"predicate":"seen","args":["?x"]},"negated":false}]}}}),
            )
            .await;
        assert_eq!(rule.status, Status::Ok, "{}", rule.text);
        let asserted = r
            .call(
                "security_record",
                json!({"operation":{"action":"fact_assert","fact":{"predicate":"seen","args":["dummy"]},"evidence":["e1"]}}),
            )
            .await;
        assert_eq!(asserted.status, Status::Ok, "{}", asserted.text);
        let id = r.shared.ledger().unwrap().security.facts.keys().next().unwrap().clone();
        let res =
            r.call("security_record", json!({"operation":{"action":"fact_retract","id":id,"reason":"mistaken"}})).await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        assert!(!r.shared.ledger().unwrap().security.died.is_empty());
        let body = body_json(&res.text);
        assert!(body["recorded"]["died"].to_string().contains("viable"), "{body}");
    }

    #[tokio::test]
    async fn a_repeated_hypothesis_open_names_the_hypothesis_id_as_unchanged() {
        let r = rig("lead", false, true);
        let op =
            json!({"operation":{"action":"hypothesis_open","hypothesis":{"statement":"candidate","priority":"high"}}});
        let first = r.call("security_record", op.clone()).await;
        assert_eq!(first.status, Status::Ok, "{}", first.text);
        let again = r.call("security_record", op).await;
        assert_eq!(again.status, Status::Ok, "{}", again.text);
        let id = stable_id("hy", &["candidate"]);
        let body = body_json(&again.text);
        assert_eq!(body["unchanged"]["hypotheses"], json!([id]), "{body}");
        let first = body_json(&first.text);
        assert!(first.get("unchanged").is_none(), "{first}");
    }

    #[tokio::test]
    async fn an_upsert_of_a_known_asset_names_its_canonical_id_as_unchanged() {
        let r = rig("lead", false, true);
        let h = r.output("synthetic evidence", "bash", ToolClass::Exec);
        evidence(&r, &h);
        let first = r.call("security_record", json!({"operation": upsert("example.test")})).await;
        assert_eq!(first.status, Status::Ok, "{}", first.text);
        let again = r.call("security_record", json!({"operation": upsert("Example.TEST.")})).await;
        assert_eq!(again.status, Status::Ok, "{}", again.text);
        let id = r.shared.ledger().unwrap().security.assets.keys().next().unwrap().clone();
        let body = body_json(&again.text);
        assert_eq!(body["unchanged"]["assets"], json!([id]), "{body}");
    }

    #[test]
    fn the_over_bound_form_stays_near_the_bound_with_long_conditions_and_keys() {
        let before = SecurityState::default();
        let mut after = before.clone();
        for i in 0..64 {
            after
                .unlocked
                .insert(Condition { kind: ConditionKind::Cred, value: format!("{i:02}{}", "v".repeat(4000)) });
        }
        for i in 0..40 {
            after.aliases.insert(format!("{i:02}{}", "k".repeat(1000)), "x".into());
        }
        let report = touched_report(&before, &after, &SecurityState::default());
        let recorded = report["recorded"].as_object().unwrap();
        let size = serde_json::to_string_pretty(recorded).unwrap().chars().count();
        assert!(size <= RECORDED_CHARS, "`recorded` is {size} characters (bound {RECORDED_CHARS})");
        assert_eq!(recorded["unlocked"], json!({"count": 64}), "{recorded:?}");
        assert_eq!(recorded["aliases"]["count"], 40, "{recorded:?}");
    }

    #[test]
    fn the_counts_and_ids_form_cuts_ids_to_80_characters() {
        let before = SecurityState::default();
        let mut after = before.clone();
        for i in 0..30 {
            after.aliases.insert(format!("{i:02}{}", "é".repeat(500)), "x".into());
        }
        let report = touched_report(&before, &after, &SecurityState::default());
        let ids = report["recorded"]["aliases"]["ids"].as_array().unwrap();
        assert_eq!(ids.len(), RECORDED_IDS);
        assert!(ids.iter().all(|id| id.as_str().unwrap().chars().count() == 80), "{ids:?}");
    }

    async fn run_direct(r: &Rig, value: Value) -> (Status, Value, String) {
        let map = value.as_object().cloned().unwrap_or_default();
        let out = SecurityRecord(r.shared.clone()).run(&r.env.ctx, &map).await;
        match out.body {
            Body::Raw(bytes) => {
                let text = String::from_utf8(bytes).unwrap();
                let json: Value = serde_json::from_str(&text).unwrap();
                (out.status, json, text)
            }
            Body::Message(text) => (out.status, Value::Null, text),
            other => panic!("unexpected body: {other:?}"),
        }
    }

    #[tokio::test]
    async fn unwrapped_top_level_action_arguments_are_accepted_with_note() {
        let r = rig("lead", false, true);
        let (status, body, text) = run_direct(&r, json!({"action": "hypothesis_open", "text": "top-level"})).await;
        assert_eq!(status, Status::Ok, "{text}");
        assert_eq!(
            body["normalized"],
            json!([
                "Read top-level arguments as `operation`.",
                "In the operation, no priority was given, so it is 3 (1 low to 5 high)."
            ])
        );
        let id = stable_id("hy", &["top-level"]);
        assert!(r.shared.ledger().unwrap().security.hypotheses.contains_key(&id));

        // Combined with N2 flat wrapper and inline out: handle.
        let h = r.output("HTTP/1.1 200 OK\nServer: nginx\n", "bash", ToolClass::Exec);
        let (status, body, text) =
            run_direct(&r, json!({"action": "asset_upsert", "kind": "host", "locator": "10.0.0.5", "evidence": [h]}))
                .await;
        assert_eq!(status, Status::Ok, "{text}");
        assert_eq!(
            body["normalized"],
            json!([
                "Read top-level arguments as `operation`.",
                "In the operation, the asset fields were moved into `asset`.",
                format!("In the operation, synthesized evidence e1 from {h}.")
            ])
        );

        // Missing both operation and action still produces the standard refusal.
        let (status, _, text) = run_direct(&r, json!({"foo": "bar"})).await;
        assert_eq!(status, Status::Error);
        assert!(text.starts_with("Correct `operation` before retrying: give an object with `action`"), "{text}");
    }

    #[tokio::test]
    async fn inline_out_handle_auto_synthesizes_attested_evidence_and_auto_opens_claim() {
        let r = rig("lead", false, true);
        // Leading blank lines are skipped so the first non-blank span is quoted.
        let h = r.output("\n\n22/tcp open ssh\n80/tcp open http\n", "bash", ToolClass::Exec);
        let res = r
            .call(
                "security_record",
                json!({"operation": {"action": "asset_upsert", "asset": {"kind": "host", "locator": "10.0.0.5", "evidence": [h]}}}),
            )
            .await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        let body = body_json(&res.text);
        assert_eq!(body["normalized"], json!([format!("In the operation, synthesized evidence e1 from {h}.")]));
        let ledger = r.shared.ledger().unwrap();
        assert_eq!(ledger.claims.len(), 1);
        assert_eq!(ledger.evidence.len(), 1);
        let ev = &ledger.evidence[0];
        assert_eq!(ev.id, "e1");
        assert!(ev.input.attested);
        assert_eq!(ev.input.kind, EvidenceKind::Execution);
        assert_eq!(ev.input.lines, Some((3, 4)));
        assert_eq!(ev.input.quote.as_deref(), Some("22/tcp open ssh\n80/tcp open http"));
        let asset_id = stable_id("as", &["Host", "10.0.0.5"]);
        assert_eq!(ledger.security.assets[&asset_id].evidence, vec!["e1"]);

        // Prefers the latest open claim over closed claims, and handles object quote specs + oversized single lines.
        r.model_op(LedgerOp::ClaimUpdate { id: "c1".into(), status: ClaimStatus::Supported, note: "done".into() });
        r.model_op(LedgerOp::ClaimAdd { text: "second open claim".into() });
        let big_line =
            format!("{{\"results\":[{{\"url\":\"http://10.0.0.5/api\",\"body\":\"{}\"}}]}}\n", "x".repeat(2500));
        let h2 = r.output(&big_line, "http_send", ToolClass::Exec);
        let h3 = r.output("line one\nsecret admin token observed\nline three\n", "read", ToolClass::Read);
        let res = r
            .call(
                "security_record",
                json!({"operation": {"action": "batch", "operations": [
                    {"action": "asset_upsert", "asset": {"kind": "service", "locator": "http://10.0.0.5:8080", "evidence": ["e1", h2]}},
                    {"action": "credential_add", "credential": {"asset": stable_id("as", &["Service", "http://10.0.0.5:8080/"]), "principal": "admin", "secret_handle": h3, "evidence": [{"handle": h3, "start": 2, "end": 2, "quote": "secret admin token observed"}]}}
                ]}}),
            )
            .await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        let body = body_json(&res.text);
        assert_eq!(
            body["normalized"],
            json!([
                format!("In operation 1 of the batch, synthesized evidence e2 from {h2}."),
                format!("In operation 2 of the batch, synthesized evidence e3 from {h3}.")
            ])
        );
        let ledger = r.shared.ledger().unwrap();
        assert_eq!(ledger.claims.len(), 2);
        assert_eq!(ledger.evidence[1].input.claim, "c2");
        assert_eq!(ledger.evidence[2].input.claim, "c2");
        assert_eq!(ledger.evidence[2].input.kind, EvidenceKind::Static);
        assert_eq!(ledger.evidence[2].input.quote.as_deref(), Some("secret admin token observed"));
        let cred = ledger.security.credentials.values().next().unwrap();
        assert_eq!(cred.input.evidence, vec!["e3"]);
        assert!(cred.input.secret_handle.starts_with("out:") && cred.input.secret_handle.len() == 68);
    }

    #[tokio::test]
    async fn inline_out_handle_enforces_scope_observation_and_batch_atomicity() {
        let r = rig("lead", false, true);
        let foreign = r.env.ctx.blobs.put_bytes(b"another mission's secret output\n").unwrap();
        let before_entries = r.shared.ledger().unwrap().entries;

        // Foreign mission blob gets the exact Unopened::Unknown sentence and records nothing.
        let res = r
            .call(
                "security_record",
                json!({"operation": {"action": "asset_upsert", "asset": {"kind": "host", "locator": "10.0.0.5", "evidence": [foreign.handle()]}}}),
            )
            .await;
        assert_eq!(res.status, Status::Error);
        assert!(res.text.contains("No output of this mission has the handle"), "{}", res.text);
        assert_eq!(r.shared.ledger().unwrap().entries, before_entries);

        // Orphan blob in scope without producer is refused by observed_producer.
        let orphan = r.env.ctx.blobs.put_bytes(b"orphan output\n").unwrap();
        r.orch.in_scope(&orphan.id);
        let res = r
            .call(
                "security_record",
                json!({"operation": {"action": "asset_upsert", "asset": {"kind": "host", "locator": "10.0.0.5", "evidence": [orphan.handle()]}}}),
            )
            .await;
        assert_eq!(res.status, Status::Error);
        assert!(res.text.contains("was not produced by a tool call of this mission"), "{}", res.text);
        assert_eq!(r.shared.ledger().unwrap().entries, before_entries);

        // Non-observation producer (`ledger`) is refused by observed_producer.
        let ledger_out = r.call("ledger", json!({})).await.output.unwrap().handle();
        let res = r
            .call(
                "security_record",
                json!({"operation": {"action": "asset_upsert", "asset": {"kind": "host", "locator": "10.0.0.5", "evidence": [ledger_out]}}}),
            )
            .await;
        assert_eq!(res.status, Status::Error);
        assert!(res.text.contains("is the result of `ledger`"), "{}", res.text);
        assert_eq!(r.shared.ledger().unwrap().entries, before_entries);

        // Batch failure in op 2 (core validation error) must NOT leave stray ClaimAdd or EvidenceAdd from op 1!
        let good = r.output("observed output\n", "bash", ToolClass::Exec);
        let res = r
            .call(
                "security_record",
                json!({"operation": {"action": "batch", "operations": [
                    {"action": "asset_upsert", "asset": {"kind": "host", "locator": "10.0.0.5", "evidence": [good]}},
                    {"action": "fact_assert", "fact": {"predicate": "bad", "args": ["?unbound"]}, "evidence": [good]}
                ]}}),
            )
            .await;
        assert_eq!(res.status, Status::Error);
        assert!(res.text.contains("Operation 2 of 2 in the batch (fact_assert):"), "{}", res.text);
        let after = r.shared.ledger().unwrap();
        assert_eq!(after.entries, before_entries);
        assert!(after.claims.is_empty());
        assert!(after.evidence.is_empty());
        assert!(after.security.assets.is_empty());
    }

    #[tokio::test]
    async fn inline_out_handle_works_for_hypothesis_open_judge_verdict_and_children() {
        let lead = rig("lead", false, true);
        let h_open = lead.output("sqli error near syntax\n", "bash", ToolClass::Exec);
        let res = lead
            .call(
                "security_record",
                json!({"operation": {"action": "hypothesis_open", "text": "SQLi in /search", "evidence": [h_open]}}),
            )
            .await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        let body = body_json(&res.text);
        assert!(
            body["normalized"]
                .as_array()
                .unwrap()
                .iter()
                .any(|n| n == &json!(format!("In the operation, synthesized evidence e1 from {h_open}."))),
            "{body}"
        );
        let hy_id = stable_id("hy", &["SQLi in /search"]);
        assert_eq!(lead.shared.ledger().unwrap().security.hypotheses[&hy_id].evidence, vec!["e1"]);

        // Child worker opens its own claim rather than attaching to lead's c1.
        let child = rig("worker", true, true);
        child
            .shared
            .journal
            .as_ref()
            .unwrap()
            .append(&"s-lead".into(), false, LedgerOp::ClaimAdd { text: "lead claim".into() }, &|_| Ok(()))
            .unwrap();
        let h_child = child.output("worker observed file\n", "read", ToolClass::Read);
        let res = child
            .call(
                "security_record",
                json!({"operation": {"action": "asset_upsert", "asset": {"kind": "host", "locator": "10.0.0.6", "evidence": [h_child]}}}),
            )
            .await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        let child_ledger = child.shared.ledger().unwrap();
        assert_eq!(child_ledger.claims.len(), 2);
        assert_eq!(child_ledger.evidence[0].input.claim, "c2");

        // Judge with `evidence` + `verdict` (e.g. op_judge) can synthesize counterevidence on existing claim.
        let mut judge_role = core_role("verifier");
        judge_role.tools.extend(["evidence".into(), "security_record".into()]);
        let judge = rig_with(judge_role, true, true, AgentsCfg::default());
        judge
            .shared
            .journal
            .as_ref()
            .unwrap()
            .append(&"s-lead".into(), false, LedgerOp::ClaimAdd { text: "lead claim".into() }, &|_| Ok(()))
            .unwrap();
        judge
            .shared
            .journal
            .as_ref()
            .unwrap()
            .append(
                &"s-lead".into(),
                false,
                LedgerOp::Security(SecurityOp::HypothesisOpen { text: "candidate".into(), priority: 3 }),
                &|_| Ok(()),
            )
            .unwrap();
        let h_judge = judge.output("403 Forbidden from endpoint\n", "bash", ToolClass::Exec);
        let cand_id = stable_id("hy", &["candidate"]);
        let res = judge
            .call(
                "security_record",
                json!({"operation": {"action": "hypothesis_verdict", "id": cand_id, "status": "refuted",
                    "note": "blocked by auth", "counterevidence": [{"handle": h_judge, "quote": "403 Forbidden"}]}}),
            )
            .await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        let j_ledger = judge.shared.ledger().unwrap();
        assert_eq!(j_ledger.security.hypotheses[&cand_id].status, HypothesisStatus::Refuted);
        assert!(!j_ledger.evidence[0].input.supports);

        // Read-only verifier WITHOUT `evidence` is refused before writing anything.
        let ro = rig("verifier", true, true);
        let h_ro = ro.output("something\n", "bash", ToolClass::Exec);
        let res = ro
            .call(
                "security_record",
                json!({"operation": {"action": "asset_upsert", "asset": {"kind": "host", "locator": "10.0.0.9", "evidence": [h_ro]}}}),
            )
            .await;
        assert_eq!(res.status, Status::Error);
        assert!(res.text.contains("read-only"), "{}", res.text);
    }

    #[tokio::test]
    async fn sole_service_inheritance_and_blocked_on_synonyms_work_end_to_end() {
        let r = rig("lead", false, true);
        let h = r.output("HTTP/1.1 200 OK\n", "bash", ToolClass::Exec);
        let svc = r
            .call(
                "security_record",
                json!({"operation": {"action": "asset_upsert", "asset": {"kind": "service", "locator": "http://10.0.0.5:8080/", "evidence": [h]}}}),
            )
            .await;
        assert_eq!(svc.status, Status::Ok, "{}", svc.text);
        let svc_id = stable_id("as", &["Service", "http://10.0.0.5:8080/"]);
        let ep = r
            .call(
                "security_record",
                json!({"operation": {"action": "asset_upsert", "asset": {"kind": "endpoint", "locator": "/login", "evidence": [h]}}}),
            )
            .await;
        assert_eq!(ep.status, Status::Ok, "{}", ep.text);
        let ep_id = stable_id("as", &["Endpoint", "http://10.0.0.5:8080/login"]);
        let state = r.shared.ledger().unwrap().security;
        assert_eq!(state.assets[&ep_id].parent.as_deref(), Some(svc_id.as_str()));
        assert!(!state.relations.is_empty());

        let blk = r
            .call(
                "security_record",
                json!({"operation": {"action": "blocked_on", "claim": "c1", "conditions": {"kind": "cred", "value": svc_id}, "reason": "need login"}}),
            )
            .await;
        assert_eq!(blk.status, Status::Ok, "{}", blk.text);
        assert_eq!(r.shared.ledger().unwrap().security.blocked["c1"].target, "c1");
    }
}
