//! SARIF 2.1.0 export for Ferret structured findings and per-surface coverage provenance.
//!
//! CONTRACT.
//!
//! Pure, deterministic builder from a folded [`LedgerState`] (plus optional [`SarifOptions`]) to an
//! OASIS SARIF 2.1.0 JSON document (`$schema: https://json.schemastore.org/sarif-2.1.0.json`,
//! `version: 2.1.0`) suitable for GitHub Code Scanning (`upload-sarif`), ASPM ingestion, and CI
//! archival. Nothing in this module touches the network or reads secrets.
//!
//! - Rules for active [`Finding`] records are keyed by canonical `CWE-NNN`, then `CVE-YYYY-NNNNN`,
//!   then finding ID, then a title slug. Each rule carries `security-severity` (`0.0`-`10.0`),
//!   `helpUri` for CWEs, and `tags` (`security`, `CWE-NNN`, `CVE-...`, and `stride:<leg>` mapped
//!   from CWE with default `stride:T`, `stride:I`).
//! - Findings with unsafe physical locations (absolute, `..`, URI/drive prefix) drop those paths
//!   and record counts in `run.properties.droppedUnsafeLocationCount` /
//!   `droppedUnsafeLocationFindings`. Findings with no safe physical location are anchored to
//!   `SECURITY.md` with `result.properties.synthetic_location = true` and a logical location
//!   (`endpoint` or `resource`) so code-scanning UIs and cross-run fingerprints stay stable.
//! - Findings with `code_locations[].fix_before` + `fix_after` emit SARIF `fixes[].artifactChanges`.
//! - `partialFingerprints.primaryLocationLineHash` hashes stable structural primitives (`rule_id`,
//!   primary `uri` + `startLine`, `METHOD endpoint`, and curated class keyword for synthetic
//!   anchors), never LLM prose; `properties.ferret_vuln_class_hash` gives a file-independent class
//!   hash for cross-rename dismissal carryover.
//! - Weaponized PoC script bodies and credentials are NEVER embedded in SARIF; `properties.ferret.poc`
//!   carries only `description` and `handle_available: true` when a `poc_handle` is stored.
//! - Every cited `eN` evidence ID on findings and coverage entries is enriched from
//!   `ledger.evidence` under `properties.ferret.evidence_provenance` (`id`, `grade`, `kind`, `tool`,
//!   `session`, `call_id`, `handle`, `lines`, `attested`).
//! - Non-`reported` [`SurfaceCoverage`] rows ride in `results` as non-failing results (`level:
//!   "none"`): `no_issue_found` / `ruled_out` → `kind: "pass"`, `not_applicable` →
//!   `kind: "notApplicable"`, `needs_follow_up` → `kind: "open"`.
//! - `run.invocations[0]` sets `executionSuccessful: false` with `toolExecutionNotifications`
//!   warnings whenever coverage is incomplete (`needs_follow_up` rows, untouched `mandatory_open`
//!   assets, `silent_children`, operator release, or cleared surfaces without attested `run`
//!   evidence).
//! - [`write_sarif_report`] writes via a sibling temp file + atomic rename.

use crate::event::EvidenceGrade;
use crate::ledger::{Evidence, EvidenceKind, LedgerState};
use crate::security_state::{
    validate_cve, validate_cwe, validate_relative_posix_path, Finding, FindingStatus, SurfaceCoverage, SurfaceOutcome,
};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::path::Path;

pub const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
pub const SARIF_VERSION: &str = "2.1.0";
pub const TOOL_NAME: &str = "Ferret";
const SYNTHETIC_LOCATION_URI: &str = "SECURITY.md";
const COVERAGE_RULE_PREFIX: &str = "ferret-coverage";

/// Optional VCS provenance attached to a SARIF run for GitHub Code Scanning / ASPM alert binding.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RepositoryContext {
    pub repository_uri: Option<String>,
    pub repository_full_name: Option<String>,
    pub commit_sha: Option<String>,
    pub branch: Option<String>,
    pub git_ref: Option<String>,
}

/// A child session that ran in the mission without recording any coverage entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SilentChild {
    pub session: String,
    pub role: String,
}

/// Options controlling SARIF 2.1.0 generation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SarifOptions {
    pub tool_version: Option<String>,
    pub mission_id: Option<String>,
    pub repository: Option<RepositoryContext>,
    pub silent_children: Vec<SilentChild>,
}

/// Curated CWE -> STRIDE legs mapping (S, T, R, I, D, E).
fn stride_legs_for_cwe(cwe: Option<&str>) -> &'static [&'static str] {
    let Some(cwe) = cwe else { return &["T", "I"] };
    let digits: String = cwe.chars().filter(char::is_ascii_digit).collect();
    match digits.as_str() {
        // Spoofing
        "287" | "290" | "294" | "346" | "384" | "521" | "613" | "640" | "1391" => &["S"],
        "306" => &["S", "E"],
        "345" => &["S", "T"],
        "352" => &["T", "S"],
        "259" | "798" => &["S", "I"],
        // Tampering
        "20" | "89" | "91" | "434" => &["T"],
        "22" | "73" | "79" | "918" => &["T", "I"],
        "78" | "94" | "502" | "1336" => &["T", "E"],
        "915" => &["E", "T"],
        "611" => &["I", "T"],
        // Repudiation
        "117" | "223" | "778" => &["R"],
        // Information disclosure
        "200" | "201" | "209" | "256" | "311" | "319" | "327" | "328" | "522" | "525" | "532" | "538" | "598" => &["I"],
        // Denial of service
        "400" | "770" | "1333" => &["D"],
        // Elevation of privilege
        "269" | "284" | "285" | "639" | "732" | "862" | "863" | "1220" => &["E"],
        // Memory corruption (Tampering + EoP / Disclosure)
        "120" | "416" | "787" => &["T", "E"],
        "125" => &["I"],
        _ => &["T", "I"],
    }
}

/// Curated vulnerability-class keywords for file-independent class fingerprints (ordered specific -> general).
const VULN_CLASS_KEYWORDS: &[&str] = &[
    "missing authentication",
    "missing authorization",
    "broken access control",
    "incorrect authorization",
    "default credentials",
    "hardcoded credentials",
    "hardcoded secret",
    "hardcoded password",
    "default admin",
    "default password",
    "session fixation",
    "open redirect",
    "path traversal",
    "directory traversal",
    "command injection",
    "sql injection",
    "code injection",
    "template injection",
    "xpath injection",
    "ldap injection",
    "log injection",
    "header injection",
    "csv injection",
    "prompt injection",
    "deserialization",
    "buffer overflow",
    "use after free",
    "out of bounds",
    "ssrf",
    "xss",
    "csrf",
    "xxe",
    "race condition",
    "toctou",
    "information disclosure",
    "insecure direct object reference",
    "idor",
    "bola",
    "bfla",
    "cross-tenant",
    "cross-project",
    "tenant bypass",
    "auth bypass",
    "rate limiting",
    "rate limit",
    "weak cryptography",
    "weak hash",
    "weak random",
    "insecure random",
    "tls verification",
    "certificate verification",
    "denial of service",
    "regex denial of service",
    "redos",
    "supply chain",
];

/// Build an OASIS SARIF 2.1.0 document from the mission ledger.
pub fn build_sarif_report(ledger: &LedgerState, opts: &SarifOptions) -> Value {
    let ev_by_id: HashMap<&str, &Evidence> = ledger.evidence.iter().map(|e| (e.id.as_str(), e)).collect();

    let mut rules: Vec<Value> = Vec::new();
    let mut rule_index_by_id: HashMap<String, usize> = HashMap::new();
    let mut results: Vec<Value> = Vec::new();
    let mut synthetic_location_count = 0usize;
    let mut dropped_unsafe_location_findings: Vec<Value> = Vec::new();
    let mut dropped_unsafe_location_total = 0usize;
    let mut withdrawn_count = 0usize;

    for finding in ledger.security.findings.values() {
        if finding.status != FindingStatus::Active {
            withdrawn_count += 1;
            continue;
        }
        let (locations, is_synthetic, dropped_count) = build_finding_locations(finding);
        if is_synthetic {
            synthetic_location_count += 1;
        }
        if dropped_count > 0 {
            dropped_unsafe_location_total += dropped_count;
            dropped_unsafe_location_findings.push(json!({
                "id": finding.id,
                "title": finding.title,
                "droppedLocationCount": dropped_count,
            }));
        }

        let rule_id = finding_rule_id(finding);
        let rule_index = match rule_index_by_id.get(&rule_id) {
            Some(&idx) => idx,
            None => {
                let idx = rules.len();
                rule_index_by_id.insert(rule_id.clone(), idx);
                rules.push(build_finding_rule(&rule_id, finding));
                idx
            }
        };

        results.push(build_finding_result(&rule_id, rule_index, finding, locations, is_synthetic, &ev_by_id));
    }

    // Non-reported per-surface coverage rides alongside alerts as non-failing SARIF results.
    for entry in ledger.security.surface_coverage.values() {
        let Some(kind) = coverage_sarif_kind(entry.outcome) else {
            continue;
        };
        let rule_id = coverage_rule_id(&entry.risk_area);
        let rule_index = match rule_index_by_id.get(&rule_id) {
            Some(&idx) => idx,
            None => {
                let idx = rules.len();
                rule_index_by_id.insert(rule_id.clone(), idx);
                rules.push(build_coverage_rule(&rule_id, &entry.risk_area));
                idx
            }
        };
        results.push(build_coverage_result(&rule_id, rule_index, kind, entry, &ev_by_id));
    }

    let mut driver = Map::new();
    driver.insert("name".into(), json!(TOOL_NAME));
    driver.insert("version".into(), json!(opts.tool_version.as_deref().unwrap_or(env!("CARGO_PKG_VERSION"))));
    driver.insert("rules".into(), Value::Array(rules));

    let mut run = Map::new();
    run.insert("tool".into(), json!({ "driver": Value::Object(driver) }));
    run.insert("results".into(), Value::Array(results));
    run.insert("invocations".into(), Value::Array(vec![build_invocation(ledger, opts, &ev_by_id)]));

    let mut run_properties = Map::new();
    if let Some(mid) = opts.mission_id.as_deref().filter(|s| !s.trim().is_empty()) {
        run_properties.insert("missionId".into(), json!(mid));
    }
    if synthetic_location_count > 0 {
        run_properties.insert("syntheticLocationCount".into(), json!(synthetic_location_count));
    }
    if dropped_unsafe_location_total > 0 {
        run_properties.insert("droppedUnsafeLocationCount".into(), json!(dropped_unsafe_location_total));
        run_properties.insert("droppedUnsafeLocationFindings".into(), Value::Array(dropped_unsafe_location_findings));
    }
    if withdrawn_count > 0 {
        run_properties.insert("withdrawnFindingCount".into(), json!(withdrawn_count));
    }
    if !ledger.security.surface_coverage.is_empty() || !ledger.security.assets.is_empty() {
        run_properties.insert("coverageProvenance".into(), build_coverage_provenance_summary(ledger, &ev_by_id));
    }

    if let Some(repo) = &opts.repository {
        apply_repository_context(&mut run, &mut run_properties, repo);
    }

    if !run_properties.is_empty() {
        run.insert("properties".into(), Value::Object(run_properties));
    }

    json!({
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [Value::Object(run)],
    })
}

/// Write a SARIF 2.1.0 report atomically to `output_path` via a sibling temp file + rename.
pub fn write_sarif_report(output_path: &Path, ledger: &LedgerState, opts: &SarifOptions) -> std::io::Result<()> {
    if let Some(parent) = output_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let sarif = build_sarif_report(ledger, opts);
    let mut bytes =
        serde_json::to_vec_pretty(&sarif).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    bytes.push(b'\n');

    let file_name = output_path.file_name().and_then(|n| n.to_str()).unwrap_or("findings.sarif");
    let tmp_path = output_path.with_file_name(format!(".{file_name}.{}.tmp", std::process::id()));
    let write_res = (|| -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp_path)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp_path, output_path)?;
        Ok(())
    })();
    if write_res.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    write_res
}

fn apply_repository_context(
    run: &mut Map<String, Value>,
    run_properties: &mut Map<String, Value>,
    ctx: &RepositoryContext,
) {
    let full_name = ctx.repository_full_name.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let uri = ctx.repository_uri.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let commit = ctx.commit_sha.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let branch = ctx.branch.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let git_ref = ctx.git_ref.as_deref().map(str::trim).filter(|s| !s.is_empty());

    if let Some(name) = full_name {
        run.insert("automationDetails".into(), json!({ "id": format!("ferret/{name}") }));
        run_properties.insert("repository".into(), json!(name));
    }
    if let Some(u) = uri {
        let mut prov = Map::new();
        prov.insert("repositoryUri".into(), json!(u));
        if let Some(c) = commit {
            prov.insert("revisionId".into(), json!(c));
        }
        if let Some(b) = branch {
            prov.insert("branch".into(), json!(b));
        }
        run.insert("versionControlProvenance".into(), Value::Array(vec![Value::Object(prov)]));
    }
    if let Some(r) = git_ref {
        run_properties.insert("ref".into(), json!(r));
    }
    if let Some(c) = commit {
        run_properties.insert("commit_sha".into(), json!(c));
    }
}

fn finding_rule_id(finding: &Finding) -> String {
    if let Some(cwe) = finding.cwe.as_deref() {
        if let Ok(norm) = validate_cwe(cwe) {
            return norm;
        }
        let digits: String = cwe.chars().filter(char::is_ascii_digit).collect();
        if !digits.is_empty() {
            return format!("CWE-{digits}");
        }
    }
    if let Some(cve) = finding.cve.as_deref() {
        if let Ok(norm) = validate_cve(cve) {
            return norm;
        }
        if !cve.trim().is_empty() {
            return cve.trim().to_string();
        }
    }
    if !finding.id.trim().is_empty() {
        return finding.id.clone();
    }
    slugify(&finding.title)
}

fn security_severity_str(finding: &Finding) -> String {
    match finding.cvss {
        Some(score) => score.format_one_decimal(),
        None => finding.severity.fallback_security_severity().to_string(),
    }
}

fn build_finding_rule(rule_id: &str, finding: &Finding) -> Value {
    let help_text = {
        let mut parts = Vec::new();
        if !finding.description.trim().is_empty() {
            parts.push(finding.description.trim());
        }
        if !finding.impact.trim().is_empty() {
            parts.push(finding.impact.trim());
        }
        if let Some(rem) = finding.remediation_steps.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            parts.push(rem);
        }
        if parts.is_empty() {
            finding.title.clone()
        } else {
            parts.join("\n\n")
        }
    };

    let mut tags = vec!["security".to_string()];
    if rule_id.starts_with("CWE-") {
        tags.push(rule_id.to_string());
    }
    if let Some(cve) = finding.cve.as_deref().filter(|s| !s.is_empty()) {
        if !tags.iter().any(|t| t == cve) {
            tags.push(cve.to_string());
        }
    }
    for leg in stride_legs_for_cwe(finding.cwe.as_deref()) {
        let tag = format!("stride:{leg}");
        if !tags.contains(&tag) {
            tags.push(tag);
        }
    }

    let mut rule = Map::new();
    rule.insert("id".into(), json!(rule_id));
    rule.insert("name".into(), json!(finding.title));
    rule.insert("shortDescription".into(), json!({ "text": finding.title }));
    rule.insert("fullDescription".into(), json!({ "text": finding.description }));
    rule.insert("defaultConfiguration".into(), json!({ "level": finding.severity.sarif_level() }));
    rule.insert("help".into(), json!({ "text": help_text, "markdown": help_text }));
    rule.insert(
        "properties".into(),
        json!({
            "security-severity": security_severity_str(finding),
            "tags": tags,
        }),
    );
    if let Some(digits) = rule_id.strip_prefix("CWE-") {
        rule.insert("helpUri".into(), json!(format!("https://cwe.mitre.org/data/definitions/{digits}.html")));
    }
    Value::Object(rule)
}

fn build_finding_locations(finding: &Finding) -> (Vec<Value>, bool, usize) {
    let mut physical = Vec::new();
    let mut dropped = 0usize;
    for loc in &finding.code_locations {
        if loc.start_line < 1 {
            dropped += 1;
            continue;
        }
        let Ok(uri) = validate_relative_posix_path(&loc.file) else {
            dropped += 1;
            continue;
        };
        let mut region = Map::new();
        region.insert("startLine".into(), json!(loc.start_line));
        if loc.end_line >= loc.start_line {
            region.insert("endLine".into(), json!(loc.end_line));
        }
        if let Some(snippet) = loc.snippet.as_deref().filter(|s| !s.trim().is_empty()) {
            region.insert("snippet".into(), json!({ "text": snippet }));
        }
        let mut entry = Map::new();
        entry.insert(
            "physicalLocation".into(),
            json!({
                "artifactLocation": { "uri": uri },
                "region": Value::Object(region),
            }),
        );
        if let Some(label) = loc.label.as_deref().filter(|s| !s.trim().is_empty()) {
            entry.insert("message".into(), json!({ "text": label }));
        }
        physical.push(Value::Object(entry));
    }

    let is_synthetic = physical.is_empty();
    let mut locations = if is_synthetic {
        vec![json!({ "physicalLocation": { "artifactLocation": { "uri": SYNTHETIC_LOCATION_URI } } })]
    } else {
        physical
    };

    if let Some(endpoint) = finding.endpoint.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        locations.push(json!({
            "logicalLocations": [{ "fullyQualifiedName": endpoint, "kind": "endpoint" }]
        }));
    } else if is_synthetic {
        let resource = if !finding.target.trim().is_empty() { finding.target.trim() } else { finding.title.trim() };
        if !resource.is_empty() {
            locations.push(json!({
                "logicalLocations": [{ "fullyQualifiedName": resource, "kind": "resource" }]
            }));
        }
    }

    (locations, is_synthetic, dropped)
}

fn build_fixes(finding: &Finding) -> Option<Vec<Value>> {
    let mut artifact_changes = Vec::new();
    for loc in &finding.code_locations {
        let (Some(before), Some(after)) = (
            loc.fix_before.as_deref().filter(|s| !s.trim().is_empty()),
            loc.fix_after.as_deref().filter(|s| !s.trim().is_empty()),
        ) else {
            continue;
        };
        let _ = before;
        if loc.start_line < 1 {
            continue;
        }
        let Ok(uri) = validate_relative_posix_path(&loc.file) else {
            continue;
        };
        let mut deleted_region = Map::new();
        deleted_region.insert("startLine".into(), json!(loc.start_line));
        if loc.end_line >= loc.start_line {
            deleted_region.insert("endLine".into(), json!(loc.end_line));
        }
        artifact_changes.push(json!({
            "artifactLocation": { "uri": uri },
            "replacements": [{
                "deletedRegion": Value::Object(deleted_region),
                "insertedContent": { "text": after },
            }],
        }));
    }
    if artifact_changes.is_empty() {
        return None;
    }
    let mut fix = Map::new();
    fix.insert("artifactChanges".into(), Value::Array(artifact_changes));
    if let Some(rem) = finding.remediation_steps.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        fix.insert("description".into(), json!({ "text": rem, "markdown": rem }));
    }
    Some(vec![Value::Object(fix)])
}

fn build_finding_result(
    rule_id: &str,
    rule_index: usize,
    finding: &Finding,
    locations: Vec<Value>,
    is_synthetic: bool,
    ev_by_id: &HashMap<&str, &Evidence>,
) -> Value {
    let message_text = if finding.description.trim().is_empty() {
        finding.title.clone()
    } else {
        format!("{}\n\n{}", finding.title, finding.description)
    };

    let mut result = Map::new();
    result.insert("ruleId".into(), json!(rule_id));
    result.insert("ruleIndex".into(), json!(rule_index));
    result.insert("kind".into(), json!("fail"));
    result.insert("level".into(), json!(finding.severity.sarif_level()));
    result.insert("message".into(), json!({ "text": message_text }));
    if !locations.is_empty() {
        result.insert("locations".into(), Value::Array(locations.clone()));
    }
    if let Some(fixes) = build_fixes(finding) {
        result.insert("fixes".into(), Value::Array(fixes));
    }
    if let Some(fp) = primary_fingerprint(rule_id, finding, &locations, is_synthetic) {
        result.insert("partialFingerprints".into(), json!({ "primaryLocationLineHash": fp }));
    }

    let class_fp = class_fingerprint(rule_id, &finding.title);
    let mut props = Map::new();
    props.insert("security-severity".into(), json!(security_severity_str(finding)));
    if let Some(cfp) = class_fp {
        props.insert("ferret_vuln_class_hash".into(), json!(cfp));
    }
    if is_synthetic {
        props.insert("synthetic_location".into(), json!(true));
    }

    let mut ferret = Map::new();
    ferret.insert("id".into(), json!(finding.id));
    ferret.insert("severity".into(), json!(finding.severity.as_str()));
    if let Some(score) = finding.cvss {
        ferret.insert("cvss".into(), json!(score));
    }
    if let Some(vec) = &finding.cvss_vector {
        ferret.insert("cvss_vector".into(), json!(vec));
    }
    if let Some(bd) = &finding.cvss_breakdown {
        ferret.insert("cvss_breakdown".into(), json!(bd));
    }
    ferret.insert("target".into(), json!(finding.target));
    if let Some(ep) = &finding.endpoint {
        ferret.insert("endpoint".into(), json!(ep));
    }
    if let Some(m) = &finding.method {
        ferret.insert("method".into(), json!(m));
    }
    if let Some(cve) = &finding.cve {
        ferret.insert("cve".into(), json!(cve));
    }
    if let Some(cwe) = &finding.cwe {
        ferret.insert("cwe".into(), json!(cwe));
    }
    ferret.insert("impact".into(), json!(finding.impact));
    if let Some(v) = &finding.technical_analysis {
        ferret.insert("technical_analysis".into(), json!(v));
    }
    if let Some(v) = &finding.remediation_steps {
        ferret.insert("remediation_steps".into(), json!(v));
    }
    if let Some(v) = &finding.assumptions {
        ferret.insert("assumptions".into(), json!(v));
    }
    ferret.insert("counterevidence".into(), json!(finding.counterevidence));
    ferret.insert("confidence".into(), json!(finding.confidence.as_str()));
    if let Some(v) = &finding.confidence_rationale {
        ferret.insert("confidence_rationale".into(), json!(v));
    }
    ferret.insert("severity_change_conditions".into(), json!(finding.severity_change_conditions));
    if let Some(v) = finding.fix_effort {
        ferret.insert("fix_effort".into(), json!(v.as_str()));
    }
    if let Some(v) = &finding.fix_verification {
        ferret.insert("fix_verification".into(), json!(v));
    }
    if finding.poc_description.is_some() || finding.poc_handle.is_some() {
        let mut poc = Map::new();
        if let Some(desc) = &finding.poc_description {
            poc.insert("description".into(), json!(desc));
        }
        if finding.poc_handle.is_some() {
            // Never embed raw exploit script bodies in SARIF intended for external upload.
            poc.insert("script_available".into(), json!(true));
        }
        ferret.insert("poc".into(), Value::Object(poc));
    }
    if !finding.http_exchanges.is_empty() {
        ferret.insert("http_exchanges".into(), json!(finding.http_exchanges));
    }
    if let Some(a) = &finding.asset {
        ferret.insert("asset".into(), json!(a));
    }
    if let Some(c) = &finding.claim {
        ferret.insert("claim".into(), json!(c));
    }
    if let Some(fp) = &finding.fingerprint {
        ferret.insert("fingerprint".into(), json!(fp));
    }
    ferret.insert("recorded_by".into(), json!(finding.recorded_by));
    ferret.insert("updated_by".into(), json!(finding.updated_by));
    ferret.insert("evidence_provenance".into(), Value::Array(resolve_evidence_provenance(&finding.evidence, ev_by_id)));

    props.insert("ferret".into(), Value::Object(ferret));
    result.insert("properties".into(), Value::Object(props));
    Value::Object(result)
}

fn coverage_sarif_kind(outcome: SurfaceOutcome) -> Option<&'static str> {
    match outcome {
        SurfaceOutcome::Reported => None,
        SurfaceOutcome::NoIssueFound | SurfaceOutcome::RuledOut => Some("pass"),
        SurfaceOutcome::NotApplicable => Some("notApplicable"),
        SurfaceOutcome::NeedsFollowUp => Some("open"),
    }
}

fn coverage_rule_id(risk_area: &str) -> String {
    format!("{COVERAGE_RULE_PREFIX}/{}", slugify(risk_area))
}

fn build_coverage_rule(rule_id: &str, risk_area: &str) -> Value {
    let desc = format!("Coverage of {risk_area} across the assessed attack surface.");
    json!({
        "id": rule_id,
        "name": risk_area,
        "shortDescription": { "text": format!("Coverage: {risk_area}") },
        "fullDescription": { "text": desc },
        "defaultConfiguration": { "level": "none" },
        "help": { "text": desc, "markdown": desc },
        "properties": { "tags": ["coverage"] },
    })
}

fn build_coverage_result(
    rule_id: &str,
    rule_index: usize,
    kind: &str,
    entry: &SurfaceCoverage,
    ev_by_id: &HashMap<&str, &Evidence>,
) -> Value {
    let mut detail_parts = Vec::new();
    if let (Some(ctrl), Some(loc)) = (&entry.control, &entry.location) {
        detail_parts.push(format!("Control: {ctrl} at {loc}"));
    } else if let Some(ctrl) = &entry.control {
        detail_parts.push(format!("Control: {ctrl}"));
    }
    if let Some(reason) = &entry.reason {
        detail_parts.push(reason.clone());
    }
    let head = format!("{} — {}: {}", entry.risk_area, entry.outcome.label(), entry.surface);
    let message = if detail_parts.is_empty() { head } else { format!("{head}\n\n{}", detail_parts.join("\n")) };

    let mut ferret = Map::new();
    ferret.insert("id".into(), json!(entry.id));
    ferret.insert("coverage_outcome".into(), json!(entry.outcome.as_str()));
    ferret.insert("risk_area".into(), json!(entry.risk_area));
    ferret.insert("surface".into(), json!(entry.surface));
    if let Some(a) = &entry.asset {
        ferret.insert("asset".into(), json!(a));
    }
    if let Some(c) = &entry.control {
        ferret.insert("control".into(), json!(c));
    }
    if let Some(l) = &entry.location {
        ferret.insert("location".into(), json!(l));
    }
    if let Some(r) = &entry.reason {
        ferret.insert("reason".into(), json!(r));
    }
    ferret.insert("recorded_by".into(), json!(entry.recorded_by));
    ferret.insert("updated_by".into(), json!(entry.updated_by));
    ferret.insert("source".into(), json!("agent_reported"));
    ferret.insert("history_count".into(), json!(entry.history.len()));
    ferret.insert("evidence_provenance".into(), Value::Array(resolve_evidence_provenance(&entry.evidence, ev_by_id)));

    json!({
        "ruleId": rule_id,
        "ruleIndex": rule_index,
        "kind": kind,
        "level": "none",
        "message": { "text": message },
        "locations": [{ "logicalLocations": [{ "fullyQualifiedName": entry.surface, "kind": "surface" }] }],
        "properties": { "ferret": Value::Object(ferret) },
    })
}

fn build_invocation(ledger: &LedgerState, opts: &SarifOptions, ev_by_id: &HashMap<&str, &Evidence>) -> Value {
    let mut caveats: Vec<String> = Vec::new();
    let follow_ups = ledger.security.surface_coverage_follow_ups();
    for fu in &follow_ups {
        let gap = fu.reason.as_deref().unwrap_or("unspecified proof gap");
        caveats.push(format!("Open coverage follow-up on `{}` ({}): {gap}", fu.surface, fu.risk_area));
    }
    let mandatory_open = ledger.security.mandatory_open();
    if !mandatory_open.is_empty() {
        caveats.push(format!(
            "{} mandatory security asset(s) remain untested: {}",
            mandatory_open.len(),
            mandatory_open.join(", ")
        ));
    }
    for child in &opts.silent_children {
        caveats.push(format!(
            "Child session `{}` (role `{}`) recorded no per-surface coverage entries.",
            child.session, child.role
        ));
    }
    if let Some(rel) = &ledger.release {
        caveats.push(format!("Mission was released by the operator short of the goal: {}", rel.reason));
    }

    // Also warn (without failing executionSuccessful on its own? Wait: an unbacked clear is a provenance caveat!)
    let mut unbacked_clears = 0usize;
    for entry in ledger.security.surface_coverage.values() {
        if matches!(entry.outcome, SurfaceOutcome::NoIssueFound | SurfaceOutcome::RuledOut) {
            let has_run = entry.evidence.iter().any(|id| {
                ev_by_id
                    .get(id.as_str())
                    .is_some_and(|e| e.input.attested && e.input.grade_or_kind() == EvidenceGrade::Run)
            });
            if !has_run {
                unbacked_clears += 1;
            }
        }
    }
    if unbacked_clears > 0 {
        caveats.push(format!(
            "{unbacked_clears} cleared surface coverage entry/entries (no_issue_found or ruled_out) carry no attested `run` execution evidence (agent-reported or static-only)."
        ));
    }

    let complete = follow_ups.is_empty()
        && mandatory_open.is_empty()
        && opts.silent_children.is_empty()
        && ledger.release.is_none();

    let mut inv = Map::new();
    inv.insert("executionSuccessful".into(), json!(complete));
    if !caveats.is_empty() {
        inv.insert(
            "toolExecutionNotifications".into(),
            Value::Array(
                caveats.into_iter().map(|text| json!({ "level": "warning", "message": { "text": text } })).collect(),
            ),
        );
    }
    Value::Object(inv)
}

fn build_coverage_provenance_summary(ledger: &LedgerState, ev_by_id: &HashMap<&str, &Evidence>) -> Value {
    let mut grade_counts: BTreeMap<&'static str, usize> =
        BTreeMap::from([("run", 0), ("analysis", 0), ("read", 0), ("reference", 0)]);
    for e in ledger.evidence.iter().filter(|e| e.input.attested) {
        *grade_counts.entry(e.input.grade_or_kind().as_str()).or_default() += 1;
    }
    let cleared_with_run = ledger
        .security
        .surface_coverage
        .values()
        .filter(|c| matches!(c.outcome, SurfaceOutcome::NoIssueFound | SurfaceOutcome::RuledOut))
        .filter(|c| {
            c.evidence.iter().any(|id| {
                ev_by_id
                    .get(id.as_str())
                    .is_some_and(|e| e.input.attested && e.input.grade_or_kind() == EvidenceGrade::Run)
            })
        })
        .count();
    json!({
        "agent_reported": {
            "total": ledger.security.surface_coverage.len(),
            "outcome_counts": ledger.security.surface_coverage_counts(),
        },
        "machine_observed": {
            "mandatory_open_count": ledger.security.mandatory_open().len(),
            "assets_count": ledger.security.assets.len(),
            "attested_evidence_grades": grade_counts,
            "cleared_surfaces_with_attested_run": cleared_with_run,
        },
    })
}

/// Resolve evidence IDs to machine-observed provenance records from the mission ledger.
pub fn resolve_evidence_provenance(ids: &[String], ev_by_id: &HashMap<&str, &Evidence>) -> Vec<Value> {
    ids.iter()
        .map(|id| match ev_by_id.get(id.as_str()) {
            Some(e) => {
                let mut m = Map::new();
                m.insert("id".into(), json!(e.id));
                m.insert("grade".into(), json!(e.input.grade_or_kind().as_str()));
                m.insert(
                    "kind".into(),
                    json!(match e.input.kind {
                        EvidenceKind::Execution => "execution",
                        EvidenceKind::Static => "static",
                    }),
                );
                if let Some(t) = &e.input.tool {
                    m.insert("tool".into(), json!(t));
                }
                m.insert("session".into(), json!(e.input.session));
                m.insert("call_id".into(), json!(e.input.call_id));
                if let Some(b) = &e.input.blob {
                    m.insert("handle".into(), json!(format!("out:{}", b.as_str())));
                }
                if let Some((a, b)) = e.input.lines {
                    m.insert("lines".into(), json!([a, b]));
                }
                m.insert("attested".into(), json!(e.input.attested));
                Value::Object(m)
            }
            None => json!({ "id": id, "attested": false, "missing": true }),
        })
        .collect()
}

fn primary_fingerprint(rule_id: &str, finding: &Finding, locations: &[Value], is_synthetic: bool) -> Option<String> {
    let first_phys = locations.iter().find_map(|l| l.get("physicalLocation"));
    let uri = first_phys
        .and_then(|p| p.get("artifactLocation"))
        .and_then(|a| a.get("uri"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let start_line = first_phys
        .and_then(|p| p.get("region"))
        .and_then(|r| r.get("startLine"))
        .and_then(Value::as_u64)
        .filter(|&l| l >= 1);

    let method = finding.method.as_deref().unwrap_or("").trim().to_ascii_uppercase();
    let endpoint = finding.endpoint.as_deref().unwrap_or("").trim();
    let route = format!("{method} {endpoint}").trim().to_string();

    if uri.is_empty() && route.is_empty() {
        return None;
    }

    let mut parts = vec![format!("rule:{rule_id}")];
    if !uri.is_empty() {
        parts.push(format!("uri:{uri}"));
        if let Some(sl) = start_line {
            parts.push(format!("line:{sl}"));
        }
    }
    if !route.is_empty() {
        parts.push(format!("route:{route}"));
    }
    if is_synthetic {
        let kw = class_keyword(&finding.title);
        if !kw.is_empty() {
            parts.push(format!("synth_class:{kw}"));
        }
    }
    Some(crate::sha256_hex(parts.join("|").as_bytes()))
}

fn class_fingerprint(rule_id: &str, title: &str) -> Option<String> {
    let kw = class_keyword(title);
    if kw.is_empty() {
        return None;
    }
    Some(crate::sha256_hex(format!("rule:{rule_id}|class:{kw}").as_bytes()))
}

fn class_keyword(title: &str) -> String {
    let lower = title.to_ascii_lowercase();
    for kw in VULN_CLASS_KEYWORDS {
        if lower.contains(kw) {
            return (*kw).to_string();
        }
    }
    let mut words = Vec::new();
    let mut cur = String::new();
    for ch in lower.chars() {
        if ch.is_ascii_alphanumeric() {
            cur.push(ch);
        } else if !cur.is_empty() {
            words.push(std::mem::take(&mut cur));
            if words.len() == 5 {
                break;
            }
        }
    }
    if !cur.is_empty() && words.len() < 5 {
        words.push(cur);
    }
    words.join(" ")
}

fn slugify(value: &str) -> String {
    let mut out = String::new();
    let mut prev_dash = true;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "unspecified".to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{BlobId, CallId, SessionId};
    use crate::ledger::{Entry, EvidenceInput, LedgerOp};
    use crate::security_state::{
        CodeLocation, CvssBreakdown, FindingConfidence, FindingInput, FindingSeverity, FindingUpdateInput, FixEffort,
        SecurityOp,
    };

    fn seeded_ledger() -> LedgerState {
        let mut l = LedgerState::default();
        l.evidence.push(Evidence {
            id: "e1".into(),
            n: 1,
            input: EvidenceInput {
                claim: "c1".into(),
                kind: EvidenceKind::Execution,
                supports: true,
                session: SessionId::from("s-lead"),
                call_id: CallId::from("call-1"),
                blob: Some(BlobId::from("a".repeat(64))),
                lines: Some((1, 4)),
                quote: Some("HTTP/1.1 200 OK".into()),
                note: "executed SQLi probe".into(),
                attested: true,
                tool: Some("bash".into()),
                grade: Some(EvidenceGrade::Run),
            },
        });
        l.evidence.push(Evidence {
            id: "e2".into(),
            n: 2,
            input: EvidenceInput {
                claim: "c1".into(),
                kind: EvidenceKind::Static,
                supports: true,
                session: SessionId::from("s-lead"),
                call_id: CallId::from("call-2"),
                blob: None,
                lines: None,
                quote: None,
                note: "read auth middleware".into(),
                attested: true,
                tool: Some("read".into()),
                grade: Some(EvidenceGrade::Read),
            },
        });
        l
    }

    fn apply_sec(l: &mut LedgerState, session: &str, op: SecurityOp) {
        l.validate(&LedgerOp::Security(op.clone()), false).unwrap();
        l.apply(&Entry {
            n: l.entries + 1,
            ts_ms: 0,
            session: SessionId::from(session),
            from_user: false,
            op: LedgerOp::Security(op),
            mac: String::new(),
        });
    }

    #[test]
    fn sarif_emits_valid_findings_fixes_fingerprints_stride_and_coverage() {
        let mut l = seeded_ledger();
        let finding = FindingInput {
            title: "SQL Injection in /api/users search parameter".into(),
            description: "The `q` parameter is interpolated directly into a SQL query.".into(),
            impact: "Unauthenticated attacker reads all database rows.".into(),
            target: "https://app.example.test".into(),
            evidence: vec!["e1".into()],
            counterevidence: "Checked router and DB layer; no parameterization or WAF found.".into(),
            confidence: FindingConfidence::High,
            confidence_rationale: None,
            severity_change_conditions: "Restricting this endpoint to admin accounts would lower PR to H.".into(),
            cvss_breakdown: Some(CvssBreakdown {
                attack_vector: "N".into(),
                attack_complexity: "L".into(),
                privileges_required: "N".into(),
                user_interaction: "N".into(),
                scope: "U".into(),
                confidentiality: "H".into(),
                integrity: "H".into(),
                availability: "H".into(),
            }),
            severity: None,
            technical_analysis: Some("Direct string formatting in `src/db/users.py`.".into()),
            remediation_steps: Some("Use parameterized SQL placeholders.".into()),
            assumptions: Some("Endpoint is reachable over the network.".into()),
            poc_description: Some("1. Send crafted SQL payload to /api/users?q=...".into()),
            poc_handle: Some(format!("out:{}", "deadbeef".repeat(2))),
            fix_effort: Some(FixEffort::Low),
            endpoint: Some("/api/users".into()),
            method: Some("GET".into()),
            cve: None,
            cwe: Some("CWE-89".into()),
            code_locations: vec![CodeLocation {
                file: "src/db/users.py".into(),
                start_line: 42,
                end_line: 43,
                snippet: Some("cur.execute(f\"SELECT * FROM users WHERE name = '{q}'\")".into()),
                label: Some("SQL sink".into()),
                fix_before: Some("cur.execute(f\"SELECT * FROM users WHERE name = '{q}'\")".into()),
                fix_after: Some("cur.execute(\"SELECT * FROM users WHERE name = %s\", (q,))".into()),
            }],
            fix_verification: Some(
                "1. Closure: parameter binding prevents SQL syntax injection. 2. Bypass: checked sibling queries. 3. Preserved: normal search returns identical rows. 4. Executed unit tests."
                    .into(),
            ),
            http_exchanges: vec!["ex-1".into()],
            asset: None,
            claim: None,
        };
        apply_sec(&mut l, "s-lead", SecurityOp::FindingRecord { finding: Box::new(finding) });

        // Add coverage entries across dispositions
        apply_sec(
            &mut l,
            "s-lead",
            SecurityOp::CoverageRecord {
                surface: "POST /api/login".into(),
                risk_area: "SQL injection".into(),
                outcome: SurfaceOutcome::RuledOut,
                control: Some("Prepared statement via sqlx::query!".into()),
                location: Some("src/auth/login.rs:88".into()),
                reason: Some("Verified all login paths use compile-time checked bound queries.".into()),
                evidence: vec!["e2".into()],
                asset: None,
            },
        );
        apply_sec(
            &mut l,
            "s-lead",
            SecurityOp::CoverageRecord {
                surface: "POST /api/export".into(),
                risk_area: "XXE".into(),
                outcome: SurfaceOutcome::NotApplicable,
                control: None,
                location: None,
                reason: Some("Endpoint accepts JSON only; no XML parser is linked.".into()),
                evidence: vec![],
                asset: None,
            },
        );
        apply_sec(
            &mut l,
            "s-lead",
            SecurityOp::CoverageRecord {
                surface: "POST /api/billing/refund".into(),
                risk_area: "IDOR / BOLA".into(),
                outcome: SurfaceOutcome::NeedsFollowUp,
                control: None,
                location: None,
                reason: Some("Need second tenant account credentials to test cross-tenant refund.".into()),
                evidence: vec![],
                asset: None,
            },
        );

        let opts = SarifOptions {
            tool_version: Some("1.2.3".into()),
            mission_id: Some("m-test".into()),
            repository: Some(RepositoryContext {
                repository_uri: Some("https://github.com/acme/app".into()),
                repository_full_name: Some("acme/app".into()),
                commit_sha: Some("0123456789abcdef".into()),
                branch: Some("main".into()),
                git_ref: Some("refs/heads/main".into()),
            }),
            silent_children: vec![SilentChild { session: "s-child-1".into(), role: "scanner".into() }],
        };
        let doc = build_sarif_report(&l, &opts);
        assert_eq!(doc["version"], SARIF_VERSION);
        assert_eq!(doc["$schema"], SARIF_SCHEMA);

        let run = &doc["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "Ferret");
        assert_eq!(run["tool"]["driver"]["version"], "1.2.3");
        assert_eq!(run["automationDetails"]["id"], "ferret/acme/app");
        assert_eq!(run["versionControlProvenance"][0]["revisionId"], "0123456789abcdef");

        let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
        let cwe_rule = rules.iter().find(|r| r["id"] == "CWE-89").unwrap();
        assert_eq!(cwe_rule["properties"]["security-severity"], "9.8");
        assert_eq!(cwe_rule["helpUri"], "https://cwe.mitre.org/data/definitions/89.html");
        let tags: Vec<&str> =
            cwe_rule["properties"]["tags"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
        assert!(tags.contains(&"security") && tags.contains(&"CWE-89") && tags.contains(&"stride:T"));

        let results = run["results"].as_array().unwrap();
        // 1 failing finding + 3 non-reported coverage entries
        assert_eq!(results.len(), 4);
        let alert = results.iter().find(|r| r["kind"] == "fail").unwrap();
        assert_eq!(alert["ruleId"], "CWE-89");
        assert_eq!(alert["level"], "error");
        assert!(alert["partialFingerprints"]["primaryLocationLineHash"].as_str().unwrap().len() == 64);
        assert!(alert["properties"]["ferret_vuln_class_hash"].as_str().unwrap().len() == 64);
        assert_eq!(alert["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "src/db/users.py");
        assert_eq!(alert["locations"][1]["logicalLocations"][0]["fullyQualifiedName"], "/api/users");
        assert_eq!(
            alert["fixes"][0]["artifactChanges"][0]["replacements"][0]["insertedContent"]["text"],
            "cur.execute(\"SELECT * FROM users WHERE name = %s\", (q,))"
        );
        // PoC never leaks handle/body, only script_available
        assert_eq!(alert["properties"]["ferret"]["poc"]["script_available"], true);
        assert!(alert["properties"]["ferret"]["poc"].get("poc_handle").is_none());
        // Attested evidence provenance included
        assert_eq!(alert["properties"]["ferret"]["evidence_provenance"][0]["grade"], "run");
        assert_eq!(alert["properties"]["ferret"]["evidence_provenance"][0]["tool"], "bash");

        // Coverage results
        let pass = results.iter().find(|r| r["kind"] == "pass").unwrap();
        assert_eq!(pass["level"], "none");
        assert_eq!(pass["properties"]["ferret"]["coverage_outcome"], "ruled_out");
        assert_eq!(pass["properties"]["ferret"]["source"], "agent_reported");
        let na = results.iter().find(|r| r["kind"] == "notApplicable").unwrap();
        assert_eq!(na["level"], "none");
        let open = results.iter().find(|r| r["kind"] == "open").unwrap();
        assert_eq!(open["level"], "none");

        // Invocations mark incomplete run (open follow-up + silent child + unbacked static clear)
        let inv = &run["invocations"][0];
        assert_eq!(inv["executionSuccessful"], false);
        let notes = inv["toolExecutionNotifications"].as_array().unwrap();
        assert!(notes.iter().any(|n| n["message"]["text"].as_str().unwrap().contains("Open coverage follow-up")));
        assert!(notes.iter().any(|n| n["message"]["text"].as_str().unwrap().contains("s-child-1")));
        assert!(notes.iter().any(|n| n["message"]["text"].as_str().unwrap().contains("no attested `run`")));
    }

    #[test]
    fn sarif_anchors_locationless_dast_findings_and_skips_withdrawn() {
        let mut l = seeded_ledger();
        let f1 = FindingInput {
            title: "Broken Access Control on admin export".into(),
            description: "Low-privilege user downloads admin audit log.".into(),
            impact: "Full audit log disclosure.".into(),
            target: "https://api.example.test".into(),
            evidence: vec!["e1".into()],
            counterevidence: "Tested with standard member token; no role check enforced.".into(),
            confidence: FindingConfidence::High,
            confidence_rationale: None,
            severity_change_conditions: "Restricting export to tenant scope would reduce C to L.".into(),
            cvss_breakdown: None,
            severity: Some(FindingSeverity::High),
            technical_analysis: None,
            remediation_steps: None,
            assumptions: None,
            poc_description: None,
            poc_handle: None,
            fix_effort: None,
            endpoint: Some("/admin/export".into()),
            method: Some("GET".into()),
            cve: None,
            cwe: Some("CWE-862".into()),
            code_locations: vec![],
            fix_verification: None,
            http_exchanges: vec![],
            asset: None,
            claim: None,
        };
        let f1_id = f1.id();
        apply_sec(&mut l, "s-lead", SecurityOp::FindingRecord { finding: Box::new(f1) });

        let mut f2 = FindingInput {
            title: "SQL Injection on search".into(),
            description: "Initially suspected SQLi.".into(),
            impact: "None after retest.".into(),
            target: "https://api.example.test".into(),
            evidence: vec!["e1".into()],
            counterevidence: "Parameterized query confirmed on retest.".into(),
            confidence: FindingConfidence::Low,
            confidence_rationale: Some("Unconfirmed error string only.".into()),
            severity_change_conditions: "Confirming injection would raise to critical.".into(),
            cvss_breakdown: None,
            severity: Some(FindingSeverity::Medium),
            technical_analysis: None,
            remediation_steps: None,
            assumptions: None,
            poc_description: None,
            poc_handle: None,
            fix_effort: None,
            endpoint: None,
            method: None,
            cve: None,
            cwe: Some("CWE-89".into()),
            code_locations: vec![],
            fix_verification: None,
            http_exchanges: vec![],
            asset: None,
            claim: None,
        };
        f2.endpoint = Some("/search".into());
        let f2_id = f2.id();
        apply_sec(&mut l, "s-lead", SecurityOp::FindingRecord { finding: Box::new(f2) });
        apply_sec(
            &mut l,
            "s-lead",
            SecurityOp::FindingUpdate {
                update: Box::new(FindingUpdateInput {
                    id: f2_id,
                    update_reason: "False positive: ORM parameterizes input.".into(),
                    title: None,
                    description: None,
                    impact: None,
                    target: None,
                    evidence: vec![],
                    counterevidence: None,
                    confidence: None,
                    confidence_rationale: None,
                    severity_change_conditions: None,
                    cvss_breakdown: None,
                    severity: None,
                    technical_analysis: None,
                    remediation_steps: None,
                    assumptions: None,
                    poc_description: None,
                    poc_handle: None,
                    fix_effort: None,
                    endpoint: None,
                    method: None,
                    cve: None,
                    cwe: None,
                    code_locations: None,
                    fix_verification: None,
                    http_exchanges: vec![],
                    status: Some(FindingStatus::Withdrawn),
                    withdrawn_reason: None,
                }),
            },
        );

        let doc = build_sarif_report(&l, &SarifOptions::default());
        let run = &doc["runs"][0];
        let results = run["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["properties"]["ferret"]["id"], f1_id);
        assert_eq!(results[0]["properties"]["synthetic_location"], true);
        assert_eq!(results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "SECURITY.md");
        assert_eq!(results[0]["locations"][1]["logicalLocations"][0]["kind"], "endpoint");
        assert_eq!(run["properties"]["syntheticLocationCount"], 1);
        assert_eq!(run["properties"]["withdrawnFindingCount"], 1);
        assert_eq!(run["invocations"][0]["executionSuccessful"], true);

        // Atomic write smoke test
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("nested").join("findings.sarif");
        write_sarif_report(&out, &l, &SarifOptions::default()).unwrap();
        let parsed: Value = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(parsed, doc);
    }
}
