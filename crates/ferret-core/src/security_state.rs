//! Durable, evidence-linked security observations and deterministic projections.
//!
//! CONTRACT. `SecurityOp` is additive inside `LedgerOp::Security`; old journals and state snapshots
//! remain readable. Asset IDs hash a canonical kind/locator, credential IDs hash asset/principal/
//! secret handle, and foothold IDs hash asset/principal/access. Upserts merge evidence, never erase
//! it. Credentials contain handles, never secret material. A record is an observation, not authority
//! to contact an asset. All cited evidence must exist and be attested in the owning mission.
//!
//! Mandatory coverage is open until tested with evidence or deferred with a nonblank reason.
//! Per-`(surface, risk_area)` coverage entries (`cv-`) track five explicit dispositions
//! (`reported`, `no_issue_found`, `ruled_out` requiring `control` + `location`, `not_applicable`
//! requiring `reason`, and `needs_follow_up` requiring `reason`); duplicate `(surface, risk_area)`
//! records are rejected so updates preserve transition history in place. Structured findings (`fn-`)
//! carry CVSS 3.1 base scoring, CWE/CVE identifiers, repo-relative code locations with verified fix
//! suggestions, counterevidence, calibrated confidence, and attested evidence IDs for SARIF 2.1.0
//! export. Typed
//! conditions unblock claim/dead-end references only when every prerequisite is recorded. Crash
//! signatures retain frame-zero lines, omit caller lines, and exclude timeout/OOM/non-crash outcomes;
//! each signature retains its last six attempts. Prefix resolution prefers exact IDs/aliases and
//! refuses ambiguous prefixes. All maps/outputs have deterministic ordering.
//!
//! Hypotheses and the rule engine are not part of the state any more: the operations
//! `hypothesis_open`, `hypothesis_priority`, `hypothesis_evidence`, `hypothesis_verdict`,
//! `rule_install` and `rule_retract` stay deserializable so old journals load, are refused when
//! validated for a new append (`REMOVED_OP_REFUSAL`), and change nothing when applied. A snapshot
//! that still carries `hypotheses`, `rules`, `died` or `retraction_limitation` loads; they are dropped.
//!
//! `SecurityOp::action` is the serialized `action` tag of an op (`asset_upsert`, …, `batch`). A batch
//! stays one atomic append; when one of its operations fails validation the error is
//! "Operation {i} of {n} in the batch ({action}): {error}" (1-based `i`), so the caller can tell
//! which one to correct; a nested batch is one such operation ("Operation {i} of {n} in the batch
//! (batch): Nested security batches are not supported; flatten the operations."). Tests required: the
//! prefix for a failing second operation of three, the nested batch, and that nothing of the batch was
//! applied.

use crate::ledger::LedgerState;
use crate::SessionId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_ATTEMPTS: usize = 6;
pub const MAX_RECORDS: usize = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    Host,
    Service,
    Endpoint,
    File,
    Identity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetInput {
    pub kind: AssetKind,
    pub locator: String,
    #[serde(default)]
    pub evidence: Vec<String>,
    #[serde(default = "yes")]
    pub mandatory: bool,
    #[serde(default)]
    pub parent: Option<String>,
}

fn yes() -> bool {
    true
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Asset {
    pub id: String,
    pub kind: AssetKind,
    pub locator: String,
    pub evidence: Vec<String>,
    pub mandatory: bool,
    pub parent: Option<String>,
    pub coverage: CoverageDisposition,
    pub n: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum CoverageDisposition {
    #[default]
    Untested,
    Tested {
        evidence: Vec<String>,
    },
    Deferred {
        reason: String,
    },
}

/// Disposition of a per-`(surface, risk_area)` coverage entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceOutcome {
    /// Confirmed vulnerability recorded as a finding/claim with attested evidence.
    Reported,
    /// Thoroughly tested and no issue was found.
    NoIssueFound,
    /// Specific candidate disproved by naming the control and where it runs.
    RuledOut,
    /// Risk class cannot apply to this surface (with explicit reason).
    NotApplicable,
    /// Plausible risk that remains unresolved (explicit proof gap or blocker).
    NeedsFollowUp,
}

impl SurfaceOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            SurfaceOutcome::Reported => "reported",
            SurfaceOutcome::NoIssueFound => "no_issue_found",
            SurfaceOutcome::RuledOut => "ruled_out",
            SurfaceOutcome::NotApplicable => "not_applicable",
            SurfaceOutcome::NeedsFollowUp => "needs_follow_up",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            SurfaceOutcome::Reported => "Reported",
            SurfaceOutcome::NoIssueFound => "No issue found",
            SurfaceOutcome::RuledOut => "Ruled out",
            SurfaceOutcome::NotApplicable => "Not applicable",
            SurfaceOutcome::NeedsFollowUp => "Needs follow-up",
        }
    }
}

/// Snapshot of a prior state of a [`SurfaceCoverage`] entry before a `coverage_update`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceCoverageHistory {
    pub outcome: SurfaceOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    pub session: SessionId,
    pub n: u64,
}

/// Durable coverage record for one `(surface, risk_area)` pair, keyed uniquely so updates preserve
/// transition history instead of leaving stale rows beside resolutions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceCoverage {
    pub id: String,
    pub surface: String,
    pub risk_area: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset: Option<String>,
    pub outcome: SurfaceOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    pub recorded_by: SessionId,
    pub updated_by: SessionId,
    pub created_n: u64,
    pub updated_n: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<SurfaceCoverageHistory>,
}

/// Canonical content ID for a `(surface, risk_area)` coverage entry (case-insensitive, trimmed).
pub fn surface_coverage_id(surface: &str, risk_area: &str) -> String {
    stable_id("cv", &[&surface.trim().to_ascii_lowercase(), &risk_area.trim().to_ascii_lowercase()])
}

/// Qualitative severity of a structured security finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl FindingSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            FindingSeverity::Critical => "critical",
            FindingSeverity::High => "high",
            FindingSeverity::Medium => "medium",
            FindingSeverity::Low => "low",
            FindingSeverity::Info => "info",
        }
    }

    pub fn sarif_level(self) -> &'static str {
        match self {
            FindingSeverity::Critical | FindingSeverity::High => "error",
            FindingSeverity::Medium => "warning",
            FindingSeverity::Low | FindingSeverity::Info => "note",
        }
    }

    pub fn fallback_security_severity(self) -> &'static str {
        match self {
            FindingSeverity::Critical => "9.5",
            FindingSeverity::High => "8.0",
            FindingSeverity::Medium => "5.5",
            FindingSeverity::Low => "3.0",
            FindingSeverity::Info => "1.0",
        }
    }
}

/// Calibrated confidence that a finding is real and exploitable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingConfidence {
    High,
    Medium,
    Low,
}

impl FindingConfidence {
    pub fn as_str(self) -> &'static str {
        match self {
            FindingConfidence::High => "high",
            FindingConfidence::Medium => "medium",
            FindingConfidence::Low => "low",
        }
    }
}

/// Estimated engineering effort to remediate a finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixEffort {
    Trivial,
    Low,
    Medium,
    High,
}

impl FixEffort {
    pub fn as_str(self) -> &'static str {
        match self {
            FixEffort::Trivial => "trivial",
            FixEffort::Low => "low",
            FixEffort::Medium => "medium",
            FixEffort::High => "high",
        }
    }
}

/// Lifecycle status of a structured finding. Withdrawn findings remain in the ledger for auditability
/// but are excluded from active SARIF alerts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    #[default]
    Active,
    Withdrawn,
}

impl FindingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            FindingStatus::Active => "active",
            FindingStatus::Withdrawn => "withdrawn",
        }
    }
}

/// CVSS 3.1 base score stored as exact tenths (`0..=100`, representing `0.0..=10.0`) so `Eq`/`Ord`
/// hold cleanly while JSON serializes as a standard one-decimal number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CvssScore(pub u8);

impl CvssScore {
    pub fn from_tenths(tenths: u8) -> Result<Self, String> {
        if tenths > 100 {
            return Err("CVSS score must be between 0.0 and 10.0.".into());
        }
        Ok(Self(tenths))
    }

    pub fn tenths(self) -> u8 {
        self.0
    }

    pub fn format_one_decimal(self) -> String {
        format!("{}.{}", self.0 / 10, self.0 % 10)
    }
}

impl Serialize for CvssScore {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_f64(f64::from(self.0) / 10.0)
    }
}

impl<'de> Deserialize<'de> for CvssScore {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let v = f64::deserialize(deserializer)?;
        if !v.is_finite() || !(0.0..=10.0).contains(&v) {
            return Err(serde::de::Error::custom("CVSS score must be between 0.0 and 10.0"));
        }
        Ok(Self((v * 10.0).round() as u8))
    }
}

/// All eight CVSS 3.1 base metrics (FIRST CVSS v3.1 specification).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CvssBreakdown {
    pub attack_vector: String,
    pub attack_complexity: String,
    pub privileges_required: String,
    pub user_interaction: String,
    pub scope: String,
    pub confidentiality: String,
    pub integrity: String,
    pub availability: String,
}

impl CvssBreakdown {
    /// Validate all eight CVSS 3.1 base metrics and compute `(score, severity, vector)` per FIRST
    /// CVSS v3.1 Section 7 and Appendix A.
    pub fn calculate(&self) -> Result<(CvssScore, FindingSeverity, String), String> {
        let av = match self.attack_vector.as_str() {
            "N" => 0.85,
            "A" => 0.62,
            "L" => 0.55,
            "P" => 0.20,
            _ => return Err("Invalid cvss_breakdown.attack_vector; use one of N, A, L, P.".into()),
        };
        let ac = match self.attack_complexity.as_str() {
            "L" => 0.77,
            "H" => 0.44,
            _ => return Err("Invalid cvss_breakdown.attack_complexity; use L or H.".into()),
        };
        let scope_changed = match self.scope.as_str() {
            "U" => false,
            "C" => true,
            _ => return Err("Invalid cvss_breakdown.scope; use U or C.".into()),
        };
        let pr = match (self.privileges_required.as_str(), scope_changed) {
            ("N", _) => 0.85,
            ("L", false) => 0.62,
            ("L", true) => 0.68,
            ("H", false) => 0.27,
            ("H", true) => 0.50,
            _ => return Err("Invalid cvss_breakdown.privileges_required; use N, L, or H.".into()),
        };
        let ui = match self.user_interaction.as_str() {
            "N" => 0.85,
            "R" => 0.62,
            _ => return Err("Invalid cvss_breakdown.user_interaction; use N or R.".into()),
        };
        let cia = |val: &str, name: &str| -> Result<f64, String> {
            match val {
                "N" => Ok(0.0),
                "L" => Ok(0.22),
                "H" => Ok(0.56),
                _ => Err(format!("Invalid cvss_breakdown.{name}; use N, L, or H.")),
            }
        };
        let c = cia(&self.confidentiality, "confidentiality")?;
        let i = cia(&self.integrity, "integrity")?;
        let a = cia(&self.availability, "availability")?;

        let vector = format!(
            "CVSS:3.1/AV:{}/AC:{}/PR:{}/UI:{}/S:{}/C:{}/I:{}/A:{}",
            self.attack_vector,
            self.attack_complexity,
            self.privileges_required,
            self.user_interaction,
            self.scope,
            self.confidentiality,
            self.integrity,
            self.availability,
        );

        let iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
        let impact = if scope_changed { 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15) } else { 6.42 * iss };
        let tenths = if impact <= 0.0 {
            0u8
        } else {
            let exploitability = 8.22 * av * ac * pr * ui;
            let raw = if scope_changed {
                (1.08 * (impact + exploitability)).min(10.0)
            } else {
                (impact + exploitability).min(10.0)
            };
            roundup_cvss_tenths(raw)
        };
        let severity = match tenths {
            0 => FindingSeverity::Info,
            1..=39 => FindingSeverity::Low,
            40..=69 => FindingSeverity::Medium,
            70..=89 => FindingSeverity::High,
            _ => FindingSeverity::Critical,
        };
        Ok((CvssScore(tenths), severity, vector))
    }
}

/// FIRST CVSS v3.1 Appendix A `Roundup`: smallest tenth `>= input` using 5-decimal fixed rounding.
fn roundup_cvss_tenths(input: f64) -> u8 {
    let int_input = (input * 100_000.0).round() as i64;
    let tenths = if int_input % 10_000 == 0 { int_input / 10_000 } else { (int_input / 10_000) + 1 };
    tenths.clamp(0, 100) as u8
}

/// Repo-relative source location for a structured finding, with optional verified fix suggestion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeLocation {
    pub file: String,
    pub start_line: u32,
    pub end_line: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix_before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix_after: Option<String>,
}

/// Validate and normalize a repo-relative POSIX path for code locations and SARIF URIs.
pub fn validate_relative_posix_path(path: &str) -> Result<String, String> {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed.len() > 1024 || trimmed.chars().any(char::is_control) {
        return Err("Code location `file` must be a nonblank relative POSIX path without control characters.".into());
    }
    let slash = trimmed.replace('\\', "/");
    if slash.starts_with('/') {
        return Err(format!("Code location `file` must be repo-relative, not absolute (`{trimmed}`)."));
    }
    let mut parts = Vec::new();
    for part in slash.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return Err(format!("Code location `file` must not contain `..` (`{trimmed}`)."));
        }
        parts.push(part);
    }
    if parts.is_empty() {
        return Err("Code location `file` must name a relative file path.".into());
    }
    if parts[0].contains(':') {
        return Err(format!("Code location `file` must be a relative path, not a URI or drive path (`{trimmed}`)."));
    }
    Ok(parts.join("/"))
}

/// Validate a canonical CWE identifier (`CWE-NNN`).
pub fn validate_cwe(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    let Some(digits) = trimmed.strip_prefix("CWE-") else {
        return Err(format!("Invalid CWE format `{trimmed}`; expected `CWE-NNN` (for example `CWE-89`)."));
    };
    if digits.is_empty() || digits.len() > 6 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("Invalid CWE format `{trimmed}`; expected `CWE-NNN` (for example `CWE-89`)."));
    }
    Ok(trimmed.to_string())
}

/// Validate a canonical CVE identifier (`CVE-YYYY-NNNN+`).
pub fn validate_cve(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    let Some(rest) = trimmed.strip_prefix("CVE-") else {
        return Err(format!("Invalid CVE format `{trimmed}`; expected `CVE-YYYY-NNNNN`."));
    };
    let Some((year, num)) = rest.split_once('-') else {
        return Err(format!("Invalid CVE format `{trimmed}`; expected `CVE-YYYY-NNNNN`."));
    };
    if year.len() != 4
        || !year.bytes().all(|b| b.is_ascii_digit())
        || num.len() < 4
        || num.len() > 10
        || !num.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(format!("Invalid CVE format `{trimmed}`; expected `CVE-YYYY-NNNNN`."));
    }
    Ok(trimmed.to_string())
}

fn validate_out_handle(handle: &str, name: &str) -> Result<(), String> {
    if !handle
        .strip_prefix("out:")
        .is_some_and(|h| (8..=64).contains(&h.len()) && h.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(format!(
            "Store {name} in a blob and give its out: handle; do not embed raw exploit code or secrets in the ledger."
        ));
    }
    Ok(())
}

/// Input payload for recording a new structured security finding (`finding_record`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingInput {
    pub title: String,
    pub description: String,
    pub impact: String,
    pub target: String,
    #[serde(default)]
    pub evidence: Vec<String>,
    pub counterevidence: String,
    pub confidence: FindingConfidence,
    #[serde(default)]
    pub confidence_rationale: Option<String>,
    pub severity_change_conditions: String,
    #[serde(default)]
    pub cvss_breakdown: Option<CvssBreakdown>,
    #[serde(default)]
    pub severity: Option<FindingSeverity>,
    #[serde(default)]
    pub technical_analysis: Option<String>,
    #[serde(default)]
    pub remediation_steps: Option<String>,
    #[serde(default)]
    pub assumptions: Option<String>,
    #[serde(default)]
    pub poc_description: Option<String>,
    #[serde(default)]
    pub poc_handle: Option<String>,
    #[serde(default)]
    pub fix_effort: Option<FixEffort>,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub cve: Option<String>,
    #[serde(default)]
    pub cwe: Option<String>,
    #[serde(default)]
    pub code_locations: Vec<CodeLocation>,
    #[serde(default)]
    pub fix_verification: Option<String>,
    #[serde(default)]
    pub http_exchanges: Vec<String>,
    #[serde(default)]
    pub asset: Option<String>,
    #[serde(default)]
    pub claim: Option<String>,
}

impl FindingInput {
    pub fn id(&self) -> String {
        let title = self.title.trim().to_ascii_lowercase();
        let target = self.target.trim().to_ascii_lowercase();
        let endpoint = self.endpoint.as_deref().unwrap_or("").trim().to_ascii_lowercase();
        let primary_loc = self
            .code_locations
            .first()
            .map(|l| {
                let file = validate_relative_posix_path(&l.file).unwrap_or_else(|_| l.file.trim().to_string());
                format!("{file}:{}", l.start_line)
            })
            .unwrap_or_default();
        stable_id("fn", &[&title, &target, &endpoint, &primary_loc])
    }

    /// Deterministic 3-axis fingerprint (`fp:<32-hex>`) complementing exact ID deduplication:
    /// 1. normalized CWE or curated vulnerability class from `title`,
    /// 2. canonical linked `asset` ID or normalized `target` host,
    /// 3. normalized endpoint path + sorted query parameter names, or primary `file:start_line`.
    ///
    /// Returns `None` when any axis is ambiguous so distinct findings never false-collide.
    pub fn fingerprint(&self) -> Option<String> {
        finding_fingerprint_from_parts(
            self.cwe.as_deref(),
            &self.title,
            self.asset.as_deref(),
            &self.target,
            self.endpoint.as_deref(),
            &self.code_locations,
        )
    }
}

/// Curated vulnerability-class tokens for deterministic 3-axis finding deduplication.
const FP_VULN_CLASSES: &[(&str, &str)] = &[
    ("missing authentication", "missing_authentication"),
    ("missing authorization", "missing_authorization"),
    ("broken access control", "broken_access_control"),
    ("incorrect authorization", "incorrect_authorization"),
    ("default credentials", "default_credentials"),
    ("hardcoded credentials", "hardcoded_credentials"),
    ("hardcoded secret", "hardcoded_secret"),
    ("hardcoded password", "hardcoded_password"),
    ("session fixation", "session_fixation"),
    ("open redirect", "open_redirect"),
    ("path traversal", "path_traversal"),
    ("directory traversal", "path_traversal"),
    ("command injection", "command_injection"),
    ("sql injection", "sql_injection"),
    ("sqli", "sql_injection"),
    ("code injection", "code_injection"),
    ("template injection", "template_injection"),
    ("ssti", "template_injection"),
    ("xpath injection", "xpath_injection"),
    ("ldap injection", "ldap_injection"),
    ("deserialization", "deserialization"),
    ("buffer overflow", "buffer_overflow"),
    ("use after free", "use_after_free"),
    ("out of bounds", "out_of_bounds"),
    ("ssrf", "ssrf"),
    ("server-side request forgery", "ssrf"),
    ("xss", "xss"),
    ("cross-site scripting", "xss"),
    ("csrf", "csrf"),
    ("xxe", "xxe"),
    ("race condition", "race_condition"),
    ("toctou", "race_condition"),
    ("information disclosure", "information_disclosure"),
    ("insecure direct object reference", "idor"),
    ("idor", "idor"),
    ("bola", "bola"),
    ("bfla", "bfla"),
    ("auth bypass", "auth_bypass"),
];

pub fn finding_fingerprint_from_parts(
    cwe: Option<&str>,
    title: &str,
    asset: Option<&str>,
    target: &str,
    endpoint: Option<&str>,
    code_locations: &[CodeLocation],
) -> Option<String> {
    // Axis 1: canonical CWE or curated class token from title.
    let axis1 = if let Some(raw) = cwe.map(str::trim).filter(|s| !s.is_empty()) {
        let digits: String = raw.chars().filter(char::is_ascii_digit).collect();
        if digits.is_empty() {
            return None;
        }
        format!("cwe_{digits}")
    } else {
        let lower = title.to_ascii_lowercase();
        let matched = FP_VULN_CLASSES.iter().find_map(|(needle, canon)| lower.contains(needle).then_some(*canon))?;
        matched.to_string()
    };

    // Axis 2: canonical asset ID or normalized host from target URL / bare hostname.
    let axis2 = if let Some(aid) = asset.map(str::trim).filter(|s| !s.is_empty()) {
        format!("asset:{aid}")
    } else {
        let t = target.trim();
        let host = if let Ok(u) = url::Url::parse(t) {
            u.host_str().map(|h| h.trim_end_matches('.').to_ascii_lowercase())
        } else if !t.is_empty() && !t.chars().any(char::is_whitespace) {
            let authority = t.split('/').next().unwrap_or("");
            let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
            let h = if let Some(v6) = hostport.strip_prefix('[') {
                v6.split_once(']').map_or(v6, |(h, _)| h)
            } else {
                hostport.split_once(':').map_or(hostport, |(h, _)| h)
            };
            (!h.is_empty()).then(|| h.trim_end_matches('.').to_ascii_lowercase())
        } else {
            None
        }?;
        format!("host:{host}")
    };

    // Axis 3: normalized endpoint path + sorted query param names, else primary code location.
    let raw_ep = endpoint.map(str::trim).filter(|s| !s.is_empty()).map(|s| s.to_string()).or_else(|| {
        url::Url::parse(target.trim()).ok().and_then(|u| {
            let p = u.path();
            if p.is_empty() || p == "/" {
                None
            } else if let Some(q) = u.query() {
                Some(format!("{p}?{q}"))
            } else {
                Some(p.to_string())
            }
        })
    });
    let axis3 = if let Some(ep) = raw_ep {
        let stripped = if let Ok(u) = url::Url::parse(&ep) {
            match u.query() {
                Some(q) => format!("{}?{q}", u.path()),
                None => u.path().to_string(),
            }
        } else {
            ep
        };
        let (path_raw, query_raw) = stripped.split_once('?').unwrap_or((&stripped, ""));
        let mut norm_path = path_raw.trim().to_ascii_lowercase();
        while norm_path.contains("//") {
            norm_path = norm_path.replace("//", "/");
        }
        norm_path = norm_path.trim_end_matches('/').to_string();
        let mut params: BTreeSet<String> = BTreeSet::new();
        for pair in query_raw.split('&').filter(|s| !s.is_empty()) {
            let k = pair.split('=').next().unwrap_or("").trim().to_ascii_lowercase();
            if !k.is_empty() {
                params.insert(k);
            }
        }
        if norm_path.is_empty() && params.is_empty() {
            None
        } else if params.is_empty() {
            Some(format!("path:{norm_path}"))
        } else {
            let p_list: Vec<String> = params.into_iter().collect();
            Some(format!("path:{norm_path}|params:{}", p_list.join(",")))
        }
    } else {
        None
    }
    .or_else(|| {
        code_locations.first().and_then(|loc| {
            let file = validate_relative_posix_path(&loc.file).ok()?;
            Some(format!("loc:{file}:{}", loc.start_line))
        })
    })?;

    let digest = crate::sha256_hex(format!("{axis1}\0{axis2}\0{axis3}").as_bytes());
    Some(format!("fp:{}", &digest[..32]))
}

/// Input payload for revising or withdrawing an existing structured finding (`finding_update`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingUpdateInput {
    pub id: String,
    pub update_reason: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub impact: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub evidence: Vec<String>,
    #[serde(default)]
    pub counterevidence: Option<String>,
    #[serde(default)]
    pub confidence: Option<FindingConfidence>,
    #[serde(default)]
    pub confidence_rationale: Option<String>,
    #[serde(default)]
    pub severity_change_conditions: Option<String>,
    #[serde(default)]
    pub cvss_breakdown: Option<CvssBreakdown>,
    #[serde(default)]
    pub severity: Option<FindingSeverity>,
    #[serde(default)]
    pub technical_analysis: Option<String>,
    #[serde(default)]
    pub remediation_steps: Option<String>,
    #[serde(default)]
    pub assumptions: Option<String>,
    #[serde(default)]
    pub poc_description: Option<String>,
    #[serde(default)]
    pub poc_handle: Option<String>,
    #[serde(default)]
    pub fix_effort: Option<FixEffort>,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub cve: Option<String>,
    #[serde(default)]
    pub cwe: Option<String>,
    #[serde(default)]
    pub code_locations: Option<Vec<CodeLocation>>,
    #[serde(default)]
    pub fix_verification: Option<String>,
    #[serde(default)]
    pub http_exchanges: Vec<String>,
    #[serde(default)]
    pub status: Option<FindingStatus>,
    #[serde(default)]
    pub withdrawn_reason: Option<String>,
}

/// Audit trail entry recorded whenever a [`Finding`] is revised or withdrawn.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingRevision {
    pub reason: String,
    pub updated_fields: Vec<String>,
    pub previous_severity: FindingSeverity,
    pub previous_confidence: FindingConfidence,
    pub previous_status: FindingStatus,
    pub session: SessionId,
    pub n: u64,
}

/// Durable structured security finding stored in [`SecurityState::findings`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub description: String,
    pub impact: String,
    pub target: String,
    pub severity: FindingSeverity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss: Option<CvssScore>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss_vector: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss_breakdown: Option<CvssBreakdown>,
    pub evidence: Vec<String>,
    pub counterevidence: String,
    pub confidence: FindingConfidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_rationale: Option<String>,
    pub severity_change_conditions: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub technical_analysis: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation_steps: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assumptions: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poc_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poc_handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix_effort: Option<FixEffort>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cve: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwe: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub code_locations: Vec<CodeLocation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix_verification: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub http_exchanges: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<String>,
    /// Deterministic 3-axis deduplication fingerprint (`fp:<32-hex>`) over `(vuln_class/CWE,
    /// asset/host, endpoint+params|code_location)`, present when all three axes are unambiguous.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub status: FindingStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawn_reason: Option<String>,
    pub recorded_by: SessionId,
    pub updated_by: SessionId,
    pub created_n: u64,
    pub updated_n: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revisions: Vec<FindingRevision>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialInput {
    pub asset: String,
    pub principal: String,
    pub secret_handle: String,
    pub evidence: Vec<String>,
    #[serde(default)]
    pub unlocks: Vec<Condition>,
    #[serde(default)]
    pub expires_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    pub id: String,
    pub input: CredentialInput,
    pub n: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FootholdInput {
    pub asset: String,
    pub principal: String,
    pub access: String,
    pub evidence: Vec<String>,
    #[serde(default)]
    pub unlocks: Vec<Condition>,
    #[serde(default)]
    pub expires_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Foothold {
    pub id: String,
    pub input: FootholdInput,
    pub n: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionKind {
    Auth,
    Cred,
    Role,
    Leak,
    Offset,
    Key,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    pub kind: ConditionKind,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedRoute {
    pub target: String,
    pub conditions: Vec<Condition>,
    pub n: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrashOutcome {
    Crash,
    Timeout,
    Oom,
    NoCrash,
    FuzzerExit71,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrashFrame {
    pub function: String,
    pub file: String,
    #[serde(default)]
    pub line: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrashSignature {
    pub sanitizer: String,
    pub frames: Vec<CrashFrame>,
    pub outcome: CrashOutcome,
}

impl CrashSignature {
    pub fn key(&self) -> Result<String, String> {
        if self.outcome != CrashOutcome::Crash {
            return Err(
                "Only a real crash has a crash signature; record timeout, OOM, and non-crash outcomes as notes.".into(),
            );
        }
        text(&self.sanitizer, "sanitizer class")?;
        if self.frames.is_empty() || self.frames.len() > 3 {
            return Err("Give one to three crash frames; keep the source line only on frame zero.".into());
        }
        let mut parts = vec![self.sanitizer.trim().to_ascii_lowercase()];
        for (i, f) in self.frames.iter().enumerate() {
            text(&f.function, "crash function")?;
            text(&f.file, "crash source file")?;
            parts.push(format!(
                "{}@{}{}",
                f.function.trim(),
                f.file.trim(),
                if i == 0 { f.line.map(|n| format!(":{n}")).unwrap_or_default() } else { String::new() }
            ));
        }
        Ok(stable_id("cs", &parts.iter().map(String::as_str).collect::<Vec<_>>()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptInput {
    pub vector: String,
    pub summary: String,
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrashRecord {
    pub id: String,
    pub signature: CrashSignature,
    pub attempts: Vec<AttemptInput>,
    pub count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HypothesisStatus {
    Open,
    Supported,
    Refuted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationInput {
    pub from: String,
    pub to: String,
    pub kind: String,
    /// Integer cost, 1..=1000; smaller is easier/more useful to investigate.
    pub cost: u32,
    pub evidence: Vec<String>,
    #[serde(default)]
    pub expires_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Relation {
    pub id: String,
    pub input: RelationInput,
    pub n: u64,
}

/// A ground tuple the lead asserted as an observation. It is recorded and shown, never evaluated.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fact {
    pub predicate: String,
    pub args: Vec<String>,
}

impl Fact {
    pub fn id(&self) -> String {
        let parts: Vec<_> =
            std::iter::once(self.predicate.as_str()).chain(self.args.iter().map(String::as_str)).collect();
        stable_id("ft", &parts)
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.predicate.is_empty()
            || self.predicate.len() > 80
            || !self.predicate.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            || self.args.len() > 8
        {
            return Err(
                "Use an ASCII predicate name of one to 80 letters/digits/underscores and at most eight arguments."
                    .into(),
            );
        }
        for a in &self.args {
            text(a, "fact argument")?;
        }
        Ok(())
    }
}

/// The shape of a removed `rule_install` operation, kept so old journals deserialize.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Atom {
    pub predicate: String,
    pub args: Vec<String>,
}

/// See [`Atom`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Literal {
    pub atom: Atom,
    #[serde(default)]
    pub negated: bool,
}

/// See [`Atom`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,
    pub head: Atom,
    pub body: Vec<Literal>,
}

/// What a call to one of the removed hypothesis or rule operations is told.
pub const REMOVED_OP_REFUSAL: &str = "Hypotheses are not recorded in the security state any more: write the idea as a note (`note` with kind `decision`) or test it and record what the run showed.";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssertedFact {
    pub id: String,
    pub fact: Fact,
    pub evidence: Vec<String>,
    pub active: bool,
    pub n: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum SecurityOp {
    /// One validated, sealed append for scanner imports. Nested batches are refused.
    Batch {
        operations: Vec<SecurityOp>,
    },
    AssetUpsert {
        asset: AssetInput,
    },
    CredentialAdd {
        credential: CredentialInput,
    },
    FootholdAdd {
        foothold: FootholdInput,
    },
    ConditionUnlock {
        conditions: Vec<Condition>,
        evidence: Vec<String>,
    },
    BlockedOn {
        target: String,
        conditions: Vec<Condition>,
    },
    RevisitAcknowledge {
        target: String,
    },
    CoverageSet {
        asset: String,
        disposition: CoverageDisposition,
    },
    CoverageRecord {
        surface: String,
        risk_area: String,
        outcome: SurfaceOutcome,
        #[serde(default)]
        control: Option<String>,
        #[serde(default)]
        location: Option<String>,
        #[serde(default)]
        reason: Option<String>,
        #[serde(default)]
        evidence: Vec<String>,
        #[serde(default)]
        asset: Option<String>,
    },
    CoverageUpdate {
        id: String,
        outcome: SurfaceOutcome,
        #[serde(default)]
        control: Option<String>,
        #[serde(default)]
        location: Option<String>,
        #[serde(default)]
        reason: Option<String>,
        #[serde(default)]
        evidence: Vec<String>,
    },
    FindingRecord {
        finding: Box<FindingInput>,
    },
    FindingUpdate {
        update: Box<FindingUpdateInput>,
    },
    CrashRecord {
        signature: CrashSignature,
        attempt: AttemptInput,
    },
    HypothesisOpen {
        text: String,
        priority: u8,
    },
    HypothesisPriority {
        id: String,
        priority: u8,
    },
    HypothesisEvidence {
        id: String,
        evidence: Vec<String>,
        counterevidence: Vec<String>,
    },
    HypothesisVerdict {
        id: String,
        status: HypothesisStatus,
        note: String,
        evidence: Vec<String>,
        counterevidence: Vec<String>,
    },
    RelationAdd {
        relation: RelationInput,
    },
    FactAssert {
        fact: Fact,
        evidence: Vec<String>,
    },
    FactRetract {
        id: String,
        reason: String,
    },
    RuleInstall {
        rule: Rule,
    },
    RuleRetract {
        id: String,
        reason: String,
    },
    AliasAdd {
        alias: String,
        target: String,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityState {
    pub assets: BTreeMap<String, Asset>,
    pub credentials: BTreeMap<String, Credential>,
    pub footholds: BTreeMap<String, Foothold>,
    pub unlocked: BTreeSet<Condition>,
    pub condition_evidence: BTreeMap<String, Vec<String>>,
    pub blocked: BTreeMap<String, BlockedRoute>,
    pub revisited: BTreeMap<String, u64>,
    pub crashes: BTreeMap<String, CrashRecord>,
    pub vector_attempts: BTreeMap<String, Vec<AttemptInput>>,
    pub relations: BTreeMap<String, Relation>,
    pub facts: BTreeMap<String, AssertedFact>,
    pub aliases: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub surface_coverage: BTreeMap<String, SurfaceCoverage>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub findings: BTreeMap<String, Finding>,
}

/// Hash a length-delimited tuple; no separator ambiguity or truncated-hash collisions.
pub fn stable_id(prefix: &str, parts: &[&str]) -> String {
    let mut bytes = Vec::new();
    for p in parts {
        bytes.extend_from_slice(&u64::try_from(p.len()).unwrap_or(u64::MAX).to_le_bytes());
        bytes.extend_from_slice(p.as_bytes());
    }
    format!("{prefix}-{}", crate::sha256_hex(&bytes))
}

/// Canonicalize only distinctions that cannot change the named resource. URL paths retain case,
/// queries and fragments; URL credentials are refused. File/identity locators remain case-sensitive.
pub fn canonical_locator(kind: AssetKind, locator: &str) -> Result<String, String> {
    text(locator, "asset locator")?;
    let locator = locator.trim();
    match kind {
        AssetKind::Host => {
            if let Ok(ip) = locator.parse::<std::net::IpAddr>() {
                return Ok(ip.to_string());
            }
            if locator.chars().any(|c| c.is_whitespace() || matches!(c, '/' | ':' | '@')) {
                return Err("Give a host name or IP address, without a scheme, port, path, or credentials.".into());
            }
            let host = locator.trim_end_matches('.').to_ascii_lowercase();
            if host.is_empty() {
                return Err("Give a nonempty host name or IP address.".into());
            }
            Ok(host)
        }
        AssetKind::Endpoint | AssetKind::Service => {
            let mut url =
                url::Url::parse(locator).map_err(|_| "Give an absolute service or endpoint URL.".to_string())?;
            if url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() {
                return Err(
                    "Give an absolute URL with a host and no embedded credentials; store a secret handle separately."
                        .into(),
                );
            }
            if let Some(host) = url.host_str().map(|h| h.trim_end_matches('.').to_ascii_lowercase()) {
                url.set_host(Some(&host))
                    .map_err(|_| "The URL host is invalid; correct it before recording the asset.".to_string())?;
            }
            Ok(url.to_string())
        }
        AssetKind::File | AssetKind::Identity => Ok(locator.to_string()),
    }
}

impl AssetInput {
    pub fn id(&self) -> Result<String, String> {
        Ok(stable_id("as", &[&format!("{:?}", self.kind), &canonical_locator(self.kind, &self.locator)?]))
    }
}

fn text(value: &str, name: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(format!("Give a nonblank {name} of at most 4096 bytes without control characters."));
    }
    Ok(())
}

fn prose(value: &str, name: &str, max_bytes: usize) -> Result<(), String> {
    if value.trim().is_empty()
        || value.len() > max_bytes
        || value.chars().any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return Err(format!(
            "Give a nonblank {name} of at most {max_bytes} bytes without disallowed control characters."
        ));
    }
    Ok(())
}

fn clean_opt(value: Option<&str>) -> Option<String> {
    value.map(str::trim).filter(|s| !s.is_empty()).map(str::to_string)
}

fn clean_code_opt(value: Option<&str>) -> Option<String> {
    value.map(|s| s.trim_matches('\n')).filter(|s| !s.trim().is_empty()).map(str::to_string)
}

type EvidenceCheck<'a> = &'a dyn Fn(&[String], bool) -> Result<(), String>;

fn validate_surface_coverage_fields(
    outcome: SurfaceOutcome,
    control: Option<&str>,
    location: Option<&str>,
    reason: Option<&str>,
    evidence_ids: &[String],
    check_evidence: EvidenceCheck<'_>,
) -> Result<(), String> {
    if let Some(c) = control.filter(|s| !s.is_empty()) {
        text(c, "coverage control")?;
    }
    if let Some(l) = location.filter(|s| !s.is_empty()) {
        text(l, "coverage location")?;
    }
    if let Some(r) = reason.filter(|s| !s.is_empty()) {
        prose(r, "coverage reason", 4096)?;
    }
    let has_control = control.is_some_and(|s| !s.trim().is_empty());
    let has_location = location.is_some_and(|s| !s.trim().is_empty());
    let has_reason = reason.is_some_and(|s| !s.trim().is_empty());
    match outcome {
        SurfaceOutcome::Reported => {
            check_evidence(evidence_ids, true)?;
        }
        SurfaceOutcome::NoIssueFound => {
            if !evidence_ids.is_empty() {
                check_evidence(evidence_ids, false)?;
            } else if !has_reason {
                return Err(
                    "Outcome `no_issue_found` requires attested `evidence` IDs or a nonblank `reason` stating what was tested."
                        .into(),
                );
            }
        }
        SurfaceOutcome::RuledOut => {
            if !has_control || !has_location {
                return Err(
                    "Outcome `ruled_out` requires both `control` (the specific defense or guard) and `location` (file:line, handler, or config where it runs)."
                        .into(),
                );
            }
            if !evidence_ids.is_empty() {
                check_evidence(evidence_ids, false)?;
            }
        }
        SurfaceOutcome::NotApplicable => {
            if !has_reason {
                return Err(
                    "Outcome `not_applicable` requires a nonblank `reason` explaining why this risk cannot apply here."
                        .into(),
                );
            }
            if !evidence_ids.is_empty() {
                check_evidence(evidence_ids, false)?;
            }
        }
        SurfaceOutcome::NeedsFollowUp => {
            if !has_reason {
                return Err(
                    "Outcome `needs_follow_up` requires a nonblank `reason` naming the specific proof gap or blocker."
                        .into(),
                );
            }
            if !evidence_ids.is_empty() {
                check_evidence(evidence_ids, false)?;
            }
        }
    }
    Ok(())
}

fn validate_code_locations(locations: &[CodeLocation], fix_verification: Option<&str>) -> Result<(), String> {
    if locations.len() > 64 {
        return Err("Provide at most 64 code locations per finding.".into());
    }
    let mut has_fix_after = false;
    for (i, loc) in locations.iter().enumerate() {
        validate_relative_posix_path(&loc.file)?;
        if loc.start_line < 1 {
            return Err(format!("code_locations[{i}]: `start_line` must be >= 1."));
        }
        if loc.end_line < loc.start_line {
            return Err(format!(
                "code_locations[{i}]: `end_line` ({}) must be >= `start_line` ({}).",
                loc.end_line, loc.start_line
            ));
        }
        if let Some(label) = loc.label.as_deref().filter(|s| !s.is_empty()) {
            text(label, "code location label")?;
        }
        if let Some(snippet) = loc.snippet.as_deref().filter(|s| !s.is_empty()) {
            prose(snippet, "code location snippet", 16_384)?;
        }
        let has_before = loc.fix_before.as_deref().is_some_and(|s| !s.trim().is_empty());
        let has_after = loc.fix_after.as_deref().is_some_and(|s| !s.trim().is_empty());
        if has_before != has_after {
            return Err(format!(
                "code_locations[{i}]: provide both `fix_before` and `fix_after` together, or omit both."
            ));
        }
        if let Some(before) = loc.fix_before.as_deref().filter(|s| !s.trim().is_empty()) {
            prose(before, "code location fix_before", 16_384)?;
        }
        if let Some(after) = loc.fix_after.as_deref().filter(|s| !s.trim().is_empty()) {
            prose(after, "code location fix_after", 16_384)?;
            has_fix_after = true;
        }
    }
    if has_fix_after {
        match fix_verification.map(str::trim).filter(|s| !s.is_empty()) {
            Some(v) => prose(v, "fix_verification", 8192)?,
            None => {
                return Err(
                    "Field `fix_verification` is required when any code location carries `fix_after`: state security closure, bypass review, preserved behavior, and whether each check was executed or reasoned."
                        .into(),
                );
            }
        }
    }
    Ok(())
}

fn normalize_code_locations(locations: &[CodeLocation]) -> Vec<CodeLocation> {
    locations
        .iter()
        .map(|loc| CodeLocation {
            file: validate_relative_posix_path(&loc.file).unwrap_or_else(|_| loc.file.trim().to_string()),
            start_line: loc.start_line,
            end_line: loc.end_line,
            snippet: clean_code_opt(loc.snippet.as_deref()),
            label: clean_opt(loc.label.as_deref()),
            fix_before: clean_code_opt(loc.fix_before.as_deref()),
            fix_after: clean_code_opt(loc.fix_after.as_deref()),
        })
        .collect()
}

fn validate_method(method: &str) -> Result<String, String> {
    let up = method.trim().to_ascii_uppercase();
    if up.is_empty() || up.len() > 16 || !up.bytes().all(|b| b.is_ascii_alphabetic()) {
        return Err(format!("Invalid HTTP method `{method}`; give an ASCII method name such as GET or POST."));
    }
    Ok(up)
}

fn finding_update_has_changes(u: &FindingUpdateInput) -> bool {
    u.title.is_some()
        || u.description.is_some()
        || u.impact.is_some()
        || u.target.is_some()
        || !u.evidence.is_empty()
        || u.counterevidence.is_some()
        || u.confidence.is_some()
        || u.confidence_rationale.is_some()
        || u.severity_change_conditions.is_some()
        || u.cvss_breakdown.is_some()
        || u.severity.is_some()
        || u.technical_analysis.is_some()
        || u.remediation_steps.is_some()
        || u.assumptions.is_some()
        || u.poc_description.is_some()
        || u.poc_handle.is_some()
        || u.fix_effort.is_some()
        || u.endpoint.is_some()
        || u.method.is_some()
        || u.cve.is_some()
        || u.cwe.is_some()
        || u.code_locations.is_some()
        || u.fix_verification.is_some()
        || !u.http_exchanges.is_empty()
        || u.status.is_some()
        || u.withdrawn_reason.is_some()
}

fn merge<T: Clone + Ord>(into: &mut Vec<T>, values: &[T]) {
    let set: BTreeSet<_> = into.iter().chain(values).cloned().collect();
    *into = set.into_iter().collect();
}

fn conditions(values: &[Condition]) -> Result<(), String> {
    if values.is_empty() || values.len() > 64 {
        return Err("Give between one and 64 typed conditions.".into());
    }
    for c in values {
        text(&c.value, "condition value")?;
    }
    Ok(())
}

impl SecurityOp {
    /// The serialized `action` tag of this op.
    pub fn action(&self) -> &'static str {
        match self {
            SecurityOp::Batch { .. } => "batch",
            SecurityOp::AssetUpsert { .. } => "asset_upsert",
            SecurityOp::CredentialAdd { .. } => "credential_add",
            SecurityOp::FootholdAdd { .. } => "foothold_add",
            SecurityOp::ConditionUnlock { .. } => "condition_unlock",
            SecurityOp::BlockedOn { .. } => "blocked_on",
            SecurityOp::RevisitAcknowledge { .. } => "revisit_acknowledge",
            SecurityOp::CoverageSet { .. } => "coverage_set",
            SecurityOp::CoverageRecord { .. } => "coverage_record",
            SecurityOp::CoverageUpdate { .. } => "coverage_update",
            SecurityOp::FindingRecord { .. } => "finding_record",
            SecurityOp::FindingUpdate { .. } => "finding_update",
            SecurityOp::CrashRecord { .. } => "crash_record",
            SecurityOp::HypothesisOpen { .. } => "hypothesis_open",
            SecurityOp::HypothesisPriority { .. } => "hypothesis_priority",
            SecurityOp::HypothesisEvidence { .. } => "hypothesis_evidence",
            SecurityOp::HypothesisVerdict { .. } => "hypothesis_verdict",
            SecurityOp::RelationAdd { .. } => "relation_add",
            SecurityOp::FactAssert { .. } => "fact_assert",
            SecurityOp::FactRetract { .. } => "fact_retract",
            SecurityOp::RuleInstall { .. } => "rule_install",
            SecurityOp::RuleRetract { .. } => "rule_retract",
            SecurityOp::AliasAdd { .. } => "alias_add",
        }
    }
}

impl SecurityState {
    pub fn resolve(&self, wanted: &str) -> Result<String, String> {
        let ids: BTreeSet<&str> = self
            .assets
            .keys()
            .chain(self.credentials.keys())
            .chain(self.footholds.keys())
            .chain(self.crashes.keys())
            .chain(self.relations.keys())
            .chain(self.facts.keys())
            .chain(self.surface_coverage.keys())
            .chain(self.findings.keys())
            .map(String::as_str)
            .collect();
        if ids.contains(wanted) {
            return Ok(wanted.to_string());
        }
        if let Some(id) = self.aliases.get(wanted) {
            return Ok(id.clone());
        }
        if wanted.len() < 4 {
            return Err("Use an exact ID or alias, or an unambiguous prefix of at least four characters.".into());
        }
        let matches: BTreeSet<_> = ids.into_iter().filter(|id| id.starts_with(wanted)).collect();
        match matches.len() {
            1 => Ok(matches.into_iter().next().unwrap_or_default().to_string()),
            0 => {
                Err(format!("No security record matches `{wanted}`; query the current records before choosing an ID."))
            }
            _ => Err(format!("The prefix `{wanted}` is ambiguous; give more characters or an exact ID.")),
        }
    }

    pub fn mandatory_open(&self) -> Vec<String> {
        self.assets
            .values()
            .filter(|a| a.mandatory && a.coverage == CoverageDisposition::Untested)
            .map(|a| a.id.clone())
            .collect()
    }

    /// Counts of per-`(surface, risk_area)` coverage entries by outcome, in deterministic order.
    pub fn surface_coverage_counts(&self) -> BTreeMap<&'static str, usize> {
        let mut counts = BTreeMap::new();
        for outcome in [
            SurfaceOutcome::Reported,
            SurfaceOutcome::NoIssueFound,
            SurfaceOutcome::RuledOut,
            SurfaceOutcome::NotApplicable,
            SurfaceOutcome::NeedsFollowUp,
        ] {
            counts.insert(outcome.as_str(), 0);
        }
        for entry in self.surface_coverage.values() {
            *counts.entry(entry.outcome.as_str()).or_default() += 1;
        }
        counts
    }

    /// Per-`(surface, risk_area)` entries currently open as `needs_follow_up`, in deterministic ID order.
    pub fn surface_coverage_follow_ups(&self) -> Vec<&SurfaceCoverage> {
        self.surface_coverage.values().filter(|c| c.outcome == SurfaceOutcome::NeedsFollowUp).collect()
    }

    /// Active (non-withdrawn) structured findings in deterministic ID order.
    pub fn active_findings(&self) -> Vec<&Finding> {
        self.findings.values().filter(|f| f.status == FindingStatus::Active).collect()
    }

    pub fn newly_unlocked(&self) -> Vec<String> {
        self.newly_unlocked_at(0)
    }

    pub fn newly_unlocked_at(&self, now_ms: u64) -> Vec<String> {
        let mut available = self.unlocked.clone();
        for c in self.credentials.values().filter(|c| c.input.expires_ms.is_none_or(|t| t > now_ms)) {
            available.extend(c.input.unlocks.iter().cloned());
            available.insert(Condition { kind: ConditionKind::Cred, value: c.input.asset.clone() });
        }
        for f in self.footholds.values().filter(|f| f.input.expires_ms.is_none_or(|t| t > now_ms)) {
            available.extend(f.input.unlocks.iter().cloned());
            available.insert(Condition { kind: ConditionKind::Auth, value: f.input.asset.clone() });
        }
        self.blocked
            .values()
            .filter(|r| !self.revisited.contains_key(&r.target) && r.conditions.iter().all(|c| available.contains(c)))
            .map(|r| r.target.clone())
            .collect()
    }

    pub fn validate(&self, op: &SecurityOp, ledger: &LedgerState) -> Result<(), String> {
        let evidence = |refs: &[String], required: bool| -> Result<(), String> {
            if (required && refs.is_empty()) || refs.len() > 128 {
                return Err(
                    "Cite between one and 128 existing attested evidence IDs; record the observation first.".into()
                );
            }
            for id in refs {
                if !ledger.evidence.iter().any(|e| &e.id == id && e.input.attested) {
                    return Err(format!(
                        "Evidence `{id}` is missing or unattested; use the evidence tool before citing it."
                    ));
                }
            }
            Ok(())
        };
        let asset = |id: &str| -> Result<(), String> {
            if self.assets.contains_key(id) {
                Ok(())
            } else {
                Err(format!("Asset `{id}` does not exist; record it first."))
            }
        };
        match op {
            SecurityOp::Batch { operations } => {
                if operations.is_empty() || operations.len() > 1000 {
                    return Err("Give one to 1000 security operations in one import batch.".into());
                }
                let mut staged = ledger.clone();
                let n = operations.len();
                for (i, op) in operations.iter().enumerate() {
                    if matches!(op, SecurityOp::Batch { .. }) {
                        return Err(format!(
                            "Operation {} of {n} in the batch ({}): Nested security batches are not supported; \
                             flatten the operations.",
                            i.saturating_add(1),
                            op.action()
                        ));
                    }
                    staged.security.validate(op, &staged).map_err(|e| {
                        format!("Operation {} of {n} in the batch ({}): {e}", i.saturating_add(1), op.action())
                    })?;
                    staged.security.apply(op, 0, &SessionId::from("validation"));
                }
            }
            SecurityOp::AssetUpsert { asset: a } => {
                a.id()?;
                evidence(&a.evidence, true)?;
                if let Some(parent) = &a.parent {
                    asset(parent)?;
                    if Some(parent) == a.id().ok().as_ref() {
                        return Err("An asset cannot be its own parent; choose an existing containing asset.".into());
                    }
                }
                if let Some(old) = self.assets.get(&a.id()?) {
                    if old.parent != a.parent {
                        return Err(
                            "This canonical asset already has a different parent; preserve its recorded identity."
                                .into(),
                        );
                    }
                }
            }
            SecurityOp::CredentialAdd { credential: c } => {
                asset(&c.asset)?;
                text(&c.principal, "principal")?;
                evidence(&c.evidence, true)?;
                if !c
                    .secret_handle
                    .strip_prefix("out:")
                    .is_some_and(|h| (8..=64).contains(&h.len()) && h.bytes().all(|b| b.is_ascii_hexdigit()))
                {
                    return Err("Store secret material in a blob and give its out: handle; do not place a password or key in the ledger.".into());
                }
                if c.unlocks.len() > 64 {
                    return Err("A credential may unlock at most 64 conditions.".into());
                }
                for c in &c.unlocks {
                    text(&c.value, "condition value")?;
                }
            }
            SecurityOp::FootholdAdd { foothold: f } => {
                asset(&f.asset)?;
                text(&f.principal, "principal")?;
                text(&f.access, "access")?;
                evidence(&f.evidence, true)?;
                if f.unlocks.len() > 64 {
                    return Err("A foothold may unlock at most 64 conditions.".into());
                }
                for c in &f.unlocks {
                    text(&c.value, "condition value")?;
                }
            }
            SecurityOp::ConditionUnlock { conditions: c, evidence: e } => {
                conditions(c)?;
                evidence(e, true)?;
            }
            SecurityOp::BlockedOn { target, conditions: c } => {
                if !ledger.claims.iter().any(|x| &x.id == target) && !ledger.dead_ends.iter().any(|x| &x.id == target) {
                    return Err(
                        "Blocked routes must name an existing claim or dead-end ID; record it before its conditions."
                            .into(),
                    );
                }
                conditions(c)?;
            }
            SecurityOp::RevisitAcknowledge { target } => {
                if !self.newly_unlocked().contains(target) {
                    return Err("Acknowledge an unlocked, unacknowledged route from security_query revisit.".into());
                }
            }
            SecurityOp::CoverageSet { asset: id, disposition } => {
                asset(id)?;
                match disposition {
                    CoverageDisposition::Tested { evidence: e } => evidence(e, true)?,
                    CoverageDisposition::Deferred { reason } => text(reason, "coverage deferral reason")?,
                    CoverageDisposition::Untested => {}
                }
            }
            SecurityOp::CoverageRecord {
                surface,
                risk_area,
                outcome,
                control,
                location,
                reason,
                evidence: ev,
                asset: asset_id,
            } => {
                text(surface, "coverage surface")?;
                text(risk_area, "coverage risk area")?;
                let id = surface_coverage_id(surface, risk_area);
                if let Some(existing) = self.surface_coverage.get(&id) {
                    return Err(format!(
                        "Surface coverage for (`{}`, `{}`) already exists as `{id}` (recorded by `{}`, current outcome `{}`). Use `coverage_update` with `id` `{id}` to update it instead of creating a duplicate.",
                        existing.surface,
                        existing.risk_area,
                        existing.updated_by,
                        existing.outcome.as_str(),
                    ));
                }
                if let Some(aid) = asset_id.as_deref() {
                    asset(aid)?;
                }
                validate_surface_coverage_fields(
                    *outcome,
                    control.as_deref(),
                    location.as_deref(),
                    reason.as_deref(),
                    ev,
                    &evidence,
                )?;
            }
            SecurityOp::CoverageUpdate { id, outcome, control, location, reason, evidence: ev } => {
                if !self.surface_coverage.contains_key(id) {
                    return Err(format!(
                        "Surface coverage `{id}` does not exist; query security_query view `coverage` before updating."
                    ));
                }
                validate_surface_coverage_fields(
                    *outcome,
                    control.as_deref(),
                    location.as_deref(),
                    reason.as_deref(),
                    ev,
                    &evidence,
                )?;
            }
            SecurityOp::FindingRecord { finding: f } => {
                text(&f.title, "finding title")?;
                prose(&f.description, "finding description", 16_384)?;
                prose(&f.impact, "finding impact", 16_384)?;
                text(&f.target, "finding target")?;
                evidence(&f.evidence, true)?;
                prose(&f.counterevidence, "counterevidence", 8192)?;
                if f.confidence != FindingConfidence::High {
                    match f.confidence_rationale.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                        Some(r) => prose(r, "confidence_rationale", 4096)?,
                        None => {
                            return Err(
                                "Field `confidence_rationale` is required when `confidence` is not `high`: name the specific gap (for example static-only trace or unconfirmed reachability)."
                                    .into(),
                            );
                        }
                    }
                } else if let Some(r) = f.confidence_rationale.as_deref().filter(|s| !s.is_empty()) {
                    prose(r, "confidence_rationale", 4096)?;
                }
                prose(&f.severity_change_conditions, "severity_change_conditions", 4096)?;
                if let Some(breakdown) = &f.cvss_breakdown {
                    breakdown.calculate()?;
                } else if f.severity.is_none() {
                    return Err(
                        "Provide either `cvss_breakdown` (8 CVSS 3.1 base metrics) or `severity` (critical, high, medium, low, info)."
                            .into(),
                    );
                }
                if let Some(v) = f.technical_analysis.as_deref().filter(|s| !s.is_empty()) {
                    prose(v, "technical_analysis", 16_384)?;
                }
                if let Some(v) = f.remediation_steps.as_deref().filter(|s| !s.is_empty()) {
                    prose(v, "remediation_steps", 16_384)?;
                }
                if let Some(v) = f.assumptions.as_deref().filter(|s| !s.is_empty()) {
                    prose(v, "assumptions", 4096)?;
                }
                if let Some(v) = f.poc_description.as_deref().filter(|s| !s.is_empty()) {
                    prose(v, "poc_description", 8192)?;
                }
                if let Some(h) = f.poc_handle.as_deref().filter(|s| !s.is_empty()) {
                    validate_out_handle(h, "PoC script or transcript")?;
                }
                if let Some(v) = f.endpoint.as_deref().filter(|s| !s.is_empty()) {
                    text(v, "finding endpoint")?;
                }
                if let Some(v) = f.method.as_deref().filter(|s| !s.is_empty()) {
                    validate_method(v)?;
                }
                if let Some(v) = f.cve.as_deref().filter(|s| !s.is_empty()) {
                    validate_cve(v)?;
                }
                if let Some(v) = f.cwe.as_deref().filter(|s| !s.is_empty()) {
                    validate_cwe(v)?;
                }
                if let Some(v) = f.fix_verification.as_deref().filter(|s| !s.is_empty()) {
                    prose(v, "fix_verification", 8192)?;
                }
                validate_code_locations(&f.code_locations, f.fix_verification.as_deref())?;
                if f.http_exchanges.len() > 64 {
                    return Err("Provide at most 64 HTTP exchange references per finding.".into());
                }
                for ex in &f.http_exchanges {
                    text(ex, "HTTP exchange reference")?;
                }
                if let Some(aid) = f.asset.as_deref() {
                    asset(aid)?;
                }
                if let Some(cid) = f.claim.as_deref() {
                    if !ledger.claims.iter().any(|c| c.id == cid) {
                        return Err(format!(
                            "Claim `{cid}` does not exist; record the claim before linking a finding."
                        ));
                    }
                }
                let id = f.id();
                if let Some(existing) = self.findings.get(&id) {
                    return Err(format!(
                        "Finding `{}` already exists as `{id}` (severity `{}`, status `{}`). Use `finding_update` with `id` `{id}` to revise it instead of creating a duplicate.",
                        existing.title,
                        existing.severity.as_str(),
                        existing.status.as_str(),
                    ));
                }
                if let Some(fp) = f.fingerprint() {
                    if let Some(existing) = self
                        .findings
                        .values()
                        .find(|x| x.status == FindingStatus::Active && x.fingerprint.as_deref() == Some(fp.as_str()))
                    {
                        return Err(format!(
                            "Duplicate finding detected by deterministic 3-axis fingerprint (`{fp}`): matches active finding `{}` (`{}`, severity `{}`). Use `finding_update` with `id` `{}` to revise it instead of filing a duplicate.",
                            existing.id,
                            existing.title,
                            existing.severity.as_str(),
                            existing.id,
                        ));
                    }
                }
            }
            SecurityOp::FindingUpdate { update: u } => {
                let Some(existing) = self.findings.get(&u.id) else {
                    return Err(format!(
                        "Finding `{}` does not exist; query security_query view `findings` before updating.",
                        u.id
                    ));
                };
                prose(&u.update_reason, "finding update_reason", 4096)?;
                if !finding_update_has_changes(u) {
                    return Err("Provide at least one finding field to update alongside `update_reason`.".into());
                }
                if let Some(v) = u.title.as_deref() {
                    text(v, "finding title")?;
                }
                if let Some(v) = u.description.as_deref() {
                    prose(v, "finding description", 16_384)?;
                }
                if let Some(v) = u.impact.as_deref() {
                    prose(v, "finding impact", 16_384)?;
                }
                if let Some(v) = u.target.as_deref() {
                    text(v, "finding target")?;
                }
                if !u.evidence.is_empty() {
                    evidence(&u.evidence, false)?;
                }
                if let Some(v) = u.counterevidence.as_deref() {
                    prose(v, "counterevidence", 8192)?;
                }
                if let Some(v) = u.confidence_rationale.as_deref().filter(|s| !s.is_empty()) {
                    prose(v, "confidence_rationale", 4096)?;
                }
                let next_conf = u.confidence.unwrap_or(existing.confidence);
                let next_rationale = u.confidence_rationale.as_deref().or(existing.confidence_rationale.as_deref());
                if next_conf != FindingConfidence::High && !next_rationale.is_some_and(|s| !s.trim().is_empty()) {
                    return Err(
                        "Field `confidence_rationale` is required when `confidence` is not `high`: name the specific gap."
                            .into(),
                    );
                }
                if let Some(v) = u.severity_change_conditions.as_deref() {
                    prose(v, "severity_change_conditions", 4096)?;
                }
                if let Some(breakdown) = &u.cvss_breakdown {
                    breakdown.calculate()?;
                } else if u.severity.is_some() && existing.cvss_breakdown.is_some() {
                    return Err(
                        "This finding is rated by a `cvss_breakdown`; update `cvss_breakdown` so the CVSS score and severity stay consistent."
                            .into(),
                    );
                }
                if let Some(v) = u.technical_analysis.as_deref().filter(|s| !s.is_empty()) {
                    prose(v, "technical_analysis", 16_384)?;
                }
                if let Some(v) = u.remediation_steps.as_deref().filter(|s| !s.is_empty()) {
                    prose(v, "remediation_steps", 16_384)?;
                }
                if let Some(v) = u.assumptions.as_deref().filter(|s| !s.is_empty()) {
                    prose(v, "assumptions", 4096)?;
                }
                if let Some(v) = u.poc_description.as_deref().filter(|s| !s.is_empty()) {
                    prose(v, "poc_description", 8192)?;
                }
                if let Some(h) = u.poc_handle.as_deref().filter(|s| !s.is_empty()) {
                    validate_out_handle(h, "PoC script or transcript")?;
                }
                if let Some(v) = u.endpoint.as_deref().filter(|s| !s.is_empty()) {
                    text(v, "finding endpoint")?;
                }
                if let Some(v) = u.method.as_deref().filter(|s| !s.is_empty()) {
                    validate_method(v)?;
                }
                if let Some(v) = u.cve.as_deref().filter(|s| !s.is_empty()) {
                    validate_cve(v)?;
                }
                if let Some(v) = u.cwe.as_deref().filter(|s| !s.is_empty()) {
                    validate_cwe(v)?;
                }
                if let Some(v) = u.fix_verification.as_deref().filter(|s| !s.is_empty()) {
                    prose(v, "fix_verification", 8192)?;
                }
                if let Some(locs) = &u.code_locations {
                    let effective_verif = u.fix_verification.as_deref().or(existing.fix_verification.as_deref());
                    validate_code_locations(locs, effective_verif)?;
                }
                if u.http_exchanges.len() > 64 {
                    return Err("Provide at most 64 HTTP exchange references per update.".into());
                }
                for ex in &u.http_exchanges {
                    text(ex, "HTTP exchange reference")?;
                }
                if let Some(v) = u.withdrawn_reason.as_deref().filter(|s| !s.is_empty()) {
                    prose(v, "withdrawn_reason", 4096)?;
                }
            }
            SecurityOp::CrashRecord { signature, attempt } => {
                signature.key()?;
                text(&attempt.vector, "attempt vector")?;
                text(&attempt.summary, "attempt summary")?;
                if attempt.summary.lines().count() > 6 {
                    return Err("Keep the attempt summary within six compact lines.".into());
                }
                evidence(&attempt.evidence, true)?;
                if self.vector_attempts.len() >= MAX_RECORDS
                    && !self.vector_attempts.contains_key(attempt.vector.trim())
                {
                    return Err("The attempt registry reached its vector bound; start a narrower mission.".into());
                }
            }
            SecurityOp::HypothesisOpen { .. }
            | SecurityOp::HypothesisPriority { .. }
            | SecurityOp::HypothesisEvidence { .. }
            | SecurityOp::HypothesisVerdict { .. }
            | SecurityOp::RuleInstall { .. }
            | SecurityOp::RuleRetract { .. } => return Err(REMOVED_OP_REFUSAL.into()),
            SecurityOp::RelationAdd { relation: r } => {
                asset(&r.from)?;
                asset(&r.to)?;
                text(&r.kind, "relation kind")?;
                evidence(&r.evidence, true)?;
                if r.cost == 0 || r.cost > 1000 || r.from == r.to {
                    return Err(
                        "A relation needs distinct assets and an integer investigation cost from one to 1000.".into()
                    );
                }
            }
            SecurityOp::FactAssert { fact, evidence: e } => {
                fact.validate()?;
                evidence(e, true)?;
                if self
                    .facts
                    .values()
                    .any(|f| f.active && f.fact.predicate == fact.predicate && f.fact.args.len() != fact.args.len())
                {
                    return Err(
                        "A predicate must keep one arity; use a different predicate name for another tuple shape."
                            .into(),
                    );
                }
            }
            SecurityOp::FactRetract { id, reason } => {
                text(reason, "retraction reason")?;
                if !self.facts.get(id).is_some_and(|f| f.active) {
                    return Err("Retract an existing active base fact, not a derived conclusion.".into());
                }
            }
            SecurityOp::AliasAdd { alias, target } => {
                text(alias, "alias")?;
                if self.aliases.len() >= MAX_RECORDS
                    || alias.len() > 128
                    || self.resolve(alias).is_ok()
                    || !self.all_ids().contains(target)
                {
                    return Err(
                        "Choose an unused alias of at most 128 bytes and an exact existing security record ID.".into(),
                    );
                }
            }
        }
        if self.all_ids().len() >= MAX_RECORDS
            && matches!(
                op,
                SecurityOp::AssetUpsert { .. }
                    | SecurityOp::CredentialAdd { .. }
                    | SecurityOp::FootholdAdd { .. }
                    | SecurityOp::RelationAdd { .. }
                    | SecurityOp::FactAssert { .. }
                    | SecurityOp::CrashRecord { .. }
                    | SecurityOp::CoverageRecord { .. }
                    | SecurityOp::FindingRecord { .. }
            )
        {
            return Err("The security ledger reached its 10000-record bound; start a narrower mission instead of adding records.".into());
        }
        Ok(())
    }

    fn all_ids(&self) -> BTreeSet<String> {
        self.assets
            .keys()
            .chain(self.credentials.keys())
            .chain(self.footholds.keys())
            .chain(self.crashes.keys())
            .chain(self.relations.keys())
            .chain(self.facts.keys())
            .chain(self.surface_coverage.keys())
            .chain(self.findings.keys())
            .cloned()
            .collect()
    }

    pub fn apply(&mut self, op: &SecurityOp, n: u64, session: &SessionId) {
        match op {
            SecurityOp::Batch { operations } => {
                for op in operations {
                    if !matches!(op, SecurityOp::Batch { .. }) {
                        self.apply(op, n, session);
                    }
                }
            }
            SecurityOp::AssetUpsert { asset: a } => {
                if let (Ok(id), Ok(locator)) = (a.id(), canonical_locator(a.kind, &a.locator)) {
                    let record = self.assets.entry(id.clone()).or_insert_with(|| Asset {
                        id: id.clone(),
                        kind: a.kind,
                        locator,
                        evidence: Vec::new(),
                        mandatory: a.mandatory,
                        parent: a.parent.clone(),
                        coverage: CoverageDisposition::Untested,
                        n,
                    });
                    merge(&mut record.evidence, &a.evidence);
                    record.mandatory |= a.mandatory;
                    if let Some(parent) = &a.parent {
                        self.add_relation(
                            RelationInput {
                                from: parent.clone(),
                                to: id,
                                kind: "contains".into(),
                                cost: 1,
                                evidence: a.evidence.clone(),
                                expires_ms: None,
                            },
                            n,
                        );
                    }
                }
            }
            SecurityOp::CredentialAdd { credential: c } => {
                let id = stable_id("cr", &[&c.asset, &c.principal, &c.secret_handle]);
                let record =
                    self.credentials.entry(id.clone()).or_insert_with(|| Credential { id, input: c.clone(), n });
                merge(&mut record.input.evidence, &c.evidence);
                merge(&mut record.input.unlocks, &c.unlocks);
                record.input.expires_ms = c.expires_ms;
                record.n = n;
            }
            SecurityOp::FootholdAdd { foothold: f } => {
                let id = stable_id("fh", &[&f.asset, &f.principal, &f.access]);
                let record = self.footholds.entry(id.clone()).or_insert_with(|| Foothold { id, input: f.clone(), n });
                merge(&mut record.input.evidence, &f.evidence);
                merge(&mut record.input.unlocks, &f.unlocks);
                record.input.expires_ms = f.expires_ms;
                record.n = n;
            }
            SecurityOp::ConditionUnlock { conditions, evidence } => {
                self.unlocked.extend(conditions.iter().cloned());
                for c in conditions {
                    let id = stable_id("cn", &[&format!("{:?}", c.kind), &c.value]);
                    merge(self.condition_evidence.entry(id).or_default(), evidence);
                }
            }
            SecurityOp::BlockedOn { target, conditions } => {
                self.revisited.remove(target);
                self.blocked
                    .insert(target.clone(), BlockedRoute { target: target.clone(), conditions: conditions.clone(), n });
            }
            SecurityOp::RevisitAcknowledge { target } => {
                self.revisited.insert(target.clone(), n);
            }
            SecurityOp::CoverageSet { asset, disposition } => {
                if let Some(a) = self.assets.get_mut(asset) {
                    a.coverage = disposition.clone();
                }
            }
            SecurityOp::CoverageRecord { surface, risk_area, outcome, control, location, reason, evidence, asset } => {
                let id = surface_coverage_id(surface, risk_area);
                if self.surface_coverage.contains_key(&id) {
                    return;
                }
                let mut ev = Vec::new();
                merge(&mut ev, evidence);
                self.surface_coverage.insert(
                    id.clone(),
                    SurfaceCoverage {
                        id,
                        surface: surface.trim().to_string(),
                        risk_area: risk_area.trim().to_string(),
                        asset: asset.clone(),
                        outcome: *outcome,
                        control: clean_opt(control.as_deref()),
                        location: clean_opt(location.as_deref()),
                        reason: clean_opt(reason.as_deref()),
                        evidence: ev,
                        recorded_by: session.clone(),
                        updated_by: session.clone(),
                        created_n: n,
                        updated_n: n,
                        history: Vec::new(),
                    },
                );
            }
            SecurityOp::CoverageUpdate { id, outcome, control, location, reason, evidence } => {
                if let Some(entry) = self.surface_coverage.get_mut(id) {
                    entry.history.push(SurfaceCoverageHistory {
                        outcome: entry.outcome,
                        control: entry.control.clone(),
                        location: entry.location.clone(),
                        reason: entry.reason.clone(),
                        evidence: entry.evidence.clone(),
                        session: entry.updated_by.clone(),
                        n: entry.updated_n,
                    });
                    entry.outcome = *outcome;
                    entry.control = clean_opt(control.as_deref());
                    entry.location = clean_opt(location.as_deref());
                    entry.reason = clean_opt(reason.as_deref());
                    let mut ev = Vec::new();
                    merge(&mut ev, evidence);
                    entry.evidence = ev;
                    entry.updated_by = session.clone();
                    entry.updated_n = n;
                }
            }
            SecurityOp::FindingRecord { finding: f } => {
                let id = f.id();
                if self.findings.contains_key(&id) {
                    return;
                }
                let (cvss, severity, cvss_vector, cvss_breakdown) = match &f.cvss_breakdown {
                    Some(b) => match b.calculate() {
                        Ok((score, sev, vec)) => (Some(score), sev, Some(vec), Some(b.clone())),
                        Err(_) => return,
                    },
                    None => match f.severity {
                        Some(sev) => (None, sev, None, None),
                        None => return,
                    },
                };
                let mut ev = Vec::new();
                merge(&mut ev, &f.evidence);
                let mut exchanges = Vec::new();
                merge(&mut exchanges, &f.http_exchanges);
                self.findings.insert(
                    id.clone(),
                    Finding {
                        id,
                        title: f.title.trim().to_string(),
                        description: f.description.trim().to_string(),
                        impact: f.impact.trim().to_string(),
                        target: f.target.trim().to_string(),
                        severity,
                        cvss,
                        cvss_vector,
                        cvss_breakdown,
                        evidence: ev,
                        counterevidence: f.counterevidence.trim().to_string(),
                        confidence: f.confidence,
                        confidence_rationale: clean_opt(f.confidence_rationale.as_deref()),
                        severity_change_conditions: f.severity_change_conditions.trim().to_string(),
                        technical_analysis: clean_opt(f.technical_analysis.as_deref()),
                        remediation_steps: clean_opt(f.remediation_steps.as_deref()),
                        assumptions: clean_opt(f.assumptions.as_deref()),
                        poc_description: clean_opt(f.poc_description.as_deref()),
                        poc_handle: clean_opt(f.poc_handle.as_deref()),
                        fix_effort: f.fix_effort,
                        endpoint: clean_opt(f.endpoint.as_deref()),
                        method: f.method.as_deref().and_then(|m| validate_method(m).ok()),
                        cve: f.cve.as_deref().and_then(|c| validate_cve(c).ok()),
                        cwe: f.cwe.as_deref().and_then(|c| validate_cwe(c).ok()),
                        code_locations: normalize_code_locations(&f.code_locations),
                        fix_verification: clean_opt(f.fix_verification.as_deref()),
                        http_exchanges: exchanges,
                        asset: f.asset.clone(),
                        claim: f.claim.clone(),
                        fingerprint: f.fingerprint(),
                        status: FindingStatus::Active,
                        withdrawn_reason: None,
                        recorded_by: session.clone(),
                        updated_by: session.clone(),
                        created_n: n,
                        updated_n: n,
                        revisions: Vec::new(),
                    },
                );
            }
            SecurityOp::FindingUpdate { update: u } => {
                if let Some(entry) = self.findings.get_mut(&u.id) {
                    let prev_severity = entry.severity;
                    let prev_confidence = entry.confidence;
                    let prev_status = entry.status;
                    let mut updated_fields = Vec::new();
                    if let Some(v) = &u.title {
                        entry.title = v.trim().to_string();
                        updated_fields.push("title".into());
                    }
                    if let Some(v) = &u.description {
                        entry.description = v.trim().to_string();
                        updated_fields.push("description".into());
                    }
                    if let Some(v) = &u.impact {
                        entry.impact = v.trim().to_string();
                        updated_fields.push("impact".into());
                    }
                    if let Some(v) = &u.target {
                        entry.target = v.trim().to_string();
                        updated_fields.push("target".into());
                    }
                    if !u.evidence.is_empty() {
                        merge(&mut entry.evidence, &u.evidence);
                        updated_fields.push("evidence".into());
                    }
                    if let Some(v) = &u.counterevidence {
                        entry.counterevidence = v.trim().to_string();
                        updated_fields.push("counterevidence".into());
                    }
                    if let Some(v) = u.confidence {
                        entry.confidence = v;
                        updated_fields.push("confidence".into());
                    }
                    if let Some(v) = &u.confidence_rationale {
                        entry.confidence_rationale = clean_opt(Some(v));
                        updated_fields.push("confidence_rationale".into());
                    }
                    if let Some(v) = &u.severity_change_conditions {
                        entry.severity_change_conditions = v.trim().to_string();
                        updated_fields.push("severity_change_conditions".into());
                    }
                    if let Some(b) = &u.cvss_breakdown {
                        if let Ok((score, sev, vec)) = b.calculate() {
                            entry.cvss = Some(score);
                            entry.severity = sev;
                            entry.cvss_vector = Some(vec);
                            entry.cvss_breakdown = Some(b.clone());
                            updated_fields.push("cvss_breakdown".into());
                        }
                    } else if let Some(sev) = u.severity {
                        entry.severity = sev;
                        updated_fields.push("severity".into());
                    }
                    if let Some(v) = &u.technical_analysis {
                        entry.technical_analysis = clean_opt(Some(v));
                        updated_fields.push("technical_analysis".into());
                    }
                    if let Some(v) = &u.remediation_steps {
                        entry.remediation_steps = clean_opt(Some(v));
                        updated_fields.push("remediation_steps".into());
                    }
                    if let Some(v) = &u.assumptions {
                        entry.assumptions = clean_opt(Some(v));
                        updated_fields.push("assumptions".into());
                    }
                    if let Some(v) = &u.poc_description {
                        entry.poc_description = clean_opt(Some(v));
                        updated_fields.push("poc_description".into());
                    }
                    if let Some(v) = &u.poc_handle {
                        entry.poc_handle = clean_opt(Some(v));
                        updated_fields.push("poc_handle".into());
                    }
                    if let Some(v) = u.fix_effort {
                        entry.fix_effort = Some(v);
                        updated_fields.push("fix_effort".into());
                    }
                    if let Some(v) = &u.endpoint {
                        entry.endpoint = clean_opt(Some(v));
                        updated_fields.push("endpoint".into());
                    }
                    if let Some(v) = &u.method {
                        entry.method = validate_method(v).ok();
                        updated_fields.push("method".into());
                    }
                    if let Some(v) = &u.cve {
                        entry.cve = validate_cve(v).ok();
                        updated_fields.push("cve".into());
                    }
                    if let Some(v) = &u.cwe {
                        entry.cwe = validate_cwe(v).ok();
                        updated_fields.push("cwe".into());
                    }
                    if let Some(locs) = &u.code_locations {
                        entry.code_locations = normalize_code_locations(locs);
                        updated_fields.push("code_locations".into());
                    }
                    if let Some(v) = &u.fix_verification {
                        entry.fix_verification = clean_opt(Some(v));
                        updated_fields.push("fix_verification".into());
                    }
                    if !u.http_exchanges.is_empty() {
                        merge(&mut entry.http_exchanges, &u.http_exchanges);
                        updated_fields.push("http_exchanges".into());
                    }
                    if let Some(st) = u.status {
                        entry.status = st;
                        updated_fields.push("status".into());
                        if st == FindingStatus::Withdrawn {
                            entry.withdrawn_reason = clean_opt(u.withdrawn_reason.as_deref())
                                .or_else(|| Some(u.update_reason.trim().to_string()));
                        } else {
                            entry.withdrawn_reason = None;
                        }
                    } else if let Some(v) = &u.withdrawn_reason {
                        entry.withdrawn_reason = clean_opt(Some(v));
                        updated_fields.push("withdrawn_reason".into());
                    }
                    updated_fields.sort();
                    updated_fields.dedup();
                    entry.revisions.push(FindingRevision {
                        reason: u.update_reason.trim().to_string(),
                        updated_fields,
                        previous_severity: prev_severity,
                        previous_confidence: prev_confidence,
                        previous_status: prev_status,
                        session: session.clone(),
                        n,
                    });
                    entry.fingerprint = finding_fingerprint_from_parts(
                        entry.cwe.as_deref(),
                        &entry.title,
                        entry.asset.as_deref(),
                        &entry.target,
                        entry.endpoint.as_deref(),
                        &entry.code_locations,
                    );
                    entry.updated_by = session.clone();
                    entry.updated_n = n;
                }
            }
            SecurityOp::CrashRecord { signature, attempt } => {
                if let Ok(id) = signature.key() {
                    let record = self.crashes.entry(id.clone()).or_insert_with(|| CrashRecord {
                        id,
                        signature: signature.clone(),
                        attempts: Vec::new(),
                        count: 0,
                    });
                    record.count = record.count.saturating_add(1);
                    record.attempts.push(attempt.clone());
                    if record.attempts.len() > MAX_ATTEMPTS {
                        record.attempts.remove(0);
                    }
                    let attempts = self.vector_attempts.entry(attempt.vector.trim().into()).or_default();
                    attempts.push(attempt.clone());
                    if attempts.len() > MAX_ATTEMPTS {
                        attempts.remove(0);
                    }
                }
            }
            // Removed operations: old journals still hold them; they change nothing.
            SecurityOp::HypothesisOpen { .. }
            | SecurityOp::HypothesisPriority { .. }
            | SecurityOp::HypothesisEvidence { .. }
            | SecurityOp::HypothesisVerdict { .. }
            | SecurityOp::RuleInstall { .. }
            | SecurityOp::RuleRetract { .. } => {}
            SecurityOp::RelationAdd { relation } => self.add_relation(relation.clone(), n),
            SecurityOp::FactAssert { fact, evidence } => {
                let id = fact.id();
                let record = self.facts.entry(id.clone()).or_insert_with(|| AssertedFact {
                    id,
                    fact: fact.clone(),
                    evidence: Vec::new(),
                    active: true,
                    n,
                });
                record.active = true;
                merge(&mut record.evidence, evidence);
            }
            SecurityOp::FactRetract { id, .. } => {
                if let Some(f) = self.facts.get_mut(id) {
                    f.active = false;
                }
            }
            SecurityOp::AliasAdd { alias, target } => {
                self.aliases.insert(alias.clone(), target.clone());
            }
        }
    }

    fn add_relation(&mut self, input: RelationInput, n: u64) {
        let id = stable_id("rl", &[&input.from, &input.to, &input.kind]);
        let r = self.relations.entry(id.clone()).or_insert_with(|| Relation { id, input: input.clone(), n });
        merge(&mut r.input.evidence, &input.evidence);
        r.input.cost = input.cost;
        r.input.expires_ms = input.expires_ms;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{Entry, Evidence, EvidenceInput, EvidenceKind, LedgerOp};
    use crate::CallId;

    fn ledger() -> LedgerState {
        let mut l = LedgerState::default();
        for n in 1..=2 {
            l.evidence.push(Evidence {
                id: format!("e{n}"),
                n,
                input: EvidenceInput {
                    claim: "c1".into(),
                    kind: EvidenceKind::Execution,
                    supports: true,
                    session: "s-source".into(),
                    call_id: CallId::from("call"),
                    blob: None,
                    lines: None,
                    quote: None,
                    note: "test observation".into(),
                    attested: true,
                    tool: None,
                    grade: None,
                },
            });
        }
        l
    }
    fn apply(l: &mut LedgerState, op: SecurityOp) {
        l.validate(&LedgerOp::Security(op.clone()), false).unwrap();
        l.apply(&Entry {
            n: l.entries + 1,
            ts_ms: 0,
            session: "s-lead".into(),
            from_user: false,
            op: LedgerOp::Security(op),
            mac: String::new(),
        });
    }
    fn asset(l: &mut LedgerState, name: &str) -> String {
        let a = AssetInput {
            kind: AssetKind::Host,
            locator: name.into(),
            evidence: vec!["e1".into()],
            mandatory: true,
            parent: None,
        };
        let id = a.id().unwrap();
        apply(l, SecurityOp::AssetUpsert { asset: a });
        id
    }
    #[test]
    fn canonical_dedup_preserves_url_path_case_and_requires_attestation() {
        let mut l = ledger();
        let id = asset(&mut l, "Example.TEST.");
        assert_eq!(id, asset(&mut l, "example.test"));
        assert_eq!(l.security.assets.len(), 1);
        let url = canonical_locator(AssetKind::Endpoint, "HTTP://EXAMPLE.TEST:80/Case?q=Hi").unwrap();
        assert_eq!(url, "http://example.test/Case?q=Hi");
        assert_ne!(url, canonical_locator(AssetKind::Endpoint, "http://example.test/case?q=Hi").unwrap());
        assert!(canonical_locator(AssetKind::Endpoint, "https://user:pass@example.test").is_err());
        let no_evidence = SecurityOp::AssetUpsert {
            asset: AssetInput {
                kind: AssetKind::Host,
                locator: "other.test".into(),
                evidence: vec!["e404".into()],
                mandatory: true,
                parent: None,
            },
        };
        assert!(l.validate(&LedgerOp::Security(no_evidence), false).is_err());
        apply(&mut l, SecurityOp::AliasAdd { alias: "web".into(), target: id.clone() });
        assert_eq!(l.security.resolve("web").unwrap(), id);
        assert_eq!(l.security.resolve(&id.chars().take(14).collect::<String>()).unwrap(), id);
        assert!(l.security.resolve("as-").is_err());
    }

    #[test]
    fn coverage_and_typed_unlocks_do_not_close_without_evidence() {
        let mut l = ledger();
        let id = asset(&mut l, "example.test");
        assert_eq!(l.security.mandatory_open(), vec![id.clone()]);
        assert!(l
            .validate(&LedgerOp::FinishClaim { summary: "done".into(), evidence: vec!["e1".into()] }, false)
            .unwrap_err()
            .contains("coverage"));
        let bad = SecurityOp::CoverageSet {
            asset: id.clone(),
            disposition: CoverageDisposition::Tested { evidence: vec![] },
        };
        assert!(l.validate(&LedgerOp::Security(bad), false).is_err());
        let bad = SecurityOp::CoverageSet {
            asset: id.clone(),
            disposition: CoverageDisposition::Deferred { reason: " ".into() },
        };
        assert!(l.validate(&LedgerOp::Security(bad), false).is_err());
        apply(
            &mut l,
            SecurityOp::CoverageSet {
                asset: id.clone(),
                disposition: CoverageDisposition::Tested { evidence: vec!["e1".into()] },
            },
        );
        assert!(l.security.mandatory_open().is_empty());
        l.dead_ends.push(crate::ledger::DeadEnd { id: "x1".into(), what: "route".into(), why: "no auth".into(), n: 0 });
        let condition = Condition { kind: ConditionKind::Auth, value: id.clone() };
        apply(&mut l, SecurityOp::BlockedOn { target: "x1".into(), conditions: vec![condition.clone()] });
        assert!(l.security.newly_unlocked_at(100).is_empty());
        apply(
            &mut l,
            SecurityOp::FootholdAdd {
                foothold: FootholdInput {
                    asset: id,
                    principal: "dummy".into(),
                    access: "session".into(),
                    evidence: vec!["e1".into()],
                    unlocks: vec![],
                    expires_ms: Some(200),
                },
            },
        );
        assert_eq!(l.security.newly_unlocked_at(100), vec!["x1".to_string()]);
        assert!(l.security.newly_unlocked_at(201).is_empty());
        apply(&mut l, SecurityOp::RevisitAcknowledge { target: "x1".into() });
        assert!(l.security.newly_unlocked_at(100).is_empty());
        apply(&mut l, SecurityOp::BlockedOn { target: "x1".into(), conditions: vec![condition] });
        assert_eq!(l.security.newly_unlocked_at(100), vec!["x1".to_string()]);
    }

    #[test]
    fn final_acceptance_rechecks_coverage_added_after_the_finish_claim() {
        let mut l = ledger();
        let op = LedgerOp::FinishClaim { summary: "fixture result".into(), evidence: vec!["e1".into()] };
        l.validate(&op, false).unwrap();
        l.apply(&Entry { n: 1, ts_ms: 0, session: "s-lead".into(), from_user: false, op, mac: String::new() });
        asset(&mut l, "newly-discovered.test");
        let verdict = |accepted| LedgerOp::FinishVerdict {
            claim: "f1".into(),
            accepted,
            objections: vec![],
            verifier: Some("s-judge".into()),
        };
        assert!(l.validate(&verdict(true), false).unwrap_err().contains("coverage"));
        assert!(l.validate(&verdict(false), false).is_ok());
    }

    #[test]
    fn crash_signatures_keep_root_line_ignore_caller_lines_and_bound_attempts() {
        let signature = CrashSignature {
            sanitizer: "ASAN-heap-overflow".into(),
            outcome: CrashOutcome::Crash,
            frames: vec![
                CrashFrame { function: "parse".into(), file: "a.c".into(), line: Some(7) },
                CrashFrame { function: "caller".into(), file: "b.c".into(), line: Some(8) },
            ],
        };
        let mut changed = signature.clone();
        changed.frames[1].line = Some(99);
        assert_eq!(signature.key().unwrap(), changed.key().unwrap());
        changed.frames[0].line = Some(8);
        assert_ne!(signature.key().unwrap(), changed.key().unwrap());
        changed.outcome = CrashOutcome::Oom;
        assert!(changed.key().is_err());
        let mut l = ledger();
        for i in 0..9 {
            apply(
                &mut l,
                SecurityOp::CrashRecord {
                    signature: signature.clone(),
                    attempt: AttemptInput {
                        vector: "parser".into(),
                        summary: format!("attempt {i}"),
                        evidence: vec!["e1".into()],
                    },
                },
            );
        }
        let record = l.security.crashes.values().next().unwrap();
        assert_eq!(record.count, 9);
        assert_eq!(record.attempts.len(), 6);
        assert_eq!(record.attempts[0].summary, "attempt 3");
        assert_eq!(l.security.vector_attempts.get("parser").unwrap().len(), 6);
    }

    #[test]
    fn batch_error_names_the_failing_operation_and_applies_nothing() {
        let l = ledger();
        let host = |name: &str, evidence: &str| SecurityOp::AssetUpsert {
            asset: AssetInput {
                kind: AssetKind::Host,
                locator: name.into(),
                evidence: vec![evidence.into()],
                mandatory: true,
                parent: None,
            },
        };
        let ops =
            vec![host("a.test", "e1"), host("b.test", "e404"), SecurityOp::RevisitAcknowledge { target: "x".into() }];
        for op in &ops {
            assert_eq!(serde_json::to_value(op).unwrap()["action"], op.action());
        }
        let batch = SecurityOp::Batch { operations: ops };
        assert_eq!(serde_json::to_value(&batch).unwrap()["action"], batch.action());
        let err = l.validate(&LedgerOp::Security(batch), false).unwrap_err();
        assert!(err.starts_with("Operation 2 of 3 in the batch (asset_upsert): "), "{err}");
        assert!(err.contains("e404"), "{err}");
        assert!(l.security.assets.is_empty());
        // A nested batch is one of the operations that fails, and is named like the others.
        let nested = SecurityOp::Batch {
            operations: vec![host("a.test", "e1"), SecurityOp::Batch { operations: vec![host("c.test", "e1")] }],
        };
        let err = l.validate(&LedgerOp::Security(nested), false).unwrap_err();
        assert_eq!(
            err,
            "Operation 2 of 2 in the batch (batch): Nested security batches are not supported; flatten the operations."
        );
    }

    #[test]
    fn sealed_replay_batch_atomicity_and_old_snapshot_compatibility() {
        let dir = tempfile::tempdir().unwrap();
        let journal = crate::journal::Journal::new(dir.path().join("journal.jsonl"), vec![7; 32]);
        let session = SessionId::from("s-test");
        journal
            .append(
                &session,
                false,
                LedgerOp::ClaimAdd { text: "scanner observed host".into(), assets: Vec::new() },
                &|_| Ok(()),
            )
            .unwrap();
        let mut input = ledger().evidence[0].input.clone();
        input.claim = "c1".into();
        journal.append(&session, false, LedgerOp::EvidenceAdd(input), &|_| Ok(())).unwrap();
        let a = AssetInput {
            kind: AssetKind::Host,
            locator: "example.test".into(),
            evidence: vec!["e1".into()],
            mandatory: true,
            parent: None,
        };
        let batch = SecurityOp::Batch {
            operations: vec![
                SecurityOp::AssetUpsert { asset: a.clone() },
                SecurityOp::CoverageSet {
                    asset: a.id().unwrap(),
                    disposition: CoverageDisposition::Tested { evidence: vec!["e404".into()] },
                },
            ],
        };
        assert!(journal.append(&session, false, LedgerOp::Security(batch), &|_| Ok(())).is_err());
        assert!(journal.state().unwrap().security.assets.is_empty());
        let (_, saved) = journal
            .append(&session, false, LedgerOp::Security(SecurityOp::AssetUpsert { asset: a }), &|_| Ok(()))
            .unwrap();
        assert_eq!(saved, journal.state().unwrap());
        let mut json = serde_json::to_value(&saved).unwrap();
        json.as_object_mut().unwrap().remove("security");
        let old: LedgerState = serde_json::from_value(json).unwrap();
        assert_eq!(old.security, SecurityState::default());
        for e in journal.read().unwrap().into_iter().filter(|e| matches!(e.op, LedgerOp::Security(_))) {
            let json = serde_json::to_string(&e).unwrap();
            assert_eq!(e, serde_json::from_str::<Entry>(&json).unwrap());
        }
    }

    fn removed_ops() -> Vec<SecurityOp> {
        vec![
            SecurityOp::HypothesisOpen { text: "the admin panel trusts a header".into(), priority: 3 },
            SecurityOp::HypothesisPriority { id: "hy-1".into(), priority: 5 },
            SecurityOp::HypothesisEvidence {
                id: "hy-1".into(),
                evidence: vec!["e1".into()],
                counterevidence: Vec::new(),
            },
            SecurityOp::HypothesisVerdict {
                id: "hy-1".into(),
                status: HypothesisStatus::Supported,
                note: "run showed it".into(),
                evidence: vec!["e1".into()],
                counterevidence: Vec::new(),
            },
            SecurityOp::RuleInstall {
                rule: Rule {
                    name: "r".into(),
                    head: Atom { predicate: "viable".into(), args: vec!["?x".into()] },
                    body: vec![Literal {
                        atom: Atom { predicate: "asset".into(), args: vec!["?x".into(), "?k".into(), "?l".into()] },
                        negated: false,
                    }],
                },
            },
            SecurityOp::RuleRetract { id: "ru-1".into(), reason: "gone".into() },
        ]
    }

    #[test]
    fn old_logs_with_removed_ops_load_and_project_the_rest_unchanged() {
        let mut l = ledger();
        let id = asset(&mut l, "example.test");
        apply(&mut l, SecurityOp::AliasAdd { alias: "web".into(), target: id.clone() });
        let expected = l.security.clone();
        // Every removed op deserializes from its old JSON, applies as a no-op, and is named by `action`.
        for op in removed_ops() {
            let json = serde_json::to_string(&op).unwrap();
            let back: SecurityOp = serde_json::from_str(&json).unwrap();
            assert_eq!(back, op);
            assert_eq!(serde_json::to_value(&op).unwrap()["action"], op.action());
            l.security.apply(&op, 99, &SessionId::from("s-old"));
            assert_eq!(l.security, expected, "{}", op.action());
        }
        // They are also fine inside an old batch, and a new append of one is refused.
        l.security.apply(&SecurityOp::Batch { operations: removed_ops() }, 100, &SessionId::from("s-old"));
        assert_eq!(l.security, expected);
        for op in removed_ops() {
            let err = l.validate(&LedgerOp::Security(op), false).unwrap_err();
            assert_eq!(err, REMOVED_OP_REFUSAL);
        }
        // A snapshot written with the removed fields still loads and drops them.
        let mut json = serde_json::to_value(&expected).unwrap();
        json["hypotheses"] = serde_json::json!({"hy-1": {"id": "hy-1", "text": "t", "priority": 1, "status": "open"}});
        json["rules"] = serde_json::json!({});
        json["died"] = serde_json::json!([{"predicate": "viable", "args": ["a"]}]);
        json["retraction_limitation"] = serde_json::json!("old text");
        let loaded: SecurityState = serde_json::from_value(json).unwrap();
        assert_eq!(loaded, expected);
        assert_eq!(loaded.aliases.get("web"), Some(&id));
        assert_eq!(loaded.assets.len(), 1);
    }

    #[test]
    fn asserted_facts_are_recorded_and_retracted_without_an_engine() {
        let mut l = ledger();
        let f = Fact { predicate: "seen".into(), args: vec!["a".into()] };
        apply(&mut l, SecurityOp::FactAssert { fact: f.clone(), evidence: vec!["e1".into()] });
        apply(&mut l, SecurityOp::FactRetract { id: f.id(), reason: "mistaken".into() });
        assert!(!l.security.facts[&f.id()].active);
        let wrong = SecurityOp::FactAssert {
            fact: Fact { predicate: "seen".into(), args: vec![] },
            evidence: vec!["e1".into()],
        };
        assert!(l.validate(&LedgerOp::Security(wrong), false).is_ok());
    }

    #[test]
    fn surface_coverage_enforces_five_dispositions_rejects_duplicates_and_tracks_history() {
        let mut l = ledger();
        let aid = asset(&mut l, "app.example.test");

        // 1. ruled_out requires both control and location
        let bad_ruled_out = SecurityOp::CoverageRecord {
            surface: "POST /api/login".into(),
            risk_area: "SQL injection".into(),
            outcome: SurfaceOutcome::RuledOut,
            control: Some("Parameterized query".into()),
            location: None,
            reason: None,
            evidence: vec![],
            asset: Some(aid.clone()),
        };
        assert!(l.validate(&LedgerOp::Security(bad_ruled_out), false).unwrap_err().contains("location"));

        // 2. not_applicable and needs_follow_up require nonblank reason
        let bad_na = SecurityOp::CoverageRecord {
            surface: "POST /api/login".into(),
            risk_area: "XXE".into(),
            outcome: SurfaceOutcome::NotApplicable,
            control: None,
            location: None,
            reason: Some("  ".into()),
            evidence: vec![],
            asset: None,
        };
        assert!(l.validate(&LedgerOp::Security(bad_na), false).unwrap_err().contains("reason"));

        let bad_fu = SecurityOp::CoverageRecord {
            surface: "POST /api/refund".into(),
            risk_area: "IDOR".into(),
            outcome: SurfaceOutcome::NeedsFollowUp,
            control: None,
            location: None,
            reason: None,
            evidence: vec![],
            asset: None,
        };
        assert!(l.validate(&LedgerOp::Security(bad_fu), false).unwrap_err().contains("reason"));

        // 3. reported requires attested evidence
        let bad_rep = SecurityOp::CoverageRecord {
            surface: "GET /api/users".into(),
            risk_area: "SQL injection".into(),
            outcome: SurfaceOutcome::Reported,
            control: None,
            location: None,
            reason: None,
            evidence: vec![],
            asset: None,
        };
        assert!(l.validate(&LedgerOp::Security(bad_rep), false).is_err());

        // 4. no_issue_found requires evidence or reason
        let bad_nif = SecurityOp::CoverageRecord {
            surface: "GET /health".into(),
            risk_area: "SSRF".into(),
            outcome: SurfaceOutcome::NoIssueFound,
            control: None,
            location: None,
            reason: None,
            evidence: vec![],
            asset: None,
        };
        assert!(l.validate(&LedgerOp::Security(bad_nif), false).is_err());

        // Record needs_follow_up, then verify case/whitespace duplicate is rejected naming existing ID
        apply(
            &mut l,
            SecurityOp::CoverageRecord {
                surface: "POST /api/refund".into(),
                risk_area: "IDOR".into(),
                outcome: SurfaceOutcome::NeedsFollowUp,
                control: None,
                location: None,
                reason: Some("Need second user token to test cross-tenant refund.".into()),
                evidence: vec![],
                asset: Some(aid.clone()),
            },
        );
        let id = surface_coverage_id("POST /api/refund", "IDOR");
        assert_eq!(l.security.resolve(&id[..12]).unwrap(), id);
        assert_eq!(l.security.surface_coverage_follow_ups().len(), 1);

        let dup = SecurityOp::CoverageRecord {
            surface: "  post /api/refund ".into(),
            risk_area: "idor".into(),
            outcome: SurfaceOutcome::NoIssueFound,
            control: None,
            location: None,
            reason: Some("retested".into()),
            evidence: vec!["e1".into()],
            asset: None,
        };
        let err = l.validate(&LedgerOp::Security(dup), false).unwrap_err();
        assert!(err.contains(&id) && err.contains("needs_follow_up") && err.contains("coverage_update"), "{err}");

        // Update from a second session preserves transition history and immutable (surface, risk_area)
        let upd = SecurityOp::CoverageUpdate {
            id: id.clone(),
            outcome: SurfaceOutcome::RuledOut,
            control: Some("tenant_id == auth.tenant_id check".into()),
            location: Some("src/billing/refund.rs:112".into()),
            reason: Some("Confirmed ownership check runs on every refund handler path.".into()),
            evidence: vec!["e1".into()],
        };
        l.validate(&LedgerOp::Security(upd.clone()), false).unwrap();
        l.apply(&Entry {
            n: l.entries + 1,
            ts_ms: 0,
            session: SessionId::from("s-child"),
            from_user: false,
            op: LedgerOp::Security(upd),
            mac: String::new(),
        });

        let row = &l.security.surface_coverage[&id];
        assert_eq!(row.surface, "POST /api/refund");
        assert_eq!(row.risk_area, "IDOR");
        assert_eq!(row.outcome, SurfaceOutcome::RuledOut);
        assert_eq!(row.recorded_by, SessionId::from("s-lead"));
        assert_eq!(row.updated_by, SessionId::from("s-child"));
        assert_eq!(row.history.len(), 1);
        assert_eq!(row.history[0].outcome, SurfaceOutcome::NeedsFollowUp);
        assert_eq!(row.history[0].session, SessionId::from("s-lead"));
        assert!(l.security.surface_coverage_follow_ups().is_empty());

        // Record remaining outcomes and check counts
        apply(
            &mut l,
            SecurityOp::CoverageRecord {
                surface: "GET /api/users".into(),
                risk_area: "SQL injection".into(),
                outcome: SurfaceOutcome::Reported,
                control: None,
                location: None,
                reason: None,
                evidence: vec!["e1".into()],
                asset: None,
            },
        );
        apply(
            &mut l,
            SecurityOp::CoverageRecord {
                surface: "GET /health".into(),
                risk_area: "SSRF".into(),
                outcome: SurfaceOutcome::NotApplicable,
                control: None,
                location: None,
                reason: Some("Health endpoint makes no outbound network requests.".into()),
                evidence: vec![],
                asset: None,
            },
        );
        let counts = l.security.surface_coverage_counts();
        assert_eq!(counts["ruled_out"], 1);
        assert_eq!(counts["reported"], 1);
        assert_eq!(counts["not_applicable"], 1);
        assert_eq!(counts["no_issue_found"], 0);
        assert_eq!(counts["needs_follow_up"], 0);
    }

    #[test]
    fn cvss_v31_vectors_and_structured_finding_validation_and_revisions() {
        // FIRST CVSS v3.1 reference vectors
        let cases = [
            (("N", "L", "N", "N", "U", "H", "H", "H"), 98u8, FindingSeverity::Critical),
            (("N", "L", "N", "R", "C", "L", "L", "N"), 61u8, FindingSeverity::Medium),
            (("N", "L", "N", "N", "C", "H", "H", "H"), 100u8, FindingSeverity::Critical),
            (("N", "L", "N", "N", "U", "N", "N", "N"), 0u8, FindingSeverity::Info),
            (("N", "L", "L", "N", "U", "H", "N", "N"), 65u8, FindingSeverity::Medium),
        ];
        for ((av, ac, pr, ui, s, c, i, a), want_tenths, want_sev) in cases {
            let bd = CvssBreakdown {
                attack_vector: av.into(),
                attack_complexity: ac.into(),
                privileges_required: pr.into(),
                user_interaction: ui.into(),
                scope: s.into(),
                confidentiality: c.into(),
                integrity: i.into(),
                availability: a.into(),
            };
            let (score, sev, vec) = bd.calculate().unwrap();
            assert_eq!(score.tenths(), want_tenths, "{vec}");
            assert_eq!(sev, want_sev, "{vec}");
            assert!(vec.starts_with("CVSS:3.1/"));
        }

        let mut l = ledger();
        let mut f = FindingInput {
            title: "Reflected XSS in /search q parameter".into(),
            description: "The `q` query parameter is interpolated into HTML without escaping.".into(),
            impact: "Attacker executes arbitrary JavaScript in victim sessions.".into(),
            target: "https://shop.example.test".into(),
            evidence: vec!["e1".into()],
            counterevidence: "Checked headers and template; no CSP and autoescape is off.".into(),
            confidence: FindingConfidence::Medium,
            confidence_rationale: None,
            severity_change_conditions: "A strict nonce CSP would lower impact.".into(),
            cvss_breakdown: Some(CvssBreakdown {
                attack_vector: "N".into(),
                attack_complexity: "L".into(),
                privileges_required: "N".into(),
                user_interaction: "R".into(),
                scope: "C".into(),
                confidentiality: "L".into(),
                integrity: "L".into(),
                availability: "N".into(),
            }),
            severity: None,
            technical_analysis: None,
            remediation_steps: Some("Escape `q` with html.escape().".into()),
            assumptions: None,
            poc_description: None,
            poc_handle: None,
            fix_effort: Some(FixEffort::Low),
            endpoint: Some("/search".into()),
            method: Some("get".into()),
            cve: None,
            cwe: Some("CWE-79".into()),
            code_locations: vec![CodeLocation {
                file: "app/views.py".into(),
                start_line: 12,
                end_line: 12,
                snippet: None,
                label: Some("HTML sink".into()),
                fix_before: Some("return f'<h2>{q}</h2>'".into()),
                fix_after: Some("return f'<h2>{escape(q)}</h2>'".into()),
            }],
            fix_verification: None,
            http_exchanges: vec![],
            asset: None,
            claim: None,
        };

        // Missing confidence_rationale when confidence != high is refused
        assert!(l
            .validate(&LedgerOp::Security(SecurityOp::FindingRecord { finding: Box::new(f.clone()) }), false)
            .unwrap_err()
            .contains("confidence_rationale"));
        f.confidence_rationale = Some("Static trace only; did not execute in a browser.".into());

        // Missing fix_verification when fix_after is provided is refused
        assert!(l
            .validate(&LedgerOp::Security(SecurityOp::FindingRecord { finding: Box::new(f.clone()) }), false)
            .unwrap_err()
            .contains("fix_verification"));
        f.fix_verification = Some(
            "1. Closure: escape encodes <>\"'&. 2. Checked sibling templates. 3. Plain queries preserved. 4. Reasoned."
                .into(),
        );

        // Unsafe path traversal in code_locations is refused
        let mut bad_path = f.clone();
        bad_path.code_locations[0].file = "../etc/passwd".into();
        assert!(l
            .validate(&LedgerOp::Security(SecurityOp::FindingRecord { finding: Box::new(bad_path) }), false)
            .is_err());

        // Record succeeds, derives CVSS 6.1 / Medium, normalizes method to GET
        let fid = f.id();
        apply(&mut l, SecurityOp::FindingRecord { finding: Box::new(f.clone()) });
        assert_eq!(l.security.resolve(&fid[..12]).unwrap(), fid);
        let stored = &l.security.findings[&fid];
        assert_eq!(stored.cvss, Some(CvssScore(61)));
        assert_eq!(stored.severity, FindingSeverity::Medium);
        assert_eq!(stored.method.as_deref(), Some("GET"));

        // Duplicate finding is rejected
        assert!(l
            .validate(&LedgerOp::Security(SecurityOp::FindingRecord { finding: Box::new(f) }), false)
            .unwrap_err()
            .contains("finding_update"));

        // Overriding severity without cvss_breakdown when cvss_breakdown exists is rejected
        let bad_sev_upd = SecurityOp::FindingUpdate {
            update: Box::new(FindingUpdateInput {
                id: fid.clone(),
                update_reason: "re-rating".into(),
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
                severity: Some(FindingSeverity::High),
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
                status: None,
                withdrawn_reason: None,
            }),
        };
        assert!(l.validate(&LedgerOp::Security(bad_sev_upd), false).unwrap_err().contains("cvss_breakdown"));

        // Valid revision updates confidence to High and attaches e2, preserving revision trail
        apply(
            &mut l,
            SecurityOp::FindingUpdate {
                update: Box::new(FindingUpdateInput {
                    id: fid.clone(),
                    update_reason: "Confirmed execution in browser.".into(),
                    title: None,
                    description: None,
                    impact: None,
                    target: None,
                    evidence: vec!["e2".into()],
                    counterevidence: None,
                    confidence: Some(FindingConfidence::High),
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
                    status: None,
                    withdrawn_reason: None,
                }),
            },
        );
        let updated = &l.security.findings[&fid];
        assert_eq!(updated.confidence, FindingConfidence::High);
        assert_eq!(updated.evidence, vec!["e1", "e2"]);
        assert_eq!(updated.revisions.len(), 1);
        assert_eq!(updated.revisions[0].previous_confidence, FindingConfidence::Medium);
    }

    #[test]
    fn finding_three_axis_fingerprint_blocks_reworded_duplicates_and_allows_distinct_or_withdrawn() {
        let mut l = ledger();
        let make = |title: &str, ep: &str, cwe: Option<&str>| FindingInput {
            title: title.into(),
            description: "desc".into(),
            impact: "impact".into(),
            target: "https://shop.example.test".into(),
            evidence: vec!["e1".into()],
            counterevidence: "none".into(),
            confidence: FindingConfidence::High,
            confidence_rationale: None,
            severity_change_conditions: "auth".into(),
            cvss_breakdown: None,
            severity: Some(FindingSeverity::High),
            technical_analysis: None,
            remediation_steps: None,
            assumptions: None,
            poc_description: None,
            poc_handle: None,
            fix_effort: None,
            endpoint: Some(ep.into()),
            method: Some("GET".into()),
            cve: None,
            cwe: cwe.map(str::to_string),
            code_locations: vec![],
            fix_verification: None,
            http_exchanges: vec![],
            asset: None,
            claim: None,
        };

        let f1 = make("SQL Injection in search", "/api/users/?b=1&a=2", Some("CWE-89"));
        let f1_id = f1.id();
        apply(&mut l, SecurityOp::FindingRecord { finding: Box::new(f1) });
        assert!(l.security.findings[&f1_id].fingerprint.as_deref().is_some_and(|fp| fp.starts_with("fp:")));

        // Differently worded title + reversed query param order + trailing slash/casing -> SAME 3-axis fingerprint!
        let f_reworded = make("Blind SQLi on user lookup", "/API/users?a=9&b=0", Some("CWE-89"));
        assert_ne!(f_reworded.id(), f1_id);
        let err = l
            .validate(&LedgerOp::Security(SecurityOp::FindingRecord { finding: Box::new(f_reworded) }), false)
            .unwrap_err();
        assert!(err.contains("3-axis fingerprint") && err.contains(&f1_id), "{err}");

        // Different query parameter -> distinct finding, accepted
        let f_other_param = make("SQLi on sort param", "/api/users?sort=asc", Some("CWE-89"));
        apply(&mut l, SecurityOp::FindingRecord { finding: Box::new(f_other_param) });
        assert_eq!(l.security.findings.len(), 2);

        // Withdrawing f1 allows re-filing the same fingerprint later
        apply(
            &mut l,
            SecurityOp::FindingUpdate {
                update: Box::new(FindingUpdateInput {
                    id: f1_id,
                    update_reason: "re-evaluating".into(),
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
        let f_refiled = make("Confirmed SQLi on user lookup", "/api/users?a=1&b=2", Some("CWE-89"));
        apply(&mut l, SecurityOp::FindingRecord { finding: Box::new(f_refiled) });
        assert_eq!(l.security.active_findings().len(), 2);
    }
}
