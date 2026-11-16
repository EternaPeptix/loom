//! `dep_scan` — OWASP dep-scan (<https://github.com/owasp-dep-scan/dep-scan>) as a tool.
//!
//! CONTRACT.
//!
//! - Runs the operator-installed `depscan` command under the session sandbox (never installs
//!   anything, never starts its server mode). A missing command is an error with install
//!   guidance, not an invented empty result.
//! - The target is a workspace directory (`--src`) or one CycloneDX SBOM file (`--bom`),
//!   resolved and read-checked through the sandbox. All writes go to a fresh directory under
//!   the session temp dir: reports, `HOME`, the vulnerability-database cache (`VDB_HOME`) and
//!   dep-scan's temp dir all live there, so a read-only role can scan and the workspace is
//!   never polluted. That cache is per-session, so a first scan may download the (large)
//!   vulnerability database through the session's egress proxy; the network policy must
//!   allow the hosts that needs (the OCI registry dep-scan is configured with, and whatever
//!   `cdxgen` reaches for the project's ecosystem).
//! - The CycloneDX VDR (`*.vdr.json`) files in the reports directory are the record: they are
//!   parsed, deduplicated and summarised (prioritized/reachable first, then severity score),
//!   and their bytes are stored as blobs the model can page (`out_read`) and quote as
//!   evidence. The generated SBOM (`*.cdx.json`) and the scanner console are stored the same
//!   way and named in the result facts. At most [`MAX_FINDINGS`] finding lines are rendered;
//!   the counts always cover every parsed finding.
//! - dep-scan's `depscan:prioritized` / `depscan:insights` labels are its own static
//!   (reachability) analysis. The summary says so: they are scanner data about the scanned
//!   tree, not execution evidence that vulnerable code runs in a deployed system.
//! - Status is `Ok` for a completed scan whether or not it found anything (a scan result is
//!   an observation, like an HTTP error status in `web_fetch`); `Error` when the scanner did
//!   not complete or produced no parseable VDR, `Interrupted`/`Timeout` when it was stopped.
//!
//! Tests required: VDR parsing/sorting/counts and the no-findings case as pure functions; a
//! fake `depscan` on `PATH` that writes an SBOM+VDR (end to end, stored blobs, raw meta);
//! a missing `depscan` (install guidance, nothing invented); a bad target; a bad project type.

use crate::binary::{command_bounded, quote, CommandOutcome};
use crate::{params, Body, Tool, ToolCtx, ToolOutput};
use async_trait::async_trait;
use loom_core::event::{ToolClass, ToolSpec, ToolStatus, META_RAW_BLOB};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

/// Most finding lines one result renders (the counts still cover all of them).
pub const MAX_FINDINGS: usize = 50;
/// Largest VDR/SBOM file parsed and stored whole; a larger one is left in place and named.
const MAX_ARTIFACT_BYTES: u64 = 32 * 1024 * 1024;
/// Printed by the wrapper script when no `depscan` is on `PATH`.
const MISSING_MARKER: &str = "LOOM_DEPSCAN_NOT_INSTALLED";
/// Default and ceiling for one scan. A first run downloads a multi-GB vulnerability
/// database, so this is far above the other analysis tools' limits.
const DEFAULT_TIMEOUT_S: u64 = 900;
const MAX_TIMEOUT_S: u64 = 3600;

const INSTALL_GUIDANCE: &str = "The `depscan` command (OWASP dep-scan) is not installed or not on the PATH the daemon gives its commands, so no scan was run and nothing was checked. Install it once, outside the session, by one of: `brew tap owasp-dep-scan/tap && brew install dep-scan` (bundles cdxgen), a standalone `depscan` binary from the OWASP dep-scan GitHub releases (bundles cdxgen; verify its .sha256), or `pip install owasp-depscan` plus `npm install -g @cyclonedx/cdxgen`. Then call dep_scan again. A first scan also downloads the vulnerability database, which needs network scope for the registry it is configured to use.";

pub struct DepScan;

#[async_trait]
impl Tool for DepScan {
    fn spec(&self) -> ToolSpec {
        params::spec(
            "dep_scan",
            "Scan a project's dependencies with OWASP dep-scan: generate a CycloneDX SBOM (via cdxgen) for a directory, or examine an existing CycloneDX SBOM file, and report known-vulnerable components prioritized by dep-scan's own reachability analysis. Returns counts and the top findings; the full VDR and SBOM are stored so you can page them with out_read and quote them as evidence. Requires the `depscan` command installed on the host (it is never installed for you); a first scan downloads its vulnerability database through the session's network proxy, so that may need scope and can take minutes. dep-scan's prioritized/reachable labels are static scanner verdicts, not proof that vulnerable code executes.",
            ToolClass::Exec,
            &[
                params::opt("path", "string", "Project directory to scan, or one CycloneDX SBOM (.json) file to examine, relative to the workspace (default: the workspace itself)."),
                params::opt("project_type", "string", "Override dep-scan's project type detection with one type, e.g. rust, go, java, js, python, dotnet, php, docker."),
                params::opt("profile", "string", "dep-scan profile.").one_of(&["appsec", "research", "operational", "threat-modeling", "license-compliance", "generic"]),
                params::opt("min_severity", "string", "Only report advisories at or above this severity (dep-scan downloads its larger extended database for this).").one_of(&["low", "medium", "high", "critical"]),
                params::opt("reachability", "boolean", "Run dep-scan's framework reachability analysis (default true). Set false for a faster manifest-only scan whose findings carry no reachability labels."),
                params::opt("timeout_s", "integer", "Stop the scan after this many seconds (default 900; a first run may download a large vulnerability database).").min(30).max(3600),
            ],
        )
    }

    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        run(ctx, args).await
    }
}

/// One vulnerability from a VDR, normalised for sorting and display.
#[derive(Clone, Debug, PartialEq)]
struct Finding {
    id: String,
    severity: String,
    score: Option<f64>,
    affects: Vec<String>,
    fixed: Option<String>,
    insights: String,
    prioritized: bool,
    reachable: bool,
}

impl Finding {
    fn line(&self) -> String {
        let score = self.score.map_or_else(|| "-".to_string(), |s| format!("{s:.1}"));
        let affects = if self.affects.is_empty() { "-".to_string() } else { one_line(&self.affects.join(", "), 120) };
        let fixed = self.fixed.as_deref().unwrap_or("-");
        let insights = if self.insights.is_empty() { "-" } else { self.insights.as_str() };
        let prio = if self.prioritized { "  PRIORITIZED" } else { "" };
        format!("{}  {} {}  {}  fixed {}  {}{}", self.id, self.severity, score, affects, fixed, insights, prio)
    }
}

fn one_line(s: &str, max: usize) -> String {
    let joined: String = s
        .chars()
        .filter(|c| *c == '\n' || !c.is_control())
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if joined.chars().count() > max {
        format!("{}…", joined.chars().take(max).collect::<String>())
    } else {
        joined
    }
}

fn text<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

fn items<'a>(v: &'a Value, key: &str) -> impl Iterator<Item = &'a Value> {
    v.get(key).and_then(Value::as_array).into_iter().flatten()
}

fn score_of(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// The findings of one CycloneDX VDR document.
fn findings_of(vdr: &Value) -> Vec<Finding> {
    let mut out = Vec::new();
    for vuln in items(vdr, "vulnerabilities") {
        let Some(id) = text(vuln, "id").filter(|s| !s.trim().is_empty()) else { continue };
        // The strongest rating decides the severity and score shown.
        let mut severity: Option<String> = None;
        let mut score: Option<f64> = None;
        for rating in items(vuln, "ratings") {
            let s = rating.get("score").and_then(score_of);
            if s.unwrap_or(f64::MIN) >= score.unwrap_or(f64::MIN) {
                if s.is_some() {
                    score = s;
                }
                severity = text(rating, "severity").map(|x| x.trim().to_ascii_uppercase()).filter(|x| !x.is_empty());
            }
        }
        let mut affects = Vec::new();
        let mut fixed = None;
        for a in items(vuln, "affects") {
            if let Some(r) = text(a, "ref").filter(|s| !s.trim().is_empty()) {
                affects.push(r.trim().to_string());
            }
            if fixed.is_none() {
                fixed = items(a, "versions")
                    .find(|ver| text(ver, "status") == Some("unaffected"))
                    .and_then(|ver| text(ver, "version"))
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty());
            }
        }
        affects.sort();
        affects.dedup();
        let mut prioritized = false;
        let mut insights = String::new();
        for prop in items(vuln, "properties") {
            match (text(prop, "name"), text(prop, "value")) {
                (Some("depscan:prioritized"), Some(v)) => prioritized = v.trim().eq_ignore_ascii_case("true"),
                (Some("depscan:insights"), Some(v)) => {
                    insights = v.lines().map(str::trim).filter(|l| !l.is_empty()).collect::<Vec<_>>().join("; ")
                }
                _ => {}
            }
        }
        let reachable = insights.to_ascii_lowercase().contains("reachable");
        out.push(Finding {
            id: id.trim().to_string(),
            severity: severity.unwrap_or_else(|| "UNKNOWN".to_string()),
            score,
            affects,
            fixed,
            insights,
            prioritized,
            reachable,
        });
    }
    out
}

fn component_count(doc: &Value) -> usize {
    doc.get("components").and_then(Value::as_array).map_or(0, Vec::len)
}

/// Sort key: prioritized, then reachable, then score (unscored last), then id and target.
fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        b.prioritized.cmp(&a.prioritized).then_with(|| b.reachable.cmp(&a.reachable)).then_with(|| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.id.cmp(&b.id))
                .then_with(|| a.affects.cmp(&b.affects))
        })
    });
}

/// The report text for a completed scan, and the one-line outcome for its header.
fn render(target: &str, components: usize, mut findings: Vec<Finding>, artifact_names: &[String]) -> (String, String) {
    // Identical (id, targets) entries across lifecycle/multi-type VDRs are one finding.
    let mut seen = BTreeSet::new();
    findings.retain(|f| seen.insert((f.id.clone(), f.affects.join(","))));
    sort_findings(&mut findings);

    let total = findings.len();
    let prioritized = findings.iter().filter(|f| f.prioritized).count();
    let reachable = findings.iter().filter(|f| f.reachable).count();
    let mut by_severity: BTreeMap<String, usize> = BTreeMap::new();
    for f in &findings {
        *by_severity.entry(f.severity.clone()).or_default() += 1;
    }

    let outcome = if total == 0 { "no vulnerabilities".to_string() } else { format!("{total} vulnerabilities") };
    let mut r = String::new();
    r.push_str(&format!(
        "dep-scan of {target} — {components} components · {total} vulnerabilities · {prioritized} prioritized · {reachable} reachable\n"
    ));
    if total > 0 {
        let order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"];
        let mut parts: Vec<String> = order
            .iter()
            .filter_map(|k| by_severity.get(*k).map(|n| format!("{} {n}", k.to_ascii_lowercase())))
            .collect();
        for (k, n) in &by_severity {
            if !order.contains(&k.as_str()) {
                parts.push(format!("{} {n}", k.to_ascii_lowercase()));
            }
        }
        r.push_str(&format!("Severity: {}\n", parts.join(" · ")));
    }
    if total == 0 {
        r.push_str("No vulnerabilities were reported for the scanned components. That means none are recorded in dep-scan's database for this SBOM, not that the project is safe: check that the component count above covers the dependencies you expected.\n");
    } else {
        let (focus, rest): (Vec<&Finding>, Vec<&Finding>) = findings.iter().partition(|f| f.prioritized || f.reachable);
        let mut shown = 0usize;
        if !focus.is_empty() {
            r.push_str(&format!("Prioritized or reachable findings ({}):\n", focus.len()));
            for f in &focus {
                if shown >= MAX_FINDINGS {
                    break;
                }
                r.push_str(&format!("  {}\n", f.line()));
                shown += 1;
            }
        }
        if !rest.is_empty() && shown < MAX_FINDINGS {
            r.push_str(&format!("Other findings ({}):\n", rest.len()));
            for f in &rest {
                if shown >= MAX_FINDINGS {
                    break;
                }
                r.push_str(&format!("  {}\n", f.line()));
                shown += 1;
            }
        }
        if shown < total {
            r.push_str(&format!("Showing {shown} of {total} findings; the stored VDR has all of them.\n"));
        }
    }
    r.push_str("dep-scan's prioritized/reachable labels are its static reachability analysis of the scanned tree, not execution evidence that the vulnerable code runs in a deployed system.\n");
    if !artifact_names.is_empty() {
        r.push_str(&format!("Report files: {}\n", artifact_names.join(", ")));
    }
    (r, outcome)
}

struct Artifact {
    name: String,
    bytes: Vec<u8>,
}

/// Read the `*.vdr.json` / `*.cdx.json` files of the reports directory. An oversized file is
/// not read; its name is returned so the caller can keep the directory and say where it is.
fn read_artifacts(reports: &std::path::Path) -> (Vec<Artifact>, Vec<Artifact>, Vec<String>) {
    let (mut vdrs, mut boms, mut oversized) = (Vec::new(), Vec::new(), Vec::new());
    let Ok(entries) = std::fs::read_dir(reports) else { return (vdrs, boms, oversized) };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let is_vdr = name.ends_with(".vdr.json");
        let is_bom = !is_vdr && name.ends_with(".cdx.json");
        if !is_vdr && !is_bom {
            continue;
        }
        match std::fs::metadata(&path) {
            Ok(m) if m.is_file() && m.len() > MAX_ARTIFACT_BYTES => oversized.push(name),
            Ok(m) if m.is_file() => match std::fs::read(&path) {
                Ok(bytes) if is_vdr => vdrs.push(Artifact { name, bytes }),
                Ok(bytes) => boms.push(Artifact { name, bytes }),
                Err(_) => oversized.push(name),
            },
            _ => {}
        }
    }
    (vdrs, boms, oversized)
}

/// The shell script for one scan. All variable parts are single-quoted literals (see
/// [`quote`]); flags are built only from the validated tokens of `run`. `-t` comes last
/// because dep-scan's `-t`/`--type` consumes following values.
#[allow(clippy::too_many_arguments)]
fn build_script(
    run_dir: &std::path::Path,
    reports: &std::path::Path,
    target: &std::path::Path,
    bom_mode: bool,
    profile: Option<&str>,
    min_severity: Option<&str>,
    reachability: bool,
    project_type: Option<&str>,
) -> String {
    let mut script = String::new();
    script.push_str(&format!(
        "export HOME={} XDG_CACHE_HOME={} VDB_HOME={} DEPSCAN_TEMP_DIR={} TMPDIR={}\n",
        quote(&run_dir.join("home").to_string_lossy()),
        quote(&run_dir.join("cache").to_string_lossy()),
        quote(&run_dir.join("vdb").to_string_lossy()),
        quote(&run_dir.join("tmp").to_string_lossy()),
        quote(&run_dir.join("tmp").to_string_lossy()),
    ));
    script.push_str(&format!(
        "if ! command -v depscan >/dev/null 2>&1; then printf '%s\\n' '{MISSING_MARKER}'; exit 127; fi\n"
    ));
    script.push_str("depscan --no-banner --no-vuln-table");
    if bom_mode {
        script.push_str(&format!(" --bom {}", quote(&target.to_string_lossy())));
    } else {
        script.push_str(&format!(" --src {}", quote(&target.to_string_lossy())));
    }
    script.push_str(&format!(" --reports-dir {}", quote(&reports.to_string_lossy())));
    if let Some(p) = profile {
        script.push_str(&format!(" --profile {}", quote(p)));
    }
    if let Some(s) = min_severity {
        script.push_str(&format!(" --severity {}", quote(s)));
    }
    if !reachability {
        script.push_str(" --reachability-analyzer off");
    }
    if let Some(t) = project_type {
        script.push_str(&format!(" -t {}", quote(t)));
    }
    script.push('\n');
    script
}

async fn run(ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
    // --- Target -------------------------------------------------------------
    let given = args.get("path").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).unwrap_or(".");
    let resolved = match ctx.sandbox.check_read(&ctx.sandbox.resolve(given)) {
        Ok(p) => p,
        Err(e) => return ToolOutput::error(e),
    };
    let meta = match std::fs::metadata(&resolved) {
        Ok(m) => m,
        Err(e) => {
            return ToolOutput::error(format!(
                "`{given}` ({} ) cannot be scanned: {e}. Give an existing project directory or CycloneDX SBOM file inside the workspace.",
                resolved.display()
            ))
        }
    };
    let bom_mode = if meta.is_file() {
        true
    } else if meta.is_dir() {
        false
    } else {
        return ToolOutput::error(format!(
            "`{given}` is neither a directory nor a regular file, so dep-scan cannot scan it. Give a project directory or a CycloneDX SBOM file."
        ));
    };

    // --- Options ------------------------------------------------------------
    let project_type = match args.get("project_type").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()) {
        Some(t)
            if t.len() <= 32
                && t.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+')) =>
        {
            Some(t.to_string())
        }
        Some(t) => {
            return ToolOutput::error(format!(
                "`{}` is not a usable project type. Give one dep-scan type token such as rust, go, java, js, python, dotnet, php or docker (letters, digits, `-`, `_`, `.`, `+`), or leave it out for auto-detection.",
                one_line(t, 60)
            ))
        }
        None => None,
    };
    let profile = args.get("profile").and_then(Value::as_str).map(str::to_string);
    let min_severity = args.get("min_severity").and_then(Value::as_str).map(str::to_string);
    let reachability = args.get("reachability").and_then(Value::as_bool).unwrap_or(true);
    let timeout_s = args.get("timeout_s").and_then(Value::as_u64).unwrap_or(DEFAULT_TIMEOUT_S).clamp(30, MAX_TIMEOUT_S);

    // --- Run directory (the only place the scan may write) ------------------
    let run_dir = ctx.tmp_dir.join(format!("dep-scan-{:032x}", rand::random::<u128>()));
    let reports = run_dir.join("reports");
    for dir in [&reports, &run_dir.join("home"), &run_dir.join("vdb"), &run_dir.join("tmp"), &run_dir.join("cache")] {
        if let Err(e) = std::fs::create_dir_all(dir) {
            return ToolOutput::error(format!(
                "The scan's report directory could not be prepared under the session temp dir ({e}); nothing was scanned. This is a harness fault."
            ));
        }
    }

    // --- Command --------------------------------------------------------------
    let script = build_script(
        &run_dir,
        &reports,
        &resolved,
        bom_mode,
        profile.as_deref(),
        min_severity.as_deref(),
        reachability,
        project_type.as_deref(),
    );

    let outcome: CommandOutcome = match command_bounded(ctx, script, timeout_s, MAX_TIMEOUT_S).await {
        Ok(o) => o,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&run_dir);
            return ToolOutput::error(e);
        }
    };
    let console = String::from_utf8_lossy(&outcome.bytes).into_owned();

    // --- Artifacts ------------------------------------------------------------
    let (vdrs, boms, oversized) = read_artifacts(&reports);
    let keep_dir = !oversized.is_empty();
    let mut parsed: Vec<Value> = Vec::new();
    let mut unparseable = 0usize;
    for vdr in &vdrs {
        match serde_json::from_slice::<Value>(&vdr.bytes) {
            Ok(v) => parsed.push(v),
            Err(_) => unparseable += 1,
        }
    }

    if parsed.is_empty() {
        if !keep_dir {
            let _ = std::fs::remove_dir_all(&run_dir);
        }
        if console.contains(MISSING_MARKER) || (outcome.ended == crate::proc::Ended::Exit(127) && vdrs.is_empty()) {
            return ToolOutput::error(INSTALL_GUIDANCE);
        }
        let mut out = outcome.into_tool_output("dep-scan");
        out.status = ToolStatus::Error;
        if unparseable > 0 {
            out.more.push(format!(
                "dep-scan left {unparseable} VDR file(s) that are not parseable JSON, so no findings could be read from them."
            ));
        } else {
            out.more.push(
                "dep-scan produced no CycloneDX VDR report, so no findings could be read. Its console output above is the record of what happened."
                    .to_string(),
            );
        }
        if keep_dir {
            out.more.push(format!("Oversized report files were left under {}", reports.display()));
        }
        return out;
    }

    // Parse the SBOMs for the component count (a VDR trims its own component list).
    let mut components = 0usize;
    for bom in &boms {
        if let Ok(v) = serde_json::from_slice::<Value>(&bom.bytes) {
            components += component_count(&v);
        }
    }
    if components == 0 {
        components = parsed.iter().map(component_count).sum();
    }
    let mut findings: Vec<Finding> = parsed.iter().flat_map(findings_of).collect();
    let artifact_names: Vec<String> =
        vdrs.iter().map(|a| a.name.clone()).chain(boms.iter().map(|a| a.name.clone())).collect();
    let (summary, outcome_text) =
        render(&resolved.display().to_string(), components, std::mem::take(&mut findings), &artifact_names);

    let mut out = ToolOutput::ok(outcome_text, Body::Raw(summary.into_bytes()));
    // Store the artifacts so they outlive the temp directory and can be cited.
    if let Some(first) = vdrs.first() {
        match ctx.blobs.put_bytes(&first.bytes) {
            Ok(stored) => {
                out = out.with_meta(META_RAW_BLOB, json!(stored.id.as_str()));
                out = out.with_more(format!("VDR {}: {}", first.name, stored.handle()));
            }
            Err(e) => out = out.with_more(format!("the VDR could not be stored ({e})")),
        }
        for extra in vdrs.iter().skip(1) {
            if let Ok(stored) = ctx.blobs.put_bytes(&extra.bytes) {
                out = out.with_more(format!("VDR {}: {}", extra.name, stored.handle()));
            }
        }
    }
    for bom in &boms {
        if let Ok(stored) = ctx.blobs.put_bytes(&bom.bytes) {
            out = out.with_more(format!("SBOM {}: {}", bom.name, stored.handle()));
        }
    }
    if !outcome.bytes.is_empty() {
        if let Ok(stored) = ctx.blobs.put_bytes(&outcome.bytes) {
            out = out.with_more(format!("scanner console: {}", stored.handle()));
        }
    }
    if unparseable > 0 {
        out = out.with_more(format!("{unparseable} VDR file(s) were not parseable and were left out"));
    }
    if !oversized.is_empty() {
        out = out.with_more(format!(
            "report file(s) over {} MiB were not parsed and were left under {}: {}",
            MAX_ARTIFACT_BYTES / (1024 * 1024),
            reports.display(),
            oversized.join(", ")
        ));
    }
    if !outcome.success() {
        out.status = ToolStatus::Error;
        out = out.with_more(format!(
            "dep-scan did not complete cleanly ({}); the findings above come from the VDR it wrote before that and may be partial",
            outcome.ended.outcome()
        ));
    }
    if oversized.is_empty() {
        let _ = std::fs::remove_dir_all(&run_dir);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{env, TestEnv};
    use loom_core::event::ToolStatus as Status;
    use std::os::unix::fs::PermissionsExt;

    fn vdr_fixture() -> Value {
        json!({
            "bomFormat": "CycloneDX",
            "components": [{"bom-ref": "pkg:npm/a@1.0.0"}, {"bom-ref": "pkg:npm/b@2.0.0"}],
            "vulnerabilities": [
                {
                    "id": "CVE-2024-2222",
                    "ratings": [{"method": "CVSSv31", "severity": "medium", "score": 5.0}],
                    "affects": [{"ref": "pkg:npm/b@2.0.0", "versions": [{"version": "2.0.0", "status": "affected"}]}],
                    "properties": [{"name": "depscan:prioritized", "value": "false"}, {"name": "depscan:insights", "value": "Direct dependency"}]
                },
                {
                    "id": "CVE-2024-1111",
                    "ratings": [{"method": "CVSSv31", "severity": "critical", "score": 9.8}],
                    "affects": [{"ref": "pkg:npm/a@1.0.0", "versions": [{"version": "1.0.0", "status": "affected"}, {"version": "1.0.1", "status": "unaffected"}]}],
                    "properties": [{"name": "depscan:prioritized", "value": "true"}, {"name": "depscan:insights", "value": "Reachable\nDirect dependency"}]
                },
                {
                    "id": "GHSA-xxxx",
                    "ratings": [{"severity": "high", "score": "7.5"}],
                    "affects": [{"ref": "pkg:npm/a@1.0.0"}],
                    "properties": []
                }
            ]
        })
    }

    #[test]
    fn findings_are_sorted_prioritized_first_and_counted() {
        let findings = findings_of(&vdr_fixture());
        let (text, outcome) = render("/ws", 2, findings, &["sbom-js.vdr.json".to_string()]);
        assert_eq!(outcome, "3 vulnerabilities");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "dep-scan of /ws — 2 components · 3 vulnerabilities · 1 prioritized · 1 reachable");
        assert!(
            lines[1].contains("critical 1") && lines[1].contains("high 1") && lines[1].contains("medium 1"),
            "{}",
            lines[1]
        );
        let crit = text.find("CVE-2024-1111").unwrap();
        let high = text.find("GHSA-xxxx").unwrap();
        let med = text.find("CVE-2024-2222").unwrap();
        assert!(crit < high && high < med, "{text}");
        assert!(
            text.contains(
                "CVE-2024-1111  CRITICAL 9.8  pkg:npm/a@1.0.0  fixed 1.0.1  Reachable; Direct dependency  PRIORITIZED"
            ),
            "{text}"
        );
        assert!(text.contains("not execution evidence"), "{text}");
    }

    #[test]
    fn the_script_quotes_paths_and_orders_the_type_flag_last() {
        let run_dir = PathBuf::from("/tmp/run dir");
        let script = build_script(
            &run_dir,
            &run_dir.join("reports"),
            &PathBuf::from("/ws/it's here"),
            false,
            Some("research"),
            Some("high"),
            false,
            Some("rust"),
        );
        assert!(script.contains("depscan --no-banner --no-vuln-table --src '/ws/it'\\''s here'"), "{script}");
        assert!(
            script.contains("--profile 'research' --severity 'high' --reachability-analyzer off -t 'rust'\n"),
            "{script}"
        );
        assert!(script.contains("VDB_HOME='/tmp/run dir/vdb'"), "{script}");
        assert!(script.contains(MISSING_MARKER), "{script}");
        let bom = build_script(
            &run_dir,
            &run_dir.join("reports"),
            &PathBuf::from("/ws/sbom.json"),
            true,
            None,
            None,
            true,
            None,
        );
        assert!(bom.contains("--bom '/ws/sbom.json'") && !bom.contains("--reachability-analyzer"), "{bom}");
    }

    #[test]
    fn duplicates_across_vdrs_are_merged_and_empty_is_not_safe() {
        let one = findings_of(&vdr_fixture());
        let mut both = one.clone();
        both.extend(one);
        let (text, _) = render("/ws", 2, both, &[]);
        assert!(text.contains("3 vulnerabilities"), "{text}");

        let (text, outcome) = render("/ws", 0, Vec::new(), &[]);
        assert_eq!(outcome, "no vulnerabilities");
        assert!(text.contains("not that the project is safe"), "{text}");
    }

    #[test]
    fn findings_are_capped_but_counts_are_not() {
        let vulns: Vec<Value> = (0..60)
            .map(|i| json!({"id": format!("CVE-2024-{i:04}"), "ratings": [{"severity": "low", "score": 1.0}], "affects": [{"ref": format!("pkg:npm/p{i}@1.0.0")}], "properties": []}))
            .collect();
        let vdr = json!({"vulnerabilities": vulns});
        let (text, outcome) = render("/ws", 60, findings_of(&vdr), &[]);
        assert_eq!(outcome, "60 vulnerabilities");
        assert_eq!(text.matches("CVE-2024-").count(), MAX_FINDINGS, "{text}");
        assert!(text.contains("Showing 50 of 60 findings"), "{text}");
    }

    /// Put a fake `depscan` first on the PATH the tool's commands see.
    fn with_fake_depscan(e: &mut TestEnv, script: &str) -> PathBuf {
        let bin = e.ctx.workspace.join("fakebin");
        std::fs::create_dir_all(&bin).unwrap();
        let file = bin.join("depscan");
        std::fs::write(&file, script).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap_or_default());
        let mut vars = (*e.ctx.env).clone();
        vars.insert("PATH".to_string(), path);
        e.ctx.env = std::sync::Arc::new(vars);
        bin
    }

    const FAKE_SCAN: &str = r#"#!/bin/sh
reports=""
prev=""
for a in "$@"; do
  if [ "$prev" = "--reports-dir" ]; then reports="$a"; fi
  prev="$a"
done
mkdir -p "$reports"
cat > "$reports/sbom-rust.cdx.json" <<'JSON'
{"bomFormat":"CycloneDX","components":[{"bom-ref":"pkg:cargo/time@0.1.44"}]}
JSON
cat > "$reports/sbom-rust.vdr.json" <<'JSON'
{"bomFormat":"CycloneDX","vulnerabilities":[{"id":"RUSTSEC-2020-0071","ratings":[{"severity":"high","score":7.5}],"affects":[{"ref":"pkg:cargo/time@0.1.44","versions":[{"version":"0.1.44","status":"affected"},{"version":"0.2.23","status":"unaffected"}]}],"properties":[{"name":"depscan:prioritized","value":"true"},{"name":"depscan:insights","value":"Reachable"}]}]}
JSON
echo "fake depscan ran: $*"
"#;

    #[tokio::test]
    async fn a_fake_depscan_scan_is_parsed_and_its_artifacts_stored() {
        let mut e = env();
        with_fake_depscan(&mut e, FAKE_SCAN);
        std::fs::write(e.ctx.workspace.join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
        let r = e.call("dep_scan", json!({})).await;
        assert_eq!(r.status, Status::Ok, "{}", r.text);
        assert!(r.text.contains("1 vulnerabilities"), "{}", r.text);
        let stored = e.stored(&r);
        assert!(
            stored.contains("RUSTSEC-2020-0071  HIGH 7.5  pkg:cargo/time@0.1.44  fixed 0.2.23  Reachable  PRIORITIZED"),
            "{stored}"
        );
        assert!(stored.contains("1 components"), "{stored}");
        // The VDR bytes are the raw blob beside the summary, and the SBOM is named by handle.
        let raw_id = r.meta.get(META_RAW_BLOB).and_then(Value::as_str).unwrap();
        let raw = e.ctx.blobs.read_all(&e.ctx.blobs.resolve(raw_id).unwrap()).unwrap();
        assert!(String::from_utf8(raw).unwrap().contains("RUSTSEC-2020-0071"));
        assert!(r.text.contains("SBOM sbom-rust.cdx.json: out:"), "{}", r.text);
        assert!(r.text.contains("scanner console: out:"), "{}", r.text);
    }

    #[tokio::test]
    async fn an_sbom_file_is_examined_instead_of_scanned_as_a_directory() {
        let mut e = env();
        with_fake_depscan(&mut e, FAKE_SCAN);
        std::fs::write(e.ctx.workspace.join("sbom.json"), "{\"bomFormat\":\"CycloneDX\",\"components\":[]}").unwrap();
        let r = e.call("dep_scan", json!({"path": "sbom.json", "reachability": false, "timeout_s": 60})).await;
        assert_eq!(r.status, Status::Ok, "{}", r.text);
        assert!(e.stored(&r).contains("RUSTSEC-2020-0071"), "{}", r.text);
    }

    #[tokio::test]
    async fn a_missing_depscan_is_install_guidance_not_an_empty_scan() {
        let mut e = env();
        // A PATH with nothing on it: no depscan anywhere.
        let empty = e.ctx.workspace.join("emptybin");
        std::fs::create_dir_all(&empty).unwrap();
        let mut vars = (*e.ctx.env).clone();
        vars.insert("PATH".to_string(), empty.to_string_lossy().into_owned());
        e.ctx.env = std::sync::Arc::new(vars);
        let r = e.call("dep_scan", json!({})).await;
        assert_eq!(r.status, Status::Error, "{}", r.text);
        assert!(r.text.contains("not installed") && r.text.contains("brew"), "{}", r.text);
        assert!(!r.text.contains("no vulnerabilities"), "{}", r.text);
    }

    #[tokio::test]
    async fn bad_targets_and_project_types_are_refused_before_anything_runs() {
        let mut e = env();
        with_fake_depscan(&mut e, FAKE_SCAN);
        let r = e.call("dep_scan", json!({"path": "no-such-place"})).await;
        assert_eq!(r.status, Status::Error, "{}", r.text);
        assert!(r.text.contains("cannot be scanned"), "{}", r.text);
        let r = e.call("dep_scan", json!({"project_type": "rust; rm -rf /"})).await;
        assert_eq!(r.status, Status::Error, "{}", r.text);
        assert!(r.text.contains("not a usable project type"), "{}", r.text);
    }

    #[tokio::test]
    async fn a_scan_without_a_vdr_is_an_error_with_the_console() {
        let mut e = env();
        with_fake_depscan(&mut e, "#!/bin/sh\necho 'cdxgen blew up'\nexit 3\n");
        let r = e.call("dep_scan", json!({})).await;
        assert_eq!(r.status, Status::Error, "{}", r.text);
        assert!(r.text.contains("cdxgen blew up"), "{}", r.text);
        assert!(r.text.contains("no CycloneDX VDR"), "{}", r.text);
    }
}
