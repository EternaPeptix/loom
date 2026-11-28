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
//!   way and named in the result facts. The first VDR's id is `meta[META_RAW_BLOB]`; the id of
//!   every other blob a fact names (further VDRs, the SBOMs, the console) is in
//!   `meta[META_ALSO_STORED]`, so that they count among the outputs of the session's mission and
//!   `out_read` opens them (`outputs`). The reports directory is writable by the session's commands, so
//!   each report file is opened through the sandbox read check (a regular file only, judged by the real
//!   path of what was opened): a link in it to what the session cannot read (the ferret home, a credential
//!   store, an unreadable path) is refused and named in the result's facts, never stored; a link to a
//!   file the session can read still works. At most [`MAX_FINDINGS`] finding lines are rendered;
//!   the counts always cover every parsed finding.
//! - dep-scan's `depscan:prioritized` / `depscan:insights` labels are its own static
//!   (reachability) analysis. The summary says so: they are scanner data about the scanned
//!   tree, not execution evidence that vulnerable code runs in a deployed system. The harness
//!   enforces it: every result this tool's `run` returns, whatever its status, carries
//!   `meta[META_EVIDENCE_GRADE] = "analysis"`, so a quote of a scan is recorded as static evidence
//!   and never meets a rule that asks for a run (see `ferret_core::event::EvidenceGrade`), although
//!   the tool is of class `Exec`. A call refused before `run` (argument check, a cap) stores no
//!   output, and `EvidenceGrade::of_tool_result` grades any `dep_scan` result without the key as
//!   analysis too.
//! - Status is `Ok` for a completed scan whether or not it found anything (a scan result is
//!   an observation, like an HTTP error status in `web_fetch`); `Error` when the scanner did
//!   not complete or produced no parseable VDR, `Interrupted`/`Timeout` when it was stopped.
//!
//! Tests required: VDR parsing/sorting/counts and the no-findings case as pure functions; a
//! fake `depscan` on `PATH` that writes an SBOM+VDR (end to end, stored blobs, raw meta);
//! a missing `depscan` (install guidance, nothing invented); a bad target; a bad project type; a report file that is a link to a file in the ferret home or a
//! credential store is refused and named and its bytes are in no stored blob, while a link to a readable file is read; the result
//! of a completed scan and of a failed one are both graded `analysis`.

use crate::binary::{command_bounded, quote, CommandOutcome};
use crate::{params, Body, Tool, ToolCtx, ToolOutput};
use async_trait::async_trait;
use ferret_core::admit::normalize;
use ferret_core::event::{ToolClass, ToolSpec, ToolStatus, META_ALSO_STORED, META_EVIDENCE_GRADE, META_RAW_BLOB};
use ferret_core::{BlobRef, BlobStore};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

/// Most finding lines one result renders (the counts still cover all of them).
pub const MAX_FINDINGS: usize = 50;
/// Largest VDR/SBOM file parsed and stored whole; a larger one is left in place and named.
const MAX_ARTIFACT_BYTES: u64 = 32 * 1024 * 1024;
/// Maximum number of VDR/SBOM files parsed and stored from one scan's reports directory.
const MAX_ARTIFACT_FILES: usize = 32;
/// Maximum cumulative byte size across all VDR/SBOM files parsed and stored from one scan.
const MAX_ARTIFACTS_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
/// Printed by the wrapper script when no `depscan` is on `PATH`.
const MISSING_MARKER: &str = "FERRET_DEPSCAN_NOT_INSTALLED";
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
            "Scan a project's dependencies with OWASP dep-scan: generate a CycloneDX SBOM (via cdxgen) for a directory, or examine an existing CycloneDX SBOM file, and report known-vulnerable components prioritized by dep-scan's own reachability analysis. Returns counts and the top findings; the full VDR and SBOM are stored so you can page them with `read` and quote them as evidence. Requires the `depscan` command installed on the host (it is never installed for you); a first scan downloads its vulnerability database through the session's network proxy, so that may need scope and can take minutes. dep-scan's prioritized/reachable labels are static scanner verdicts, not proof that vulnerable code executes.",
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
        run(ctx, args).await.with_meta(META_EVIDENCE_GRADE, json!("analysis"))
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

/// Normalize inline display text so rendered findings and metadata never carry ANSI escapes or raw controls.
fn clean_text(s: &str) -> String {
    let normalized = normalize(s.as_bytes());
    if normalized.changed {
        normalized.text
    } else {
        s.to_string()
    }
}

fn one_line(s: &str, max: usize) -> String {
    let cleaned = clean_text(s);
    let joined: String = cleaned
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
                severity = text(rating, "severity")
                    .map(|x| clean_text(x.trim()).to_ascii_uppercase())
                    .filter(|x| !x.is_empty());
            }
        }
        let mut affects = Vec::new();
        let mut fixed = None;
        for a in items(vuln, "affects") {
            if let Some(r) = text(a, "ref").filter(|s| !s.trim().is_empty()) {
                affects.push(clean_text(r.trim()));
            }
            if fixed.is_none() {
                fixed = items(a, "versions")
                    .find(|ver| text(ver, "status") == Some("unaffected"))
                    .and_then(|ver| text(ver, "version"))
                    .map(|v| clean_text(v.trim()))
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
                    insights =
                        clean_text(v).lines().map(str::trim).filter(|l| !l.is_empty()).collect::<Vec<_>>().join("; ")
                }
                _ => {}
            }
        }
        let reachable = insights.to_ascii_lowercase().contains("reachable");
        out.push(Finding {
            id: clean_text(id.trim()),
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

/// What [`read_artifacts`] found in the reports directory.
#[derive(Default)]
struct Artifacts {
    vdrs: Vec<Artifact>,
    boms: Vec<Artifact>,
    /// Names of files over the per-file size limit, which are not read.
    oversized: Vec<String>,
    /// Names of files skipped because aggregate count or cumulative-byte limits were reached.
    skipped: Vec<String>,
    /// A sentence for each report file that was not read because the session may not read what it is.
    refused: Vec<String>,
}

/// Read the `*.vdr.json` / `*.cdx.json` files of the reports directory. The directory is writable by
/// the scan (and by any command of the session), so each file is opened as the file tools open one: only
/// a regular file, and only when `readable` accepts the real path of what was opened. A link to something
/// the session cannot read is refused and named, never stored. Files exceeding per-file or aggregate
/// limits are not read; their names are returned so the caller can keep the directory and report them.
fn read_artifacts(reports: &std::path::Path, readable: crate::files::Readable<'_>) -> Artifacts {
    read_artifacts_bounded(reports, readable, MAX_ARTIFACT_BYTES, MAX_ARTIFACT_FILES, MAX_ARTIFACTS_TOTAL_BYTES)
}

fn read_artifacts_bounded(
    reports: &std::path::Path,
    readable: crate::files::Readable<'_>,
    max_file_bytes: u64,
    max_files: usize,
    max_total_bytes: u64,
) -> Artifacts {
    use crate::files::{open_readable, NotOpened};
    use std::io::Read as _;
    let mut found = Artifacts::default();
    let Ok(entries) = std::fs::read_dir(reports) else { return found };
    let mut paths: Vec<(bool, String, PathBuf)> = entries
        .flatten()
        .filter_map(|e| {
            let path = e.path();
            let name = path.file_name()?.to_string_lossy().into_owned();
            let is_vdr = name.ends_with(".vdr.json");
            let is_bom = !is_vdr && name.ends_with(".cdx.json");
            (is_vdr || is_bom).then_some((!is_vdr, name, path))
        })
        .collect();
    // Read VDR reports before SBOMs so excess SBOMs cannot crowd out primary VDR findings.
    paths.sort();

    let mut total_bytes = 0u64;
    for (is_bom, name, path) in paths {
        let is_vdr = !is_bom;
        if found.vdrs.len() + found.boms.len() >= max_files {
            found.skipped.push(name);
            continue;
        }
        let remaining = max_total_bytes.saturating_sub(total_bytes);
        if remaining == 0 {
            found.skipped.push(name);
            continue;
        }
        let (file, meta) = match open_readable(&path, readable) {
            Ok(opened) => opened,
            Err(NotOpened::Denied(sentence)) => {
                found.refused.push(format!("report file {name} was not read: {sentence}"));
                continue;
            }
            Err(NotOpened::NotRegular(kind)) => {
                found.refused.push(format!(
                    "report file {name} was not read: it is {}, not a regular file",
                    crate::files::describe_type(&kind)
                ));
                continue;
            }
            Err(NotOpened::Io(_)) => continue,
        };
        if meta.len() > max_file_bytes {
            found.oversized.push(name);
            continue;
        }
        if meta.len() > remaining {
            found.skipped.push(name);
            continue;
        }
        let cap = max_file_bytes.min(remaining);
        // A file that grew after the check is not read whole.
        let mut bytes = Vec::new();
        match file.take(cap.saturating_add(1)).read_to_end(&mut bytes) {
            Ok(_) if bytes.len() as u64 > max_file_bytes => found.oversized.push(name),
            Ok(_) if bytes.len() as u64 > remaining => found.skipped.push(name),
            Ok(_) => {
                total_bytes = total_bytes.saturating_add(bytes.len() as u64);
                if is_vdr {
                    found.vdrs.push(Artifact { name, bytes });
                } else {
                    found.boms.push(Artifact { name, bytes });
                }
            }
            Err(_) => found.oversized.push(name),
        }
    }
    found
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

fn format_name_list(names: &[String], max_names: usize) -> String {
    let shown: Vec<String> = names.iter().take(max_names).map(|n| clean_text(n)).collect();
    if names.len() > max_names {
        format!("{}, and {} more", shown.join(", "), names.len() - max_names)
    } else {
        shown.join(", ")
    }
}

fn skipped_fact(skipped: &[String], reports: &std::path::Path) -> String {
    format!(
        "{} report file(s) were skipped under the artifact limit ({} files / {} MiB total) and were left under {}: {}",
        skipped.len(),
        MAX_ARTIFACT_FILES,
        MAX_ARTIFACTS_TOTAL_BYTES / (1024 * 1024),
        reports.display(),
        format_name_list(skipped, 16),
    )
}

fn put_normalized(blobs: &BlobStore, raw: &[u8]) -> std::io::Result<(BlobRef, bool)> {
    let normalized = normalize(raw);
    let stored = blobs.put_bytes(normalized.text.as_bytes())?;
    Ok((stored, normalized.changed))
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
    let Artifacts { vdrs, boms, oversized, skipped, refused } =
        read_artifacts(&reports, &|real| ctx.sandbox.check_read(real).map(|_| ()));
    let keep_dir = !oversized.is_empty() || !skipped.is_empty();
    let mut parsed_vdrs = 0usize;
    let mut unparseable = 0usize;
    let mut vdr_components = 0usize;
    let mut findings: Vec<Finding> = Vec::new();
    for vdr in &vdrs {
        match serde_json::from_slice::<Value>(&vdr.bytes) {
            Ok(v) => {
                parsed_vdrs += 1;
                vdr_components = vdr_components.saturating_add(component_count(&v));
                findings.extend(findings_of(&v));
            }
            Err(_) => unparseable += 1,
        }
    }

    if parsed_vdrs == 0 {
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
        if !oversized.is_empty() {
            out.more.push(format!("Oversized report files were left under {}", reports.display()));
        }
        if !skipped.is_empty() {
            out.more.push(skipped_fact(&skipped, &reports));
        }
        out.more.extend(refused);
        return out;
    }

    // Parse the SBOMs for the component count (a VDR trims its own component list).
    let mut components = 0usize;
    for bom in &boms {
        if let Ok(v) = serde_json::from_slice::<Value>(&bom.bytes) {
            components = components.saturating_add(component_count(&v));
        }
    }
    if components == 0 {
        components = vdr_components;
    }
    let artifact_names: Vec<String> = vdrs.iter().chain(boms.iter()).map(|a| clean_text(&a.name)).collect();
    let (summary, outcome_text) = render(
        &clean_text(&resolved.display().to_string()),
        components,
        std::mem::take(&mut findings),
        &artifact_names,
    );

    let mut out = ToolOutput::ok(outcome_text, Body::Raw(summary.into_bytes()));
    // The ids of every further blob a fact names, so they count as outputs of the mission.
    let mut also: Vec<String> = Vec::new();
    // Store the normalized artifacts so they outlive the temp directory and can be cited safely.
    if let Some(first) = vdrs.first() {
        match put_normalized(&ctx.blobs, &first.bytes) {
            Ok((stored, changed)) => {
                out = out.with_meta(META_RAW_BLOB, json!(stored.id.as_str()));
                let note = if changed { " (normalized)" } else { "" };
                out = out.with_more(format!("VDR {}: {}{note}", clean_text(&first.name), stored.handle()));
            }
            Err(e) => out = out.with_more(format!("the VDR could not be stored ({e})")),
        }
        for extra in vdrs.iter().skip(1) {
            if let Ok((stored, changed)) = put_normalized(&ctx.blobs, &extra.bytes) {
                also.push(stored.id.as_str().to_string());
                let note = if changed { " (normalized)" } else { "" };
                out = out.with_more(format!("VDR {}: {}{note}", clean_text(&extra.name), stored.handle()));
            }
        }
    }
    for bom in &boms {
        if let Ok((stored, changed)) = put_normalized(&ctx.blobs, &bom.bytes) {
            also.push(stored.id.as_str().to_string());
            let note = if changed { " (normalized)" } else { "" };
            out = out.with_more(format!("SBOM {}: {}{note}", clean_text(&bom.name), stored.handle()));
        }
    }
    if !outcome.bytes.is_empty() {
        if let Ok((stored, changed)) = put_normalized(&ctx.blobs, &outcome.bytes) {
            also.push(stored.id.as_str().to_string());
            let note = if changed { " (normalized)" } else { "" };
            out = out.with_more(format!("scanner console: {}{note}", stored.handle()));
        }
    }
    if !also.is_empty() {
        out = out.with_meta(META_ALSO_STORED, json!(also));
    }
    if unparseable > 0 {
        out = out.with_more(format!("{unparseable} VDR file(s) were not parseable and were left out"));
    }
    for sentence in refused {
        out = out.with_more(sentence);
    }
    if !oversized.is_empty() {
        out = out.with_more(format!(
            "report file(s) over {} MiB were not parsed and were left under {}: {}",
            MAX_ARTIFACT_BYTES / (1024 * 1024),
            reports.display(),
            format_name_list(&oversized, 16)
        ));
    }
    if !skipped.is_empty() {
        out = out.with_more(skipped_fact(&skipped, &reports));
    }
    if !outcome.success() {
        out.status = ToolStatus::Error;
        out = out.with_more(format!(
            "dep-scan did not complete cleanly ({}); the findings above come from the VDR it wrote before that and may be partial",
            outcome.ended.outcome()
        ));
    }
    if !keep_dir {
        let _ = std::fs::remove_dir_all(&run_dir);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{env, TestEnv};
    use ferret_core::event::ToolStatus as Status;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

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
        // Every other blob a fact names is in META_ALSO_STORED, as full ids that the store holds.
        let also: Vec<&str> =
            r.meta.get(META_ALSO_STORED).and_then(Value::as_array).unwrap().iter().filter_map(Value::as_str).collect();
        assert_eq!(also.len(), 2, "{also:?}");
        for id in &also {
            assert_eq!(id.len(), 64);
            assert!(e.ctx.blobs.resolve(id).is_ok());
            assert!(r.text.contains(&format!("out:{}", &id[..16])), "{}", r.text);
        }
        assert!(!also.contains(&raw_id));
    }

    /// Every byte stored under the ferret home's blob directory.
    fn all_stored_bytes(e: &TestEnv) -> Vec<u8> {
        let mut all = Vec::new();
        let mut dirs = vec![e.dir.path().join("home/blobs")];
        while let Some(d) = dirs.pop() {
            for entry in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                if entry.path().is_dir() {
                    dirs.push(entry.path());
                } else {
                    all.extend(std::fs::read(entry.path()).unwrap_or_default());
                }
            }
        }
        all
    }

    /// A fake `depscan` that writes a valid VDR and then plants one report link per `(name, target)`.
    fn planting_scan(links: &[(&str, &Path)]) -> String {
        let mut script = FAKE_SCAN.replace("echo \"fake depscan ran: $*\"\n", "");
        for (name, target) in links {
            script.push_str(&format!("ln -s '{}' \"$reports/{name}\"\n", target.display()));
        }
        script
    }

    #[tokio::test]
    async fn a_report_file_that_links_to_the_ferret_home_or_a_credential_is_refused_and_not_stored() {
        let mut e = env();
        let root = e.dir.path().canonicalize().unwrap();
        let home = root.join("home");
        std::fs::create_dir_all(home.join("sessions/other")).unwrap();
        std::fs::write(home.join("sessions/other/log.jsonl"), "OTHER-LOG-SECRET").unwrap();
        std::fs::write(home.join("token"), "T0KEN-SECRET").unwrap();
        let readable = e.ctx.workspace.join("readable.txt");
        std::fs::write(&readable, "READABLE-FILE-BYTES").unwrap();
        let (log, token) = (home.join("sessions/other/log.jsonl"), home.join("token"));
        with_fake_depscan(
            &mut e,
            &planting_scan(&[("x.cdx.json", &log), ("y.cdx.json", &token), ("z.cdx.json", &readable)]),
        );
        std::fs::write(e.ctx.workspace.join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
        let r = e.call("dep_scan", json!({})).await;
        assert_eq!(r.status, Status::Ok, "{}", r.text);
        assert!(r.text.contains("x.cdx.json was not read") && r.text.contains("y.cdx.json was not read"), "{}", r.text);
        assert!(r.text.contains("ferret home"), "{}", r.text);
        assert!(!r.text.contains("SBOM x.cdx.json") && !r.text.contains("SBOM y.cdx.json"), "{}", r.text);
        // The control: a link to a file the session can read is stored.
        assert!(r.text.contains("SBOM z.cdx.json: out:"), "{}", r.text);
        let stored = String::from_utf8_lossy(&all_stored_bytes(&e)).into_owned();
        assert!(stored.contains("READABLE-FILE-BYTES"), "the control was not stored");
        assert!(!stored.contains("OTHER-LOG-SECRET") && !stored.contains("T0KEN-SECRET"), "a refused file was stored");
        assert!(!r.text.contains("OTHER-LOG-SECRET") && !r.text.contains("T0KEN-SECRET"), "{}", r.text);
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

    fn grade(r: &ferret_core::event::ToolResult) -> Option<&str> {
        r.meta.get(META_EVIDENCE_GRADE).and_then(Value::as_str)
    }

    #[tokio::test]
    async fn every_dep_scan_result_is_graded_analysis() {
        let mut e = env();
        // A missing depscan.
        let empty = e.ctx.workspace.join("emptybin");
        std::fs::create_dir_all(&empty).unwrap();
        let mut vars = (*e.ctx.env).clone();
        vars.insert("PATH".to_string(), empty.to_string_lossy().into_owned());
        e.ctx.env = std::sync::Arc::new(vars);
        let r = e.call("dep_scan", json!({})).await;
        assert_eq!(r.status, Status::Error, "{}", r.text);
        assert_eq!(grade(&r), Some("analysis"));
        // A completed scan, a refused target and a failed scan.
        let mut e = env();
        with_fake_depscan(&mut e, FAKE_SCAN);
        std::fs::write(e.ctx.workspace.join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
        let r = e.call("dep_scan", json!({})).await;
        assert_eq!(r.status, Status::Ok, "{}", r.text);
        assert_eq!(grade(&r), Some("analysis"));
        let r = e.call("dep_scan", json!({"path": "no-such-place"})).await;
        assert_eq!(r.status, Status::Error, "{}", r.text);
        assert_eq!(grade(&r), Some("analysis"));
        let mut e = env();
        with_fake_depscan(&mut e, "#!/bin/sh\nexit 3\n");
        let r = e.call("dep_scan", json!({})).await;
        assert_eq!(r.status, Status::Error, "{}", r.text);
        assert_eq!(grade(&r), Some("analysis"));
    }

    #[tokio::test]
    async fn aggregate_artifact_file_count_and_total_byte_caps_bound_reads() {
        // Direct unit check on bounded aggregate reading: VDRs precede SBOMs and excess files are skipped unread.
        let dir = tempfile::tempdir().unwrap();
        let reports = dir.path();
        std::fs::write(reports.join("z.vdr.json"), vec![b'a'; 50]).unwrap();
        std::fs::write(reports.join("a.cdx.json"), vec![b'b'; 50]).unwrap();
        std::fs::write(reports.join("b.cdx.json"), vec![b'c'; 50]).unwrap();
        let a = read_artifacts_bounded(reports, &|_| Ok(()), 100, 10, 110);
        assert_eq!(a.vdrs.len(), 1);
        assert_eq!(a.vdrs[0].name, "z.vdr.json");
        assert_eq!(a.boms.len(), 1);
        assert_eq!(a.boms[0].name, "a.cdx.json");
        assert_eq!(a.skipped, vec!["b.cdx.json"]);

        // File-count cap end-to-end: 1 VDR + 34 SBOMs (35 total > MAX_ARTIFACT_FILES = 32).
        let mut e = env();
        let fixtures = e.ctx.workspace.join("fixtures-count");
        std::fs::create_dir_all(&fixtures).unwrap();
        std::fs::write(
            fixtures.join("00-main.vdr.json"),
            r#"{"bomFormat":"CycloneDX","vulnerabilities":[{"id":"CVE-2024-9001","ratings":[{"severity":"high","score":7.0}],"affects":[{"ref":"pkg:cargo/x@1.0.0"}]}]}"#,
        )
        .unwrap();
        for i in 1..=34 {
            std::fs::write(
                fixtures.join(format!("{i:02}.cdx.json")),
                r#"{"bomFormat":"CycloneDX","components":[{"bom-ref":"pkg:cargo/x@1.0.0"}]}"#,
            )
            .unwrap();
        }
        let script = format!(
            "#!/bin/sh\nreports=\"\"\nprev=\"\"\nfor a in \"$@\"; do\n  if [ \"$prev\" = \"--reports-dir\" ]; then reports=\"$a\"; fi\n  prev=\"$a\"\ndone\ncp '{}'/* \"$reports/\"\n",
            fixtures.display()
        );
        with_fake_depscan(&mut e, &script);
        let r = e.call("dep_scan", json!({})).await;
        assert_eq!(r.status, Status::Ok, "{}", r.text);
        assert!(r.text.contains("skipped under the artifact limit"), "{}", r.text);
        assert!(r.text.contains("3 report file(s)"), "{}", r.text);
        for skipped in ["32.cdx.json", "33.cdx.json", "34.cdx.json"] {
            assert!(r.text.contains(skipped), "missing {skipped} in {}", r.text);
            assert!(!r.text.contains(&format!("SBOM {skipped}: out:")), "{}", r.text);
        }
        let also: Vec<&str> =
            r.meta.get(META_ALSO_STORED).and_then(Value::as_array).unwrap().iter().filter_map(Value::as_str).collect();
        // 31 stored SBOMs (with 1 VDR = 32 MAX_ARTIFACT_FILES); console output was empty so not stored.
        assert_eq!(also.len(), MAX_ARTIFACT_FILES - 1, "{also:?}");

        // Cumulative total-byte cap end-to-end: 3 x 25 MiB VDRs (each < 32 MiB, total 75 MiB > 64 MiB).
        let mut e = env();
        let fixtures = e.ctx.workspace.join("fixtures-bytes");
        std::fs::create_dir_all(&fixtures).unwrap();
        let pad = " ".repeat(25 * 1024 * 1024);
        for (name, cve) in
            [("v1.vdr.json", "CVE-2024-0001"), ("v2.vdr.json", "CVE-2024-0002"), ("v3.vdr.json", "CVE-2024-0003")]
        {
            let content = format!(
                "{pad}{{\"bomFormat\":\"CycloneDX\",\"vulnerabilities\":[{{\"id\":\"{cve}\",\"ratings\":[{{\"severity\":\"low\",\"score\":1.0}}]}}]}}"
            );
            std::fs::write(fixtures.join(name), content).unwrap();
        }
        let script = format!(
            "#!/bin/sh\nreports=\"\"\nprev=\"\"\nfor a in \"$@\"; do\n  if [ \"$prev\" = \"--reports-dir\" ]; then reports=\"$a\"; fi\n  prev=\"$a\"\ndone\ncp '{}'/* \"$reports/\"\n",
            fixtures.display()
        );
        with_fake_depscan(&mut e, &script);
        let r = e.call("dep_scan", json!({})).await;
        assert_eq!(r.status, Status::Ok, "{}", r.text);
        let stored = e.stored(&r);
        assert!(stored.contains("CVE-2024-0001") && stored.contains("CVE-2024-0002"), "{stored}");
        assert!(!stored.contains("CVE-2024-0003"), "v3 should have been skipped unread: {stored}");
        assert!(r.text.contains("v3.vdr.json") && r.text.contains("skipped under the artifact limit"), "{}", r.text);
    }

    #[tokio::test]
    async fn stored_artifacts_normalize_control_and_ansi_bytes() {
        let mut e = env();
        let fixtures = e.ctx.workspace.join("fixtures-norm");
        std::fs::create_dir_all(&fixtures).unwrap();
        std::fs::write(
            fixtures.join("a.vdr.json"),
            b"{\r\n\"bomFormat\":\"CycloneDX\",\"vulnerabilities\":[{\"id\":\"CVE-2024-7777\x7f\",\"ratings\":[{\"severity\":\"high\",\"score\":8.0}],\"affects\":[{\"ref\":\"pkg:npm/a@1.0.0\"}],\"properties\":[{\"name\":\"depscan:insights\",\"value\":\"\\u001b[31mReachable\\u001b[0m\"}]}]}\r\n",
        )
        .unwrap();
        std::fs::write(fixtures.join("b.vdr.json"), b"not-json \x1b[31mBAD-VDR\x1b[0m\njunk\rKEEP-VDR\x07\n").unwrap();
        std::fs::write(
            fixtures.join("sbom.cdx.json"),
            b"{\"bomFormat\":\"CycloneDX\",\"components\":[{\"bom-ref\":\"pkg:npm/padded-package-name-over-100-bytes@1.0.0\"}]}\n\x1b[32mSBOM-OK\x1b[0m\nold\rNEW-SBOM\x00\n",
        )
        .unwrap();
        let script = format!(
            "#!/bin/sh\nreports=\"\"\nprev=\"\"\nfor a in \"$@\"; do\n  if [ \"$prev\" = \"--reports-dir\" ]; then reports=\"$a\"; fi\n  prev=\"$a\"\ndone\ncp '{}'/* \"$reports/\"\nprintf '\\033[33mconsole-ok\\033[0m\\n'\n",
            fixtures.display()
        );
        with_fake_depscan(&mut e, &script);
        let r = e.call("dep_scan", json!({})).await;
        assert_eq!(r.status, Status::Ok, "{}", r.text);
        assert!(r.text.contains("Reachable") && !r.text.contains('\x1b'), "{}", r.text);

        // No stored blob payload (excluding binary `.idx` line-offset indexes) may hold raw ANSI ESC, NUL, BEL, DEL, or CR bytes.
        let mut stored_all = Vec::new();
        let mut dirs = vec![e.dir.path().join("home/blobs")];
        while let Some(d) = dirs.pop() {
            for entry in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                let p = entry.path();
                if p.is_dir() {
                    dirs.push(p);
                } else if p.extension().and_then(|ext| ext.to_str()) != Some("idx") {
                    stored_all.extend(std::fs::read(&p).unwrap_or_default());
                }
            }
        }
        assert!(!stored_all.is_empty());
        for forbidden in [0x1bu8, 0x00, 0x07, 0x7f, b'\r'] {
            assert!(!stored_all.contains(&forbidden), "found unnormalized byte {forbidden:#04x} in blob store");
        }

        // First VDR stays in META_RAW_BLOB (not overwritten by Body::Raw), normalized, and readable via out_read.
        let raw_id = r.meta.get(META_RAW_BLOB).and_then(Value::as_str).unwrap();
        let vdr_read = e.call("out_read", json!({"handle": format!("out:{}", &raw_id[..16])})).await;
        assert_eq!(vdr_read.status, Status::Ok, "{}", vdr_read.text);
        assert!(vdr_read.text.contains("CVE-2024-7777\\x7f"), "{}", vdr_read.text);

        let also: Vec<&str> =
            r.meta.get(META_ALSO_STORED).and_then(Value::as_array).unwrap().iter().filter_map(Value::as_str).collect();
        assert_eq!(also.len(), 3, "{also:?}");
        let extra_vdr = e.call("out_read", json!({"handle": format!("out:{}", &also[0][..16])})).await;
        assert!(extra_vdr.text.contains("BAD-VDR") && extra_vdr.text.contains("KEEP-VDR\\x07"), "{}", extra_vdr.text);
        assert!(!extra_vdr.text.contains("junk") && !extra_vdr.text.contains('\x1b'), "{}", extra_vdr.text);

        let sbom_read = e.call("out_read", json!({"handle": format!("out:{}", &also[1][..16])})).await;
        assert!(sbom_read.text.contains("SBOM-OK") && sbom_read.text.contains("NEW-SBOM\\x00"), "{}", sbom_read.text);
        assert!(!sbom_read.text.contains("old") && !sbom_read.text.contains('\x1b'), "{}", sbom_read.text);
        let sbom_grep =
            e.call("out_grep", json!({"handle": format!("out:{}", &also[1][..16]), "pattern": "NEW-SBOM"})).await;
        assert!(sbom_grep.text.contains("NEW-SBOM\\x00") && !sbom_grep.text.contains('\x1b'), "{}", sbom_grep.text);

        let console_read = e.call("out_read", json!({"handle": format!("out:{}", &also[2][..16])})).await;
        assert!(
            console_read.text.contains("console-ok") && !console_read.text.contains('\x1b'),
            "{}",
            console_read.text
        );
    }
}
