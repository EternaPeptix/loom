//! Security-data lookup tools: `cve_lookup`, `cve_search`, `advisory_lookup`.
//!
//! These give a vulnerability-research session first-class, cited access to the public CVE and
//! advisory record, so a claim about a CVE rests on a retrieved, stored, attestable record rather
//! than the model's memory. Each result is admitted and stored like any tool output, so `evidence`
//! can quote it verbatim.
//!
//! CONTRACT (the body of each `run` is a placeholder for the implementer; every `spec()` is fixed).
//! Follow `web.rs` for how a native tool reaches the network: build one `reqwest::Client` with
//! [`build_client`] — redirects off, `.no_proxy()`, and the session's egress proxy from `ctx.env`
//! (`HTTPS_PROXY`/`https_proxy`/`HTTP_PROXY`/`http_proxy`) when present, so every request passes the
//! proxy's allowlist and is logged as a `net` decision. Read nothing from the process environment.
//! Timeout each whole exchange at `ctx.cfg.web_fetch_timeout_s`; `ctx.cancel` aborts (status
//! `Interrupted`). A `407`/`403` carrying header `X-Loom-Proxy: 1` is `denied` with the proxy body
//! (the host is not on the daemon's network allowlist — the message says so and names the host).
//!
//! The daemon must allow these hosts (config `[network]` allowlist) or every call is denied:
//! `services.nvd.nist.gov` (NVD), `api.first.org` (EPSS), `api.osv.dev` (OSV). The tools never
//! contact any other host. No API key is used (NVD works unauthenticated at a lower rate limit); a
//! 403/429 from NVD itself is reported as `error` with the fact `NVD rate-limited this request —
//! wait a few seconds and retry` (not a proxy denial).
//!
//! Output: each tool returns `Body::Raw` of a compact, human-and-model-readable **text** report
//! (not raw JSON) whose first lines are the headline facts, so a cut still shows them; the complete
//! upstream JSON of each source is stored too (see each tool). `outcome` is a few words. Numbers are
//! plain. Every retrieval notes its source and that it was retrieved now (the record is a snapshot).
//!
//! ## `cve_lookup` — one consolidated CVE record (ToolClass::Read)
//! Args: `id` (required string). Normalise to `CVE-YYYY-NNNN…` (uppercase; accept lowercase and a
//! bare `YYYY-NNNN`); reject anything else with a sentence showing the expected shape.
//! 1. NVD 2.0: `GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={id}`. `totalResults==0`
//!    → `ok` outcome `not found`, body a one-line message that NVD has no such record (not an error).
//!    From `vulnerabilities[0].cve` take: `descriptions` (lang `en`), CVSS — prefer v4.0
//!    (`metrics.cvssMetricV40`), else v3.1, else v3.0, else v2 — as `{version} {baseScore}
//!    {baseSeverity} {vectorString}` (unscored → `not scored`); CWEs from `weaknesses[].description`
//!    (lang `en`, e.g. `CWE-502`); affected products from `configurations[].nodes[].cpeMatch` as the
//!    CPE `criteria` with any `versionEndExcluding`/`versionStartIncluding`/… and the fix hint; up to
//!    `MAX_REFERENCES` (12) `references[].url`; `vulnStatus`, `published`, `lastModified`. KEV comes
//!    from NVD's own fields on the cve object: present `cisaExploitAdd` → KEV `added {date}`,
//!    `cisaRequiredAction`, `cisaVulnerabilityName`, and `known ransomware use` only if NVD says so;
//!    absent → `not in KEV`.
//! 2. EPSS: `GET https://api.first.org/data/v1/epss?cve={id}`. `data[0]` → `EPSS {epss} (percentile
//!    {percentile}) as of {date}`; empty → `EPSS not available`. An EPSS failure never fails the
//!    lookup — show `EPSS lookup failed: {why}` and keep the NVD record.
//! Body text, in order: a header line `{id} — CVSS {score/severity or 'not scored'} · EPSS {score or
//! 'n/a'} · KEV {yes+date|no}`; then `Description:`, `CVSS:`, `CWE:`, `Affected:`, `KEV:`, `EPSS:`,
//! `References:`, `Retrieved: NVD {ts}, EPSS {ts}`. Store the raw NVD JSON as a second blob and name
//! it with meta `META_RAW_BLOB`. `outcome`: `CVE {id}` (or `not found`). Facts (`with_more`): the
//! CVSS severity, `KEV` when in KEV, `EPSS {score}` when present.
//!
//! ## `cve_search` — CVEs matching a filter (ToolClass::Nav)
//! Args: `query?` (keyword), `vendor?`, `kev?` (bool), `min_cvss?` (number 0–10), `min_epss?`
//! (number 0–1). At least one of `query`/`vendor`/`kev` is required (else a sentence saying so).
//! Build the NVD query: `keywordSearch={query}` (NVD ANDs multiple keywords), `virtualMatchString=
//! cpe:2.3:*:{vendor}` for `vendor`, `hasKevTrue`-style flag for `kev`, `resultsPerPage=40`. Fetch
//! one page. For `min_cvss` filter client-side on the best CVSS base score. For EPSS: one bulk call
//! `GET https://api.first.org/data/v1/epss?cve={comma-joined ids}` to enrich, then apply `min_epss`
//! and rank by EPSS descending (ties by CVSS, then recency). Show up to `MAX_HITS` (20) rows, each
//! `{id}  CVSS {score}  EPSS {score}  {KEV flag}  {first 100 chars of description}`; a header line
//! says how many matched and how many are shown, and names the filters applied. Store the raw NVD
//! JSON (meta `META_RAW_BLOB`). `outcome`: `{n} CVEs` (or `no matches`).
//!
//! ## `advisory_lookup` — package vulnerabilities from OSV (ToolClass::Read)
//! Args: `name` (required), `ecosystem` (required; e.g. `PyPI`, `npm`, `Maven`, `Go`, `crates.io`,
//! `RubyGems`), `version?`. `POST https://api.osv.dev/v1/query` with `{"package":{"name","ecosystem"}}`
//! plus `"version"` when given. Up to `MAX_ADVISORIES` (50) `vulns[]`: each `{id}  {severity if any}
//! {aliases joined}  {first line of summary}`. Note in the header that OSV reports advisories for the
//! name/version, not whether the vulnerable code is reachable in a given build. `outcome`: `{n}
//! advisories` (or `none`). Store the raw OSV JSON (meta `META_RAW_BLOB`). An unknown ecosystem still
//! queries OSV (it may return nothing) — do not reject it; list the common ecosystems in the param help.
//!
//! Tests required (a local `axum` server on loopback standing in for each upstream, reached directly
//! — no proxy — by pointing the base URLs at it through the `#[cfg(test)]` seam below): cve_lookup
//! consolidates NVD+EPSS incl. KEV present/absent, unscored, and not-found; EPSS failure degrades
//! gracefully; cve_search ranks by EPSS and applies min_cvss/min_epss and the no-filter refusal;
//! advisory_lookup with and without version and the empty case; a proxy `403` with `X-Loom-Proxy`
//! reads as `denied` naming the host; a bad CVE id is refused with the expected shape; cancellation.

use crate::{Tool, ToolCtx, ToolOutput};
use async_trait::async_trait;
use loom_core::event::{ToolClass, ToolSpec};
use serde_json::{Map, Value};

/// Most references listed by `cve_lookup`.
pub const MAX_REFERENCES: usize = 12;
/// Most rows `cve_search` shows.
pub const MAX_HITS: usize = 20;
/// Most advisories `advisory_lookup` shows.
pub const MAX_ADVISORIES: usize = 50;

/// Upstream base URLs. A test points these at a local server; production uses the constants.
/// The implementer threads these through `run` (e.g. an internal struct with these fields defaulting
/// to the constants, overridden in tests) rather than hardcoding the literals inside the request code.
pub const NVD_BASE: &str = "https://services.nvd.nist.gov";
pub const EPSS_BASE: &str = "https://api.first.org";
pub const OSV_BASE: &str = "https://api.osv.dev";

pub struct CveLookup;
pub struct CveSearch;
pub struct AdvisoryLookup;

#[async_trait]
impl Tool for CveLookup {
    fn spec(&self) -> ToolSpec {
        crate::params::spec(
            "cve_lookup",
            "Look up one CVE and return a consolidated record: description, CVSS score and vector, CWE, affected products, references, EPSS exploit-prediction score, and CISA KEV (known-exploited) status. The full record is stored so you can quote it as evidence.",
            ToolClass::Read,
            &[crate::params::req("id", "string", "A CVE id, e.g. CVE-2021-44228.")],
        )
    }

    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let _ = (ctx, args);
        todo!("implement per module contract")
    }
}

#[async_trait]
impl Tool for CveSearch {
    fn spec(&self) -> ToolSpec {
        crate::params::spec(
            "cve_search",
            "Search CVEs by keyword and/or vendor, optionally limited to known-exploited (KEV) or a minimum CVSS or EPSS score. Returns the top matches ranked by exploit-prediction (EPSS). Use cve_lookup for the full record of one.",
            ToolClass::Nav,
            &[
                crate::params::opt("query", "string", "Keywords to match in the CVE description."),
                crate::params::opt("vendor", "string", "Limit to a vendor/product (matched against CPE)."),
                crate::params::opt("kev", "boolean", "Only CVEs in the CISA Known Exploited Vulnerabilities catalog."),
                crate::params::opt("min_cvss", "number", "Only CVEs with a CVSS base score at least this (0-10).").min(0).max(10),
                crate::params::opt("min_epss", "number", "Only CVEs with an EPSS score at least this (0-1)."),
            ],
        )
    }

    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let _ = (ctx, args);
        todo!("implement per module contract")
    }
}

#[async_trait]
impl Tool for AdvisoryLookup {
    fn spec(&self) -> ToolSpec {
        crate::params::spec(
            "advisory_lookup",
            "List known vulnerabilities (advisories) for a software package from the OSV database. Give the package name and ecosystem, and optionally a version to narrow to advisories affecting it. OSV reports advisories for the package, not whether the vulnerable code is reachable in a given build.",
            ToolClass::Read,
            &[
                crate::params::req("name", "string", "The package name, exactly as its ecosystem spells it."),
                crate::params::req("ecosystem", "string", "The ecosystem: PyPI, npm, Maven, Go, crates.io, RubyGems, NuGet, Packagist, Hex, Pub, …"),
                crate::params::opt("version", "string", "A specific version to filter to (e.g. 2.14.0)."),
            ],
        )
    }

    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let _ = (ctx, args);
        todo!("implement per module contract")
    }
}
