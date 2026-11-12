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
//! Refusals are recognised as `web.rs` does: the marker only on the answer to an http:// URL through
//! the proxy, and for an https:// URL the proxy's verdict asked for before the request and again when
//! the request fails to connect.
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
//!
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

use crate::web::{ProxyVerdict, Tunnel};
use crate::{Body, Tool, ToolCtx, ToolOutput};
use async_trait::async_trait;
use futures_util::StreamExt;
use loom_core::event::{ToolClass, ToolSpec, ToolStatus, META_RAW_BLOB};
use reqwest::{redirect, Client, Proxy, RequestBuilder};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::time::Duration;
use url::Url;

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

/// The three upstream base URLs a call talks to. Production uses the constants; tests point them
/// at a local server.
#[derive(Clone, Debug)]
struct Endpoints {
    nvd: String,
    epss: String,
    osv: String,
}

impl Default for Endpoints {
    fn default() -> Endpoints {
        Endpoints { nvd: NVD_BASE.to_string(), epss: EPSS_BASE.to_string(), osv: OSV_BASE.to_string() }
    }
}

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
        cve_lookup(ctx, args, &Endpoints::default()).await
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
        cve_search(ctx, args, &Endpoints::default()).await
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
        advisory_lookup(ctx, args, &Endpoints::default()).await
    }
}

// ---------------------------------------------------------------------------------------------
// Transport

/// Most of a proxy refusal's body that is read.
const PROXY_BODY_MAX: usize = 64 * 1024;

/// Why an exchange produced no usable response.
enum Failure {
    /// The session's egress proxy refused the request.
    Denied(String),
    Error(String),
}

impl Failure {
    /// One short clause, for tools that carry on without this source.
    fn short(&self) -> String {
        match self {
            Failure::Denied(_) => "the egress proxy refused the request (the host is not on the daemon's network allowlist)".to_string(),
            Failure::Error(m) => m.clone(),
        }
    }

    fn into_output(self) -> ToolOutput {
        match self {
            Failure::Denied(m) => ToolOutput::denied(m),
            Failure::Error(m) => ToolOutput::error(m),
        }
    }
}

struct Reply {
    status: u16,
    body: Vec<u8>,
}

/// A client that never follows redirects, uses the session's proxy if there is one, and reads
/// nothing from the process environment.
fn build_client(ctx: &ToolCtx) -> Result<Client, String> {
    let mut builder = Client::builder().redirect(redirect::Policy::none()).no_proxy().user_agent("loom-cve/0.1");
    let proxy = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"]
        .iter()
        .find_map(|k| ctx.env.get(*k).filter(|v| !v.trim().is_empty()));
    if let Some(p) = proxy {
        let proxy = Proxy::all(p.trim()).map_err(|e| {
            format!("The session's proxy setting is not usable ({e}); this is a harness configuration fault. Report it; the CVE tools cannot run until it is fixed.")
        })?;
        builder = builder.proxy(proxy);
    }
    builder.build().map_err(|e| format!("The HTTP client could not be built ({e}); this is a harness fault."))
}

/// The error and its causes, as one line.
fn describe(e: &(dyn std::error::Error + 'static)) -> String {
    let mut parts = vec![e.to_string()];
    let mut source = e.source();
    while let Some(s) = source {
        let text = s.to_string();
        if !parts.iter().any(|p| p.contains(&text)) {
            parts.push(text);
        }
        source = s.source();
    }
    parts.join(": ")
}

/// `tunnel`: for an https request through the egress proxy that failed to connect, what the proxy
/// said about the host afterwards. The stage is read from the causes of the error, not from its own
/// text, which names the URL.
fn request_failure(e: &reqwest::Error, what: &str, host: &str, tunnel: Option<&Tunnel>) -> Failure {
    let detail = describe(e);
    let lower = crate::web::causes(e).to_lowercase();
    let has = |words: &[&str]| words.iter().any(|w| lower.contains(w));
    let (stage, advice) = if e.is_timeout() {
        ("timed out".to_string(), "Try again later.")
    } else if has(&["dns", "resolve", "lookup", "name or service", "nodename", "no such host"]) {
        ("could not resolve the host name".to_string(), "Check the network and try again.")
    } else if has(&["certificate", "tls", "ssl", "handshake"]) {
        ("failed the TLS handshake".to_string(), "The server's certificate or protocol was not acceptable.")
    } else if let (Some(t), true) = (tunnel, e.is_connect()) {
        t.failure()
    } else if e.is_connect() {
        ("could not connect".to_string(), "The service may be down; try again later.")
    } else {
        ("failed".to_string(), "Try again later.")
    };
    Failure::Error(format!("The {what} request to {host} {stage}: {detail}. {advice}"))
}

/// A refusal by the session's egress proxy, with its text.
fn refused(text: &str, status: u16, what: &str, host: &str) -> Failure {
    let message = if text.is_empty() { "(the proxy gave no reason)" } else { text };
    Failure::Denied(format!(
        "{message}\nThe session's egress proxy refused the {what} request (HTTP {status}): {host} is not on the daemon's network allowlist. Do not retry; ask the user to add {host} to the daemon's `[network]` allowlist if this lookup is needed."
    ))
}

/// The proxy's verdict on the host, asked before the request and again when it fails to connect: an
/// error when the proxy refuses the host or cannot look it up.
fn verdict(v: Option<ProxyVerdict>, what: &str, host: &str) -> Result<Tunnel, Failure> {
    match v {
        Some(ProxyVerdict::Allowed(rule)) => Ok(Tunnel::Allowed(rule)),
        None => Ok(Tunnel::Unknown),
        Some(ProxyVerdict::Refused(status, text)) => Err(refused(&text, status, what, host)),
        Some(ProxyVerdict::Unreachable(text)) => Err(Failure::Error(format!(
            "The {what} request to {host} failed: the egress proxy could not look up the host. {text}"
        ))),
    }
}

/// The body up to `limit` bytes; the flag says the response was larger.
async fn read_limited(resp: reqwest::Response, limit: usize) -> Result<(Vec<u8>, bool), String> {
    let mut buf: Vec<u8> = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let c = chunk.map_err(|e| describe(&e))?;
        let room = limit.saturating_sub(buf.len());
        if c.len() > room {
            buf.extend_from_slice(c.get(..room).unwrap_or_default());
            return Ok((buf, true));
        }
        buf.extend_from_slice(&c);
    }
    Ok((buf, false))
}

/// Send one request, with the whole exchange (headers and body) bounded by the configured timeout.
async fn exchange(ctx: &ToolCtx, req: RequestBuilder, url: &Url, what: &str) -> Result<Reply, Failure> {
    let host = url.host_str().unwrap_or("the host").to_string();
    let limit = Duration::from_secs(ctx.cfg.web_fetch_timeout_s.max(1));
    let max = usize::try_from(ctx.cfg.web_fetch_max_bytes).unwrap_or(usize::MAX);
    let proxied = crate::web::session_proxy(ctx).is_some();
    let work = async {
        let (client, req) = req.build_split();
        let req = req.map_err(|e| request_failure(&e, what, &host, None))?;
        // The proxy answers the CONNECT of an https URL out of the client's sight, so it is asked first.
        let tunnelled = proxied && url.scheme() == "https";
        if tunnelled {
            verdict(crate::web::proxy_verdict(&client, url).await, what, &host)?;
        }
        let resp = match client.execute(req).await {
            Ok(r) => r,
            // A refused CONNECT looks like any failure to connect: the proxy is asked again (see `Tunnel`).
            Err(e) if tunnelled && e.is_connect() && !crate::web::names_tls_failure(&e) => {
                let tunnel = verdict(crate::web::proxy_verdict(&client, url).await, what, &host)?;
                return Err(request_failure(&e, what, &host, Some(&tunnel)));
            }
            Err(e) => return Err(request_failure(&e, what, &host, None)),
        };
        let status = resp.status().as_u16();
        if crate::web::marked_by_proxy(proxied, url, resp.headers()) && matches!(status, 403 | 407) {
            let (body, _) = read_limited(resp, PROXY_BODY_MAX).await.unwrap_or_default();
            return Err(refused(String::from_utf8_lossy(&body).trim(), status, what, &host));
        }
        match read_limited(resp, max).await {
            Ok((body, false)) => Ok(Reply { status, body }),
            Ok((_, true)) => Err(Failure::Error(format!(
                "The {what} response from {host} is larger than the {max}-byte limit, so it was not kept. Narrow the request and try again."
            ))),
            Err(why) => Err(Failure::Error(format!(
                "The {what} response from {host} broke off while it was being read ({why}). Try again."
            ))),
        }
    };
    match tokio::time::timeout(limit, work).await {
        Ok(r) => r,
        Err(_) => Err(Failure::Error(format!(
            "The {what} request to {host} timed out after {} s (the limit covers the whole exchange). Try again later.",
            limit.as_secs()
        ))),
    }
}

/// `base` + `path` with the given query pairs and valueless flags.
fn endpoint(base: &str, path: &str, pairs: &[(&str, &str)], flags: &[&str]) -> Result<Url, String> {
    let mut url = Url::parse(base).map_err(|e| format!("The upstream address `{base}` is not a valid URL ({e}); this is a harness configuration fault."))?;
    url.set_path(path);
    {
        let mut q = url.query_pairs_mut();
        for (k, v) in pairs {
            q.append_pair(k, v);
        }
        for f in flags {
            q.append_key_only(f);
        }
    }
    Ok(url)
}

/// The result of a call that was cancelled.
fn interrupted(what: &str) -> ToolOutput {
    ToolOutput {
        status: ToolStatus::Interrupted,
        outcome: "interrupted".into(),
        more: Vec::new(),
        body: Body::Message(format!("The {what} was cancelled before its answers were complete; nothing was kept. Call the tool again if the data is still needed.")),
        meta: Map::new(),
    }
}

/// Run `fut`, abandoning it if the call is cancelled.
async fn cancellable(ctx: &ToolCtx, what: &str, fut: impl std::future::Future<Output = ToolOutput>) -> ToolOutput {
    tokio::select! {
        biased;
        _ = ctx.cancel.cancelled() => interrupted(what),
        out = fut => out,
    }
}

/// Store `bytes` as the call's raw upstream record and name it in the meta.
fn attach_raw(ctx: &ToolCtx, out: ToolOutput, bytes: &[u8]) -> ToolOutput {
    match ctx.blobs.put_bytes(bytes) {
        Ok(stored) => out.with_meta(META_RAW_BLOB, json!(stored.id.as_str())),
        Err(e) => out.with_more(format!("the raw upstream JSON could not be stored ({e})")),
    }
}

const RATE_LIMIT_FACT: &str = "NVD rate-limited this request — wait a few seconds and retry";

/// The NVD answer as JSON, or the output to return instead.
fn nvd_value(reply: &Reply, tolerate_404: bool) -> Result<Value, Box<ToolOutput>> {
    if matches!(reply.status, 403 | 429) {
        return Err(Box::new(ToolOutput::error(format!(
            "NVD answered HTTP {} — it is rate-limiting unauthenticated requests. Wait a few seconds and call the tool again.",
            reply.status
        ))
        .with_more(RATE_LIMIT_FACT)));
    }
    let ok_status = (200..300).contains(&reply.status);
    let unusable = || {
        ToolOutput::error(format!(
            "NVD answered HTTP {} without a usable record. Try again in a few seconds; if it persists NVD may be down.",
            reply.status
        ))
    };
    match serde_json::from_slice::<Value>(&reply.body) {
        Ok(v) if ok_status || reply.status == 404 => Ok(v),
        Err(_) if tolerate_404 && reply.status == 404 => Ok(Value::Null),
        Err(e) if ok_status => Err(Box::new(ToolOutput::error(format!(
            "NVD answered but the response was not valid JSON ({e}). Try again in a few seconds."
        )))),
        _ => Err(Box::new(unusable())),
    }
}

// ---------------------------------------------------------------------------------------------
// Reading upstream JSON (untrusted; every access is checked)

fn text<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

fn items<'a>(v: &'a Value, key: &str) -> impl Iterator<Item = &'a Value> {
    v.get(key).and_then(Value::as_array).into_iter().flatten()
}

/// A number given either as a JSON number or as a numeric string (EPSS serves strings).
fn number(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse::<f64>().ok(),
        _ => None,
    }
}

/// A scalar as plain text.
fn plain(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Upstream text made safe to put in a report: control characters other than newline are dropped.
fn clean(s: &str) -> String {
    s.chars().filter(|c| *c == '\n' || !c.is_control()).collect::<String>().trim().to_string()
}

/// The text on one line, cut to `max` characters.
fn one_line(s: &str, max: usize) -> String {
    let joined = clean(s).split_whitespace().collect::<Vec<_>>().join(" ");
    if joined.chars().count() > max {
        let cut: String = joined.chars().take(max).collect();
        format!("{cut}…")
    } else {
        joined
    }
}

/// The English entry of a `[{lang, value}]` list, else the first.
fn english(v: &Value, key: &str) -> Option<String> {
    let list: Vec<&Value> = items(v, key).collect();
    list.iter()
        .find(|d| text(d, "lang") == Some("en"))
        .or_else(|| list.first())
        .and_then(|d| text(d, "value"))
        .map(clean)
        .filter(|s| !s.is_empty())
}

struct Cvss {
    version: String,
    score: f64,
    severity: Option<String>,
    vector: Option<String>,
}

impl Cvss {
    fn short(&self) -> String {
        match &self.severity {
            Some(s) => format!("{:.1}/{s}", self.score),
            None => format!("{:.1}", self.score),
        }
    }

    fn long(&self) -> String {
        let mut out = format!("{} {:.1}", self.version, self.score);
        if let Some(s) = &self.severity {
            out.push(' ');
            out.push_str(s);
        }
        if let Some(v) = &self.vector {
            out.push(' ');
            out.push_str(v);
        }
        out
    }
}

/// The best CVSS score on a cve object: v4.0, else v3.1, else v3.0, else v2.
fn best_cvss(cve: &Value) -> Option<Cvss> {
    let metrics = cve.get("metrics")?;
    for (key, default_version) in [("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")] {
        let list: Vec<&Value> = items(metrics, key).collect();
        let pick = list.iter().find(|m| text(m, "type") == Some("Primary")).or_else(|| list.first());
        let Some(metric) = pick else { continue };
        let Some(data) = metric.get("cvssData") else { continue };
        let Some(score) = data.get("baseScore").and_then(number) else { continue };
        let severity = text(data, "baseSeverity").or_else(|| text(metric, "baseSeverity")).map(|s| clean(s).to_uppercase());
        return Some(Cvss {
            version: text(data, "version").map(clean).unwrap_or_else(|| default_version.to_string()),
            score,
            severity: severity.filter(|s| !s.is_empty()),
            vector: text(data, "vectorString").map(clean),
        });
    }
    None
}

fn is_kev(cve: &Value) -> bool {
    text(cve, "cisaExploitAdd").is_some()
}

/// `CWE-502, CWE-20` from the English weakness entries.
fn cwes(cve: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for w in items(cve, "weaknesses") {
        for d in items(w, "description") {
            if text(d, "lang") == Some("en") {
                if let Some(v) = text(d, "value") {
                    let v = clean(v);
                    if !v.is_empty() && !out.contains(&v) {
                        out.push(v);
                    }
                }
            }
        }
    }
    out
}

/// Most affected-product lines listed.
const MAX_AFFECTED: usize = 15;

/// One line per vulnerable CPE match, with its version bounds and the fix hint.
fn affected(cve: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for conf in items(cve, "configurations") {
        for node in items(conf, "nodes") {
            for m in items(node, "cpeMatch") {
                if m.get("vulnerable").and_then(Value::as_bool) == Some(false) {
                    continue;
                }
                let Some(criteria) = text(m, "criteria") else { continue };
                let mut bounds: Vec<String> = Vec::new();
                for (key, op) in [("versionStartIncluding", ">="), ("versionStartExcluding", ">"), ("versionEndIncluding", "<="), ("versionEndExcluding", "<")] {
                    if let Some(v) = text(m, key) {
                        bounds.push(format!("{op} {}", clean(v)));
                    }
                }
                let mut line = clean(criteria);
                if !bounds.is_empty() {
                    line.push_str(&format!(" [{}]", bounds.join(", ")));
                }
                if let Some(v) = text(m, "versionEndExcluding") {
                    line.push_str(&format!(" — fixed in {}", clean(v)));
                }
                if !out.contains(&line) {
                    out.push(line);
                }
            }
        }
    }
    out
}

/// One EPSS row.
#[derive(Clone, Debug)]
struct Epss {
    score: String,
    value: f64,
    percentile: Option<String>,
    date: Option<String>,
}

/// EPSS rows by upper-case CVE id.
fn epss_rows(v: &Value) -> BTreeMap<String, Epss> {
    let mut out = BTreeMap::new();
    for row in items(v, "data") {
        let Some(id) = text(row, "cve") else { continue };
        let Some(score_v) = row.get("epss") else { continue };
        let (Some(value), Some(score)) = (number(score_v), plain(score_v)) else { continue };
        out.insert(
            id.trim().to_uppercase(),
            Epss {
                score: clean(&score),
                value,
                percentile: row.get("percentile").and_then(plain).map(|s| clean(&s)),
                date: text(row, "date").map(clean),
            },
        );
    }
    out
}

/// `YYYY-MM-DDTHH:MM:SSZ` for a Unix time in milliseconds.
fn utc_stamp(ms: u64) -> String {
    let secs = ms / 1000;
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    // Days since 1970-01-01 to a civil date (proleptic Gregorian).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z", rem / 3600, (rem % 3600) / 60, rem % 60)
}

fn now_stamp() -> String {
    utc_stamp(loom_core::now_ms())
}

// ---------------------------------------------------------------------------------------------
// cve_lookup

/// `CVE-YYYY-NNNN…` from `CVE-2021-44228`, `cve-2021-44228` or `2021-44228`.
fn normalize_cve_id(given: &str) -> Option<String> {
    let t = given.trim();
    let rest = match t.get(..4) {
        Some(p) if p.eq_ignore_ascii_case("CVE-") => t.get(4..)?,
        _ => t,
    };
    let (year, seq) = rest.split_once('-')?;
    let digits = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit());
    if year.len() == 4 && digits(year) && seq.len() >= 4 && digits(seq) {
        Some(format!("CVE-{year}-{seq}"))
    } else {
        None
    }
}

async fn cve_lookup(ctx: &ToolCtx, args: &Map<String, Value>, ep: &Endpoints) -> ToolOutput {
    let given = args.get("id").and_then(Value::as_str).unwrap_or_default();
    let Some(id) = normalize_cve_id(given) else {
        return ToolOutput::error(format!(
            "`{}` is not a CVE id. A CVE id looks like CVE-2021-44228: `CVE-`, a four-digit year, `-`, and a number of at least four digits. Call cve_lookup again with an id of that shape.",
            one_line(given, 60)
        ));
    };
    let client = match build_client(ctx) {
        Ok(c) => c,
        Err(m) => return ToolOutput::error(m),
    };
    cancellable(ctx, &format!("lookup of {id}"), lookup_run(ctx, &client, ep, &id)).await
}

async fn lookup_run(ctx: &ToolCtx, client: &Client, ep: &Endpoints, id: &str) -> ToolOutput {
    let url = match endpoint(&ep.nvd, "/rest/json/cves/2.0", &[("cveId", id)], &[]) {
        Ok(u) => u,
        Err(m) => return ToolOutput::error(m),
    };
    let reply = match exchange(ctx, client.get(url.clone()), &url, "NVD").await {
        Ok(r) => r,
        Err(f) => return f.into_output(),
    };
    let nvd_time = now_stamp();
    let nvd = match nvd_value(&reply, true) {
        Ok(v) => v,
        Err(out) => return *out,
    };
    let cve = items(&nvd, "vulnerabilities").find_map(|v| v.get("cve"));
    let Some(cve) = cve else {
        let out = ToolOutput::ok(
            "not found",
            Body::Message(format!("NVD has no record for {id}. Check the id's digits; a very recent or reserved CVE may not be published yet. (Source: NVD, retrieved {nvd_time}.)")),
        );
        return attach_raw(ctx, out, &reply.body);
    };

    // EPSS never fails the lookup.
    let epss_url = endpoint(&ep.epss, "/data/v1/epss", &[("cve", id)], &[]);
    let (epss, epss_time): (Result<Option<Epss>, String>, String) = match epss_url {
        Err(m) => (Err(m), String::new()),
        Ok(u) => match exchange(ctx, client.get(u.clone()), &u, "EPSS").await {
            Err(f) => (Err(f.short()), String::new()),
            Ok(r) if !(200..300).contains(&r.status) => (Err(format!("EPSS answered HTTP {}", r.status)), String::new()),
            Ok(r) => match serde_json::from_slice::<Value>(&r.body) {
                Ok(v) => (Ok(epss_rows(&v).remove(id)), now_stamp()),
                Err(e) => (Err(format!("EPSS gave an unreadable answer ({e})")), String::new()),
            },
        },
    };

    let cvss = best_cvss(cve);
    let kev = is_kev(cve);
    let kev_added = text(cve, "cisaExploitAdd").map(clean);
    let cvss_head = cvss.as_ref().map(Cvss::short).unwrap_or_else(|| "not scored".to_string());
    let epss_head = match &epss {
        Ok(Some(e)) => e.score.clone(),
        _ => "n/a".to_string(),
    };
    let kev_head = match &kev_added {
        Some(d) => format!("yes (added {d})"),
        None => "no".to_string(),
    };

    let mut r = String::new();
    r.push_str(&format!("{id} — CVSS {cvss_head} · EPSS {epss_head} · KEV {kev_head}\n"));
    r.push_str(&format!("Description: {}\n", english(cve, "descriptions").unwrap_or_else(|| "(NVD gives no description)".to_string())));
    r.push_str(&format!("CVSS: {}\n", cvss.as_ref().map(Cvss::long).unwrap_or_else(|| "not scored".to_string())));
    let weak = cwes(cve);
    r.push_str(&format!("CWE: {}\n", if weak.is_empty() { "none listed".to_string() } else { weak.join(", ") }));
    let aff = affected(cve);
    if aff.is_empty() {
        r.push_str("Affected: no affected-product configuration listed\n");
    } else {
        r.push_str("Affected:\n");
        for line in aff.iter().take(MAX_AFFECTED) {
            r.push_str(&format!("  {line}\n"));
        }
        if aff.len() > MAX_AFFECTED {
            r.push_str(&format!("  … and {} more (see the stored NVD JSON)\n", aff.len() - MAX_AFFECTED));
        }
    }
    if kev {
        let mut k = format!("KEV: added {}", kev_added.clone().unwrap_or_default());
        if let Some(n) = text(cve, "cisaVulnerabilityName") {
            k.push_str(&format!("; {}", one_line(n, 200)));
        }
        if let Some(a) = text(cve, "cisaRequiredAction") {
            k.push_str(&format!("; required action: {}", one_line(a, 300)));
        }
        if let Some(d) = text(cve, "cisaActionDue") {
            k.push_str(&format!("; due {}", clean(d)));
        }
        if text(cve, "knownRansomwareCampaignUse").is_some_and(|s| s.eq_ignore_ascii_case("known")) {
            k.push_str("; known ransomware use");
        }
        r.push_str(&k);
        r.push('\n');
    } else {
        r.push_str("KEV: not in KEV\n");
    }
    match &epss {
        Ok(Some(e)) => {
            r.push_str(&format!("EPSS: EPSS {} (percentile {})", e.score, e.percentile.as_deref().unwrap_or("n/a")));
            if let Some(d) = &e.date {
                r.push_str(&format!(" as of {d}"));
            }
            r.push('\n');
        }
        Ok(None) => r.push_str("EPSS: EPSS not available\n"),
        Err(why) => r.push_str(&format!("EPSS: EPSS lookup failed: {why}\n")),
    }
    let refs: Vec<String> = items(cve, "references").filter_map(|x| text(x, "url")).map(clean).filter(|u| !u.is_empty()).collect();
    if refs.is_empty() {
        r.push_str("References: none listed\n");
    } else {
        r.push_str("References:\n");
        for u in refs.iter().take(MAX_REFERENCES) {
            r.push_str(&format!("  {u}\n"));
        }
        if refs.len() > MAX_REFERENCES {
            r.push_str(&format!("  … and {} more (see the stored NVD JSON)\n", refs.len() - MAX_REFERENCES));
        }
    }
    r.push_str(&format!(
        "Record: status {}, published {}, last modified {}\n",
        text(cve, "vulnStatus").map(clean).unwrap_or_else(|| "unknown".into()),
        text(cve, "published").map(clean).unwrap_or_else(|| "unknown".into()),
        text(cve, "lastModified").map(clean).unwrap_or_else(|| "unknown".into()),
    ));
    let epss_retrieved = if epss_time.is_empty() { "EPSS unavailable".to_string() } else { format!("EPSS {epss_time}") };
    r.push_str(&format!("Retrieved: NVD {nvd_time}, {epss_retrieved} (a snapshot; sources: NVD, FIRST EPSS)"));

    let mut out = ToolOutput::ok(format!("CVE {id}"), Body::Raw(r.into_bytes()));
    if let Some(sev) = cvss.as_ref().and_then(|c| c.severity.clone()) {
        out = out.with_more(sev);
    }
    if kev {
        out = out.with_more("KEV");
    }
    if let Ok(Some(e)) = &epss {
        out = out.with_more(format!("EPSS {}", e.score));
    }
    attach_raw(ctx, out, &reply.body)
}

// ---------------------------------------------------------------------------------------------
// cve_search

struct Hit {
    id: String,
    cvss: Option<f64>,
    epss: Option<Epss>,
    kev: bool,
    published: String,
    desc: String,
}

async fn cve_search(ctx: &ToolCtx, args: &Map<String, Value>, ep: &Endpoints) -> ToolOutput {
    let arg_text = |k: &str| args.get(k).and_then(Value::as_str).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let query = arg_text("query");
    let vendor = arg_text("vendor");
    let kev = args.get("kev").and_then(Value::as_bool).unwrap_or(false);
    let min_cvss = args.get("min_cvss").and_then(number);
    let min_epss = args.get("min_epss").and_then(number);
    if query.is_none() && vendor.is_none() && !kev {
        return ToolOutput::error("cve_search needs at least one of `query` (keywords), `vendor`, or `kev: true` — min_cvss and min_epss only narrow a search, they cannot start one. Call again with one of those.");
    }
    if min_cvss.is_some_and(|v| !(0.0..=10.0).contains(&v)) {
        return ToolOutput::error("`min_cvss` is a CVSS base score between 0 and 10. Call cve_search again with a value in that range.");
    }
    if min_epss.is_some_and(|v| !(0.0..=1.0).contains(&v)) {
        return ToolOutput::error("`min_epss` is an EPSS probability between 0 and 1 (for example 0.5, not 50). Call cve_search again with a value in that range.");
    }
    let client = match build_client(ctx) {
        Ok(c) => c,
        Err(m) => return ToolOutput::error(m),
    };

    let mut filters: Vec<String> = Vec::new();
    if let Some(q) = &query {
        filters.push(format!("keywords \"{}\"", one_line(q, 80)));
    }
    if let Some(v) = &vendor {
        filters.push(format!("vendor {}", one_line(v, 60)));
    }
    if kev {
        filters.push("KEV only".to_string());
    }
    if let Some(v) = min_cvss {
        filters.push(format!("CVSS >= {v}"));
    }
    if let Some(v) = min_epss {
        filters.push(format!("EPSS >= {v}"));
    }

    let run = async {
        let cpe = vendor.as_ref().map(|v| format!("cpe:2.3:*:{}", v.to_lowercase().replace(' ', "_")));
        let mut pairs: Vec<(&str, &str)> = vec![("resultsPerPage", "40")];
        if let Some(q) = &query {
            pairs.push(("keywordSearch", q));
        }
        if let Some(c) = &cpe {
            pairs.push(("virtualMatchString", c));
        }
        let mut flags = vec!["noRejected"];
        if kev {
            flags.push("hasKev");
        }
        let url = match endpoint(&ep.nvd, "/rest/json/cves/2.0", &pairs, &flags) {
            Ok(u) => u,
            Err(m) => return ToolOutput::error(m),
        };
        let reply = match exchange(ctx, client.get(url.clone()), &url, "NVD").await {
            Ok(r) => r,
            Err(f) => return f.into_output(),
        };
        let nvd = match nvd_value(&reply, false) {
            Ok(v) => v,
            Err(out) => return *out,
        };
        let total = nvd.get("totalResults").and_then(Value::as_u64);
        let mut hits: Vec<Hit> = items(&nvd, "vulnerabilities")
            .filter_map(|v| v.get("cve"))
            .filter_map(|cve| {
                Some(Hit {
                    id: text(cve, "id").map(|s| clean(s).to_uppercase())?,
                    cvss: best_cvss(cve).map(|c| c.score),
                    epss: None,
                    kev: is_kev(cve),
                    published: text(cve, "published").map(clean).unwrap_or_default(),
                    desc: english(cve, "descriptions").unwrap_or_default(),
                })
            })
            .collect();
        let examined = hits.len();
        if let Some(m) = min_cvss {
            hits.retain(|h| h.cvss.is_some_and(|s| s >= m));
        }

        // One bulk EPSS call for whatever survived.
        let mut epss_note: Option<String> = None;
        if !hits.is_empty() {
            let ids = hits.iter().map(|h| h.id.as_str()).collect::<Vec<_>>().join(",");
            let fetched = match endpoint(&ep.epss, "/data/v1/epss", &[("cve", &ids)], &[]) {
                Err(m) => Err(m),
                Ok(u) => match exchange(ctx, client.get(u.clone()), &u, "EPSS").await {
                    Err(f) => Err(f.short()),
                    Ok(r) if !(200..300).contains(&r.status) => Err(format!("EPSS answered HTTP {}", r.status)),
                    Ok(r) => serde_json::from_slice::<Value>(&r.body).map_err(|e| format!("EPSS gave an unreadable answer ({e})")),
                },
            };
            match fetched {
                Ok(v) => {
                    let rows = epss_rows(&v);
                    for h in &mut hits {
                        h.epss = rows.get(&h.id).cloned();
                    }
                }
                Err(why) if min_epss.is_some() => {
                    return ToolOutput::error(format!(
                        "EPSS lookup failed ({why}), so `min_epss` cannot be applied. Call cve_search again in a moment, or without `min_epss`."
                    ));
                }
                Err(why) => epss_note = Some(format!("EPSS lookup failed ({why}); rows are ranked by CVSS then recency")),
            }
        }
        if let Some(m) = min_epss {
            hits.retain(|h| h.epss.as_ref().is_some_and(|e| e.value >= m));
        }
        hits.sort_by(|a, b| {
            let ea = a.epss.as_ref().map(|e| e.value);
            let eb = b.epss.as_ref().map(|e| e.value);
            eb.partial_cmp(&ea)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.cvss.partial_cmp(&a.cvss).unwrap_or(std::cmp::Ordering::Equal))
                .then_with(|| b.published.cmp(&a.published))
        });

        let matched = hits.len();
        let shown = matched.min(MAX_HITS);
        let mut r = format!("{matched} CVEs matched, showing {shown}. Filters: {}.\n", filters.join(", "));
        match total {
            Some(t) if usize::try_from(t).map_or(true, |t| t > examined) => {
                r.push_str(&format!("Only the first {examined} of NVD's {t} results were examined; narrow the filters to reach the rest.\n"));
            }
            _ => {}
        }
        if let Some(n) = &epss_note {
            r.push_str(&format!("Note: {n}.\n"));
        }
        r.push_str(&format!("Source: NVD and FIRST EPSS, retrieved {} (a snapshot).\n", now_stamp()));
        for h in hits.iter().take(MAX_HITS) {
            r.push_str(&format!(
                "{}  CVSS {}  EPSS {}  {}  {}\n",
                h.id,
                h.cvss.map_or_else(|| "n/a".to_string(), |s| format!("{s:.1}")),
                h.epss.as_ref().map_or("n/a", |e| e.score.as_str()),
                if h.kev { "KEV" } else { "-" },
                one_line(&h.desc, 100),
            ));
        }
        let (outcome, body) = if matched == 0 {
            (
                "no matches".to_string(),
                Body::Message(format!("No CVEs matched ({}); {examined} were returned by NVD before the CVSS/EPSS filters. Loosen a filter or change the keywords.", filters.join(", "))),
            )
        } else {
            (format!("{matched} CVEs"), Body::Raw(r.into_bytes()))
        };
        attach_raw(ctx, ToolOutput::ok(outcome, body), &reply.body)
    };
    cancellable(ctx, "CVE search", run).await
}

// ---------------------------------------------------------------------------------------------
// advisory_lookup

async fn advisory_lookup(ctx: &ToolCtx, args: &Map<String, Value>, ep: &Endpoints) -> ToolOutput {
    let arg_text = |k: &str| args.get(k).and_then(Value::as_str).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let (Some(name), Some(ecosystem)) = (arg_text("name"), arg_text("ecosystem")) else {
        return ToolOutput::error("advisory_lookup needs both `name` (the package name) and `ecosystem` (for example PyPI, npm, Maven, Go, crates.io, RubyGems). Call again with both.");
    };
    let version = arg_text("version");
    let client = match build_client(ctx) {
        Ok(c) => c,
        Err(m) => return ToolOutput::error(m),
    };
    let run = async {
        let mut body = json!({"package": {"name": name, "ecosystem": ecosystem}});
        if let (Some(v), Some(obj)) = (&version, body.as_object_mut()) {
            obj.insert("version".to_string(), json!(v));
        }
        let url = match endpoint(&ep.osv, "/v1/query", &[], &[]) {
            Ok(u) => u,
            Err(m) => return ToolOutput::error(m),
        };
        let reply = match exchange(ctx, client.post(url.clone()).json(&body), &url, "OSV").await {
            Ok(r) => r,
            Err(f) => return f.into_output(),
        };
        let parsed = serde_json::from_slice::<Value>(&reply.body);
        let subject = match &version {
            Some(v) => format!("{name} {v} ({ecosystem})"),
            None => format!("{name} ({ecosystem}), all versions"),
        };
        if !(200..300).contains(&reply.status) {
            return match parsed {
                Ok(v) if reply.status < 500 => {
                    let why = text(&v, "message").map(|m| one_line(m, 300)).unwrap_or_else(|| "no reason given".to_string());
                    attach_raw(
                        ctx,
                        ToolOutput::ok(
                            format!("OSV HTTP {}", reply.status),
                            Body::Message(format!("OSV did not accept the query for {subject}: {why}. Check the package name and the ecosystem spelling (for example `PyPI`, `npm`, `crates.io`) and call again.")),
                        ),
                        &reply.body,
                    )
                }
                _ => ToolOutput::error(format!("OSV answered HTTP {} without a usable result. Try again in a moment.", reply.status)),
            };
        }
        let v = match parsed {
            Ok(v) => v,
            Err(e) => return ToolOutput::error(format!("OSV answered but the response was not valid JSON ({e}). Try again in a moment.")),
        };
        let vulns: Vec<&Value> = items(&v, "vulns").collect();
        let total = vulns.len();
        if total == 0 {
            let out = ToolOutput::ok(
                "none",
                Body::Message(format!("OSV lists no advisories for {subject}. That means none are recorded, not that the package is safe; the ecosystem or name may also be misspelled. (Source: OSV, retrieved {}.)", now_stamp())),
            );
            return attach_raw(ctx, out, &reply.body);
        }
        let mut r = format!(
            "{total} advisories for {subject}. OSV reports advisories for the package name/version, not whether the vulnerable code is reachable in a given build.\nSource: OSV, retrieved {} (a snapshot).\n",
            now_stamp()
        );
        if total > MAX_ADVISORIES {
            r.push_str(&format!("Showing the first {MAX_ADVISORIES} of {total}.\n"));
        }
        if v.get("next_page_token").is_some() {
            r.push_str("OSV has further pages of results that were not fetched.\n");
        }
        for a in vulns.iter().take(MAX_ADVISORIES) {
            let id = text(a, "id").map(clean).unwrap_or_else(|| "(no id)".to_string());
            let severity = a
                .get("database_specific")
                .and_then(|d| text(d, "severity"))
                .map(|s| clean(s).to_uppercase())
                .or_else(|| {
                    items(a, "severity").next().and_then(|s| {
                        let score = text(s, "score")?;
                        Some(match text(s, "type") {
                            Some(t) => format!("{} {}", clean(t), clean(score)),
                            None => clean(score),
                        })
                    })
                })
                .unwrap_or_else(|| "severity n/a".to_string());
            let aliases: Vec<String> = items(a, "aliases").filter_map(Value::as_str).map(clean).collect();
            let summary = text(a, "summary")
                .map(clean)
                .filter(|s| !s.is_empty())
                .or_else(|| text(a, "details").map(clean))
                .and_then(|s| s.lines().next().map(str::to_string))
                .map(|s| one_line(&s, 160))
                .unwrap_or_default();
            r.push_str(&format!("{id}  {severity}  {}  {summary}\n", if aliases.is_empty() { "-".to_string() } else { aliases.join(",") }));
        }
        attach_raw(ctx, ToolOutput::ok(format!("{total} advisories"), Body::Raw(r.into_bytes())), &reply.body)
    };
    cancellable(ctx, "advisory lookup", run).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{env, env_with, TestEnv};
    use axum::extract::Query;
    use axum::http::{HeaderMap, HeaderValue, StatusCode};
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use loom_core::config::{SandboxCfg, SandboxMode, ToolsCfg};
    use std::collections::HashMap;
    use std::sync::Arc;

    /// A tool that runs the real code against test endpoints.
    struct Seam {
        ep: Endpoints,
        which: u8,
    }

    #[async_trait]
    impl Tool for Seam {
        fn spec(&self) -> ToolSpec {
            match self.which {
                0 => CveLookup.spec(),
                1 => CveSearch.spec(),
                _ => AdvisoryLookup.spec(),
            }
        }

        async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
            match self.which {
                0 => cve_lookup(ctx, args, &self.ep).await,
                1 => cve_search(ctx, args, &self.ep).await,
                _ => advisory_lookup(ctx, args, &self.ep).await,
            }
        }
    }

    fn seamed(e: &mut TestEnv, base: &str) {
        let ep = Endpoints { nvd: base.to_string(), epss: base.to_string(), osv: base.to_string() };
        for which in 0..3 {
            e.registry.add(Arc::new(Seam { ep: ep.clone(), which }));
        }
    }

    async fn serve(app: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    fn cve_json(id: &str, extra: Value) -> Value {
        let mut cve = json!({
            "id": id,
            "published": "2021-12-10T10:15:09.143",
            "lastModified": "2023-04-03T20:15:07.000",
            "vulnStatus": "Analyzed",
            "descriptions": [
                {"lang": "es", "value": "descripcion"},
                {"lang": "en", "value": format!("Remote code execution in thing {id}.\nSecond line.")}
            ],
            "metrics": {
                "cvssMetricV31": [{"type": "Primary", "cvssData": {"version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}],
                "cvssMetricV2": [{"baseSeverity": "HIGH", "cvssData": {"version": "2.0", "baseScore": 7.5, "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P"}}]
            },
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-502"}, {"lang": "en", "value": "CWE-20"}]}],
            "configurations": [{"nodes": [{"cpeMatch": [
                {"vulnerable": true, "criteria": "cpe:2.3:a:acme:thing:*:*:*:*:*:*:*:*", "versionStartIncluding": "2.0", "versionEndExcluding": "2.15.0"},
                {"vulnerable": false, "criteria": "cpe:2.3:o:acme:os:-:*:*:*:*:*:*:*"}
            ]}]}],
            "references": [{"url": "https://example.org/a"}, {"url": "https://example.org/b"}]
        });
        if let (Some(c), Some(x)) = (cve.as_object_mut(), extra.as_object()) {
            for (k, v) in x {
                c.insert(k.clone(), v.clone());
            }
        }
        cve
    }

    fn kev_fields() -> Value {
        json!({
            "cisaExploitAdd": "2021-12-10",
            "cisaActionDue": "2021-12-24",
            "cisaRequiredAction": "Apply updates per vendor instructions.",
            "cisaVulnerabilityName": "Acme Thing RCE"
        })
    }

    fn nvd_page(cves: Vec<Value>) -> Value {
        json!({"totalResults": cves.len(), "vulnerabilities": cves.into_iter().map(|c| json!({"cve": c})).collect::<Vec<_>>()})
    }

    /// NVD, EPSS and OSV in one server.
    fn upstream() -> Router {
        async fn nvd(Query(q): Query<HashMap<String, String>>) -> Json<Value> {
            if let Some(id) = q.get("cveId") {
                return Json(match id.as_str() {
                    "CVE-2021-44228" => nvd_page(vec![cve_json(id, kev_fields())]),
                    "CVE-2024-0001" => nvd_page(vec![cve_json(id, json!({}))]),
                    "CVE-2024-0002" => nvd_page(vec![cve_json(id, json!({"metrics": {}}))]),
                    "CVE-2024-0003" => nvd_page(vec![cve_json(id, json!({}))]),
                    _ => json!({"totalResults": 0, "vulnerabilities": []}),
                });
            }
            let mut a = cve_json("CVE-2024-1001", json!({"published": "2024-01-01T00:00:00.000"}));
            let mut b = cve_json("CVE-2024-1002", kev_fields());
            let mut c = cve_json("CVE-2024-1003", json!({"published": "2024-03-01T00:00:00.000"}));
            let d = cve_json("CVE-2024-1004", json!({"metrics": {}}));
            // a: CVSS 5.0, b: 9.8, c: 7.0
            if let Some(m) = a.pointer_mut("/metrics/cvssMetricV31/0/cvssData/baseScore") {
                *m = json!(5.0);
            }
            if let Some(m) = c.pointer_mut("/metrics/cvssMetricV31/0/cvssData/baseScore") {
                *m = json!(7.0);
            }
            if let Some(o) = b.as_object_mut() {
                o.insert("descriptions".into(), json!([{"lang": "en", "value": "x".repeat(300)}]));
            }
            let wrapped: Vec<Value> = vec![a, b, c, d].into_iter().map(|c| json!({"cve": c})).collect();
            Json(json!({"totalResults": 90, "vulnerabilities": wrapped}))
        }
        async fn epss(Query(q): Query<HashMap<String, String>>) -> Json<Value> {
            let ids = q.get("cve").cloned().unwrap_or_default();
            let data: Vec<Value> = ids
                .split(',')
                .filter_map(|id| {
                    let score = match id {
                        "CVE-2021-44228" => "0.97565",
                        "CVE-2024-0001" => "0.00100",
                        "CVE-2024-1001" => "0.90000",
                        "CVE-2024-1002" => "0.20000",
                        "CVE-2024-1003" => "0.50000",
                        _ => return None,
                    };
                    Some(json!({"cve": id, "epss": score, "percentile": "0.99900", "date": "2026-11-10"}))
                })
                .collect();
            Json(json!({"status": "OK", "data": data}))
        }
        async fn osv(Json(body): Json<Value>) -> Json<Value> {
            let name = body.pointer("/package/name").and_then(Value::as_str).unwrap_or_default().to_string();
            let version = body.get("version").and_then(Value::as_str).map(str::to_string);
            if name == "empty" {
                return Json(json!({}));
            }
            let mut vulns = vec![
                json!({"id": "GHSA-aaaa-bbbb-cccc", "summary": "Prototype pollution\nmore", "aliases": ["CVE-2020-1111"], "database_specific": {"severity": "high"}}),
                json!({"id": "PYSEC-2020-1", "details": "Details only here.", "aliases": [], "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}]}),
            ];
            if version.is_none() {
                vulns.push(json!({"id": "GHSA-dddd", "summary": "Only without version", "aliases": ["CVE-2019-2"]}));
            }
            Json(json!({"vulns": vulns, "echo_version": version}))
        }
        Router::new()
            .route("/rest/json/cves/2.0", get(nvd))
            .route("/data/v1/epss", get(epss))
            .route("/v1/query", post(osv))
    }

    async fn env_up(app: Router) -> TestEnv {
        let base = serve(app).await;
        let mut e = env();
        seamed(&mut e, &base);
        e
    }

    #[test]
    fn ids_normalise() {
        assert_eq!(normalize_cve_id("cve-2021-44228").as_deref(), Some("CVE-2021-44228"));
        assert_eq!(normalize_cve_id(" 2021-44228 ").as_deref(), Some("CVE-2021-44228"));
        assert_eq!(normalize_cve_id("CVE-2021-4422").as_deref(), Some("CVE-2021-4422"));
        for bad in ["", "CVE-21-44228", "CVE-2021-12", "CVE-2021-12a4", "log4shell", "CVE-2021", "é"] {
            assert!(normalize_cve_id(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn stamp_is_utc_iso() {
        assert_eq!(utc_stamp(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc_stamp(1_700_000_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(utc_stamp(951_782_400_000), "2000-02-29T00:00:00Z");
    }

    #[tokio::test]
    async fn lookup_consolidates_nvd_epss_and_kev() {
        let e = env_up(upstream()).await;
        let r = e.call("cve_lookup", json!({"id": "cve-2021-44228"})).await;
        assert_eq!(r.status, ToolStatus::Ok, "{}", r.text);
        assert!(r.text.contains("CVE CVE-2021-44228"), "{}", r.text);
        assert!(r.text.contains("CRITICAL") && r.text.contains("KEV") && r.text.contains("EPSS 0.97565"), "{}", r.text);
        let t = e.stored(&r);
        let first = t.lines().next().unwrap();
        assert_eq!(first, "CVE-2021-44228 — CVSS 9.8/CRITICAL · EPSS 0.97565 · KEV yes (added 2021-12-10)");
        let order = ["Description:", "CVSS:", "CWE:", "Affected:", "KEV:", "EPSS:", "References:", "Retrieved:"];
        let mut at = 0;
        for h in order {
            let p = t[at..].find(&format!("\n{h}")).unwrap_or_else(|| panic!("{h} missing or out of order in\n{t}"));
            at += p + 1;
        }
        assert!(t.contains("Remote code execution in thing CVE-2021-44228."), "{t}");
        assert!(!t.contains("descripcion"));
        assert!(t.contains("CVSS: 3.1 9.8 CRITICAL CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), "{t}");
        assert!(t.contains("CWE: CWE-502, CWE-20"), "{t}");
        assert!(t.contains("cpe:2.3:a:acme:thing:*:*:*:*:*:*:*:* [>= 2.0, < 2.15.0] — fixed in 2.15.0"), "{t}");
        assert!(!t.contains("acme:os"), "non-vulnerable match must be left out: {t}");
        assert!(t.contains("KEV: added 2021-12-10; Acme Thing RCE; required action: Apply updates per vendor instructions.; due 2021-12-24"), "{t}");
        assert!(!t.contains("ransomware"), "{t}");
        assert!(t.contains("EPSS: EPSS 0.97565 (percentile 0.99900) as of 2026-11-10"), "{t}");
        assert!(t.contains("https://example.org/a") && t.contains("Retrieved: NVD 20"), "{t}");
        // The raw NVD JSON is the second blob.
        let raw_id = r.meta.get(META_RAW_BLOB).and_then(Value::as_str).unwrap();
        let id = e.ctx.blobs.resolve(raw_id).unwrap();
        let raw: Value = serde_json::from_slice(&e.ctx.blobs.read_all(&id).unwrap()).unwrap();
        assert_eq!(raw.pointer("/vulnerabilities/0/cve/id").and_then(Value::as_str), Some("CVE-2021-44228"));
        assert_ne!(Some(id.as_str()), r.output.as_ref().map(|b| b.id.as_str()));
    }

    #[tokio::test]
    async fn lookup_without_kev_says_so() {
        let e = env_up(upstream()).await;
        let r = e.call("cve_lookup", json!({"id": "CVE-2024-0001"})).await;
        let t = e.stored(&r);
        assert!(t.lines().next().unwrap().ends_with("KEV no"), "{t}");
        assert!(t.contains("KEV: not in KEV"), "{t}");
    }

    #[tokio::test]
    async fn lookup_unscored_and_without_epss() {
        let e = env_up(upstream()).await;
        let r = e.call("cve_lookup", json!({"id": "CVE-2024-0002"})).await;
        let t = e.stored(&r);
        assert_eq!(t.lines().next().unwrap(), "CVE-2024-0002 — CVSS not scored · EPSS n/a · KEV no");
        assert!(t.contains("CVSS: not scored"), "{t}");
        assert!(t.contains("EPSS: EPSS not available"), "{t}");
        assert_eq!(r.status, ToolStatus::Ok);
    }

    #[tokio::test]
    async fn lookup_not_found_is_ok() {
        let e = env_up(upstream()).await;
        let r = e.call("cve_lookup", json!({"id": "CVE-2099-99999"})).await;
        assert_eq!(r.status, ToolStatus::Ok, "{}", r.text);
        assert!(r.text.contains("not found"), "{}", r.text);
        assert!(r.text.contains("NVD has no record for CVE-2099-99999"), "{}", r.text);
    }

    #[tokio::test]
    async fn epss_failure_keeps_the_nvd_record() {
        let app = Router::new()
            .route(
                "/rest/json/cves/2.0",
                get(|| async { Json(nvd_page(vec![cve_json("CVE-2024-0001", json!({}))])) }),
            )
            .route("/data/v1/epss", get(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "boom") }));
        let e = env_up(app).await;
        let r = e.call("cve_lookup", json!({"id": "CVE-2024-0001"})).await;
        assert_eq!(r.status, ToolStatus::Ok, "{}", r.text);
        let t = e.stored(&r);
        assert!(t.contains("EPSS lookup failed: EPSS answered HTTP 500"), "{t}");
        assert!(t.lines().next().unwrap().contains("CVSS 9.8/CRITICAL · EPSS n/a"), "{t}");
        assert!(t.contains("EPSS unavailable"), "{t}");
    }

    #[tokio::test]
    async fn epss_refused_connection_degrades_too() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let live = serve(Router::new().route("/rest/json/cves/2.0", get(|| async { Json(nvd_page(vec![cve_json("CVE-2024-0001", json!({}))])) }))).await;
        let mut e = env();
        let ep = Endpoints { nvd: live, epss: dead, osv: String::new() };
        e.registry.add(Arc::new(Seam { ep, which: 0 }));
        let r = e.call("cve_lookup", json!({"id": "CVE-2024-0001"})).await;
        assert_eq!(r.status, ToolStatus::Ok, "{}", r.text);
        assert!(e.stored(&r).contains("EPSS lookup failed: The EPSS request to 127.0.0.1 could not connect"), "{}", e.stored(&r));
    }

    #[tokio::test]
    async fn nvd_rate_limit_is_an_error_not_a_denial() {
        for code in [StatusCode::FORBIDDEN, StatusCode::TOO_MANY_REQUESTS] {
            let app = Router::new().fallback(move || async move { (code, "slow down") });
            let e = env_up(app).await;
            let r = e.call("cve_lookup", json!({"id": "CVE-2024-0001"})).await;
            assert_eq!(r.status, ToolStatus::Error, "{}", r.text);
            assert!(r.text.contains("NVD rate-limited this request — wait a few seconds and retry"), "{}", r.text);
        }
    }

    #[tokio::test]
    async fn nvd_server_error_is_an_error_naming_the_stage() {
        let app = Router::new().fallback(|| async { (StatusCode::BAD_GATEWAY, "bad gateway") });
        let e = env_up(app).await;
        let r = e.call("cve_lookup", json!({"id": "CVE-2024-0001"})).await;
        assert_eq!(r.status, ToolStatus::Error, "{}", r.text);
        assert!(r.text.contains("NVD answered HTTP 502"), "{}", r.text);
    }

    #[tokio::test]
    async fn bad_ids_are_refused_with_the_shape() {
        let e = env_up(upstream()).await;
        for bad in ["log4shell", "CVE-21-1", ""] {
            let r = e.call("cve_lookup", json!({"id": bad})).await;
            assert_eq!(r.status, ToolStatus::Error, "{bad}: {}", r.text);
            assert!(r.text.contains("CVE-2021-44228") && r.text.contains("four-digit year"), "{bad}: {}", r.text);
        }
    }

    #[tokio::test]
    async fn search_ranks_by_epss_and_filters() {
        let e = env_up(upstream()).await;
        let r = e.call("cve_search", json!({"query": "thing"})).await;
        assert_eq!(r.status, ToolStatus::Ok, "{}", r.text);
        assert!(r.text.contains("4 CVEs"), "{}", r.text);
        let t = e.stored(&r);
        let rows: Vec<&str> = t.lines().filter(|l| l.starts_with("CVE-")).collect();
        let ids: Vec<&str> = rows.iter().map(|l| l.split_whitespace().next().unwrap()).collect();
        // EPSS 0.9, 0.5, 0.2, then the one with no EPSS row.
        assert_eq!(ids, ["CVE-2024-1001", "CVE-2024-1003", "CVE-2024-1002", "CVE-2024-1004"], "{t}");
        assert!(rows[0].contains("CVSS 5.0  EPSS 0.90000  -  "), "{}", rows[0]);
        assert!(rows[2].contains("CVSS 9.8  EPSS 0.20000  KEV  "), "{}", rows[2]);
        assert!(rows[3].contains("CVSS n/a  EPSS n/a"), "{}", rows[3]);
        assert!(rows[2].ends_with(&format!("{}…", "x".repeat(100))), "description cut at 100 chars: {}", rows[2]);
        assert!(t.lines().next().unwrap().contains("4 CVEs matched, showing 4. Filters: keywords \"thing\""), "{t}");
        assert!(t.contains("Only the first 4 of NVD's 90 results were examined"), "{t}");
        assert!(r.meta.get(META_RAW_BLOB).is_some());

        let r = e.call("cve_search", json!({"query": "thing", "min_cvss": 7})).await;
        let t = e.stored(&r);
        let ids: Vec<&str> = t.lines().filter(|l| l.starts_with("CVE-")).map(|l| l.split_whitespace().next().unwrap()).collect();
        assert_eq!(ids, ["CVE-2024-1003", "CVE-2024-1002"], "{t}");
        assert!(t.contains("CVSS >= 7"), "{t}");

        let r = e.call("cve_search", json!({"query": "thing", "min_epss": 0.4})).await;
        let t = e.stored(&r);
        let ids: Vec<&str> = t.lines().filter(|l| l.starts_with("CVE-")).map(|l| l.split_whitespace().next().unwrap()).collect();
        assert_eq!(ids, ["CVE-2024-1001", "CVE-2024-1003"], "{t}");

        let r = e.call("cve_search", json!({"vendor": "acme", "kev": true, "min_cvss": 10})).await;
        assert_eq!(r.status, ToolStatus::Ok, "{}", r.text);
        assert!(r.text.contains("no matches"), "{}", r.text);
    }

    #[tokio::test]
    async fn search_sends_the_nvd_filters() {
        use std::sync::Mutex;
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        let app = Router::new().route(
            "/rest/json/cves/2.0",
            get(move |uri: axum::http::Uri| {
                let log = log.clone();
                async move {
                    log.lock().unwrap().push(uri.query().unwrap_or_default().to_string());
                    Json(json!({"totalResults": 0, "vulnerabilities": []}))
                }
            }),
        );
        let e = env_up(app).await;
        let r = e.call("cve_search", json!({"query": "heap overflow", "vendor": "Acme", "kev": true})).await;
        assert!(r.text.contains("no matches"), "{}", r.text);
        let q = seen.lock().unwrap().first().cloned().unwrap();
        assert!(q.contains("keywordSearch=heap+overflow") || q.contains("keywordSearch=heap%20overflow"), "{q}");
        assert!(q.contains("virtualMatchString=cpe%3A2.3%3A*%3Aacme") || q.contains("virtualMatchString=cpe:2.3:*:acme"), "{q}");
        assert!(q.contains("resultsPerPage=40") && q.contains("noRejected") && q.contains("hasKev"), "{q}");
    }

    #[tokio::test]
    async fn search_without_a_starting_filter_is_refused() {
        let e = env_up(upstream()).await;
        for args in [json!({}), json!({"min_cvss": 7}), json!({"min_epss": 0.5, "kev": false})] {
            let r = e.call("cve_search", args).await;
            assert_eq!(r.status, ToolStatus::Error, "{}", r.text);
            assert!(r.text.contains("at least one of `query`"), "{}", r.text);
        }
        let r = e.call("cve_search", json!({"query": "x", "min_epss": 50})).await;
        assert!(r.text.contains("between 0 and 1"), "{}", r.text);
    }

    #[tokio::test]
    async fn search_survives_an_epss_outage_unless_min_epss_needs_it() {
        let app = Router::new()
            .route(
                "/rest/json/cves/2.0",
                get(|| async { Json(nvd_page(vec![cve_json("CVE-2024-0001", json!({}))])) }),
            )
            .route("/data/v1/epss", get(|| async { StatusCode::SERVICE_UNAVAILABLE }));
        let e = env_up(app).await;
        let r = e.call("cve_search", json!({"query": "thing"})).await;
        assert_eq!(r.status, ToolStatus::Ok, "{}", r.text);
        assert!(e.stored(&r).contains("EPSS lookup failed"), "{}", e.stored(&r));
        let r = e.call("cve_search", json!({"query": "thing", "min_epss": 0.1})).await;
        assert_eq!(r.status, ToolStatus::Error, "{}", r.text);
        assert!(r.text.contains("`min_epss` cannot be applied"), "{}", r.text);
    }

    #[tokio::test]
    async fn advisories_with_and_without_a_version() {
        let e = env_up(upstream()).await;
        let r = e.call("advisory_lookup", json!({"name": "lodash", "ecosystem": "npm"})).await;
        assert_eq!(r.status, ToolStatus::Ok, "{}", r.text);
        assert!(r.text.contains("3 advisories"), "{}", r.text);
        let t = e.stored(&r);
        assert!(t.lines().next().unwrap().contains("3 advisories for lodash (npm), all versions"), "{t}");
        assert!(t.contains("not whether the vulnerable code is reachable"), "{t}");
        assert!(t.contains("GHSA-aaaa-bbbb-cccc  HIGH  CVE-2020-1111  Prototype pollution\n"), "{t}");
        assert!(t.contains("PYSEC-2020-1  CVSS_V3 CVSS:3.1/AV:N  -  Details only here."), "{t}");
        assert!(t.contains("GHSA-dddd  severity n/a  CVE-2019-2  Only without version"), "{t}");
        let raw_id = r.meta.get(META_RAW_BLOB).and_then(Value::as_str).unwrap();
        let raw = e.ctx.blobs.read_all(&e.ctx.blobs.resolve(raw_id).unwrap()).unwrap();
        assert!(String::from_utf8(raw).unwrap().contains("\"vulns\""));

        let r = e.call("advisory_lookup", json!({"name": "lodash", "ecosystem": "npm", "version": "4.17.0"})).await;
        assert!(r.text.contains("2 advisories"), "{}", r.text);
        let t = e.stored(&r);
        assert!(t.contains("for lodash 4.17.0 (npm)") && !t.contains("GHSA-dddd"), "{t}");
        let raw_id = r.meta.get(META_RAW_BLOB).and_then(Value::as_str).unwrap();
        let raw = e.ctx.blobs.read_all(&e.ctx.blobs.resolve(raw_id).unwrap()).unwrap();
        assert!(String::from_utf8(raw).unwrap().contains("\"echo_version\":\"4.17.0\""));
    }

    #[tokio::test]
    async fn advisories_none_is_ok() {
        let e = env_up(upstream()).await;
        let r = e.call("advisory_lookup", json!({"name": "empty", "ecosystem": "NoSuchEco"})).await;
        assert_eq!(r.status, ToolStatus::Ok, "{}", r.text);
        assert!(r.text.contains("none"), "{}", r.text);
        assert!(r.text.contains("OSV lists no advisories for empty (NoSuchEco)"), "{}", r.text);
    }

    #[tokio::test]
    async fn osv_rejection_is_an_observation() {
        let app = Router::new().route(
            "/v1/query",
            post(|| async { (StatusCode::BAD_REQUEST, Json(json!({"code": 3, "message": "Invalid ecosystem."}))) }),
        );
        let e = env_up(app).await;
        let r = e.call("advisory_lookup", json!({"name": "x", "ecosystem": "bogus"})).await;
        assert_eq!(r.status, ToolStatus::Ok, "{}", r.text);
        assert!(r.text.contains("OSV HTTP 400") && r.text.contains("Invalid ecosystem."), "{}", r.text);
    }

    #[tokio::test]
    async fn advisory_list_is_capped() {
        let app = Router::new().route(
            "/v1/query",
            post(|| async {
                let vulns: Vec<Value> = (0..60).map(|i| json!({"id": format!("V-{i}")})).collect();
                Json(json!({"vulns": vulns}))
            }),
        );
        let e = env_up(app).await;
        let r = e.call("advisory_lookup", json!({"name": "x", "ecosystem": "npm"})).await;
        let t = e.stored(&r);
        assert!(r.text.contains("60 advisories"), "{}", r.text);
        assert!(t.contains("Showing the first 50 of 60"), "{t}");
        assert_eq!(t.lines().filter(|l| l.starts_with("V-")).count(), 50);
    }

    /// A stand-in egress proxy that refuses everything the way the real one does.
    async fn refusing_proxy() -> String {
        serve(Router::new().fallback(|| async {
            let mut h = HeaderMap::new();
            h.insert("x-loom-proxy", HeaderValue::from_static("1"));
            (StatusCode::FORBIDDEN, h, "host not allowed by policy")
        }))
        .await
    }

    #[tokio::test]
    async fn proxy_refusal_is_denied_and_names_the_host() {
        let proxy = refusing_proxy().await;
        let mut e = env();
        let mut vars = std::collections::BTreeMap::new();
        vars.insert("HTTP_PROXY".to_string(), proxy);
        e.ctx.env = Arc::new(vars);
        let ep = Endpoints { nvd: "http://nvd.blocked.invalid".into(), epss: "http://epss.blocked.invalid".into(), osv: "http://osv.blocked.invalid".into() };
        for which in 0..3 {
            e.registry.add(Arc::new(Seam { ep: ep.clone(), which }));
        }
        let r = e.call("cve_lookup", json!({"id": "CVE-2021-44228"})).await;
        assert_eq!(r.status, ToolStatus::Denied, "{}", r.text);
        assert!(r.text.contains("nvd.blocked.invalid") && r.text.contains("network allowlist"), "{}", r.text);
        assert!(r.text.contains("host not allowed by policy"), "{}", r.text);
        let r = e.call("cve_search", json!({"query": "x"})).await;
        assert_eq!(r.status, ToolStatus::Denied, "{}", r.text);
        let r = e.call("advisory_lookup", json!({"name": "x", "ecosystem": "npm"})).await;
        assert_eq!(r.status, ToolStatus::Denied, "{}", r.text);
        assert!(r.text.contains("osv.blocked.invalid"), "{}", r.text);
    }

    #[tokio::test]
    async fn an_https_refusal_by_the_real_proxy_names_its_rule_and_an_unreachable_host_is_not_one() {
        use loom_core::config::{NetworkCfg, NetworkMode};
        let deny = vec!["*.blocked.test".to_string()];
        let cfg = NetworkCfg { mode: NetworkMode::Open, allow: Vec::new(), deny, allow_private: vec!["127.0.0.1".into()] };
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let proxy = loom_net::Proxy::start(0, tx).await.unwrap();
        let grant = proxy.grant(&loom_core::SessionId::from("s-cve"), loom_net::Policy::new(&cfg).unwrap());
        let mut e = env();
        e.ctx.env = Arc::new(grant.env());
        seamed(&mut e, "https://nvd.blocked.test");
        let r = e.call("cve_lookup", json!({"id": "CVE-2021-44228"})).await;
        assert_eq!(r.status, ToolStatus::Denied, "{}", r.text);
        assert!(r.text.contains("refused by rule `deny *.blocked.test`") && r.text.contains("nvd.blocked.test"), "{}", r.text);
        // Allowed, but nothing listens there: an error naming the proxy's rule, not a refusal.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut e = env();
        e.ctx.env = Arc::new(grant.env());
        seamed(&mut e, &format!("https://127.0.0.1:{port}"));
        let r = e.call("cve_lookup", json!({"id": "CVE-2021-44228"})).await;
        assert_eq!(r.status, ToolStatus::Error, "{}", r.text);
        assert!(r.text.contains("which allows it by rule `allow_private 127.0.0.1`"), "{}", r.text);
        drop(proxy);
    }

    #[tokio::test]
    async fn an_https_request_that_fails_to_connect_after_the_check_puts_the_question_again() {
        use loom_core::config::{NetworkCfg, NetworkMode};
        use loom_core::{event::NetDecision, SessionId};
        let private = vec!["127.0.0.1".to_string()];
        let cfg = NetworkCfg { mode: NetworkMode::Open, allow_private: private, ..NetworkCfg::default() };
        let deny_all = NetworkCfg { mode: NetworkMode::DenyAll, ..NetworkCfg::default() };
        // The policy changes between the check and the CONNECT, which is refused; asked again, the
        // proxy says so.
        let cell: Arc<std::sync::OnceLock<loom_net::Proxy>> = Arc::default();
        let handle = cell.clone();
        let audit: loom_net::AuditFn = Arc::new(move |s: Option<&SessionId>, d: &NetDecision| {
            if let (Some(p), Some(s), true) = (handle.get(), s, d.method == loom_net::CHECK_METHOD && d.allowed) {
                p.set_policy(s, loom_net::Policy::new(&deny_all).unwrap());
            }
            Ok(())
        });
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let proxy = loom_net::Proxy::start_with(0, tx, Some(audit), loom_net::Limits::default()).await.unwrap();
        let _ = cell.set(proxy.clone());
        let grant = proxy.grant(&SessionId::from("s-cve-again"), loom_net::Policy::new(&cfg).unwrap());
        let mut e = env();
        e.ctx.env = Arc::new(grant.env());
        seamed(&mut e, "https://127.0.0.1:9");
        let r = e.call("cve_lookup", json!({"id": "CVE-2021-44228"})).await;
        assert_eq!(r.status, ToolStatus::Denied, "{}", r.text);
        assert!(r.text.contains("refused by rule `mode deny_all`"), "{}", r.text);
        proxy.shutdown();
        // A proxy that gives no verdict (here every connection of the session is over its limit) is
        // named as what stopped the request, not a service that may be down.
        let limits = loom_net::Limits { max_per_session: 0, ..loom_net::Limits::default() };
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let proxy = loom_net::Proxy::start_with(0, tx, None, limits).await.unwrap();
        let grant = proxy.grant(&SessionId::from("s-cve-busy"), loom_net::Policy::new(&cfg).unwrap());
        let mut e = env();
        e.ctx.env = Arc::new(grant.env());
        seamed(&mut e, "https://127.0.0.1:9");
        let r = e.call("cve_lookup", json!({"id": "CVE-2021-44228"})).await;
        assert_eq!(r.status, ToolStatus::Error, "{}", r.text);
        let expected = "the egress proxy did not open a tunnel to the destination and gave no verdict on it";
        assert!(r.text.contains(expected) && !r.text.contains("could not connect"), "{}", r.text);
    }

    #[tokio::test]
    async fn cancel_interrupts() {
        let app = Router::new().fallback(|| async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            "late"
        });
        let e = env_up(app).await;
        let cancel = e.ctx.cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            cancel.cancel();
        });
        let r = e.call("cve_lookup", json!({"id": "CVE-2021-44228"})).await;
        assert_eq!(r.status, ToolStatus::Interrupted, "{}", r.text);
        assert!(r.text.contains("cancelled"), "{}", r.text);
    }

    #[tokio::test]
    async fn timeout_is_an_error_that_says_so() {
        let app = Router::new().fallback(|| async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            "late"
        });
        let base = serve(app).await;
        let cfg = ToolsCfg { web_fetch_timeout_s: 1, ..ToolsCfg::default() };
        let mut e = env_with(cfg, SandboxCfg { mode: SandboxMode::None, ..SandboxCfg::default() });
        seamed(&mut e, &base);
        let r = e.call("cve_lookup", json!({"id": "CVE-2021-44228"})).await;
        assert_eq!(r.status, ToolStatus::Error, "{}", r.text);
        assert!(r.text.contains("timed out after 1 s"), "{}", r.text);
    }

    #[test]
    fn production_endpoints_are_the_constants() {
        let ep = Endpoints::default();
        assert_eq!((ep.nvd.as_str(), ep.epss.as_str(), ep.osv.as_str()), (NVD_BASE, EPSS_BASE, OSV_BASE));
    }
}
