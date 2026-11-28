//! Stateful structured HTTP, with bounded replay and race batches.
//!
//! CONTRACT: every exchange uses the ordinary session proxy (never the reference credential), no
//! automatic redirects, no ambient proxy/cookie state, valid HTTP framing recomputed by reqwest.
//! Content-Length, Transfer-Encoding, Host and proxy headers supplied by the model are discarded.
//! Raw desynchronization is deliberately not implemented by this structured client. Session-ending,
//! destructive-lifecycle, and single-use token URLs (after up to three rounds of percent-decoding) are
//! refused unless `allow_quarantined: true` is passed. A per-session RFC cookie jar, origin-bound
//! captures, and a bounded per-route status matrix survive calls, but are discarded at restart.
//! HTML responses include bounded `<form>` and field metadata (`hidden`, `readonly`, `disabled`).
//! Cross-principal `2xx` vs `401/403` status differentials on normalized route templates are surfaced
//! as observations, never independent goal or authorization oracles. Request IDs name completed
//! exchanges only. Race batches (2..20) release together, then respect the daemon-wide two-request
//! host semaphore; they do not promise simultaneous wire arrival.

use crate::{
    params::{opt, req, spec},
    Body, Tool, ToolCtx, ToolOutput,
};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use ferret_core::event::{ToolClass, ToolSpec, ToolStatus};
use futures_util::{future::join_all, StreamExt};
use reqwest::{
    cookie::{CookieStore, Jar},
    header::{HeaderMap, HeaderName, HeaderValue},
    Client, Method, Proxy,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};
use tokio::sync::{Barrier, Semaphore};
use url::Url;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub url: String,
    #[serde(default = "get")]
    pub method: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub body_base64: Option<String>,
    #[serde(default)]
    pub json: Option<Value>,
}
fn get() -> String {
    "GET".into()
}

#[derive(Clone)]
struct Variable {
    value: String,
    origin: String,
}

type RouteKey = (String, String, String);
type PrincipalObservations = BTreeMap<String, (String, u16)>;

#[derive(Default)]
pub struct HttpState {
    jar: Arc<Jar>,
    requests: BTreeMap<String, Request>,
    variables: BTreeMap<String, Variable>,
    route_matrix: BTreeMap<RouteKey, PrincipalObservations>,
    next: u64,
}

pub struct HttpSend;
pub struct HttpRepeat;
pub struct HttpAuthzMatrix;

fn fields() -> Vec<crate::params::Param> {
    vec![
        opt("capture", "object", "name -> json:/pointer, header:Name, or regex:pattern (first group).")
            .with("additionalProperties", json!({"type":"string"})),
        opt(
            "race_count",
            "integer",
            "1 normally; 2..20 releases a bounded batch together, still subject to target concurrency limits.",
        )
        .min(1)
        .max(20),
        opt("timeout_s", "integer", "Whole batch timeout, default 30 seconds; maximum 120.").min(1).max(120),
        opt(
            "allow_quarantined",
            "boolean",
            "Explicitly permit requesting a quarantined logout, unsubscribe, or single-use token URL (default false).",
        ),
        opt(
            "as_profile",
            "string",
            "Named mounted credential profile to inject for this request (or \"anon\" for unauthenticated). Strips existing auth headers and bypasses session jar cookies when switching away from the default profile.",
        ),
        opt(
            "strip_auth",
            "boolean",
            "Strip existing auth headers, skip session jar cookies, and disable credential profile injection (default false).",
        ),
    ]
}

#[async_trait]
impl Tool for HttpSend {
    fn spec(&self) -> ToolSpec {
        let mut p = vec![req(
            "request",
            "object",
            "URL, method, headers, body/body_base64/json. Only one body form; no automatic redirects.",
        )
        .with("additionalProperties", json!(true))];
        p.extend(fields());
        spec(
            "http_send",
            "Send a structured HTTP request through the session's scoped egress proxy. Keep cookies between calls, capture origin-bound variables, and store complete bounded exchanges. Headers/body are evidence and may contain secrets; avoid unnecessary credentials.",
            ToolClass::Exec,
            &p,
        )
    }
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let request = match serde_json::from_value(args.get("request").cloned().unwrap_or(Value::Null)) {
            Ok(r) => r,
            Err(e) => return ToolOutput::error(format!("Correct the request object: {e}.")),
        };
        run(ctx, "http_send", request, args).await
    }
}

#[async_trait]
impl Tool for HttpRepeat {
    fn spec(&self) -> ToolSpec {
        let mut p=vec![req("request_id","string","A completed rq ID, an ex- id of a recorded exchange (works after a restart), or last."),opt("patch","object","Overlay method, path, query, headers (null deletes), cookies, json, body or body_base64. Origin changes are refused.").with("additionalProperties",json!(true))];
        p.extend(fields());
        spec(
            "http_repeat",
            "Replay a stored HTTP request with a structured patch. Preserve session cookies and recompute framing; no raw-smuggling mode.",
            ToolClass::Exec,
            &p,
        )
    }
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let id = args.get("request_id").and_then(Value::as_str).unwrap_or_default();
        if id.trim().is_empty() {
            return ToolOutput::error("Supply a complete request_id or last.");
        }
        let (mut r, from_ex) = match resolve_saved_request(ctx, id).await {
            Ok(found) => found,
            Err(e) => return ToolOutput::error(e),
        };
        if let Some(p) = args.get("patch").and_then(Value::as_object) {
            if let Err(e) = patch(&mut r, p) {
                return ToolOutput::error(e);
            }
        }
        let mut out = run(ctx, "http_repeat", r, args).await;
        if from_ex {
            out.more.push(format!(
                "{id} was replayed from its stored request; its cookie jar and captured variables are not restored, so use `as_profile`, headers, or the patch for authentication."
            ));
        }
        out
    }
}

async fn resolve_saved_request(ctx: &ToolCtx, raw_id: &str) -> Result<(Request, bool), String> {
    let id = raw_id.trim();
    if id.starts_with("ex-") {
        return Ok((stored_request(ctx, id)?, true));
    }
    let state = ctx.capabilities.http.lock().await;
    let resolved_id: String = if id == "last" {
        state
            .requests
            .keys()
            .max_by_key(|k| k.strip_prefix("rq").and_then(|v| v.parse::<u64>().ok()).unwrap_or(0))
            .cloned()
            .unwrap_or_default()
    } else if let Some(rest) = id.strip_prefix("req-") {
        let alias = format!("rq{rest}");
        if state.requests.contains_key(id) {
            id.to_string()
        } else if state.requests.contains_key(&alias) {
            alias
        } else {
            id.to_string()
        }
    } else {
        id.to_string()
    };
    let request = state.requests.get(&resolved_id).cloned().or_else(|| {
        let mut matches = state.requests.iter().filter(|(k, _)| k.starts_with(&resolved_id));
        match (matches.next(), matches.next()) {
            (Some((_, r)), None) => Some(r.clone()),
            _ => None,
        }
    });
    drop(state);
    request.map(|r| (r, false)).ok_or_else(|| {
        "Request ID is unknown or ambiguous. Use a complete rq ID from this session or an ex- exchange ID; restart discards rq replay state."
            .into()
    })
}

/// Headers stripped when replaying proxy-captured exchanges (which may carry injected or rewritten
/// credentials that the model must not replay to arbitrary paths).
fn is_sensitive_auth_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization" | "proxy-authorization" | "cookie" | "x-api-key" | "x-auth-token"
    )
}

/// True when a stored header value contains a redaction placeholder produced by secret/credential scrubbing.
fn is_redacted_header_value(value: &str) -> bool {
    value.to_ascii_lowercase().contains("[redacted]")
}

/// The request of a recorded exchange (`ex-` id), read from the session log and the blob store, so it works
/// after a restart.
fn stored_request(ctx: &ToolCtx, id: &str) -> Result<Request, String> {
    let lookup =
        ctx.capabilities.exchange_lookup.get().ok_or("Recorded exchanges cannot be replayed in this session.")?;
    let x = lookup(id).ok_or_else(|| {
        format!("No exchange {id} was recorded by this session. Copy the id from an http_send result or the log.")
    })?;
    if x.method == "TLS" || (x.source == "proxy" && !matches!(x.tls.as_str(), "plain" | "intercepted")) {
        return Err(format!("{id} is not a replayable HTTP request."));
    }
    if x.tool.as_deref().is_some_and(|t| t.starts_with("mcp__")) {
        return Err(format!("{id} is an MCP transport exchange and cannot be replayed with http_repeat."));
    }
    if x.truncated && x.request_bytes > crate::traffic::CAPTURE_MAX_BYTES as u64 {
        return Err(format!(
            "The request of {id} was stored cut at {} bytes; replaying it would send a different body.",
            crate::traffic::CAPTURE_MAX_BYTES
        ));
    }
    let bytes =
        ctx.blobs.read_all(&x.request.id).map_err(|e| format!("The stored request of {id} could not be read: {e}."))?;
    let (method, headers, body) =
        crate::traffic::parse_request(&bytes).ok_or("The stored request is not a readable HTTP message.")?;
    let from_proxy = x.source == "proxy";
    let filtered_headers: BTreeMap<String, String> = headers
        .into_iter()
        .filter(|(k, v)| {
            if from_proxy && (is_sensitive_auth_header(k) || is_redacted_header_value(v)) {
                return false;
            }
            if is_sensitive_auth_header(k) && is_redacted_header_value(v) {
                return false;
            }
            true
        })
        .collect();
    let url = if x.target.starts_with("http://") || x.target.starts_with("https://") {
        x.target.clone()
    } else {
        let default_port = if x.scheme == "https" { 443 } else { 80 };
        let host = if x.port == default_port { x.host.clone() } else { format!("{}:{}", x.host, x.port) };
        format!("{}://{host}{}", x.scheme, x.target)
    };
    let mut r = Request { url, method, headers: filtered_headers, body: String::new(), body_base64: None, json: None };
    if !body.is_empty() {
        r.body_base64 = Some(STANDARD.encode(&body));
    }
    Ok(r)
}

fn checked_url(s: &str) -> Result<Url, String> {
    let u = Url::parse(s).map_err(|e| format!("Use a full http(s) URL: {e}."))?;
    if !matches!(u.scheme(), "http" | "https")
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
    {
        return Err(
            "Use an http(s) URL with a host and no embedded credentials. Supply explicit headers instead.".into()
        );
    }
    Ok(u)
}

fn patch(r: &mut Request, p: &Map<String, Value>) -> Result<(), String> {
    for k in p.keys() {
        if !["method", "path", "query", "headers", "cookies", "json", "body", "body_base64"].contains(&k.as_str()) {
            return Err(format!("Unknown replay patch field {k}; the request origin cannot be changed."));
        }
    }
    let mut u = checked_url(&r.url)?;
    if let Some(v) = p.get("path") {
        u.set_path(v.as_str().ok_or("path must be a string.")?);
    }
    if let Some(v) = p.get("query") {
        let q = v.as_object().ok_or("query must be an object of string values.")?;
        let mut qp = u.query_pairs_mut();
        qp.clear();
        for (k, v) in q {
            qp.append_pair(k, v.as_str().ok_or("query values must be strings.")?);
        }
    }
    r.url = u.to_string();
    if let Some(v) = p.get("method") {
        r.method = v.as_str().ok_or("method must be a string.")?.into();
    }
    if let Some(v) = p.get("headers") {
        for (k, v) in v.as_object().ok_or("headers must be an object.")? {
            r.headers.retain(|old, _| !old.eq_ignore_ascii_case(k));
            if !v.is_null() {
                r.headers.insert(k.clone(), v.as_str().ok_or("header values must be strings or null.")?.into());
            }
        }
    }
    if let Some(v) = p.get("cookies") {
        let mut values = Vec::new();
        for (k, v) in v.as_object().ok_or("cookies must be an object.")? {
            let val = v.as_str().ok_or("cookie values must be strings.")?;
            if k.contains([';', '\r', '\n', '=']) || val.contains([';', '\r', '\n']) {
                return Err("Cookie names/values cannot contain framing delimiters.".into());
            }
            values.push(format!("{k}={val}"));
        }
        r.headers.retain(|k, _| !k.eq_ignore_ascii_case("cookie"));
        r.headers.insert("Cookie".into(), values.join("; "));
    }
    let forms = ["body", "body_base64", "json"].iter().filter(|k| p.contains_key(**k)).count();
    if forms > 1 {
        return Err("Choose one body, body_base64 or json patch.".into());
    }
    if forms == 1 {
        r.body.clear();
        r.body_base64 = None;
        r.json = None;
    }
    if let Some(v) = p.get("body") {
        r.body = v.as_str().ok_or("body must be a string.")?.into();
    }
    if let Some(v) = p.get("body_base64") {
        r.body_base64 = Some(v.as_str().ok_or("body_base64 must be a string.")?.into());
    }
    if let Some(v) = p.get("json") {
        r.json = Some(v.clone());
    }
    Ok(())
}

fn expand(s: &str, vars: &BTreeMap<String, Variable>, origin: &str) -> Result<String, String> {
    let mut result = String::new();
    let mut rest = s;
    while let Some((a, b)) = rest.split_once("{{") {
        result.push_str(a);
        let (name, tail) = b.split_once("}}").ok_or("Close the {{variable}} placeholder.")?;
        let v = vars.get(name).ok_or_else(|| format!("Capture variable {name} before using it."))?;
        if v.origin != origin {
            return Err(format!(
                "Variable {name} belongs to a different origin; cross-origin capture replay is refused."
            ));
        }
        result.push_str(&v.value);
        rest = tail;
        if result.len() > 2_000_000 {
            return Err("Expanded request exceeds two million bytes.".into());
        }
    }
    result.push_str(rest);
    Ok(result)
}

/// `insecure`: do not verify the server certificate (S12; the caller asks `web::insecure_for_str`).
pub(crate) fn client(ctx: &ToolCtx, jar: Arc<Jar>, insecure: bool) -> Result<Client, String> {
    let mut b = Client::builder()
        .danger_accept_invalid_certs(insecure)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .pool_max_idle_per_host(0)
        .cookie_provider(jar);
    if let Some(p) = crate::web::session_proxy(ctx) {
        b = b.proxy(Proxy::all(p).map_err(|_| "The session proxy is invalid; ask the operator to fix it.")?);
    } else if !cfg!(test) {
        return Err("The session egress proxy is absent. Ask the operator to fix session network setup; direct HTTP is refused.".into());
    }
    b.build().map_err(|e| format!("The HTTP client could not be built: {e}."))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FormField {
    pub name: String,
    pub kind: String,
    pub hidden: bool,
    pub readonly: bool,
    pub disabled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FormSurface {
    pub action: String,
    pub method: String,
    pub fields: Vec<FormField>,
}

pub fn quarantined_locator(url_str: &str) -> Option<&'static str> {
    const SESSION_SEGMENTS: &[&str] = &[
        "logout",
        "log-out",
        "signout",
        "sign-out",
        "unsubscribe",
        "revoke-session",
        "delete-account",
        "close-account",
    ];
    const TOKEN_SEGMENTS: &[&str] = &[
        "reset-password",
        "password-reset",
        "verify-email",
        "email-verify",
        "magic-link",
        "confirm-email",
        "accept-invite",
    ];
    const TOKEN_QUERY_KEYS: &[&str] =
        &["oobcode", "magic_token", "invite_token", "unsubscribe_token", "reset_token", "verification_token"];

    let decoded = crate::capabilities::decode_percent_rounds(url_str, 3);
    for candidate in [url_str, decoded.as_str()] {
        let Ok(url) = Url::parse(candidate) else { continue };
        for seg in url.path().split('/') {
            let norm = crate::capabilities::decode_percent_rounds(seg.trim(), 2).to_ascii_lowercase();
            if SESSION_SEGMENTS.contains(&norm.as_str()) {
                return Some("session-terminating or destructive lifecycle endpoint");
            }
            if TOKEN_SEGMENTS.contains(&norm.as_str()) {
                return Some("single-use token or account-verification endpoint");
            }
        }
        for (k, _) in url.query_pairs() {
            let key = crate::capabilities::decode_percent_rounds(k.trim(), 2).to_ascii_lowercase();
            if TOKEN_QUERY_KEYS.contains(&key.as_str()) {
                return Some("single-use query token parameter");
            }
        }
    }
    None
}

pub fn is_static_asset_locator(url_str: &str) -> bool {
    const STATIC_EXTS: &[&str] = &[
        ".css", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".mp4", ".webm", ".mp3",
    ];
    let Ok(url) = Url::parse(url_str) else { return false };
    if url.query().is_some() {
        return false;
    }
    let Some(last) = url.path().rsplit('/').find(|s| !s.is_empty()) else { return false };
    let lower = last.to_ascii_lowercase();
    STATIC_EXTS.iter().any(|ext| lower.ends_with(ext))
}

fn is_uuid_segment(seg: &str) -> bool {
    if seg.len() != 36 {
        return false;
    }
    let parts: Vec<&str> = seg.split('-').collect();
    matches!(
        parts.as_slice(),
        [a, b, c, d, e]
            if a.len() == 8
                && b.len() == 4
                && c.len() == 4
                && d.len() == 4
                && e.len() == 12
                && [a, b, c, d, e].iter().all(|p| p.bytes().all(|ch| ch.is_ascii_hexdigit()))
    )
}

pub fn route_template(path: &str) -> String {
    if path.is_empty() || path == "/" {
        return "/".into();
    }
    let normalized: Vec<&str> = path
        .split('/')
        .map(|seg| {
            if seg.is_empty() {
                ""
            } else if is_uuid_segment(seg) {
                "{uuid}"
            } else if (1..=20).contains(&seg.len()) && seg.bytes().all(|b| b.is_ascii_digit()) {
                "{id}"
            } else if seg.len() >= 16 && seg.len().is_multiple_of(2) && seg.bytes().all(|b| b.is_ascii_hexdigit()) {
                "{hex}"
            } else {
                seg
            }
        })
        .collect();
    let joined = normalized.join("/");
    if joined.is_empty() {
        "/".into()
    } else {
        joined
    }
}

fn html_attr(attrs: &str, name: &str) -> Option<String> {
    let pattern = format!(r#"(?i)\b{name}\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>"']+))"#);
    let re = regex::Regex::new(&pattern).ok()?;
    let caps = re.captures(attrs)?;
    caps.get(1).or_else(|| caps.get(2)).or_else(|| caps.get(3)).map(|m| m.as_str().to_string())
}

fn html_flag(attrs: &str, name: &str) -> bool {
    let pattern = format!(r"(?i)(?:^|\s){name}(?:\s|=|$)");
    regex::Regex::new(&pattern).ok().is_some_and(|re| re.is_match(attrs))
}

fn extract_forms(headers: &BTreeMap<String, String>, body_text: &str) -> Vec<FormSurface> {
    let ct_html = headers.get("content-type").is_some_and(|ct| ct.to_ascii_lowercase().contains("html"));
    let trimmed = body_text.trim_start();
    let head: String = trimmed.chars().take(32).collect();
    let head_lower = head.to_ascii_lowercase();
    let body_html =
        head_lower.starts_with("<!doctype html") || head_lower.starts_with("<html") || head_lower.starts_with("<form");
    if !ct_html && !body_html {
        return Vec::new();
    }
    let bounded: String = body_text.chars().take(131_072).collect();
    let Ok(form_re) = regex::Regex::new(r"(?is)<form\b([^>]*)>(.*?)</form>") else { return Vec::new() };
    let Ok(field_re) = regex::Regex::new(r"(?is)<(input|select|textarea)\b([^>]*)>") else { return Vec::new() };
    let mut forms = Vec::new();
    for caps in form_re.captures_iter(&bounded).take(16) {
        let attrs = caps.get(1).map_or("", |m| m.as_str());
        let inner = caps.get(2).map_or("", |m| m.as_str());
        let action = html_attr(attrs, "action").unwrap_or_default();
        let method = html_attr(attrs, "method").unwrap_or_else(|| "GET".into()).to_ascii_uppercase();
        let mut fields = Vec::new();
        for fcaps in field_re.captures_iter(inner).take(32) {
            let tag = fcaps.get(1).map_or("input", |m| m.as_str()).to_ascii_lowercase();
            let fattrs = fcaps.get(2).map_or("", |m| m.as_str());
            let name = html_attr(fattrs, "name").unwrap_or_default();
            if name.is_empty() {
                continue;
            }
            let kind = if tag == "input" {
                html_attr(fattrs, "type").unwrap_or_else(|| "text".into()).to_ascii_lowercase()
            } else {
                tag
            };
            let hidden = kind == "hidden" || html_flag(fattrs, "hidden");
            let readonly = html_flag(fattrs, "readonly");
            let disabled = html_flag(fattrs, "disabled");
            fields.push(FormField { name, kind, hidden, readonly, disabled });
        }
        forms.push(FormSurface { action, method, fields });
    }
    forms
}

fn principal_tag(
    resolved_principal: &str,
    inject: Option<&ferret_net::Inject>,
    explicit_profile: bool,
    jar: Option<&Jar>,
    url: &Url,
    r: &Request,
) -> String {
    let host = url.host_str().unwrap_or_default();
    if resolved_principal != "anon" && (explicit_profile || inject.is_some_and(|i| i.applies_to(host))) {
        return resolved_principal.to_string();
    }
    let mut material = Vec::new();
    if let Some(jar) = jar {
        if let Some(cookie) = jar.cookies(url) {
            if !cookie.is_empty() {
                material.push(format!("jar={}", String::from_utf8_lossy(cookie.as_bytes())));
            }
        }
    }
    for (k, v) in &r.headers {
        let low = k.to_ascii_lowercase();
        if ["cookie", "authorization", "x-api-key", "x-auth-token"].contains(&low.as_str()) && !v.trim().is_empty() {
            material.push(format!("{low}={}", v.trim()));
        }
    }
    if material.is_empty() {
        return "anon".into();
    }
    material.sort();
    let digest = hex::encode(Sha256::digest(material.join("\n").as_bytes()));
    format!("auth:{}", digest.get(..8).unwrap_or_default())
}

fn is_non_default_profile(ctx: &ToolCtx, as_profile: Option<&str>) -> bool {
    let Some(name) = as_profile.map(str::trim).filter(|s| !s.is_empty()) else {
        return false;
    };
    if name == "anon" {
        return true;
    }
    if let Some(def) = ctx.capabilities.default_profile.get().map(String::as_str).filter(|s| !s.is_empty()) {
        return name != def;
    }
    !(name == "default" && ctx.capabilities.creds.get().is_some())
}

impl HttpState {
    fn record_route_status(
        &mut self,
        origin: &str,
        method: &str,
        path: &str,
        principal: &str,
        req_id: &str,
        status: u16,
    ) -> Option<Value> {
        let template = route_template(path);
        let key = (origin.to_string(), method.to_ascii_uppercase(), template.clone());
        if !self.route_matrix.contains_key(&key) && self.route_matrix.len() >= 256 {
            return None;
        }
        let by_principal = self.route_matrix.entry(key).or_default();
        if by_principal.contains_key(principal) || by_principal.len() < 16 {
            by_principal.insert(principal.to_string(), (req_id.to_string(), status));
        }
        let allowed = by_principal.iter().find(|(_, (_, code))| (200..300).contains(code));
        let denied = by_principal
            .iter()
            .find(|(p, (_, code))| matches!(code, 401 | 403) && allowed.is_some_and(|(ap, _)| *p != ap));
        let ((ap, (aid, acode)), (dp, (did, dcode))) = (allowed?, denied?);
        Some(json!({
            "route_template": template,
            "allowed": { "request_id": aid, "principal": ap, "status": acode },
            "denied": { "request_id": did, "principal": dp, "status": dcode },
        }))
    }
}

#[derive(Serialize)]
pub(crate) struct Exchange {
    request: Request,
    pub status: u16,
    headers: BTreeMap<String, String>,
    body_base64: String,
    pub body_text: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub forms: Vec<FormSurface>,
    pub truncated: bool,
    pub read_error: Option<String>,
    pub proxy_generated: bool,
    /// The id of the `exchange` record this one became (C3); not part of the tool's JSON.
    #[serde(skip)]
    ex_id: Option<String>,
}

/// Where the exchanges a call makes are collected (see `traffic`), with the tool's name.
type Sink<'a> = Option<(&'a str, &'a std::sync::Mutex<Vec<ferret_core::event::Exchange>>)>;

pub(crate) async fn one(ctx: &ToolCtx, client: &Client, r: &Request) -> Result<Exchange, String> {
    exchange(ctx, client, r, None, None, None, None).await
}

async fn exchange(
    ctx: &ToolCtx,
    client: &Client,
    r: &Request,
    sink: Sink<'_>,
    jar: Option<&Jar>,
    inject_profile: Option<&ferret_net::Inject>,
    principal: Option<&str>,
) -> Result<Exchange, String> {
    let started = std::time::Instant::now();
    let url = checked_url(&r.url)?;
    let _permit = crate::capabilities::target_permit(url.host_str().unwrap_or_default(), &ctx.cancel).await?;
    let method = Method::from_bytes(r.method.as_bytes()).map_err(|_| "Use a valid HTTP method token.")?;
    if method == Method::CONNECT || method.as_str().eq_ignore_ascii_case(ferret_net::CHECK_METHOD) {
        return Err("CONNECT and harness proxy control methods are not application requests.".into());
    }
    let mut headers = HeaderMap::new();
    for (k, v) in &r.headers {
        if ["host", "content-length", "transfer-encoding", "connection", "trailer", "upgrade"]
            .contains(&k.to_ascii_lowercase().as_str())
            || k.to_ascii_lowercase().starts_with("proxy-")
        {
            continue;
        }
        headers.insert(
            HeaderName::from_bytes(k.as_bytes()).map_err(|_| format!("Invalid header name {k}."))?,
            HeaderValue::from_str(v).map_err(|_| format!("Invalid value for header {k}."))?,
        );
    }
    let body = if let Some(v) = &r.json {
        headers.insert(reqwest::header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
        serde_json::to_vec(v).map_err(|e| e.to_string())?
    } else if let Some(s) = &r.body_base64 {
        STANDARD.decode(s).map_err(|e| format!("Invalid Base64 body: {e}."))?
    } else {
        r.body.as_bytes().to_vec()
    };
    if body.len() > 2_000_000 {
        return Err("Request body exceeds two million bytes; use a smaller bounded request.".into());
    }
    // Credential profile injection (S8): explicit for `http_send`, `http_repeat`, and `http_authz_matrix`;
    // `None` for `oracle.rs` (`http::one`).
    let mut shown: Option<Vec<(String, Vec<u8>)>> = None;
    if let (Some(inject), Some(host)) = (inject_profile, url.host_str()) {
        let had_cookie = headers.contains_key(reqwest::header::COOKIE);
        // reqwest sends the jar only on a request without a `Cookie` header of its own, so a jar cookie is
        // one the request "already sends" exactly then, and the jar is merged by hand if we add a header.
        let jar_cookie = if had_cookie {
            None
        } else {
            jar.and_then(|j| j.cookies(&url)).and_then(|v| v.to_str().ok().map(str::to_string))
        };
        let already: Vec<String> = jar_cookie
            .iter()
            .flat_map(|c| c.split(';'))
            .filter_map(|p| p.split('=').next())
            .map(|n| n.trim().to_string())
            .collect();
        let pairs: Vec<(String, Vec<u8>)> =
            headers.iter().map(|(k, v)| (k.as_str().to_string(), v.as_bytes().to_vec())).collect();
        if let Some(mut inj) = crate::traffic::inject_with(inject, host, &pairs, &already) {
            if let Some(jc) = jar_cookie.filter(|j| !j.is_empty()) {
                for set in [&mut inj.real, &mut inj.shown] {
                    if let Some((_, v)) = set.iter_mut().find(|(n, _)| n.eq_ignore_ascii_case("cookie")) {
                        let mut merged = format!("{jc}; ").into_bytes();
                        merged.extend_from_slice(v);
                        *v = merged;
                    }
                }
            }
            let mut rebuilt = HeaderMap::new();
            for (k, v) in &inj.real {
                if let (Ok(k), Ok(v)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_bytes(v)) {
                    rebuilt.append(k, v);
                }
            }
            headers = rebuilt;
            shown = Some(inj.shown);
        }
    }
    let sent: Vec<(String, String)> = match &shown {
        Some(s) => s.iter().map(|(k, v)| (k.clone(), String::from_utf8_lossy(v).into_owned())).collect(),
        None => headers.iter().map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("(non-UTF8)").to_string())).collect(),
    };
    let request_wire = crate::traffic::request_message(method.as_str(), &url, &sent, &body);
    let method_text = method.as_str().to_string();
    let response = match client.request(method, url.clone()).headers(headers).body(body).send().await {
        Ok(r) => r,
        Err(e) => {
            let msg = format!(
                "HTTP exchange failed: {}. Consult the session egress log for proxy decisions.",
                crate::web::transport_error(ctx, &url, &e)
            );
            if let Some((tool, out)) = sink {
                let made = crate::traffic::Made {
                    tool,
                    url: &url,
                    method: &method_text,
                    request: &request_wire,
                    response: None,
                    status: None,
                    error: Some(msg.clone()),
                    response_cut: false,
                    unverified: crate::web::insecure_for(ctx, &url),
                    started,
                    principal,
                };
                if let Some(x) = crate::traffic::record(ctx, &made) {
                    out.lock().unwrap_or_else(|p| p.into_inner()).push(x);
                }
            }
            return Err(msg);
        }
    };
    let proxy_generated =
        crate::web::marked_by_proxy(crate::web::session_proxy(ctx).is_some(), &url, response.headers());
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("(non-UTF8)").to_string()))
        .collect();
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    let mut truncated = false;
    let mut read_error = None;
    let max = ctx.cfg.web_fetch_max_bytes.min(2_000_000) as usize;
    while let Some(c) = stream.next().await {
        match c {
            Ok(c) => {
                let room = max.saturating_sub(body.len());
                if c.len() > room {
                    body.extend_from_slice(c.get(..room).unwrap_or_default());
                    truncated = true;
                    break;
                }
                body.extend_from_slice(&c);
            }
            Err(e) => {
                read_error = Some(crate::web::error_chain(&e));
                break;
            }
        }
    }
    let body_text = String::from_utf8_lossy(&body).into_owned();
    let forms = extract_forms(&headers, &body_text);
    let mut ex_id = None;
    if let Some((tool, out)) = sink {
        let pairs: Vec<(String, String)> = headers.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        let wire = crate::traffic::response_message(status, &pairs, &body);
        let made = crate::traffic::Made {
            tool,
            url: &url,
            method: &method_text,
            request: &request_wire,
            response: Some(&wire),
            status: Some(status),
            error: read_error.clone(),
            response_cut: truncated,
            unverified: crate::web::insecure_for(ctx, &url),
            started,
            principal,
        };
        if let Some(x) = crate::traffic::record(ctx, &made) {
            ex_id = Some(x.id.clone());
            out.lock().unwrap_or_else(|p| p.into_inner()).push(x);
        }
    }
    Ok(Exchange {
        request: r.clone(),
        status,
        headers,
        body_text,
        forms,
        body_base64: STANDARD.encode(&body),
        truncated,
        read_error,
        proxy_generated,
        ex_id,
    })
}

async fn run(ctx: &ToolCtx, tool: &str, mut r: Request, args: &Map<String, Value>) -> ToolOutput {
    let origin = match checked_url(&r.url) {
        Ok(u) => u.origin().ascii_serialization(),
        Err(e) => return ToolOutput::error(e),
    };
    let as_profile = args.get("as_profile").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty());
    let strip_auth = args.get("strip_auth").and_then(Value::as_bool).unwrap_or(false);
    let (inject_opt, resolved_principal) = match ctx.capabilities.resolve_profile(as_profile, strip_auth) {
        Ok(v) => v,
        Err(e) => return ToolOutput::error(e),
    };
    let state = ctx.capabilities.http.lock().await;
    if state.requests.len() >= 1024 {
        return ToolOutput::error(
            "This session has 1024 saved HTTP requests. Start a fresh bounded child for further exchanges.",
        );
    }
    let session_jar = state.jar.clone();
    let variables = state.variables.clone();
    drop(state);
    let expanded = (|| -> Result<Url, String> {
        r.url = expand(&r.url, &variables, &origin)?;
        let parsed = checked_url(&r.url)?;
        if parsed.origin().ascii_serialization() != origin {
            return Err("URL expansion cannot change the origin.".into());
        }
        r.body = expand(&r.body, &variables, &origin)?;
        for v in r.headers.values_mut() {
            *v = expand(v, &variables, &origin)?;
        }
        if let Some(v) = r.json.take() {
            r.json = Some(expand_json(v, &variables, &origin)?);
        }
        let forms =
            usize::from(!r.body.is_empty()) + usize::from(r.body_base64.is_some()) + usize::from(r.json.is_some());
        if forms > 1 {
            return Err("Choose only one body, body_base64 or json field.".into());
        }
        Ok(parsed)
    })();
    let parsed_url = match expanded {
        Ok(u) => u,
        Err(e) => return ToolOutput::error(e),
    };
    let allow_quarantined = args.get("allow_quarantined").and_then(Value::as_bool).unwrap_or(false);
    if !allow_quarantined {
        if let Some(reason) = quarantined_locator(&r.url) {
            return ToolOutput::error(format!(
                "Quarantined URL refused ({reason}): {}. Pass `allow_quarantined: true` only when the assignment explicitly tests this endpoint.",
                r.url
            ));
        }
    }
    if strip_auth || as_profile.is_some() {
        r.headers.retain(|k, _| !is_sensitive_auth_header(k));
    }
    let skip_jar = strip_auth || is_non_default_profile(ctx, as_profile);
    let active_jar = if skip_jar { Arc::new(Jar::default()) } else { session_jar };
    let jar_for_inject = if skip_jar { None } else { Some(active_jar.clone()) };
    let principal = principal_tag(
        &resolved_principal,
        inject_opt.as_deref(),
        as_profile.is_some(),
        jar_for_inject.as_deref(),
        &parsed_url,
        &r,
    );
    let client = match client(ctx, active_jar, crate::web::insecure_for(ctx, &parsed_url)) {
        Ok(c) => c,
        Err(e) => return ToolOutput::error(e),
    };
    let count = args.get("race_count").and_then(Value::as_u64).unwrap_or(1).clamp(1, 20) as usize;
    let barrier = Arc::new(Barrier::new(count));
    let slots = Arc::new(Semaphore::new(ctx.capabilities.target_concurrency as usize));
    let made: std::sync::Mutex<Vec<ferret_core::event::Exchange>> = std::sync::Mutex::new(Vec::new());
    let made = &made;
    let futures = (0..count).map(|_| {
        let barrier = barrier.clone();
        let slots = slots.clone();
        let client = &client;
        let r = &r;
        let jar_ref = jar_for_inject.as_deref();
        let inject_ref = inject_opt.as_deref();
        let principal_ref = principal.as_str();
        async move {
            barrier.wait().await;
            let _slot = slots.acquire().await.map_err(|_| "HTTP batch closed.".to_string())?;
            exchange(ctx, client, r, Some((tool, made)), jar_ref, inject_ref, Some(principal_ref)).await
        }
    });
    let secs = args.get("timeout_s").and_then(Value::as_u64).unwrap_or(30).clamp(1, 120);
    let result = tokio::select! {biased;_ = ctx.cancel.cancelled()=>return ToolOutput::denied("HTTP batch cancelled. Some requests may have reached the target; do not assume rollback."),
    out=tokio::time::timeout(Duration::from_secs(secs),join_all(futures))=>out};
    let exchanges = match result {
        Ok(r) => r,
        Err(_) => {
            return ToolOutput::error(
                "HTTP batch timed out. Requests may have reached the target; no completed replay IDs were committed. Inspect the target before retrying.",
            );
        }
    };
    let mut state = ctx.capabilities.http.lock().await;
    let mut outputs = Vec::new();
    let mut failed = false;
    for e in exchanges {
        match e {
            Err(e) => {
                failed = true;
                outputs.push(json!({"error":e}));
            }
            Ok(e) => {
                state.next = state.next.saturating_add(1);
                let id = format!("rq{}", state.next);
                state.requests.insert(id.clone(), r.clone());
                let differential =
                    state.record_route_status(&origin, &r.method, parsed_url.path(), &principal, &id, e.status);
                let mut capture_errors = Vec::new();
                if let Some(captures) = args.get("capture").and_then(Value::as_object) {
                    for (name, selector) in captures {
                        if name.len() > 64 || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                            capture_errors.push(format!("Invalid capture name {name}."));
                            continue;
                        }
                        let val = selector.as_str().and_then(|s| capture(&e, s));
                        if let Some(value) = val.filter(|s| s.len() <= 8192) {
                            state.variables.insert(name.clone(), Variable { value, origin: origin.clone() });
                        } else {
                            capture_errors.push(format!("Capture {name} did not match or exceeded 8192 bytes."));
                        }
                    }
                }
                let mut entry =
                    json!({"request_id":id,"exchange_id":e.ex_id,"exchange":e,"capture_errors":capture_errors});
                if let Some(diff) = differential {
                    if let Some(obj) = entry.as_object_mut() {
                        obj.insert("differential_observation".into(), diff);
                    }
                }
                outputs.push(entry);
            }
        }
    }
    let recorded = std::mem::take(&mut *made.lock().unwrap_or_else(|p| p.into_inner()));
    ToolOutput{status:if failed{ToolStatus::Error}else{ToolStatus::Ok},outcome:format!("{} HTTP exchanges",outputs.len()),more:vec!["redirects not followed; race workers respect a two-request per-host limit; captures/cookies are session-local".into()],body:Body::Raw(json!(outputs).to_string().into_bytes()),meta:Map::new()}.with_exchanges(&recorded)
}

fn expand_json(v: Value, vars: &BTreeMap<String, Variable>, origin: &str) -> Result<Value, String> {
    Ok(match v {
        Value::String(s) => Value::String(expand(&s, vars, origin)?),
        Value::Array(a) => Value::Array(a.into_iter().map(|v| expand_json(v, vars, origin)).collect::<Result<_, _>>()?),
        Value::Object(m) => Value::Object(
            m.into_iter().map(|(k, v)| Ok((k, expand_json(v, vars, origin)?))).collect::<Result<_, String>>()?,
        ),
        v => v,
    })
}
fn capture(e: &Exchange, selector: &str) -> Option<String> {
    if let Some(p) = selector.strip_prefix("json:") {
        let v: Value = serde_json::from_str(&e.body_text).ok()?;
        let v = v.pointer(p)?;
        return Some(v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string()));
    }
    if let Some(h) = selector.strip_prefix("header:") {
        return e.headers.get(&h.to_ascii_lowercase()).cloned();
    }
    if let Some(p) = selector.strip_prefix("regex:").filter(|p| p.len() <= 1024) {
        let re = regex::Regex::new(p).ok()?;
        return re.captures(&e.body_text)?.get(1).map(|m| m.as_str().to_string());
    }
    None
}

// ---- http_authz_matrix ---------------------------------------------------------------------------

/// Maximum distinct principals probed in one `http_authz_matrix` call.
const MAX_MATRIX_PRINCIPALS: usize = 16;

/// Volatile JSON keys stripped recursively before comparing response structures across principals.
const VOLATILE_JSON_KEYS: &[&str] = &[
    "timestamp",
    "timestamps",
    "ts",
    "time",
    "request_id",
    "requestid",
    "req_id",
    "trace_id",
    "traceid",
    "correlation_id",
    "correlationid",
    "span_id",
    "nonce",
    "date",
    "expires_at",
    "expiresat",
    "created_at",
    "updated_at",
    "server_time",
    "etag",
    "csrf_token",
    "csrf",
    "x_request_id",
    "duration_ms",
    "latency_ms",
];

fn is_volatile_json_key(key: &str) -> bool {
    let norm: String = key.trim().to_ascii_lowercase().replace('-', "_");
    VOLATILE_JSON_KEYS.contains(&norm.as_str())
}

fn normalize_json_value(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, val) in map {
                if !is_volatile_json_key(k) {
                    out.insert(k.clone(), normalize_json_value(val));
                }
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(normalize_json_value).collect()),
        other => other.clone(),
    }
}

fn collect_json_features(v: &Value, path: &str, keys: &mut BTreeSet<String>, leaves: &mut BTreeMap<String, String>) {
    match v {
        Value::Object(map) => {
            for (k, val) in map {
                let child = format!("{path}.{k}");
                keys.insert(child.clone());
                collect_json_features(val, &child, keys, leaves);
            }
        }
        Value::Array(arr) => {
            let elem_path = format!("{path}[]");
            keys.insert(elem_path.clone());
            for (i, val) in arr.iter().take(64).enumerate() {
                let idx_path = format!("{path}[{i}]");
                collect_json_features(val, &idx_path, keys, leaves);
            }
        }
        leaf => {
            leaves.insert(path.to_string(), leaf.to_string());
        }
    }
}

fn jaccard_sets(a: &BTreeSet<String>, b: &BTreeSet<String>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let inter = a.intersection(b).count();
    let union = a.union(b).count();
    if union == 0 {
        1.0
    } else {
        inter as f64 / union as f64
    }
}

fn content_type_class(ct: &str) -> &'static str {
    let low = ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    if low.is_empty() {
        "empty"
    } else if low.contains("json") {
        "json"
    } else if low.contains("html") {
        "html"
    } else if low.contains("xml") {
        "xml"
    } else if low.starts_with("text/") {
        "text"
    } else {
        "binary"
    }
}

fn text_tokens(body: &str) -> BTreeSet<String> {
    body.chars()
        .take(65_536)
        .collect::<String>()
        .split(|c: char| !c.is_alphanumeric() && c != '_' && c != '-')
        .filter(|tok| !tok.is_empty())
        .map(str::to_ascii_lowercase)
        .take(4096)
        .collect()
}

struct StructuralComparison {
    exact_normalized_match: bool,
    similarity: f64,
    highlights: Vec<String>,
}

fn compare_responses(
    base_status: u16,
    base_ct: &str,
    base_body: &str,
    probe_status: u16,
    probe_ct: &str,
    probe_body: &str,
) -> StructuralComparison {
    let mut highlights = Vec::new();
    if base_status != probe_status {
        highlights.push(format!("status {base_status} -> {probe_status}"));
    }
    let base_class = content_type_class(base_ct);
    let probe_class = content_type_class(probe_ct);
    if base_class != probe_class {
        highlights.push(format!("content-type {base_class} -> {probe_class}"));
    }
    if let (Ok(bj), Ok(pj)) = (serde_json::from_str::<Value>(base_body), serde_json::from_str::<Value>(probe_body)) {
        let nb = normalize_json_value(&bj);
        let np = normalize_json_value(&pj);
        let exact = nb == np;
        let (mut bkeys, mut bleaves) = (BTreeSet::new(), BTreeMap::new());
        let (mut pkeys, mut pleaves) = (BTreeSet::new(), BTreeMap::new());
        collect_json_features(&nb, "$", &mut bkeys, &mut bleaves);
        collect_json_features(&np, "$", &mut pkeys, &mut pleaves);
        let key_sim = jaccard_sets(&bkeys, &pkeys);
        let b_leaf_set: BTreeSet<String> = bleaves.iter().map(|(k, v)| format!("{k}={v}")).collect();
        let p_leaf_set: BTreeSet<String> = pleaves.iter().map(|(k, v)| format!("{k}={v}")).collect();
        let leaf_sim = jaccard_sets(&b_leaf_set, &p_leaf_set);
        let similarity = if exact { 1.0 } else { 0.4 * key_sim + 0.6 * leaf_sim };

        if !exact {
            for k in pkeys.difference(&bkeys).take(4) {
                highlights.push(format!("+{k}"));
            }
            for k in bkeys.difference(&pkeys).take(4) {
                highlights.push(format!("-{k}"));
            }
            for (k, bv) in &bleaves {
                if highlights.len() >= 10 {
                    break;
                }
                if let Some(pv) = pleaves.get(k) {
                    if bv != pv {
                        highlights.push(format!("~{k}: {} -> {}", crate::preview(bv, 40), crate::preview(pv, 40)));
                    }
                }
            }
        }
        return StructuralComparison { exact_normalized_match: exact, similarity, highlights };
    }

    let exact = base_body == probe_body;
    let similarity = if exact { 1.0 } else { jaccard_sets(&text_tokens(base_body), &text_tokens(probe_body)) };
    if !exact {
        highlights.push(format!("bytes {} -> {}", base_body.len(), probe_body.len()));
        if let Some((bl, pl)) = base_body.lines().zip(probe_body.lines()).find(|(a, b)| a != b) {
            highlights.push(format!("line diff: `{}` -> `{}`", crate::preview(bl, 40), crate::preview(pl, 40)));
        }
    }
    StructuralComparison { exact_normalized_match: exact, similarity, highlights }
}

fn build_matrix_request(args: &Map<String, Value>) -> Result<Request, String> {
    let url = args
        .get("url")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or("Provide either `request_id` or `url`.")?
        .to_string();
    let method = args
        .get("method")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("GET")
        .to_string();
    let mut headers = BTreeMap::new();
    if let Some(hmap) = args.get("headers").and_then(Value::as_object) {
        for (k, v) in hmap {
            let val = v.as_str().ok_or_else(|| format!("Header `{k}` value must be a string."))?;
            headers.insert(k.clone(), val.to_string());
        }
    }
    let body = args.get("body").and_then(Value::as_str).unwrap_or_default().to_string();
    let body_base64 = args.get("body_base64").and_then(Value::as_str).map(str::to_string);
    let json_val = args.get("json").cloned();
    let forms = usize::from(!body.is_empty()) + usize::from(body_base64.is_some()) + usize::from(json_val.is_some());
    if forms > 1 {
        return Err("Choose only one of `body`, `body_base64`, or `json`.".into());
    }
    Ok(Request { url, method, headers, body, body_base64, json: json_val })
}

#[async_trait]
impl Tool for HttpAuthzMatrix {
    fn spec(&self) -> ToolSpec {
        spec(
            "http_authz_matrix",
            "Replay an HTTP request across multiple isolated principals (e.g. anon and mounted credential profiles) with strict cookie/header isolation, compare response structures against a baseline, record an Exchange per probe, and flag potential BOLA/IDOR authorization bypasses. Raw profile secrets are never exposed.",
            ToolClass::Exec,
            &[
                opt(
                    "request_id",
                    "string",
                    "Optional rq ID, req-* alias, ex- exchange ID (including proxy/intercepted captures), or last to replay. Mutually exclusive with url.",
                ),
                opt("url", "string", "Explicit http(s) URL to probe when request_id is omitted."),
                opt("method", "string", "HTTP method when using url (default GET)."),
                opt("headers", "object", "Non-auth request headers when using url (auth headers are stripped per principal).")
                    .with("additionalProperties", json!({"type": "string"})),
                opt("body", "string", "Plain text body when using url."),
                opt("body_base64", "string", "Base64-encoded body when using url."),
                opt("json", "object", "JSON body when using url.").with("additionalProperties", json!(true)),
                opt(
                    "principals",
                    "array",
                    "Principals to probe (\"anon\" or mounted profile names). Defaults to [\"anon\"] + all mounted profiles sorted; at least 2 required.",
                )
                .items("string"),
                opt(
                    "baseline",
                    "string",
                    "Reference principal for structural comparison (defaults to first non-\"anon\" principal, or first principal).",
                ),
                opt("timeout_s", "integer", "Whole matrix timeout in seconds (default 30, maximum 120).")
                    .min(1)
                    .max(120),
                opt(
                    "allow_quarantined",
                    "boolean",
                    "Explicitly permit probing a quarantined logout, unsubscribe, or single-use token URL (default false).",
                ),
            ],
        )
    }

    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let req_id = args.get("request_id").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty());
        let has_url = args.get("url").and_then(Value::as_str).is_some_and(|s| !s.trim().is_empty());
        if req_id.is_some() && has_url {
            return ToolOutput::error("Provide either `request_id` or `url`, not both.");
        }
        let mut base_req = match req_id {
            Some(id) => match resolve_saved_request(ctx, id).await {
                Ok((r, _)) => r,
                Err(e) => return ToolOutput::error(e),
            },
            None => match build_matrix_request(args) {
                Ok(r) => r,
                Err(e) => return ToolOutput::error(e),
            },
        };

        let origin = match checked_url(&base_req.url) {
            Ok(u) => u.origin().ascii_serialization(),
            Err(e) => return ToolOutput::error(e),
        };
        let variables = {
            let state = ctx.capabilities.http.lock().await;
            state.variables.clone()
        };
        let expanded = (|| -> Result<Url, String> {
            base_req.url = expand(&base_req.url, &variables, &origin)?;
            let parsed = checked_url(&base_req.url)?;
            if parsed.origin().ascii_serialization() != origin {
                return Err("URL expansion cannot change the origin.".into());
            }
            base_req.body = expand(&base_req.body, &variables, &origin)?;
            for v in base_req.headers.values_mut() {
                *v = expand(v, &variables, &origin)?;
            }
            if let Some(v) = base_req.json.take() {
                base_req.json = Some(expand_json(v, &variables, &origin)?);
            }
            Ok(parsed)
        })();
        let parsed_url = match expanded {
            Ok(u) => u,
            Err(e) => return ToolOutput::error(e),
        };

        let allow_quarantined = args.get("allow_quarantined").and_then(Value::as_bool).unwrap_or(false);
        if !allow_quarantined {
            if let Some(reason) = quarantined_locator(&base_req.url) {
                return ToolOutput::error(format!(
                    "Quarantined URL refused ({reason}): {}. Pass `allow_quarantined: true` only when the assignment explicitly tests this endpoint.",
                    base_req.url
                ));
            }
        }

        // Strip all sensitive auth headers from the base request so nothing bleeds across principals.
        base_req.headers.retain(|k, _| !is_sensitive_auth_header(k));

        // Resolve requested principal list.
        let mut principal_names: Vec<String> = Vec::new();
        if let Some(arr) = args.get("principals").and_then(Value::as_array) {
            for item in arr {
                if let Some(s) = item.as_str().map(str::trim).filter(|s| !s.is_empty()) {
                    if !principal_names.iter().any(|existing| existing == s) {
                        principal_names.push(s.to_string());
                    }
                }
            }
        } else {
            principal_names.push("anon".into());
            for name in ctx.capabilities.mounted_profile_names() {
                if !principal_names.iter().any(|existing| existing == &name) {
                    principal_names.push(name);
                }
            }
        }
        if principal_names.len() < 2 {
            let mounted = ctx.capabilities.mounted_profile_names();
            return ToolOutput::error(format!(
                "http_authz_matrix requires at least 2 distinct principals (got {}). Mounted profiles: {}. Mount credential profiles or pass explicit `principals`.",
                principal_names.len(),
                if mounted.is_empty() { "none".into() } else { mounted.join(", ") }
            ));
        }
        if principal_names.len() > MAX_MATRIX_PRINCIPALS {
            return ToolOutput::error(format!(
                "http_authz_matrix accepts at most {MAX_MATRIX_PRINCIPALS} principals per call (got {}).",
                principal_names.len()
            ));
        }

        let mut resolved_principals: Vec<(String, Option<Arc<ferret_net::Inject>>, String)> = Vec::new();
        for name in &principal_names {
            match ctx.capabilities.resolve_profile(Some(name), name == "anon") {
                Ok((inject, tag)) => resolved_principals.push((name.clone(), inject, tag)),
                Err(e) => return ToolOutput::error(e),
            }
        }

        let baseline_name = match args.get("baseline").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty())
        {
            Some(b) => {
                if !principal_names.iter().any(|p| p == b) {
                    return ToolOutput::error(format!(
                        "Baseline principal `{b}` is not in the selected principals ({}).",
                        principal_names.join(", ")
                    ));
                }
                b.to_string()
            }
            None => principal_names
                .iter()
                .find(|p| p.as_str() != "anon")
                .cloned()
                .unwrap_or_else(|| principal_names[0].clone()),
        };

        let insecure = crate::web::insecure_for(ctx, &parsed_url);
        let secs = args.get("timeout_s").and_then(Value::as_u64).unwrap_or(30).clamp(1, 120);
        let made: std::sync::Mutex<Vec<ferret_core::event::Exchange>> = std::sync::Mutex::new(Vec::new());

        struct ProbeResult {
            name: String,
            principal_tag: String,
            outcome: Result<Exchange, String>,
        }

        let probe_fut = async {
            let mut results = Vec::with_capacity(resolved_principals.len());
            for (name, inject_opt, tag) in &resolved_principals {
                // Strictly isolated per-principal cookie jar & HTTP client — zero cross-principal jar bleed.
                let iso_jar = Arc::new(Jar::default());
                let iso_client = match client(ctx, iso_jar, insecure) {
                    Ok(c) => c,
                    Err(e) => {
                        results.push(ProbeResult { name: name.clone(), principal_tag: tag.clone(), outcome: Err(e) });
                        continue;
                    }
                };
                let res = exchange(
                    ctx,
                    &iso_client,
                    &base_req,
                    Some(("http_authz_matrix", &made)),
                    None,
                    inject_opt.as_deref(),
                    Some(tag.as_str()),
                )
                .await;
                results.push(ProbeResult { name: name.clone(), principal_tag: tag.clone(), outcome: res });
            }
            results
        };

        let results = tokio::select! {
            biased;
            _ = ctx.cancel.cancelled() => {
                return ToolOutput::denied("http_authz_matrix cancelled. Some probes may have reached the target.");
            }
            r = tokio::time::timeout(Duration::from_secs(secs), probe_fut) => match r {
                Ok(v) => v,
                Err(_) => return ToolOutput::error("http_authz_matrix timed out before completing all principal probes."),
            },
        };

        // Defense-in-depth redactor covering session secrets plus any probed profile values.
        let fallback_secrets = if ctx.capabilities.secrets.get().is_none() {
            let mut all_items = Vec::new();
            for (_, inj, _) in &resolved_principals {
                if let Some(i) = inj {
                    all_items.extend_from_slice(i.items());
                }
            }
            if all_items.is_empty() {
                None
            } else {
                Some(ferret_core::creds::Secrets::for_items(&all_items))
            }
        } else {
            None
        };
        let redact = |s: &str| -> String {
            if let Some(sec) = ctx.capabilities.secrets.get().filter(|x| !x.is_empty()) {
                sec.redact(s).into_owned()
            } else if let Some(sec) = fallback_secrets.as_ref().filter(|x| !x.is_empty()) {
                sec.redact(s).into_owned()
            } else {
                s.to_string()
            }
        };

        let baseline_probe = results.iter().find(|r| r.name == baseline_name);
        let baseline_ex = baseline_probe.and_then(|r| r.outcome.as_ref().ok());
        let baseline_status = baseline_ex.map(|e| e.status);
        let baseline_ct = baseline_ex.and_then(|e| e.headers.get("content-type").map(String::as_str)).unwrap_or("");
        let baseline_is_auth_2xx = baseline_name != "anon" && baseline_status.is_some_and(|s| (200..300).contains(&s));

        let mut rows_json = Vec::new();
        let mut anomalies: Vec<Value> = Vec::new();
        let mut table_lines = Vec::new();
        let mut diff_lines = Vec::new();
        table_lines.push("principal | status | content-type | bytes | similarity | exchange_id | flag".to_string());
        table_lines.push("--- | --- | --- | --- | --- | --- | ---".to_string());

        for r in &results {
            let is_baseline = r.name == baseline_name;
            match &r.outcome {
                Err(e) => {
                    let clean_err = redact(e);
                    table_lines.push(format!("{} | error | - | 0 | - | - | error", r.name));
                    diff_lines.push(format!("- {}: error: {clean_err}", r.name));
                    rows_json.push(json!({
                        "principal": r.name,
                        "principal_tag": r.principal_tag,
                        "baseline": is_baseline,
                        "error": clean_err,
                        "flags": [],
                    }));
                }
                Ok(ex) => {
                    let ct = ex.headers.get("content-type").map(String::as_str).unwrap_or("-");
                    let ct_short = ct.split(';').next().unwrap_or("-").trim();
                    let ex_id = ex.ex_id.as_deref().unwrap_or("-");
                    let body_len = ex.body_text.len();
                    let mut flags: Vec<String> = Vec::new();
                    let (sim_str, similarity_opt, exact_opt, highlights) = if is_baseline {
                        ("1.00 (baseline)".to_string(), Some(1.0), Some(true), Vec::new())
                    } else if let Some(bex) = baseline_ex {
                        let cmp =
                            compare_responses(bex.status, baseline_ct, &bex.body_text, ex.status, ct, &ex.body_text);
                        let same_ct_class = {
                            let bc = content_type_class(baseline_ct);
                            let pc = content_type_class(ct);
                            bc == pc || bc == "empty" || pc == "empty"
                        };
                        let probe_is_2xx = (200..300).contains(&ex.status);
                        let len_close = {
                            let max_len = bex.body_text.len().max(body_len);
                            let min_len = bex.body_text.len().min(body_len);
                            max_len > 0 && (min_len as f64 / max_len as f64) >= 0.85
                        };
                        if baseline_is_auth_2xx
                            && probe_is_2xx
                            && same_ct_class
                            && (cmp.exact_normalized_match
                                || cmp.similarity >= 0.70
                                || (ex.status == bex.status && len_close && cmp.similarity >= 0.50))
                        {
                            flags.push("potential_bola_idor".into());
                            let reason = if r.name == "anon" {
                                format!(
                                    "unauthenticated `anon` received HTTP {} with {:.2} structural similarity to authenticated baseline `{}` (HTTP {})",
                                    ex.status, cmp.similarity, baseline_name, bex.status
                                )
                            } else {
                                format!(
                                    "non-baseline principal `{}` received HTTP {} with {:.2} structural similarity to baseline `{}` (HTTP {})",
                                    r.name, ex.status, cmp.similarity, baseline_name, bex.status
                                )
                            };
                            anomalies.push(json!({
                                "flag": "potential_bola_idor",
                                "principal": r.name,
                                "baseline": baseline_name,
                                "status": ex.status,
                                "similarity": (cmp.similarity * 100.0).round() / 100.0,
                                "exchange_id": ex.ex_id,
                                "reason": reason,
                            }));
                        }
                        let clean_highlights: Vec<String> = cmp.highlights.iter().map(|h| redact(h)).collect();
                        if !clean_highlights.is_empty() {
                            diff_lines.push(format!("- {}: {}", r.name, clean_highlights.join("; ")));
                        } else if cmp.exact_normalized_match {
                            diff_lines
                                .push(format!("- {}: identical normalized structure to `{baseline_name}`", r.name));
                        }
                        (
                            format!("{:.2}", cmp.similarity),
                            Some((cmp.similarity * 100.0).round() / 100.0),
                            Some(cmp.exact_normalized_match),
                            clean_highlights,
                        )
                    } else {
                        ("-".to_string(), None, None, Vec::new())
                    };
                    let flag_cell = if flags.is_empty() { "-".to_string() } else { flags.join(",") };
                    table_lines.push(format!(
                        "{} | {} | {} | {} | {} | {} | {}",
                        r.name, ex.status, ct_short, body_len, sim_str, ex_id, flag_cell
                    ));
                    rows_json.push(json!({
                        "principal": r.name,
                        "principal_tag": r.principal_tag,
                        "baseline": is_baseline,
                        "status": ex.status,
                        "content_type": ct_short,
                        "body_bytes": body_len,
                        "similarity": similarity_opt,
                        "exact_normalized_match": exact_opt,
                        "exchange_id": ex.ex_id,
                        "flags": flags,
                        "diff_highlights": highlights,
                    }));
                }
            }
        }

        let mut report = format!(
            "Target: {} {}\nBaseline: {}\nFlags: {}\n\n{}\n",
            base_req.method,
            redact(&base_req.url),
            baseline_name,
            if anomalies.is_empty() {
                "none".to_string()
            } else {
                anomalies.iter().filter_map(|a| a.get("reason").and_then(Value::as_str)).collect::<Vec<_>>().join("; ")
            },
            table_lines.join("\n"),
        );
        if !diff_lines.is_empty() {
            report.push_str("\nDiff highlights:\n");
            report.push_str(&diff_lines.join("\n"));
            report.push('\n');
        }
        let report = redact(&report);
        let recorded = std::mem::take(&mut *made.lock().unwrap_or_else(|p| p.into_inner()));
        let any_err = results.iter().any(|r| r.outcome.is_err());
        let outcome = if anomalies.is_empty() {
            format!("{} principals probed; no authz anomalies", results.len())
        } else {
            format!("{} principals probed; {} potential_bola_idor flag(s)", results.len(), anomalies.len())
        };
        let mut meta = Map::new();
        meta.insert("baseline".into(), json!(baseline_name));
        meta.insert("anomalies".into(), Value::Array(anomalies));
        meta.insert("matrix".into(), Value::Array(rows_json));
        ToolOutput {
            status: if any_err { ToolStatus::Error } else { ToolStatus::Ok },
            outcome,
            more: vec![
                "isolated per-principal cookie jars; redirects not followed; auth headers stripped before injection"
                    .into(),
            ],
            body: Body::Raw(report.into_bytes()),
            meta,
        }
        .with_exchanges(&recorded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn patches_and_origin_checks() {
        let mut r: Request =
            serde_json::from_value(json!({"url":"http://target/a","headers":{"Cookie":"a=b"},"json":{"x":1}})).unwrap();
        patch(
            &mut r,
            json!({"path":"/b","query":{"x":"a&b"},"headers":{"Cookie":null},"body":"plain"}).as_object().unwrap(),
        )
        .unwrap();
        assert_eq!(r.url, "http://target/b?x=a%26b");
        assert!(r.json.is_none());
        assert!(r.headers.is_empty());
        assert!(patch(&mut r, json!({"url":"http://other"}).as_object().unwrap()).is_err());
        let vars =
            BTreeMap::from([("token".into(), Variable { value: "secret".into(), origin: "http://target".into() })]);
        assert!(expand("{{token}}", &vars, "http://other").is_err());
    }
    #[tokio::test]
    async fn http_cookie_replay_framing_capture_and_race() {
        use axum::{
            http::{HeaderMap, StatusCode},
            routing::post,
            Router,
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            .route(
                "/login",
                post(|| async { ([("set-cookie", "session=abc; Path=/")], axum::Json(json!({"token":"xyz"}))) }),
            )
            .route(
                "/check",
                post(|h: HeaderMap, b: String| async move {
                    if h.get("cookie").is_some_and(|v| v == "session=abc")
                        && h.get("authorization").is_some_and(|v| v == "Bearer xyz")
                        && b == "new"
                        && (h.get("content-length").is_some_and(|v| v == "3"))
                    {
                        StatusCode::OK
                    } else {
                        StatusCode::BAD_REQUEST
                    }
                }),
            );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let env = crate::testutil::env();
        let ctx = env.ctx;
        let args = json!({"capture":{"jwt":"json:/token"}});
        let r: Request = serde_json::from_value(json!({"url":format!("http://{addr}/login"),"method":"POST"})).unwrap();
        let out = run(&ctx, "http_send", r, args.as_object().unwrap()).await;
        assert_eq!(out.status, ToolStatus::Ok);
        let out=HttpRepeat.run(&ctx,json!({"request_id":"rq1","patch":{"path":"/check","headers":{"Authorization":"Bearer {{jwt}}","Content-Length":"999","Transfer-Encoding":"chunked"},"body":"new"},"race_count":2}).as_object().unwrap()).await;
        let Body::Raw(bytes) = out.body else { panic!() };
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v[0]["exchange"]["status"], 200);
        assert_eq!(v[1]["exchange"]["status"], 200);
        server.abort();
    }

    #[tokio::test]
    async fn quarantine_route_differentials_and_html_form_surfaces_work() {
        use axum::{
            http::{HeaderMap, StatusCode},
            routing::get,
            Router,
        };
        assert!(quarantined_locator("https://example.test/auth/logout").is_some());
        assert!(quarantined_locator("https://example.test/%6cogout").is_some());
        assert!(quarantined_locator("https://example.test/account?magic_token=abc").is_some());
        assert!(quarantined_locator("https://example.test/api/users/42").is_none());
        assert!(is_static_asset_locator("https://example.test/assets/app.woff2"));
        assert!(!is_static_asset_locator("https://example.test/assets/app.png?file=x"));
        assert!(!is_static_asset_locator("https://example.test/assets/app.js.map"));
        assert_eq!(
            route_template("/api/users/42/items/550e8400-e29b-41d4-a716-446655440000/0123456789abcdef"),
            "/api/users/{id}/items/{uuid}/{hex}"
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            .route(
                "/orders/{id}",
                get(|h: HeaderMap| async move {
                    if h.get("authorization").is_some_and(|v| v == "Bearer user1") {
                        (
                            StatusCode::OK,
                            [("content-type", "text/html")],
                            "<form action='/orders/update' method='post'><input type='hidden' name='csrf' value='1'><input name='role' readonly><input name='note' disabled></form>",
                        )
                    } else {
                        (StatusCode::FORBIDDEN, [("content-type", "text/plain")], "denied")
                    }
                }),
            )
            .route("/logout", get(|| async { StatusCode::OK }));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let env = crate::testutil::env();
        let ctx = env.ctx;

        // Quarantined URL is refused by default and permitted only with allow_quarantined: true.
        let blocked =
            HttpSend.run(&ctx, json!({"request":{"url":format!("http://{addr}/logout")}}).as_object().unwrap()).await;
        assert_eq!(blocked.status, ToolStatus::Error);
        let allowed = HttpSend
            .run(
                &ctx,
                json!({"request":{"url":format!("http://{addr}/logout")},"allow_quarantined":true})
                    .as_object()
                    .unwrap(),
            )
            .await;
        assert_eq!(allowed.status, ToolStatus::Ok);

        // Unauthenticated request to /orders/1 returns 403; authenticated request to /orders/2 returns 200
        // on the same normalized `/orders/{id}` template and surfaces both the differential and hidden form fields.
        let first =
            HttpSend.run(&ctx, json!({"request":{"url":format!("http://{addr}/orders/1")}}).as_object().unwrap()).await;
        assert_eq!(first.status, ToolStatus::Ok);
        let second = HttpSend
            .run(
                &ctx,
                json!({"request":{"url":format!("http://{addr}/orders/2"),"headers":{"Authorization":"Bearer user1"}}})
                    .as_object()
                    .unwrap(),
            )
            .await;
        let Body::Raw(bytes) = second.body else { panic!() };
        let parsed: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed[0]["differential_observation"]["route_template"], "/orders/{id}");
        assert_eq!(parsed[0]["differential_observation"]["denied"]["principal"], "anon");
        assert_eq!(parsed[0]["differential_observation"]["denied"]["status"], 403);
        assert_eq!(parsed[0]["differential_observation"]["allowed"]["status"], 200);
        assert!(parsed[0]["differential_observation"]["allowed"]["principal"].as_str().unwrap().starts_with("auth:"));
        assert!(!parsed[0]["differential_observation"].to_string().contains("Bearer user1"));
        let forms = parsed[0]["exchange"]["forms"].as_array().unwrap();
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0]["action"], "/orders/update");
        assert_eq!(forms[0]["method"], "POST");
        assert_eq!(forms[0]["fields"][0]["name"], "csrf");
        assert_eq!(forms[0]["fields"][0]["hidden"], true);
        assert_eq!(forms[0]["fields"][1]["readonly"], true);
        assert_eq!(forms[0]["fields"][2]["disabled"], true);
        server.abort();
    }

    #[tokio::test]
    async fn http_repeat_prefers_exact_request_id_over_prefix_matches() {
        use axum::{routing::get, Router};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/first", get(|| async { "first" }))
            .route("/other", get(|| async { "other" }))
            .route("/prefixed", get(|| async { "prefixed" }));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let env = crate::testutil::env();
        let ctx = env.ctx;

        // Create rq1 -> /first and rq2..=rq10 -> /other so both "rq1" and "rq10" exist.
        let first =
            HttpSend.run(&ctx, json!({"request":{"url":format!("http://{addr}/first")}}).as_object().unwrap()).await;
        assert_eq!(first.status, ToolStatus::Ok);
        let rest = HttpSend
            .run(&ctx, json!({"request":{"url":format!("http://{addr}/other")},"race_count":9}).as_object().unwrap())
            .await;
        assert_eq!(rest.status, ToolStatus::Ok);

        // Exact key "rq1" resolves deterministically even though "rq10" also starts with "rq1".
        let rep = HttpRepeat.run(&ctx, json!({"request_id":"rq1"}).as_object().unwrap()).await;
        assert_eq!(rep.status, ToolStatus::Ok);
        let Body::Raw(bytes) = rep.body else { panic!() };
        let parsed: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed[0]["exchange"]["body_text"], "first");

        // An ambiguous prefix without an exact match still fails.
        let ambig = HttpRepeat.run(&ctx, json!({"request_id":"rq"}).as_object().unwrap()).await;
        assert_eq!(ambig.status, ToolStatus::Error);
        let Body::Message(msg) = ambig.body else { panic!() };
        assert!(msg.contains("unknown or ambiguous"), "{msg}");

        // Unique prefix matching still works when there is no exact key match.
        {
            let mut st = ctx.capabilities.http.lock().await;
            st.requests.insert(
                "unique99".into(),
                Request {
                    url: format!("http://{addr}/prefixed"),
                    method: "GET".into(),
                    headers: BTreeMap::new(),
                    body: String::new(),
                    body_base64: None,
                    json: None,
                },
            );
        }
        let uniq = HttpRepeat.run(&ctx, json!({"request_id":"unique9"}).as_object().unwrap()).await;
        assert_eq!(uniq.status, ToolStatus::Ok);
        let Body::Raw(bytes) = uniq.body else { panic!() };
        let parsed: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed[0]["exchange"]["body_text"], "prefixed");

        server.abort();
    }

    #[test]
    fn stored_request_blocks_mcp_exchanges_and_strips_sensitive_proxy_headers() {
        let env = crate::testutil::env();
        let ctx = env.ctx;
        let mcp_req = b"POST /mcp HTTP/1.1\r\nHost: mcp.example\r\nAuthorization: Bearer topsecret\r\nContent-Type: application/json\r\n\r\n{}";
        let mcp_blob = ctx.blobs.put_bytes(mcp_req).unwrap();
        let proxy_req = b"GET /api/data HTTP/1.1\r\nHost: target.example\r\nAuthorization: Bearer injected\r\nProxy-Authorization: Basic abc\r\nCookie: sid=secret\r\nX-Api-Key: k123\r\nX-Auth-Token: t456\r\nX-Custom: keepme\r\nX-Redacted: [redacted]\r\n\r\n";
        let proxy_blob = ctx.blobs.put_bytes(proxy_req).unwrap();
        let tool_req = b"GET /api/data HTTP/1.1\r\nHost: target.example\r\nAuthorization: [redacted]\r\nCookie: sid=ok\r\nX-Custom: keep\r\n\r\n";
        let tool_blob = ctx.blobs.put_bytes(tool_req).unwrap();

        let make_ex = |id: &str,
                       source: &str,
                       tls: &str,
                       scheme: &str,
                       port: u16,
                       tool: Option<&str>,
                       blob: ferret_core::blob::BlobRef| {
            ferret_core::event::Exchange {
                id: id.into(),
                call_id: None,
                source: source.into(),
                tool: tool.map(str::to_string),
                scheme: scheme.into(),
                tls: tls.into(),
                method: "GET".into(),
                host: "target.example".into(),
                port,
                target: "/api/data".into(),
                status: Some(200),
                error: None,
                request_bytes: 100,
                response_bytes: 0,
                request: blob,
                response: None,
                truncated: false,
                upstream_unverified: false,
                duration_ms: 1,
                passive_signals: Vec::new(),
                principal: None,
            }
        };
        let intercepted_req = b"POST /api/orders HTTP/1.1\r\nHost: target.example\r\nAuthorization: Bearer mitm-secret\r\nCookie: sid=mitm\r\nContent-Type: application/json\r\nX-Trace: ok\r\n\r\n{\"id\":1}";
        let intercepted_blob = ctx.blobs.put_bytes(intercepted_req).unwrap();
        let tunnel_blob = ctx.blobs.put_bytes(b"").unwrap();
        let mut tunnel_ex = make_ex("ex-tunnel", "proxy", "tunnel", "https", 443, None, tunnel_blob);
        tunnel_ex.method = "TLS".into();

        let map = std::collections::HashMap::from([
            ("ex-mcp".to_string(), make_ex("ex-mcp", "tool", "tool", "http", 80, Some("mcp__gh__issues"), mcp_blob)),
            ("ex-proxy".to_string(), make_ex("ex-proxy", "proxy", "plain", "http", 80, None, proxy_blob)),
            (
                "ex-intercepted".to_string(),
                make_ex("ex-intercepted", "proxy", "intercepted", "https", 443, None, intercepted_blob),
            ),
            ("ex-tunnel".to_string(), tunnel_ex),
            ("ex-tool".to_string(), make_ex("ex-tool", "tool", "tool", "http", 80, Some("http_send"), tool_blob)),
        ]);
        let _ = ctx.capabilities.exchange_lookup.set(Arc::new(move |id| map.get(id).cloned()));

        // MCP HTTP exchanges are unconditionally refused.
        let err = stored_request(&ctx, "ex-mcp").unwrap_err();
        assert!(err.contains("MCP"), "{err}");

        // Opaque TLS tunnels remain refused.
        assert!(stored_request(&ctx, "ex-tunnel").is_err());

        // Proxy-captured plain HTTP exchanges strip all sensitive auth headers and redacted placeholders.
        let proxy_replayed = stored_request(&ctx, "ex-proxy").unwrap();
        for forbidden in ["Authorization", "Proxy-Authorization", "Cookie", "X-Api-Key", "X-Auth-Token", "X-Redacted"] {
            assert!(
                !proxy_replayed.headers.keys().any(|k| k.eq_ignore_ascii_case(forbidden)),
                "{forbidden} must be stripped from proxy replay: {:?}",
                proxy_replayed.headers
            );
        }
        assert_eq!(proxy_replayed.headers.get("X-Custom").map(String::as_str), Some("keepme"));

        // Proxy-captured intercepted HTTPS exchanges ARE now replayable, with auth headers stripped.
        let mitm_replayed = stored_request(&ctx, "ex-intercepted").unwrap();
        assert_eq!(mitm_replayed.url, "https://target.example/api/data");
        assert_eq!(mitm_replayed.method, "POST");
        assert!(!mitm_replayed.headers.keys().any(|k| k.eq_ignore_ascii_case("Authorization")));
        assert!(!mitm_replayed.headers.keys().any(|k| k.eq_ignore_ascii_case("Cookie")));
        assert_eq!(mitm_replayed.headers.get("X-Trace").map(String::as_str), Some("ok"));
        assert!(mitm_replayed.body_base64.is_some());

        // Tool exchanges strip redacted auth placeholders while preserving ordinary headers.
        let tool_replayed = stored_request(&ctx, "ex-tool").unwrap();
        assert!(!tool_replayed.headers.keys().any(|k| k.eq_ignore_ascii_case("Authorization")));
        assert_eq!(tool_replayed.headers.get("Cookie").map(String::as_str), Some("sid=ok"));
        assert_eq!(tool_replayed.headers.get("X-Custom").map(String::as_str), Some("keep"));
    }

    #[tokio::test]
    async fn multi_principal_as_profile_strip_auth_and_authz_matrix_bola_detection() {
        use axum::{
            http::{HeaderMap, StatusCode},
            routing::get,
            Router,
        };
        use ferret_core::creds::{Item, ItemKind, Secrets};
        use ferret_net::Inject;

        const SECRET_A: &str = "Bearer tok-alice-secret-1111";
        const SECRET_B: &str = "Bearer tok-bob-secret-2222";
        const COOKIE_A: &str = "alice-cookie-secret-3333";
        const COOKIE_B: &str = "bob-cookie-secret-4444";

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            // Vulnerable BOLA endpoint: ignores ownership and returns Alice's invoice for any user (and echoes a header).
            .route(
                "/api/invoices/42",
                get(|h: HeaderMap| async move {
                    let auth = h.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
                    let ts = if auth == SECRET_A { "2026-11-28T00:00:01Z" } else { "2026-11-28T00:00:09Z" };
                    let req_id = if auth == SECRET_A { "r-1" } else { "r-2" };
                    if auth == SECRET_A || auth == SECRET_B {
                        (
                            StatusCode::OK,
                            [("content-type", "application/json"), ("set-cookie", "leak=from-server; Path=/")],
                            json!({
                                "id": 42,
                                "owner": "alice",
                                "amount_cents": 9900,
                                "timestamp": ts,
                                "request_id": req_id,
                                "echo_auth": auth,
                            })
                            .to_string(),
                        )
                    } else {
                        (
                            StatusCode::UNAUTHORIZED,
                            [("content-type", "application/json"), ("set-cookie", "anon=1; Path=/")],
                            json!({"error": "unauthorized"}).to_string(),
                        )
                    }
                }),
            )
            // Properly protected endpoint: only Alice gets 200; Bob gets 403; anon gets 401.
            .route(
                "/api/private/42",
                get(|h: HeaderMap| async move {
                    let auth = h.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
                    if auth == SECRET_A {
                        (
                            StatusCode::OK,
                            [("content-type", "application/json")],
                            json!({"secret": "alice-only"}).to_string(),
                        )
                    } else if auth == SECRET_B {
                        (
                            StatusCode::FORBIDDEN,
                            [("content-type", "application/json")],
                            json!({"error": "forbidden"}).to_string(),
                        )
                    } else {
                        (
                            StatusCode::UNAUTHORIZED,
                            [("content-type", "application/json")],
                            json!({"error": "login required"}).to_string(),
                        )
                    }
                }),
            )
            // Echo endpoint for verifying as_profile / strip_auth header & jar isolation.
            .route(
                "/whoami",
                get(|h: HeaderMap| async move {
                    let auth = h.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("-");
                    let cookie = h.get("cookie").and_then(|v| v.to_str().ok()).unwrap_or("-");
                    format!("auth={auth}|cookie={cookie}")
                }),
            )
            .route("/set-jar", get(|| async { ([("set-cookie", "jar_sid=jar-alice; Path=/")], "ok") }));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let e = crate::testutil::env();
        let items_a = vec![
            Item {
                kind: ItemKind::Header,
                name: "Authorization".into(),
                value: SECRET_A.into(),
                host: "127.0.0.1".into(),
            },
            Item { kind: ItemKind::Cookie, name: "sid".into(), value: COOKIE_A.into(), host: "127.0.0.1".into() },
        ];
        let items_b = vec![
            Item {
                kind: ItemKind::Header,
                name: "Authorization".into(),
                value: SECRET_B.into(),
                host: "127.0.0.1".into(),
            },
            Item { kind: ItemKind::Cookie, name: "sid".into(), value: COOKIE_B.into(), host: "127.0.0.1".into() },
        ];
        let all_items: Vec<Item> = items_a.iter().chain(items_b.iter()).cloned().collect();
        let inj_a = Arc::new(Inject::new(items_a));
        let inj_b = Arc::new(Inject::new(items_b));
        e.ctx.capabilities.creds.set(inj_a.clone()).unwrap();
        e.ctx.capabilities.default_profile.set("user_a".into()).unwrap();
        e.ctx
            .capabilities
            .creds_profiles
            .set(BTreeMap::from([("user_a".into(), inj_a), ("user_b".into(), inj_b)]))
            .unwrap();
        e.ctx.capabilities.secrets.set(Arc::new(Secrets::for_items(&all_items))).unwrap();

        // Populate session jar under default user_a.
        let jar_res = e.call("http_send", json!({"request":{"url":format!("http://{addr}/set-jar")}})).await;
        assert_eq!(jar_res.status, ToolStatus::Ok);
        assert_eq!(jar_res.exchanges[0].principal.as_deref(), Some("profile:user_a"));

        // `strip_auth: true` strips caller auth headers AND skips session jar & default profile.
        let stripped = e
            .call(
                "http_send",
                json!({
                    "request": {
                        "url": format!("http://{addr}/whoami"),
                        "headers": {"Authorization": "Bearer manual", "Cookie": "c=1"}
                    },
                    "strip_auth": true
                }),
            )
            .await;
        assert_eq!(stripped.status, ToolStatus::Ok, "{}", stripped.text);
        assert!(stripped.text.contains("auth=-|cookie=-"), "{}", stripped.text);
        assert_eq!(stripped.exchanges[0].principal.as_deref(), Some("anon"));

        // `as_profile: "user_b"` strips caller auth headers, skips user_a's jar, injects user_b, redacts secrets!
        let as_b = e
            .call(
                "http_send",
                json!({
                    "request": {
                        "url": format!("http://{addr}/whoami"),
                        "headers": {"Authorization": "Bearer manual"}
                    },
                    "as_profile": "user_b"
                }),
            )
            .await;
        assert_eq!(as_b.status, ToolStatus::Ok, "{}", as_b.text);
        assert_eq!(as_b.exchanges[0].principal.as_deref(), Some("profile:user_b"));
        assert!(!as_b.text.contains("jar_sid"), "user_a jar must not bleed into user_b: {}", as_b.text);
        assert!(
            !as_b.text.contains("tok-bob") && !as_b.text.contains("bob-cookie"),
            "no raw secret leak: {}",
            as_b.text
        );
        assert!(as_b.text.contains("auth=[redacted]|cookie=sid=[redacted]"), "{}", as_b.text);

        // `http_authz_matrix` detects BOLA on `/api/invoices/42` despite differing volatile keys, with ZERO secret leak!
        let bola = e
            .call("http_authz_matrix", json!({"url": format!("http://{addr}/api/invoices/42"), "baseline": "user_a"}))
            .await;
        assert_eq!(bola.status, ToolStatus::Ok, "{}", bola.text);
        assert_eq!(bola.exchanges.len(), 3, "one Exchange per principal");
        let principals: Vec<&str> = bola.exchanges.iter().filter_map(|x| x.principal.as_deref()).collect();
        assert_eq!(principals, ["anon", "profile:user_a", "profile:user_b"]);
        assert!(bola.text.contains("potential_bola_idor"), "{}", bola.text);
        let meta_str = serde_json::to_string(&bola.meta).unwrap();
        for secret in ["tok-alice", "tok-bob", "alice-cookie", "bob-cookie"] {
            assert!(!bola.text.contains(secret), "secret `{secret}` leaked in matrix report: {}", bola.text);
            assert!(!meta_str.contains(secret), "secret `{secret}` leaked in matrix meta");
            for ex in &bola.exchanges {
                let req_txt = String::from_utf8_lossy(&e.ctx.blobs.read_all(&ex.request.id).unwrap()).into_owned();
                assert!(!req_txt.contains(secret), "secret `{secret}` leaked in request blob: {req_txt}");
                if let Some(resp) = &ex.response {
                    let resp_txt = String::from_utf8_lossy(&e.ctx.blobs.read_all(&resp.id).unwrap()).into_owned();
                    assert!(!resp_txt.contains(secret), "secret `{secret}` leaked in response blob: {resp_txt}");
                }
            }
        }
        let anomalies = bola.meta.get("anomalies").and_then(Value::as_array).unwrap();
        assert_eq!(anomalies.len(), 1, "{anomalies:?}");
        assert_eq!(anomalies[0]["principal"], "user_b");
        assert_eq!(anomalies[0]["flag"], "potential_bola_idor");

        // Properly protected endpoint raises ZERO BOLA flags.
        let safe = e
            .call("http_authz_matrix", json!({"url": format!("http://{addr}/api/private/42"), "baseline": "user_a"}))
            .await;
        assert_eq!(safe.status, ToolStatus::Ok, "{}", safe.text);
        assert!(!safe.text.contains("potential_bola_idor"), "{}", safe.text);
        assert_eq!(safe.meta.get("anomalies").and_then(Value::as_array).unwrap().len(), 0);

        // Unknown principal or <2 principals fail cleanly.
        let bad_p = e
            .call(
                "http_authz_matrix",
                json!({"url": format!("http://{addr}/api/private/42"), "principals": ["anon", "nope"]}),
            )
            .await;
        assert_eq!(bad_p.status, ToolStatus::Error);
        assert!(bad_p.text.contains("nope") && bad_p.text.contains("user_a"), "{}", bad_p.text);

        let too_few = e
            .call("http_authz_matrix", json!({"url": format!("http://{addr}/api/private/42"), "principals": ["anon"]}))
            .await;
        assert_eq!(too_few.status, ToolStatus::Error);
        assert!(too_few.text.contains("at least 2"), "{}", too_few.text);

        server.abort();
    }
}
