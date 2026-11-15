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
use futures_util::{future::join_all, StreamExt};
use loom_core::event::{ToolClass, ToolSpec, ToolStatus};
use reqwest::{
    cookie::{CookieStore, Jar},
    header::{HeaderMap, HeaderName, HeaderValue},
    Client, Method, Proxy,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
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
        spec("http_send","Send a structured HTTP request through the session's scoped egress proxy. Keep cookies between calls, capture origin-bound variables, and store complete bounded exchanges. Headers/body are evidence and may contain secrets; avoid unnecessary credentials.",ToolClass::Exec,&p)
    }
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let request = match serde_json::from_value(args.get("request").cloned().unwrap_or(Value::Null)) {
            Ok(r) => r,
            Err(e) => return ToolOutput::error(format!("Correct the request object: {e}.")),
        };
        run(ctx, request, args).await
    }
}

#[async_trait]
impl Tool for HttpRepeat {
    fn spec(&self) -> ToolSpec {
        let mut p=vec![req("request_id","string","A completed rq ID or last; state is not restored after restart."),opt("patch","object","Overlay method, path, query, headers (null deletes), cookies, json, body or body_base64. Origin changes are refused.").with("additionalProperties",json!(true))];
        p.extend(fields());
        spec("http_repeat","Replay a stored HTTP request with a structured patch. Preserve session cookies and recompute framing; no raw-smuggling mode.",ToolClass::Exec,&p)
    }
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let id = args.get("request_id").and_then(Value::as_str).unwrap_or_default();
        if id.trim().is_empty() {
            return ToolOutput::error("Supply a complete request_id or last.");
        }
        let state = ctx.capabilities.http.lock().await;
        let id = if id == "last" {
            state
                .requests
                .keys()
                .max_by_key(|k| k.strip_prefix("rq").and_then(|v| v.parse::<u64>().ok()).unwrap_or(0))
                .map(String::as_str)
                .unwrap_or("")
        } else {
            id
        };
        let matches: Vec<_> = state.requests.iter().filter(|(k, _)| k.as_str() == id || k.starts_with(id)).collect();
        let mut request = if matches.len() == 1 { matches.first().map(|(_, r)| (*r).clone()) } else { None };
        drop(state);
        let Some(mut r) = request.take() else {
            return ToolOutput::error("Request ID is unknown or ambiguous. Use a complete rq ID from this session; restart discards replay state.");
        };
        if let Some(p) = args.get("patch").and_then(Value::as_object) {
            if let Err(e) = patch(&mut r, p) {
                return ToolOutput::error(e);
            }
        }
        run(ctx, r, args).await
    }
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

pub(crate) fn client(ctx: &ToolCtx, jar: Arc<Jar>) -> Result<Client, String> {
    let mut b = Client::builder()
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
        ".mp4", ".webm", ".mp3", ".map",
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

fn principal_tag(jar: &Jar, url: &Url, r: &Request) -> String {
    let mut material = Vec::new();
    if let Some(cookie) = jar.cookies(url) {
        if !cookie.is_empty() {
            material.push(format!("jar={}", String::from_utf8_lossy(cookie.as_bytes())));
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
}

pub(crate) async fn one(ctx: &ToolCtx, client: &Client, r: &Request) -> Result<Exchange, String> {
    let url = checked_url(&r.url)?;
    let _permit = crate::capabilities::target_permit(url.host_str().unwrap_or_default(), &ctx.cancel).await?;
    let method = Method::from_bytes(r.method.as_bytes()).map_err(|_| "Use a valid HTTP method token.")?;
    if method == Method::CONNECT || method.as_str().eq_ignore_ascii_case(loom_net::CHECK_METHOD) {
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
    let response = client
        .request(method, url.clone())
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|e| format!("HTTP exchange failed: {e}. Consult the session egress log for proxy decisions."))?;
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
                read_error = Some(e.to_string());
                break;
            }
        }
    }
    let body_text = String::from_utf8_lossy(&body).into_owned();
    let forms = extract_forms(&headers, &body_text);
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
    })
}

async fn run(ctx: &ToolCtx, mut r: Request, args: &Map<String, Value>) -> ToolOutput {
    let origin = match checked_url(&r.url) {
        Ok(u) => u.origin().ascii_serialization(),
        Err(e) => return ToolOutput::error(e),
    };
    let state = ctx.capabilities.http.lock().await;
    if state.requests.len() >= 1024 {
        return ToolOutput::error(
            "This session has 1024 saved HTTP requests. Start a fresh bounded child for further exchanges.",
        );
    }
    let jar = state.jar.clone();
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
    let principal = principal_tag(&jar, &parsed_url, &r);
    let client = match client(ctx, jar) {
        Ok(c) => c,
        Err(e) => return ToolOutput::error(e),
    };
    let count = args.get("race_count").and_then(Value::as_u64).unwrap_or(1).clamp(1, 20) as usize;
    let barrier = Arc::new(Barrier::new(count));
    let slots = Arc::new(Semaphore::new(ctx.capabilities.target_concurrency as usize));
    let futures = (0..count).map(|_| {
        let barrier = barrier.clone();
        let slots = slots.clone();
        let client = &client;
        let r = &r;
        async move {
            barrier.wait().await;
            let _slot = slots.acquire().await.map_err(|_| "HTTP batch closed.".to_string())?;
            one(ctx, client, r).await
        }
    });
    let secs = args.get("timeout_s").and_then(Value::as_u64).unwrap_or(30).clamp(1, 120);
    let result = tokio::select! {biased;_ = ctx.cancel.cancelled()=>return ToolOutput::denied("HTTP batch cancelled. Some requests may have reached the target; do not assume rollback."),
    out=tokio::time::timeout(Duration::from_secs(secs),join_all(futures))=>out};
    let exchanges=match result {Ok(r)=>r,Err(_)=>return ToolOutput::error("HTTP batch timed out. Requests may have reached the target; no completed replay IDs were committed. Inspect the target before retrying.")};
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
                let mut entry = json!({"request_id":id,"exchange":e,"capture_errors":capture_errors});
                if let Some(diff) = differential {
                    if let Some(obj) = entry.as_object_mut() {
                        obj.insert("differential_observation".into(), diff);
                    }
                }
                outputs.push(entry);
            }
        }
    }
    ToolOutput{status:if failed{ToolStatus::Error}else{ToolStatus::Ok},outcome:format!("{} HTTP exchanges",outputs.len()),more:vec!["redirects not followed; race workers respect a two-request per-host limit; captures/cookies are session-local".into()],body:Body::Raw(json!(outputs).to_string().into_bytes()),meta:Map::new()}
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
        let out = run(&ctx, r, args.as_object().unwrap()).await;
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
}
