//! Stateful structured HTTP, with bounded replay and race batches.
//!
//! CONTRACT: every exchange uses the ordinary session proxy (never the reference credential), no
//! automatic redirects, no ambient proxy/cookie state, valid HTTP framing recomputed by reqwest.
//! Content-Length, Transfer-Encoding, Host and proxy headers supplied by the model are discarded.
//! Raw desynchronization is deliberately not implemented by this structured client. A per-session
//! RFC cookie jar and origin-bound captures survive calls, but are discarded at restart. Request IDs
//! name completed exchanges only. Full bounded exchanges are BlobStore-backed observations, not
//! independent goal or authorization oracles. Race batches (2..20) release together, then respect the
//! daemon-wide two-request host semaphore; they do not promise simultaneous wire arrival.

use crate::{
    params::{opt, req, spec},
    Body, Tool, ToolCtx, ToolOutput,
};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use futures_util::{future::join_all, StreamExt};
use loom_core::event::{ToolClass, ToolSpec, ToolStatus};
use reqwest::{
    cookie::Jar,
    header::{HeaderMap, HeaderName, HeaderValue},
    Client, Method, Proxy,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
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

#[derive(Default)]
pub struct HttpState {
    jar: Arc<Jar>,
    requests: BTreeMap<String, Request>,
    variables: BTreeMap<String, Variable>,
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

#[derive(Serialize)]
pub(crate) struct Exchange {
    request: Request,
    pub status: u16,
    headers: BTreeMap<String, String>,
    body_base64: String,
    pub body_text: String,
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
    Ok(Exchange {
        request: r.clone(),
        status,
        headers,
        body_text: String::from_utf8_lossy(&body).into_owned(),
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
    let expanded = (|| -> Result<(), String> {
        r.url = expand(&r.url, &variables, &origin)?;
        if checked_url(&r.url)?.origin().ascii_serialization() != origin {
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
        Ok(())
    })();
    if let Err(e) = expanded {
        return ToolOutput::error(e);
    }
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
                outputs.push(json!({"request_id":id,"exchange":e,"capture_errors":capture_errors}));
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
}
