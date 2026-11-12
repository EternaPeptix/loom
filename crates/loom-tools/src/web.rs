//! `web_fetch`.
//!
//! CONTRACT (the body of `run` is a placeholder for the implementer; `spec` is fixed).
//!
//! - `url` must parse as `http` or `https` (else an error sentence showing what was received).
//! - The request goes through the session's egress proxy when `ctx.env` has `HTTPS_PROXY` /
//!   `HTTP_PROXY` (use that value, including its credentials, as the proxy for both schemes); with
//!   neither, it goes direct. Redirects are followed by hand, at most 10, so every hop passes the
//!   proxy's policy; the hops are listed in the result when there were any (`redirected: a → b → c`).
//! - Timeouts: `cfg.web_fetch_timeout_s` for the whole exchange; `ctx.cancel` aborts it (status
//!   `Interrupted`).
//! - The body is read up to `cfg.web_fetch_max_bytes`; if the response is larger, reading stops and
//!   the result has the fact `stopped at {limit} bytes — the response is larger` (never silently).
//! - Conversion happens on the complete downloaded body: `text/html` (or a body that starts with
//!   `<!doctype html`/`<html`, case-insensitive) is rendered to text with `html2text` at width 100
//!   unless `raw` is set; everything else is taken as is. The text shown is `Body::Raw` (stored
//!   whole, admitted). When conversion happened, the original bytes are also stored and meta
//!   `META_RAW_BLOB` names them, with the fact `html rendered as text (raw: out:{id})`.
//! - Outcome: `HTTP {status}`. Facts: final URL when it differs from the request, content type,
//!   `{bytes} bytes`. Status `Ok` for any HTTP response, including 4xx/5xx — a response is an
//!   observation; `Error` only when no response was obtained (the sentence names the stage: resolve,
//!   connect, TLS, proxy refusal with the proxy's message, timeout).
//! - A `407`/`403` from the proxy itself (header `X-Loom-Proxy: 1`) is reported as `denied` with the
//!   proxy's body as the message. Only the answer to an http:// URL fetched through the proxy can be
//!   the proxy's: inside the tunnel of an https:// URL only the destination speaks, so there the
//!   marker means nothing. The proxy answers the CONNECT of an https:// URL itself, which an HTTP
//!   client reports as a bare error, so before each https:// request through the proxy the tool asks
//!   the proxy for its verdict on the host and port ([`proxy_verdict`], a check that connects to
//!   nothing): a refusal is `denied` with the proxy's text, and a name that does not resolve is an
//!   error saying so. When the request then fails to connect, the proxy is asked again (the name's
//!   addresses or the policy may have changed): a refusal is `denied` as before, and otherwise the error
//!   says that the destination was not reached through the proxy, with the rule the proxy allows it by
//!   or the fact that it gave no verdict, and that the session's egress log has the proxy's decision.
//!   The stage of a failure is read from the causes of the error, never from text that contains the URL.
//!
//! Tests required (local `axum` server on loopback; no proxy): plain text; html rendered and raw
//! stored; `raw: true`; redirect chain reported; redirect loop stops at 10; 404 is `Ok` with the
//! body; size limit reported; timeout; cancel; bad URL; large html is converted completely (text
//! from the end of the document is present in the stored output).

use crate::{params, Body, Tool, ToolCtx, ToolOutput};
use async_trait::async_trait;
use futures_util::StreamExt;
use loom_core::event::{ToolClass, ToolSpec, ToolStatus, META_RAW_BLOB};
use reqwest::header::HeaderMap;
use reqwest::{header, redirect, Client, Method, Proxy};
use serde_json::{json, Map, Value};
use std::time::Duration;
use url::Url;

/// Redirects followed before giving up.
const MAX_REDIRECTS: usize = 10;
/// Width the HTML rendering wraps to.
const RENDER_WIDTH: usize = 100;
/// Most of a proxy refusal's body that is read.
const PROXY_BODY_MAX: usize = 64 * 1024;

pub struct WebFetch;

#[async_trait]
impl Tool for WebFetch {
    fn spec(&self) -> ToolSpec {
        params::spec(
            "web_fetch",
            "Fetch a URL with an HTTP GET and return the response body. HTML pages are rendered as readable text (set `raw` to get the HTML source). The header gives the HTTP status; an error status such as 404 is still returned with its body. For anything other than a simple GET — other methods, headers, cookies — use `curl` through `bash`.",
            ToolClass::Read,
            &[
                params::req("url", "string", "The http:// or https:// URL."),
                params::opt("raw", "boolean", "Return the body exactly as served instead of rendering HTML as text (default false)."),
            ],
        )
    }

    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let given = args.get("url").and_then(Value::as_str).unwrap_or_default().trim().to_string();
        let raw = args.get("raw").and_then(Value::as_bool).unwrap_or(false);
        let url = match Url::parse(&given) {
            Ok(u) if matches!(u.scheme(), "http" | "https") && u.host_str().is_some() => u,
            Ok(u) => {
                return ToolOutput::error(format!(
                    "`{given}` cannot be fetched: web_fetch handles http:// and https:// URLs with a host, and this one is `{}`. Call again with a full http:// or https:// URL.",
                    u.scheme()
                ))
            }
            Err(e) => {
                return ToolOutput::error(format!(
                    "`{given}` is not a valid URL ({e}). Call again with a full http:// or https:// URL."
                ))
            }
        };
        let client = match build_client(ctx) {
            Ok(c) => c,
            Err(msg) => return ToolOutput::error(msg),
        };
        let limit = Duration::from_secs(ctx.cfg.web_fetch_timeout_s.max(1));
        tokio::select! {
            biased;
            _ = ctx.cancel.cancelled() => ToolOutput {
                status: ToolStatus::Interrupted,
                outcome: "interrupted".into(),
                more: Vec::new(),
                body: Body::Message(format!("The fetch of {url} was cancelled before the response was complete; nothing was kept. Call `web_fetch` again if the page is still needed.")),
                meta: Map::new(),
            },
            r = tokio::time::timeout(limit, fetch(ctx, &client, url.clone(), raw)) => match r {
                Ok(out) => out,
                Err(_) => ToolOutput {
                    status: ToolStatus::Error,
                    outcome: "timeout".into(),
                    more: Vec::new(),
                    body: Body::Message(format!("The fetch of {url} timed out after {} s (the limit covers the whole exchange, redirects and body included); nothing was kept. Try again, or use `curl --max-time` through `bash` for a longer limit.", limit.as_secs())),
                    meta: Map::new(),
                },
            },
        }
    }
}

/// A client that never follows redirects itself, uses the session's proxy if there is one, and
/// reads nothing from the process environment.
fn build_client(ctx: &ToolCtx) -> Result<Client, String> {
    let mut builder = Client::builder().redirect(redirect::Policy::none()).no_proxy().user_agent("loom-web-fetch/0.1");
    if let Some(p) = session_proxy(ctx) {
        let proxy = Proxy::all(p).map_err(|e| {
            format!("The session's proxy setting is not usable ({e}); this is a harness configuration fault. Use `bash` with `curl` if the fetch is urgent, and report it.")
        })?;
        builder = builder.proxy(proxy);
    }
    builder.build().map_err(|e| format!("The HTTP client could not be built ({e}); this is a harness fault."))
}

/// The session's egress proxy, when the command environment in `ctx.env` names one.
pub(crate) fn session_proxy(ctx: &ToolCtx) -> Option<&str> {
    ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"]
        .iter()
        .find_map(|k| ctx.env.get(*k).map(|v| v.trim()).filter(|v| !v.is_empty()))
}

/// Whether a response to `url` is an answer the egress proxy generated itself (header
/// `X-Loom-Proxy: 1`). Only the answer to an http:// URL fetched through the proxy can be one: inside
/// the tunnel of an https:// URL only the destination speaks, and it may send any header.
pub(crate) fn marked_by_proxy(proxied: bool, url: &Url, headers: &HeaderMap) -> bool {
    proxied && url.scheme() == "http" && headers.get("x-loom-proxy").and_then(|v| v.to_str().ok()) == Some("1")
}

/// What the egress proxy answered when asked about a destination (see [`proxy_verdict`]).
pub(crate) enum ProxyVerdict {
    /// Allowed, by this rule.
    Allowed(String),
    /// Refused (`403`, or `407` for credentials it does not know), with the proxy's text.
    Refused(u16, String),
    /// Allowed by name, but the proxy could not look the name up, with the proxy's text.
    Unreachable(String),
}

/// Asks the session's egress proxy for its verdict on the host and port of `url` with a check
/// (method `LOOM-CHECK`), which the proxy answers itself and records as a check: it connects to
/// nothing. `None` when no verdict came back; the request then goes ahead and the proxy decides on it.
pub(crate) async fn proxy_verdict(client: &Client, url: &Url) -> Option<ProxyVerdict> {
    let (host, port) = (url.host_str()?, url.port_or_known_default()?);
    let target = Url::parse(&format!("http://{host}:{port}/")).ok()?;
    let method = Method::from_bytes(loom_net::CHECK_METHOD.as_bytes()).ok()?;
    let resp = client.request(method, target).send().await.ok()?;
    if resp.headers().get("x-loom-proxy").and_then(|v| v.to_str().ok()) != Some("1") {
        return None;
    }
    let rule = resp.headers().get(loom_net::RULE_HEADER).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
    let status = resp.status().as_u16();
    let (body, _) = read_body(resp, PROXY_BODY_MAX).await;
    let text = String::from_utf8_lossy(&body).trim().to_string();
    match status {
        200 => Some(ProxyVerdict::Allowed(rule)),
        403 | 407 => Some(ProxyVerdict::Refused(status, text)),
        502 => Some(ProxyVerdict::Unreachable(text)),
        _ => None,
    }
}

/// What the egress proxy says, when asked again after the failure, about the destination of an https
/// request that failed to connect through it: an HTTP client shows a refused CONNECT as any failure to
/// connect, and the name's addresses or the policy may have changed since the first check.
pub(crate) enum Tunnel {
    /// It allows the destination, by this rule.
    Allowed(String),
    /// It gave no verdict (it is at a limit, or the check failed).
    Unknown,
}

impl Tunnel {
    /// The stage and the advice for the failed request.
    pub(crate) fn failure(&self) -> (String, &'static str) {
        match self {
            Tunnel::Allowed(rule) => (
                format!("could not be reached through the egress proxy, which allows it by rule `{rule}`"),
                "Either the server did not accept the connection (it may be down, or the port is wrong) or the proxy refused the CONNECT for an address the name resolved to only then; the session's egress log has the proxy's decision.",
            ),
            Tunnel::Unknown => (
                "was not completed: the egress proxy did not open a tunnel to the destination and gave no verdict on it"
                    .to_string(),
                "The proxy refused the destination, could not reach it, or is at its connection limit; the session's egress log has any decision it made. Do not retry at once; if this keeps happening, ask the user to check that log.",
            ),
        }
    }
}

/// The causes of an error as one line, without the error's own text: for a request error that names
/// the URL, whose words say nothing about the stage that failed.
pub(crate) fn causes(e: &(dyn std::error::Error + 'static)) -> String {
    e.source().map(describe).unwrap_or_default()
}

/// Whether lowercased error causes (see [`causes`]) name a TLS or certificate failure.
pub(crate) fn names_tls(lower_causes: &str) -> bool {
    ["certificate", "tls", "ssl", "handshake"].iter().any(|w| lower_causes.contains(w))
}

/// Whether one of the error's causes names a TLS or certificate failure; its own text, which names the
/// URL, is not read. reqwest reports these failures as connect errors, but they are not a refused
/// CONNECT, so the proxy need not be asked again about them.
pub(crate) fn names_tls_failure(e: &(dyn std::error::Error + 'static)) -> bool {
    names_tls(&causes(e).to_lowercase())
}

/// A refusal by the session's egress proxy, with its text.
fn denied(text: &str, status: u16) -> ToolOutput {
    let message = if text.is_empty() { "(the proxy gave no reason)" } else { text };
    ToolOutput::denied(format!(
        "{message}\nThe session's egress proxy refused this request (HTTP {status}). Do not retry the same URL; ask the user to change the network policy if the host is needed."
    ))
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
/// said about the destination afterwards.
fn request_error(e: &reqwest::Error, url: &Url, hops: &[Url], tunnel: Option<&Tunnel>) -> ToolOutput {
    let detail = describe(e);
    let lower = causes(e).to_lowercase();
    let has = |words: &[&str]| words.iter().any(|w| lower.contains(w));
    let (stage, advice) = if e.is_timeout() {
        ("timed out".to_string(), "Try again later.")
    } else if has(&["dns", "resolve", "lookup", "name or service", "nodename", "no such host"]) {
        ("could not resolve the host name".to_string(), "Check the spelling of the host.")
    } else if names_tls(&lower) {
        ("failed the TLS handshake".to_string(), "The server's certificate or protocol was not acceptable.")
    } else if let (Some(t), true) = (tunnel, e.is_connect()) {
        t.failure()
    } else if e.is_connect() {
        ("could not connect".to_string(), "The server may be down or the port wrong.")
    } else {
        ("failed".to_string(), "Check the URL.")
    };
    let via = if hops.len() > 1 { format!(" (after redirects: {})", chain_text(hops)) } else { String::new() };
    ToolOutput::error(format!("The fetch of {url} {stage}{via}: {detail}. {advice}"))
}

/// The proxy's verdict on `url`, asked before the request and again when it fails to connect: `Err`
/// with the result of the fetch when the proxy refuses the destination or cannot look up its host.
fn verdict(v: Option<ProxyVerdict>, url: &Url) -> Result<Tunnel, Box<ToolOutput>> {
    match v {
        Some(ProxyVerdict::Allowed(rule)) => Ok(Tunnel::Allowed(rule)),
        None => Ok(Tunnel::Unknown),
        Some(ProxyVerdict::Refused(status, text)) => Err(Box::new(denied(&text, status))),
        Some(ProxyVerdict::Unreachable(text)) => Err(Box::new(ToolOutput::error(format!(
            "The fetch of {url} failed: the egress proxy could not look up the host. {text}"
        )))),
    }
}

fn chain_text(hops: &[Url]) -> String {
    hops.iter().map(Url::as_str).collect::<Vec<_>>().join(" → ")
}

/// Follow the redirects by hand, then turn the final response into the result.
async fn fetch(ctx: &ToolCtx, client: &Client, start: Url, raw: bool) -> ToolOutput {
    let proxied = session_proxy(ctx).is_some();
    let mut hops = vec![start];
    loop {
        let current = hops.last().cloned().unwrap_or_else(|| hops[0].clone());
        // The proxy answers the CONNECT of an https URL out of the client's sight, so it is asked first.
        let tunnelled = proxied && current.scheme() == "https";
        if tunnelled {
            if let Err(out) = verdict(proxy_verdict(client, &current).await, &current) {
                return *out;
            }
        }
        let resp = match client.get(current.clone()).send().await {
            Ok(r) => r,
            // A refused CONNECT looks like any failure to connect: the proxy is asked again (see [`Tunnel`]).
            Err(e) if tunnelled && e.is_connect() && !names_tls_failure(&e) => {
                return match verdict(proxy_verdict(client, &current).await, &current) {
                    Ok(tunnel) => request_error(&e, &current, &hops, Some(&tunnel)),
                    Err(out) => *out,
                };
            }
            Err(e) => return request_error(&e, &current, &hops, None),
        };
        if resp.status().is_redirection() {
            let target = resp.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()).map(str::to_string);
            if let Some(location) = target {
                if hops.len() > MAX_REDIRECTS {
                    return ToolOutput::error(format!(
                        "The fetch of {} stopped after {MAX_REDIRECTS} redirects without reaching a page: {}. This is probably a redirect loop; try a different address.",
                        hops[0],
                        chain_text(&hops)
                    ));
                }
                let next = match current.join(&location) {
                    Ok(n) if matches!(n.scheme(), "http" | "https") => n,
                    Ok(n) => {
                        return ToolOutput::error(format!(
                            "{current} redirects to `{n}`, which is not an http:// or https:// URL, so web_fetch did not follow it. Use `bash` if that target is what you need."
                        ))
                    }
                    Err(e) => {
                        return ToolOutput::error(format!(
                            "{current} redirects to `{location}`, which is not a usable URL ({e}); nothing further was fetched."
                        ))
                    }
                };
                hops.push(next);
                continue;
            }
        }
        return finish(ctx, resp, &hops, raw, proxied).await;
    }
}

enum Ended {
    Complete,
    Limit,
    Failed(String),
}

/// The body up to `limit` bytes, and how reading ended.
async fn read_body(resp: reqwest::Response, limit: usize) -> (Vec<u8>, Ended) {
    let mut buf: Vec<u8> = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(c) => {
                let room = limit.saturating_sub(buf.len());
                if c.len() > room {
                    buf.extend_from_slice(c.get(..room).unwrap_or_default());
                    return (buf, Ended::Limit);
                }
                buf.extend_from_slice(&c);
            }
            Err(e) => return (buf, Ended::Failed(describe(&e))),
        }
    }
    (buf, Ended::Complete)
}

fn looks_like_html(content_type: &str, body: &[u8]) -> bool {
    if content_type.to_ascii_lowercase().contains("text/html") {
        return true;
    }
    let head: Vec<u8> =
        body.iter().copied().skip_while(u8::is_ascii_whitespace).take(15).map(|b| b.to_ascii_lowercase()).collect();
    head.starts_with(b"<!doctype html") || head.starts_with(b"<html")
}

async fn finish(ctx: &ToolCtx, resp: reqwest::Response, hops: &[Url], raw: bool, proxied: bool) -> ToolOutput {
    let status = resp.status();
    let content_type =
        resp.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
    let from_proxy = hops.last().is_some_and(|url| marked_by_proxy(proxied, url, resp.headers()));

    if from_proxy && matches!(status.as_u16(), 403 | 407) {
        let (body, _) = read_body(resp, PROXY_BODY_MAX).await;
        return denied(String::from_utf8_lossy(&body).trim(), status.as_u16());
    }

    let limit = ctx.cfg.web_fetch_max_bytes;
    let (bytes, ended) = read_body(resp, usize::try_from(limit).unwrap_or(usize::MAX)).await;

    let mut more = Vec::new();
    if hops.len() > 1 {
        more.push(format!("redirected: {}", chain_text(hops)));
    }
    if let (Some(last), Some(first)) = (hops.last(), hops.first()) {
        if last != first {
            more.push(format!("final URL: {last}"));
        }
    }
    if !content_type.is_empty() {
        more.push(format!("content-type: {content_type}"));
    }
    more.push(format!("{} bytes", bytes.len()));
    match &ended {
        Ended::Complete => {}
        Ended::Limit => more.push(format!("stopped at {limit} bytes — the response is larger")),
        Ended::Failed(why) => more.push(format!("incomplete: the connection failed after {} bytes ({why})", bytes.len())),
    }

    let mut meta = Map::new();
    let body = if bytes.is_empty() {
        Body::Message("The response body is empty.".to_string())
    } else if !raw && looks_like_html(&content_type, &bytes) {
        // The complete download is stored before it is converted.
        let original = ctx.blobs.put_bytes(&bytes);
        let source = bytes.clone();
        let rendered = tokio::task::spawn_blocking(move || html2text::from_read(&source[..], RENDER_WIDTH)).await;
        match rendered {
            Ok(Ok(text)) => {
                match original {
                    Ok(stored) => {
                        meta.insert(META_RAW_BLOB.to_string(), json!(stored.id.as_str()));
                        more.push(format!("html rendered as text (raw: {})", stored.handle()));
                    }
                    Err(e) => more.push(format!("html rendered as text (the original could not be stored: {e})")),
                }
                Body::Raw(text.into_bytes())
            }
            Ok(Err(e)) => {
                more.push(format!("html could not be rendered as text ({e}); showing the source"));
                Body::Raw(bytes)
            }
            Err(e) => {
                more.push(format!("html could not be rendered as text (renderer failed: {e}); showing the source"));
                Body::Raw(bytes)
            }
        }
    } else {
        Body::Raw(bytes)
    };

    ToolOutput { status: ToolStatus::Ok, outcome: format!("HTTP {}", status.as_u16()), more, body, meta }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{env, env_with, TestEnv};
    use axum::http::{HeaderMap, HeaderValue, StatusCode};
    use axum::response::{IntoResponse, Redirect};
    use axum::routing::get;
    use axum::Router;
    use loom_core::config::{NetworkCfg, NetworkMode, SandboxCfg, SandboxMode, ToolsCfg};
    use std::collections::BTreeMap;
    use std::sync::Arc;

    /// An error with `text`, caused by the next hop.
    #[derive(Debug)]
    struct Hop(String, Option<Box<Hop>>);

    fn hop(text: &str, cause: Option<Hop>) -> Hop {
        Hop(text.to_string(), cause.map(Box::new))
    }

    impl std::fmt::Display for Hop {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }

    impl std::error::Error for Hop {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.1.as_deref().map(|h| h as &(dyn std::error::Error + 'static))
        }
    }

    #[test]
    fn a_certificate_failure_in_the_chain_is_named() {
        let cert = hop("error trying to connect", Some(hop("invalid peer certificate: UnknownIssuer", None)));
        assert!(names_tls_failure(&cert));
        let refused = hop("error trying to connect", Some(hop("tcp connect error: Connection refused", None)));
        assert!(!names_tls_failure(&refused));
        // The error's own text names the URL, whose words say nothing about the stage that failed.
        for url in ["https://github.com/rustls/rustls", "https://www.openssl.org/", "https://badssl.com/"] {
            let top = format!("error sending request for url ({url})");
            let tunnel = hop(&top, Some(hop("client error (Connect)", Some(hop("unsuccessful tunnel", None)))));
            assert!(!names_tls_failure(&tunnel), "{url}");
            let cert = hop(&top, Some(hop("invalid peer certificate: UnknownIssuer", None)));
            assert!(names_tls_failure(&cert), "{url}");
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

    fn html(body: &'static str) -> impl IntoResponse {
        ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], body)
    }

    fn quick(max_bytes: u64, timeout_s: u64) -> TestEnv {
        let cfg = ToolsCfg { web_fetch_max_bytes: max_bytes, web_fetch_timeout_s: timeout_s, ..ToolsCfg::default() };
        env_with(cfg, SandboxCfg { mode: SandboxMode::None, ..SandboxCfg::default() })
    }

    #[tokio::test]
    async fn plain_text() {
        let base = serve(Router::new().route("/t", get(|| async { "hello world" }))).await;
        let e = env();
        let r = e.call("web_fetch", json!({"url": format!("{base}/t")})).await;
        assert_eq!(r.status, ToolStatus::Ok, "{}", r.text);
        assert!(r.text.contains("HTTP 200"), "{}", r.text);
        assert!(r.text.contains("11 bytes"), "{}", r.text);
        assert_eq!(e.stored(&r), "hello world");
        assert!(r.meta.get(META_RAW_BLOB).is_none());
    }

    #[tokio::test]
    async fn html_is_rendered_and_the_original_is_stored() {
        let page = "<html><body><h1>Title</h1><p>Some <b>bold</b> words.</p></body></html>";
        let base = serve(Router::new().route("/p", get(|| async { html(page) }))).await;
        let e = env();
        let r = e.call("web_fetch", json!({"url": format!("{base}/p")})).await;
        let shown = e.stored(&r);
        assert!(shown.contains("Title") && shown.contains("bold"), "{shown}");
        assert!(!shown.contains("<h1>"), "{shown}");
        assert!(r.text.contains("html rendered as text (raw: out:"), "{}", r.text);
        let raw_id = r.meta.get(META_RAW_BLOB).and_then(Value::as_str).unwrap();
        let id = e.ctx.blobs.resolve(raw_id).unwrap();
        assert_eq!(e.ctx.blobs.read_all(&id).unwrap(), page.as_bytes());
    }

    #[tokio::test]
    async fn html_is_recognised_by_its_start_without_a_content_type() {
        let base = serve(Router::new().route("/p", get(|| async { "  <!DOCTYPE HTML><html><body><p>sniffed</p></body></html>" }))).await;
        let e = env();
        let r = e.call("web_fetch", json!({"url": format!("{base}/p")})).await;
        assert!(r.text.contains("html rendered as text"), "{}", r.text);
        assert!(!e.stored(&r).contains("<p>"));
    }

    #[tokio::test]
    async fn raw_returns_the_source() {
        let page = "<html><body><h1>Title</h1></body></html>";
        let base = serve(Router::new().route("/p", get(|| async { html(page) }))).await;
        let e = env();
        let r = e.call("web_fetch", json!({"url": format!("{base}/p"), "raw": true})).await;
        assert_eq!(e.stored(&r), page);
        assert!(!r.text.contains("rendered as text"), "{}", r.text);
        assert!(r.meta.get(META_RAW_BLOB).is_none());
    }

    #[tokio::test]
    async fn redirect_chain_is_followed_and_reported() {
        let app = Router::new()
            .route("/a", get(|| async { Redirect::temporary("/b") }))
            .route("/b", get(|| async { Redirect::permanent("/c") }))
            .route("/c", get(|| async { "arrived" }));
        let base = serve(app).await;
        let e = env();
        let r = e.call("web_fetch", json!({"url": format!("{base}/a")})).await;
        assert_eq!(r.status, ToolStatus::Ok, "{}", r.text);
        assert_eq!(e.stored(&r), "arrived");
        assert!(r.text.contains(&format!("redirected: {base}/a → {base}/b → {base}/c")), "{}", r.text);
        assert!(r.text.contains(&format!("final URL: {base}/c")), "{}", r.text);
    }

    #[tokio::test]
    async fn redirect_loop_stops_at_ten() {
        let base = serve(Router::new().route("/loop", get(|| async { Redirect::to("/loop") }))).await;
        let e = env();
        let r = e.call("web_fetch", json!({"url": format!("{base}/loop")})).await;
        assert_eq!(r.status, ToolStatus::Error, "{}", r.text);
        assert!(r.text.contains("stopped after 10 redirects"), "{}", r.text);
        assert!(r.text.matches(&format!("{base}/loop")).count() >= 11, "{}", r.text);
    }

    #[tokio::test]
    async fn a_redirect_without_a_location_is_the_response() {
        let app = Router::new().route("/r", get(|| async { (StatusCode::FOUND, "moved, no target") }));
        let base = serve(app).await;
        let e = env();
        let r = e.call("web_fetch", json!({"url": format!("{base}/r")})).await;
        assert_eq!(r.status, ToolStatus::Ok);
        assert!(r.text.contains("HTTP 302"), "{}", r.text);
        assert_eq!(e.stored(&r), "moved, no target");
    }

    #[tokio::test]
    async fn error_status_is_an_observation_with_its_body() {
        let app = Router::new().route("/missing", get(|| async { (StatusCode::NOT_FOUND, "no such page here") }));
        let base = serve(app).await;
        let e = env();
        let r = e.call("web_fetch", json!({"url": format!("{base}/missing")})).await;
        assert_eq!(r.status, ToolStatus::Ok);
        assert!(r.text.contains("HTTP 404"), "{}", r.text);
        assert_eq!(e.stored(&r), "no such page here");
    }

    #[tokio::test]
    async fn size_limit_is_reported() {
        let base = serve(Router::new().route("/big", get(|| async { "a".repeat(5000) }))).await;
        let e = quick(1000, 30);
        let r = e.call("web_fetch", json!({"url": format!("{base}/big")})).await;
        assert_eq!(r.status, ToolStatus::Ok);
        assert_eq!(e.stored(&r).len(), 1000);
        assert!(r.text.contains("stopped at 1000 bytes — the response is larger"), "{}", r.text);
        // A body of exactly the limit is complete.
        let base = serve(Router::new().route("/exact", get(|| async { "a".repeat(1000) }))).await;
        let r = e.call("web_fetch", json!({"url": format!("{base}/exact")})).await;
        assert!(!r.text.contains("stopped at"), "{}", r.text);
    }

    #[tokio::test]
    async fn timeout_is_an_error_that_says_so() {
        let app = Router::new().route(
            "/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(30)).await;
                "late"
            }),
        );
        let base = serve(app).await;
        let e = quick(1000, 1);
        let r = e.call("web_fetch", json!({"url": format!("{base}/slow")})).await;
        assert_eq!(r.status, ToolStatus::Error, "{}", r.text);
        assert!(r.text.contains("timed out after 1 s"), "{}", r.text);
    }

    #[tokio::test]
    async fn cancel_interrupts() {
        let app = Router::new().route(
            "/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(30)).await;
                "late"
            }),
        );
        let base = serve(app).await;
        let e = env();
        let cancel = e.ctx.cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            cancel.cancel();
        });
        let r = e.call("web_fetch", json!({"url": format!("{base}/slow")})).await;
        assert_eq!(r.status, ToolStatus::Interrupted, "{}", r.text);
        assert!(r.text.contains("cancelled"), "{}", r.text);
    }

    #[tokio::test]
    async fn bad_urls_are_error_sentences() {
        let e = env();
        for bad in ["not a url", "ftp://example.com/file", "file:///etc/passwd", "http://"] {
            let r = e.call("web_fetch", json!({"url": bad})).await;
            assert_eq!(r.status, ToolStatus::Error, "{bad}: {}", r.text);
            assert!(r.text.contains("Call again with a full http:// or https:// URL"), "{bad}: {}", r.text);
        }
    }

    #[tokio::test]
    async fn connection_refused_names_the_stage() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let e = env();
        let r = e.call("web_fetch", json!({"url": format!("http://127.0.0.1:{port}/")})).await;
        assert_eq!(r.status, ToolStatus::Error);
        assert!(r.text.contains("could not connect"), "{}", r.text);
    }

    #[tokio::test]
    async fn the_words_of_the_url_do_not_decide_the_stage() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let url = format!("http://127.0.0.1:{port}/ssl-guide/tls-handshake-and-proxy-tunnel-dns");
        let mut e = env();
        let r = e.call("web_fetch", json!({"url": url})).await;
        assert_eq!(r.status, ToolStatus::Error);
        assert!(r.text.contains("could not connect"), "{}", r.text);
        // Through the egress proxy, which refuses loopback: a refusal, whatever the path says.
        let (proxy, grant) = loom_proxy(&[], &[]).await;
        e.ctx.env = Arc::new(grant.env());
        let r = e.call("web_fetch", json!({"url": url})).await;
        assert_eq!(r.status, ToolStatus::Denied, "{}", r.text);
        assert!(r.text.contains("refused by rule `deny private-address 127.0.0.1`"), "{}", r.text);
        drop(proxy);
    }

    #[tokio::test]
    async fn large_html_is_converted_completely() {
        let mut page = String::from("<html><body>");
        for i in 0..40_000 {
            page.push_str(&format!("<p>paragraph number {i}</p>\n"));
        }
        page.push_str("<p>THE-END-MARKER</p></body></html>");
        let served = page.clone();
        let app = Router::new().route(
            "/big",
            get(move || {
                let served = served.clone();
                async move { ([(header::CONTENT_TYPE, "text/html")], served) }
            }),
        );
        let base = serve(app).await;
        let e = env();
        let r = e.call("web_fetch", json!({"url": format!("{base}/big")})).await;
        let stored = e.stored(&r);
        assert!(stored.contains("paragraph number 0"));
        assert!(stored.contains("THE-END-MARKER"), "the end of the document is missing");
        let raw_id = r.meta.get(META_RAW_BLOB).and_then(Value::as_str).unwrap();
        let id = e.ctx.blobs.resolve(raw_id).unwrap();
        assert_eq!(e.ctx.blobs.read_all(&id).unwrap().len(), page.len());
    }

    #[tokio::test]
    async fn the_session_proxy_is_used_and_its_refusal_is_denied() {
        // The "proxy" sees the absolute-form request and refuses it the way the egress proxy does.
        let app = Router::new().fallback(|| async {
            let mut h = HeaderMap::new();
            h.insert("x-loom-proxy", HeaderValue::from_static("1"));
            (StatusCode::FORBIDDEN, h, "host not allowed by policy")
        });
        let proxy = serve(app).await;
        let mut e = env();
        let mut vars = BTreeMap::new();
        vars.insert("HTTP_PROXY".to_string(), proxy.clone());
        e.ctx.env = Arc::new(vars);
        let r = e.call("web_fetch", json!({"url": "http://blocked.invalid/page"})).await;
        assert_eq!(r.status, ToolStatus::Denied, "{}", r.text);
        assert!(r.text.contains("host not allowed by policy"), "{}", r.text);
    }

    /// The real egress proxy with an open policy and these deny and allow_private lists, and a grant.
    async fn loom_proxy(deny: &[&str], private: &[&str]) -> (loom_net::Proxy, loom_net::SessionGrant) {
        let v = |x: &[&str]| x.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let cfg = NetworkCfg { mode: NetworkMode::Open, allow: Vec::new(), deny: v(deny), allow_private: v(private) };
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let proxy = loom_net::Proxy::start(0, tx).await.unwrap();
        let grant = proxy.grant(&loom_core::SessionId::from("s-web"), loom_net::Policy::new(&cfg).unwrap());
        (proxy, grant)
    }

    #[tokio::test]
    async fn an_https_refusal_reports_the_proxy_rule_and_an_unreachable_host_is_not_one() {
        let (proxy, grant) = loom_proxy(&["blocked.test"], &["127.0.0.1"]).await;
        let mut e = env();
        e.ctx.env = Arc::new(grant.env());
        let r = e.call("web_fetch", json!({"url": "https://blocked.test/ssl/page"})).await;
        assert_eq!(r.status, ToolStatus::Denied, "{}", r.text);
        assert!(r.text.contains("refused by rule `deny blocked.test`"), "{}", r.text);
        // Allowed, but nothing listens there: an error that says so, not a refusal.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let r = e.call("web_fetch", json!({"url": format!("https://127.0.0.1:{port}/")})).await;
        assert_eq!(r.status, ToolStatus::Error, "{}", r.text);
        let expected = "could not be reached through the egress proxy, which allows it by rule `allow_private 127.0.0.1`";
        assert!(r.text.contains(expected), "{}", r.text);
        drop(proxy);
    }

    #[tokio::test]
    async fn an_https_request_that_fails_to_connect_after_the_check_puts_the_question_again() {
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
        let grant = proxy.grant(&SessionId::from("s-web-again"), loom_net::Policy::new(&cfg).unwrap());
        let mut e = env();
        e.ctx.env = Arc::new(grant.env());
        let r = e.call("web_fetch", json!({"url": "https://127.0.0.1:9/"})).await;
        assert_eq!(r.status, ToolStatus::Denied, "{}", r.text);
        assert!(r.text.contains("refused by rule `mode deny_all`"), "{}", r.text);
        proxy.shutdown();
        // A proxy that gives no verdict (here every connection of the session is over its limit) is
        // named as what stopped the request, not a server that may be down.
        let limits = loom_net::Limits { max_per_session: 0, ..loom_net::Limits::default() };
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let proxy = loom_net::Proxy::start_with(0, tx, None, limits).await.unwrap();
        let grant = proxy.grant(&SessionId::from("s-web-busy"), loom_net::Policy::new(&cfg).unwrap());
        e.ctx.env = Arc::new(grant.env());
        let r = e.call("web_fetch", json!({"url": "https://127.0.0.1:9/"})).await;
        assert_eq!(r.status, ToolStatus::Error, "{}", r.text);
        let expected = "the egress proxy did not open a tunnel to the destination and gave no verdict on it";
        assert!(r.text.contains(expected) && !r.text.contains("could not connect"), "{}", r.text);
    }

    #[tokio::test]
    async fn the_marker_counts_only_on_the_answer_to_an_http_url_through_the_proxy() {
        let e = env();
        let answer = || {
            let resp = axum::http::Response::builder().status(403).header("x-loom-proxy", "1").body("origin says no").unwrap();
            reqwest::Response::from(resp)
        };
        let raw_body = |r: &ToolOutput| match &r.body {
            Body::Raw(b) => String::from_utf8_lossy(b).to_string(),
            _ => String::new(),
        };
        // Inside the tunnel of an https URL only the origin speaks: its 403 is an observation.
        let https = [Url::parse("https://origin.test/x").unwrap()];
        let r = finish(&e.ctx, answer(), &https, false, true).await;
        assert_eq!((r.status, r.outcome.as_str(), raw_body(&r).as_str()), (ToolStatus::Ok, "HTTP 403", "origin says no"));
        // The answer to an http URL through the proxy is the proxy's.
        let http = [Url::parse("http://origin.test/x").unwrap()];
        let r = finish(&e.ctx, answer(), &http, false, true).await;
        assert_eq!(r.status, ToolStatus::Denied);
        // Without a proxy there is no proxy to answer.
        assert_eq!(finish(&e.ctx, answer(), &http, false, false).await.status, ToolStatus::Ok);
    }

    #[tokio::test]
    async fn a_proxy_status_without_the_marker_is_an_ordinary_response() {
        let app = Router::new().fallback(|| async { (StatusCode::FORBIDDEN, "origin says no") });
        let base = serve(app).await;
        let e = env();
        let r = e.call("web_fetch", json!({"url": format!("{base}/x")})).await;
        assert_eq!(r.status, ToolStatus::Ok);
        assert!(r.text.contains("HTTP 403"), "{}", r.text);
        assert_eq!(e.stored(&r), "origin says no");
    }
}
