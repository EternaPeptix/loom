//! Exchanges the in-process tools make themselves (CONTRACTS-TRAFFIC-TARGETS C3).
//!
//! `http_send`, `http_repeat`, `web_fetch` and MCP over HTTP build the HTTP/1.1 messages they sent and
//! received, store them as blobs and hand the [`Exchange`] back through `ToolOutput::with_exchanges`; the
//! session records one `exchange` right after the call's `tool_result`. They exist whether or not the proxy
//! captures, so a finding can point at them.

use crate::ToolCtx;
use loom_core::event::Exchange;
use loom_core::ids::new_exchange_id;
use std::time::Instant;
use url::Url;

/// Bytes kept per body (`[network] capture_max_bytes` default). The true size is always recorded.
pub const CAPTURE_MAX_BYTES: usize = 1 << 20;

/// An HTTP/1.1 request message: head and body.
pub fn request_message(method: &str, url: &Url, headers: &[(String, String)], body: &[u8]) -> Vec<u8> {
    let target = target_of(url);
    let mut out = format!("{method} {target} HTTP/1.1\r\n").into_bytes();
    if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
        let host = url.host_str().unwrap_or_default();
        let host = match url.port() {
            Some(p) => format!("{host}:{p}"),
            None => host.to_string(),
        };
        out.extend_from_slice(format!("Host: {host}\r\n").as_bytes());
    }
    for (k, v) in headers {
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    if !body.is_empty() && !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-length")) {
        out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

/// An HTTP/1.1 response message: head and body.
pub fn response_message(status: u16, headers: &[(String, String)], body: &[u8]) -> Vec<u8> {
    let reason = reqwest::StatusCode::from_u16(status).ok().and_then(|s| s.canonical_reason()).unwrap_or("");
    let mut out = format!("HTTP/1.1 {status} {reason}\r\n").into_bytes();
    for (k, v) in headers {
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

/// Path and query as sent.
pub fn target_of(url: &Url) -> String {
    match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_string(),
    }
}

/// Cuts the body part of a message to [`CAPTURE_MAX_BYTES`]; the head is kept whole. True when it cut.
fn bounded(message: &[u8]) -> (&[u8], bool) {
    let head = message.windows(4).position(|w| w == b"\r\n\r\n").map_or(message.len(), |p| p + 4);
    let keep = head.saturating_add(CAPTURE_MAX_BYTES).min(message.len());
    (message.get(..keep).unwrap_or(message), keep < message.len())
}

/// What a tool knows of one exchange.
pub struct Made<'a> {
    pub tool: &'a str,
    pub url: &'a Url,
    pub method: &'a str,
    /// The whole request message (see [`request_message`]).
    pub request: &'a [u8],
    /// The whole response message, when one arrived.
    pub response: Option<&'a [u8]>,
    pub status: Option<u16>,
    pub error: Option<String>,
    /// The tool itself cut the response body (its own read limit).
    pub response_cut: bool,
    pub started: Instant,
}

/// Stores the messages and returns the record. `None` when the blob store refuses (a harness fault the
/// tool should not turn into a failed call).
pub fn record(ctx: &ToolCtx, made: &Made<'_>) -> Option<Exchange> {
    let (req, req_cut) = bounded(made.request);
    let request = ctx.blobs.put_bytes(req).ok()?;
    let (response, resp_cut) = match made.response {
        Some(r) => {
            let (kept, cut) = bounded(r);
            (Some(ctx.blobs.put_bytes(kept).ok()?), cut)
        }
        None => (None, false),
    };
    Some(Exchange {
        id: new_exchange_id(),
        call_id: Some(ctx.call_id.clone()),
        source: "tool".into(),
        tool: Some(made.tool.to_string()),
        scheme: made.url.scheme().to_string(),
        tls: "tool".into(),
        method: made.method.to_string(),
        host: made.url.host_str().unwrap_or_default().to_string(),
        port: made.url.port_or_known_default().unwrap_or(0),
        target: target_of(made.url),
        status: made.status,
        error: made.error.clone(),
        request,
        response,
        request_bytes: made.request.len() as u64,
        response_bytes: made.response.map_or(0, |r| r.len() as u64),
        truncated: req_cut || resp_cut || made.response_cut,
        upstream_unverified: false,
        duration_ms: made.started.elapsed().as_millis() as u64,
    })
}

/// Parses a stored request message back into method, header pairs (without `Host`) and body.
/// A parsed request: method, headers (without Host and Content-Length), body.
pub type Parsed = (String, Vec<(String, String)>, Vec<u8>);

pub fn parse_request(message: &[u8]) -> Option<Parsed> {
    let split = message.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(message.get(..split)?).ok()?;
    let body = message.get(split + 4..)?.to_vec();
    let mut lines = head.split("\r\n");
    let method = lines.next()?.split(' ').next()?.to_string();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .filter(|(k, _)| !k.eq_ignore_ascii_case("host") && !k.eq_ignore_ascii_case("content-length"))
        .collect();
    Some((method, headers, body))
}

/// Finds a recorded exchange by id: the runtime reads the session's log (so it works after a restart).
pub type ExchangeLookup = dyn Fn(&str) -> Option<Exchange> + Send + Sync;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_round_trip_and_cut_bodies() {
        let url = Url::parse("http://t.test:8080/a?b=1").unwrap();
        let m = request_message("POST", &url, &[("X-A".into(), "1".into())], b"hello");
        let text = String::from_utf8(m.clone()).unwrap();
        assert!(text.starts_with("POST /a?b=1 HTTP/1.1\r\nHost: t.test:8080\r\n"), "{text}");
        let (method, headers, body) = parse_request(&m).unwrap();
        assert_eq!((method.as_str(), body.as_slice()), ("POST", &b"hello"[..]));
        assert_eq!(headers, vec![("X-A".to_string(), "1".to_string())]);
        let big = response_message(200, &[], &vec![b'x'; CAPTURE_MAX_BYTES + 10]);
        let (kept, cut) = bounded(&big);
        assert!(cut && kept.len() < big.len());
    }
}
