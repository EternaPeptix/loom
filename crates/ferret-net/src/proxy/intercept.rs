//! Captured exchanges and HTTPS interception of the proxy (CONTRACTS-TRAFFIC-TARGETS C3, I4).
//!
//! CONTRACT
//!
//! Capture. A session granted with [`Proxy::grant_with_capture`] has its forwarded plain `http://` requests
//! captured: one [`Captured`] per request, sent to the grant's sink with the session id when the request
//! ends (response complete, or failed with `error`). `request` is the head as the destination received
//! it (origin-form target, no `Proxy-Authorization`, `Proxy-Connection`, `Connection` or `Upgrade`, and the
//! proxy's own `Connection: close`) and the request body; `response` is the head and body as the proxy
//! relayed them to the client (for plain HTTP that is the rewritten head of *Forwarded requests*). Each body is
//! kept up to `max_bytes`; `request_bytes` and `response_bytes` are the sizes of the whole messages (head and
//! the full body) and `truncated` says a body was cut. Capture only copies what is relayed: it does not
//! wait for the sink (an unbounded channel), and a closed sink drops the capture and nothing else.
//! A session granted without capture is relayed exactly as before.
//!
//! Interception. For an allowed `CONNECT host:port` of a session whose grant has `intercept` and a CA, unless
//! the host (`host` or `host:port`, `*`, `*.suffix`) is in `passthrough`, or the client sent bytes ahead of the
//! `200`, or it does not start a TLS handshake within 3 s (a server-first protocol, or not TLS at all, which is
//! then tunneled as bytes), the proxy
//! 1. connects to the destination with TLS (SNI = host, ALPN `http/1.1`; roots = Mozilla roots plus
//!    [`Proxy::set_upstream_roots`]; no verification for a host in `upstream_insecure`, whose exchanges all
//!    carry `upstream_unverified`). A handshake that fails is recorded as the decision
//!    `upstream certificate not valid for {host}: {reason}` (refused) and as one `Captured` with method
//!    `CONNECT`, target `host:port` and that `error`; the client's handshake is then ended with a TLS alert;
//! 2. does the TLS handshake with the client using a leaf of the CA for the host. A client that refuses it is
//!    recorded as the decision `client refused the interception certificate for {host}`;
//! 3. serves HTTP/1.1 on the decrypted stream, one request after the other (keep-alive), each relayed as it
//!    arrives and captured when its response ends, with `transport: Intercepted`. The head bytes are
//!    forwarded as the client sent them. Bodies are followed by their framing (`Content-Length`, chunked).
//!    A `101` response turns the connection into a byte relay after it. A request that cannot be framed
//!    (an unknown transfer coding) or parsed gets `400` and ends the connection.
//!    If the first bytes after the handshake are not an HTTP/1.1 request, or none come within 3 s, the stream
//!    is relayed as bytes and one `Captured` with method `TLS`, target `host:port`, no status and
//!    `error: "not HTTP/1.1: {up} bytes out, {down} bytes in, not stored"` is sent when it ends.
//!
//! The decision for the CONNECT (allow or refusal, address) is made and recorded once, before any of this, by
//! the same path as an opaque tunnel.

use super::*;
use crate::capture::{CaptureGrant, CaptureSink, Captured, Transport};
use crate::inject::{apply_head, Inject};
use crate::tls::Ca;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::ClientConfig;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// How long a tunnel's client may stay silent before it is taken for a protocol that does not start with
/// a TLS or HTTP message from the client.
const FIRST_BYTES: Duration = Duration::from_secs(3);

/// A session's capture settings.
pub(super) struct CaptureCfg {
    pub grant: CaptureGrant,
    pub sink: CaptureSink,
    pub ca: Option<Arc<Ca>>,
}

/// Whether `host:port` is named by one of `patterns`: `host`, `host:port`, `*` or `*.suffix` (any depth).
pub fn listed(patterns: &[String], host: &str, port: u16) -> bool {
    let host = normalize_host(host);
    patterns.iter().any(|p| {
        let p = p.trim();
        let (name, want) = match p.rsplit_once(':') {
            Some((n, port)) if !n.contains(':') || n.starts_with('[') => match port.parse::<u16>() {
                Ok(v) => (n, Some(v)),
                Err(_) => (p, None),
            },
            _ => (p, None),
        };
        if want.is_some_and(|w| w != port) {
            return false;
        }
        let name = normalize_host(name);
        match name.strip_prefix("*.") {
            Some(suffix) => host.len() > suffix.len() + 1 && host.ends_with(&format!(".{suffix}")),
            None => name == "*" || name == host,
        }
    })
}

impl CaptureCfg {
    /// Whether a tunnel to `host:port` is decrypted.
    pub fn intercepts(&self, host: &str, port: u16) -> bool {
        self.grant.intercept && self.ca.is_some() && !listed(&self.grant.passthrough, host, port) && self.in_scope(host)
    }

    /// Whether `host` passes the grant's `intercept_scope` (always, when it has none).
    fn in_scope(&self, host: &str) -> bool {
        self.grant.intercept_scope.as_ref().is_none_or(|s| s.contains(host))
    }

    fn insecure(&self, host: &str, port: u16) -> bool {
        listed(&self.grant.upstream_insecure, host, port)
    }

    /// Hands a capture to the sink, with the destination of `cx`. A closed sink drops it.
    pub fn send(&self, cx: &Ctx<'_>, mut c: Captured) {
        if !self.in_scope(cx.host) {
            return;
        }
        c.host = cx.host.to_string();
        c.port = cx.port;
        let _ = self.sink.send((cx.session.clone(), c));
    }
}

/// The TLS client configs towards destinations, built on first use.
#[derive(Default)]
pub(super) struct UpstreamTls {
    extra: Vec<CertificateDer<'static>>,
    verified: Option<Arc<ClientConfig>>,
    unverified: Option<Arc<ClientConfig>>,
}

impl UpstreamTls {
    pub fn set_extra(&mut self, roots: Vec<CertificateDer<'static>>) {
        *self = UpstreamTls { extra: roots, verified: None, unverified: None };
    }

    fn get(&mut self, verify: bool) -> Result<Arc<ClientConfig>, String> {
        let slot = if verify { &mut self.verified } else { &mut self.unverified };
        if let Some(c) = slot {
            return Ok(c.clone());
        }
        let c = crate::tls::upstream_client_config(&self.extra, verify)?;
        *slot = Some(c.clone());
        Ok(c)
    }
}

/// What one exchange has relayed so far, kept for its capture.
pub(super) struct Tap {
    max: u64,
    started: Instant,
    ts_ms: u64,
    d: Mutex<TapData>,
}

struct TapData {
    req_head: Vec<u8>,
    req_body: Vec<u8>,
    req_body_total: u64,
    resp: Vec<u8>,
    resp_total: u64,
    head_end: Option<u64>,
    status: Option<u16>,
}

impl Tap {
    pub fn new(max_bytes: u64, req_head: Vec<u8>) -> Tap {
        let ts_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let d = TapData {
            req_head,
            req_body: Vec::new(),
            req_body_total: 0,
            resp: Vec::new(),
            resp_total: 0,
            head_end: None,
            status: None,
        };
        Tap { max: max_bytes, started: Instant::now(), ts_ms, d: Mutex::new(d) }
    }

    /// Request body bytes that were written to the destination.
    pub fn request_body(&self, data: &[u8]) {
        let mut d = lock(&self.d);
        d.req_body_total = d.req_body_total.saturating_add(data.len() as u64);
        let room = usize::try_from(self.max).unwrap_or(usize::MAX).saturating_sub(d.req_body.len());
        d.req_body.extend_from_slice(data.get(..room.min(data.len())).unwrap_or(&[]));
    }

    /// Response bytes that were written to the client; `head_end` is where the body starts in all the response
    /// bytes so far, once the final head is in them, and `status` its code.
    pub fn response(&self, data: &[u8], head_end: Option<u64>, status: Option<u16>) {
        let mut d = lock(&self.d);
        d.resp_total = d.resp_total.saturating_add(data.len() as u64);
        if head_end.is_some() {
            d.head_end = head_end;
        }
        if status.is_some() {
            d.status = status;
        }
        let limit = match d.head_end {
            Some(h) => usize::try_from(h.saturating_add(self.max)).unwrap_or(usize::MAX),
            None => 2 * MAX_HEAD,
        };
        let room = limit.saturating_sub(d.resp.len());
        d.resp.extend_from_slice(data.get(..room.min(data.len())).unwrap_or(&[]));
    }

    /// Bytes of the response written so far.
    fn response_total(&self) -> u64 {
        lock(&self.d).resp_total
    }

    /// The capture of the exchange as it stands; the host and port are added by [`CaptureCfg::send`].
    pub fn finish(
        &self,
        transport: Transport,
        method: &str,
        target: &str,
        error: Option<String>,
        upstream_unverified: bool,
    ) -> Captured {
        let d = lock(&self.d);
        let resp_body = d.head_end.map_or(0, |h| d.resp_total.saturating_sub(h));
        let mut request = d.req_head.clone();
        request.extend_from_slice(&d.req_body);
        Captured {
            ts_ms: self.ts_ms,
            transport,
            method: method.to_string(),
            host: String::new(),
            port: 0,
            target: target.to_string(),
            status: d.status,
            error,
            request,
            response: (!d.resp.is_empty()).then(|| d.resp.clone()),
            request_bytes: (d.req_head.len() as u64).saturating_add(d.req_body_total),
            response_bytes: d.resp_total,
            truncated: d.req_body_total > self.max || resp_body > self.max,
            upstream_unverified,
            duration_ms: u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
        }
    }
}

/// How the interception of a tunnel ended.
pub(super) enum Ended {
    /// Served (or refused) and closed.
    Done,
    /// The client does not speak TLS (or nothing): the streams, for an opaque tunnel.
    Opaque(TcpStream, TcpStream),
}

/// Intercepts an allowed tunnel whose `200` has been sent (see the module contract).
pub(super) async fn run(
    client: TcpStream,
    up: TcpStream,
    cx: &Ctx<'_>,
    allowed: &Allowed,
    cap: &CaptureCfg,
    inject: Option<&Inject>,
    cancel: &CancellationToken,
) -> Ended {
    let Some(ca) = cap.ca.as_ref() else { return Ended::Opaque(client, up) };
    let mut first = [0u8; 1];
    match tokio::time::timeout(FIRST_BYTES, client.peek(&mut first)).await {
        Ok(Ok(1)) if first[0] == 0x16 => {}
        Ok(Ok(0) | Err(_)) => return Ended::Done,
        _ => return Ended::Opaque(client, up),
    }
    let limits = &cx.shared.limits;
    let insecure = cap.insecure(cx.host, cx.port);
    let config = lock(&cx.shared.upstream_tls).get(!insecure);
    let (config, name) = match (config, ServerName::try_from(cx.host.to_string())) {
        (Ok(c), Ok(n)) => (c, n),
        (Err(why), _) => return refuse_client(client, cx, allowed, cap, &why, insecure).await,
        (_, Err(_)) => return Ended::Opaque(client, up),
    };

    // The destination first: a certificate that does not verify refuses the client before it sends anything.
    let upstream = tokio::time::timeout(CONNECT_TIMEOUT, TlsConnector::from(config).connect(name, up)).await;
    let up_tls = match upstream {
        Ok(Ok(s)) => s,
        other => {
            let reason = match other {
                Ok(Err(e)) => e.to_string(),
                _ => format!("the TLS handshake did not finish within {}", human(CONNECT_TIMEOUT)),
            };
            let why = format!("upstream certificate not valid for {}: {reason}", cx.host);
            return refuse_client(client, cx, allowed, cap, &why, insecure).await;
        }
    };

    let leaf = match ca.leaf(cx.host) {
        Ok(l) => l,
        Err(why) => {
            cx.failed_after_allow(allowed, &format!("no interception certificate: {why}")).await;
            return Ended::Done;
        }
    };
    let accepted = tokio::time::timeout(limits.head_timeout, TlsAcceptor::from(leaf).accept(client)).await;
    let Ok(Ok(client_tls)) = accepted else {
        let rule = format!("client refused the interception certificate for {}", cx.host);
        cx.record_best_effort(true, rule, Some(allowed.ip)).await;
        return Ended::Done;
    };
    tokio::select! {
        _ = serve(client_tls, up_tls, cx, cap, inject, insecure, cancel) => {}
        _ = cancel.cancelled() => cx.failed_after_allow(allowed, SHUTDOWN).await,
    }
    Ended::Done
}

/// The destination cannot be spoken to as a TLS client: record the decision and the capture with `why`, and
/// end the client's handshake with an alert.
async fn refuse_client(
    client: TcpStream,
    cx: &Ctx<'_>,
    allowed: &Allowed,
    cap: &CaptureCfg,
    why: &str,
    unverified: bool,
) -> Ended {
    cx.record_best_effort(false, why.to_string(), Some(allowed.ip)).await;
    let tap = Tap::new(cap.grant.max_bytes, Vec::new());
    let target = format!("{}:{}", cx.host, cx.port);
    cap.send(cx, tap.finish(Transport::Intercepted, "CONNECT", &target, Some(why.to_string()), unverified));
    if let Ok(refusing) = crate::tls::refusing_server_config() {
        let _ = tokio::time::timeout(Duration::from_secs(2), TlsAcceptor::from(refusing).accept(client)).await;
    }
    Ended::Done
}

type Cs = tokio_rustls::server::TlsStream<TcpStream>;
type Us = tokio_rustls::client::TlsStream<TcpStream>;

/// What reading a request head gave.
enum Req {
    Head(Head, Vec<u8>),
    /// The client ended, or was silent, between requests.
    Closed,
    /// The first bytes are not an HTTP/1.1 request (or none came).
    NotHttp,
    Bad(String),
}

async fn read_request<R: AsyncRead + Unpin>(r: &mut R, buf: &mut Vec<u8>, first: bool, cx: &Ctx<'_>) -> Req {
    let limits = &cx.shared.limits;
    loop {
        match try_parse(buf) {
            Ok(Some((head, n))) => {
                if n > MAX_HEAD {
                    return Req::Bad(too_large());
                }
                return Req::Head(head, buf.drain(..n).collect());
            }
            Ok(None) => {}
            Err(m) => return if first { Req::NotHttp } else { Req::Bad(m) },
        }
        if buf.len() >= MAX_HEAD {
            return Req::Bad(too_large());
        }
        let wait = match (buf.is_empty(), first) {
            (true, true) => FIRST_BYTES,
            (true, false) => limits.idle_timeout,
            (false, _) => limits.head_timeout,
        };
        match tokio::time::timeout(wait, r.read_buf(buf)).await {
            Ok(Ok(0)) if buf.is_empty() => return Req::Closed,
            Ok(Ok(0)) => return if first { Req::NotHttp } else { Req::Bad("the request head is incomplete".into()) },
            Ok(Ok(_)) => {}
            Ok(Err(_)) => return Req::Closed,
            Err(_) if buf.is_empty() => return if first { Req::NotHttp } else { Req::Closed },
            Err(_) => return Req::Bad(format!("no complete request head arrived within {}", human(wait))),
        }
    }
}

/// Writes all of `bytes` and flushes, within `idle`.
async fn send<W: AsyncWrite + Unpin>(w: &mut W, bytes: &[u8], idle: Duration) -> bool {
    let both = async {
        w.write_all(bytes).await?;
        w.flush().await
    };
    matches!(tokio::time::timeout(idle, both).await, Ok(Ok(())))
}

async fn bad_request_tls<W: AsyncWrite + Unpin>(w: &mut W, why: &str, idle: Duration) {
    let body = format!("ferret proxy: {why}\n");
    let text = format!(
        "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    send(w, text.as_bytes(), idle).await;
}

/// The decrypted stream of an intercepted tunnel: requests one by one, then closed.
async fn serve(
    client: Cs,
    up: Us,
    cx: &Ctx<'_>,
    cap: &CaptureCfg,
    inject: Option<&Inject>,
    unverified: bool,
    cancel: &CancellationToken,
) {
    let idle = cx.shared.limits.idle_timeout;
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut ur, mut uw) = tokio::io::split(up);
    let (mut cbuf, mut ubuf): (Vec<u8>, Vec<u8>) = (Vec::new(), Vec::new());
    let mut first = true;
    loop {
        let (head, raw) = match read_request(&mut cr, &mut cbuf, first, cx).await {
            Req::Head(h, raw) => (h, raw),
            Req::Closed => break,
            Req::NotHttp => {
                raw_tls(&mut cr, &mut cw, &mut ur, &mut uw, cbuf, cx, cap, unverified).await;
                return;
            }
            Req::Bad(why) => {
                bad_request_tls(&mut cw, &why, idle).await;
                break;
            }
        };
        first = false;
        let gov = cx.shared.governor();
        let _pace = gov.acquire(cx.host, cancel).await;
        // S3, S6: decided again for every request of the connection, on the tunnel's destination.
        let mut raw = match inject.filter(|i| i.applies_to(cx.host)).and_then(|i| apply_head(i.items(), cx.host, &raw)) {
            Some(injected) => injected,
            None => raw,
        };
        if let Some(ua) = cx.shared.assessment_ua() {
            if let Some(tagged) = ua.apply_raw_request_head("https", cx.host, cx.port, &raw) {
                raw = tagged;
            }
        }
        if let Some(ua) = gov.profile().user_agent.as_deref() {
            if let Some(tagged) = crate::rewrite::apply_default_ua_raw(&raw, ua) {
                raw = tagged;
            }
        }
        let mut req_method = head.method.clone();
        let mut req_target = head.target.clone();
        if let Some((rewritten, m, t, _ids)) = cx.shared.rewrites().apply_raw_request_head_parts(cx.host, &raw) {
            raw = rewritten;
            req_method = m;
            req_target = t;
        }
        let body = match body_kind(&head) {
            Ok(Body::Stream) => {
                bad_request_tls(&mut cw, "a request body with this transfer coding cannot be relayed", idle).await;
                break;
            }
            Ok(b) => b,
            Err(m) => {
                bad_request_tls(&mut cw, &m, idle).await;
                break;
            }
        };
        let http11 = raw.split(|b| *b == b'\n').next().is_some_and(|l| l.trim_ascii_end().ends_with(b"HTTP/1.1"));
        let keep = http11 && !connection_has(&head.headers, "close");
        let tap = Tap::new(cap.grant.max_bytes, raw.clone());
        let head_request = req_method.eq_ignore_ascii_case("HEAD");
        let x = exchange(
            &mut cr,
            &mut cw,
            &mut ur,
            &mut uw,
            &mut cbuf,
            &mut ubuf,
            &raw,
            body,
            head_request,
            &tap,
            idle,
            (!gov.is_off()).then_some((&*gov, cx.host)),
        );
        let out = x.await;
        cap.send(cx, tap.finish(Transport::Intercepted, &req_method, &req_target, out.error.clone(), unverified));
        if out.upgraded {
            let _ = pump(&mut cr, &mut cw, &mut ur, &mut uw, idle).await;
            return;
        }
        if out.error.is_some() || !out.reusable || !keep {
            break;
        }
    }
    let _ = cw.shutdown().await;
    let _ = uw.shutdown().await;
}

/// Whether a `Connection` header of `headers` lists `token`.
fn connection_has(headers: &[(String, Vec<u8>)], token: &str) -> bool {
    headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("connection"))
        .any(|(_, v)| v.split(|b| *b == b',').any(|t| t.trim_ascii().eq_ignore_ascii_case(token.as_bytes())))
}

/// A stream that is not HTTP/1.1: relayed as bytes and recorded as one `TLS` exchange when it ends.
#[allow(clippy::too_many_arguments)]
async fn raw_tls<CR, CW, UR, UW>(
    cr: &mut CR,
    cw: &mut CW,
    ur: &mut UR,
    uw: &mut UW,
    ahead: Vec<u8>,
    cx: &Ctx<'_>,
    cap: &CaptureCfg,
    unverified: bool,
) where
    CR: AsyncRead + Unpin,
    CW: AsyncWrite + Unpin,
    UR: AsyncRead + Unpin,
    UW: AsyncWrite + Unpin,
{
    let idle = cx.shared.limits.idle_timeout;
    let tap = Tap::new(cap.grant.max_bytes, Vec::new());
    let mut out = ahead.len() as u64;
    let mut back = 0u64;
    if ahead.is_empty() || send(uw, &ahead, idle).await {
        let (a, b) = pump(cr, cw, ur, uw, idle).await;
        out = out.saturating_add(a);
        back = b;
    }
    let why = format!("not HTTP/1.1: {out} bytes out, {back} bytes in, not stored");
    let target = format!("{}:{}", cx.host, cx.port);
    let mut c = tap.finish(Transport::Intercepted, "TLS", &target, Some(why), unverified);
    (c.request_bytes, c.response_bytes) = (out, back);
    cap.send(cx, c);
}

/// Copies both ways until both sides are done or a direction is silent for `idle`; returns the bytes
/// client to destination and destination to client.
async fn pump<CR, CW, UR, UW>(cr: &mut CR, cw: &mut CW, ur: &mut UR, uw: &mut UW, idle: Duration) -> (u64, u64)
where
    CR: AsyncRead + Unpin,
    CW: AsyncWrite + Unpin,
    UR: AsyncRead + Unpin,
    UW: AsyncWrite + Unpin,
{
    async fn dir<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(r: &mut R, w: &mut W, idle: Duration) -> u64 {
        let mut buf = vec![0u8; 16 * 1024];
        let mut n = 0u64;
        loop {
            match tokio::time::timeout(idle, r.read(&mut buf)).await {
                Ok(Ok(k)) if k > 0 => {
                    if !send(w, buf.get(..k).unwrap_or(&[]), idle).await {
                        break;
                    }
                    n = n.saturating_add(k as u64);
                }
                _ => break,
            }
        }
        let _ = w.shutdown().await;
        n
    }
    tokio::join!(dir(cr, uw, idle), dir(ur, cw, idle))
}

/// What one request and its response came to.
struct Outcome {
    error: Option<String>,
    /// Both messages ended cleanly and the connection may carry another request.
    reusable: bool,
    /// The response was `101`: the connection is a byte relay from here.
    upgraded: bool,
}

impl Outcome {
    fn failed(why: impl Into<String>) -> Outcome {
        Outcome { error: Some(why.into()), reusable: false, upgraded: false }
    }
}

/// A response head as read from the destination, unchanged.
struct RawResp {
    len: usize,
    code: u16,
    is_final: bool,
    framing: Option<Framing>,
    close: bool,
    retry_after: Option<String>,
}

fn raw_response_head(buf: &[u8], head_request: bool) -> Result<Option<RawResp>, String> {
    let mut headers = vec![httparse::EMPTY_HEADER; MAX_RESPONSE_HEADERS];
    let mut resp = httparse::Response::new(&mut headers);
    let parsed = httparse::ParserConfig::default()
        .allow_obsolete_multiline_headers_in_responses(true)
        .allow_spaces_after_header_name_in_responses(true)
        .allow_multiple_spaces_in_response_status_delimiters(true)
        .parse_response(&mut resp, buf);
    let len = match parsed {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => return Ok(None),
        Err(e) => return Err(format!("the destination did not answer with a valid HTTP response ({e})")),
    };
    let (Some(version), Some(code)) = (resp.version, resp.code) else {
        return Err("the destination did not answer with a valid HTTP response".into());
    };
    let is_final = !(100..200).contains(&code) || code == 101;
    let coding = resp.headers.iter().rev().find(|h| h.name.eq_ignore_ascii_case("transfer-encoding"));
    let framing = if !is_final {
        None
    } else if head_request || matches!(code, 204 | 304) {
        Some(Framing::Length(0))
    } else if code == 101 {
        Some(Framing::UntilClose)
    } else if let Some(c) = coding {
        Some(if ends_chunked(c.value) { Framing::Chunked(Chunked::new()) } else { Framing::UntilClose })
    } else {
        Some(content_length(resp.headers)?.map_or(Framing::UntilClose, Framing::Length))
    };
    let has_token = |token: &str| {
        resp.headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case("connection"))
            .any(|h| h.value.split(|b| *b == b',').any(|t| t.trim_ascii().eq_ignore_ascii_case(token.as_bytes())))
    };
    let close = has_token("close") || (version == 0 && !has_token("keep-alive"));
    let retry_after = is_final
        .then(|| {
            resp.headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("retry-after"))
                .and_then(|h| std::str::from_utf8(h.value).ok())
                .map(|s| s.trim().to_string())
        })
        .flatten();
    Ok(Some(RawResp { len, code, is_final, framing, close, retry_after }))
}

/// How many of `data` belong to the body of a response with `framing`.
fn frame_take(framing: &mut Framing, data: &[u8]) -> Result<usize, String> {
    match framing {
        Framing::Length(left) => {
            let k = usize::try_from(*left).map_or(data.len(), |l| l.min(data.len()));
            *left = left.saturating_sub(k as u64);
            Ok(k)
        }
        Framing::Chunked(c) => {
            c.feed(data).map_err(|m| format!("the destination's chunked response is malformed ({m})"))
        }
        Framing::UntilClose => Ok(data.len()),
    }
}

fn framing_done(framing: &Framing) -> bool {
    match framing {
        Framing::Length(left) => *left == 0,
        Framing::Chunked(c) => c.done(),
        Framing::UntilClose => false,
    }
}

/// One request through the destination and its response back, relayed as they arrive.
#[allow(clippy::too_many_arguments)]
async fn exchange<CR, CW, UR, UW>(
    cr: &mut CR,
    cw: &mut CW,
    ur: &mut UR,
    uw: &mut UW,
    cbuf: &mut Vec<u8>,
    ubuf: &mut Vec<u8>,
    raw_head: &[u8],
    body: Body,
    head_request: bool,
    tap: &Tap,
    idle: Duration,
    pace: Option<(&crate::pace::Governor, &str)>,
) -> Outcome
where
    CR: AsyncRead + Unpin,
    CW: AsyncWrite + Unpin,
    UR: AsyncRead + Unpin,
    UW: AsyncWrite + Unpin,
{
    if !send(uw, raw_head, idle).await {
        return Outcome::failed("sending the request to the destination failed");
    }
    let mut owed = match body {
        Body::None | Body::Stream => Owed::Bytes(0),
        Body::Length(n) => Owed::Bytes(n),
        Body::Chunked => Owed::Chunked(Chunked::new()),
    };
    // The request body, from what the client sent ahead and then from the client.
    let upload = async {
        let ahead = owed.take(cbuf).min(cbuf.len());
        let first: Vec<u8> = cbuf.drain(..ahead).collect();
        if !first.is_empty() {
            if !send(uw, &first, idle).await {
                return Err("sending the request body to the destination failed".to_string());
            }
            tap.request_body(&first);
        }
        let mut buf = vec![0u8; 16 * 1024];
        while !owed.finished() {
            let n = match tokio::time::timeout(idle, cr.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => n,
                _ => return Err("the client's connection ended in the middle of the request body".to_string()),
            };
            let data = buf.get(..n).unwrap_or(&[]);
            let k = owed.take(data).min(n);
            let (mine, past) = data.split_at(k);
            if !mine.is_empty() {
                if !send(uw, mine, idle).await {
                    return Err("sending the request body to the destination failed".to_string());
                }
                tap.request_body(mine);
            }
            cbuf.extend_from_slice(past);
        }
        Ok(())
    };
    // The response: heads (interim ones too), then the body as its head frames it.
    let download = async {
        let mut sent = 0u64;
        let mut chunk = vec![0u8; 16 * 1024];
        let (code, mut framing, close) = loop {
            match raw_response_head(ubuf, head_request) {
                Ok(Some(h)) => {
                    let bytes: Vec<u8> = ubuf.drain(..h.len.min(ubuf.len())).collect();
                    if !send(cw, &bytes, idle).await {
                        return Err("writing to the client failed".to_string());
                    }
                    sent = sent.saturating_add(bytes.len() as u64);
                    let end = h.is_final.then_some(sent);
                    tap.response(&bytes, end, h.is_final.then_some(h.code));
                    if h.is_final {
                        if let Some((gov, host)) = pace {
                            gov.note_response(host, h.code, h.retry_after.as_deref());
                        }
                    }
                    if let Some(f) = h.framing {
                        break (h.code, f, h.close);
                    }
                    continue;
                }
                Ok(None) => {}
                Err(m) => return Err(m),
            }
            if ubuf.len() > MAX_HEAD {
                return Err(format!("the destination sent a response head larger than {} KiB", MAX_HEAD / 1024));
            }
            match tokio::time::timeout(idle, ur.read(&mut chunk)).await {
                Ok(Ok(n)) if n > 0 => ubuf.extend_from_slice(chunk.get(..n).unwrap_or(&[])),
                Ok(Ok(_) | Err(_)) => return Err("the destination closed the connection before it answered".into()),
                Err(_) => return Err(format!("the destination sent no response for {}", human(idle))),
            }
        };
        if code == 101 {
            return Ok((true, false));
        }
        let mut clean = true;
        while !framing_done(&framing) {
            let data: Vec<u8> = if ubuf.is_empty() {
                match tokio::time::timeout(idle, ur.read(&mut chunk)).await {
                    Ok(Ok(n)) if n > 0 => chunk.get(..n).unwrap_or(&[]).to_vec(),
                    Ok(Ok(_)) if matches!(framing, Framing::UntilClose) => {
                        clean = false;
                        break;
                    }
                    Ok(Ok(_) | Err(_)) => {
                        return Err("the destination's connection ended in the middle of the response".into())
                    }
                    Err(_) => return Err(format!("the destination's response stalled for {}", human(idle))),
                }
            } else {
                std::mem::take(ubuf)
            };
            let k = frame_take(&mut framing, &data)?.min(data.len());
            let (mine, past) = data.split_at(k);
            if !mine.is_empty() {
                if !send(cw, mine, idle).await {
                    return Err("writing to the client failed".to_string());
                }
                tap.response(mine, None, None);
            }
            if !past.is_empty() {
                // Bytes after the end of the response: the connection cannot be trusted for another one.
                clean = false;
            }
        }
        let until_close = matches!(framing, Framing::UntilClose);
        Ok((false, clean && !close && !until_close))
    };
    let mut uploaded = false;
    let result = {
        tokio::pin!(upload, download);
        loop {
            tokio::select! {
                r = &mut upload, if !uploaded => match r {
                    Ok(()) => uploaded = true,
                    Err(why) => return Outcome::failed(why),
                },
                r = &mut download => break r,
            }
        }
    };
    match result {
        Ok((upgraded, reusable)) => Outcome { error: None, reusable: reusable && uploaded, upgraded },
        Err(why) => {
            if tap.response_total() == 0 {
                bad_gateway(cw, &why, idle).await;
            }
            Outcome::failed(why)
        }
    }
}

async fn bad_gateway<W: AsyncWrite + Unpin>(w: &mut W, why: &str, idle: Duration) {
    let body = format!("ferret proxy: the destination could not be used: {why}\n");
    let text = format!(
        "HTTP/1.1 502 Bad Gateway\r\n{MARKER}: 1\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    send(w, text.as_bytes(), idle).await;
}
