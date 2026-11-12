//! The proxy server.
//!
//! CONTRACT (bodies are placeholders for the implementer; signatures and types are fixed).
//!
//! `Proxy::start(port, sink)` binds `127.0.0.1:{port}` (0 = any free port) and serves until
//! `shutdown` or drop. It speaks HTTP/1.1 proxying only:
//! - `CONNECT host:port` → on success `HTTP/1.1 200 Connection established\r\n\r\n`, then bytes are
//!   copied both ways until either side closes;
//! - a request with an absolute `http://` URI → the proxy connects to that host (port 80 by
//!   default), sends the request with an origin-form target, drops `Proxy-Authorization` and
//!   `Proxy-Connection`, adds `Connection: close`, and copies the request body and the response
//!   through unchanged. One request per client connection.
//! - anything else (origin-form target, `https://` absolute URI, unparseable head, a head larger than
//!   64 KiB, no head within 30 s) → `400` with a sentence.
//!
//! ## Sessions
//! `grant(session, policy)` returns a [`SessionGrant`] with fresh random credentials (user = the
//! session id, password = 32 hex chars). The client authenticates with `Proxy-Authorization: Basic`.
//! Missing or unknown credentials → `407` with `Proxy-Authenticate: Basic realm="loom"`.
//! `revoke(session)` drops them; connections already open are left to finish.
//! `set_policy(session, policy)` replaces the policy of a session that holds a grant and keeps its
//! credentials, so commands already running pick the change up on their next connection.
//! `SessionGrant::env()` gives the variables to place in a command's environment so that ordinary
//! clients use the proxy: `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and their lower-case forms, all
//! `http://{user}:{password}@127.0.0.1:{port}`, plus `NO_PROXY`/`no_proxy` = `` (empty, so loopback
//! labs also pass policy unless the sandbox opens their ports directly).
//!
//! ## Deciding and connecting
//! For each request: `policy.check_name` → if allowed, resolve the name (`tokio::net::lookup_host`;
//! an IP literal resolves to itself), then walk the resolved addresses in order and connect to the
//! first one that `policy.check_addr` allows (10 s connect timeout each). The connection is made to
//! that checked address, never by name, so a second lookup cannot change the destination. If every
//! address is refused the decision is the first refusal.
//! Every request produces exactly one `NetDecision` sent to `sink` together with the session id:
//! `host`, `port`, `method` (`CONNECT` or the request method), `allowed`, `rule`, `resolved` (the
//! address connected to, or the refused address, when there is one). Resolution or connect failures
//! after an allow are reported as allowed with the rule suffixed ` (unreachable: {why})`.
//! Refusals answer `403` with header `X-Loom-Proxy: 1` and a plain-text body that states the
//! destination, the rule, and that the network policy is set by the operator in the loom config
//! (`[network]`) — a command cannot change it. Unreachable destinations answer `502` with
//! `X-Loom-Proxy: 1` and the reason. Proxy-generated responses always carry `X-Loom-Proxy: 1` and
//! `Connection: close`.
//!
//! The proxy never logs or stores request or response bodies. It must not panic on any input; a
//! failing connection affects only itself. `Proxy` is cheap to clone (shared state inside).
//!
//! Tests required (all on loopback with local listeners; grant policies with
//! `allow_private = ["127.0.0.1"]` where a test needs to reach its own listener): CONNECT tunnel
//! echoes bytes both ways; plain HTTP forward rewrites the target, strips proxy headers, relays the
//! body and the response; 407 without / with wrong credentials; credentials of a revoked session;
//! deny rule → 403 + header + one refused decision; open mode to loopback without allow_private →
//! refused as private-address with `resolved` set; allowlist miss; unreachable port → 502 and an
//! allowed decision with the suffix; exactly one decision per request and the right session id on
//! each when two sessions use the proxy at once; malformed heads → 400 and the server keeps serving;
//! oversized head; `env()` contents; shutdown stops accepting.
//!
//! ## Audit, limits, and the response marker (added by the egress audit fixes)
//! - An audit hook ([`AuditFn`]) records every decision. For an allowed connection it runs after the
//!   upstream connect and before anything is sent either way; when it fails the client gets `502` (with
//!   the marker) and the connection is closed. Refusals, `400`, `407` (when the credentials name a
//!   granted session) and over-limit answers are audited best effort; a failure is logged.
//! - `check_addr` applies the `deny` list to the resolved address too (see `policy.rs`).
//! - [`Limits`]: 256 connections in all (over it: `503` written at once), 64 per session (`429`), 10
//!   minutes without a byte in either direction on a tunnel or forwarded request, 16 concurrent name
//!   lookups. A forwarded request ends when the client goes away.
//! - A plain-HTTP response head from the destination is relayed without any `X-Loom-Proxy` header; only
//!   responses the proxy generates carry it.

use crate::policy::{normalize_host, Policy};
use base64::Engine as _;
use loom_core::event::NetDecision;
use loom_core::SessionId;
use rand::Rng;
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

const MAX_HEAD: usize = 64 * 1024;
const MAX_HEADERS: usize = 100;
const HEAD_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);
/// Addresses of one name that are examined; a name with more is cut here.
const MAX_ADDRS: usize = 32;

/// The audit hook: called with the session and the decision, it must have recorded the decision
/// durably when it returns `Ok`. It may block (it runs on a blocking thread). For an allowed
/// connection the proxy calls it before the upstream socket is used and refuses the connection (502)
/// when it fails.
pub type AuditFn = Arc<dyn Fn(&SessionId, &NetDecision) -> std::io::Result<()> + Send + Sync>;

/// Test hook: name to addresses, instead of a system lookup.
type Resolver = Arc<dyn Fn(&str) -> Vec<IpAddr> + Send + Sync>;

/// Resource limits of one proxy.
#[derive(Clone, Debug)]
pub struct Limits {
    /// Concurrent client connections, all sessions together. Default 256.
    pub max_connections: usize,
    /// Concurrent client connections of one session. Default 64.
    pub max_per_session: usize,
    /// A tunnel or forwarded request with no bytes in either direction for this long is closed.
    /// Default 10 minutes.
    pub idle_timeout: Duration,
    /// Concurrent name lookups. Default 16.
    pub max_lookups: usize,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_connections: 256,
            max_per_session: 64,
            idle_timeout: Duration::from_secs(600),
            max_lookups: 16,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("could not bind the egress proxy on 127.0.0.1:{port}: {source}")]
    Bind { port: u16, source: std::io::Error },
}

/// Credentials and address for one session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionGrant {
    pub port: u16,
    pub user: String,
    pub password: String,
}

impl SessionGrant {
    /// `http://{user}:{password}@127.0.0.1:{port}`
    pub fn url(&self) -> String {
        format!("http://{}:{}@127.0.0.1:{}", self.user, self.password, self.port)
    }

    /// Proxy variables for a command's environment (see module contract).
    pub fn env(&self) -> BTreeMap<String, String> {
        let url = self.url();
        let mut m = BTreeMap::new();
        for k in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"] {
            m.insert(k.to_string(), url.clone());
        }
        m.insert("NO_PROXY".to_string(), String::new());
        m.insert("no_proxy".to_string(), String::new());
        m
    }
}

struct Entry {
    session: SessionId,
    password: String,
    policy: Arc<Policy>,
    /// One permit per open client connection of the session.
    permits: Arc<Semaphore>,
}

/// State shared with every connection task (tasks never hold `Inner`, so dropping the last `Proxy`
/// handle stops the server).
struct Shared {
    sessions: Mutex<HashMap<String, Entry>>,
    sink: UnboundedSender<(SessionId, NetDecision)>,
    audit: Option<AuditFn>,
    limits: Limits,
    connections: Arc<Semaphore>,
    lookups: Arc<Semaphore>,
    resolver: Option<Resolver>,
}

struct Inner {
    port: u16,
    shared: Arc<Shared>,
    cancel: CancellationToken,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[derive(Clone)]
pub struct Proxy {
    inner: Arc<Inner>,
}

impl Proxy {
    /// A proxy without an audit hook and with the default limits.
    pub async fn start(port: u16, sink: UnboundedSender<(SessionId, NetDecision)>) -> Result<Proxy, ProxyError> {
        Proxy::start_with(port, sink, None, Limits::default()).await
    }

    /// `audit` records every decision before it takes effect (see [`AuditFn`]); `sink` still receives
    /// the decisions of requests that reached the policy, for display.
    pub async fn start_with(
        port: u16,
        sink: UnboundedSender<(SessionId, NetDecision)>,
        audit: Option<AuditFn>,
        limits: Limits,
    ) -> Result<Proxy, ProxyError> {
        Proxy::start_inner(port, sink, audit, limits, None).await
    }

    async fn start_inner(
        port: u16,
        sink: UnboundedSender<(SessionId, NetDecision)>,
        audit: Option<AuditFn>,
        limits: Limits,
        resolver: Option<Resolver>,
    ) -> Result<Proxy, ProxyError> {
        let listener = TcpListener::bind(("127.0.0.1", port))
            .await
            .map_err(|source| ProxyError::Bind { port, source })?;
        let bound = listener.local_addr().map_err(|source| ProxyError::Bind { port, source })?.port();
        let shared = Arc::new(Shared {
            sessions: Mutex::new(HashMap::new()),
            sink,
            audit,
            connections: Arc::new(Semaphore::new(limits.max_connections)),
            lookups: Arc::new(Semaphore::new(limits.max_lookups)),
            limits,
            resolver,
        });
        let cancel = CancellationToken::new();
        tokio::spawn(accept_loop(listener, shared.clone(), cancel.clone()));
        Ok(Proxy { inner: Arc::new(Inner { port: bound, shared, cancel }) })
    }

    /// The port actually bound.
    pub fn port(&self) -> u16 {
        self.inner.port
    }

    pub fn grant(&self, session: &SessionId, policy: Policy) -> SessionGrant {
        let password = format!("{:032x}", rand::rng().random::<u128>());
        let entry = Entry {
            session: session.clone(),
            password: password.clone(),
            policy: Arc::new(policy),
            permits: Arc::new(Semaphore::new(self.inner.shared.limits.max_per_session)),
        };
        lock(&self.inner.shared.sessions).insert(session.as_str().to_string(), entry);
        SessionGrant { port: self.inner.port, user: session.as_str().to_string(), password }
    }

    /// Replace the policy of a session that holds a grant. Its credentials stay as they are. False
    /// when the session holds no grant.
    pub fn set_policy(&self, session: &SessionId, policy: Policy) -> bool {
        match lock(&self.inner.shared.sessions).get_mut(session.as_str()) {
            Some(entry) => {
                entry.policy = Arc::new(policy);
                true
            }
            None => false,
        }
    }

    pub fn revoke(&self, session: &SessionId) {
        lock(&self.inner.shared.sessions).remove(session.as_str());
    }

    /// Stop accepting connections. Open tunnels are closed.
    pub fn shutdown(&self) {
        self.inner.cancel.cancel();
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

async fn accept_loop(listener: TcpListener, shared: Arc<Shared>, cancel: CancellationToken) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            r = listener.accept() => match r {
                Ok((stream, _)) => match shared.connections.clone().try_acquire_owned() {
                    Ok(permit) => {
                        tokio::spawn(handle(stream, shared.clone(), cancel.clone(), permit));
                    }
                    Err(_) => refuse_at_once(&stream, &shared),
                },
                // Out of descriptors or a connection reset before accept: keep serving.
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            },
        }
    }
}

/// Answers a connection over the global cap without a task: one non-blocking write, then close.
fn refuse_at_once(stream: &TcpStream, shared: &Shared) {
    let body = format!(
        "loom proxy: too many open proxy connections (limit {}). Wait for running commands to finish, or retry shortly.\n",
        shared.limits.max_connections
    );
    let _ = stream.try_write(response_bytes("503 Service Unavailable", "Retry-After: 5\r\n", &body).as_bytes());
}

struct Head {
    method: String,
    target: String,
    headers: Vec<(String, Vec<u8>)>,
}

impl Head {
    fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_slice())
    }
}

enum HeadError {
    Closed,
    Bad(String),
}

fn try_parse(buf: &[u8]) -> Result<Option<(Head, usize)>, String> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(buf) {
        Ok(httparse::Status::Complete(n)) => {
            if !matches!(req.version, Some(0 | 1)) {
                return Err("only HTTP/1.0 and HTTP/1.1 requests are supported".into());
            }
            let method = req.method.ok_or("the request has no method")?.to_string();
            let target = req.path.ok_or("the request has no target")?.to_string();
            let headers = req.headers.iter().map(|h| (h.name.to_string(), h.value.to_vec())).collect();
            Ok(Some((Head { method, target, headers }, n)))
        }
        Ok(httparse::Status::Partial) => Ok(None),
        Err(e) => Err(format!("the request head could not be parsed ({e})")),
    }
}

/// Reads up to the end of the request head; returns it with any bytes read past it.
async fn read_head(client: &mut TcpStream) -> Result<(Head, Vec<u8>), HeadError> {
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    loop {
        match try_parse(&buf) {
            Ok(Some((head, n))) => {
                if n > MAX_HEAD {
                    return Err(HeadError::Bad(too_large()));
                }
                return Ok((head, buf.split_off(n)));
            }
            Ok(None) => {}
            Err(m) => return Err(HeadError::Bad(m)),
        }
        if buf.len() >= MAX_HEAD {
            return Err(HeadError::Bad(too_large()));
        }
        match client.read_buf(&mut buf).await {
            Ok(0) if buf.is_empty() => return Err(HeadError::Closed),
            Ok(0) => return Err(HeadError::Bad("the connection closed in the middle of the request head".into())),
            Ok(_) => {}
            Err(_) => return Err(HeadError::Closed),
        }
    }
}

fn too_large() -> String {
    format!("the request head is larger than {} KiB; send a smaller head", MAX_HEAD / 1024)
}

/// A proxy-generated response. These, and only these, carry `X-Loom-Proxy: 1`.
fn response_bytes(status: &str, extra: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nX-Loom-Proxy: 1\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\n{extra}Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

/// Writes a proxy-generated response and closes. Unread input is drained briefly so that closing
/// does not reset the connection before the client has read the response.
async fn respond(client: &mut TcpStream, status: &str, extra: &str, body: &str) {
    let msg = response_bytes(status, extra, body);
    if client.write_all(msg.as_bytes()).await.is_err() {
        return;
    }
    let _ = client.shutdown().await;
    let drain = async {
        let mut sink = [0u8; 4096];
        let mut total = 0usize;
        while total < 256 * 1024 {
            match client.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(n) => total = total.saturating_add(n),
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_millis(500), drain).await;
}

async fn bad_request(client: &mut TcpStream, why: &str) {
    let body = format!(
        "loom proxy: {why}. This proxy accepts `CONNECT host:port` and `GET http://host/path`-style requests with an absolute http:// URI; use CONNECT for https.\n"
    );
    respond(client, "400 Bad Request", "", &body).await;
}

/// Records a decision: the audit hook first (on a blocking thread, so file I/O never stalls a worker),
/// then, when `to_sink`, the display sink. A failing hook is returned; the sink then gets the decision
/// as a refusal so the operator sees what happened.
async fn audit_decision(shared: &Shared, session: &SessionId, d: NetDecision, to_sink: bool) -> std::io::Result<()> {
    let result = match &shared.audit {
        None => Ok(()),
        Some(f) => {
            let (f, s, dd) = (f.clone(), session.clone(), d.clone());
            match tokio::task::spawn_blocking(move || f(&s, &dd)).await {
                Ok(r) => r,
                Err(e) => Err(std::io::Error::other(format!("the audit task failed: {e}"))),
            }
        }
    };
    if to_sink {
        let shown = match &result {
            Ok(()) => d,
            Err(_) => NetDecision { allowed: false, rule: format!("{} (refused: egress audit log not written)", d.rule), ..d },
        };
        let _ = shared.sink.send((session.clone(), shown));
    }
    result
}

/// Audits a request the proxy answers itself (400, 407, over a limit). Best effort: a failure is logged.
async fn audit_local(shared: &Shared, session: &SessionId, method: &str, target: &str, rule: String) {
    let d = NetDecision {
        host: target.chars().take(200).collect(),
        port: 0,
        method: method.chars().take(32).collect(),
        allowed: false,
        rule,
        resolved: None,
    };
    if let Err(e) = audit_decision(shared, session, d, false).await {
        tracing::warn!("cannot write the egress audit record of {}: {e}", session.as_str());
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

struct Authed {
    session: SessionId,
    policy: Arc<Policy>,
    permits: Arc<Semaphore>,
}

/// The session whose Basic credentials the request carries. On failure, the session the request
/// claimed to be (a known user with a wrong password), for the audit record.
fn authenticate(shared: &Shared, head: &Head) -> Result<Authed, Option<SessionId>> {
    let decoded = (|| {
        let value = std::str::from_utf8(head.header("proxy-authorization")?).ok()?;
        let (scheme, encoded) = value.trim().split_once(' ')?;
        if !scheme.eq_ignore_ascii_case("basic") {
            return None;
        }
        let decoded = base64::engine::general_purpose::STANDARD.decode(encoded.trim()).ok()?;
        String::from_utf8(decoded).ok()
    })();
    let Some(decoded) = decoded else { return Err(None) };
    // Passwords are hex, so the last colon separates the two.
    let Some((user, password)) = decoded.rsplit_once(':') else { return Err(None) };
    let sessions = lock(&shared.sessions);
    let Some(e) = sessions.get(user) else { return Err(None) };
    if constant_time_eq(e.password.as_bytes(), password.as_bytes()) {
        Ok(Authed { session: e.session.clone(), policy: e.policy.clone(), permits: e.permits.clone() })
    } else {
        Err(Some(e.session.clone()))
    }
}

/// `host[:port]` or `[v6][:port]`, without credentials. The host is returned normalized.
fn parse_authority(s: &str, default_port: Option<u16>) -> Result<(String, u16), String> {
    if s.is_empty() {
        return Err("the destination is empty".into());
    }
    if s.contains('@') {
        return Err("credentials inside the destination are not supported".into());
    }
    let port_of = |p: Option<&str>| -> Result<u16, String> {
        match p {
            Some(p) => p.parse::<u16>().ok().filter(|p| *p != 0).ok_or_else(|| format!("`{p}` is not a valid port")),
            None => default_port.ok_or_else(|| "the destination has no port; write host:port".to_string()),
        }
    };
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (inner, after) = rest.split_once(']').ok_or("the `[` has no closing `]`")?;
        if inner.parse::<std::net::Ipv6Addr>().is_err() {
            return Err("the text in brackets is not an IPv6 address".into());
        }
        let port = match after {
            "" => port_of(None)?,
            _ => port_of(Some(after.strip_prefix(':').ok_or("only `:port` may follow `]`")?))?,
        };
        (inner, port)
    } else {
        match s.split_once(':') {
            None => (s, port_of(None)?),
            Some((h, p)) => (h, port_of(Some(p))?),
        }
    };
    let host = normalize_host(host);
    let name_ok = !host.is_empty() && host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'));
    if !name_ok && host.parse::<IpAddr>().is_err() {
        return Err(format!("`{host}` is not a usable host name (use ASCII names or punycode)"));
    }
    Ok((host, port))
}

/// Everything needed to attribute and report one request's decision.
struct Ctx<'a> {
    shared: &'a Shared,
    session: &'a SessionId,
    method: &'a str,
    host: &'a str,
    port: u16,
}

impl Ctx<'_> {
    /// Audits and publishes this request's decision.
    async fn record(&self, allowed: bool, rule: String, resolved: Option<IpAddr>) -> std::io::Result<()> {
        let d = NetDecision {
            host: self.host.to_string(),
            port: self.port,
            method: self.method.to_string(),
            allowed,
            rule,
            resolved: resolved.map(|a| a.to_string()),
        };
        audit_decision(self.shared, self.session, d, true).await
    }

    /// Like `record`, for decisions that need no audit to succeed: a failure is only logged.
    async fn record_best_effort(&self, allowed: bool, rule: String, resolved: Option<IpAddr>) {
        if let Err(e) = self.record(allowed, rule, resolved).await {
            tracing::warn!("cannot write the egress audit record of {}: {e}", self.session.as_str());
        }
    }

    fn dest(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    fn refused(&self, rule: &str) -> (&'static str, String) {
        (
            "403 Forbidden",
            format!(
                "loom network policy: {} to {} was refused by rule `{rule}`. The network policy is set by the operator in the loom config ([network]); a command cannot change it. Use a destination the policy allows, or ask the operator to change the config.\n",
                self.method,
                self.dest()
            ),
        )
    }

    fn unreachable(&self, why: &str) -> (&'static str, String) {
        (
            "502 Bad Gateway",
            format!(
                "loom proxy: {} was allowed by the network policy but could not be reached: {why}. Check the host name and port, or try again later.\n",
                self.dest()
            ),
        )
    }

    fn audit_failed(&self, e: &std::io::Error) -> (&'static str, String) {
        (
            "502 Bad Gateway",
            format!(
                "loom proxy: the egress audit log could not be written ({e}), so the connection to {} was refused. Tell the operator to check the session directory and the disk, then retry.\n",
                self.dest()
            ),
        )
    }
}

/// Name to addresses: the test hook, or a system lookup on its own task. Lookups are bounded: a
/// permit is held until the lookup itself ends, even when the caller has given up waiting for it.
async fn resolve(shared: &Shared, host: &str, port: u16) -> Result<Vec<IpAddr>, String> {
    if let Some(r) = &shared.resolver {
        return Ok(r(host).into_iter().take(MAX_ADDRS).collect());
    }
    let permit = match tokio::time::timeout(RESOLVE_TIMEOUT, shared.lookups.clone().acquire_owned()).await {
        Ok(Ok(p)) => p,
        _ => return Err("too many name lookups are in progress".to_string()),
    };
    let name = host.to_string();
    let task = tokio::spawn(async move {
        let found = tokio::net::lookup_host((name.as_str(), port)).await;
        drop(permit);
        found.map(|it| it.map(|a| a.ip()).take(MAX_ADDRS).collect::<Vec<_>>())
    });
    match tokio::time::timeout(RESOLVE_TIMEOUT, task).await {
        Ok(Ok(Ok(v))) => Ok(v),
        Ok(Ok(Err(e))) => Err(format!("name lookup failed: {e}")),
        Ok(Err(_)) => Err("name lookup failed".to_string()),
        Err(_) => Err("name lookup timed out".to_string()),
    }
}

/// Applies the policy to the name, resolves it, and connects to the first address the policy allows.
/// Reports exactly one decision; for the connection it returns, the audit hook has succeeded first.
/// On failure returns the status line and body to send.
async fn open_upstream(cx: &Ctx<'_>, policy: &Policy) -> Result<TcpStream, (&'static str, String)> {
    let v = policy.check_name(cx.host, cx.port);
    if !v.allowed {
        cx.record_best_effort(false, v.rule.clone(), None).await;
        return Err(cx.refused(&v.rule));
    }
    let name_rule = v.rule;

    let addrs: Vec<IpAddr> = match cx.host.parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => match resolve(cx.shared, cx.host, cx.port).await {
            Ok(a) => a,
            Err(why) => return Err(unreachable_decision(cx, &name_rule, None, &why).await),
        },
    };
    if addrs.is_empty() {
        return Err(unreachable_decision(cx, &name_rule, None, "the name has no addresses").await);
    }

    let mut first_refusal: Option<(String, IpAddr)> = None;
    let mut first_failure: Option<(String, IpAddr, String)> = None;
    for ip in addrs {
        let cv = policy.check_addr(cx.host, cx.port, ip, &name_rule);
        if !cv.allowed {
            first_refusal.get_or_insert((cv.rule, ip));
            continue;
        }
        match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(SocketAddr::new(ip, cx.port))).await {
            Ok(Ok(s)) => {
                let _ = s.set_nodelay(true);
                // Nothing has been sent upstream yet; the connection is used only once it is on record.
                return match cx.record(true, cv.rule, Some(ip)).await {
                    Ok(()) => Ok(s),
                    Err(e) => {
                        tracing::warn!("cannot write the egress audit record of {}: {e}", cx.session.as_str());
                        Err(cx.audit_failed(&e))
                    }
                };
            }
            Ok(Err(e)) => {
                first_failure.get_or_insert((cv.rule, ip, e.to_string()));
            }
            Err(_) => {
                first_failure.get_or_insert((cv.rule, ip, "connection timed out".to_string()));
            }
        }
    }
    if let Some((rule, ip, why)) = first_failure {
        return Err(unreachable_decision(cx, &rule, Some(ip), &why).await);
    }
    match first_refusal {
        Some((rule, ip)) => {
            cx.record_best_effort(false, rule.clone(), Some(ip)).await;
            Err(cx.refused(&rule))
        }
        None => Err(unreachable_decision(cx, &name_rule, None, "the name has no addresses").await),
    }
}

async fn unreachable_decision(cx: &Ctx<'_>, rule: &str, ip: Option<IpAddr>, why: &str) -> (&'static str, String) {
    cx.record_best_effort(true, format!("{rule} (unreachable: {why})"), ip).await;
    cx.unreachable(why)
}

/// Answers a request the proxy rejects itself with 400, after auditing it.
async fn reject(client: &mut TcpStream, shared: &Shared, session: &SessionId, head: &Head, why: &str) {
    audit_local(shared, session, &head.method, &head.target, format!("bad request: {why}")).await;
    bad_request(client, why).await;
}

async fn handle(mut client: TcpStream, shared: Arc<Shared>, cancel: CancellationToken, _slot: OwnedSemaphorePermit) {
    let _ = client.set_nodelay(true);
    let read = tokio::time::timeout(HEAD_TIMEOUT, read_head(&mut client)).await;
    let (head, extra) = match read {
        Err(_) => return bad_request(&mut client, "no complete request head arrived within 30 seconds").await,
        Ok(Err(HeadError::Closed)) => return,
        Ok(Err(HeadError::Bad(m))) => return bad_request(&mut client, &m).await,
        Ok(Ok(x)) => x,
    };
    let auth = match authenticate(&shared, &head) {
        Ok(a) => a,
        Err(claimed) => {
            if let Some(session) = claimed {
                audit_local(&shared, &session, &head.method, &head.target, "proxy authentication failed".to_string()).await;
            }
            let body = "loom proxy: missing or unknown proxy credentials. Use the proxy settings from the command's environment (HTTP_PROXY / HTTPS_PROXY), which carry this session's credentials.\n";
            return respond(&mut client, "407 Proxy Authentication Required", "Proxy-Authenticate: Basic realm=\"loom\"\r\n", body)
                .await;
        }
    };
    let Authed { session, policy, permits } = auth;
    let Ok(_session_slot) = permits.try_acquire_owned() else {
        let body = format!(
            "loom proxy: this session already has {} open proxy connections, the limit. Let running requests finish before starting more.\n",
            shared.limits.max_per_session
        );
        audit_local(&shared, &session, &head.method, &head.target, "connection limit (per session)".to_string()).await;
        return respond(&mut client, "429 Too Many Requests", "Retry-After: 5\r\n", &body).await;
    };
    if head.method == "CONNECT" {
        match parse_authority(&head.target, None) {
            Ok((host, port)) => {
                let cx = Ctx { shared: &shared, session: &session, method: "CONNECT", host: &host, port };
                tunnel(client, extra, &cx, &policy, cancel).await;
            }
            Err(m) => reject(&mut client, &shared, &session, &head, &m).await,
        }
        return;
    }
    let lower = head.target.get(..8).map(str::to_ascii_lowercase);
    if lower.as_deref() == Some("https://") {
        let why = "https:// absolute URIs are not proxied; use CONNECT host:443 for https";
        return reject(&mut client, &shared, &session, &head, why).await;
    }
    if !matches!(head.target.get(..7), Some(p) if p.eq_ignore_ascii_case("http://")) {
        let why = "the request target is not an absolute http:// URI or a CONNECT destination";
        return reject(&mut client, &shared, &session, &head, why).await;
    }
    match plain_target(&head.target) {
        Ok((host, port, authority, path)) => {
            let cx = Ctx { shared: &shared, session: &session, method: &head.method, host: &host, port };
            forward(client, extra, &head, &cx, &policy, &authority, &path, cancel).await;
        }
        Err(m) => reject(&mut client, &shared, &session, &head, &m).await,
    }
}

/// Splits `http://authority/path` into (host, port, authority as written, origin-form path).
fn plain_target(target: &str) -> Result<(String, u16, String, String), String> {
    let rest = target.get(7..).ok_or("the request target is too short")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let (host, port) = parse_authority(authority, Some(80))?;
    let tail = tail.split('#').next().unwrap_or("");
    let path = if tail.is_empty() {
        "/".to_string()
    } else if tail.starts_with('/') {
        tail.to_string()
    } else {
        format!("/{tail}")
    };
    Ok((host, port, authority.to_string(), path))
}

async fn tunnel(mut client: TcpStream, extra: Vec<u8>, cx: &Ctx<'_>, policy: &Policy, cancel: CancellationToken) {
    let idle = cx.shared.limits.idle_timeout;
    let mut up = match open_upstream(cx, policy).await {
        Ok(s) => s,
        Err((status, body)) => return respond(&mut client, status, "", &body).await,
    };
    if client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.is_err() {
        return;
    }
    if !extra.is_empty() && !write_within(&mut up, &extra, idle).await {
        return;
    }
    tokio::select! {
        _ = relay(&mut client, &mut up, idle, None) => {}
        _ = cancel.cancelled() => {}
    }
}

/// Writes all of `bytes` within `idle`; false when the peer is gone or too slow.
async fn write_within<W: AsyncWriteExt + Unpin>(w: &mut W, bytes: &[u8], idle: Duration) -> bool {
    matches!(tokio::time::timeout(idle, w.write_all(bytes)).await, Ok(Ok(())))
}

/// How the request body of a forwarded request is framed.
enum Body {
    None,
    Length(u64),
    /// Chunked or otherwise unframed by length: relay until the client stops sending.
    Stream,
}

fn body_kind(head: &Head) -> Result<Body, String> {
    let mut length: Option<u64> = None;
    let mut chunked = false;
    for (n, v) in &head.headers {
        if n.eq_ignore_ascii_case("content-length") {
            let parsed = std::str::from_utf8(v)
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .ok_or("the Content-Length header is not a number")?;
            if length.is_some_and(|l| l != parsed) {
                return Err("the request has conflicting Content-Length headers".into());
            }
            length = Some(parsed);
        } else if n.eq_ignore_ascii_case("transfer-encoding") {
            chunked = true;
        }
    }
    match (length, chunked) {
        (Some(_), true) => Err("the request has both Content-Length and Transfer-Encoding".into()),
        (Some(n), false) => Ok(Body::Length(n)),
        (None, true) => Ok(Body::Stream),
        (None, false) => Ok(Body::None),
    }
}

/// Response heads from the destination, with any `X-Loom-Proxy` header removed: only the proxy's own
/// responses may carry that marker. Interim (1xx) heads are filtered too.
struct HeadFilter {
    buf: Vec<u8>,
    done: bool,
}

impl HeadFilter {
    /// Takes the next bytes from the destination; returns what may be sent to the client now.
    fn push(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
        if self.done {
            return Ok(data.to_vec());
        }
        self.buf.extend_from_slice(data);
        let mut out = Vec::new();
        loop {
            let Some(end) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                if self.buf.len() > MAX_HEAD {
                    return Err(format!(
                        "the destination sent a response head larger than {} KiB",
                        MAX_HEAD / 1024
                    ));
                }
                return Ok(out);
            };
            let rest = self.buf.split_off(end.saturating_add(4));
            let head = std::mem::replace(&mut self.buf, rest);
            let code = status_code(&head).ok_or("the destination did not answer with a valid HTTP response")?;
            out.extend_from_slice(&strip_marker(&head));
            if (100..200).contains(&code) && code != 101 {
                continue;
            }
            self.done = true;
            out.append(&mut self.buf);
            return Ok(out);
        }
    }
}

fn status_code(head: &[u8]) -> Option<u16> {
    let line_end = head.windows(2).position(|w| w == b"\r\n")?;
    let line = std::str::from_utf8(head.get(..line_end)?).ok()?;
    let mut parts = line.split(' ');
    if !parts.next()?.starts_with("HTTP/") {
        return None;
    }
    parts.next()?.parse().ok()
}

/// A response head without its `X-Loom-Proxy` lines (and their continuation lines).
fn strip_marker(head: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(head.len());
    let mut dropping = false;
    let mut rest = head;
    while !rest.is_empty() {
        let n = rest.windows(2).position(|w| w == b"\r\n").map_or(rest.len(), |p| p.saturating_add(2));
        let (line, tail) = rest.split_at(n);
        rest = tail;
        let folded = matches!(line.first(), Some(b' ' | b'\t'));
        let name = line.split(|b| *b == b':').next().unwrap_or(&[]).trim_ascii();
        dropping = if folded { dropping } else { name.eq_ignore_ascii_case(b"x-loom-proxy") && line.contains(&b':') };
        if !dropping {
            out.extend_from_slice(line);
        }
    }
    out
}

enum RelayEnd {
    Done,
    /// The destination's response was unusable; whether anything has been sent to the client yet.
    BadUpstream(String, bool),
}

/// Copies bytes both ways until both sides are done, `idle` passes with no byte moving in either
/// direction, or a write stalls for `idle`.
///
/// With `forward` (a forwarded plain request, its request body budget in bytes, `None` for no limit)
/// the destination's response head is filtered, bytes of the client past the body are discarded, the
/// relay ends when the response ends, and it ends when the client goes away.
async fn relay(client: &mut TcpStream, up: &mut TcpStream, idle: Duration, forward: Option<Option<u64>>) -> RelayEnd {
    let (mut cr, mut cw) = client.split();
    let (mut ur, mut uw) = up.split();
    let mut cbuf = vec![0u8; 16 * 1024];
    let mut ubuf = vec![0u8; 16 * 1024];
    let (mut c_open, mut u_open) = (true, true);
    let mut budget = forward.flatten();
    let is_forward = forward.is_some();
    let mut filter = is_forward.then(|| HeadFilter { buf: Vec::new(), done: false });
    let mut wrote = false;
    let mut discarded: usize = 0;
    while c_open || u_open {
        tokio::select! {
            r = cr.read(&mut cbuf), if c_open => {
                let n = r.unwrap_or(0);
                if n == 0 {
                    if is_forward {
                        return RelayEnd::Done;
                    }
                    c_open = false;
                    let _ = tokio::time::timeout(idle, uw.shutdown()).await;
                    continue;
                }
                let take = budget.map_or(n, |b| usize::try_from(b).map_or(n, |b| b.min(n)));
                if take == 0 {
                    discarded = discarded.saturating_add(n);
                    if discarded > 1024 * 1024 {
                        return RelayEnd::Done;
                    }
                    continue;
                }
                if !write_within(&mut uw, cbuf.get(..take).unwrap_or(&[]), idle).await {
                    return RelayEnd::Done;
                }
                budget = budget.map(|b| b.saturating_sub(take as u64));
            }
            r = ur.read(&mut ubuf), if u_open => {
                let chunk = ubuf.get(..r.unwrap_or(0)).unwrap_or(&[]);
                if chunk.is_empty() {
                    u_open = false;
                    if filter.as_ref().is_some_and(|f| !f.done) {
                        return RelayEnd::BadUpstream("the destination closed the connection before it answered".to_string(), wrote);
                    }
                    let _ = tokio::time::timeout(idle, cw.shutdown()).await;
                    if is_forward {
                        return RelayEnd::Done;
                    }
                    continue;
                }
                let out = match filter.as_mut() {
                    Some(f) => match f.push(chunk) {
                        Ok(v) => v,
                        Err(m) => return RelayEnd::BadUpstream(m, wrote),
                    },
                    None => chunk.to_vec(),
                };
                if !out.is_empty() {
                    if !write_within(&mut cw, &out, idle).await {
                        return RelayEnd::Done;
                    }
                    wrote = true;
                }
            }
            _ = tokio::time::sleep(idle) => return RelayEnd::Done,
        }
    }
    RelayEnd::Done
}

#[allow(clippy::too_many_arguments)]
async fn forward(
    mut client: TcpStream,
    extra: Vec<u8>,
    head: &Head,
    cx: &Ctx<'_>,
    policy: &Policy,
    authority: &str,
    path: &str,
    cancel: CancellationToken,
) {
    let idle = cx.shared.limits.idle_timeout;
    let body = match body_kind(head) {
        Ok(b) => b,
        Err(m) => return reject(&mut client, cx.shared, cx.session, head, &m).await,
    };
    let mut up = match open_upstream(cx, policy).await {
        Ok(s) => s,
        Err((status, text)) => return respond(&mut client, status, "", &text).await,
    };

    let mut out: Vec<u8> = format!("{} {} HTTP/1.1\r\nHost: {}\r\n", head.method, path, authority).into_bytes();
    for (n, v) in &head.headers {
        let drop = ["proxy-authorization", "proxy-connection", "connection", "keep-alive", "upgrade", "host"]
            .iter()
            .any(|d| n.eq_ignore_ascii_case(d));
        if drop {
            continue;
        }
        out.extend_from_slice(n.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    // Bytes of the body that arrived with the head, and how many more the client still owes.
    let (already, owed): (&[u8], Option<u64>) = match body {
        Body::None => (&[] as &[u8], Some(0)),
        Body::Length(n) => {
            let k = usize::try_from(n).map_or(extra.len(), |n| n.min(extra.len()));
            (extra.get(..k).unwrap_or(&[]), Some(n.saturating_sub(k as u64)))
        }
        Body::Stream => (extra.as_slice(), None),
    };
    out.extend_from_slice(already);
    if !write_within(&mut up, &out, idle).await {
        let (status, text) = cx.unreachable("sending the request failed");
        return respond(&mut client, status, "", &text).await;
    }

    let end = tokio::select! {
        r = relay(&mut client, &mut up, idle, Some(owed)) => r,
        _ = cancel.cancelled() => RelayEnd::Done,
    };
    if let RelayEnd::BadUpstream(why, false) = end {
        let (status, text) = cx.unreachable(&why);
        respond(&mut client, status, "", &text).await;
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use loom_core::config::{NetworkCfg, NetworkMode};
    use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
    use tokio::time::timeout;

    type Rx = UnboundedReceiver<(SessionId, NetDecision)>;
    const T: Duration = Duration::from_secs(5);

    async fn start() -> (Proxy, Rx) {
        let (tx, rx) = unbounded_channel();
        (Proxy::start(0, tx).await.unwrap(), rx)
    }

    type Seen = Arc<Mutex<Vec<(SessionId, NetDecision)>>>;

    /// A proxy whose audit hook records into the returned list (and fails when `fail` is set).
    async fn start_audited(fail: bool, limits: Limits, resolver: Option<Resolver>) -> (Proxy, Rx, Seen) {
        let (tx, rx) = unbounded_channel();
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        let audit: AuditFn = Arc::new(move |s, d| {
            if fail {
                return Err(std::io::Error::other("disk full"));
            }
            lock(&log).push((s.clone(), d.clone()));
            Ok(())
        });
        (Proxy::start_inner(0, tx, Some(audit), limits, resolver).await.unwrap(), rx, seen)
    }

    /// Accepts one connection and returns what it received until the peer closes.
    async fn silent_server() -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let h = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut got = Vec::new();
            let _ = timeout(T, s.read_to_end(&mut got)).await;
            got
        });
        (port, h)
    }

    fn policy(mode: NetworkMode, allow: &[&str], deny: &[&str], private: &[&str]) -> Policy {
        let v = |x: &[&str]| x.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        Policy::new(&NetworkCfg { mode, allow: v(allow), deny: v(deny), allow_private: v(private) }).unwrap()
    }

    fn lab() -> Policy {
        policy(NetworkMode::Open, &[], &[], &["127.0.0.1"])
    }

    fn auth(g: &SessionGrant) -> String {
        let c = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", g.user, g.password));
        format!("Proxy-Authorization: Basic {c}\r\n")
    }

    async fn echo_server() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        port
    }

    /// Accepts one connection, reads a request (head plus Content-Length body), answers with `reply`
    /// and returns what it received.
    async fn http_server(reply: &'static str) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let h = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut got = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let n = s.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&got).to_string();
                if let Some(i) = text.find("\r\n\r\n") {
                    let want = text
                        .lines()
                        .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0)))
                        .unwrap_or(0);
                    if got.len() >= i + 4 + want {
                        break;
                    }
                }
            }
            s.write_all(reply.as_bytes()).await.unwrap();
            let _ = s.shutdown().await;
            got
        });
        (port, h)
    }

    /// Sends `bytes`, reads until the proxy closes.
    async fn raw(port: u16, bytes: &[u8]) -> String {
        let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let _ = s.write_all(bytes).await;
        let mut out = Vec::new();
        let _ = timeout(T, s.read_to_end(&mut out)).await;
        String::from_utf8_lossy(&out).to_string()
    }

    fn status(resp: &str) -> u16 {
        resp.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0)
    }

    async fn decision(rx: &mut Rx) -> (SessionId, NetDecision) {
        timeout(T, rx.recv()).await.unwrap().unwrap()
    }

    fn no_more(rx: &mut Rx) {
        assert!(rx.try_recv().is_err(), "unexpected extra decision");
    }

    fn connect_req(g: &SessionGrant, dest: &str) -> String {
        format!("CONNECT {dest} HTTP/1.1\r\nHost: {dest}\r\n{}\r\n", auth(g))
    }

    async fn read_until(s: &mut TcpStream, end: &str) -> String {
        let mut got = Vec::new();
        let mut b = [0u8; 1];
        while !String::from_utf8_lossy(&got).ends_with(end) {
            timeout(T, s.read_exact(&mut b)).await.unwrap().unwrap();
            got.push(b[0]);
        }
        String::from_utf8_lossy(&got).to_string()
    }

    #[tokio::test]
    async fn connect_tunnel_echoes_both_ways() {
        let (p, mut rx) = start().await;
        let echo = echo_server().await;
        let sid = SessionId::from("s-one");
        let g = p.grant(&sid, lab());
        let mut s = TcpStream::connect(("127.0.0.1", p.port())).await.unwrap();
        s.write_all(connect_req(&g, &format!("127.0.0.1:{echo}")).as_bytes()).await.unwrap();
        let head = read_until(&mut s, "\r\n\r\n").await;
        assert_eq!(head, "HTTP/1.1 200 Connection established\r\n\r\n");
        for msg in [&b"hello"[..], b"second round"] {
            s.write_all(msg).await.unwrap();
            let mut back = vec![0u8; msg.len()];
            timeout(T, s.read_exact(&mut back)).await.unwrap().unwrap();
            assert_eq!(back, msg);
        }
        let (who, d) = decision(&mut rx).await;
        assert_eq!(who, sid);
        assert_eq!((d.host.as_str(), d.port, d.method.as_str(), d.allowed), ("127.0.0.1", echo, "CONNECT", true));
        assert_eq!(d.rule, "allow_private 127.0.0.1");
        assert_eq!(d.resolved.as_deref(), Some("127.0.0.1"));
        no_more(&mut rx);
    }

    #[tokio::test]
    async fn localhost_name_reaches_allowed_loopback_address() {
        let (p, mut rx) = start().await;
        let echo = echo_server().await;
        let g = p.grant(&SessionId::from("s-lh"), lab());
        let mut s = TcpStream::connect(("127.0.0.1", p.port())).await.unwrap();
        s.write_all(connect_req(&g, &format!("localhost:{echo}")).as_bytes()).await.unwrap();
        let head = read_until(&mut s, "\r\n\r\n").await;
        assert_eq!(status(&head), 200);
        let (_, d) = decision(&mut rx).await;
        assert!(d.allowed);
        assert_eq!(d.resolved.as_deref(), Some("127.0.0.1"), "{d:?}");
    }

    #[tokio::test]
    async fn plain_forward_rewrites_target_and_relays() {
        let (p, mut rx) = start().await;
        let (port, server) = http_server("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await;
        let sid = SessionId::from("s-fwd");
        let g = p.grant(&sid, lab());
        let req = format!(
            "GET http://127.0.0.1:{port}/a/b?x=1#frag HTTP/1.1\r\nHost: wrong.test\r\n{}Proxy-Connection: keep-alive\r\nConnection: keep-alive\r\nX-Test: 1\r\n\r\n",
            auth(&g)
        );
        let resp = raw(p.port(), req.as_bytes()).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "{resp}");
        assert!(resp.ends_with("\r\n\r\nok"), "{resp}");
        let got = String::from_utf8(server.await.unwrap()).unwrap();
        assert!(got.starts_with("GET /a/b?x=1 HTTP/1.1\r\n"), "{got}");
        assert!(got.contains(&format!("Host: 127.0.0.1:{port}\r\n")), "{got}");
        assert!(got.contains("X-Test: 1\r\n"), "{got}");
        assert!(got.contains("Connection: close\r\n"), "{got}");
        let lower = got.to_ascii_lowercase();
        assert!(!lower.contains("proxy-"), "{got}");
        assert!(!lower.contains("keep-alive"), "{got}");
        assert!(!lower.contains("wrong.test"), "{got}");
        let (who, d) = decision(&mut rx).await;
        assert_eq!(who, sid);
        assert_eq!((d.method.as_str(), d.port, d.allowed), ("GET", port, true));
        no_more(&mut rx);
    }

    #[tokio::test]
    async fn plain_forward_relays_request_body() {
        let (p, _rx) = start().await;
        let (port, server) = http_server("HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n").await;
        let g = p.grant(&SessionId::from("s-post"), lab());
        let req = format!(
            "POST http://127.0.0.1:{port} HTTP/1.1\r\n{}Content-Length: 11\r\n\r\nhello world",
            auth(&g)
        );
        let resp = raw(p.port(), req.as_bytes()).await;
        assert_eq!(status(&resp), 201, "{resp}");
        let got = String::from_utf8(server.await.unwrap()).unwrap();
        assert!(got.starts_with("POST / HTTP/1.1\r\n"), "{got}");
        assert!(got.ends_with("\r\n\r\nhello world"), "{got}");
    }

    #[tokio::test]
    async fn failing_audit_refuses_the_connection_and_nothing_reaches_the_upstream() {
        let (p, mut rx, seen) = start_audited(true, Limits::default(), None).await;
        let (port, server) = silent_server().await;
        let g = p.grant(&SessionId::from("s-af"), lab());
        let req = format!("GET http://127.0.0.1:{port}/x HTTP/1.1\r\n{}\r\n", auth(&g));
        let resp = raw(p.port(), req.as_bytes()).await;
        assert_eq!(status(&resp), 502, "{resp}");
        assert!(resp.contains("X-Loom-Proxy: 1\r\n") && resp.contains("egress audit log could not be written"), "{resp}");
        assert!(server.await.unwrap().is_empty(), "the upstream must not receive bytes");
        assert!(lock(&seen).is_empty());
        let (_, d) = decision(&mut rx).await;
        assert!(!d.allowed && d.rule.contains("audit log not written"), "{d:?}");
        // CONNECT is refused before the 200 as well.
        let (port, server) = silent_server().await;
        let r = raw(p.port(), connect_req(&g, &format!("127.0.0.1:{port}")).as_bytes()).await;
        assert_eq!(status(&r), 502, "{r}");
        assert!(server.await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn audit_is_written_before_the_upstream_sees_the_request() {
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (tx, _rx) = unbounded_channel();
        let f2 = flag.clone();
        let audit: AuditFn = Arc::new(move |_, d| {
            assert!(d.allowed);
            std::thread::sleep(Duration::from_millis(150));
            f2.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        });
        let p = Proxy::start_inner(0, tx, Some(audit), Limits::default(), None).await.unwrap();
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let f3 = flag.clone();
        let server = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut b = [0u8; 1];
            let n = timeout(T, s.read(&mut b)).await.unwrap().unwrap();
            let audited = f3.load(std::sync::atomic::Ordering::SeqCst);
            let _ = s.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await;
            (n, audited)
        });
        let g = p.grant(&SessionId::from("s-ord"), lab());
        let req = format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\n{}\r\n", auth(&g));
        let resp = raw(p.port(), req.as_bytes()).await;
        assert_eq!(status(&resp), 204, "{resp}");
        assert_eq!(server.await.unwrap(), (1, true), "the upstream saw bytes before the audit record was written");
    }

    #[tokio::test]
    async fn bad_requests_and_failed_authentication_are_audited() {
        let (p, _rx, seen) = start_audited(false, Limits::default(), None).await;
        let sid = SessionId::from("s-aud");
        let g = p.grant(&sid, lab());
        let r = raw(p.port(), format!("GET https://example.test/ HTTP/1.1\r\n{}\r\n", auth(&g)).as_bytes()).await;
        assert_eq!(status(&r), 400);
        let wrong = SessionGrant { password: "0".repeat(32), ..g.clone() };
        let r = raw(p.port(), connect_req(&wrong, "127.0.0.1:9").as_bytes()).await;
        assert_eq!(status(&r), 407);
        let r = raw(p.port(), connect_req(&g, "nohostport").as_bytes()).await;
        assert_eq!(status(&r), 400);
        let seen = lock(&seen).clone();
        assert_eq!(seen.len(), 3, "{seen:?}");
        assert!(seen.iter().all(|(s, d)| *s == sid && !d.allowed));
        assert!(seen[0].1.rule.starts_with("bad request: https://"), "{:?}", seen[0]);
        assert_eq!(seen[1].1.rule, "proxy authentication failed");
        assert_eq!((seen[1].1.method.as_str(), seen[1].1.host.as_str()), ("CONNECT", "127.0.0.1:9"));
        assert!(seen[2].1.rule.starts_with("bad request: "), "{:?}", seen[2]);
    }

    #[tokio::test]
    async fn missing_wrong_and_revoked_credentials_get_407() {
        let (p, mut rx) = start().await;
        let sid = SessionId::from("s-auth");
        let g = p.grant(&sid, lab());
        let none = raw(p.port(), b"CONNECT 127.0.0.1:9 HTTP/1.1\r\n\r\n").await;
        assert_eq!(status(&none), 407, "{none}");
        assert!(none.contains("Proxy-Authenticate: Basic realm=\"loom\"\r\n"), "{none}");
        assert!(none.contains("X-Loom-Proxy: 1\r\n"));
        let wrong = SessionGrant { password: "0".repeat(32), ..g.clone() };
        let r = raw(p.port(), connect_req(&wrong, "127.0.0.1:9").as_bytes()).await;
        assert_eq!(status(&r), 407);
        let unknown = SessionGrant { user: "s-nobody".into(), ..g.clone() };
        assert_eq!(status(&raw(p.port(), connect_req(&unknown, "127.0.0.1:9").as_bytes()).await), 407);
        let garbage = raw(p.port(), b"CONNECT 127.0.0.1:9 HTTP/1.1\r\nProxy-Authorization: Basic !!!\r\n\r\n").await;
        assert_eq!(status(&garbage), 407);
        p.revoke(&sid);
        assert_eq!(status(&raw(p.port(), connect_req(&g, "127.0.0.1:9").as_bytes()).await), 407);
        no_more(&mut rx);
    }

    #[tokio::test]
    async fn deny_rule_answers_403_with_one_decision() {
        let (p, mut rx) = start().await;
        let sid = SessionId::from("s-deny");
        let g = p.grant(&sid, policy(NetworkMode::Open, &[], &["blocked.test"], &[]));
        let r = raw(p.port(), connect_req(&g, "Blocked.test.:443").as_bytes()).await;
        assert_eq!(status(&r), 403, "{r}");
        assert!(r.contains("X-Loom-Proxy: 1\r\n"));
        assert!(r.contains("Connection: close\r\n"));
        assert!(r.contains("blocked.test:443") && r.contains("deny blocked.test") && r.contains("[network]"), "{r}");
        let (who, d) = decision(&mut rx).await;
        assert_eq!(who, sid);
        assert_eq!((d.allowed, d.rule.as_str(), d.resolved.clone()), (false, "deny blocked.test", None));
        assert_eq!(d.host, "blocked.test");
        no_more(&mut rx);
    }

    #[tokio::test]
    async fn open_mode_loopback_is_refused_as_private() {
        let (p, mut rx) = start().await;
        let echo = echo_server().await;
        let g = p.grant(&SessionId::from("s-priv"), policy(NetworkMode::Open, &[], &[], &[]));
        let r = raw(p.port(), connect_req(&g, &format!("127.0.0.1:{echo}")).as_bytes()).await;
        assert_eq!(status(&r), 403, "{r}");
        let (_, d) = decision(&mut rx).await;
        assert!(!d.allowed);
        assert_eq!(d.rule, "deny private-address 127.0.0.1");
        assert_eq!(d.resolved.as_deref(), Some("127.0.0.1"));
        // The same through a name that resolves to loopback, and through a mapped IPv6 literal.
        let r = raw(p.port(), connect_req(&g, &format!("localhost:{echo}")).as_bytes()).await;
        assert_eq!(status(&r), 403, "{r}");
        let (_, d) = decision(&mut rx).await;
        assert!(!d.allowed && d.resolved.is_some(), "{d:?}");
        let r = raw(p.port(), connect_req(&g, &format!("[::ffff:127.0.0.1]:{echo}")).as_bytes()).await;
        assert_eq!(status(&r), 403, "{r}");
        let (_, d) = decision(&mut rx).await;
        assert_eq!(d.rule, "deny private-address ::ffff:127.0.0.1");
        no_more(&mut rx);
    }

    #[tokio::test]
    async fn deny_list_applies_to_resolved_addresses() {
        let resolver: Resolver = Arc::new(|name: &str| {
            let ip = match name {
                "lab.test" => "10.0.0.5",
                "mapped.test" => "::ffff:10.0.0.5",
                "cidr.test" => "10.1.2.3",
                "pub.test" => "203.0.113.7",
                _ => return Vec::new(),
            };
            vec![ip.parse().unwrap()]
        });
        let (tx, mut rx) = unbounded_channel();
        let p = Proxy::start_inner(0, tx, None, Limits::default(), Some(resolver)).await.unwrap();
        let deny = ["10.0.0.5", "10.1.0.0/16", "203.0.113.7"];
        let g = p.grant(&SessionId::from("s-dr"), policy(NetworkMode::Open, &[], &deny, &["10.0.0.0/8"]));
        for (dest, rule) in [
            ("lab.test:80", "deny 10.0.0.5"),
            ("mapped.test:80", "deny 10.0.0.5"),
            ("[::ffff:10.0.0.5]:80", "deny 10.0.0.5"),
            ("cidr.test:80", "deny 10.1.0.0/16"),
            ("pub.test:443", "deny 203.0.113.7"),
        ] {
            let r = raw(p.port(), connect_req(&g, dest).as_bytes()).await;
            assert_eq!(status(&r), 403, "{dest}: {r}");
            let (_, d) = decision(&mut rx).await;
            assert!(!d.allowed, "{dest}: {d:?}");
            assert_eq!(d.rule, rule, "{dest}");
        }
        no_more(&mut rx);
    }

    #[tokio::test]
    async fn allowlist_miss_is_refused_without_resolving() {
        let (p, mut rx) = start().await;
        let g = p.grant(&SessionId::from("s-al"), policy(NetworkMode::Allowlist, &["only.test"], &[], &[]));
        let r = raw(p.port(), connect_req(&g, "other.test:443").as_bytes()).await;
        assert_eq!(status(&r), 403);
        let (_, d) = decision(&mut rx).await;
        assert_eq!((d.rule.as_str(), d.resolved), ("not in allow list", None));
        let g = p.grant(&SessionId::from("s-da"), policy(NetworkMode::DenyAll, &[], &[], &[]));
        let r = raw(p.port(), format!("GET http://x.test/ HTTP/1.1\r\n{}\r\n", auth(&g)).as_bytes()).await;
        assert_eq!(status(&r), 403);
        let (_, d) = decision(&mut rx).await;
        assert_eq!((d.rule.as_str(), d.method.as_str()), ("mode deny_all", "GET"));
        no_more(&mut rx);
    }

    #[tokio::test]
    async fn set_policy_changes_what_the_same_credentials_may_reach() {
        let (p, mut rx) = start().await;
        let sid = SessionId::from("s-sp");
        let g = p.grant(&sid, policy(NetworkMode::Allowlist, &["only.test"], &[], &[]));
        let r = raw(p.port(), connect_req(&g, "other.test:443").as_bytes()).await;
        assert_eq!(status(&r), 403);
        let (_, d) = decision(&mut rx).await;
        assert_eq!(d.rule.as_str(), "not in allow list");
        // The new policy lists the host; the same credentials now pass the name check.
        assert!(p.set_policy(&sid, policy(NetworkMode::Allowlist, &["only.test", "other.test"], &[], &[])));
        let r = raw(p.port(), connect_req(&g, "other.test:443").as_bytes()).await;
        assert_ne!(status(&r), 407, "{r}");
        let (_, d) = decision(&mut rx).await;
        assert_ne!(d.rule.as_str(), "not in allow list", "{d:?}");
        // And back.
        assert!(p.set_policy(&sid, policy(NetworkMode::DenyAll, &[], &[], &[])));
        let r = raw(p.port(), connect_req(&g, "other.test:443").as_bytes()).await;
        assert_eq!(status(&r), 403);
        let (_, d) = decision(&mut rx).await;
        assert_eq!(d.rule.as_str(), "mode deny_all");
        assert!(!p.set_policy(&SessionId::from("s-none"), policy(NetworkMode::Open, &[], &[], &[])));
        no_more(&mut rx);
    }

    #[tokio::test]
    async fn unreachable_port_is_502_and_allowed_decision() {
        let (p, mut rx) = start().await;
        let dead = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        };
        let g = p.grant(&SessionId::from("s-502"), lab());
        let r = raw(p.port(), connect_req(&g, &format!("127.0.0.1:{dead}")).as_bytes()).await;
        assert_eq!(status(&r), 502, "{r}");
        assert!(r.contains("X-Loom-Proxy: 1\r\n"));
        let (_, d) = decision(&mut rx).await;
        assert!(d.allowed);
        assert!(d.rule.starts_with("allow_private 127.0.0.1 (unreachable: "), "{}", d.rule);
        assert_eq!(d.resolved.as_deref(), Some("127.0.0.1"));
        no_more(&mut rx);
    }

    #[tokio::test]
    async fn two_sessions_are_attributed_separately() {
        let (p, mut rx) = start().await;
        let echo = echo_server().await;
        let (a, b) = (SessionId::from("s-aaa"), SessionId::from("s-bbb"));
        let ga = p.grant(&a, lab());
        let gb = p.grant(&b, policy(NetworkMode::Open, &[], &[], &[]));
        let dest = format!("127.0.0.1:{echo}");
        let port = p.port();
        let ra = connect_req(&ga, &dest);
        let rb = connect_req(&gb, &dest);
        let one = async {
            let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            s.write_all(ra.as_bytes()).await.unwrap();
            let h = read_until(&mut s, "\r\n\r\n").await;
            status(&h)
        };
        let two = async { status(&raw(port, rb.as_bytes()).await) };
        let (sa, sb) = tokio::join!(one, two);
        assert_eq!((sa, sb), (200, 403));
        let mut seen = [decision(&mut rx).await, decision(&mut rx).await];
        seen.sort_by(|x, y| x.0.cmp(&y.0));
        assert_eq!(seen[0].0, a);
        assert!(seen[0].1.allowed);
        assert_eq!(seen[1].0, b);
        assert!(!seen[1].1.allowed);
        no_more(&mut rx);
    }

    #[tokio::test]
    async fn malformed_requests_get_400_and_server_keeps_serving() {
        let (p, mut rx) = start().await;
        let echo = echo_server().await;
        let g = p.grant(&SessionId::from("s-bad"), lab());
        let a = auth(&g);
        let cases: Vec<String> = vec![
            "garbage\r\n\r\n".into(),
            "\x00\x01\x02\r\n\r\n".into(),
            "GET / HTTP/9.9\r\n\r\n".into(),
            format!("GET /origin HTTP/1.1\r\n{a}\r\n"),
            format!("GET https://example.test/ HTTP/1.1\r\n{a}\r\n"),
            format!("CONNECT nohostport HTTP/1.1\r\n{a}\r\n"),
            format!("CONNECT a b:443 HTTP/1.1\r\n{a}\r\n"),
            format!("CONNECT host:0 HTTP/1.1\r\n{a}\r\n"),
            format!("CONNECT [::1:443 HTTP/1.1\r\n{a}\r\n"),
            format!("GET http://user@host.test/ HTTP/1.1\r\n{a}\r\n"),
            format!("GET http://h.test/ HTTP/1.1\r\n{a}Content-Length: 1\r\nContent-Length: 2\r\n\r\n"),
            format!("POST http://h.test/ HTTP/1.1\r\n{a}Content-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n"),
            format!("GET http://h\u{e9}.test/ HTTP/1.1\r\n{a}\r\n"),
        ];
        for c in cases {
            let r = raw(p.port(), c.as_bytes()).await;
            
            assert_eq!(status(&r), 400, "request {c:?} got {r}");
            assert!(r.contains("X-Loom-Proxy: 1\r\n"), "{r}");
        }
        // A client that connects and leaves, or sends half a head, does not disturb anything.
        drop(TcpStream::connect(("127.0.0.1", p.port())).await.unwrap());
        let mut half = TcpStream::connect(("127.0.0.1", p.port())).await.unwrap();
        half.write_all(b"CONNECT 127.0.0.1:1 HT").await.unwrap();
        drop(half);
        let mut s = TcpStream::connect(("127.0.0.1", p.port())).await.unwrap();
        s.write_all(connect_req(&g, &format!("127.0.0.1:{echo}")).as_bytes()).await.unwrap();
        assert_eq!(status(&read_until(&mut s, "\r\n\r\n").await), 200);
        let (_, d) = decision(&mut rx).await;
        assert!(d.allowed);
        no_more(&mut rx);
    }

    #[tokio::test]
    async fn oversized_head_gets_400() {
        let (p, _rx) = start().await;
        let g = p.grant(&SessionId::from("s-big"), lab());
        let req = format!("CONNECT 127.0.0.1:1 HTTP/1.1\r\n{}X-Pad: {}\r\n\r\n", auth(&g), "a".repeat(70 * 1024));
        let r = raw(p.port(), req.as_bytes()).await;
        assert_eq!(status(&r), 400, "{}", &r[..r.len().min(200)]);
        assert!(r.contains("64 KiB"));
        // Still serving.
        assert_eq!(status(&raw(p.port(), b"x\r\n\r\n").await), 400);
    }

    #[tokio::test]
    async fn connection_caps_apply_globally_and_per_session() {
        let echo = echo_server().await;
        let dest = format!("127.0.0.1:{echo}");
        let tunnel = |p: &Proxy, g: &SessionGrant| {
            let (port, req) = (p.port(), connect_req(g, &dest));
            async move {
                let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
                s.write_all(req.as_bytes()).await.unwrap();
                let head = read_until(&mut s, "\r\n\r\n").await;
                (s, status(&head))
            }
        };
        // Per session: the second tunnel of a session at its cap gets 429; another session is unaffected.
        let limits = Limits { max_per_session: 1, ..Limits::default() };
        let (p, _rx, seen) = start_audited(false, limits, None).await;
        let (ga, gb) = (p.grant(&SessionId::from("s-ca"), lab()), p.grant(&SessionId::from("s-cb"), lab()));
        let (held, st) = tunnel(&p, &ga).await;
        assert_eq!(st, 200);
        let r = raw(p.port(), connect_req(&ga, &dest).as_bytes()).await;
        assert_eq!(status(&r), 429, "{r}");
        assert!(r.contains("X-Loom-Proxy: 1\r\n"));
        assert!(lock(&seen).iter().any(|(_, d)| d.rule == "connection limit (per session)"));
        let (_other, st) = tunnel(&p, &gb).await;
        assert_eq!(st, 200);
        // The permit comes back when the tunnel closes.
        drop(held);
        let deadline = tokio::time::Instant::now() + T;
        loop {
            let (_s, st) = tunnel(&p, &ga).await;
            if st == 200 {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline, "the session cap was never released");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Globally: connections past the cap are answered 503 at once.
        let limits = Limits { max_connections: 2, ..Limits::default() };
        let (p, _rx, _seen) = start_audited(false, limits, None).await;
        let _a = TcpStream::connect(("127.0.0.1", p.port())).await.unwrap();
        let _b = TcpStream::connect(("127.0.0.1", p.port())).await.unwrap();
        let mut c = TcpStream::connect(("127.0.0.1", p.port())).await.unwrap();
        let mut out = Vec::new();
        let _ = timeout(T, c.read_to_end(&mut out)).await.unwrap();
        let r = String::from_utf8_lossy(&out).to_string();
        assert_eq!(status(&r), 503, "{r}");
        assert!(r.contains("X-Loom-Proxy: 1\r\n") && r.contains("limit 2"), "{r}");
    }

    #[tokio::test]
    async fn idle_tunnels_and_idle_forwards_are_closed() {
        let limits = Limits { idle_timeout: Duration::from_millis(300), ..Limits::default() };
        let (p, _rx, _seen) = start_audited(false, limits, None).await;
        let g = p.grant(&SessionId::from("s-idle"), lab());
        // A tunnel to a peer that never speaks.
        let (port, _server) = silent_server().await;
        let mut s = TcpStream::connect(("127.0.0.1", p.port())).await.unwrap();
        s.write_all(connect_req(&g, &format!("127.0.0.1:{port}")).as_bytes()).await.unwrap();
        assert_eq!(status(&read_until(&mut s, "\r\n\r\n").await), 200);
        let mut rest = Vec::new();
        let n = timeout(T, s.read_to_end(&mut rest)).await.expect("the idle tunnel was not closed").unwrap();
        assert_eq!(n, 0);
        // A forwarded request whose upstream never answers.
        let (port, _server) = silent_server().await;
        let req = format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\n{}\r\n", auth(&g));
        let mut s = TcpStream::connect(("127.0.0.1", p.port())).await.unwrap();
        s.write_all(req.as_bytes()).await.unwrap();
        let mut rest = Vec::new();
        timeout(T, s.read_to_end(&mut rest)).await.expect("the idle forward was not closed").unwrap();
        assert!(rest.is_empty());
        // Traffic keeps a tunnel alive past the idle period.
        let echo = echo_server().await;
        let mut s = TcpStream::connect(("127.0.0.1", p.port())).await.unwrap();
        s.write_all(connect_req(&g, &format!("127.0.0.1:{echo}")).as_bytes()).await.unwrap();
        assert_eq!(status(&read_until(&mut s, "\r\n\r\n").await), 200);
        for _ in 0..4 {
            tokio::time::sleep(Duration::from_millis(150)).await;
            s.write_all(b"x").await.unwrap();
            let mut b = [0u8; 1];
            timeout(T, s.read_exact(&mut b)).await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn forward_ends_when_the_client_goes_away() {
        let (p, _rx) = start().await;
        let g = p.grant(&SessionId::from("s-gone"), lab());
        let (port, server) = silent_server().await;
        let req = format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\n{}\r\n", auth(&g));
        let mut s = TcpStream::connect(("127.0.0.1", p.port())).await.unwrap();
        s.write_all(req.as_bytes()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        drop(s);
        // The upstream sees the request and then its connection closing, long before any idle timeout.
        let got = timeout(T, server).await.expect("the upstream connection stayed open").unwrap();
        assert!(String::from_utf8_lossy(&got).starts_with("GET / HTTP/1.1\r\n"));
    }

    #[tokio::test]
    async fn upstream_proxy_marker_is_not_relayed() {
        let (p, _rx) = start().await;
        let g = p.grant(&SessionId::from("s-mark"), lab());
        let (port, _server) =
            http_server("HTTP/1.1 403 Forbidden\r\nx-loom-proxy: 1\r\nX-Other: kept\r\nContent-Length: 4\r\n\r\nnope").await;
        let req = format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\n{}\r\n", auth(&g));
        let resp = raw(p.port(), req.as_bytes()).await;
        assert_eq!(status(&resp), 403, "{resp}");
        assert!(!resp.to_ascii_lowercase().contains("loom-proxy"), "{resp}");
        assert!(resp.contains("X-Other: kept\r\n") && resp.ends_with("\r\n\r\nnope"), "{resp}");
        // A destination that does not speak HTTP gets a proxy-generated 502, which does carry the marker.
        let (port, _server) = http_server("not http at all\r\n\r\n").await;
        let req = format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\n{}\r\n", auth(&g));
        let resp = raw(p.port(), req.as_bytes()).await;
        assert_eq!(status(&resp), 502, "{resp}");
        assert!(resp.contains("X-Loom-Proxy: 1\r\n"));
    }

    #[tokio::test]
    async fn env_and_grant_contents() {
        let (p, _rx) = start().await;
        let g = p.grant(&SessionId::from("s-env"), lab());
        assert_eq!(g.port, p.port());
        assert_eq!(g.user, "s-env");
        assert_eq!(g.password.len(), 32);
        assert!(g.password.chars().all(|c| c.is_ascii_hexdigit()));
        let url = format!("http://s-env:{}@127.0.0.1:{}", g.password, p.port());
        assert_eq!(g.url(), url);
        let env = g.env();
        assert_eq!(env.len(), 8);
        for k in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"] {
            assert_eq!(env.get(k), Some(&url), "{k}");
        }
        assert_eq!(env.get("NO_PROXY").map(String::as_str), Some(""));
        assert_eq!(env.get("no_proxy").map(String::as_str), Some(""));
        let g2 = p.grant(&SessionId::from("s-env2"), lab());
        assert_ne!(g.password, g2.password);
    }

    #[tokio::test]
    async fn bind_error_and_shutdown() {
        let (p, _rx) = start().await;
        let (tx, _r2) = unbounded_channel();
        let e = Proxy::start(p.port(), tx).await.err().unwrap();
        assert!(e.to_string().contains(&p.port().to_string()));
        let port = p.port();
        p.shutdown();
        let deadline = tokio::time::Instant::now() + T;
        loop {
            if TcpStream::connect(("127.0.0.1", port)).await.is_err() {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline, "still accepting after shutdown");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[tokio::test]
    async fn dropping_the_last_handle_stops_the_server() {
        let (p, _rx) = start().await;
        let port = p.port();
        let q = p.clone();
        drop(p);
        assert!(TcpStream::connect(("127.0.0.1", port)).await.is_ok());
        drop(q);
        let deadline = tokio::time::Instant::now() + T;
        while TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            assert!(tokio::time::Instant::now() < deadline, "still accepting after drop");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[test]
    fn authority_parsing() {
        assert_eq!(parse_authority("Example.TEST.:443", None), Ok(("example.test".into(), 443)));
        assert_eq!(parse_authority("example.test", Some(80)), Ok(("example.test".into(), 80)));
        assert_eq!(parse_authority("[::1]:8080", None), Ok(("::1".into(), 8080)));
        assert_eq!(parse_authority("[::1]", Some(80)), Ok(("::1".into(), 80)));
        for bad in ["", "host", "host:", "host:99999", "a@b:1", "::1:80", "[::1", "[x]:1", "h st:1", ":80"] {
            assert!(parse_authority(bad, None).is_err(), "{bad:?}");
        }
    }
}
