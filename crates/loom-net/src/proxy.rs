//! The proxy server.
//!
//! CONTRACT.
//!
//! `Proxy::start(port, sink)` binds `127.0.0.1:{port}` (0 = any free port) and serves until
//! `shutdown` or drop. It speaks HTTP/1.1 proxying only:
//! - `CONNECT host:port` → on success `HTTP/1.1 200 Connection established\r\n\r\n`, then bytes are
//!   copied both ways until either side closes;
//! - a request with an absolute `http://` URI → the proxy connects to that host (port 80 by
//!   default), sends the request with an origin-form target, drops `Proxy-Authorization` and
//!   `Proxy-Connection`, adds `Connection: close`, and copies the request body and the response
//!   through, one request and one response per client connection (see *Forwarded requests*);
//! - a check, method [`CHECK_METHOD`] with the destination as `host:port` or as an absolute
//!   `http://host:port/` URI (see *Checks*);
//! - anything else (origin-form target, `https://` absolute URI, unparseable head, a head larger than
//!   64 KiB, no head within the head timeout of [`Limits`]) → `400` with a sentence.
//!
//! ## Checks
//! A check asks for the policy's verdict on a destination without using it: the proxy applies the
//! policy to the name, resolves it and checks the addresses as for a connection, but connects to
//! nothing. It answers `200` (allowed), `403` (refused, with the refusal text) or `502` (the name does
//! not resolve), with the rule in header [`RULE_HEADER`], and records the decision with method
//! `LOOM-CHECK` and the rule suffixed ` (check only)`. Tools ask it before an https request, because an
//! HTTP client does not show what the proxy answered to its CONNECT.
//!
//! ## Sessions
//! `grant(session, policy)` returns a [`SessionGrant`] with fresh random credentials (user = the
//! session id, password = 32 hex chars). The client authenticates with `Proxy-Authorization: Basic`.
//! Missing or unknown credentials → `407` with `Proxy-Authenticate: Basic realm="loom"`.
//! `grant_reference(session, cfg)` returns a separate `ReferenceGrant` (URL and host matcher, no env).
//! Its random credential is kept only in trusted in-process tools, with GET/check/CONNECT permitted.
//! Plain HTTP strips Authorization, Cookie and Referer. HTTPS CONNECT is opaque: the trusted client
//! enforces GET, no URL user-info, no credential headers and redirect policy at every hop. Neither a
//! host reservation nor GET-only access prevents exfiltration in URL paths/queries.
//! `revoke(session)` drops both command and reference grants; connections already open are left to finish.
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
//! Every request produces exactly one `NetDecision` (and a second one when it fails after an allow,
//! see below) sent to `sink` together with the session id:
//! `host`, `port`, `method` (`CONNECT` or the request method), `allowed`, `rule`, `resolved` (the
//! address connected to, or the refused address, when there is one). Resolution or connect failures
//! after an allow are reported as allowed with the rule suffixed ` (unreachable: {why})`.
//! A connection on record as allowed that then fails gets a second decision: the same destination,
//! address and rule, allowed, with the rule suffixed ` (failed after the allow: {why})`. For a tunnel
//! that is when its client is gone before the `200`, the bytes it sent ahead cannot be written, it
//! ends (closed, failed on either side, or idle) before the destination sent a byte, or the proxy shuts
//! down while it is open (reason "the egress proxy shut down"); once bytes have come from the
//! destination the proxy cannot tell a cut-off encrypted stream from a routine close, so the tunnel is
//! not judged further otherwise. For a forwarded request it is when the request cannot be written,
//! the destination answers nothing usable or stalls, the relay fails on either side, or the proxy shuts
//! down during the relay.
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
//! ## Audit
//! `start_with` takes an audit hook ([`AuditFn`]), called on a blocking thread with the session (or
//! `None`) and the decision. For an allowed connection it runs after the name lookup and the TCP
//! connect to the checked address, and before any byte is sent either way: the `200` of a CONNECT and
//! the forwarded request wait for it. When it fails the client gets `502` (with the marker) saying
//! that the egress audit log could not be written, and the connection is closed. So the DNS query and
//! the TCP handshake to an allowed destination leave the host before the record exists, and a lookup
//! that fails is recorded best effort only.
//! Refusals, unreachable destinations and the answers the proxy gives itself (`400`, `407`, `429`,
//! `503`) are recorded best effort: a failure is logged. Answers that cannot be tied to a granted
//! session by its credentials (no or wrong credentials, a head that cannot be read or does not arrive,
//! the limit of all sessions) go to the hook with `None`, at most 10 a minute; the next one recorded
//! says how many were left out. The records of these answers carry the destination only when the
//! request names a valid one (else host `-`, port 0); their texts are cut, with `…` marking the cut.
//! With a hook, `sink` receives only the decisions of requests that reached the policy and that the
//! hook failed to record, so a consumer that shows what the hook recorded and what the sink sends sees
//! each decision once.
//!
//! ## Limits ([`Limits`], defaults)
//! - 256 connections in all. A connection that has not sent a complete head within 10 s gets `400`.
//!   At the limit a new connection takes the slot of the oldest connection that is only being
//!   answered by the proxy itself and drained, or, when there is none, of the oldest connection that
//!   has not sent a complete head yet (that one is closed); when there is neither it is answered `503`
//!   with `Retry-After: 5`.
//! - 64 connections per session; over it `429` with `Retry-After: 5`.
//! - 16 name lookups at once, at most 4 of them for one session; a lookup waits up to 10 s for a turn.
//! - The two directions of a tunnel or forwarded request are relayed independently. With no byte
//!   moving in either direction for 10 minutes the connection is closed; a forwarded request that has
//!   sent nothing back yet gets `504` first. A tunnel passes a half close on to the other side.
//! - A forwarded request whose client ends its side (closes, or only shuts down its writing half) is
//!   not read any more but still gets the response while the destination keeps sending: it ends when
//!   the destination is silent for 30 s, or at once when a write to the client fails.
//!
//! ## Forwarded requests
//! The request body is forwarded up to its end as its head frames it: `Content-Length` bytes, or a
//! `chunked` body up to its last chunk and trailers (a body with another transfer coding, or a chunked
//! body the proxy cannot follow, runs until the client stops sending). What the client sends after it
//! is not forwarded.
//! A plain-HTTP response head from the destination is parsed as an HTTP client parses it (a bare LF
//! ends a line too) and written to the client again with CRLF line ends and without any
//! `X-Loom-Proxy` header; only responses the proxy generates carry that marker. The final (non-1xx)
//! head also loses the destination's `Connection`, `Keep-Alive` and `Proxy-Connection` headers, and its
//! `Content-Length` when it has a `Transfer-Encoding`, and ends in `Connection: close`. A head that does
//! not parse, or whose `Content-Length` values are not numbers or differ, gets `502`.
//! The response ends where its head says, read as hyper reads it: at the head for a `HEAD` request and
//! for `204` and `304`; after the last chunk and the trailers when the last coding of the last
//! `Transfer-Encoding` is `chunked`; after `Content-Length` bytes; otherwise (and for `101`) when the
//! destination closes. At that end the proxy closes the connection and relays nothing more, so bytes
//! a destination sends after its response never reach the client. A chunked body that breaks the
//! chunked format ends the relay where it breaks.
//! When the client sends anything after its request other than empty lines, a response that runs
//! until the destination closes is cut: the relay ends with the bytes that carried its head, or at once
//! when they have already been relayed.

use crate::policy::{normalize_host, Policy};
use base64::Engine as _;
use loom_core::event::NetDecision;
use loom_core::SessionId;
use rand::Rng;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

const MAX_HEAD: usize = 64 * 1024;
const MAX_HEADERS: usize = 100;
/// Headers of a destination's response head that are read; a head with more gets `502`.
const MAX_RESPONSE_HEADERS: usize = 256;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);
/// Addresses of one name that are examined; a name with more is cut here.
const MAX_ADDRS: usize = 32;
/// Tasks that answer connections over the limit of all sessions with a `503` the client can read.
const REFUSALS: usize = 16;
/// Records a minute of answers that name no granted session.
const UNATTRIBUTED_PER_MINUTE: u32 = 10;
/// Bytes past its body that the client of a forwarded request may send before the request is dropped.
const MAX_DISCARD: usize = 1024 * 1024;
/// The header that marks a response the proxy generated itself.
const MARKER: &str = "x-loom-proxy";
/// The method of a check (see *Checks*).
pub const CHECK_METHOD: &str = "LOOM-CHECK";
/// The header of a check's answer that carries the rule.
pub const RULE_HEADER: &str = "X-Loom-Rule";

/// The audit hook: called with the session (`None` for an answer that names no granted session) and
/// the decision, it must have recorded the decision durably when it returns `Ok`. It may block (it
/// runs on a blocking thread). For an allowed connection the proxy calls it before the upstream socket
/// is used and refuses the connection (502) when it fails.
pub type AuditFn = Arc<dyn Fn(Option<&SessionId>, &NetDecision) -> std::io::Result<()> + Send + Sync>;

/// Test hook: name to addresses, instead of a system lookup.
type Resolver = Arc<dyn Fn(&str) -> Vec<IpAddr> + Send + Sync>;

/// Resource limits of one proxy.
#[derive(Clone, Debug)]
pub struct Limits {
    /// Concurrent client connections, all sessions together. Default 256.
    pub max_connections: usize,
    /// Concurrent client connections of one session. Default 64.
    pub max_per_session: usize,
    /// A connection that has not sent a complete request head within this gets `400`. Default 10 s.
    pub head_timeout: Duration,
    /// A tunnel or forwarded request with no bytes in either direction for this long is closed.
    /// Default 10 minutes.
    pub idle_timeout: Duration,
    /// After the client of a forwarded request has ended its side, the request ends once the
    /// destination is silent for this long (or `idle_timeout`, when shorter). Default 30 s.
    pub forward_grace: Duration,
    /// Concurrent name lookups. Default 16.
    pub max_lookups: usize,
    /// Concurrent name lookups of one session. Default 4.
    pub max_lookups_per_session: usize,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_connections: 256,
            max_per_session: 64,
            head_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(600),
            forward_grace: Duration::from_secs(30),
            max_lookups: 16,
            max_lookups_per_session: 4,
        }
    }
}

fn semaphore(permits: usize) -> Arc<Semaphore> {
    Arc::new(Semaphore::new(permits.min(Semaphore::MAX_PERMITS)))
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

/// A separate capability held only by trusted in-process reference clients, never command env.
/// CONNECT is opaque: the client must enforce GET, strip credentials and validate each redirect.
#[derive(Clone, Debug)]
pub struct ReferenceGrant {
    grant: SessionGrant,
    raw_policy: Policy,
}

impl ReferenceGrant {
    pub fn url(&self) -> String {
        self.grant.url()
    }

    /// Pattern routing only; the proxy still checks deny rules and resolved addresses.
    pub fn matches_host(&self, host: &str, port: u16) -> bool {
        self.raw_policy.matches_reference(host, port)
    }
}

struct Entry {
    reference: bool,
    session: SessionId,
    password: String,
    policy: Arc<Policy>,
    /// One permit per open client connection of the session.
    permits: Arc<Semaphore>,
    /// One permit per name lookup of the session in progress.
    lookups: Arc<Semaphore>,
}

/// A pending connection: its id, the token that closes it and its connection permit.
type PendingEntry = (u64, CancellationToken, OwnedSemaphorePermit);

/// The connections whose slot a new one may take at the limit, each queue oldest first: those only
/// being drained after an answer of the proxy itself, and those that have not sent a complete request
/// head yet.
#[derive(Default)]
struct Pending {
    next: u64,
    draining: VecDeque<PendingEntry>,
    heads: VecDeque<PendingEntry>,
}

/// Records of answers that name no granted session: how many were written in the current minute,
/// and how many were left out since the last one written.
struct Budget {
    since: std::time::Instant,
    used: u32,
    left_out: u64,
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
    pending: Mutex<Pending>,
    refusals: Arc<Semaphore>,
    unattributed: Mutex<Budget>,
    /// The tasks that serve or refuse a connection.
    tasks: TaskTracker,
}

impl Shared {
    /// Registers a new connection, which has not sent its head yet, as pending; returns its id and the
    /// token that closes it.
    fn add_pending(&self, permit: OwnedSemaphorePermit) -> (u64, CancellationToken) {
        self.enqueue(permit, false)
    }

    /// Registers a connection that is only being drained after an answer of the proxy itself as
    /// pending. It has nothing left to serve, so eviction closes it before any connection still sending
    /// its head; among those drained, the oldest goes first, as its client has had the longest to read
    /// the answer.
    fn add_draining(&self, permit: OwnedSemaphorePermit) -> (u64, CancellationToken) {
        self.enqueue(permit, true)
    }

    fn enqueue(&self, permit: OwnedSemaphorePermit, draining: bool) -> (u64, CancellationToken) {
        let mut guard = lock(&self.pending);
        let p = &mut *guard;
        let id = p.next;
        p.next = p.next.wrapping_add(1);
        let token = CancellationToken::new();
        let queue = if draining { &mut p.draining } else { &mut p.heads };
        queue.push_back((id, token.clone(), permit));
        (id, token)
    }

    /// Closes the oldest connection being drained, or else the oldest one still sending its head, and
    /// returns its permit.
    fn evict_pending(&self) -> Option<OwnedSemaphorePermit> {
        let (_, token, permit) = {
            let mut guard = lock(&self.pending);
            let p = &mut *guard;
            p.draining.pop_front().or_else(|| p.heads.pop_front())?
        };
        token.cancel();
        Some(permit)
    }

    /// Takes a pending connection's permit back; `None` when a newer connection was given it.
    fn claim_pending(&self, id: u64) -> Option<OwnedSemaphorePermit> {
        let mut guard = lock(&self.pending);
        let p = &mut *guard;
        for queue in [&mut p.draining, &mut p.heads] {
            if let Some(i) = queue.iter().position(|(x, _, _)| *x == id) {
                return queue.remove(i).map(|(_, _, permit)| permit);
            }
        }
        None
    }

    /// Whether a record of an answer that names no session may be written now; if so, how many such
    /// records were left out before it.
    fn unattributed_turn(&self) -> Option<u64> {
        let mut b = lock(&self.unattributed);
        if b.since.elapsed() >= Duration::from_secs(60) {
            b.since = std::time::Instant::now();
            b.used = 0;
        }
        if b.used >= UNATTRIBUTED_PER_MINUTE {
            if b.left_out == 0 {
                tracing::warn!(
                    "the egress proxy is answering many requests that name no session; recording at most {UNATTRIBUTED_PER_MINUTE} a minute"
                );
            }
            b.left_out = b.left_out.saturating_add(1);
            return None;
        }
        b.used = b.used.saturating_add(1);
        Some(std::mem::take(&mut b.left_out))
    }

    fn leave_out(&self) {
        let mut b = lock(&self.unattributed);
        b.left_out = b.left_out.saturating_add(1);
    }
}

/// A pending connection's place in [`Pending`]; dropped before it is claimed, it gives the permit back.
struct PendingGuard<'a> {
    shared: &'a Shared,
    id: u64,
}

impl PendingGuard<'_> {
    fn claim(self) -> Option<OwnedSemaphorePermit> {
        self.shared.claim_pending(self.id)
    }
}

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        drop(self.shared.claim_pending(self.id));
    }
}

/// Why a connection on record as allowed ended when the proxy was cancelled.
const SHUTDOWN: &str = "the egress proxy shut down";

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

    /// `audit` records every decision before it takes effect (see [`AuditFn`] and *Audit* above); `sink`
    /// then receives only the decisions it failed to record. Without `audit`, `sink` receives every
    /// decision of a request that reached the policy.
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
        let listener =
            TcpListener::bind(("127.0.0.1", port)).await.map_err(|source| ProxyError::Bind { port, source })?;
        let bound = listener.local_addr().map_err(|source| ProxyError::Bind { port, source })?.port();
        let shared = Arc::new(Shared {
            sessions: Mutex::new(HashMap::new()),
            sink,
            audit,
            connections: semaphore(limits.max_connections),
            lookups: semaphore(limits.max_lookups),
            limits,
            resolver,
            pending: Mutex::new(Pending::default()),
            refusals: semaphore(REFUSALS),
            unattributed: Mutex::new(Budget { since: std::time::Instant::now(), used: 0, left_out: 0 }),
            tasks: TaskTracker::new(),
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
        let limits = &self.inner.shared.limits;
        let entry = Entry {
            reference: false,
            session: session.clone(),
            password: password.clone(),
            policy: Arc::new(policy),
            permits: semaphore(limits.max_per_session),
            lookups: semaphore(limits.max_lookups_per_session),
        };
        lock(&self.inner.shared.sessions).insert(session.as_str().to_string(), entry);
        SessionGrant { port: self.inner.port, user: session.as_str().to_string(), password }
    }

    /// Mint a credential for in-process reference GET clients. It is not added to command env.
    pub fn grant_reference(
        &self,
        session: &SessionId,
        cfg: &loom_core::config::NetworkCfg,
    ) -> Result<ReferenceGrant, String> {
        let raw_policy = Policy::new(cfg)?;
        let policy = Policy::reference(cfg)?;
        let user = format!("reference-{:032x}", rand::rng().random::<u128>());
        let password = format!("{:032x}", rand::rng().random::<u128>());
        let limits = &self.inner.shared.limits;
        let entry = Entry {
            reference: true,
            session: session.clone(),
            password: password.clone(),
            policy: Arc::new(policy),
            permits: semaphore(limits.max_per_session),
            lookups: semaphore(limits.max_lookups_per_session),
        };
        let mut sessions = lock(&self.inner.shared.sessions);
        sessions.retain(|_, entry| !(entry.reference && &entry.session == session));
        sessions.insert(user.clone(), entry);
        Ok(ReferenceGrant { grant: SessionGrant { port: self.inner.port, user, password }, raw_policy })
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

    /// What the name check of the session's current policy says about `host:port`; `None` when the
    /// session holds no grant.
    pub fn check_name(&self, session: &SessionId, host: &str, port: u16) -> Option<crate::policy::Verdict> {
        lock(&self.inner.shared.sessions).get(session.as_str()).map(|e| e.policy.check_name(host, port))
    }

    pub fn revoke(&self, session: &SessionId) {
        lock(&self.inner.shared.sessions).retain(|_, entry| &entry.session != session);
    }

    /// Stop accepting connections. Open tunnels are closed.
    pub fn shutdown(&self) {
        self.inner.cancel.cancel();
    }

    /// Like [`Proxy::shutdown`], then waits up to `within` for the connections to end, so that the records
    /// they write on the way out (the second decision of one on record as allowed) are written before the
    /// caller goes on, e.g. to exit the process.
    pub async fn stop(&self, within: Duration) {
        self.shutdown();
        let tasks = &self.inner.shared.tasks;
        tasks.close();
        let _ = tokio::time::timeout(within, tasks.wait()).await;
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
                Ok((stream, _)) => {
                    // At the limit, the slot of a connection being drained, or else of the oldest one still
                    // without a head, is taken over.
                    let slot = shared.connections.clone().try_acquire_owned().ok().or_else(|| shared.evict_pending());
                    match slot {
                        Some(permit) => {
                            let (id, evicted) = shared.add_pending(permit);
                            shared.tasks.spawn(handle(stream, shared.clone(), cancel.clone(), id, evicted));
                        }
                        None => refuse(stream, &shared),
                    }
                }
                // Out of descriptors or a connection reset before accept: keep serving.
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            },
        }
    }
}

/// Answers a connection over the limit of all sessions with `503`: from one of a few tasks that let
/// the client read it, or, when those are busy too, with one non-blocking write and close.
fn refuse(stream: TcpStream, shared: &Arc<Shared>) {
    let body = format!(
        "loom proxy: too many open proxy connections (limit {}). Wait for running commands to finish, or retry shortly.\n",
        shared.limits.max_connections
    );
    let (status, extra) = ("503 Service Unavailable", "Retry-After: 5\r\n");
    match shared.refusals.clone().try_acquire_owned() {
        Ok(permit) => {
            let owner = shared.clone();
            shared.tasks.spawn(async move {
                let mut stream = stream;
                audit_local(&owner, None, local_decision(None, "connection limit (all sessions)")).await;
                respond(&mut stream, status, extra, &body).await;
                drop(permit);
            });
        }
        Err(_) => {
            let _ = stream.try_write(response_bytes(status, extra, &body).as_bytes());
            shared.leave_out();
        }
    }
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

/// `d` in words: whole minutes, whole seconds, or milliseconds.
fn human(d: Duration) -> String {
    let s = d.as_secs();
    let (minutes, seconds) = (s / 60, s % 60);
    let plural = |n: u64, unit: &str| format!("{n} {unit}{}", if n == 1 { "" } else { "s" });
    if d.subsec_nanos() != 0 || s == 0 {
        format!("{} ms", d.as_millis())
    } else if minutes > 0 && seconds == 0 {
        plural(minutes, "minute")
    } else {
        plural(s, "second")
    }
}

/// `s` cut to `max` characters, with `…` when something was cut.
fn cut(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((i, _)) => format!("{}…", s.get(..i).unwrap_or("")),
        None => s.to_string(),
    }
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
    if send(client, status, extra, body).await {
        drain(client).await;
    }
}

/// Like [`respond`], for a connection that holds the global `slot`: before the drain the slot is
/// pending again, so at the limit a new connection takes it over (and this one is closed) rather than
/// wait for a connection that has nothing left to serve; it is taken before the slot of any
/// connection still sending its head (see [`Shared::add_draining`]).
async fn answer(
    client: &mut TcpStream,
    shared: &Shared,
    slot: OwnedSemaphorePermit,
    status: &str,
    extra: &str,
    body: &str,
) {
    if !send(client, status, extra, body).await {
        return;
    }
    let (id, evicted) = shared.add_draining(slot);
    let _pending = PendingGuard { shared, id };
    tokio::select! {
        _ = drain(client) => {}
        _ = evicted.cancelled() => {}
    }
}

/// Writes a proxy-generated response and ends the writing side; false when the client is gone.
async fn send(client: &mut TcpStream, status: &str, extra: &str, body: &str) -> bool {
    let msg = response_bytes(status, extra, body);
    if client.write_all(msg.as_bytes()).await.is_err() {
        return false;
    }
    let _ = client.shutdown().await;
    true
}

/// Reads and drops what the client still sends, for up to 500 ms.
async fn drain(client: &mut TcpStream) {
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

async fn bad_request(client: &mut TcpStream, shared: &Shared, slot: OwnedSemaphorePermit, why: &str) {
    let body = format!(
        "loom proxy: {why}. This proxy accepts `CONNECT host:port` and `GET http://host/path`-style requests with an absolute http:// URI; use CONNECT for https.\n"
    );
    answer(client, shared, slot, "400 Bad Request", "", &body).await;
}

/// Records a decision: the audit hook first (on a blocking thread, so file I/O never stalls a worker).
/// The sink gets the decision when `to_sink` and the hook did not record it: always without a hook,
/// and as a refusal when the hook failed. A failing hook is returned.
async fn audit_decision(
    shared: &Shared,
    session: Option<&SessionId>,
    d: NetDecision,
    to_sink: bool,
) -> std::io::Result<()> {
    let result = match &shared.audit {
        None => Err(None),
        Some(f) => {
            let (f, s, dd) = (f.clone(), session.cloned(), d.clone());
            match tokio::task::spawn_blocking(move || f(s.as_ref(), &dd)).await {
                Ok(r) => r.map_err(Some),
                Err(e) => Err(Some(std::io::Error::other(format!("the audit task failed: {e}")))),
            }
        }
    };
    if let (Err(failure), true, Some(s)) = (&result, to_sink, session) {
        let shown = match failure {
            None => d,
            Some(_) if d.allowed => {
                NetDecision { allowed: false, rule: format!("{} (refused: egress audit log not written)", d.rule), ..d }
            }
            Some(_) => NetDecision { rule: format!("{} (egress audit log not written)", d.rule), ..d },
        };
        let _ = shared.sink.send((s.clone(), shown));
    }
    match result {
        Ok(()) | Err(None) => Ok(()),
        Err(Some(e)) => Err(e),
    }
}

/// Records an answer the proxy gives itself, best effort: a failure is logged. Answers that name no
/// session are recorded at most [`UNATTRIBUTED_PER_MINUTE`] a minute.
async fn audit_local(shared: &Shared, session: Option<&SessionId>, mut d: NetDecision) {
    if shared.audit.is_none() {
        return;
    }
    if session.is_none() {
        match shared.unattributed_turn() {
            None => return,
            Some(0) => {}
            Some(n) => d.rule = format!("{} ({n} similar answers before this one were not recorded)", d.rule),
        }
    }
    if let Err(e) = audit_decision(shared, session, d, false).await {
        let whose = session.map_or("a request without a session", |s| s.as_str());
        tracing::warn!("cannot write the egress audit record of {whose}: {e}");
    }
}

/// The record of an answer the proxy gives itself to `head` (when it was read).
fn local_decision(head: Option<&Head>, rule: &str) -> NetDecision {
    let (host, port) = head.and_then(destination).unwrap_or_else(|| ("-".to_string(), 0));
    NetDecision {
        host: cut(&host, 255),
        port,
        method: head.map_or_else(|| "-".to_string(), |h| cut(&h.method, 32)),
        allowed: false,
        rule: cut(rule, 300),
        resolved: None,
    }
}

/// The destination a request names, when its target parses as one.
fn destination(head: &Head) -> Option<(String, u16)> {
    let t = head.target.as_str();
    let http = t.get(..7).is_some_and(|p| p.eq_ignore_ascii_case("http://"));
    if head.method == "CONNECT" || (head.method == CHECK_METHOD && !http) {
        return parse_authority(t, None).ok();
    }
    if http {
        return plain_target(t).ok().map(|(host, port, _, _)| (host, port));
    }
    let rest = t.get(..8).filter(|p| p.eq_ignore_ascii_case("https://")).and_then(|_| t.get(8..))?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    parse_authority(rest.get(..end)?, Some(443)).ok()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

struct Authed {
    reference: bool,
    session: SessionId,
    policy: Arc<Policy>,
    permits: Arc<Semaphore>,
    lookups: Arc<Semaphore>,
}

/// The session whose Basic credentials the request carries, or why there is none.
fn authenticate(shared: &Shared, head: &Head) -> Result<Authed, String> {
    let Some(value) = head.header("proxy-authorization") else { return Err("no credentials".into()) };
    let decoded = (|| {
        let value = std::str::from_utf8(value).ok()?;
        let (scheme, encoded) = value.trim().split_once(' ')?;
        if !scheme.eq_ignore_ascii_case("basic") {
            return None;
        }
        let decoded = base64::engine::general_purpose::STANDARD.decode(encoded.trim()).ok()?;
        String::from_utf8(decoded).ok()
    })();
    // Passwords are hex, so the last colon separates the two.
    let Some((user, password)) = decoded.as_deref().and_then(|d| d.rsplit_once(':')) else {
        return Err("the credentials are not Basic user:password".into());
    };
    let sessions = lock(&shared.sessions);
    let Some(e) = sessions.get(user) else { return Err("unknown user".into()) };
    if constant_time_eq(e.password.as_bytes(), password.as_bytes()) {
        let (session, policy) = (e.session.clone(), e.policy.clone());
        Ok(Authed { reference: e.reference, session, policy, permits: e.permits.clone(), lookups: e.lookups.clone() })
    } else {
        Err(format!("wrong password for session {}", e.session.as_str()))
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
    /// The session's name lookup turns.
    lookups: &'a Arc<Semaphore>,
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
        audit_decision(self.shared, Some(self.session), d, true).await
    }

    /// Like `record`, for decisions that need no audit to succeed: a failure is only logged.
    async fn record_best_effort(&self, allowed: bool, rule: String, resolved: Option<IpAddr>) {
        if let Err(e) = self.record(allowed, rule, resolved).await {
            tracing::warn!("cannot write the egress audit record of {}: {e}", self.session.as_str());
        }
    }

    /// Records that a connection on record as allowed failed before or while its request was relayed:
    /// the allow's rule and address again, with the failure, so the trail never ends at a bare allow
    /// for traffic that did not flow. Best effort.
    async fn failed_after_allow(&self, allowed: &Allowed, why: &str) {
        let rule = format!("{} (failed after the allow: {why})", allowed.rule);
        self.record_best_effort(true, rule, Some(allowed.ip)).await;
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
                if self.method == CHECK_METHOD { "a connection" } else { self.method },
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

    fn silent(&self, after: Duration) -> (&'static str, String) {
        (
            "504 Gateway Timeout",
            format!(
                "loom proxy: {} sent no response for {}, so the request was closed. Retry it, or check that the host is up and answering.\n",
                self.dest(),
                human(after)
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

/// Name to addresses, on a task of its own: the test hook, or a system lookup. A lookup holds a turn
/// of its session and one of the proxy until it ends, even when the caller has given up waiting.
async fn resolve(cx: &Ctx<'_>) -> Result<Vec<IpAddr>, String> {
    let turn = |s: &Arc<Semaphore>| tokio::time::timeout(RESOLVE_TIMEOUT, s.clone().acquire_owned());
    let Ok(Ok(mine)) = turn(cx.lookups).await else {
        return Err(format!(
            "this session already has {} name lookups in progress",
            cx.shared.limits.max_lookups_per_session
        ));
    };
    let Ok(Ok(all)) = turn(&cx.shared.lookups).await else {
        return Err("too many name lookups are in progress".to_string());
    };
    let (name, port, resolver) = (cx.host.to_string(), cx.port, cx.shared.resolver.clone());
    let task = tokio::spawn(async move {
        let found = match resolver {
            Some(r) => tokio::task::spawn_blocking(move || r(&name)).await.map_err(std::io::Error::other),
            None => tokio::net::lookup_host((name.as_str(), port)).await.map(|it| it.map(|a| a.ip()).collect()),
        };
        drop((mine, all));
        found.map(|v: Vec<IpAddr>| v.into_iter().take(MAX_ADDRS).collect::<Vec<_>>())
    });
    match tokio::time::timeout(RESOLVE_TIMEOUT, task).await {
        Ok(Ok(Ok(v))) => Ok(v),
        Ok(Ok(Err(e))) => Err(format!("name lookup failed: {e}")),
        Ok(Err(_)) => Err("name lookup failed".to_string()),
        Err(_) => Err("name lookup timed out".to_string()),
    }
}

/// The rule and the address of a connection that is on record as allowed.
struct Allowed {
    rule: String,
    ip: IpAddr,
}

/// Applies the policy to the name, resolves it, and connects to the first address the policy allows.
/// Reports exactly one decision; for the connection it returns, the audit hook has succeeded first, and
/// the rule and address it was recorded with come along. On failure returns the status line and body
/// to send.
async fn open_upstream(cx: &Ctx<'_>, policy: &Policy) -> Result<(TcpStream, Allowed), (&'static str, String)> {
    let v = policy.check_name(cx.host, cx.port);
    if !v.allowed {
        cx.record_best_effort(false, v.rule.clone(), None).await;
        return Err(cx.refused(&v.rule));
    }
    let name_rule = v.rule;

    let addrs: Vec<IpAddr> = match cx.host.parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => match resolve(cx).await {
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
                return match cx.record(true, cv.rule.clone(), Some(ip)).await {
                    Ok(()) => Ok((s, Allowed { rule: cv.rule, ip })),
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

/// Answers a check (see *Checks*): the decision `open_upstream` would make, without connecting.
async fn check(client: &mut TcpStream, cx: &Ctx<'_>, policy: &Policy, slot: OwnedSemaphorePermit) {
    let name = policy.check_name(cx.host, cx.port);
    let found = if name.allowed {
        let addrs = match cx.host.parse::<IpAddr>() {
            Ok(ip) => Ok(vec![ip]),
            Err(_) => resolve(cx).await,
        };
        // The first address the policy allows, else the first refusal.
        addrs.and_then(|addrs| {
            let mut checked =
                addrs.into_iter().map(|ip| (policy.check_addr(cx.host, cx.port, ip, &name.rule), Some(ip)));
            let first = checked.next().ok_or("the name has no addresses")?;
            Ok(if first.0.allowed { first } else { checked.find(|(v, _)| v.allowed).unwrap_or(first) })
        })
    } else {
        Ok((name.clone(), None))
    };
    let (allowed, rule, resolved, (status, body)) = match found {
        Ok((v, ip)) if v.allowed => {
            let body = format!("loom network policy: a connection to {} is allowed by rule `{}`.\n", cx.dest(), v.rule);
            (true, v.rule, ip, ("200 OK", body))
        }
        Ok((v, ip)) => (false, v.rule.clone(), ip, cx.refused(&v.rule)),
        Err(why) => (true, format!("{} (unreachable: {why})", name.rule), None, cx.unreachable(&why)),
    };
    let header: String = rule.chars().map(|c| if c == ' ' || c.is_ascii_graphic() { c } else { '?' }).collect();
    cx.record_best_effort(allowed, format!("{rule} (check only)"), resolved).await;
    answer(client, cx.shared, slot, status, &format!("{RULE_HEADER}: {header}\r\n"), &body).await;
}

/// Answers a request of a session that the proxy rejects itself with 400, after auditing it.
async fn reject(
    client: &mut TcpStream,
    shared: &Shared,
    slot: OwnedSemaphorePermit,
    session: &SessionId,
    head: &Head,
    why: &str,
) {
    audit_local(shared, Some(session), local_decision(Some(head), &format!("bad request: {why}"))).await;
    bad_request(client, shared, slot, why).await;
}

/// Serves one connection. It is pending (`id`, closed through `evicted`) until its head is complete.
async fn handle(
    mut client: TcpStream,
    shared: Arc<Shared>,
    cancel: CancellationToken,
    id: u64,
    evicted: CancellationToken,
) {
    let _ = client.set_nodelay(true);
    let pending = PendingGuard { shared: &shared, id };
    let wait = shared.limits.head_timeout;
    let read = tokio::select! {
        r = tokio::time::timeout(wait, read_head(&mut client)) => r,
        _ = evicted.cancelled() => return,
        _ = cancel.cancelled() => return,
    };
    // From here the connection holds its slot itself; when a newer one was given it meanwhile, it ends.
    let Some(slot) = pending.claim() else { return };
    let (head, extra) = match read {
        Err(_) => {
            let why = format!("no complete request head arrived within {}", human(wait));
            audit_local(&shared, None, local_decision(None, &format!("bad request: {why}"))).await;
            return bad_request(&mut client, &shared, slot, &why).await;
        }
        Ok(Err(HeadError::Closed)) => return,
        Ok(Err(HeadError::Bad(m))) => {
            audit_local(&shared, None, local_decision(None, &format!("bad request: {m}"))).await;
            return bad_request(&mut client, &shared, slot, &m).await;
        }
        Ok(Ok(x)) => x,
    };
    let auth = match authenticate(&shared, &head) {
        Ok(a) => a,
        Err(why) => {
            let rule = format!("proxy authentication failed: {why}");
            audit_local(&shared, None, local_decision(Some(&head), &rule)).await;
            let body = "loom proxy: missing or unknown proxy credentials. Use the proxy settings from the command's environment (HTTP_PROXY / HTTPS_PROXY), which carry this session's credentials.\n";
            let challenge = "Proxy-Authenticate: Basic realm=\"loom\"\r\n";
            return answer(&mut client, &shared, slot, "407 Proxy Authentication Required", challenge, body).await;
        }
    };
    let Authed { reference, session, policy, permits, lookups } = auth;
    if reference && !matches!(head.method.as_str(), "GET" | "CONNECT" | CHECK_METHOD) {
        return reject(
            &mut client,
            &shared,
            slot,
            &session,
            &head,
            "reference credentials allow GET only; use an active scope grant for other methods",
        )
        .await;
    }
    let Ok(_session_slot) = permits.try_acquire_owned() else {
        let body = format!(
            "loom proxy: this session already has {} open proxy connections, the limit. Let running requests finish before starting more.\n",
            shared.limits.max_per_session
        );
        audit_local(&shared, Some(&session), local_decision(Some(&head), "connection limit (per session)")).await;
        return answer(&mut client, &shared, slot, "429 Too Many Requests", "Retry-After: 5\r\n", &body).await;
    };
    let connect = head.method == "CONNECT";
    if connect || head.method == CHECK_METHOD {
        // A check may name its destination as an absolute http:// URI, which HTTP clients send as is.
        let dest = match head.target.get(..7) {
            Some(s) if !connect && s.eq_ignore_ascii_case("http://") => {
                plain_target(&head.target).map(|(host, port, _, _)| (host, port))
            }
            _ => parse_authority(&head.target, None),
        };
        match dest {
            Ok((host, port)) => {
                let (shared, session, lookups) = (&*shared, &session, &lookups);
                let method = if connect { "CONNECT" } else { CHECK_METHOD };
                let cx = Ctx { shared, session, lookups, method, host: &host, port };
                if connect {
                    tunnel(client, extra, &cx, &policy, slot, cancel).await;
                } else {
                    check(&mut client, &cx, &policy, slot).await;
                }
            }
            Err(m) => reject(&mut client, &shared, slot, &session, &head, &m).await,
        }
        return;
    }
    let lower = head.target.get(..8).map(str::to_ascii_lowercase);
    if lower.as_deref() == Some("https://") {
        let why = "https:// absolute URIs are not proxied; use CONNECT host:443 for https";
        return reject(&mut client, &shared, slot, &session, &head, why).await;
    }
    if !matches!(head.target.get(..7), Some(p) if p.eq_ignore_ascii_case("http://")) {
        let why = "the request target is not an absolute http:// URI or a CONNECT destination";
        return reject(&mut client, &shared, slot, &session, &head, why).await;
    }
    match plain_target(&head.target) {
        Ok((host, port, authority, path)) => {
            let (shared, session, lookups) = (&*shared, &session, &lookups);
            let cx = Ctx { shared, session, lookups, method: &head.method, host: &host, port };
            forward(client, extra, &head, &cx, &policy, &authority, &path, reference, slot, cancel).await;
        }
        Err(m) => reject(&mut client, &shared, slot, &session, &head, &m).await,
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

async fn tunnel(
    mut client: TcpStream,
    extra: Vec<u8>,
    cx: &Ctx<'_>,
    policy: &Policy,
    slot: OwnedSemaphorePermit,
    cancel: CancellationToken,
) {
    let idle = cx.shared.limits.idle_timeout;
    let (mut up, allowed) = match open_upstream(cx, policy).await {
        Ok(s) => s,
        Err((status, body)) => return answer(&mut client, cx.shared, slot, status, "", &body).await,
    };
    let _slot = slot;
    if client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.is_err() {
        return cx.failed_after_allow(&allowed, "the client closed the connection before the tunnel was open").await;
    }
    if !extra.is_empty() && !write_within(&mut up, &extra, idle).await {
        let why = "the bytes the client sent ahead could not be written to the destination";
        return cx.failed_after_allow(&allowed, why).await;
    }
    let end = tokio::select! {
        end = relay(&mut client, &mut up, idle, None) => end,
        _ = cancel.cancelled() => return cx.failed_after_allow(&allowed, SHUTDOWN).await,
    };
    // Once bytes have come from the destination, a failure cannot be told from a routine close.
    let why = match end {
        RelayEnd::Done(false) => "the tunnel closed".to_string(),
        RelayEnd::Failed(why, false) => why.to_string(),
        RelayEnd::Idle(false, after) => format!("the tunnel was idle for {}", human(after)),
        RelayEnd::Done(true) | RelayEnd::Failed(_, true) | RelayEnd::Idle(true, _) | RelayEnd::BadUpstream(..) => {
            return
        }
    };
    cx.failed_after_allow(&allowed, &format!("{why} before the destination sent a byte")).await;
}

/// Writes all of `bytes` within `idle`; false when the peer is gone or too slow.
async fn write_within<W: AsyncWriteExt + Unpin>(w: &mut W, bytes: &[u8], idle: Duration) -> bool {
    matches!(tokio::time::timeout(idle, w.write_all(bytes)).await, Ok(Ok(())))
}

/// How the request body of a forwarded request is framed.
enum Body {
    None,
    Length(u64),
    /// Chunked: relay up to the last chunk and its trailers.
    Chunked,
    /// Another transfer coding, unframed by length: relay until the client stops sending.
    Stream,
}

fn body_kind(head: &Head) -> Result<Body, String> {
    let mut length: Option<u64> = None;
    let mut coding: Option<&[u8]> = None;
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
            coding = Some(v);
        }
    }
    match (length, coding) {
        (Some(_), Some(_)) => Err("the request has both Content-Length and Transfer-Encoding".into()),
        (Some(n), None) => Ok(Body::Length(n)),
        (None, Some(v)) if ends_chunked(v) => Ok(Body::Chunked),
        (None, Some(_)) => Ok(Body::Stream),
        (None, None) => Ok(Body::None),
    }
}

/// Whether the value of the last `Transfer-Encoding` header makes the body chunked: its last coding is
/// `chunked` (as hyper reads it).
fn ends_chunked(value: &[u8]) -> bool {
    value.rsplit(|b| *b == b',').next().is_some_and(|c| c.trim_ascii().eq_ignore_ascii_case(b"chunked"))
}

/// Whether bytes a client sent after its request are more than the empty lines some clients add after
/// a body.
fn further_request(past: &[u8]) -> bool {
    past.iter().any(|b| !matches!(b, b'\r' | b'\n'))
}

/// Follows the framing of a chunked body to find where it ends, as leniently as common HTTP clients
/// read it; the bytes themselves are passed on unchanged.
#[derive(Clone, Copy)]
enum Chunked {
    /// In a chunk-size line, before or in the size: the size so far, and whether a digit was read.
    Size(u64, bool),
    /// In a chunk-size line after the size (extensions, spaces) up to the line end: the size.
    Line(u64),
    /// In the data of a chunk: the bytes still to come.
    Data(u64),
    /// After the data of a chunk, before its line end.
    DataEnd,
    /// In the trailer section after the last chunk; whether the current line is still empty.
    Trailer(bool),
    /// The body has ended.
    Done,
}

impl Chunked {
    fn new() -> Self {
        Chunked::Size(0, false)
    }

    fn done(&self) -> bool {
        matches!(self, Chunked::Done)
    }

    /// Takes the next bytes; returns how many of them belong to the body (all of them until it ends).
    fn feed(&mut self, data: &[u8]) -> Result<usize, &'static str> {
        let mut used = 0usize;
        loop {
            let rest = data.get(used..).unwrap_or(&[]);
            let Some(&b) = rest.first() else { return Ok(used) };
            let n = match *self {
                Chunked::Done => return Ok(used),
                Chunked::Data(left) => {
                    let k = usize::try_from(left).map_or(rest.len(), |l| l.min(rest.len()));
                    let left = left.saturating_sub(k as u64);
                    *self = if left == 0 { Chunked::DataEnd } else { Chunked::Data(left) };
                    k
                }
                state => {
                    *self = state.step(b)?;
                    1
                }
            };
            used = used.saturating_add(n);
        }
    }

    /// The state after one byte outside chunk data.
    fn step(self, b: u8) -> Result<Chunked, &'static str> {
        if let (Chunked::Size(size, _), Some(d)) = (self, char::from(b).to_digit(16)) {
            let size = size.checked_mul(16).and_then(|s| s.checked_add(u64::from(d)));
            return Ok(Chunked::Size(size.ok_or("a chunk size is too large")?, true));
        }
        Ok(match (self, b) {
            (Chunked::Size(_, false), b' ' | b'\t') => self,
            (Chunked::Size(_, false), _) => return Err("a chunk does not start with its size"),
            (Chunked::Size(0, true) | Chunked::Line(0), b'\n') => Chunked::Trailer(true),
            (Chunked::Size(size, true) | Chunked::Line(size), b'\n') => Chunked::Data(size),
            (Chunked::Size(size, true) | Chunked::Line(size), _) => Chunked::Line(size),
            (Chunked::DataEnd, b'\r') => self,
            (Chunked::DataEnd, b'\n') => Chunked::new(),
            (Chunked::DataEnd, _) => return Err("the data of a chunk is not followed by a line end"),
            (Chunked::Trailer(true), b'\n') => Chunked::Done,
            (Chunked::Trailer(_), b'\n') => Chunked::Trailer(true),
            (Chunked::Trailer(empty), b'\r') => Chunked::Trailer(empty),
            (Chunked::Trailer(_), _) => Chunked::Trailer(false),
            (Chunked::Data(_) | Chunked::Done, _) => self,
        })
    }
}

/// What is still to come of the request body of a forwarded request.
enum Owed {
    /// This many bytes.
    Bytes(u64),
    /// The rest of a chunked body.
    Chunked(Chunked),
    /// Everything until the client stops sending.
    Stream,
}

impl Owed {
    /// How many of `data`, the client's next bytes, belong to the body; the rest come after it.
    fn take(&mut self, data: &[u8]) -> usize {
        match self {
            Owed::Bytes(left) => {
                let k = usize::try_from(*left).map_or(data.len(), |l| l.min(data.len()));
                *left = left.saturating_sub(k as u64);
                k
            }
            Owed::Chunked(c) => match c.feed(data) {
                Ok(k) => k,
                // A body the proxy cannot follow is passed on whole, for the destination to judge.
                Err(_) => {
                    *self = Owed::Stream;
                    data.len()
                }
            },
            Owed::Stream => data.len(),
        }
    }
}

/// Response heads from the destination, written again without any `X-Loom-Proxy` header (see
/// [`response_head`]). Interim (1xx) heads are treated the same way. The body after the final head is
/// passed on up to the end that head gives it; bytes after that end are dropped.
struct HeadFilter {
    buf: Vec<u8>,
    /// The request was `HEAD`: the response has no body whatever its headers say.
    head_request: bool,
    /// How the body after the final head is framed; `None` until that head has been read.
    body: Option<Framing>,
}

/// How the body of a response is framed.
enum Framing {
    /// Bytes still to come (none for a response without a body).
    Length(u64),
    Chunked(Chunked),
    /// Everything until the destination closes.
    UntilClose,
}

impl HeadFilter {
    fn new(head_request: bool) -> Self {
        Self { buf: Vec::new(), head_request, body: None }
    }

    /// The final head has been read.
    fn head_done(&self) -> bool {
        self.body.is_some()
    }

    /// The response is complete; nothing further from the destination is relayed.
    fn finished(&self) -> bool {
        match &self.body {
            Some(Framing::Length(left)) => *left == 0,
            Some(Framing::Chunked(c)) => c.done(),
            Some(Framing::UntilClose) | None => false,
        }
    }

    /// The final head has been read and the body runs until the destination closes.
    fn until_close(&self) -> bool {
        matches!(self.body, Some(Framing::UntilClose))
    }

    /// Takes the next bytes from the destination; returns what may be sent to the client now.
    fn push(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
        if self.body.is_some() {
            return self.pass(data);
        }
        self.buf.extend_from_slice(data);
        let mut out = Vec::new();
        while let Some(h) = response_head(&self.buf, self.head_request)? {
            out.extend_from_slice(&h.head);
            self.buf.drain(..h.len.min(self.buf.len()));
            if let Some(framing) = h.body {
                self.body = Some(framing);
                let rest = std::mem::take(&mut self.buf);
                out.append(&mut self.pass(&rest)?);
                return Ok(out);
            }
        }
        if self.buf.len() > MAX_HEAD {
            return Err(format!("the destination sent a response head larger than {} KiB", MAX_HEAD / 1024));
        }
        Ok(out)
    }

    /// The bytes of `data`, which follow the final head, that belong to the body.
    fn pass(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
        let k = match &mut self.body {
            Some(Framing::Length(left)) => {
                let k = usize::try_from(*left).map_or(data.len(), |l| l.min(data.len()));
                *left = left.saturating_sub(k as u64);
                k
            }
            Some(Framing::Chunked(c)) => {
                c.feed(data).map_err(|m| format!("the destination's chunked response is malformed ({m})"))?
            }
            Some(Framing::UntilClose) | None => data.len(),
        };
        Ok(data.get(..k).unwrap_or(&[]).to_vec())
    }
}

/// A response head read from the destination.
struct RespHead {
    /// The head written again with CRLF line ends and without `X-Loom-Proxy` headers. A final head
    /// has no `Connection`, `Keep-Alive` or `Proxy-Connection` header of the destination, no
    /// `Content-Length` when it has a `Transfer-Encoding`, and ends in `Connection: close`.
    head: Vec<u8>,
    /// Its length in the buffer it was read from.
    len: usize,
    /// For a final head, how the body after it is framed; `None` for an interim (1xx) head.
    body: Option<Framing>,
}

/// The body length that the `Content-Length` headers give, read as hyper reads them: `None` when
/// there is none, an error when a value is not a number or two differ.
fn content_length(headers: &[httparse::Header<'_>]) -> Result<Option<u64>, String> {
    let mut length = None;
    for h in headers.iter().filter(|h| h.name.eq_ignore_ascii_case("content-length")) {
        for v in h.value.split(|b| *b == b',').map(<[u8]>::trim_ascii) {
            let n = std::str::from_utf8(v).ok().filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()));
            match (n.and_then(|n| n.parse::<u64>().ok()), length) {
                (Some(n), None) => length = Some(n),
                (Some(n), Some(l)) if n == l => {}
                _ => return Err("the destination's response has an invalid or conflicting Content-Length".into()),
            }
        }
    }
    Ok(length)
}

/// The response head at the start of `buf`, parsed as an HTTP client parses it, for a request that
/// was `HEAD` or not. `None` while it is incomplete.
fn response_head(buf: &[u8], head_request: bool) -> Result<Option<RespHead>, String> {
    let mut headers = vec![httparse::EMPTY_HEADER; MAX_RESPONSE_HEADERS];
    let mut resp = httparse::Response::new(&mut headers);
    let parsed = httparse::ParserConfig::default()
        .allow_obsolete_multiline_headers_in_responses(true)
        .allow_spaces_after_header_name_in_responses(true)
        .allow_multiple_spaces_in_response_status_delimiters(true)
        .parse_response(&mut resp, buf);
    let n = match parsed {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => return Ok(None),
        Err(e) => return Err(format!("the destination did not answer with a valid HTTP response ({e})")),
    };
    let (Some(version), Some(code)) = (resp.version, resp.code) else {
        return Err("the destination did not answer with a valid HTTP response".into());
    };
    let is_final = !(100..200).contains(&code) || code == 101;
    let coding = resp.headers.iter().rev().find(|h| h.name.eq_ignore_ascii_case("transfer-encoding"));
    let body = if !is_final {
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
    let dropped = |name: &str| {
        let connection = ["connection", "keep-alive", "proxy-connection"].iter().any(|d| name.eq_ignore_ascii_case(d));
        is_final && (connection || (coding.is_some() && name.eq_ignore_ascii_case("content-length")))
    };
    let mut head = format!("HTTP/1.{version} {code} {}\r\n", resp.reason.unwrap_or("")).into_bytes();
    for h in resp.headers.iter().filter(|h| !h.name.eq_ignore_ascii_case(MARKER) && !dropped(h.name)) {
        head.extend_from_slice(h.name.as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(h.value);
        head.extend_from_slice(b"\r\n");
    }
    if is_final {
        head.extend_from_slice(b"Connection: close\r\n");
    }
    head.extend_from_slice(b"\r\n");
    Ok(Some(RespHead { head, len: n, body }))
}

/// What the relay of a forwarded request needs.
struct Fwd {
    /// What the client still owes of the request body.
    owed: Owed,
    /// The client sent more than its request together with it (see [`further_request`]).
    further: bool,
    /// After the client has ended its side, how long a silent destination is waited for.
    grace: Duration,
    /// The request method is `HEAD`.
    head_request: bool,
}

/// How a relay ended. The flag says whether anything from the destination had been sent to the client.
enum RelayEnd {
    /// Both sides are done (a forwarded request: the response ended).
    Done(bool),
    /// A peer failed, or the client sent too much: why.
    Failed(&'static str, bool),
    /// No byte moved for the period given; whether anything had been sent to the client.
    Idle(bool, Duration),
    /// The destination's response was unusable; whether anything had been sent to the client.
    BadUpstream(String, bool),
}

/// What the two directions of a relay share.
struct Flow {
    start: tokio::time::Instant,
    /// When a byte last moved in either direction, in milliseconds after `start`.
    last_ms: AtomicU64,
    /// The client of a forwarded request has ended its side.
    client_done: AtomicBool,
    /// The client of a forwarded request sent more than its request (see [`further_request`]).
    extra_request: AtomicBool,
    /// The head of a forwarded response whose body runs until the destination closes has been relayed.
    until_close: AtomicBool,
    /// Something has been sent to the client.
    wrote: AtomicBool,
}

impl Flow {
    /// Notes that the client sent more than its request; true when the response runs until the
    /// destination closes and its head has been relayed, so the relay ends now. The two sides note
    /// their part and read the other's in the opposite order, so at least one of them sees both.
    fn client_sent_more(&self) -> bool {
        self.extra_request.store(true, Ordering::SeqCst);
        self.until_close.load(Ordering::SeqCst)
    }

    /// Notes that the head of a response that runs until the destination closes has been relayed; true
    /// when the client has sent more than its request, so the relay ends now.
    fn response_until_close(&self) -> bool {
        self.until_close.store(true, Ordering::SeqCst);
        self.extra_request.load(Ordering::SeqCst)
    }

    fn touch(&self) {
        let ms = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_ms.fetch_max(ms, Ordering::Relaxed);
    }

    fn last(&self) -> tokio::time::Instant {
        let ms = Duration::from_millis(self.last_ms.load(Ordering::Relaxed));
        self.start.checked_add(ms).unwrap_or(self.start)
    }
}

/// How one direction of a relay ended.
enum Pump {
    /// Its source ended cleanly.
    Ended,
    /// The relay must stop: a peer failed, or the client sent too much; why.
    Stop(&'static str),
    /// The destination's response was unusable.
    Bad(String),
    /// The client of a forwarded request sent more than its request while the response runs until the
    /// destination closes: nothing more is relayed.
    Cut,
}

/// Writes all of `bytes`, counting each partial write as activity.
async fn write_counted(w: &mut WriteHalf<'_>, mut bytes: &[u8], flow: &Flow) -> std::io::Result<()> {
    while !bytes.is_empty() {
        let n = w.write(bytes).await?;
        if n == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        flow.touch();
        bytes = bytes.get(n..).unwrap_or(&[]);
    }
    Ok(())
}

/// Client to destination. A tunnel passes the client's end on. With `forward` (what the client of a
/// forwarded request still owes of its body) bytes past the body are discarded and noted in `flow`,
/// the client's end is noted in `flow`, and a destination that stops reading does not end the relay.
async fn upload(r: &mut ReadHalf<'_>, w: &mut WriteHalf<'_>, flow: &Flow, mut forward: Option<Owed>) -> Pump {
    let mut buf = vec![0u8; 16 * 1024];
    let mut sending = true;
    let mut discarded = 0usize;
    loop {
        let n = match r.read(&mut buf).await {
            Ok(n) => n,
            Err(_) => return Pump::Stop("the client's connection failed"),
        };
        flow.touch();
        if n == 0 {
            if forward.is_some() {
                flow.client_done.store(true, Ordering::Relaxed);
            } else {
                let _ = w.shutdown().await;
            }
            return Pump::Ended;
        }
        let data = buf.get(..n).unwrap_or(&[]);
        let body = forward.as_mut().map_or(n, |owed| owed.take(data));
        let more = further_request(data.get(body..).unwrap_or(&[]));
        let take = if sending { body } else { 0 };
        discarded = discarded.saturating_add(n.saturating_sub(take));
        if discarded > MAX_DISCARD {
            return Pump::Stop("the client sent more than 1 MiB past the request body");
        }
        if take > 0 && write_counted(w, data.get(..take).unwrap_or(&[]), flow).await.is_err() {
            if forward.is_none() {
                return Pump::Stop("writing to the destination failed");
            }
            // The destination stopped reading; its answer may still come.
            sending = false;
        }
        // A further request on a connection that carries one: no later destination bytes may be read as
        // its answer.
        if more && flow.client_sent_more() {
            return Pump::Cut;
        }
    }
}

/// Destination to client. A tunnel passes the destination's end on. With `filter` (a forwarded
/// request) the response head is filtered, an end before the head is complete is `Bad`, and the
/// relay ends at the end of the response, or after its head when the response runs until the
/// destination closes and the client has sent more than its request.
async fn download(r: &mut ReadHalf<'_>, w: &mut WriteHalf<'_>, flow: &Flow, mut filter: Option<HeadFilter>) -> Pump {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let read = r.read(&mut buf).await;
        let head_pending = filter.as_ref().is_some_and(|f| !f.head_done());
        let n = match read {
            Ok(0) | Err(_) if head_pending => {
                return Pump::Bad("the destination closed the connection before it answered".to_string())
            }
            Ok(0) => {
                let _ = w.shutdown().await;
                return Pump::Ended;
            }
            Ok(n) => n,
            Err(_) => return Pump::Stop("the connection to the destination failed"),
        };
        flow.touch();
        let chunk = buf.get(..n).unwrap_or(&[]);
        let out = match filter.as_mut() {
            Some(f) => match f.push(chunk) {
                Ok(v) => Cow::Owned(v),
                Err(m) => return Pump::Bad(m),
            },
            None => Cow::Borrowed(chunk),
        };
        if !out.is_empty() {
            flow.wrote.store(true, Ordering::Relaxed);
            if write_counted(w, &out, flow).await.is_err() {
                return Pump::Stop("writing to the client failed");
            }
        }
        // One request, one response: what follows its end is not relayed.
        let over = filter.as_ref().is_some_and(|f| f.finished() || (f.until_close() && flow.response_until_close()));
        if over {
            let _ = w.shutdown().await;
            return Pump::Ended;
        }
    }
}

/// Ends when no byte has moved for `idle`, or for `grace` once the client of a forwarded request has
/// ended its side; returns the period that passed.
async fn watchdog(flow: &Flow, idle: Duration, grace: Option<Duration>) -> Duration {
    let step = grace.unwrap_or(idle);
    loop {
        let limit = match grace {
            Some(g) if flow.client_done.load(Ordering::Relaxed) => g,
            _ => idle,
        };
        let now = tokio::time::Instant::now();
        let deadline = flow.last().checked_add(limit).unwrap_or(now);
        if now >= deadline {
            return limit;
        }
        let wake = now.checked_add(step).map_or(deadline, |w| w.min(deadline));
        tokio::time::sleep_until(wake).await;
    }
}

/// Copies bytes both ways, each direction on its own, until both sides are done or no byte has moved
/// in either direction for `idle`. A failing peer ends both.
///
/// With `forward` (a forwarded plain request) the destination's response head is filtered, bytes of
/// the client past the body are discarded, and the relay ends when the response ends (see
/// *Forwarded requests*); after the client has ended its side it also ends when the destination is
/// silent for the grace period.
async fn relay(client: &mut TcpStream, up: &mut TcpStream, idle: Duration, forward: Option<Fwd>) -> RelayEnd {
    let (mut cr, mut cw) = client.split();
    let (mut ur, mut uw) = up.split();
    let flow = Flow {
        start: tokio::time::Instant::now(),
        last_ms: AtomicU64::new(0),
        client_done: AtomicBool::new(false),
        extra_request: AtomicBool::new(forward.as_ref().is_some_and(|f| f.further)),
        until_close: AtomicBool::new(false),
        wrote: AtomicBool::new(false),
    };
    let is_forward = forward.is_some();
    let (owed, filter, grace) = match forward {
        Some(f) => (Some(f.owed), Some(HeadFilter::new(f.head_request)), Some(f.grace.min(idle))),
        None => (None, None, None),
    };
    let to_up = upload(&mut cr, &mut uw, &flow, owed);
    let to_client = download(&mut ur, &mut cw, &flow, filter);
    let quiet = watchdog(&flow, idle, grace);
    tokio::pin!(to_up, to_client, quiet);
    let wrote = || flow.wrote.load(Ordering::Relaxed);
    let (mut up_open, mut down_open) = (true, true);
    while up_open || down_open {
        tokio::select! {
            r = &mut to_up, if up_open => match r {
                Pump::Ended => up_open = false,
                Pump::Stop(why) => return RelayEnd::Failed(why, wrote()),
                Pump::Bad(_) | Pump::Cut => return RelayEnd::Done(wrote()),
            },
            r = &mut to_client, if down_open => match r {
                Pump::Ended | Pump::Cut if is_forward => return RelayEnd::Done(wrote()),
                Pump::Ended | Pump::Cut => down_open = false,
                Pump::Stop(why) => return RelayEnd::Failed(why, wrote()),
                Pump::Bad(why) => return RelayEnd::BadUpstream(why, wrote()),
            },
            after = &mut quiet => return RelayEnd::Idle(wrote(), after),
        }
    }
    RelayEnd::Done(wrote())
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
    reference: bool,
    slot: OwnedSemaphorePermit,
    cancel: CancellationToken,
) {
    let idle = cx.shared.limits.idle_timeout;
    let body = match body_kind(head) {
        Ok(b) => b,
        Err(m) => return reject(&mut client, cx.shared, slot, cx.session, head, &m).await,
    };
    let (mut up, allowed) = match open_upstream(cx, policy).await {
        Ok(s) => s,
        Err((status, text)) => return answer(&mut client, cx.shared, slot, status, "", &text).await,
    };

    let mut out: Vec<u8> = format!("{} {} HTTP/1.1\r\nHost: {}\r\n", head.method, path, authority).into_bytes();
    for (n, v) in &head.headers {
        let drop = ["proxy-authorization", "proxy-connection", "connection", "keep-alive", "upgrade", "host"]
            .iter()
            .any(|d| n.eq_ignore_ascii_case(d));
        let secret = reference && ["authorization", "cookie", "referer"].iter().any(|x| n.eq_ignore_ascii_case(x));
        if drop || secret {
            continue;
        }
        out.extend_from_slice(n.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    // The bytes of the body that arrived with the head, what the client still owes, and what it sent
    // after its request.
    let mut owed = match body {
        Body::None => Owed::Bytes(0),
        Body::Length(n) => Owed::Bytes(n),
        Body::Chunked => Owed::Chunked(Chunked::new()),
        Body::Stream => Owed::Stream,
    };
    let (already, past) = extra.split_at(owed.take(&extra).min(extra.len()));
    out.extend_from_slice(already);
    if !write_within(&mut up, &out, idle).await {
        let why = "sending the request to the destination failed";
        cx.failed_after_allow(&allowed, why).await;
        let (status, text) = cx.unreachable(why);
        return answer(&mut client, cx.shared, slot, status, "", &text).await;
    }

    let fwd = Fwd {
        owed,
        further: further_request(past),
        grace: cx.shared.limits.forward_grace,
        head_request: head.method.eq_ignore_ascii_case("HEAD"),
    };
    let end = tokio::select! {
        r = relay(&mut client, &mut up, idle, Some(fwd)) => r,
        _ = cancel.cancelled() => return cx.failed_after_allow(&allowed, SHUTDOWN).await,
    };
    let (why, reply) = match end {
        RelayEnd::Done(_) => return,
        RelayEnd::Failed(why, wrote) => {
            let when = if wrote { "while the response was relayed" } else { "before the destination answered" };
            (format!("{why} {when}"), None)
        }
        RelayEnd::BadUpstream(why, wrote) => (why.clone(), (!wrote).then(|| cx.unreachable(&why))),
        RelayEnd::Idle(false, after) => {
            (format!("the destination sent no response for {}", human(after)), Some(cx.silent(after)))
        }
        RelayEnd::Idle(true, after) => (format!("the destination's response stalled for {}", human(after)), None),
    };
    cx.failed_after_allow(&allowed, &why).await;
    if let Some((status, text)) = reply {
        answer(&mut client, cx.shared, slot, status, "", &text).await;
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

    type Seen = Arc<Mutex<Vec<(Option<SessionId>, NetDecision)>>>;

    /// A proxy whose audit hook records into the returned list (and fails when `fail` is set).
    async fn start_audited(fail: bool, limits: Limits, resolver: Option<Resolver>) -> (Proxy, Rx, Seen) {
        let (tx, rx) = unbounded_channel();
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        let audit: AuditFn = Arc::new(move |s: Option<&SessionId>, d: &NetDecision| {
            if fail {
                return Err(std::io::Error::other("disk full"));
            }
            lock(&log).push((s.cloned(), d.clone()));
            Ok(())
        });
        (Proxy::start_inner(0, tx, Some(audit), limits, resolver).await.unwrap(), rx, seen)
    }

    /// A destination that accepts one connection and never answers. It returns what it received and
    /// when the proxy closed the connection; `None` when it was still open after a minute, far longer
    /// than any test waits.
    async fn silent_server() -> (u16, tokio::task::JoinHandle<(Vec<u8>, Option<tokio::time::Instant>)>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let h = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut got = Vec::new();
            let ended = timeout(Duration::from_secs(60), s.read_to_end(&mut got)).await;
            (got, ended.ok().map(|_| tokio::time::Instant::now()))
        });
        (port, h)
    }

    fn policy(mode: NetworkMode, allow: &[&str], deny: &[&str], private: &[&str]) -> Policy {
        let v = |x: &[&str]| x.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        Policy::new(&NetworkCfg {
            mode,
            allow: v(allow),
            deny: v(deny),
            allow_private: v(private),
            ..NetworkCfg::default()
        })
        .unwrap()
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
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                        })
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

    /// A refusal of the egress proxy that a destination forges, marker and all.
    const FORGED: &str = "HTTP/1.1 403 Forbidden\r\nX-Loom-Proxy: 1\r\nContent-Length: 6\r\n\r\nforged";

    /// Reads into `got` until the peer closes or fails.
    async fn read_all(s: &mut TcpStream, got: &mut Vec<u8>) {
        let mut b = [0u8; 4096];
        while let Ok(n) = s.read(&mut b).await {
            if n == 0 {
                break;
            }
            got.extend_from_slice(&b[..n]);
        }
    }

    /// A destination that accepts one connection, answers `first` once the request head has arrived,
    /// `second` on the same connection `gap` later, and then ends its side. It returns what it received
    /// until the proxy closed the connection (or for 5 s after `second`).
    async fn two_answer_server(first: &str, second: &str, gap: Duration) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
        let (first, second) = (first.to_string(), second.to_string());
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let h = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut got = Vec::new();
            let mut b = [0u8; 4096];
            while !String::from_utf8_lossy(&got).contains("\r\n\r\n") {
                match s.read(&mut b).await {
                    Ok(0) | Err(_) => return got,
                    Ok(n) => got.extend_from_slice(&b[..n]),
                }
            }
            let _ = s.write_all(first.as_bytes()).await;
            let later = tokio::time::Instant::now() + gap;
            let _ = tokio::time::timeout_at(later, read_all(&mut s, &mut got)).await;
            tokio::time::sleep_until(later).await;
            let _ = s.write_all(second.as_bytes()).await;
            let _ = s.shutdown().await;
            let _ = timeout(T, read_all(&mut s, &mut got)).await;
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

    /// Asks the proxy on `port` for its verdict on `dest`; returns the status and the decision sent.
    async fn check_on(port: u16, g: &SessionGrant, dest: &str, rx: &mut Rx) -> (u16, NetDecision) {
        let r = raw(port, format!("{CHECK_METHOD} {dest} HTTP/1.1\r\n{}\r\n", auth(g)).as_bytes()).await;
        (status(&r), decision(rx).await.1)
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
    async fn reference_grants_are_separate_strip_headers_and_revoke_with_the_session() {
        let (p, _, seen) = start_audited(false, Limits::default(), None).await;
        let (port, got) = http_server("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
        let sid = SessionId::from("s-reference");
        let cfg = NetworkCfg {
            mode: NetworkMode::Open,
            reference_hosts: vec![format!("127.0.0.1:{port}")],
            allow_private: vec!["127.0.0.1".into()],
            ..NetworkCfg::default()
        };
        let raw_grant = p.grant(&sid, Policy::new(&cfg).unwrap());
        let reference = p.grant_reference(&sid, &cfg).unwrap();
        assert_ne!(reference.url(), raw_grant.url());
        assert!(reference.matches_host("127.0.0.1", port));
        assert!(!raw_grant.env().values().any(|value| value == &reference.url()));
        let url = format!("http://127.0.0.1:{port}/reference?q=public");
        let denied = raw(p.port(), format!("GET {url} HTTP/1.1\r\n{}\r\n", auth(&raw_grant)).as_bytes()).await;
        assert_eq!(status(&denied), 403);
        assert!(!lock(&seen).last().unwrap().1.allowed);
        let post = raw(
            p.port(),
            format!("POST {url} HTTP/1.1\r\n{}Content-Length: 0\r\n\r\n", auth(&reference.grant)).as_bytes(),
        )
        .await;
        assert_eq!(status(&post), 400);
        assert!(!lock(&seen).last().unwrap().1.allowed);
        let response = raw(
            p.port(),
            format!(
                "GET {url} HTTP/1.1\r\n{}Authorization: secret\r\nCookie: secret\r\nReferer: secret\r\n\r\n",
                auth(&reference.grant)
            )
            .as_bytes(),
        )
        .await;
        assert_eq!(status(&response), 200);
        let (who, decision) = lock(&seen).last().unwrap().clone();
        assert_eq!(who, Some(sid.clone()));
        assert!(decision.allowed);
        let request = String::from_utf8(got.await.unwrap()).unwrap().to_lowercase();
        assert!(!request.contains("authorization:") && !request.contains("cookie:") && !request.contains("referer:"));
        p.revoke(&sid);
        let revoked = raw(p.port(), format!("GET {url} HTTP/1.1\r\n{}\r\n", auth(&reference.grant)).as_bytes()).await;
        assert_eq!(status(&revoked), 407);
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
        let req = format!("POST http://127.0.0.1:{port} HTTP/1.1\r\n{}Content-Length: 11\r\n\r\nhello world", auth(&g));
        let resp = raw(p.port(), req.as_bytes()).await;
        assert_eq!(status(&resp), 201, "{resp}");
        let got = String::from_utf8(server.await.unwrap()).unwrap();
        assert!(got.starts_with("POST / HTTP/1.1\r\n"), "{got}");
        assert!(got.ends_with("\r\n\r\nhello world"), "{got}");
    }

    #[tokio::test]
    async fn a_chunked_request_body_is_forwarded_to_its_last_chunk_and_no_further() {
        let (p, _rx) = start().await;
        let g = p.grant(&SessionId::from("s-chunked-post"), lab());
        let (port, server) = two_answer_server("HTTP/1.0 200 OK\r\n\r\nfirst", FORGED, Duration::from_secs(2)).await;
        let mut s = TcpStream::connect(("127.0.0.1", p.port())).await.unwrap();
        let head = format!("POST http://127.0.0.1:{port}/ HTTP/1.1\r\n{}Transfer-Encoding: chunked\r\n\r\n", auth(&g));
        s.write_all(format!("{head}4\r\nbo").as_bytes()).await.unwrap();
        let begun = read_until(&mut s, "first").await;
        // The rest of the body, then a further request in the same write.
        let more = format!("dy\r\n0\r\n\r\nGET http://127.0.0.1:{port}/ HTTP/1.1\r\n{}\r\n", auth(&g));
        s.write_all(more.as_bytes()).await.unwrap();
        let started = tokio::time::Instant::now();
        let mut rest = Vec::new();
        let _ = timeout(T, s.read_to_end(&mut rest)).await;
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the proxy waited for the destination: {:?}",
            started.elapsed()
        );
        assert!(begun.ends_with("\r\n\r\nfirst") && rest.is_empty(), "{begun:?} {:?}", String::from_utf8_lossy(&rest));
        let got = String::from_utf8(server.await.unwrap()).unwrap();
        assert!(got.ends_with("\r\n\r\n4\r\nbody\r\n0\r\n\r\n") && !got.contains("GET "), "{got}");
    }

    #[tokio::test]
    async fn failing_audit_refuses_the_connection_and_nothing_reaches_the_upstream() {
        let (p, mut rx, seen) = start_audited(true, Limits::default(), None).await;
        let (port, server) = silent_server().await;
        let g = p.grant(&SessionId::from("s-af"), lab());
        let req = format!("GET http://127.0.0.1:{port}/x HTTP/1.1\r\n{}\r\n", auth(&g));
        let resp = raw(p.port(), req.as_bytes()).await;
        assert_eq!(status(&resp), 502, "{resp}");
        assert!(
            resp.contains("X-Loom-Proxy: 1\r\n") && resp.contains("egress audit log could not be written"),
            "{resp}"
        );
        let (got, closed) = server.await.unwrap();
        assert!(got.is_empty() && closed.is_some(), "the upstream must not receive bytes: {got:?}");
        assert!(lock(&seen).is_empty());
        let (_, d) = decision(&mut rx).await;
        assert!(!d.allowed && d.rule.contains("audit log not written"), "{d:?}");
        // CONNECT is refused before the 200 as well.
        let (port, server) = silent_server().await;
        let r = raw(p.port(), connect_req(&g, &format!("127.0.0.1:{port}")).as_bytes()).await;
        assert_eq!(status(&r), 502, "{r}");
        assert!(server.await.unwrap().0.is_empty());
    }

    #[tokio::test]
    async fn audit_is_written_before_the_upstream_sees_the_request() {
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (tx, _rx) = unbounded_channel();
        let f2 = flag.clone();
        let audit: AuditFn = Arc::new(move |_: Option<&SessionId>, d: &NetDecision| {
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
        let limits = Limits { head_timeout: Duration::from_millis(300), ..Limits::default() };
        let (p, mut rx, seen) = start_audited(false, limits, None).await;
        let sid = SessionId::from("s-aud");
        let g = p.grant(&sid, lab());
        // Requests of a session: under that session, with the destination when the target names one.
        let r = raw(p.port(), format!("GET https://example.test/ HTTP/1.1\r\n{}\r\n", auth(&g)).as_bytes()).await;
        assert_eq!(status(&r), 400);
        let r = raw(p.port(), connect_req(&g, "nohostport").as_bytes()).await;
        assert_eq!(status(&r), 400);
        // Requests that name no granted session: under no session, whatever user they claim.
        let none = raw(p.port(), b"CONNECT 127.0.0.1:9 HTTP/1.1\r\n\r\n").await;
        assert_eq!(status(&none), 407);
        let unknown = SessionGrant { user: "s-nobody".into(), ..g.clone() };
        assert_eq!(status(&raw(p.port(), connect_req(&unknown, "127.0.0.1:9").as_bytes()).await), 407);
        let wrong = SessionGrant { password: "0".repeat(32), ..g.clone() };
        assert_eq!(status(&raw(p.port(), connect_req(&wrong, "127.0.0.1:9").as_bytes()).await), 407);
        assert_eq!(status(&raw(p.port(), b"garbage\r\n\r\n").await), 400);
        let mut slow = TcpStream::connect(("127.0.0.1", p.port())).await.unwrap();
        slow.write_all(b"CONNECT 127.0.0.1:9 HT").await.unwrap();
        let mut out = Vec::new();
        timeout(T, slow.read_to_end(&mut out)).await.unwrap().unwrap();
        assert_eq!(status(&String::from_utf8_lossy(&out)), 400);
        let check = format!("{CHECK_METHOD} 127.0.0.1:9 HTTP/1.1\r\n\r\n");
        assert_eq!(status(&raw(p.port(), check.as_bytes()).await), 407);
        let seen = lock(&seen).clone();
        assert_eq!(seen.len(), 8, "{seen:?}");
        assert!(seen.iter().all(|(_, d)| !d.allowed));
        let rule = |i: usize| seen[i].1.rule.as_str();
        assert_eq!(row(&seen[0]), (Some("s-aud"), "GET", "example.test", 443));
        assert!(rule(0).starts_with("bad request: https://"), "{seen:?}");
        assert_eq!(row(&seen[1]), (Some("s-aud"), "CONNECT", "-", 0));
        assert_eq!(row(&seen[2]), (None, "CONNECT", "127.0.0.1", 9));
        assert_eq!(rule(2), "proxy authentication failed: no credentials");
        assert_eq!(row(&seen[3]), (None, "CONNECT", "127.0.0.1", 9));
        assert_eq!(rule(3), "proxy authentication failed: unknown user");
        assert_eq!(row(&seen[4]), (None, "CONNECT", "127.0.0.1", 9));
        assert_eq!(rule(4), "proxy authentication failed: wrong password for session s-aud");
        assert_eq!(row(&seen[5]), (None, "-", "-", 0));
        assert!(rule(5).starts_with("bad request: the request head could not be parsed"), "{seen:?}");
        assert_eq!(row(&seen[6]), (None, "-", "-", 0));
        assert_eq!(rule(6), "bad request: no complete request head arrived within 300 ms");
        // A check names its destination as `host:port`, like a CONNECT.
        assert_eq!(row(&seen[7]), (None, CHECK_METHOD, "127.0.0.1", 9));
        // None of these reached the policy, so the sink gets none of them.
        no_more(&mut rx);
    }

    fn row(e: &(Option<SessionId>, NetDecision)) -> (Option<&str>, &str, &str, u16) {
        (e.0.as_ref().map(SessionId::as_str), e.1.method.as_str(), e.1.host.as_str(), e.1.port)
    }

    #[tokio::test]
    async fn unattributed_records_are_capped_and_count_what_they_left_out() {
        let (p, _rx, seen) = start_audited(false, Limits::default(), None).await;
        for _ in 0..13 {
            assert_eq!(status(&raw(p.port(), b"garbage\r\n\r\n").await), 400);
        }
        assert_eq!(lock(&seen).len(), 10);
        // A minute later the next one is recorded, with the number left out before it.
        let earlier = std::time::Instant::now().checked_sub(Duration::from_secs(61)).unwrap();
        lock(&p.inner.shared.unattributed).since = earlier;
        assert_eq!(status(&raw(p.port(), b"garbage\r\n\r\n").await), 400);
        let last = lock(&seen).last().unwrap().1.rule.clone();
        assert_eq!(lock(&seen).len(), 11);
        assert!(last.ends_with("(3 similar answers before this one were not recorded)"), "{last}");
        // Long texts from the request are cut, and the cut is marked.
        let g = p.grant(&SessionId::from("s-cut"), lab());
        let r = raw(p.port(), format!("CONNECT {}!:1 HTTP/1.1\r\n{}\r\n", "b".repeat(500), auth(&g)).as_bytes()).await;
        assert_eq!(status(&r), 400);
        let r = raw(p.port(), format!("CONNECT {}:1 HTTP/1.1\r\n\r\n", "a".repeat(500)).as_bytes()).await;
        assert_eq!(status(&r), 407);
        let all = lock(&seen).clone();
        let (_, bad) = all.iter().find(|(s, _)| s.as_ref().is_some_and(|s| s.as_str() == "s-cut")).unwrap();
        assert!(bad.rule.chars().count() == 301 && bad.rule.ends_with('…'), "{}", bad.rule);
        let (who, failed) = all.last().unwrap();
        assert!(who.is_none() && failed.host.chars().count() == 256 && failed.host.ends_with('…'), "{}", failed.host);
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
    async fn ipv6_forms_that_carry_a_private_ipv4_address_are_refused_by_name_and_as_literals() {
        // NAT64 (both prefixes) and 6to4 forms of each address, each reachable through a name of its own.
        let carried = |v4: &str| {
            let n = u32::from(v4.parse::<std::net::Ipv4Addr>().unwrap());
            [format!("64:ff9b::{v4}"), format!("64:ff9b:1::{v4}"), format!("2002:{:x}:{:x}::1", n >> 16, n & 0xffff)]
        };
        let teredo = "2001:0:4136:e378:8000:63bf:3fff:fdd2";
        let mut table: Vec<(String, String)> = vec![("teredo.test".into(), teredo.into())];
        for v4 in ["10.0.0.5", "127.0.0.1", "169.254.169.254", "8.8.8.8"] {
            for (i, a) in carried(v4).into_iter().enumerate() {
                table.push((format!("f{i}-{v4}.test"), a));
            }
        }
        let names = table.clone();
        let resolver: Resolver = Arc::new(move |name: &str| {
            names.iter().filter(|(n, _)| n == name).map(|(_, a)| a.parse().unwrap()).collect()
        });
        let (tx, mut rx) = unbounded_channel();
        let p = Proxy::start_inner(0, tx, None, Limits::default(), Some(resolver)).await.unwrap();
        let open = p.grant(&SessionId::from("s-c-open"), policy(NetworkMode::Open, &[], &[], &[]));
        let al = p.grant(&SessionId::from("s-c-al"), policy(NetworkMode::Allowlist, &["*"], &[], &[]));
        let listed = p.grant(&SessionId::from("s-c-ls"), policy(NetworkMode::Open, &[], &[], &["10.0.0.5", "8.8.8.8"]));
        let deny = ["10.0.0.5", "8.8.8.0/24"];
        let denied = p.grant(&SessionId::from("s-c-dn"), policy(NetworkMode::Open, &[], &deny, &["10.0.0.0/8"]));
        for (name, addr) in &table {
            let v4 = name.split_once('-').map_or("", |(_, rest)| rest.trim_end_matches(".test"));
            let shown = addr.parse::<IpAddr>().unwrap().to_string();
            for dest in [format!("{name}:443"), format!("[{addr}]:443")] {
                for g in [&open, &al] {
                    let (code, d) = check_on(p.port(), g, &dest, &mut rx).await;
                    if v4 == "8.8.8.8" {
                        assert_eq!(code, 200, "{dest}: {d:?}");
                    } else {
                        assert_eq!(
                            (code, d.rule),
                            (403, format!("deny private-address {shown} (check only)")),
                            "{dest}"
                        );
                        assert_eq!(d.resolved.as_deref(), Some(shown.as_str()), "{dest}");
                    }
                }
                let (code, d) = check_on(p.port(), &listed, &dest, &mut rx).await;
                assert_eq!(code == 200, matches!(v4, "10.0.0.5" | "8.8.8.8"), "{dest}: {d:?}");
                if v4 == "10.0.0.5" {
                    assert_eq!(d.rule, "allow_private 10.0.0.5 (check only)", "{dest}");
                }
                let (code, d) = check_on(p.port(), &denied, &dest, &mut rx).await;
                match v4 {
                    "10.0.0.5" => assert_eq!((code, d.rule.as_str()), (403, "deny 10.0.0.5 (check only)"), "{dest}"),
                    "8.8.8.8" => assert_eq!((code, d.rule.as_str()), (403, "deny 8.8.8.0/24 (check only)"), "{dest}"),
                    _ => assert_eq!(code, 403, "{dest}: {d:?}"),
                }
            }
        }
        // A real connection through a name to such an address is refused before connecting.
        let r = raw(p.port(), connect_req(&open, "f2-127.0.0.1.test:443").as_bytes()).await;
        assert_eq!(status(&r), 403, "{r}");
        assert_eq!(decision(&mut rx).await.1.rule, "deny private-address 2002:7f00:1::1");
        no_more(&mut rx);
    }

    #[tokio::test]
    async fn name_lookups_are_bounded_per_session_and_in_all() {
        use std::sync::atomic::AtomicUsize;
        let calls = Arc::new(AtomicUsize::new(0));
        let open = Arc::new(AtomicBool::new(false));
        let (c, o) = (calls.clone(), open.clone());
        let resolver: Resolver = Arc::new(move |_: &str| {
            c.fetch_add(1, Ordering::SeqCst);
            while !o.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(10));
            }
            vec!["10.9.9.9".parse().unwrap()]
        });
        let limits = Limits { max_lookups: 3, max_lookups_per_session: 2, ..Limits::default() };
        let (tx, _rx) = unbounded_channel();
        let p = Proxy::start_inner(0, tx, None, limits, Some(resolver)).await.unwrap();
        let ga = p.grant(&SessionId::from("s-la"), policy(NetworkMode::Open, &[], &[], &[]));
        let gb = p.grant(&SessionId::from("s-lb"), policy(NetworkMode::Open, &[], &[], &[]));
        let ask = |g: &SessionGrant| {
            let (port, req) = (p.port(), connect_req(g, "slow.test:80"));
            tokio::spawn(async move { status(&raw(port, req.as_bytes()).await) })
        };
        let settled = |n: usize| {
            let calls = calls.clone();
            async move {
                let deadline = tokio::time::Instant::now() + T;
                while calls.load(Ordering::SeqCst) < n {
                    assert!(tokio::time::Instant::now() < deadline, "only {calls:?} lookups started");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                tokio::time::sleep(Duration::from_millis(300)).await;
                calls.load(Ordering::SeqCst)
            }
        };
        // One session gets two lookups at once; its third waits.
        let mut asked: Vec<_> = (0..3).map(|_| ask(&ga)).collect();
        assert_eq!(settled(2).await, 2);
        // Another session still gets a turn, which fills the proxy's three.
        asked.push(ask(&gb));
        assert_eq!(settled(3).await, 3);
        asked.push(ask(&gb));
        assert_eq!(settled(3).await, 3);
        open.store(true, Ordering::SeqCst);
        for a in asked {
            assert_eq!(timeout(T, a).await.unwrap().unwrap(), 403);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 5);
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
    async fn a_check_answers_the_verdict_and_the_rule_without_connecting() {
        let resolver: Resolver = Arc::new(|name: &str| match name {
            "lab.test" => vec!["127.0.0.1".parse().unwrap()],
            _ => Vec::new(),
        });
        let (tx, mut rx) = unbounded_channel();
        let p = Proxy::start_inner(0, tx, None, Limits::default(), Some(resolver)).await.unwrap();
        let sid = SessionId::from("s-check");
        let g = p.grant(&sid, policy(NetworkMode::Open, &[], &["blocked.test"], &["127.0.0.1"]));
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let ask = |target: String| format!("{CHECK_METHOD} {target} HTTP/1.1\r\n{}\r\n", auth(&g));
        let rule = |r: &str| r.lines().find_map(|l| l.strip_prefix("X-Loom-Rule: ")).map(str::to_string);
        // Allowed, as host:port and as the absolute URI an HTTP client sends; nothing connects.
        for target in [format!("lab.test:{port}"), format!("http://lab.test:{port}/")] {
            let r = raw(p.port(), ask(target).as_bytes()).await;
            assert_eq!(status(&r), 200, "{r}");
            assert!(r.contains("X-Loom-Proxy: 1\r\n"), "{r}");
            assert_eq!(rule(&r).as_deref(), Some("allow_private 127.0.0.1"), "{r}");
            let (who, d) = decision(&mut rx).await;
            assert_eq!((who, d.method.as_str(), d.allowed), (sid.clone(), CHECK_METHOD, true));
            assert_eq!(
                (d.rule.as_str(), d.resolved.as_deref()),
                ("allow_private 127.0.0.1 (check only)", Some("127.0.0.1"))
            );
        }
        assert!(timeout(Duration::from_millis(200), l.accept()).await.is_err(), "a check connected to the destination");
        // Refused, with the refusal text and the rule.
        let r = raw(p.port(), ask("blocked.test:443".into()).as_bytes()).await;
        assert_eq!(status(&r), 403, "{r}");
        assert_eq!(rule(&r).as_deref(), Some("deny blocked.test"), "{r}");
        assert!(r.contains("refused by rule `deny blocked.test`"), "{r}");
        assert_eq!(decision(&mut rx).await.1.rule, "deny blocked.test (check only)");
        // A name that does not resolve.
        let r = raw(p.port(), ask("nowhere.test:443".into()).as_bytes()).await;
        assert_eq!(status(&r), 502, "{r}");
        let (_, d) = decision(&mut rx).await;
        assert!(
            d.allowed && d.rule.starts_with("mode open (unreachable: ") && d.rule.ends_with("(check only)"),
            "{d:?}"
        );
        // A check needs the session's credentials like any request.
        let r = raw(p.port(), format!("{CHECK_METHOD} blocked.test:443 HTTP/1.1\r\n\r\n").as_bytes()).await;
        assert_eq!(status(&r), 407, "{r}");
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
    async fn a_failure_after_an_allow_is_recorded_after_it_in_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("net.jsonl");
        let (writer, file) = (Arc::new(crate::netlog::NetLogWriter::new()), path.clone());
        // A destination that resets each connection it accepts once the proxy, connected to it, is
        // recording its allow: a reset any earlier could fail the proxy's connect instead.
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let (reset, mut resets) = unbounded_channel::<()>();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                let _ = resets.recv().await;
                s.set_zero_linger().unwrap();
            }
        });
        // Allows announce themselves and are slow to record, so that what a peer does meanwhile has
        // happened when the proxy goes on.
        let (allowing, mut allows) = unbounded_channel::<String>();
        let audit: AuditFn = Arc::new(move |_: Option<&SessionId>, d: &NetDecision| {
            if d.allowed && !d.rule.contains("(failed after the allow: ") {
                let _ = allowing.send(d.method.clone());
                if d.port == port {
                    let _ = reset.send(());
                }
                std::thread::sleep(Duration::from_millis(300));
            }
            writer.append(&file, d)
        });
        let (tx, _rx) = unbounded_channel();
        let p = Proxy::start_inner(0, tx, Some(audit), Limits::default(), None).await.unwrap();
        let g = p.grant(&SessionId::from("s-after"), lab());
        let lines = |n: usize| {
            let path = path.clone();
            async move {
                let deadline = tokio::time::Instant::now() + T;
                loop {
                    let text = std::fs::read_to_string(&path).unwrap_or_default();
                    if text.lines().count() >= n {
                        return text;
                    }
                    assert!(tokio::time::Instant::now() < deadline, "not recorded: {text}");
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
        };
        // A forwarded request: the destination is gone before the request head can be written to it.
        let r = raw(p.port(), format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\n{}\r\n", auth(&g)).as_bytes()).await;
        assert_eq!(status(&r), 502, "{r}");
        assert_eq!(timeout(T, allows.recv()).await.unwrap().as_deref(), Some("GET"));
        // A tunnel whose client resets while its allow is being recorded, before the proxy can answer.
        let echo = echo_server().await;
        let mut s = TcpStream::connect(("127.0.0.1", p.port())).await.unwrap();
        s.write_all(connect_req(&g, &format!("127.0.0.1:{echo}")).as_bytes()).await.unwrap();
        assert_eq!(timeout(T, allows.recv()).await.unwrap().as_deref(), Some("CONNECT"));
        s.set_zero_linger().unwrap();
        drop(s);
        lines(4).await;
        // A tunnel whose destination resets before it sends a byte, while the client stays.
        let mut s = TcpStream::connect(("127.0.0.1", p.port())).await.unwrap();
        s.write_all(connect_req(&g, &format!("127.0.0.1:{port}")).as_bytes()).await.unwrap();
        assert_eq!(status(&read_until(&mut s, "\r\n\r\n").await), 200);
        let mut rest = Vec::new();
        let _ = timeout(T, s.read_to_end(&mut rest)).await.unwrap();
        assert!(rest.is_empty(), "{rest:?}");
        lines(6).await;
        // A tunnel both sides close before the destination sent a byte.
        let mut s = TcpStream::connect(("127.0.0.1", p.port())).await.unwrap();
        s.write_all(connect_req(&g, &format!("127.0.0.1:{echo}")).as_bytes()).await.unwrap();
        assert_eq!(status(&read_until(&mut s, "\r\n\r\n").await), 200);
        s.shutdown().await.unwrap();
        let _ = timeout(T, s.read_to_end(&mut rest)).await.unwrap();
        let text = lines(8).await;
        assert_eq!(crate::netlog::verify(&text), Ok(()));
        let rows: Vec<NetDecision> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        let rules: Vec<(&str, bool, &str)> =
            rows.iter().map(|d| (d.method.as_str(), d.allowed, d.rule.as_str())).collect();
        assert_eq!(rules.len(), 8, "{rules:?}");
        let failures = [
            ("GET", "sending the request to the destination failed"),
            ("CONNECT", "the client closed the connection before the tunnel was open"),
            ("CONNECT", "the connection to the destination failed before the destination sent a byte"),
            ("CONNECT", "the tunnel closed before the destination sent a byte"),
        ];
        for (i, (method, why)) in failures.into_iter().enumerate() {
            assert_eq!(rules[2 * i], (method, true, "allow_private 127.0.0.1"), "{rules:?}");
            let failed = format!("allow_private 127.0.0.1 (failed after the allow: {why})");
            assert_eq!(rules[2 * i + 1], (method, true, failed.as_str()), "{rules:?}");
            assert_eq!(rows[2 * i + 1].resolved.as_deref(), Some("127.0.0.1"));
        }
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
        // Globally: with every slot held by a connection that has sent its head, the next one gets 503,
        // recorded under no session.
        let limits = Limits { max_connections: 2, ..Limits::default() };
        let (p, _rx, seen) = start_audited(false, limits, None).await;
        let g = p.grant(&SessionId::from("s-cg"), lab());
        let (_a, st) = tunnel(&p, &g).await;
        assert_eq!(st, 200);
        let (_b, st) = tunnel(&p, &g).await;
        assert_eq!(st, 200);
        let r = raw(p.port(), connect_req(&g, &dest).as_bytes()).await;
        assert_eq!(status(&r), 503, "{r}");
        assert!(r.contains("X-Loom-Proxy: 1\r\n") && r.contains("limit 2") && r.contains("Retry-After: 5\r\n"), "{r}");
        let last = lock(&seen).last().cloned().unwrap();
        assert_eq!((last.0, last.1.rule.as_str()), (None, "connection limit (all sessions)"));
    }

    #[tokio::test]
    async fn at_the_limit_a_new_connection_takes_the_slot_of_the_oldest_silent_one() {
        let echo = echo_server().await;
        let limits = Limits { max_connections: 2, ..Limits::default() };
        let (p, _rx, _seen) = start_audited(false, limits, None).await;
        let g = p.grant(&SessionId::from("s-ev"), lab());
        // Two connections that never send a head hold both slots.
        let mut oldest = TcpStream::connect(("127.0.0.1", p.port())).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut newer = TcpStream::connect(("127.0.0.1", p.port())).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        // A real request still gets through, and the oldest silent connection is closed for it.
        let mut s = TcpStream::connect(("127.0.0.1", p.port())).await.unwrap();
        s.write_all(connect_req(&g, &format!("127.0.0.1:{echo}")).as_bytes()).await.unwrap();
        assert_eq!(status(&read_until(&mut s, "\r\n\r\n").await), 200);
        let mut out = Vec::new();
        timeout(T, oldest.read_to_end(&mut out)).await.expect("the oldest silent connection was kept").unwrap();
        assert!(out.is_empty());
        let mut b = [0u8; 1];
        assert!(timeout(Duration::from_millis(200), newer.read(&mut b)).await.is_err(), "the newer one was closed too");
    }

    #[tokio::test]
    async fn connections_the_proxy_has_answered_itself_do_not_hold_their_slot() {
        let echo = echo_server().await;
        let limits = Limits { max_connections: 2, ..Limits::default() };
        let (p, _rx, _seen) = start_audited(false, limits, None).await;
        let g = p.grant(&SessionId::from("s-drain"), lab());
        // Each client reads its answer (407, 400, 403) and keeps the connection open, so the proxy is
        // left waiting for it to close.
        let mut held = Vec::new();
        let requests = [
            "CONNECT 127.0.0.1:9 HTTP/1.1\r\n\r\n".to_string(),
            "garbage\r\n\r\n".to_string(),
            connect_req(&g, "127.0.0.1:1"),
            connect_req(
                &p.grant(&SessionId::from("s-drain-2"), policy(NetworkMode::DenyAll, &[], &[], &[])),
                "x.test:1",
            ),
        ];
        for req in requests.iter().cycle().take(12) {
            let mut s = TcpStream::connect(("127.0.0.1", p.port())).await.unwrap();
            s.write_all(req.as_bytes()).await.unwrap();
            let head = read_until(&mut s, "\r\n\r\n").await;
            assert!(matches!(status(&head), 400 | 403 | 407 | 502), "{head}");
            held.push(s);
        }
        let mut s = TcpStream::connect(("127.0.0.1", p.port())).await.unwrap();
        s.write_all(connect_req(&g, &format!("127.0.0.1:{echo}")).as_bytes()).await.unwrap();
        assert_eq!(status(&read_until(&mut s, "\r\n\r\n").await), 200);
    }

    #[tokio::test]
    async fn eviction_closes_the_oldest_draining_connection_before_any_still_sending_a_head() {
        let (p, _rx) = start().await;
        let shared = &p.inner.shared;
        let permit = || shared.connections.clone().try_acquire_owned().unwrap();
        let (_, waiting) = shared.add_pending(permit());
        let (_, older) = shared.add_draining(permit());
        let (_, newer) = shared.add_draining(permit());
        let (_, later) = shared.add_pending(permit());
        let order = [&older, &newer, &waiting, &later];
        for (i, closed) in order.iter().enumerate() {
            assert!(shared.evict_pending().is_some());
            assert!(closed.is_cancelled(), "{i}");
            assert!(order.iter().skip(i + 1).all(|t| !t.is_cancelled()), "{i}");
        }
        assert!(shared.evict_pending().is_none());
    }

    #[tokio::test]
    async fn at_the_limit_a_new_connection_takes_the_slot_of_a_drained_one_before_a_silent_one() {
        let echo = echo_server().await;
        let limits = Limits { max_connections: 3, ..Limits::default() };
        let (p, _rx, _seen) = start_audited(false, limits, None).await;
        let g = p.grant(&SessionId::from("s-order"), lab());
        let shared = p.inner.shared.clone();
        // The ids of the connections being drained, or of those still sending a head, oldest first.
        let queued = move |draining: bool| -> Vec<u64> {
            let p = lock(&shared.pending);
            let queue = if draining { &p.draining } else { &p.heads };
            queue.iter().map(|(id, _, _)| *id).collect()
        };
        async fn until(what: &str, done: impl Fn() -> bool) {
            let deadline = tokio::time::Instant::now() + T;
            while !done() {
                assert!(tokio::time::Instant::now() < deadline, "{what}");
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        // The oldest connection has not sent its head.
        let mut silent = TcpStream::connect(("127.0.0.1", p.port())).await.unwrap();
        until("the silent connection was never accepted", || queued(false).len() == 1).await;
        // Two newer ones are answered 407 and stay open, so the proxy drains them.
        let mut answered = Vec::new();
        let mut drained: Vec<u64> = Vec::new();
        for _ in 0..2 {
            let mut s = TcpStream::connect(("127.0.0.1", p.port())).await.unwrap();
            s.write_all(b"CONNECT 127.0.0.1:9 HTTP/1.1\r\n\r\n").await.unwrap();
            assert_eq!(status(&read_until(&mut s, "\r\n\r\n").await), 407);
            let new = || queued(true).into_iter().filter(|id| !drained.contains(id)).collect::<Vec<u64>>();
            until("the answered connection was never drained", || !new().is_empty()).await;
            let new = new();
            drained.extend(new);
            answered.push(s);
        }
        // Every slot is taken; a new connection gets the one of the older drained connection. A drain
        // lasts 500 ms, so that one may also have ended by itself; either way it is gone.
        let mut s = TcpStream::connect(("127.0.0.1", p.port())).await.unwrap();
        s.write_all(connect_req(&g, &format!("127.0.0.1:{echo}")).as_bytes()).await.unwrap();
        assert_eq!(status(&read_until(&mut s, "\r\n\r\n").await), 200);
        assert!(!queued(true).contains(&drained[0]), "the newer drained connection was closed first: {drained:?}");
        let mut b = [0u8; 1];
        assert!(
            timeout(Duration::from_millis(200), silent.read(&mut b)).await.is_err(),
            "the silent connection was closed"
        );
    }

    #[tokio::test]
    async fn idle_tunnels_and_idle_forwards_are_closed() {
        let idle = Duration::from_secs(1);
        let limits = Limits { idle_timeout: idle, ..Limits::default() };
        let (p, _rx, seen) = start_audited(false, limits, None).await;
        let g = p.grant(&SessionId::from("s-idle"), lab());
        // A tunnel to a peer that never speaks (and would hold its side open for a minute).
        let (port, server) = silent_server().await;
        let mut s = TcpStream::connect(("127.0.0.1", p.port())).await.unwrap();
        s.write_all(connect_req(&g, &format!("127.0.0.1:{port}")).as_bytes()).await.unwrap();
        assert_eq!(status(&read_until(&mut s, "\r\n\r\n").await), 200);
        let started = tokio::time::Instant::now();
        let mut rest = Vec::new();
        let n = timeout(T, s.read_to_end(&mut rest)).await.expect("the idle tunnel was not closed").unwrap();
        let waited = started.elapsed();
        assert_eq!(n, 0);
        assert!(waited >= idle - Duration::from_millis(100) && waited < Duration::from_secs(3), "{waited:?}");
        let (_, closed) = timeout(T, server).await.unwrap().unwrap();
        assert!(closed.is_some_and(|at| at.duration_since(started) < Duration::from_secs(3)));
        // Nothing came from the destination, so the allow is followed by a record that says so.
        let rules: Vec<String> = lock(&seen).iter().map(|(_, d)| d.rule.clone()).collect();
        let idled = "(failed after the allow: the tunnel was idle for 1 second before the destination sent a byte)";
        assert_eq!(rules, ["allow_private 127.0.0.1".to_string(), format!("allow_private 127.0.0.1 {idled}")]);
        // A forwarded request whose upstream never answers gets a 504 that says so.
        let (port, server) = silent_server().await;
        let req = format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\n{}\r\n", auth(&g));
        let started = tokio::time::Instant::now();
        let resp = raw(p.port(), req.as_bytes()).await;
        let waited = started.elapsed();
        assert_eq!(status(&resp), 504, "{resp}");
        assert!(resp.contains("X-Loom-Proxy: 1\r\n") && resp.contains("sent no response for 1 second"), "{resp}");
        assert!(waited >= idle - Duration::from_millis(100) && waited < Duration::from_secs(3), "{waited:?}");
        assert!(timeout(T, server).await.unwrap().unwrap().1.is_some());
        // Traffic keeps a tunnel alive past the idle period.
        let echo = echo_server().await;
        let mut s = TcpStream::connect(("127.0.0.1", p.port())).await.unwrap();
        s.write_all(connect_req(&g, &format!("127.0.0.1:{echo}")).as_bytes()).await.unwrap();
        assert_eq!(status(&read_until(&mut s, "\r\n\r\n").await), 200);
        for _ in 0..8 {
            tokio::time::sleep(Duration::from_millis(200)).await;
            s.write_all(b"x").await.unwrap();
            let mut b = [0u8; 1];
            timeout(T, s.read_exact(&mut b)).await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn forward_ends_when_the_client_goes_away() {
        let limits = Limits { forward_grace: Duration::from_millis(300), ..Limits::default() };
        let (p, _rx, _seen) = start_audited(false, limits, None).await;
        let g = p.grant(&SessionId::from("s-gone"), lab());
        let (port, server) = silent_server().await;
        let req = format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\n{}\r\n", auth(&g));
        let mut s = TcpStream::connect(("127.0.0.1", p.port())).await.unwrap();
        s.write_all(req.as_bytes()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let gone = tokio::time::Instant::now();
        drop(s);
        // The upstream sees the request and then its connection closing, long before the 10-minute idle
        // timeout and long before the helper would give up on its own.
        let (got, closed) = timeout(T, server).await.expect("the upstream connection stayed open").unwrap();
        assert!(String::from_utf8_lossy(&got).starts_with("GET / HTTP/1.1\r\n"));
        let closed = closed.expect("the upstream connection stayed open");
        assert!(closed.duration_since(gone) < Duration::from_secs(2), "{:?}", closed.duration_since(gone));
    }

    #[tokio::test]
    async fn forward_still_answers_a_client_that_half_closes() {
        let (p, _rx) = start().await;
        let g = p.grant(&SessionId::from("s-half"), lab());
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut got = Vec::new();
            let mut b = [0u8; 1024];
            while !String::from_utf8_lossy(&got).contains("\r\n\r\n") {
                let n = s.read(&mut b).await.unwrap();
                assert!(n > 0, "the request was cut off");
                got.extend_from_slice(&b[..n]);
            }
            // Answer only after the client has ended its side.
            tokio::time::sleep(Duration::from_millis(300)).await;
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await.unwrap();
            let _ = s.shutdown().await;
        });
        let mut s = TcpStream::connect(("127.0.0.1", p.port())).await.unwrap();
        s.write_all(format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\n{}\r\n", auth(&g)).as_bytes()).await.unwrap();
        s.shutdown().await.unwrap();
        let mut out = Vec::new();
        timeout(T, s.read_to_end(&mut out)).await.unwrap().unwrap();
        let resp = String::from_utf8_lossy(&out).to_string();
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n") && resp.ends_with("\r\n\r\nok"), "{resp}");
    }

    #[tokio::test]
    async fn tunnel_relays_both_directions_at_once() {
        // Each side writes everything before it reads anything back: both directions must move at once.
        const N: usize = 32 * 1024 * 1024;
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            let (mut r, mut w) = s.into_split();
            let writer = tokio::spawn(async move {
                w.write_all(&vec![b'd'; N]).await.unwrap();
                w.shutdown().await.unwrap();
            });
            let mut got = Vec::new();
            r.read_to_end(&mut got).await.unwrap();
            writer.await.unwrap();
            got.len()
        });
        let (p, _rx) = start().await;
        let g = p.grant(&SessionId::from("s-duplex"), lab());
        let mut s = TcpStream::connect(("127.0.0.1", p.port())).await.unwrap();
        s.write_all(connect_req(&g, &format!("127.0.0.1:{port}")).as_bytes()).await.unwrap();
        assert_eq!(status(&read_until(&mut s, "\r\n\r\n").await), 200);
        let both = async {
            s.write_all(&vec![b'u'; N]).await.unwrap();
            s.shutdown().await.unwrap();
            let mut back = Vec::new();
            s.read_to_end(&mut back).await.unwrap();
            back
        };
        let back = timeout(Duration::from_secs(30), both).await.expect("the tunnel stalled");
        assert!(back.len() == N && back.iter().all(|b| *b == b'd'));
        assert_eq!(timeout(T, server).await.unwrap().unwrap(), N);
    }

    /// A response as an HTTP client sees it: status, headers (names lower-cased), body.
    fn client_view(resp: &str) -> (u16, Vec<(String, String)>, String) {
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut r = httparse::Response::new(&mut headers);
        let n = match r.parse(resp.as_bytes()) {
            Ok(httparse::Status::Complete(n)) => n,
            other => panic!("the client cannot read {resp:?}: {other:?}"),
        };
        let headers = r
            .headers
            .iter()
            .map(|h| (h.name.to_ascii_lowercase(), String::from_utf8_lossy(h.value).to_string()))
            .collect();
        (r.code.unwrap(), headers, resp[n..].to_string())
    }

    #[tokio::test]
    async fn upstream_proxy_marker_is_not_relayed() {
        let (p, _rx) = start().await;
        let g = p.grant(&SessionId::from("s-mark"), lab());
        let (port, _server) =
            http_server("HTTP/1.1 403 Forbidden\r\nx-loom-proxy: 1\r\nX-Other: kept\r\nContent-Length: 4\r\n\r\nnope")
                .await;
        let req = format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\n{}\r\n", auth(&g));
        let resp = raw(p.port(), req.as_bytes()).await;
        assert_eq!(status(&resp), 403, "{resp}");
        assert!(!resp.to_ascii_lowercase().contains("loom-proxy"), "{resp}");
        assert!(resp.contains("X-Other: kept\r\n") && resp.ends_with("\r\n\r\nnope"), "{resp}");
        // Heads with bare LF line ends: the proxy reads them as a client does, so the marker cannot hide.
        let cases: [(&'static str, u16, &str); 3] = [
            ("HTTP/1.1 403 Forbidden\r\nX-A: b\nX-Loom-Proxy: 1\r\nContent-Length: 4\r\n\r\nnope", 403, "nope"),
            ("HTTP/1.1 403 Forbidden\nX-Loom-Proxy: 1\nContent-Length: 8\n\nab\r\n\r\ncd", 403, "ab\r\n\r\ncd"),
            ("HTTP/1.0 200 OK\n\nhi", 200, "hi"),
        ];
        for (reply, code, body) in cases {
            let (port, _server) = http_server(reply).await;
            let req = format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\n{}\r\n", auth(&g));
            let resp = raw(p.port(), req.as_bytes()).await;
            let (got_code, headers, got_body) = client_view(&resp);
            assert_eq!((got_code, got_body.as_str()), (code, body), "{reply:?} -> {resp:?}");
            assert!(!headers.iter().any(|(n, _)| n == "x-loom-proxy"), "{reply:?} -> {resp:?}");
        }
        // A destination that does not speak HTTP gets a proxy-generated 502, which does carry the marker.
        let (port, _server) = http_server("not http at all\r\n\r\n").await;
        let req = format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\n{}\r\n", auth(&g));
        let resp = raw(p.port(), req.as_bytes()).await;
        assert_eq!(status(&resp), 502, "{resp}");
        assert!(resp.contains("X-Loom-Proxy: 1\r\n"));
    }

    #[tokio::test]
    async fn a_forwarded_response_says_connection_close_and_ends_the_connection() {
        let (p, _rx) = start().await;
        let g = p.grant(&SessionId::from("s-close"), lab());
        let first = "HTTP/1.1 302 Found\r\nLocation: /b\r\nConnection: keep-alive\r\nKeep-Alive: timeout=5\r\n\
                     Proxy-Connection: keep-alive\r\nContent-Length: 0\r\n\r\n";
        let (port, _server) = two_answer_server(first, FORGED, Duration::from_secs(2)).await;
        let mut s = TcpStream::connect(("127.0.0.1", p.port())).await.unwrap();
        s.write_all(format!("GET http://127.0.0.1:{port}/a HTTP/1.1\r\n{}\r\n", auth(&g)).as_bytes()).await.unwrap();
        let head = read_until(&mut s, "\r\n\r\n").await;
        let started = tokio::time::Instant::now();
        // A client that ignores the head sends the next hop on the same connection.
        let _ = s.write_all(format!("GET http://127.0.0.1:{port}/b HTTP/1.1\r\n{}\r\n", auth(&g)).as_bytes()).await;
        let mut rest = Vec::new();
        let _ = timeout(T, s.read_to_end(&mut rest)).await;
        assert!(head.starts_with("HTTP/1.1 302 Found\r\nLocation: /b\r\n"), "{head}");
        assert_eq!(head.matches("Connection: close\r\n").count(), 1, "{head}");
        let lower = head.to_ascii_lowercase();
        assert!(!lower.contains("keep-alive") && !lower.contains("proxy-connection"), "{head}");
        assert!(rest.is_empty(), "{:?}", String::from_utf8_lossy(&rest));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the proxy waited for the destination: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn chunked_bodies_are_followed_to_their_end_across_any_split() {
        let bodies = [
            "0\r\n\r\n",
            "2\r\nok\r\n0\r\n\r\n",
            "A;name=value\r\n0123456789\r\n0\r\nX-Trailer: t\r\nY: u\r\n\r\n",
            " 3 \nabc\n0\n\n",
            "00002\r\nok\r\r\n0\r\n\r\n",
        ];
        for body in bodies {
            let all = format!("{body}{FORGED}");
            for split in 0..=all.len() {
                let (a, b) = all.as_bytes().split_at(split);
                let mut c = Chunked::new();
                let used = c.feed(a).unwrap() + c.feed(b).unwrap();
                assert_eq!(used, body.len(), "{body:?} split at {split}");
                assert!(c.done(), "{body:?} split at {split}");
            }
        }
        let mut c = Chunked::new();
        assert_eq!(c.feed(b"5\r\nab"), Ok(5));
        assert!(!c.done());
        for bad in ["x\r\n", "\r\n", "2\r\nokX", "1FFFFFFFFFFFFFFFF\r\n"] {
            assert!(Chunked::new().feed(bad.as_bytes()).is_err(), "{bad:?}");
        }
        // A request body the proxy cannot follow is passed on whole.
        let mut owed = Owed::Chunked(Chunked::new());
        assert_eq!(owed.take(b"zz\r\nmore"), 8);
        assert!(matches!(owed, Owed::Stream));
    }

    #[tokio::test]
    async fn a_chunked_response_ends_after_its_last_chunk_and_trailers() {
        let (p, _rx) = start().await;
        let g = p.grant(&SessionId::from("s-chunked"), lab());
        let body = "2\r\nok\r\n3;note=x\r\nabc\r\n0\r\nX-Trailer: t\r\n\r\n";
        // The forged answer comes in the same segment as the last chunk, or later on the same connection.
        let together =
            format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n{body}{FORGED}");
        let apart = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n{body}");
        for (first, second) in [(together.as_str(), ""), (apart.as_str(), FORGED)] {
            for pipelined in [false, true] {
                let (port, _server) = two_answer_server(first, second, Duration::from_secs(2)).await;
                let one = format!("GET http://127.0.0.1:{port}/a HTTP/1.1\r\n{}\r\n", auth(&g));
                let req = if pipelined { one.repeat(2) } else { one };
                let started = tokio::time::Instant::now();
                let resp = raw(p.port(), req.as_bytes()).await;
                assert!(started.elapsed() < Duration::from_secs(1), "{first:?}: {:?}", started.elapsed());
                let (code, headers, got) = client_view(&resp);
                assert_eq!((code, got.as_str()), (200, body), "{resp:?}");
                // A length beside the transfer coding is dropped, so no client reads the body by it.
                assert!(!headers.iter().any(|(n, _)| n == "content-length"), "{resp:?}");
                assert_eq!(headers.last().map(|(n, v)| (n.as_str(), v.as_str())), Some(("connection", "close")));
            }
        }
    }

    #[tokio::test]
    async fn a_response_ends_at_its_head_or_after_its_length() {
        let (p, _rx) = start().await;
        let g = p.grant(&SessionId::from("s-length"), lab());
        let cases: [(&str, &str, u16, &str); 5] = [
            // No body for HEAD, 204 and 304, whatever the length says.
            ("HEAD", "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n", 200, ""),
            ("GET", "HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\nhello", 204, ""),
            ("GET", "HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\n\r\nhello", 304, ""),
            // Bytes past the length are not relayed; repeated equal values are one length.
            ("GET", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokay", 200, "ok"),
            ("GET", "HTTP/1.1 200 OK\r\nContent-Length: 2, 2\r\n\r\nokay", 200, "ok"),
        ];
        for (method, first, code, body) in cases {
            let (port, _server) = two_answer_server(first, FORGED, Duration::from_secs(2)).await;
            let req = format!("{method} http://127.0.0.1:{port}/ HTTP/1.1\r\n{}\r\n", auth(&g));
            let started = tokio::time::Instant::now();
            let resp = raw(p.port(), req.as_bytes()).await;
            assert!(started.elapsed() < Duration::from_secs(1), "{first:?}: {:?}", started.elapsed());
            let (got_code, _, got_body) = client_view(&resp);
            assert_eq!((got_code, got_body.as_str()), (code, body), "{first:?} -> {resp:?}");
        }
        // A length that clients would read differently gets a 502 from the proxy.
        let unclear = [
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nokay",
            "HTTP/1.1 200 OK\r\nContent-Length: +2\r\n\r\nok",
        ];
        for first in unclear {
            let (port, _server) = two_answer_server(first, "", Duration::from_secs(2)).await;
            let req = format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\n{}\r\n", auth(&g));
            let resp = raw(p.port(), req.as_bytes()).await;
            assert_eq!(status(&resp), 502, "{first:?} -> {resp:?}");
            assert!(
                resp.contains("X-Loom-Proxy: 1\r\n") && resp.contains("invalid or conflicting Content-Length"),
                "{resp}"
            );
        }
    }

    #[tokio::test]
    async fn a_client_that_sends_more_than_its_request_cuts_a_response_that_runs_until_close() {
        let (p, _rx) = start().await;
        let g = p.grant(&SessionId::from("s-more"), lab());
        let gap = Duration::from_secs(2);
        let get = |port: u16| format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\n{}\r\n", auth(&g));
        // Two requests in one write: only the first is forwarded, and its answer ends the connection.
        let (port, server) = two_answer_server("HTTP/1.0 200 OK\r\n\r\nfirst", FORGED, gap).await;
        let started = tokio::time::Instant::now();
        let resp = raw(p.port(), get(port).repeat(2).as_bytes()).await;
        assert!(started.elapsed() < Duration::from_secs(1), "{:?}", started.elapsed());
        assert_eq!(client_view(&resp).2, "first", "{resp:?}");
        let got = String::from_utf8(server.await.unwrap()).unwrap();
        assert_eq!(got.matches("GET ").count(), 1, "{got}");
        // The end of a body and a further request in one read, while the destination is silent.
        let (port, server) = two_answer_server("HTTP/1.0 200 OK\r\n\r\nfirst", FORGED, gap).await;
        let mut s = TcpStream::connect(("127.0.0.1", p.port())).await.unwrap();
        let post = format!("POST http://127.0.0.1:{port}/ HTTP/1.1\r\n{}Content-Length: 4\r\n\r\nbo", auth(&g));
        s.write_all(post.as_bytes()).await.unwrap();
        let begun = read_until(&mut s, "first").await;
        let started = tokio::time::Instant::now();
        s.write_all(format!("dy{}", get(port)).as_bytes()).await.unwrap();
        let mut rest = Vec::new();
        let _ = timeout(T, s.read_to_end(&mut rest)).await;
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the proxy waited for the destination: {:?}",
            started.elapsed()
        );
        assert!(begun.ends_with("\r\n\r\nfirst") && rest.is_empty(), "{begun:?} {:?}", String::from_utf8_lossy(&rest));
        let got = String::from_utf8(server.await.unwrap()).unwrap();
        assert!(got.ends_with("\r\n\r\nbody") && !got.contains("GET "), "{got}");
        // Empty lines after a body are not a further request.
        let (port, _server) = two_answer_server("HTTP/1.0 200 OK\r\n\r\none", "two", Duration::from_millis(300)).await;
        let req = format!("POST http://127.0.0.1:{port}/ HTTP/1.1\r\n{}Content-Length: 4\r\n\r\nbody\r\n", auth(&g));
        assert_eq!(client_view(&raw(p.port(), req.as_bytes()).await).2, "onetwo");
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
    async fn shutdown_during_a_tunnel_or_forward_is_recorded_after_the_allow() {
        let (p, _rx, seen) = start_audited(false, Limits::default(), None).await;
        let g = p.grant(&SessionId::from("s-down"), lab());
        let (port, _server) = silent_server().await;
        let mut s = TcpStream::connect(("127.0.0.1", p.port())).await.unwrap();
        s.write_all(connect_req(&g, &format!("127.0.0.1:{port}")).as_bytes()).await.unwrap();
        assert_eq!(status(&read_until(&mut s, "\r\n\r\n").await), 200);
        let (port2, _server2) = silent_server().await;
        let mut f = TcpStream::connect(("127.0.0.1", p.port())).await.unwrap();
        f.write_all(format!("GET http://127.0.0.1:{port2}/ HTTP/1.1\r\n{}\r\n", auth(&g)).as_bytes()).await.unwrap();
        // The methods of the allowed requests recorded with `rule`, sorted.
        let methods = |rule: &str| -> Vec<String> {
            let seen = lock(&seen);
            let mut m: Vec<String> =
                seen.iter().filter(|(_, d)| d.allowed && d.rule == rule).map(|(_, d)| d.method.clone()).collect();
            m.sort();
            m
        };
        // Both are on record as allowed before the proxy shuts down; from there nothing is checked before
        // the relay, which sees the shutdown even when it starts after it.
        let deadline = tokio::time::Instant::now() + T;
        while methods("allow_private 127.0.0.1") != ["CONNECT", "GET"] {
            assert!(tokio::time::Instant::now() < deadline, "{:?}", lock(&seen));
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // `stop` returns once the connections have ended, their records written.
        timeout(T, p.stop(T)).await.unwrap();
        let shut = "allow_private 127.0.0.1 (failed after the allow: the egress proxy shut down)";
        assert_eq!(methods(shut), ["CONNECT", "GET"], "{:?}", lock(&seen));
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
