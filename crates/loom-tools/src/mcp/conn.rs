//! The two transports of an MCP connection (CONTRACTS-MCP M2, M3): newline-delimited JSON-RPC over the
//! stdio of a sandboxed child, and Streamable HTTP. Both answer [`Transport::rpc`] with the result of the
//! request with a given id, handle the server's own requests and notifications, and never log a header or
//! environment value.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, MutexGuard};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{ChildStderr, ChildStdin, ChildStdout};
use tokio::sync::{oneshot, Mutex};

use super::{McpServer, PROTOCOL_VERSIONS};
use crate::ToolCtx;

/// Lines of a server's stderr kept.
pub(super) const STDERR_RING: usize = 200;
/// Longest stderr line kept, in characters.
const STDERR_LINE_CHARS: usize = 2000;

pub(super) fn lock<T>(m: &StdMutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Why a request has no result.
#[derive(Debug)]
pub(super) enum Fail {
    /// The server answered with a JSON-RPC error.
    Rpc { code: i64, message: String, data: Option<Value> },
    /// The request did not reach the server.
    NotSent(String),
    /// The connection failed or ended before the answer.
    Lost(String),
    /// HTTP only: the server forgot the session (404 with a session id).
    Expired,
}

/// State shared by the two halves of a connection and kept across reconnects of one handle.
#[derive(Default)]
pub(super) struct Shared {
    next_id: AtomicU64,
    pub list_changed: AtomicBool,
    ring: StdMutex<VecDeque<String>>,
    dropped: AtomicU64,
    /// HTTP messages of the current call, taken by the tool after it (CONTRACTS-TRAFFIC-TARGETS C3).
    traffic: StdMutex<Vec<Raw>>,
}

/// One POST of the HTTP transport, before it is stored as an exchange.
pub(super) struct Raw {
    pub url: String,
    pub request: Vec<u8>,
    pub response: Option<Vec<u8>>,
    pub status: Option<u16>,
    pub error: Option<String>,
    pub started: std::time::Instant,
}

const TRAFFIC_BUFFER: usize = 64;

impl Shared {
    fn push_traffic(&self, raw: Raw) {
        let mut t = lock(&self.traffic);
        if t.len() < TRAFFIC_BUFFER {
            t.push(raw);
        }
    }

    pub fn take_traffic(&self) -> Vec<Raw> {
        std::mem::take(&mut *lock(&self.traffic))
    }

    pub fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn push_line(&self, line: &[u8]) {
        let text = String::from_utf8_lossy(line);
        let text = text.trim_end_matches(['\r', '\n']);
        let shown: String = text.chars().take(STDERR_LINE_CHARS).collect();
        let mut ring = lock(&self.ring);
        if ring.len() >= STDERR_RING {
            ring.pop_front();
        }
        ring.push_back(shown);
    }

    /// The last `n` stderr lines.
    pub fn tail(&self, n: usize) -> Vec<String> {
        let ring = lock(&self.ring);
        ring.iter().skip(ring.len().saturating_sub(n)).cloned().collect()
    }

    fn note_dropped(&self) {
        if self.dropped.fetch_add(1, Ordering::Relaxed) == 0 {
            self.push_line(b"[loom] a line on the server's stdout was not JSON and was dropped");
        }
    }
}

/// What the server told us in `initialize`.
#[derive(Clone, Debug, Default)]
pub(super) struct ServerInfo {
    pub protocol: String,
    pub name: String,
    pub version: String,
}

fn request_json(id: u64, method: &str, params: &Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

fn notification_json(method: &str, params: &Value) -> Value {
    if params.is_null() {
        json!({"jsonrpc": "2.0", "method": method})
    } else {
        json!({"jsonrpc": "2.0", "method": method, "params": params})
    }
}

/// The answer to a server-to-client request: `ping` is `{}`, anything else is method not found.
fn reply_to(id: &Value, method: &str) -> Value {
    if method == "ping" {
        json!({"jsonrpc": "2.0", "id": id, "result": {}})
    } else {
        json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "method not found"}})
    }
}

/// What one message from the server is.
enum Incoming {
    Response(Option<u64>, Result<Value, Fail>),
    Request(Value, String),
    Notification(String),
    Other,
}

fn classify(msg: &Value) -> Incoming {
    let Some(obj) = msg.as_object() else { return Incoming::Other };
    if let Some(method) = obj.get("method").and_then(Value::as_str) {
        return match obj.get("id") {
            Some(id) if !id.is_null() => Incoming::Request(id.clone(), method.to_string()),
            _ => Incoming::Notification(method.to_string()),
        };
    }
    let Some(id) = obj.get("id") else { return Incoming::Other };
    let id = id.as_u64().or_else(|| id.as_str().and_then(|s| s.parse().ok()));
    if let Some(err) = obj.get("error") {
        let code = err.get("code").and_then(Value::as_i64).unwrap_or(-32603);
        let message = err.get("message").and_then(Value::as_str).unwrap_or("(no message)").to_string();
        let data = err.get("data").cloned();
        return Incoming::Response(id, Err(Fail::Rpc { code, message, data }));
    }
    match obj.get("result") {
        Some(r) => Incoming::Response(id, Ok(r.clone())),
        None => Incoming::Other,
    }
}

#[async_trait::async_trait]
pub(super) trait Transport: Send + Sync {
    /// Send a request and wait for the answer with this id. Dropping the future abandons the request.
    async fn rpc(&self, id: u64, method: &str, params: Value) -> Result<Value, Fail>;
    async fn notify(&self, method: &str, params: Value);
    /// Tell the transport the negotiated version (HTTP sends it as a header).
    fn set_protocol(&self, version: &str);
}

/// `initialize` and `notifications/initialized` (M2).
pub(super) async fn initialize<T: Transport + ?Sized>(t: &T, shared: &Shared) -> Result<ServerInfo, String> {
    let params = json!({
        "protocolVersion": PROTOCOL_VERSIONS[0],
        "capabilities": {},
        "clientInfo": {"name": "loom", "version": env!("CARGO_PKG_VERSION")},
    });
    let result = match t.rpc(shared.next_id(), "initialize", params).await {
        Ok(r) => r,
        Err(Fail::Rpc { code, message, .. }) => {
            return Err(format!("the server refused to initialize (error {code}): {message}"));
        }
        Err(Fail::NotSent(m) | Fail::Lost(m)) => return Err(m),
        Err(Fail::Expired) => return Err("the server forgot the session during initialize".into()),
    };
    let version = result.get("protocolVersion").and_then(Value::as_str).unwrap_or("").to_string();
    if !PROTOCOL_VERSIONS.contains(&version.as_str()) {
        return Err(format!(
            "the server answered protocol version {}; this client works with {}",
            if version.is_empty() { "(none)".to_string() } else { version },
            PROTOCOL_VERSIONS.iter().rev().copied().collect::<Vec<_>>().join(", ")
        ));
    }
    t.set_protocol(&version);
    t.notify("notifications/initialized", Value::Null).await;
    let info = result.get("serverInfo");
    let text = |k: &str| info.and_then(|i| i.get(k)).and_then(Value::as_str).unwrap_or("").to_string();
    Ok(ServerInfo { protocol: version, name: text("name"), version: text("version") })
}

/// A connection of either kind.
pub(super) enum Conn {
    Stdio(Stdio),
    Http(Http),
}

impl Conn {
    pub fn alive(&self) -> bool {
        match self {
            Conn::Stdio(s) => s.alive.load(Ordering::SeqCst),
            Conn::Http(h) => h.alive.load(Ordering::SeqCst),
        }
    }

    pub fn alive_flag(&self) -> Arc<AtomicBool> {
        match self {
            Conn::Stdio(s) => s.alive.clone(),
            Conn::Http(h) => h.alive.clone(),
        }
    }

    pub async fn rpc(&self, id: u64, method: &str, params: Value) -> Result<Value, Fail> {
        match self {
            Conn::Stdio(s) => s.rpc(id, method, params).await,
            Conn::Http(h) => h.rpc(id, method, params).await,
        }
    }

    pub async fn notify(&self, method: &str, params: Value) {
        match self {
            Conn::Stdio(s) => s.notify(method, params).await,
            Conn::Http(h) => h.notify(method, params).await,
        }
    }

    /// Stdio: kill the process group. HTTP: `DELETE` the session, ignoring errors.
    pub async fn shutdown(&self) {
        match self {
            Conn::Stdio(s) => s.kill(),
            Conn::Http(h) => h.delete().await,
        }
    }

    pub async fn initialize(&self, shared: &Shared) -> Result<ServerInfo, String> {
        match self {
            Conn::Stdio(s) => initialize(s, shared).await,
            Conn::Http(h) => initialize(h, shared).await,
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// stdio

type Pending = Arc<StdMutex<HashMap<u64, oneshot::Sender<Result<Value, Fail>>>>>;

pub(super) struct Stdio {
    stdin: Arc<Mutex<ChildStdin>>,
    pending: Pending,
    alive: Arc<AtomicBool>,
    exited: Arc<AtomicBool>,
    pid: u32,
}

struct PendingGuard {
    pending: Pending,
    id: u64,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        lock(&self.pending).remove(&self.id);
    }
}

async fn write_line(stdin: &Mutex<ChildStdin>, msg: &Value) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(msg).unwrap_or_default();
    line.push(b'\n');
    let mut w = stdin.lock().await;
    w.write_all(&line).await?;
    w.flush().await
}

impl Stdio {
    /// Start the server in the session's sandbox, in its own process group.
    pub fn spawn(ctx: &ToolCtx, server: &McpServer, shared: &Arc<Shared>) -> Result<Stdio, String> {
        let Some(argv) = server.cfg.command.as_ref().filter(|c| !c.is_empty()) else {
            return Err("the server has no command".into());
        };
        // Asked first, as for every sandboxed command: a server that cannot be given room leaves nothing behind.
        let nproc = ctx.sandbox.nproc_limit()?;
        let quoted = shlex::try_join(argv.iter().map(String::as_str))
            .map_err(|_| "the command contains a NUL byte".to_string())?;
        let script = format!("exec {quoted}");
        let (program, args) = ctx.sandbox.command(&script);
        let cwd = ctx.sandbox.resolve(server.cfg.cwd.as_deref().unwrap_or("."));
        let mut env = ctx.sandbox.env(&ctx.env);
        for (k, v) in &server.env {
            env.insert(k.clone(), v.clone());
        }
        let mut cmd = tokio::process::Command::new(program);
        cmd.args(args)
            .current_dir(&cwd)
            .env_clear()
            .envs(env)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .process_group(0);
        if let Some(limit) = nproc {
            // SAFETY: the hook only calls setrlimit(2), which is safe between fork and exec.
            unsafe {
                cmd.pre_exec(move || crate::procinfo::set_nproc(limit));
            }
        }
        let mut child = cmd.spawn().map_err(|e| format!("could not start {}: {e}", argv[0]))?;
        let pid = child.id().unwrap_or(0);
        let (Some(stdin), Some(stdout), Some(stderr)) = (child.stdin.take(), child.stdout.take(), child.stderr.take())
        else {
            return Err("the server's pipes are not available".into());
        };
        let stdin = Arc::new(Mutex::new(stdin));
        let pending: Pending = Arc::default();
        let alive = Arc::new(AtomicBool::new(true));
        let exited = Arc::new(AtomicBool::new(false));
        tokio::spawn(read_stdout(stdout, pending.clone(), alive.clone(), stdin.clone(), shared.clone()));
        tokio::spawn(read_stderr(stderr, shared.clone()));
        {
            let (alive, exited) = (alive.clone(), exited.clone());
            tokio::spawn(async move {
                let _ = child.wait().await;
                alive.store(false, Ordering::SeqCst);
                // What the leader left behind goes with it.
                if pid > 0 {
                    kill_group(pid);
                }
                exited.store(true, Ordering::SeqCst);
            });
        }
        Ok(Stdio { stdin, pending, alive, exited, pid })
    }

    fn kill(&self) {
        self.alive.store(false, Ordering::SeqCst);
        if self.pid > 0 && !self.exited.load(Ordering::SeqCst) {
            kill_group(self.pid);
        }
    }
}

fn kill_group(pid: u32) {
    // SAFETY: killpg of the group this process created for the child; an error (the group is gone) is ignored.
    unsafe {
        libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
    }
}

impl Drop for Stdio {
    fn drop(&mut self) {
        self.kill();
    }
}

async fn read_stderr(stderr: ChildStderr, shared: Arc<Shared>) {
    let mut r = BufReader::new(stderr);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match r.read_until(b'\n', &mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(_) => shared.push_line(&buf),
        }
    }
}

async fn read_stdout(
    stdout: ChildStdout,
    pending: Pending,
    alive: Arc<AtomicBool>,
    stdin: Arc<Mutex<ChildStdin>>,
    shared: Arc<Shared>,
) {
    let mut r = BufReader::new(stdout);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match r.read_until(b'\n', &mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let line = buf.trim_ascii();
        if line.is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_slice::<Value>(line) else {
            shared.note_dropped();
            continue;
        };
        match classify(&msg) {
            Incoming::Response(Some(id), result) => {
                if let Some(tx) = lock(&pending).remove(&id) {
                    let _ = tx.send(result);
                }
            }
            Incoming::Request(id, method) => {
                let _ = write_line(&stdin, &reply_to(&id, &method)).await;
            }
            Incoming::Notification(method) => {
                if method == "notifications/tools/list_changed" {
                    shared.list_changed.store(true, Ordering::SeqCst);
                }
            }
            Incoming::Response(None, _) | Incoming::Other => {}
        }
    }
    alive.store(false, Ordering::SeqCst);
    let waiting: Vec<_> = lock(&pending).drain().collect();
    for (_, tx) in waiting {
        let _ = tx.send(Err(Fail::Lost("the server closed its output (it exited)".into())));
    }
}

#[async_trait::async_trait]
impl Transport for Stdio {
    async fn rpc(&self, id: u64, method: &str, params: Value) -> Result<Value, Fail> {
        if !self.alive.load(Ordering::SeqCst) {
            return Err(Fail::NotSent("the server is not running".into()));
        }
        let (tx, rx) = oneshot::channel();
        lock(&self.pending).insert(id, tx);
        let _guard = PendingGuard { pending: self.pending.clone(), id };
        if let Err(e) = write_line(&self.stdin, &request_json(id, method, &params)).await {
            return Err(Fail::NotSent(format!("could not write to the server: {e}")));
        }
        match rx.await {
            Ok(r) => r,
            Err(_) => Err(Fail::Lost("the server closed its output (it exited)".into())),
        }
    }

    async fn notify(&self, method: &str, params: Value) {
        let _ = write_line(&self.stdin, &notification_json(method, &params)).await;
    }

    fn set_protocol(&self, _version: &str) {}
}

// ---------------------------------------------------------------------------------------------------
// Streamable HTTP

pub(super) struct Http {
    client: reqwest::Client,
    url: String,
    extra: Vec<(reqwest::header::HeaderName, reqwest::header::HeaderValue)>,
    session: StdMutex<Option<String>>,
    protocol: StdMutex<Option<String>>,
    shared: Arc<Shared>,
    reinit: Mutex<()>,
    alive: Arc<AtomicBool>,
}

/// Splits a stream of bytes into the `data` of its server-sent events.
#[derive(Default)]
struct Sse {
    buf: Vec<u8>,
    data: Vec<String>,
}

impl Sse {
    fn push(&mut self, chunk: &[u8]) -> Vec<String> {
        self.buf.extend_from_slice(chunk);
        let mut events = Vec::new();
        while let Some(at) = self.buf.iter().position(|b| *b == b'\n') {
            let raw: Vec<u8> = self.buf.drain(..=at).collect();
            let line = String::from_utf8_lossy(&raw);
            let line = line.trim_end_matches(['\n', '\r']);
            if let Some(ev) = self.line(line) {
                events.push(ev);
            }
        }
        events
    }

    fn finish(&mut self) -> Option<String> {
        if !self.buf.is_empty() {
            let raw = std::mem::take(&mut self.buf);
            let line = String::from_utf8_lossy(&raw).trim_end_matches(['\n', '\r']).to_string();
            if let Some(ev) = self.line(&line) {
                return Some(ev);
            }
        }
        self.line("")
    }

    fn line(&mut self, line: &str) -> Option<String> {
        if line.is_empty() {
            return (!self.data.is_empty()).then(|| std::mem::take(&mut self.data).join("\n"));
        }
        if line.starts_with(':') {
            return None;
        }
        let (field, value) = line.split_once(':').unwrap_or((line, ""));
        if field == "data" {
            self.data.push(value.strip_prefix(' ').unwrap_or(value).to_string());
        }
        None
    }
}

impl Http {
    pub fn new(ctx: &ToolCtx, server: &McpServer, shared: &Arc<Shared>) -> Result<Http, String> {
        let Some(url) = server.cfg.url.clone() else { return Err("the server has no url".into()) };
        let client = crate::web::build_client(ctx)?;
        let mut extra = Vec::new();
        for (name, value) in &server.headers {
            let n = reqwest::header::HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| format!("the header name `{name}` is not valid"))?;
            let mut v = reqwest::header::HeaderValue::from_str(value)
                .map_err(|_| format!("the value of the header `{name}` is not valid"))?;
            v.set_sensitive(true);
            extra.push((n, v));
        }
        Ok(Http {
            client,
            url,
            extra,
            session: StdMutex::new(None),
            protocol: StdMutex::new(None),
            shared: shared.clone(),
            reinit: Mutex::new(()),
            alive: Arc::new(AtomicBool::new(true)),
        })
    }

    fn session(&self) -> Option<String> {
        lock(&self.session).clone()
    }

    fn builder(&self, method: reqwest::Method) -> reqwest::RequestBuilder {
        let mut rb = self.client.request(method, &self.url);
        for (n, v) in &self.extra {
            rb = rb.header(n, v);
        }
        if let Some(s) = self.session() {
            rb = rb.header("Mcp-Session-Id", s);
        }
        if let Some(p) = lock(&self.protocol).clone() {
            rb = rb.header("MCP-Protocol-Version", p);
        }
        rb
    }

    /// The request as it goes out (headers the transport adds are included; stored as sent, C5).
    fn request_wire(&self, body: &Value) -> Vec<u8> {
        let mut headers: Vec<(String, String)> = vec![
            ("Accept".into(), "application/json, text/event-stream".into()),
            ("Content-Type".into(), "application/json".into()),
        ];
        for (n, v) in &self.extra {
            headers.push((n.to_string(), v.to_str().unwrap_or_default().to_string()));
        }
        if let Some(s) = self.session() {
            headers.push(("Mcp-Session-Id".into(), s));
        }
        if let Some(p) = lock(&self.protocol).clone() {
            headers.push(("MCP-Protocol-Version".into(), p));
        }
        match url::Url::parse(&self.url) {
            Ok(u) => {
                crate::traffic::request_message("POST", &u, &headers, &serde_json::to_vec(body).unwrap_or_default())
            }
            Err(_) => Vec::new(),
        }
    }

    fn post_builder(&self, body: &Value) -> reqwest::RequestBuilder {
        self.builder(reqwest::Method::POST)
            .header("Accept", "application/json, text/event-stream")
            .header("Content-Type", "application/json")
            .body(serde_json::to_vec(body).unwrap_or_default())
    }

    /// POST a message whose answer matters little (a notification or a reply to the server).
    async fn send_only(&self, body: &Value) {
        let _ = self.post_builder(body).send().await;
    }

    /// POST a request and read the answer with id `want`.
    async fn post(&self, body: &Value, want: u64) -> Result<Value, Fail> {
        let sent_with_session = self.session().is_some();
        let started = std::time::Instant::now();
        let request_wire = self.request_wire(body);
        let mut resp = match self.post_builder(body).send().await {
            Ok(r) => r,
            Err(e) => {
                let connect = e.is_connect();
                let text = e.without_url().to_string();
                self.shared.push_traffic(Raw {
                    url: self.url.clone(),
                    request: request_wire,
                    response: None,
                    status: None,
                    error: Some(text.clone()),
                    started,
                });
                return Err(if connect {
                    Fail::NotSent(format!("could not connect to the server: {text}"))
                } else {
                    Fail::Lost(format!("the request failed: {text}"))
                });
            }
        };
        if let Some(s) = resp.headers().get("mcp-session-id").and_then(|v| v.to_str().ok()) {
            *lock(&self.session) = Some(s.to_string());
        }
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND && sent_with_session {
            return Err(Fail::Expired);
        }
        let content_type =
            resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_ascii_lowercase();
        let head: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("(non-UTF8)").to_string()))
            .collect();
        let note = |body: &[u8], error: Option<String>| {
            self.shared.push_traffic(Raw {
                url: self.url.clone(),
                request: request_wire.clone(),
                response: Some(crate::traffic::response_message(status.as_u16(), &head, body)),
                status: Some(status.as_u16()),
                error,
                started,
            });
        };
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            note(text.as_bytes(), None);
            if let Ok(msg) = serde_json::from_str::<Value>(&text) {
                if let Incoming::Response(_, Err(fail)) = classify(&msg) {
                    return Err(fail);
                }
            }
            let shown: String = text.trim().chars().take(500).collect();
            return Err(Fail::Lost(if shown.is_empty() {
                format!("the server answered HTTP {status}")
            } else {
                format!("the server answered HTTP {status}: {shown}")
            }));
        }
        if content_type.starts_with("text/event-stream") {
            let mut sse = Sse::default();
            let mut seen: Vec<u8> = Vec::new();
            loop {
                let chunk = match resp.chunk().await {
                    Ok(Some(c)) => c,
                    Ok(None) => break,
                    Err(e) => {
                        let why = format!("the event stream failed: {}", e.without_url());
                        note(&seen, Some(why.clone()));
                        return Err(Fail::Lost(why));
                    }
                };
                if seen.len() < crate::traffic::CAPTURE_MAX_BYTES {
                    seen.extend_from_slice(&chunk);
                }
                for data in sse.push(&chunk) {
                    if let Some(r) = self.on_message(&data, want).await {
                        return r;
                    }
                }
            }
            note(&seen, None);
            if let Some(data) = sse.finish() {
                if let Some(r) = self.on_message(&data, want).await {
                    return r;
                }
            }
            return Err(Fail::Lost("the event stream ended without an answer".into()));
        }
        let bytes = resp.bytes().await.map_err(|e| Fail::Lost(format!("the answer failed: {}", e.without_url())))?;
        note(&bytes, None);
        let text = String::from_utf8_lossy(&bytes).into_owned();
        if let Some(r) = self.on_message(&text, want).await {
            return r;
        }
        Err(Fail::Lost("the server answered without a response to the request".into()))
    }

    /// One JSON message (or batch) from the server; `Some` when it holds the answer to `want`.
    async fn on_message(&self, text: &str, want: u64) -> Option<Result<Value, Fail>> {
        let Ok(value) = serde_json::from_str::<Value>(text) else {
            self.shared.note_dropped();
            return None;
        };
        let messages = match value {
            Value::Array(a) => a,
            other => vec![other],
        };
        let mut answer = None;
        for msg in messages {
            match classify(&msg) {
                Incoming::Response(Some(id), r) if id == want => answer = Some(r),
                Incoming::Request(id, method) => self.send_only(&reply_to(&id, &method)).await,
                Incoming::Notification(method) if method == "notifications/tools/list_changed" => {
                    self.shared.list_changed.store(true, Ordering::SeqCst);
                }
                _ => {}
            }
        }
        answer
    }

    async fn delete(&self) {
        if self.session().is_none() {
            return;
        }
        let _ = tokio::time::timeout(Duration::from_secs(5), self.builder(reqwest::Method::DELETE).send()).await;
    }
}

#[async_trait::async_trait]
impl Transport for Http {
    async fn rpc(&self, id: u64, method: &str, params: Value) -> Result<Value, Fail> {
        let body = request_json(id, method, &params);
        let before = self.session();
        match self.post(&body, id).await {
            Err(Fail::Expired) if method != "initialize" => {
                {
                    let _g = self.reinit.lock().await;
                    // Another call may have started a new session while this one waited.
                    if self.session() == before {
                        *lock(&self.session) = None;
                        *lock(&self.protocol) = None;
                        initialize(self, &self.shared).await.map_err(Fail::Lost)?;
                    }
                }
                match self.post(&body, id).await {
                    Err(Fail::Expired) => Err(Fail::Lost("the server forgot the session again".into())),
                    r => r,
                }
            }
            r => r,
        }
    }

    async fn notify(&self, method: &str, params: Value) {
        self.send_only(&notification_json(method, &params)).await;
    }

    fn set_protocol(&self, version: &str) {
        *lock(&self.protocol) = Some(version.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sse_events_split_across_chunks_and_line_endings() {
        let mut s = Sse::default();
        let mut got = Vec::new();
        for c in [&b"event: message\r\ndata: {\"a\""[..], b":1}\r\n\r\n: comment\n", b"data: x\ndata: y\n\ndata: tail"]
        {
            got.extend(s.push(c));
        }
        got.extend(s.finish());
        assert_eq!(got, vec!["{\"a\":1}".to_string(), "x\ny".to_string(), "tail".to_string()]);
    }

    #[test]
    fn classify_tells_the_message_kinds_apart() {
        assert!(matches!(classify(&json!({"id": 3, "result": {}})), Incoming::Response(Some(3), Ok(_))));
        assert!(matches!(
            classify(&json!({"id": 3, "error": {"code": -1, "message": "m"}})),
            Incoming::Response(Some(3), Err(Fail::Rpc { code: -1, .. }))
        ));
        assert!(matches!(classify(&json!({"id": "7", "method": "ping"})), Incoming::Request(..)));
        assert!(matches!(classify(&json!({"method": "notifications/x"})), Incoming::Notification(_)));
        assert!(matches!(classify(&json!([1])), Incoming::Other));
    }
}
