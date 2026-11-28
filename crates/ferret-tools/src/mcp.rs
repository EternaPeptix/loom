//! MCP servers as tools. `docs/CONTRACTS-MCP.md` is normative; this module implements M2, M3 and M5.
//!
//! CONTRACT
//!
//! - [`McpServer::resolve`] turns a `[mcp.servers.<name>]` entry into a startable server: `env:NAME`
//!   reads the daemon's environment, `file:/path` reads the file (trimmed), anything else is the literal
//!   value. A missing source is an error naming the server and the source (not the value).
//! - [`McpHandle`] is one session's connection to one server. It connects lazily (first `list` or
//!   `call`), keeps one connection, closes it after `idle_close` without a call or on [`McpHandle::close`],
//!   and restarts a dead server once per call (M3). Calls on one handle may run concurrently; JSON-RPC ids
//!   are unique per connection and answers are matched by id.
//!   - stdio: the child is `ctx.sandbox.command("exec " + shell-quoted argv)`, cwd `ctx.sandbox.resolve
//!     (cfg.cwd or ".")`, env `ctx.sandbox.env(...)` over the resolved server env (names the server sets
//!     pass the sandbox's filter), its own process group, killed with the group on close. stdout is
//!     newline-delimited JSON-RPC; stderr goes to a ring of the last 200 lines; a non-JSON stdout line is
//!     dropped and counted.
//!   - HTTP: Streamable HTTP through the session's egress proxy, built like `web.rs` `build_client`
//!     (the proxy from `ctx.env`), so `net.jsonl` sees it and the session's network policy decides.
//!   - Handshake, versions, paging, server-to-client requests, cancel: M2 exactly.
//! - [`McpTool`] is one listed tool presented to the model (M5): name [`tool_name`], description cut at
//!   2,000 characters, parameters the `inputSchema` without a top-level `$schema` (an empty object schema
//!   when missing), class `Read` when `readOnlyHint` is true else `Exec`, never speculative. `run` checks
//!   the arguments with `schema::check` only when [`crate::schema::checkable`] says the schema uses
//!   nothing else, calls the server with the server's `timeout_s`, and maps the result (content blocks,
//!   status, facts) as M5 says, through [`map_result`].
//! - [`presented_tools`] picks a listing's tools for a role: the `tools` filter, sanitised names, the
//!   64-character cut and collisions (the first kept), in listing order.
//!
//! Tests (M9): protocol over stdio against a `/bin/sh` fake and over HTTP against a local route (handshake
//! and version check, paging, call, JSON-RPC error, `isError`, `ping` and an unknown server request,
//! timeout sending `notifications/cancelled`, restart once, the stderr ring); every content block kind,
//! `structuredContent`, empty content, an image over `max_image_bytes`; naming; a stdio server cannot write
//! outside the workspace and cannot connect under `deny_all`; a resolved `env:` value appears in no output.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::{Duration, Instant};

use base64::Engine as _;
use ferret_core::config::McpServerCfg;
use ferret_core::event::{McpListing, McpToolDef, ToolClass, ToolSpec, ToolStatus};
use serde_json::{json, Map, Value};

use crate::{Body, Tool, ToolCtx, ToolOutput};
use conn::{lock, Conn, Fail, Shared};

mod conn;
#[cfg(test)]
mod tests;

/// The protocol versions this client works with, newest first; the first is the one it asks for.
pub const PROTOCOL_VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

/// Longest name a presented tool may have.
pub const MAX_TOOL_NAME: usize = 64;

/// Longest description a presented tool has, in characters.
const MAX_DESCRIPTION_CHARS: usize = 2000;
/// Pages of `tools/list` followed.
const MAX_PAGES: usize = 50;
/// Lines of stderr in a failure.
const FAIL_TAIL: usize = 40;
/// Maximum size of a `file:` secret referenced by `[mcp.servers.<name>]` (64 KiB).
pub const MAX_SECRET_FILE_BYTES: usize = 64 * 1024;

/// A configured server with its secrets resolved. `Debug` never prints a value of `env` or `headers`.
#[derive(Clone)]
pub struct McpServer {
    pub name: String,
    pub cfg: McpServerCfg,
    /// Resolved `env` (stdio) and `headers` (HTTP) values.
    pub env: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
}

impl std::fmt::Debug for McpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpServer")
            .field("name", &self.name)
            .field("env", &self.env.keys().collect::<Vec<_>>())
            .field("headers", &self.headers.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// Read a private (`0600`, owner UID matching effective UID, regular file, no symlink follow) secret file
/// up to `max_bytes`. Never includes file content in error messages.
pub(crate) fn read_private_secret_file(
    path: &std::path::Path,
    label: &str,
    max_bytes: usize,
) -> Result<String, String> {
    use std::io::Read;
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = opts.open(path).map_err(|e| {
        #[cfg(unix)]
        if e.raw_os_error() == Some(libc::ELOOP) {
            return format!("{label}: the file {} must not be a symlink", path.display());
        }
        format!("{label}: the file {} could not be read ({})", path.display(), e.kind())
    })?;
    let meta = file
        .metadata()
        .map_err(|e| format!("{label}: the file {} could not be inspected ({})", path.display(), e.kind()))?;
    if !meta.file_type().is_file() {
        return Err(format!("{label}: the file {} must be a regular file", path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "{label}: the file {} has permissions {:04o}; make it owner-only first (`chmod 600 {}`)",
                path.display(),
                mode,
                path.display()
            ));
        }
        // SAFETY: geteuid has no preconditions and returns the current process's effective UID.
        let euid = unsafe { libc::geteuid() };
        if meta.uid() != euid {
            return Err(format!(
                "{label}: the file {} is owned by uid {}, expected uid {euid}",
                path.display(),
                meta.uid()
            ));
        }
    }
    if meta.len() > max_bytes as u64 {
        return Err(format!("{label}: the file {} exceeds the {max_bytes}-byte cap", path.display()));
    }
    let mut buf = Vec::new();
    file.by_ref()
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("{label}: the file {} could not be read ({})", path.display(), e.kind()))?;
    if buf.len() > max_bytes {
        return Err(format!("{label}: the file {} exceeds the {max_bytes}-byte cap", path.display()));
    }
    String::from_utf8(buf).map_err(|_| format!("{label}: the file {} is not valid UTF-8", path.display()))
}

/// One `env`/`headers` value: `env:NAME`, `file:/path` (trimmed, private `0600` regular file, `O_NOFOLLOW`,
/// UID-matched, <= 64 KiB) or the literal.
fn resolve_value(server: &str, kind: &str, key: &str, source: &str) -> Result<String, String> {
    let at = format!("mcp.servers.{server}.{kind}.{key}");
    if let Some(var) = source.strip_prefix("env:") {
        return match std::env::var(var) {
            Ok(v) => Ok(v),
            Err(_) => Err(format!("{at}: the environment variable {var} is not set")),
        };
    }
    if let Some(path) = source.strip_prefix("file:") {
        let raw = read_private_secret_file(std::path::Path::new(path), &at, MAX_SECRET_FILE_BYTES)?;
        return Ok(raw.trim().to_string());
    }
    Ok(source.to_string())
}

impl McpServer {
    /// Resolve `env:`/`file:` sources (see the module CONTRACT).
    pub fn resolve(name: &str, cfg: &McpServerCfg) -> Result<McpServer, String> {
        let mut env = BTreeMap::new();
        for (k, v) in &cfg.env {
            env.insert(k.clone(), resolve_value(name, "env", k, v)?);
        }
        let mut headers = BTreeMap::new();
        for (k, v) in &cfg.headers {
            headers.insert(k.clone(), resolve_value(name, "headers", k, v)?);
        }
        Ok(McpServer { name: name.to_string(), cfg: cfg.clone(), env, headers })
    }

    /// `stdio` or `http`.
    pub fn transport(&self) -> &'static str {
        if self.cfg.url.is_some() {
            "http"
        } else {
            "stdio"
        }
    }
}

/// What a session's connection to a server is doing, for `GET /api/sessions/{id}/mcp` (M7).
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct McpStatus {
    /// `not started`, `running`, `closed` or `failed`.
    pub state: String,
    pub error: Option<String>,
    pub stderr_tail: Vec<String>,
    /// The server sent `notifications/tools/list_changed` since this handle connected.
    pub list_changed: bool,
    pub calls: u64,
    pub last_call_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum State {
    NotStarted,
    Running,
    Closed,
    Failed(String),
}

struct Slot {
    conn: Option<Arc<Conn>>,
    state: State,
    info: conn::ServerInfo,
    generation: u64,
}

/// One session's connection to one server.
pub struct McpHandle {
    server: McpServer,
    idle_close: Duration,
    me: Weak<McpHandle>,
    shared: Arc<Shared>,
    /// Held while a connection is opened, so concurrent calls share one.
    opening: tokio::sync::Mutex<()>,
    slot: StdMutex<Slot>,
    calls: AtomicU64,
    last_call_ms: AtomicU64,
    inflight: AtomicU64,
    last_used: StdMutex<Instant>,
}

const NO_CALL: u64 = u64::MAX;

struct Inflight<'a>(&'a McpHandle);

impl<'a> Inflight<'a> {
    fn new(h: &'a McpHandle) -> Self {
        h.inflight.fetch_add(1, Ordering::SeqCst);
        *lock(&h.last_used) = Instant::now();
        Inflight(h)
    }
}

impl Drop for Inflight<'_> {
    fn drop(&mut self) {
        *lock(&self.0.last_used) = Instant::now();
        self.0.inflight.fetch_sub(1, Ordering::SeqCst);
    }
}

/// What a request can come to besides an answer.
enum ReqErr {
    Call(CallError),
    /// The request never reached the server.
    NotSent,
}

impl McpHandle {
    pub fn new(server: McpServer, idle_close: Duration) -> Arc<McpHandle> {
        Arc::new_cyclic(|me| McpHandle {
            server,
            idle_close,
            me: me.clone(),
            shared: Arc::default(),
            opening: tokio::sync::Mutex::new(()),
            slot: StdMutex::new(Slot {
                conn: None,
                state: State::NotStarted,
                info: conn::ServerInfo::default(),
                generation: 0,
            }),
            calls: AtomicU64::new(0),
            last_call_ms: AtomicU64::new(NO_CALL),
            inflight: AtomicU64::new(0),
            last_used: StdMutex::new(Instant::now()),
        })
    }

    pub fn server(&self) -> &McpServer {
        &self.server
    }

    /// All resolved secret values (and `<scheme> <token>` tokens for auth headers), sorted longest-first.
    fn secret_values(&self) -> Vec<&str> {
        let mut secrets: Vec<&str> = Vec::new();
        for v in self.server.env.values() {
            if !v.is_empty() {
                secrets.push(v.as_str());
            }
        }
        for v in self.server.headers.values() {
            if !v.is_empty() {
                secrets.push(v.as_str());
                // Also scrub bare token from `<scheme> <token>` headers (e.g. `Bearer <tok>`)
                // when echoed back without the scheme prefix, matching `Secrets::for_items`.
                if let Some((_, tok)) = v.trim().split_once(' ') {
                    if tok.len() >= 6 && !tok.contains(' ') {
                        secrets.push(tok);
                    }
                }
            }
        }
        secrets.sort_by_key(|a| std::cmp::Reverse(a.len()));
        secrets.dedup();
        secrets
    }

    /// Remove every resolved secret of the server from `text`, longest secret first.
    fn redact(&self, text: &str) -> String {
        let mut out = text.to_string();
        for v in self.secret_values() {
            out = out.replace(v, "[redacted]");
        }
        out
    }

    /// Remove every resolved secret of the server from raw HTTP wire bytes before traffic capture.
    fn redact_bytes(&self, input: &[u8]) -> Vec<u8> {
        let mut buf = input.to_vec();
        for v in self.secret_values() {
            buf = replace_bytes(&buf, v.as_bytes(), b"[redacted]");
        }
        buf
    }

    fn tail(&self, n: usize) -> Vec<String> {
        self.shared.tail(n).iter().map(|l| self.redact(l)).collect()
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(self.server.cfg.timeout_s.max(1))
    }

    fn fail_text(&self, reason: &str) -> String {
        let mut text = self.redact(reason);
        let tail = self.tail(FAIL_TAIL);
        if !tail.is_empty() {
            text.push_str("\nlast lines of the server's stderr:\n");
            text.push_str(&tail.join("\n"));
        }
        text
    }

    /// The open connection, opening one when there is none or it died. The flag is true when a dead one
    /// was replaced.
    async fn ensure(&self, ctx: &ToolCtx) -> Result<(Arc<Conn>, bool), String> {
        let _opening = self.opening.lock().await;
        let restarted = {
            let slot = lock(&self.slot);
            match &slot.conn {
                Some(c) if c.alive() => return Ok((c.clone(), false)),
                Some(_) => true,
                None => false,
            }
        };
        let old = lock(&self.slot).conn.take();
        if let Some(old) = old {
            old.shutdown().await;
        }
        let limit = self.timeout();
        let opened = tokio::time::timeout(limit, self.open(ctx))
            .await
            .unwrap_or_else(|_| Err(format!("the server did not finish its handshake within {}s", limit.as_secs())));
        match opened {
            Ok((conn, info)) => {
                let conn = Arc::new(conn);
                let generation = {
                    let mut slot = lock(&self.slot);
                    slot.conn = Some(conn.clone());
                    slot.state = State::Running;
                    slot.info = info;
                    slot.generation += 1;
                    slot.generation
                };
                self.watch(generation);
                Ok((conn, restarted))
            }
            Err(reason) => {
                let text = self.fail_text(&reason);
                lock(&self.slot).state = State::Failed(self.redact(&reason));
                Err(text)
            }
        }
    }

    async fn open(&self, ctx: &ToolCtx) -> Result<(Conn, conn::ServerInfo), String> {
        let conn = if self.server.cfg.url.is_some() {
            Conn::Http(conn::Http::new(ctx, &self.server, &self.shared)?)
        } else {
            Conn::Stdio(conn::Stdio::spawn(ctx, &self.server, &self.shared)?)
        };
        match conn.initialize(&self.shared).await {
            Ok(info) => Ok((conn, info)),
            Err(e) => {
                conn.shutdown().await;
                Err(e)
            }
        }
    }

    /// Close the connection after `idle_close` without a call.
    fn watch(&self, generation: u64) {
        if self.idle_close.is_zero() {
            return;
        }
        let weak = self.me.clone();
        let idle = self.idle_close;
        tokio::spawn(async move {
            let mut wait = idle;
            loop {
                tokio::time::sleep(wait).await;
                let Some(h) = weak.upgrade() else { return };
                if lock(&h.slot).generation != generation {
                    return;
                }
                let since = lock(&h.last_used).elapsed();
                if h.inflight.load(Ordering::SeqCst) == 0 && since >= idle {
                    h.close_generation(generation).await;
                    return;
                }
                wait = idle.saturating_sub(since).max(Duration::from_millis(50));
            }
        });
    }

    async fn close_generation(&self, generation: u64) {
        let old = {
            let mut slot = lock(&self.slot);
            if slot.generation != generation {
                return;
            }
            slot.state = State::Closed;
            slot.conn.take()
        };
        if let Some(c) = old {
            c.shutdown().await;
        }
    }

    /// One request with the server's timeout, stopped by `ctx.cancel`.
    async fn request(&self, ctx: &ToolCtx, conn: &Conn, method: &str, params: Value) -> Result<Value, ReqErr> {
        let id = self.shared.next_id();
        let timeout = self.timeout();
        let cancelled = |reason: &str| json!({"requestId": id, "reason": reason});
        tokio::select! {
            biased;
            () = ctx.cancel.cancelled() => {
                conn.notify("notifications/cancelled", cancelled("the call was stopped")).await;
                Err(ReqErr::Call(CallError::Interrupted))
            }
            () = tokio::time::sleep(timeout) => {
                conn.notify("notifications/cancelled", cancelled("the call timed out")).await;
                Err(ReqErr::Call(CallError::Timeout { after_s: timeout.as_secs() }))
            }
            r = conn.rpc(id, method, params) => match r {
                Ok(v) => Ok(v),
                Err(Fail::Rpc { code, message, data }) => {
                    Err(ReqErr::Call(CallError::Rpc { code, message: self.redact(&message), data }))
                }
                Err(Fail::NotSent(_)) => Err(ReqErr::NotSent),
                Err(Fail::Lost(m)) => Err(ReqErr::Call(CallError::Failed {
                    reason: self.redact(&m),
                    stderr_tail: self.tail(FAIL_TAIL),
                })),
                Err(Fail::Expired) => Err(ReqErr::Call(CallError::Failed {
                    reason: "the server forgot the session".into(),
                    stderr_tail: self.tail(FAIL_TAIL),
                })),
            },
        }
    }

    /// A request on an open connection; a request that did not reach a dead server opens a new connection
    /// once. The flag is true when the server was restarted for it.
    async fn request_restarting(&self, ctx: &ToolCtx, method: &str, params: Value) -> (Result<Value, CallError>, bool) {
        let mut restarted = false;
        for attempt in 0..2 {
            let (conn, again) = match self.ensure(ctx).await {
                Ok(c) => c,
                Err(text) => {
                    let (reason, tail) = split_fail(&text);
                    return (Err(CallError::Failed { reason, stderr_tail: tail }), restarted);
                }
            };
            restarted |= again;
            match self.request(ctx, &conn, method, params.clone()).await {
                Ok(v) => return (Ok(v), restarted),
                Err(ReqErr::Call(e)) => return (Err(e), restarted),
                Err(ReqErr::NotSent) => {
                    conn.alive_flag().store(false, Ordering::SeqCst);
                    if attempt == 1 {
                        break;
                    }
                }
            }
        }
        let reason = "the server could not be reached".to_string();
        lock(&self.slot).state = State::Failed(reason.clone());
        (Err(CallError::Failed { reason, stderr_tail: self.tail(FAIL_TAIL) }), restarted)
    }

    /// Connect if needed, then `tools/list` (all pages) into a listing. A failure is an `Err` with the
    /// reason and the last 40 stderr lines; the caller records it as the listing's `error`.
    pub async fn list(&self, ctx: &ToolCtx) -> Result<McpListing, String> {
        let _busy = Inflight::new(self);
        let mut tools = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let params = match &cursor {
                Some(c) => json!({"cursor": c}),
                None => json!({}),
            };
            let (result, _) = self.request_restarting(ctx, "tools/list", params).await;
            let page = match result {
                Ok(v) => v,
                Err(CallError::Failed { reason, .. }) => return Err(self.fail_text(&reason)),
                Err(e) => return Err(self.fail_text(&describe_error(&e))),
            };
            for t in page.get("tools").and_then(Value::as_array).into_iter().flatten() {
                let Some(name) = t.get("name").and_then(Value::as_str) else { continue };
                tools.push(McpToolDef {
                    name: name.to_string(),
                    description: t.get("description").and_then(Value::as_str).unwrap_or("").to_string(),
                    input_schema: t.get("inputSchema").cloned().unwrap_or(Value::Null),
                    read_only_hint: t.pointer("/annotations/readOnlyHint").and_then(Value::as_bool),
                });
            }
            cursor = page.get("nextCursor").and_then(Value::as_str).filter(|c| !c.is_empty()).map(str::to_string);
            if cursor.is_none() {
                break;
            }
        }
        verify_schema_pin(&self.server.name, &tools, self.server.cfg.pinned_schema_sha256.as_deref())?;
        let info = lock(&self.slot).info.clone();
        Ok(McpListing {
            server: self.server.name.clone(),
            transport: self.server.transport().to_string(),
            protocol: info.protocol,
            server_name: info.name,
            server_version: info.version,
            tools,
            error: None,
        })
    }

    /// One `tools/call`. `Ok` is the result object (`content`, `structuredContent`, `isError`);
    /// `Err` is [`CallError`].
    pub async fn call(&self, ctx: &ToolCtx, tool: &str, args: Value) -> Result<Value, CallError> {
        self.call_restarting(ctx, tool, args).await.0
    }

    /// [`McpHandle::call`], and whether the server had to be restarted for it (the fact `server restarted`).
    pub async fn call_restarting(&self, ctx: &ToolCtx, tool: &str, args: Value) -> (Result<Value, CallError>, bool) {
        let _busy = Inflight::new(self);
        let started = Instant::now();
        let out = self.request_restarting(ctx, "tools/call", json!({"name": tool, "arguments": args})).await;
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.last_call_ms.store(started.elapsed().as_millis() as u64, Ordering::Relaxed);
        out
    }

    pub fn status(&self) -> McpStatus {
        let slot = lock(&self.slot);
        let (state, error) = match &slot.state {
            State::NotStarted => ("not started", None),
            State::Closed => ("closed", None),
            State::Failed(e) => ("failed", Some(e.clone())),
            State::Running if slot.conn.as_ref().is_some_and(|c| c.alive()) => ("running", None),
            State::Running => ("failed", Some("the server exited".to_string())),
        };
        let last = self.last_call_ms.load(Ordering::Relaxed);
        McpStatus {
            state: state.to_string(),
            error,
            stderr_tail: self.tail(FAIL_TAIL),
            list_changed: self.shared.list_changed.load(Ordering::SeqCst),
            calls: self.calls.load(Ordering::Relaxed),
            last_call_ms: (last != NO_CALL).then_some(last),
        }
    }

    /// Close the connection (stdio: kill the group; HTTP: `DELETE` the session). A later call opens it again.
    pub async fn close(&self) {
        let old = {
            let mut slot = lock(&self.slot);
            slot.generation += 1;
            if slot.state == State::Running {
                slot.state = State::Closed;
            }
            slot.conn.take()
        };
        if let Some(c) = old {
            c.shutdown().await;
        }
    }
}

fn split_fail(text: &str) -> (String, Vec<String>) {
    match text.split_once("\nlast lines of the server's stderr:\n") {
        Some((reason, tail)) => (reason.to_string(), tail.lines().map(str::to_string).collect()),
        None => (text.to_string(), Vec::new()),
    }
}

fn describe_error(e: &CallError) -> String {
    match e {
        CallError::Rpc { code, message, .. } => format!("the server answered error {code}: {message}"),
        CallError::Timeout { after_s } => format!("no answer within {after_s}s"),
        CallError::Interrupted => "stopped".to_string(),
        CallError::Failed { reason, .. } => reason.clone(),
    }
}

/// Why a call has no result object.
#[derive(Clone, Debug, PartialEq)]
pub enum CallError {
    /// The server answered with a JSON-RPC error.
    Rpc { code: i64, message: String, data: Option<Value> },
    /// No answer within the server's `timeout_s` (`notifications/cancelled` was sent).
    Timeout { after_s: u64 },
    /// The call was stopped (`ctx.cancel`; `notifications/cancelled` was sent).
    Interrupted,
    /// The server could not be started or the connection failed; `stderr_tail` is its last lines.
    Failed { reason: String, stderr_tail: Vec<String> },
}

fn replace_bytes(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return haystack.to_vec();
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut i = 0;
    while i <= haystack.len() - needle.len() {
        if &haystack[i..i + needle.len()] == needle {
            out.extend_from_slice(replacement);
            i += needle.len();
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    out.extend_from_slice(&haystack[i..]);
    out
}

/// Deterministic JSON serialization with recursively sorted object keys.
fn canonical_json(v: &Value) -> String {
    match v {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            serde_json::to_string(v).unwrap_or_default()
        }
        Value::Array(items) => {
            let mut out = String::from("[");
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&canonical_json(item));
            }
            out.push(']');
            out
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = String::from("{");
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).unwrap_or_default());
                out.push(':');
                out.push_str(&canonical_json(&map[*k]));
            }
            out.push('}');
            out
        }
    }
}

/// Compute a canonical lowercase hex SHA-256 hash over an MCP server's `tools/list` definitions
/// (tool names, descriptions, and canonicalized `inputSchema` JSON), independent of paging/key order.
pub fn schema_sha256(tools: &[McpToolDef]) -> String {
    let mut entries: Vec<(&str, &str, String)> =
        tools.iter().map(|t| (t.name.as_str(), t.description.as_str(), canonical_json(&t.input_schema))).collect();
    entries.sort();
    let mut canonical = String::from("[");
    for (i, (name, desc, schema)) in entries.iter().enumerate() {
        if i > 0 {
            canonical.push(',');
        }
        canonical.push_str("{\"description\":");
        canonical.push_str(&serde_json::to_string(desc).unwrap_or_default());
        canonical.push_str(",\"inputSchema\":");
        canonical.push_str(schema);
        canonical.push_str(",\"name\":");
        canonical.push_str(&serde_json::to_string(name).unwrap_or_default());
        canonical.push('}');
    }
    canonical.push(']');
    ferret_core::sha256_hex(canonical.as_bytes())
}

/// Verify an MCP server's `tools/list` schema against an optional operator-pinned SHA-256 hex digest.
/// Returns the computed canonical SHA-256 digest on success.
pub fn verify_schema_pin(server: &str, tools: &[McpToolDef], pinned_sha256: Option<&str>) -> Result<String, String> {
    let actual = schema_sha256(tools);
    if let Some(expected) = pinned_sha256.map(str::trim).filter(|s| !s.is_empty()) {
        if !actual.eq_ignore_ascii_case(expected) {
            return Err(format!(
                "mcp.servers.{server}: tools/list schema SHA-256 mismatch (expected {expected}, got {actual}); refusing mutated tool definitions"
            ));
        }
    }
    Ok(actual)
}

/// Effective [`ToolClass`] for an MCP tool. Server-advertised `readOnlyHint` is untrusted by default
/// and only downgrades `Exec -> Read` when the operator explicitly enables `trust_read_only_hints`.
pub fn tool_class(def: &McpToolDef, trust_read_only_hints: bool) -> ToolClass {
    if trust_read_only_hints && def.read_only_hint == Some(true) {
        ToolClass::Read
    } else {
        ToolClass::Exec
    }
}

/// `mcp__{server}__{tool}` with every character of `tool` outside `[A-Za-z0-9_-]` replaced by `_`, cut
/// to [`MAX_TOOL_NAME`] characters.
pub fn tool_name(server: &str, tool: &str) -> String {
    let mut name = format!("mcp__{server}__");
    name.extend(tool.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' }));
    name.chars().take(MAX_TOOL_NAME).collect()
}

/// The tools of `listing` a role gets, as `(presented name, def)` in listing order, and the server's names
/// of the tools left out by a collision after sanitising and cutting (M5, M6). `filter` is the server's
/// `tools`.
pub fn presented_tools(listing: &McpListing, filter: Option<&[String]>) -> (Vec<(String, McpToolDef)>, Vec<String>) {
    let mut kept: Vec<(String, McpToolDef)> = Vec::new();
    let mut left_out = Vec::new();
    for def in &listing.tools {
        if filter.is_some_and(|f| !f.iter().any(|n| n == &def.name)) {
            continue;
        }
        let name = tool_name(&listing.server, &def.name);
        if kept.iter().any(|(n, _)| n == &name) {
            left_out.push(def.name.clone());
        } else {
            kept.push((name, def.clone()));
        }
    }
    (kept, left_out)
}

fn decode(data: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(data.trim()).ok()
}

fn blob_size(b: &Value) -> u64 {
    let data = b.as_str().unwrap_or("");
    decode(data).map_or_else(|| (data.len() as u64 / 4) * 3, |v| v.len() as u64)
}

/// The body line (and image) for one `image` block.
fn image_block(ctx: &ToolCtx, block: &Value, images: &mut Vec<ferret_core::ImageRef>) -> String {
    let mime = block.get("mimeType").and_then(Value::as_str).unwrap_or("image");
    let size = blob_size(&block["data"]);
    let not_kept = format!("[image not kept: {mime}, {size} bytes]");
    if size > ctx.cfg.max_image_bytes {
        return not_kept;
    }
    let Some(bytes) = block.get("data").and_then(Value::as_str).and_then(decode) else { return not_kept };
    let Some(info) = ferret_core::image::detect(&bytes) else { return not_kept };
    match ctx.blobs.put_bytes(&bytes) {
        Ok(stored) => {
            images.push(ferret_core::ImageRef {
                blob: stored.id.as_str().to_string(),
                mime: info.mime.to_string(),
                bytes: bytes.len() as u64,
                width: info.width,
                height: info.height,
                name: None,
            });
            format!("[image: {}x{} {}, {}]", info.width, info.height, info.mime, ferret_core::image::size_label(size))
        }
        Err(_) => not_kept,
    }
}

/// A call's outcome as a tool output (M5): body from the content blocks, images through
/// `ToolOutput::with_images`, status and outcome, the `{server}` fact and `restarted`.
pub fn map_result(ctx: &ToolCtx, server: &str, result: Result<Value, CallError>, restarted: bool) -> ToolOutput {
    let mut images = Vec::new();
    let (status, outcome, text) = match result {
        Ok(v) => {
            let mut blocks: Vec<String> = Vec::new();
            let mut has_text = false;
            for b in v.get("content").and_then(Value::as_array).into_iter().flatten() {
                let s = |k: &str| b.get(k).and_then(Value::as_str);
                match s("type").unwrap_or("") {
                    "text" => {
                        has_text = true;
                        blocks.push(s("text").unwrap_or("").to_string());
                    }
                    "image" => blocks.push(image_block(ctx, b, &mut images)),
                    "audio" => blocks.push(format!(
                        "[audio not shown: {}, {} bytes]",
                        s("mimeType").unwrap_or("audio"),
                        blob_size(&b["data"])
                    )),
                    "resource_link" => {
                        let mut line = format!("[resource {}", s("uri").unwrap_or(""));
                        for extra in [s("name"), s("mimeType")].into_iter().flatten() {
                            line.push_str(" \u{b7} ");
                            line.push_str(extra);
                        }
                        line.push(']');
                        blocks.push(line);
                    }
                    "resource" => {
                        let r = b.get("resource").unwrap_or(&Value::Null);
                        let uri = r.get("uri").and_then(Value::as_str).unwrap_or("");
                        if let Some(t) = r.get("text").and_then(Value::as_str) {
                            blocks.push(format!("[resource {uri}]\n{t}"));
                        } else {
                            blocks.push(format!(
                                "[resource {uri}: {}, {} bytes, not shown]",
                                r.get("mimeType").and_then(Value::as_str).unwrap_or("unknown type"),
                                blob_size(&r["blob"])
                            ));
                        }
                    }
                    other => blocks.push(format!("[content of type {other} not shown]")),
                }
            }
            if !has_text {
                if let Some(sc) = v.get("structuredContent").filter(|s| !s.is_null()) {
                    blocks.push(serde_json::to_string_pretty(sc).unwrap_or_default());
                }
            }
            let text = if blocks.is_empty() { "(no content)".to_string() } else { blocks.join("\n\n") };
            if v.get("isError").and_then(Value::as_bool) == Some(true) {
                (ToolStatus::Error, "error".to_string(), text)
            } else {
                (ToolStatus::Ok, "ok".to_string(), text)
            }
        }
        Err(CallError::Rpc { code, message, data }) => {
            let mut text = message;
            if let Some(d) = data.filter(|d| !d.is_null()) {
                text.push('\n');
                text.push_str(&d.to_string());
            }
            (ToolStatus::Error, format!("mcp error {code}"), text)
        }
        Err(CallError::Timeout { after_s }) => (
            ToolStatus::Timeout,
            format!("stopped after {after_s}s"),
            format!("The server `{server}` did not answer within {after_s}s (timeout_s); the call was cancelled."),
        ),
        Err(CallError::Interrupted) => {
            (ToolStatus::Interrupted, "interrupted".to_string(), format!("The call to `{server}` was stopped."))
        }
        Err(CallError::Failed { reason, stderr_tail }) => {
            let mut text = format!("The server `{server}` failed: {reason}");
            if !stderr_tail.is_empty() {
                text.push_str("\nlast lines of its stderr:\n");
                text.push_str(&stderr_tail.join("\n"));
            }
            (ToolStatus::Error, "error".to_string(), text)
        }
    };
    let mut out = ToolOutput::ok(outcome, Body::Message(text));
    out.status = status;
    out = out.with_more(server.to_string());
    if restarted {
        out = out.with_more("server restarted");
    }
    out.with_images(&images)
}

/// One server tool presented to the model.
pub struct McpTool {
    pub handle: Arc<McpHandle>,
    /// The presented name (`mcp__…`).
    pub name: String,
    pub def: McpToolDef,
}

#[async_trait::async_trait]
impl Tool for McpTool {
    fn spec(&self) -> ToolSpec {
        let mut parameters = match &self.def.input_schema {
            Value::Object(o) if !o.is_empty() => Value::Object(o.clone()),
            _ => json!({"type": "object", "properties": {}}),
        };
        if let Some(o) = parameters.as_object_mut() {
            o.remove("$schema");
        }
        ToolSpec {
            name: self.name.clone(),
            description: self.def.description.chars().take(MAX_DESCRIPTION_CHARS).collect(),
            parameters,
            class: tool_class(&self.def, self.handle.server.cfg.trust_read_only_hints),
        }
    }

    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let _ = self.handle.shared.take_traffic();
        let (result, restarted) = self.handle.call_restarting(ctx, &self.def.name, Value::Object(args.clone())).await;
        let mut out = map_result(ctx, &self.handle.server.name, result, restarted);
        let made: Vec<_> = self
            .handle
            .shared
            .take_traffic()
            .into_iter()
            .filter_map(|raw| {
                let url = url::Url::parse(&raw.url).ok()?;
                let req = self.handle.redact_bytes(&raw.request);
                let resp = raw.response.as_deref().map(|r| self.handle.redact_bytes(r));
                let err = raw.error.as_deref().map(|e| self.handle.redact(e));
                crate::traffic::record(
                    ctx,
                    &crate::traffic::Made {
                        tool: &self.name,
                        url: &url,
                        method: "POST",
                        request: &req,
                        response: resp.as_deref(),
                        status: raw.status,
                        error: err,
                        response_cut: false,
                        unverified: false,
                        started: raw.started,
                        principal: None,
                    },
                )
            })
            .collect();
        out = out.with_exchanges(&made);
        if let Body::Message(t) = &out.body {
            out.body = Body::Message(self.handle.redact(t));
        }
        out
    }
}
