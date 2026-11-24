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
use loom_core::config::McpServerCfg;
use loom_core::event::{McpListing, McpToolDef, ToolClass, ToolSpec, ToolStatus};
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

/// One `env`/`headers` value: `env:NAME`, `file:/path` (trimmed) or the literal.
fn resolve_value(server: &str, kind: &str, key: &str, source: &str) -> Result<String, String> {
    let at = format!("mcp.servers.{server}.{kind}.{key}");
    if let Some(var) = source.strip_prefix("env:") {
        return match std::env::var(var) {
            Ok(v) => Ok(v),
            Err(_) => Err(format!("{at}: the environment variable {var} is not set")),
        };
    }
    if let Some(path) = source.strip_prefix("file:") {
        return match std::fs::read_to_string(path) {
            Ok(v) => Ok(v.trim().to_string()),
            Err(e) => Err(format!("{at}: the file {path} could not be read ({})", e.kind())),
        };
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

    /// Remove every resolved secret of the server from `text`.
    fn redact(&self, text: &str) -> String {
        let mut out = text.to_string();
        for v in self.server.env.values().chain(self.server.headers.values()) {
            if !v.is_empty() {
                out = out.replace(v.as_str(), "[redacted]");
            }
        }
        out
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
fn image_block(ctx: &ToolCtx, block: &Value, images: &mut Vec<loom_core::ImageRef>) -> String {
    let mime = block.get("mimeType").and_then(Value::as_str).unwrap_or("image");
    let size = blob_size(&block["data"]);
    let not_kept = format!("[image not kept: {mime}, {size} bytes]");
    if size > ctx.cfg.max_image_bytes {
        return not_kept;
    }
    let Some(bytes) = block.get("data").and_then(Value::as_str).and_then(decode) else { return not_kept };
    let Some(info) = loom_core::image::detect(&bytes) else { return not_kept };
    match ctx.blobs.put_bytes(&bytes) {
        Ok(stored) => {
            images.push(loom_core::ImageRef {
                blob: stored.id.as_str().to_string(),
                mime: info.mime.to_string(),
                bytes: bytes.len() as u64,
                width: info.width,
                height: info.height,
                name: None,
            });
            format!("[image: {}x{} {}, {}]", info.width, info.height, info.mime, loom_core::image::size_label(size))
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
            class: if self.def.read_only_hint == Some(true) { ToolClass::Read } else { ToolClass::Exec },
        }
    }

    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let (result, restarted) = self.handle.call_restarting(ctx, &self.def.name, Value::Object(args.clone())).await;
        let mut out = map_result(ctx, &self.handle.server.name, result, restarted);
        if let Body::Message(t) = &out.body {
            out.body = Body::Message(self.handle.redact(t));
        }
        out
    }
}
