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
use std::sync::Arc;
use std::time::Duration;

use loom_core::config::McpServerCfg;
use loom_core::event::{McpListing, McpToolDef, ToolSpec};
use serde_json::{Map, Value};

use crate::{Tool, ToolCtx, ToolOutput};

/// The protocol versions this client works with, newest first; the first is the one it asks for.
pub const PROTOCOL_VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

/// Longest name a presented tool may have.
pub const MAX_TOOL_NAME: usize = 64;

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

impl McpServer {
    /// Resolve `env:`/`file:` sources (see the module CONTRACT).
    pub fn resolve(name: &str, cfg: &McpServerCfg) -> Result<McpServer, String> {
        let _ = (name, cfg);
        todo!("CONTRACTS-MCP M1")
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

/// One session's connection to one server.
pub struct McpHandle {
    server: McpServer,
    idle_close: Duration,
    // Implementation state (connection, ids, pending answers, stderr ring, counters) goes here.
}

impl McpHandle {
    pub fn new(server: McpServer, idle_close: Duration) -> Arc<McpHandle> {
        Arc::new(McpHandle { server, idle_close })
    }

    pub fn server(&self) -> &McpServer {
        &self.server
    }

    /// Connect if needed, then `tools/list` (all pages) into a listing. A failure is an `Err` with the
    /// reason and the last 40 stderr lines; the caller records it as the listing's `error`.
    pub async fn list(&self, ctx: &ToolCtx) -> Result<McpListing, String> {
        let _ = (ctx, self.idle_close);
        todo!("CONTRACTS-MCP M2, M3")
    }

    /// One `tools/call`. `Ok` is the result object (`content`, `structuredContent`, `isError`);
    /// `Err` is [`CallError`].
    pub async fn call(&self, ctx: &ToolCtx, tool: &str, args: Value) -> Result<Value, CallError> {
        let _ = (ctx, tool, args);
        todo!("CONTRACTS-MCP M2, M3, M5")
    }

    pub fn status(&self) -> McpStatus {
        todo!("CONTRACTS-MCP M7")
    }

    /// Close the connection (stdio: kill the group; HTTP: `DELETE` the session). A later call opens it again.
    pub async fn close(&self) {
        todo!("CONTRACTS-MCP M3")
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
    let _ = (server, tool);
    todo!("CONTRACTS-MCP M5")
}

/// The tools of `listing` a role gets, as `(presented name, def)` in listing order, and the names left
/// out by a collision after sanitising and cutting (M5, M6). `filter` is the server's `tools`.
pub fn presented_tools(listing: &McpListing, filter: Option<&[String]>) -> (Vec<(String, McpToolDef)>, Vec<String>) {
    let _ = (listing, filter);
    todo!("CONTRACTS-MCP M5, M6")
}

/// A call's outcome as a tool output (M5): body from the content blocks, images through
/// `ToolOutput::with_images`, status and outcome, the `{server}` fact and `restarted`.
pub fn map_result(ctx: &ToolCtx, server: &str, result: Result<Value, CallError>, restarted: bool) -> ToolOutput {
    let _ = (ctx, server, result, restarted);
    todo!("CONTRACTS-MCP M5")
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
        todo!("CONTRACTS-MCP M5")
    }

    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let _ = (ctx, args);
        todo!("CONTRACTS-MCP M5")
    }
}
