//! The HTTP API over a runtime, and the routes that serve the web UI.
//!
//! CONTRACT (bodies are placeholders for the implementer; public signatures and types are fixed;
//! handlers and helpers are yours). JSON types: `crate::wire` and `loom_agent::runtime`.
//!
//! ## Every request
//! In this order, before any handler runs (one middleware):
//! 1. `auth::host_allowed(Host, state.port)`, else `403` `{"error": "This address is not the loom
//!    daemon's own (Host header)."}`.
//! 2. For every method other than GET and HEAD: `auth::origin_allowed(Origin, state.port)`, else
//!    `403` `{"error": "Requests from other origins are refused."}`.
//! 3. Token: `auth::presented_token(Authorization, Cookie)` must match `state.token`
//!    (`auth::token_matches`). Exceptions: `GET /` (below) and `GET /healthz`. Otherwise `401`
//!    `{"error": "Missing or wrong access token. Run `loom open`, or send the token in ~/.loom/token as a Bearer token."}`.
//!
//! Every response carries `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.
//! Errors are `ErrorBody` JSON: a runtime error (`Err(sentence)`) is `404` when the sentence starts
//! with `There is no` or `No `, otherwise `409`; a body or query that does not parse is `400`
//! (`{"error": "The request body is not valid: {why}"}`); an unknown path is `404`. No handler
//! panics; a handler never holds a lock across an await.
//!
//! ## Web UI
//! - `GET /`: with a valid cookie → `ui::INDEX_HTML` (`text/html; charset=utf-8`). With
//!   `?token=<token>` that matches → `303` to `/` with `Set-Cookie: auth::session_cookie(token)`.
//!   Otherwise `401` with a small plain-text page: `Open the UI with `loom open` (it carries the
//!   access token).`
//! - `GET /app.js` and `GET /core.js` (`text/javascript; charset=utf-8`), `GET /style.css`
//!   (`text/css; charset=utf-8`). These need the token like everything else.
//! - All of them carry `Content-Security-Policy: ui::CSP` and `Referrer-Policy: no-referrer`.
//! - `GET /healthz` → `200` `ok` (no token; says nothing else).
//!
//! ## API (all under `/api`; JSON in, JSON out)
//! | Route | Does | Answers |
//! |---|---|---|
//! | `GET /status` | `runtime.health()`, counts from `sessions(true)` and `inbox()` | `StatusView` |
//! | `GET /sessions?archived=true` | `runtime.sessions(archived)` (default false) | `[SessionInfo]` |
//! | `POST /sessions` (`NewSession`) | `runtime.create_session` | `201` `SessionInfo` |
//! | `GET /sessions/{id}` | the session and its children (sessions whose `parent` is it) | `SessionDetail` |
//! | `GET /sessions/{id}/records?after={seq}&limit={n}` | `runtime.records` (`limit` default 500, at most 2000) | `RecordsPage` (`next_after` = last seq of the page when the page is full, else `null`) |
//! | `GET /sessions/{id}/stream?after={seq}` | see *Streams* | SSE |
//! | `POST /sessions/{id}/messages` (`MessageBody`) | `runtime.send_message` | `202` `{}` |
//! | `POST /sessions/{id}/stop` | `runtime.stop` | `202` `{}` |
//! | `POST /sessions/{id}/resume` | `runtime.resume` | `202` `{}` |
//! | `POST /sessions/{id}/reweave` | `runtime.reweave` | `202` `{}` |
//! | `POST /sessions/{id}/archive` (`ArchiveBody`) | `runtime.archive` | `200` `{}` |
//! | `GET /sessions/{id}/window` | `runtime.window` | `WindowView` |
//! | `GET /sessions/{id}/net?limit={n}` | `runtime.net` (default 200, at most 2000) | `[NetEntry]` |
//! | `GET /missions` | `runtime.missions` | `[MissionInfo]` |
//! | `GET /missions/{id}/ledger` | `runtime.ledger` | `LedgerView` |
//! | `GET /inbox` | `runtime.inbox` | `[InboxEntry]` |
//! | `POST /inbox/{item_id}` (`AnswerBody`) | `runtime.answer` | `202` `{}` |
//! | `GET /blobs/{handle}` | `blobs.resolve` + `meta` | `BlobRef` |
//! | `GET /blobs/{handle}/raw` | the stored bytes | `application/octet-stream`, `Content-Disposition: attachment` |
//! | `GET /blobs/{handle}/lines?start={a}&end={b}` | `blobs.read_lines` (1-based inclusive; default `1..=2000`; at most 5000 lines per call) | `LinesView` |
//! | `GET /events?deltas=true` | see *Streams* | SSE |
//! | `POST /shutdown` | cancels `state.shutdown` | `202` `{}` |
//!
//! A session id that no session has is `404` `{"error": "There is no session {id}."}`; a handle
//! that does not resolve is `404` `{"error": "There is no stored output {handle}."}`. Blob bytes are
//! read with `spawn_blocking`.
//!
//! ## Streams (server-sent events)
//! Every event is one `data:` line holding one JSON object: a `BusEvent` in its serde form
//! (`{"type": "record", …}`). No `event:` field is used. A comment line (`: keep-alive`) is sent
//! every 15 s. Response headers: `Content-Type: text/event-stream`, `Cache-Control: no-store`,
//! `X-Accel-Buffering: no`.
//!
//! - `GET /events`: every `BusEvent` as published, except `Delta` unless `deltas=true`.
//! - `GET /sessions/{id}/stream`: first the session's records after `after` (query parameter; else
//!   the `Last-Event-ID` header; else from the beginning) as `Record` events, then live `Record`,
//!   `Delta` and `Status` events of that session. No record is skipped and none is sent twice:
//!   subscribe to the bus **before** reading the log, read the log in pages until a page is not
//!   full, remember the last seq sent, and drop live records at or below it. Record events carry
//!   `id: {seq}`. The stream starts with one `Status` event holding the session's current status.
//! - A subscriber that falls behind (`RecvError::Lagged(n)`) is sent `{"type": "lagged", "missed":
//!   n}` and the stream goes on. A stream ends when the client goes away or the daemon shuts down.
//!
//! Tests required (a real `Runtime` over a temporary home with a `loom_model::mock::MockServer`
//! as the model and `SandboxMode::None`; requests through `tower::ServiceExt::oneshot` or a bound
//! listener and `reqwest`; no real network):
//! - the three gates: wrong Host, foreign Origin on POST (and allowed on GET), missing/wrong token,
//!   token by header and by cookie; `GET /?token=` sets the cookie and redirects; a wrong token on
//!   `/?token=` is 401; `/healthz` needs nothing;
//! - UI files carry the CSP; every response has `no-store` and `nosniff`;
//! - create a session with a message, then: it is listed; its records page (`limit=2` pages through
//!   with `next_after`); its detail has children after a spawn; `window`; `status` counts;
//! - `stream`: replays from the start, then delivers a record appended after the stream opened;
//!   `after` and `Last-Event-ID` skip what was seen; no duplicate around the replay/live boundary
//!   (send a message while the replay is being read);
//! - `events` without and with `deltas`;
//! - message / stop / resume / archive / answer round trips, and their refusals as 409 with the
//!   runtime's sentence; unknown session and unknown handle as 404; a bad body as 400;
//! - blob meta, raw and lines (range clamped, default range);
//! - `POST /shutdown` cancels the token.

use axum::Router;
use loom_agent::runtime::Runtime;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// What the handlers share.
#[derive(Clone)]
pub struct ApiState {
    pub runtime: Runtime,
    pub token: Arc<String>,
    /// The address the listener is bound to, as text (`127.0.0.1:7878`).
    pub bind: String,
    /// Its port, for the Host and Origin checks.
    pub port: u16,
    pub started_ms: u64,
    /// Cancelled by `POST /api/shutdown`; the server stops when it is.
    pub shutdown: CancellationToken,
}

/// The whole application: UI routes, `/api`, and the gates in front of both.
pub fn router(state: ApiState) -> Router {
    let _ = state;
    todo!("implement per module contract")
}
