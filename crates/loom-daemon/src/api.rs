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
//! 3. Token: `auth::bearer_token(Authorization)` must match `state.token` (`auth::token_matches`)
//!    or be a live web-session secret (`state.logins`); there are no cookies. Exceptions: `GET /`,
//!    `GET /healthz`, the three static assets and `POST /api/web-sessions`. Otherwise `401`
//!    `{"error": "Missing or wrong access token. Run `loom open`, or send the token in ~/.loom/token as a Bearer token."}`.
//!
//! Every response carries `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.
//! Errors are `ErrorBody` JSON: a runtime error (`Err(sentence)`) is `404` when the sentence starts
//! with `There is no` or `No `, otherwise `409`; a body or query that does not parse is `400`
//! (`{"error": "The request body is not valid: {why}"}`); an unknown path is `404`. No handler
//! panics; a handler never holds a lock across an await.
//!
//! ## Web UI
//! - `GET /`: `ui::INDEX_HTML` (`text/html; charset=utf-8`), no authentication. With
//!   `?token=<token>` that matches → `303` to `/#code=<fresh login code>` (no cookie); with a
//!   wrong token → `401` with a small plain-text page: `Open the UI with `loom open` (it carries
//!   the access token).` The page itself (not the redirect, not the 401) answers a request that
//!   still carries the token cookie of an older daemon (`auth::LEGACY_COOKIE`) with
//!   `Set-Cookie: auth::FORGET_LEGACY_COOKIE`, which removes it; the cookie is never a credential.
//! - `GET /app.js` and `GET /core.js` (`text/javascript; charset=utf-8`), `GET /style.css`
//!   (`text/css; charset=utf-8`). No authentication.
//! - `POST /api/login-codes` (API token only) → `{"code", "expires_in_s"}`; `POST /api/web-sessions`
//!   `{"code"}` (no Authorization) → `{"secret"}`, a bearer for the other `/api` routes.
//! - All of them carry `Content-Security-Policy: ui::CSP` and `Referrer-Policy: no-referrer`.
//! - `GET /healthz` → `200` `ok` (no token; says nothing else). `?nonce=<32..128 hex>` →
//!   `{"ok":true,"proof":hex(HMAC-SHA256(token, "loom-healthz-v1:"+nonce))}`; any other nonce is `400`.
//!
//! ## API (all under `/api`; JSON in, JSON out)
//! | Route | Does | Answers |
//! |---|---|---|
//! | `GET /status` | `runtime.health()`, counts from `sessions(true)` and `inbox()`, `statvfs` of the loom home on a blocking thread (`disk`, `null` when it cannot be read) | `StatusView` |
//! | `GET /sessions?archived=true` | `runtime.sessions(archived)` (default false) | `[SessionInfo]` |
//! | `POST /sessions` (`NewSession`) | `runtime.create_session` | `201` `SessionInfo` |
//! | `GET /sessions/{id}` | the session and its children (sessions whose `parent` is it) | `SessionDetail` |
//! | `GET /sessions/{id}/records?after={seq}&limit={n}` | `runtime.records` (`limit` default 500, at most 2000) | `RecordsPage` (`next_after` = last seq of the page when the page is full, else `null`) |
//! | `GET /sessions/{id}/stream?after={seq}` | see *Streams* | SSE |
//! | `POST /sessions/{id}/messages` (`MessageBody`) | `runtime.send_message` | `202` `{}` |
//! | `POST /sessions/{id}/rules` (`RuleBody`) | `runtime.add_rule` (a child's id goes to its lead) | `202` `RuleReceipt` (`queued`: the lead is in a turn and records it at its next step) |
//! | `POST /sessions/{id}/approvals` (`ApprovalBody`; `scope` may be left out) | `runtime.approve` | `202` `RuleReceipt` |
//! | `POST /sessions/{id}/rules/{rule_id}/withdraw` (`WithdrawBody`; `reason` may be left out) | `runtime.withdraw_rule` (`404` when the mission has no such rule, `409` when it is already withdrawn) | `202` `RuleReceipt` |
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
//! | `POST /gc` (`GcBody`) | `runtime.gc(apply, None)` | `200` `SweepReport` |
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
//!   token by header; a cookie carrying the token is refused; `/`, the static assets and `/healthz`
//!   need nothing; `GET /?token=` redirects to `/#code=` and sets no cookie; a wrong token on
//!   `/?token=` is 401; the index page expires the token cookie of an older daemon and nothing
//!   else ever sends `Set-Cookie`;
//! - login codes: minted with the API token only, exchanged once, refused when wrong, used or
//!   expired; a web-session secret opens `/api` but cannot mint codes; the Host and Origin checks
//!   apply to the exchange; outstanding codes and web sessions are bounded;
//! - UI files, the 401 page and the redirect carry the CSP; every response has `no-store` and
//!   `nosniff`;
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

use crate::auth;
use crate::ui;
use crate::wire::{
    AnswerBody, ApprovalBody, ArchiveBody, DiskSpace, ErrorBody, GcBody, LinesView, MessageBody, RecordsPage,
    RuleBody, SessionDetail, StatusView, WithdrawBody,
};
use axum::body::{Body, Bytes};
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use loom_agent::runtime::{BusEvent, NewSession, Runtime, SessionInfo};
use loom_agent::session::Phase;
use loom_core::event::Seq;
use loom_core::{BlobRef, MissionId, SessionId};
use serde::de::DeserializeOwned;
use serde_json::json;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
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
    /// Login codes and web-session secrets of the web UI.
    pub logins: Arc<auth::Logins>,
}

/// Records per page while a stream replays the log.
const REPLAY_PAGE: usize = 500;
const RECORDS_DEFAULT: usize = 500;
const RECORDS_MAX: usize = 2_000;
const NET_DEFAULT: usize = 200;
const NET_MAX: usize = 2_000;
const LINES_DEFAULT_END: u64 = 2_000;
const LINES_MAX: u64 = 5_000;
const KEEP_ALIVE: Duration = Duration::from_secs(15);
/// Events a stream task may queue for a client that reads slowly before it waits for it.
const STREAM_BUFFER: usize = 256;

const UI_NOT_OPENED: &str = "Open the UI with `loom open` (it carries the access token).";

/// The whole application: UI routes, `/api`, and the gates in front of both.
pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.js", get(|| async { asset("text/javascript; charset=utf-8", ui::APP_JS) }))
        .route("/core.js", get(|| async { asset("text/javascript; charset=utf-8", ui::CORE_JS) }))
        .route("/style.css", get(|| async { asset("text/css; charset=utf-8", ui::STYLE_CSS) }))
        .route("/healthz", get(healthz))
        .route("/api/login-codes", post(login_code))
        .route("/api/web-sessions", post(web_session))
        .route("/api/status", get(status))
        .route("/api/sessions", get(list_sessions).post(create_session))
        .route("/api/sessions/{id}", get(session_detail))
        .route("/api/sessions/{id}/records", get(records))
        .route("/api/sessions/{id}/stream", get(session_stream))
        .route("/api/sessions/{id}/messages", post(message))
        .route("/api/sessions/{id}/rules", post(add_rule))
        .route("/api/sessions/{id}/approvals", post(approve))
        .route("/api/sessions/{id}/rules/{rule_id}/withdraw", post(withdraw_rule))
        .route("/api/sessions/{id}/stop", post(stop))
        .route("/api/sessions/{id}/resume", post(resume))
        .route("/api/sessions/{id}/reweave", post(reweave))
        .route("/api/sessions/{id}/archive", post(archive))
        .route("/api/sessions/{id}/window", get(window))
        .route("/api/sessions/{id}/net", get(net))
        .route("/api/missions", get(missions))
        .route("/api/missions/{id}/ledger", get(ledger))
        .route("/api/inbox", get(inbox))
        .route("/api/inbox/{item_id}", post(answer))
        .route("/api/blobs/{handle}", get(blob_meta))
        .route("/api/blobs/{handle}/raw", get(blob_raw))
        .route("/api/blobs/{handle}/lines", get(blob_lines))
        .route("/api/events", get(events))
        .route("/api/gc", post(gc))
        .route("/api/shutdown", post(shutdown))
        .fallback(not_found)
        .layer(middleware::from_fn_with_state(state.clone(), gate))
        .with_state(state)
}

// ---------------------------------------------------------------------------------------------
// Errors and small helpers

struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> ApiError {
        ApiError { status, message: message.into() }
    }

    fn bad_body(why: impl std::fmt::Display) -> ApiError {
        ApiError::new(StatusCode::BAD_REQUEST, format!("The request body is not valid: {why}"))
    }

    fn bad_query(why: impl std::fmt::Display) -> ApiError {
        ApiError::new(StatusCode::BAD_REQUEST, format!("The request query is not valid: {why}"))
    }

    fn no_session(id: &str) -> ApiError {
        ApiError::new(StatusCode::NOT_FOUND, format!("There is no session {id}."))
    }

    fn no_blob(handle: &str) -> ApiError {
        ApiError::new(StatusCode::NOT_FOUND, format!("There is no stored output {handle}."))
    }

    /// `candidates` holds at most `BLOB_CANDIDATES + 1` ids; the extra one only says there are more than are listed.
    fn ambiguous_blob(handle: &str, candidates: &[loom_core::BlobId]) -> ApiError {
        let listed = &candidates[..candidates.len().min(BLOB_CANDIDATES)];
        // Long enough to tell the listed ones apart: past what they share, and never under the usual 16.
        let shared = listed
            .iter()
            .skip(1)
            .map(|c| c.as_str().bytes().zip(listed[0].as_str().bytes()).take_while(|(a, b)| a == b).count())
            .min()
            .unwrap_or(0);
        let width = (shared + 4).clamp(16, 64);
        let ids: Vec<String> = listed.iter().map(|c| c.as_str().chars().take(width).collect()).collect();
        let count = if candidates.len() > BLOB_CANDIDATES { "several".to_string() } else { listed.len().to_string() };
        ApiError::new(
            StatusCode::CONFLICT,
            format!("The handle {handle} matches {count} stored outputs ({}). Give more of the id.", ids.join(", ")),
        )
    }

    fn unreadable_blob(handle: &str, why: impl std::fmt::Display) -> ApiError {
        ApiError::new(StatusCode::CONFLICT, format!("Cannot read stored output {handle}: {why}."))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(ErrorBody { error: self.message })).into_response()
    }
}

type Res<T> = Result<T, ApiError>;

/// A runtime refusal: `404` when it says something does not exist, else `409`.
fn rt_err(sentence: String) -> ApiError {
    let status = if sentence.starts_with("There is no") || sentence.starts_with("No ") {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::CONFLICT
    };
    ApiError::new(status, sentence)
}

fn accepted() -> Response {
    (StatusCode::ACCEPTED, Json(json!({}))).into_response()
}

fn ok_empty() -> Response {
    (StatusCode::OK, Json(json!({}))).into_response()
}

type RawQuery = Result<Query<HashMap<String, String>>, QueryRejection>;

fn params(q: RawQuery) -> Res<HashMap<String, String>> {
    q.map(|Query(m)| m).map_err(|e| ApiError::bad_query(e.body_text()))
}

fn number(q: &HashMap<String, String>, key: &str) -> Res<Option<u64>> {
    match q.get(key) {
        None => Ok(None),
        Some(v) => v
            .trim()
            .parse::<u64>()
            .map(Some)
            .map_err(|_| ApiError::bad_query(format!("{key} must be a whole number, not \"{v}\"."))),
    }
}

fn flag(q: &HashMap<String, String>, key: &str) -> Res<Option<bool>> {
    match q.get(key).map(|v| v.trim()) {
        None => Ok(None),
        Some("true") => Ok(Some(true)),
        Some("false") => Ok(Some(false)),
        Some(v) => Err(ApiError::bad_query(format!("{key} must be true or false, not \"{v}\"."))),
    }
}

fn json_body<T: DeserializeOwned>(body: &Bytes) -> Res<T> {
    serde_json::from_slice(body).map_err(ApiError::bad_body)
}

fn clamp_limit(requested: Option<u64>, default: usize, max: usize) -> usize {
    requested.map(|n| usize::try_from(n).unwrap_or(max)).unwrap_or(default).clamp(1, max)
}

/// How many candidate ids an ambiguous-handle answer lists at most.
const BLOB_CANDIDATES: usize = 5;

/// The stored output a handle means; an ambiguous handle is a 409 that lists the candidates, anything else 404.
fn resolve_blob(blobs: &loom_core::blob::BlobStore, handle: &str) -> Res<loom_core::BlobId> {
    blobs.resolve(handle).map_err(|_| {
        let candidates = blobs.candidates(handle, BLOB_CANDIDATES + 1);
        if candidates.len() > 1 {
            ApiError::ambiguous_blob(handle, &candidates)
        } else {
            ApiError::no_blob(handle)
        }
    })
}

/// Run blocking work off the async threads.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Res<T> + Send + 'static) -> Res<T> {
    match tokio::task::spawn_blocking(f).await {
        Ok(r) => r,
        Err(_) => Err(ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The daemon could not finish that read; try the request again.",
        )),
    }
}

// ---------------------------------------------------------------------------------------------
// The gates

fn presented(headers: &HeaderMap) -> Option<String> {
    auth::bearer_token(headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()))
}

/// Whether the request carries the API token itself.
fn token_ok(state: &ApiState, headers: &HeaderMap) -> bool {
    presented(headers).is_some_and(|t| auth::token_matches(&state.token, &t))
}

/// Whether the request carries the API token or a web-session secret.
fn bearer_ok(state: &ApiState, headers: &HeaderMap) -> bool {
    presented(headers).is_some_and(|t| auth::token_matches(&state.token, &t) || state.logins.session_ok(&t))
}

const UNAUTHORIZED: &str =
    "Missing or wrong access token. Run `loom open`, or send the token in ~/.loom/token as a Bearer token.";

fn refusal(status: StatusCode, message: &str) -> Response {
    ApiError::new(status, message).into_response()
}

/// The one middleware: Host, then Origin (unsafe methods), then the token; and the headers every
/// response carries.
async fn gate(State(state): State<ApiState>, req: Request, next: Next) -> Response {
    let response = admit(&state, req, next).await;
    seal(response)
}

async fn admit(state: &ApiState, req: Request, next: Next) -> Response {
    let headers = req.headers();
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
    if !auth::host_allowed(host, state.port) {
        return refusal(StatusCode::FORBIDDEN, "This address is not the loom daemon's own (Host header).");
    }
    let method = req.method();
    if method != Method::GET && method != Method::HEAD {
        // An Origin that is not text cannot be ours.
        let origin = headers.get(header::ORIGIN).map(|v| v.to_str().unwrap_or("?"));
        if !auth::origin_allowed(origin, state.port) {
            return refusal(StatusCode::FORBIDDEN, "Requests from other origins are refused.");
        }
    }
    // The page and its scripts hold no secret; a login code is its own credential.
    let path = req.uri().path();
    let exempt = (method == Method::GET && matches!(path, "/" | "/healthz" | "/app.js" | "/core.js" | "/style.css"))
        || (method == Method::POST && path == "/api/web-sessions");
    if !exempt && !bearer_ok(state, headers) {
        return refusal(StatusCode::UNAUTHORIZED, UNAUTHORIZED);
    }
    next.run(req).await
}

fn seal(mut response: Response) -> Response {
    // axum answers a known path with the wrong method with an empty 405; give it the usual body.
    if response.status() == StatusCode::METHOD_NOT_ALLOWED && !response.headers().contains_key(header::CONTENT_TYPE) {
        let allow = response.headers().get(header::ALLOW).cloned();
        response = refusal(StatusCode::METHOD_NOT_ALLOWED, "That method is not allowed on this path.");
        if let Some(allow) = allow {
            response.headers_mut().insert(header::ALLOW, allow);
        }
    }
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    response
}

/// `GET /healthz` answers `ok`; with `?nonce=<hex>` it answers `{"ok":true,"proof":…}`, which only a holder of the
/// API token can compute, so a client can tell this home's daemon from any other listener before it sends the token.
async fn healthz(State(s): State<ApiState>, q: RawQuery) -> Res<Response> {
    let q = params(q)?;
    let Some(nonce) = q.get("nonce") else { return Ok("ok".into_response()) };
    if !auth::valid_nonce(nonce) {
        return Err(ApiError::bad_query("nonce must be 32 to 128 hexadecimal characters."));
    }
    let proof = auth::healthz_proof(&s.token, nonce).ok_or_else(|| {
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "The daemon cannot compute a proof with its access token.")
    })?;
    Ok(Json(json!({ "ok": true, "proof": proof })).into_response())
}

async fn not_found() -> Response {
    refusal(StatusCode::NOT_FOUND, "There is no such path on the loom daemon.")
}

// ---------------------------------------------------------------------------------------------
// Web UI

fn with_ui_headers(mut response: Response) -> Response {
    let headers = response.headers_mut();
    if let Ok(csp) = HeaderValue::from_str(ui::CSP) {
        headers.insert(header::CONTENT_SECURITY_POLICY, csp);
    }
    headers.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    response
}

fn asset(content_type: &'static str, body: &'static str) -> Response {
    let mut response = Response::new(Body::from(body));
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    with_ui_headers(response)
}

fn unauthorized_page() -> Response {
    let mut response = Response::new(Body::from(UI_NOT_OPENED));
    *response.status_mut() = StatusCode::UNAUTHORIZED;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    with_ui_headers(response)
}

async fn index(State(s): State<ApiState>, headers: HeaderMap, q: RawQuery) -> Response {
    let query = q.map(|Query(m)| m).unwrap_or_default();
    // Older clients open `/?token=`: trade the token for a login code in the fragment, which the
    // browser never sends anywhere, and set no cookie.
    if let Some(token) = query.get("token") {
        if !auth::token_matches(&s.token, token) {
            return unauthorized_page();
        }
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::SEE_OTHER;
        if let Ok(location) = HeaderValue::from_str(&format!("/#code={}", s.logins.mint_code())) {
            response.headers_mut().insert(header::LOCATION, location);
        }
        return with_ui_headers(response);
    }
    let mut response = asset("text/html; charset=utf-8", ui::INDEX_HTML);
    // A browser that signed in to an older daemon still holds the API token in a cookie and sends
    // it to every port on this host. It opens nothing here; tell the browser to drop it.
    if headers.get_all(header::COOKIE).iter().any(|v| v.to_str().is_ok_and(auth::names_legacy_cookie)) {
        response.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_static(auth::FORGET_LEGACY_COOKIE));
    }
    response
}

/// `POST /api/login-codes`: a single-use code for the web UI. Only the API token may ask.
async fn login_code(State(s): State<ApiState>, headers: HeaderMap) -> Response {
    if !token_ok(&s, &headers) {
        return refusal(StatusCode::UNAUTHORIZED, UNAUTHORIZED);
    }
    let code = s.logins.mint_code();
    Json(json!({ "code": code, "expires_in_s": auth::CODE_TTL.as_secs() })).into_response()
}

#[derive(serde::Deserialize)]
struct CodeBody {
    code: String,
}

/// `POST /api/web-sessions`: a login code for a web-session secret.
async fn web_session(State(s): State<ApiState>, body: Bytes) -> Res<Response> {
    let body: CodeBody = json_body(&body)?;
    match s.logins.redeem(&body.code) {
        Some(secret) => Ok(Json(json!({ "secret": secret })).into_response()),
        None => Ok(refusal(StatusCode::UNAUTHORIZED, UNAUTHORIZED)),
    }
}

// ---------------------------------------------------------------------------------------------
// API: sessions, missions, inbox

/// Free and total bytes of the volume that holds `path` (`statvfs`); `None` when they cannot be read.
fn disk_space(path: &std::path::Path) -> Option<DiskSpace> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: `statvfs` is plain integers, for which all-zero is a valid value.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c_path` is a NUL-terminated string and `st` a live, exclusively borrowed `statvfs`.
    if unsafe { libc::statvfs(c_path.as_ptr(), &mut st) } != 0 {
        return None;
    }
    // Counts are in fragments (`f_frsize`); a file system that leaves that 0 counts in blocks.
    let unit = u128::from(if st.f_frsize > 0 { st.f_frsize } else { st.f_bsize });
    let free_bytes = u64::try_from(u128::from(st.f_bavail) * unit).ok()?;
    let total_bytes = u64::try_from(u128::from(st.f_blocks) * unit).ok()?;
    (total_bytes > 0 && free_bytes <= total_bytes).then_some(DiskSpace { free_bytes, total_bytes })
}

async fn status(State(s): State<ApiState>) -> Json<StatusView> {
    let models = s.runtime.health().await;
    // Off the async threads: the loom home may be on a slow mount. A task that fails reads as unknown.
    let home = s.runtime.paths().home.clone();
    let disk = tokio::task::spawn_blocking(move || disk_space(&home)).await.ok().flatten();
    let sessions = s.runtime.sessions(true);
    let inbox_open = s.runtime.inbox().len();
    Json(StatusView {
        version: env!("CARGO_PKG_VERSION").to_string(),
        pid: std::process::id(),
        started_ms: s.started_ms,
        bind: s.bind.clone(),
        proxy_port: s.runtime.proxy_port(),
        home: s.runtime.paths().home.display().to_string(),
        disk,
        models,
        sessions_total: sessions.len(),
        sessions_active: sessions.iter().filter(|i| i.active).count(),
        sessions_running: sessions.iter().filter(|i| i.status.phase == Phase::Running).count(),
        inbox_open,
    })
}

async fn list_sessions(State(s): State<ApiState>, q: RawQuery) -> Res<Json<Vec<SessionInfo>>> {
    let archived = flag(&params(q)?, "archived")?.unwrap_or(false);
    Ok(Json(s.runtime.sessions(archived)))
}

async fn create_session(State(s): State<ApiState>, body: Bytes) -> Res<Response> {
    let new: NewSession = json_body(&body)?;
    let info = s.runtime.create_session(new).await.map_err(rt_err)?;
    Ok((StatusCode::CREATED, Json(info)).into_response())
}

fn known(s: &ApiState, id: &str) -> Res<SessionInfo> {
    s.runtime.session(&SessionId::from(id)).ok_or_else(|| ApiError::no_session(id))
}

async fn session_detail(State(s): State<ApiState>, Path(id): Path<String>) -> Res<Json<SessionDetail>> {
    let info = known(&s, &id)?;
    let mut children: Vec<SessionInfo> =
        s.runtime.sessions(true).into_iter().filter(|c| c.meta.parent.as_ref() == Some(&info.meta.id)).collect();
    // `sessions` lists newest first; children are shown oldest first.
    children.reverse();
    Ok(Json(SessionDetail { info, children }))
}

async fn records(State(s): State<ApiState>, Path(id): Path<String>, q: RawQuery) -> Res<Json<RecordsPage>> {
    let q = params(q)?;
    let after = number(&q, "after")?;
    let limit = clamp_limit(number(&q, "limit")?, RECORDS_DEFAULT, RECORDS_MAX);
    // The log is read from disk; keep that off the async workers.
    let runtime = s.runtime.clone();
    let records = blocking(move || runtime.records(&SessionId::from(id), after, limit).map_err(rt_err)).await?;
    let next_after = if records.len() >= limit { records.last().map(|r| r.seq) } else { None };
    Ok(Json(RecordsPage { records, next_after }))
}

async fn message(State(s): State<ApiState>, Path(id): Path<String>, body: Bytes) -> Res<Response> {
    let body: MessageBody = json_body(&body)?;
    s.runtime.send_message(&SessionId::from(id), &body.text).await.map_err(rt_err)?;
    Ok(accepted())
}

async fn add_rule(State(s): State<ApiState>, Path(id): Path<String>, body: Bytes) -> Res<Response> {
    let body: RuleBody = json_body(&body)?;
    let receipt = s.runtime.add_rule(&SessionId::from(id), &body.text).await.map_err(rt_err)?;
    Ok((StatusCode::ACCEPTED, Json(receipt)).into_response())
}

async fn approve(State(s): State<ApiState>, Path(id): Path<String>, body: Bytes) -> Res<Response> {
    let body: ApprovalBody = json_body(&body)?;
    let receipt = s.runtime.approve(&SessionId::from(id), &body.text, &body.scope).await.map_err(rt_err)?;
    Ok((StatusCode::ACCEPTED, Json(receipt)).into_response())
}

async fn withdraw_rule(
    State(s): State<ApiState>,
    Path((id, rule_id)): Path<(String, String)>,
    body: Bytes,
) -> Res<Response> {
    let body: WithdrawBody = json_body(&body)?;
    let receipt = s.runtime.withdraw_rule(&SessionId::from(id), &rule_id, &body.reason).await.map_err(rt_err)?;
    Ok((StatusCode::ACCEPTED, Json(receipt)).into_response())
}

async fn stop(State(s): State<ApiState>, Path(id): Path<String>) -> Res<Response> {
    s.runtime.stop(&SessionId::from(id)).await.map_err(rt_err)?;
    Ok(accepted())
}

async fn resume(State(s): State<ApiState>, Path(id): Path<String>) -> Res<Response> {
    s.runtime.resume(&SessionId::from(id)).await.map_err(rt_err)?;
    Ok(accepted())
}

async fn reweave(State(s): State<ApiState>, Path(id): Path<String>) -> Res<Response> {
    s.runtime.reweave(&SessionId::from(id)).await.map_err(rt_err)?;
    Ok(accepted())
}

async fn archive(State(s): State<ApiState>, Path(id): Path<String>, body: Bytes) -> Res<Response> {
    let body: ArchiveBody = json_body(&body)?;
    s.runtime.archive(&SessionId::from(id), body.archived).await.map_err(rt_err)?;
    Ok(ok_empty())
}

async fn window(State(s): State<ApiState>, Path(id): Path<String>) -> Res<Response> {
    let view = s.runtime.window(&SessionId::from(id)).map_err(rt_err)?;
    Ok(Json(view).into_response())
}

async fn net(State(s): State<ApiState>, Path(id): Path<String>, q: RawQuery) -> Res<Response> {
    let limit = clamp_limit(number(&params(q)?, "limit")?, NET_DEFAULT, NET_MAX);
    let entries = s.runtime.net(&SessionId::from(id), limit).map_err(rt_err)?;
    Ok(Json(entries).into_response())
}

async fn missions(State(s): State<ApiState>) -> Response {
    Json(s.runtime.missions()).into_response()
}

async fn ledger(State(s): State<ApiState>, Path(id): Path<String>) -> Res<Response> {
    let view = s.runtime.ledger(&MissionId::from(id)).map_err(rt_err)?;
    Ok(Json(view).into_response())
}

async fn inbox(State(s): State<ApiState>) -> Response {
    Json(s.runtime.inbox()).into_response()
}

async fn answer(State(s): State<ApiState>, Path(item_id): Path<String>, body: Bytes) -> Res<Response> {
    let body: AnswerBody = json_body(&body)?;
    s.runtime.answer(&item_id, &body.answer).await.map_err(rt_err)?;
    Ok(accepted())
}

async fn gc(State(s): State<ApiState>, body: Bytes) -> Res<Response> {
    let body: GcBody = json_body(&body)?;
    let report = s.runtime.gc(body.apply, None).await.map_err(rt_err)?;
    Ok(Json(report).into_response())
}

async fn shutdown(State(s): State<ApiState>) -> Response {
    s.shutdown.cancel();
    accepted()
}

// ---------------------------------------------------------------------------------------------
// API: stored outputs

async fn blob_meta(State(s): State<ApiState>, Path(handle): Path<String>) -> Res<Json<BlobRef>> {
    let blobs = s.runtime.blobs().clone();
    let meta = blocking(move || {
        let id = resolve_blob(&blobs, &handle)?;
        blobs.meta(&id).map_err(|e| ApiError::unreadable_blob(&handle, e))
    })
    .await?;
    Ok(Json(meta))
}

async fn blob_raw(State(s): State<ApiState>, Path(handle): Path<String>) -> Res<Response> {
    let blobs = s.runtime.blobs().clone();
    let (id, bytes) = blocking(move || {
        let id = resolve_blob(&blobs, &handle)?;
        let bytes = blobs.read_all(&id).map_err(|e| ApiError::unreadable_blob(&handle, e))?;
        Ok((id, bytes))
    })
    .await?;
    let mut response = Response::new(Body::from(bytes));
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    let disposition = format!("attachment; filename=\"out-{}\"", id.as_str().chars().take(16).collect::<String>());
    if let Ok(value) = HeaderValue::from_str(&disposition) {
        headers.insert(header::CONTENT_DISPOSITION, value);
    }
    Ok(response)
}

async fn blob_lines(State(s): State<ApiState>, Path(handle): Path<String>, q: RawQuery) -> Res<Json<LinesView>> {
    let q = params(q)?;
    let start = number(&q, "start")?.unwrap_or(1).max(1);
    let end = number(&q, "end")?.unwrap_or(LINES_DEFAULT_END).min(start.saturating_add(LINES_MAX - 1));
    let blobs = s.runtime.blobs().clone();
    let slice = blocking(move || {
        let id = resolve_blob(&blobs, &handle)?;
        blobs.read_lines(&id, start, end).map_err(|e| ApiError::unreadable_blob(&handle, e))
    })
    .await?;
    Ok(Json(LinesView { text: slice.text, first: slice.first, last: slice.last, total: slice.total }))
}

// ---------------------------------------------------------------------------------------------
// Streams

/// One bus event as an SSE event; records carry their seq as the event id.
fn sse_event(event: &BusEvent) -> Option<Event> {
    let data = serde_json::to_string(event).ok()?;
    let out = Event::default().data(data);
    Some(match event {
        BusEvent::Record { record, .. } => out.id(record.seq.to_string()),
        _ => out,
    })
}

/// Queue `event`; false when the client has gone.
async fn push(tx: &mpsc::Sender<Event>, event: &BusEvent) -> bool {
    match sse_event(event) {
        Some(e) => tx.send(e).await.is_ok(),
        None => true,
    }
}

fn sse_response(rx: mpsc::Receiver<Event>) -> Response {
    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|e| (Ok::<Event, Infallible>(e), rx))
    });
    let mut response = Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(KEEP_ALIVE).text("keep-alive"))
        .into_response();
    response.headers_mut().insert("x-accel-buffering", HeaderValue::from_static("no"));
    response
}

async fn events(State(s): State<ApiState>, q: RawQuery) -> Res<Response> {
    let deltas = flag(&params(q)?, "deltas")?.unwrap_or(false);
    let bus = s.runtime.subscribe();
    let (tx, rx) = mpsc::channel(STREAM_BUFFER);
    tokio::spawn(pump_events(bus, tx, deltas, s.shutdown.clone()));
    Ok(sse_response(rx))
}

async fn pump_events(
    mut bus: broadcast::Receiver<BusEvent>,
    tx: mpsc::Sender<Event>,
    deltas: bool,
    stop: CancellationToken,
) {
    loop {
        let next = tokio::select! {
            _ = tx.closed() => return,
            _ = stop.cancelled() => return,
            next = bus.recv() => next,
        };
        let event = match next {
            Ok(BusEvent::Delta { .. }) if !deltas => continue,
            Ok(event) => event,
            Err(broadcast::error::RecvError::Lagged(missed)) => BusEvent::Lagged { missed },
            Err(broadcast::error::RecvError::Closed) => return,
        };
        if !push(&tx, &event).await {
            return;
        }
    }
}

async fn session_stream(
    State(s): State<ApiState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    q: RawQuery,
) -> Res<Response> {
    let q = params(q)?;
    let after: Option<Seq> = match number(&q, "after")? {
        Some(a) => Some(a),
        None => headers
            .get("last-event-id")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<Seq>().ok()),
    };
    // Subscribe before the log is read: whatever is appended from here on arrives on the bus, and
    // what the log already holds is replayed.
    let bus = s.runtime.subscribe();
    let info = known(&s, &id)?;
    let (tx, rx) = mpsc::channel(STREAM_BUFFER);
    tokio::spawn(pump_session(s.runtime.clone(), info, after, bus, tx, s.shutdown.clone()));
    Ok(sse_response(rx))
}

/// Send the records after `*after` from the log, page by page, advancing `*after`. False when the
/// stream should end (client gone, or the log cannot be read).
async fn replay(runtime: &Runtime, id: &SessionId, after: &mut Option<Seq>, tx: &mpsc::Sender<Event>) -> bool {
    loop {
        let page = {
            let (runtime, sid, from) = (runtime.clone(), id.clone(), *after);
            match tokio::task::spawn_blocking(move || runtime.records(&sid, from, REPLAY_PAGE)).await {
                Ok(Ok(page)) => page,
                Ok(Err(message)) => {
                    let _ = push(tx, &BusEvent::Error { session: Some(id.clone()), message }).await;
                    return false;
                }
                Err(_) => return false,
            }
        };
        let full = page.len() >= REPLAY_PAGE;
        for record in page {
            *after = Some(record.seq);
            let event = BusEvent::Record { session: id.clone(), record: Box::new(record) };
            if !push(tx, &event).await {
                return false;
            }
        }
        if !full {
            return true;
        }
    }
}

async fn pump_session(
    runtime: Runtime,
    info: SessionInfo,
    mut after: Option<Seq>,
    mut bus: broadcast::Receiver<BusEvent>,
    tx: mpsc::Sender<Event>,
    stop: CancellationToken,
) {
    let id = info.meta.id.clone();
    if !push(&tx, &BusEvent::Status { session: id.clone(), status: info.status.clone() }).await {
        return;
    }
    if !replay(&runtime, &id, &mut after, &tx).await {
        return;
    }
    loop {
        let next = tokio::select! {
            _ = tx.closed() => return,
            _ = stop.cancelled() => return,
            next = bus.recv() => next,
        };
        let event = match next {
            Ok(event) => event,
            Err(broadcast::error::RecvError::Lagged(missed)) => {
                if !push(&tx, &BusEvent::Lagged { missed }).await {
                    return;
                }
                // Records among the missed events are still in the log.
                if !replay(&runtime, &id, &mut after, &tx).await {
                    return;
                }
                continue;
            }
            Err(broadcast::error::RecvError::Closed) => return,
        };
        let wanted = match &event {
            BusEvent::Record { session, record } if *session == id => {
                if after.is_some_and(|a| record.seq <= a) {
                    false
                } else {
                    after = Some(record.seq);
                    true
                }
            }
            BusEvent::Delta { session, .. } | BusEvent::Status { session, .. } => *session == id,
            _ => false,
        };
        if wanted && !push(&tx, &event).await {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loom_agent::runtime::Delta;
    use loom_core::config::{Config, ModelProfile, NetworkMode, Paths, SandboxMode};
    use loom_model::mock::{Action, MockServer, Reply, Script};
    use reqwest::Method;
    use serde_json::{json, Value};
    use std::path::PathBuf;

    const WAIT: Duration = Duration::from_secs(30);

    struct Env {
        dir: tempfile::TempDir,
        _server: MockServer,
        rt: Runtime,
        port: u16,
        token: String,
        http: reqwest::Client,
        shutdown: CancellationToken,
        ws: PathBuf,
        logins: Arc<auth::Logins>,
        serve: tokio::task::JoinHandle<()>,
    }

    impl Drop for Env {
        fn drop(&mut self) {
            self.serve.abort();
        }
    }

    fn has_tool(body: &Value, name: &str) -> bool {
        body["tools"].as_array().is_some_and(|t| t.iter().any(|x| x["function"]["name"] == name))
    }

    fn last_role(body: &Value) -> String {
        body["messages"]
            .as_array()
            .and_then(|m| m.iter().rev().find(|m| !m["content"].as_str().unwrap_or("").starts_with("<harness-state>")))
            .and_then(|m| m["role"].as_str())
            .unwrap_or("")
            .to_string()
    }

    fn call(name: &str, args: Value) -> Action {
        Action::Reply(Reply::tool(name, args.to_string()))
    }

    fn finish(answer: &str) -> Action {
        call("finish", json!({ "answer": answer }))
    }

    /// `finish` whose reply takes a while to arrive, so records are appended while a client reads.
    fn slow_finish(answer: &str, delay_ms: u64) -> Action {
        Action::Reply(Reply::tool("finish", json!({ "answer": answer }).to_string()).with_delay_ms(delay_ms))
    }

    async fn env(script: Script) -> Env {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let server = MockServer::start(script).await.unwrap();
        let mut config = Config::default();
        config.models.clear();
        config.models.insert(
            "mock".into(),
            ModelProfile {
                base_url: server.base_url(),
                model: "mock".into(),
                context_window: Some(1_000_000),
                retry_window_s: 1,
                retry_max_delay_s: 1,
                stall_timeout_s: 30,
                ..ModelProfile::default()
            },
        );
        config.default_model = "mock".into();
        config.sandbox.mode = SandboxMode::None;
        config.network.mode = NetworkMode::DenyAll;
        config.agents.verify_finish = false;
        config.tools.kill_grace_s = 1;
        let rt = Runtime::start(config, Paths::at(dir.path().join("home"))).await.unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let token = "ab".repeat(32);
        let shutdown = CancellationToken::new();
        let logins = Arc::new(auth::Logins::new());
        let state = ApiState {
            runtime: rt.clone(),
            token: Arc::new(token.clone()),
            bind: format!("127.0.0.1:{port}"),
            port,
            started_ms: 1_234,
            shutdown: shutdown.clone(),
            logins: logins.clone(),
        };
        let app = router(state);
        let serve = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        Env { dir, _server: server, rt, port, token, http, shutdown, ws, logins, serve }
    }

    async fn json_of(response: reqwest::Response) -> (u16, Value) {
        let status = response.status().as_u16();
        let text = response.text().await.unwrap_or_default();
        (status, serde_json::from_str(&text).unwrap_or(Value::String(text)))
    }

    impl Env {
        fn url(&self, path: &str) -> String {
            format!("http://127.0.0.1:{}{path}", self.port)
        }

        /// A request with the access token.
        fn rq(&self, method: Method, path: &str) -> reqwest::RequestBuilder {
            self.http.request(method, self.url(path)).bearer_auth(&self.token)
        }

        async fn get(&self, path: &str) -> (u16, Value) {
            json_of(self.rq(Method::GET, path).send().await.unwrap()).await
        }

        async fn post(&self, path: &str, body: Value) -> (u16, Value) {
            json_of(self.rq(Method::POST, path).json(&body).send().await.unwrap()).await
        }

        async fn post_text(&self, path: &str, body: &str) -> (u16, Value) {
            json_of(self.rq(Method::POST, path).body(body.to_string()).send().await.unwrap()).await
        }

        async fn create(&self, message: &str) -> String {
            let (status, body) = self.post("/api/sessions", json!({"workspace": self.ws, "message": message})).await;
            assert_eq!(status, 201, "{body}");
            body["id"].as_str().unwrap().to_string()
        }

        async fn records(&self, id: &str) -> Vec<Value> {
            let (status, body) = self.get(&format!("/api/sessions/{id}/records?limit=2000")).await;
            assert_eq!(status, 200, "{body}");
            body["records"].as_array().cloned().unwrap_or_default()
        }

        async fn wait_turn_ends(&self, id: &str, n: usize) {
            let end = tokio::time::Instant::now() + WAIT;
            loop {
                let count = self.records(id).await.iter().filter(|r| r["kind"] == "turn_end").count();
                if count >= n {
                    return;
                }
                assert!(tokio::time::Instant::now() < end, "timed out waiting for turn {n} to end");
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }

        /// The state of the mission's ledger once `done` holds for it.
        async fn ledger_state(&self, mission: &str, what: &str, done: impl Fn(&Value) -> bool) -> Value {
            let end = tokio::time::Instant::now() + WAIT;
            loop {
                let (_, ledger) = self.get(&format!("/api/missions/{mission}/ledger")).await;
                if done(&ledger["state"]) {
                    return ledger["state"].clone();
                }
                assert!(tokio::time::Instant::now() < end, "timed out waiting for {what} in the ledger");
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }

        async fn sse(&self, path: &str, headers: &[(&str, &str)]) -> Sse {
            let mut request = self.rq(Method::GET, path);
            for (k, v) in headers {
                request = request.header(*k, *v);
            }
            let response = request.send().await.unwrap();
            assert_eq!(response.status(), 200);
            Sse { response, buf: Vec::new() }
        }
    }

    /// A client of a server-sent event stream.
    struct Sse {
        response: reqwest::Response,
        buf: Vec<u8>,
    }

    impl Sse {
        /// The next event: its `id:` and its parsed `data:`. Comments are skipped.
        async fn next(&mut self) -> Option<(Option<String>, Value)> {
            loop {
                let text = String::from_utf8_lossy(&self.buf).into_owned();
                if let Some(at) = text.find("\n\n") {
                    let block = text[..at].to_string();
                    self.buf.drain(..at + 2);
                    let mut id = None;
                    let mut data = String::new();
                    for line in block.lines() {
                        if let Some(v) = line.strip_prefix("id:") {
                            id = Some(v.trim().to_string());
                        } else if let Some(v) = line.strip_prefix("data:") {
                            data.push_str(v.strip_prefix(' ').unwrap_or(v));
                        }
                    }
                    if data.is_empty() {
                        continue;
                    }
                    return Some((id, serde_json::from_str(&data).unwrap()));
                }
                match tokio::time::timeout(WAIT, self.response.chunk()).await {
                    Ok(Ok(Some(chunk))) => self.buf.extend_from_slice(&chunk),
                    Ok(_) => return None,
                    Err(_) => panic!("timed out waiting for the next stream event"),
                }
            }
        }

        /// Events up to and including the first for which `stop` is true.
        async fn until(&mut self, stop: impl Fn(&Value) -> bool) -> Vec<(Option<String>, Value)> {
            let mut out = Vec::new();
            while let Some((id, ev)) = self.next().await {
                let done = stop(&ev);
                out.push((id, ev));
                if done {
                    return out;
                }
            }
            panic!("the stream ended before the awaited event; got {out:?}");
        }
    }

    fn is_turn_end(ev: &Value) -> bool {
        ev["type"] == "record" && ev["record"]["kind"] == "turn_end"
    }

    fn record_seqs(events: &[(Option<String>, Value)]) -> Vec<u64> {
        events.iter().filter(|(_, e)| e["type"] == "record").map(|(_, e)| e["record"]["seq"].as_u64().unwrap()).collect()
    }

    fn assert_contiguous_from(seqs: &[u64], first: u64) {
        let want: Vec<u64> = (first..first + seqs.len() as u64).collect();
        assert_eq!(seqs, want.as_slice(), "records must arrive once each, in order");
    }

    fn lead_script(child_args: Value) -> Script {
        Script::new(move |body, _| {
            if has_tool(body, "agent_spawn") {
                if last_role(body) == "tool" {
                    finish("lead done")
                } else {
                    call("agent_spawn", child_args.clone())
                }
            } else {
                finish("child report")
            }
        })
    }

    // --- the gates -------------------------------------------------------------------------

    #[tokio::test]
    async fn the_gates_run_host_then_origin_then_token() {
        let e = env(Script::new(|_, _| finish("x"))).await;
        let anon = |m: Method, p: &str| e.http.request(m, e.url(p));

        // Host first, whatever else is wrong.
        let (s, b) = json_of(anon(Method::GET, "/api/status").header("Host", "evil.example").send().await.unwrap()).await;
        assert_eq!((s, b["error"].as_str().unwrap()), (403, "This address is not the loom daemon's own (Host header)."));
        let wrong_port = format!("127.0.0.1:{}", e.port.wrapping_add(1));
        let (s, _) = json_of(e.rq(Method::GET, "/api/status").header("Host", wrong_port).send().await.unwrap()).await;
        assert_eq!(s, 403);
        let (s, _) = json_of(
            anon(Method::POST, "/api/shutdown")
                .header("Host", "evil.example")
                .header("Origin", "http://evil.example")
                .send()
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(s, 403);
        let localhost = format!("localhost:{}", e.port);
        let (s, _) = json_of(e.rq(Method::GET, "/api/status").header("Host", localhost).send().await.unwrap()).await;
        assert_eq!(s, 200);

        // Origin next, for methods that change things; before the token is looked at.
        let (s, b) = json_of(
            anon(Method::POST, "/api/sessions/s-x/stop").header("Origin", "http://evil.example").send().await.unwrap(),
        )
        .await;
        assert_eq!((s, b["error"].as_str().unwrap()), (403, "Requests from other origins are refused."));
        let (s, _) = json_of(
            e.rq(Method::POST, "/api/sessions/s-x/stop").header("Origin", "http://evil.example").send().await.unwrap(),
        )
        .await;
        assert_eq!(s, 403);
        let own = format!("http://127.0.0.1:{}", e.port);
        let (s, b) = json_of(e.rq(Method::POST, "/api/sessions/s-x/stop").header("Origin", own).send().await.unwrap()).await;
        assert_eq!((s, b["error"].as_str().unwrap()), (404, "There is no session s-x."));
        // GET is not subject to the Origin check.
        let (s, _) = json_of(e.rq(Method::GET, "/api/status").header("Origin", "http://evil.example").send().await.unwrap()).await;
        assert_eq!(s, 200);

        // Then the token.
        let message = "Missing or wrong access token. Run `loom open`, or send the token in ~/.loom/token as a Bearer token.";
        let (s, b) = json_of(anon(Method::GET, "/api/status").send().await.unwrap()).await;
        assert_eq!((s, b["error"].as_str().unwrap()), (401, message));
        let (s, _) = json_of(anon(Method::GET, "/api/status").bearer_auth("nope").send().await.unwrap()).await;
        assert_eq!(s, 401);
        let (s, _) = json_of(anon(Method::POST, "/api/shutdown").send().await.unwrap()).await;
        assert_eq!(s, 401);
        assert!(!e.shutdown.is_cancelled());
        // The header carries it.
        let (s, _) = json_of(anon(Method::GET, "/api/status").bearer_auth(&e.token).send().await.unwrap()).await;
        assert_eq!(s, 200);
        // A cookie, even one carrying the token, is not a credential.
        let pair = format!("loom_token={}", e.token);
        let (s, _) = json_of(anon(Method::GET, "/api/status").header("Cookie", pair.clone()).send().await.unwrap()).await;
        assert_eq!(s, 401);
        let (s, _) = json_of(anon(Method::POST, "/api/shutdown").header("Cookie", pair).send().await.unwrap()).await;
        assert_eq!(s, 401);
        assert!(!e.shutdown.is_cancelled());
        // The page and its scripts need nothing.
        let (s, _) = json_of(anon(Method::GET, "/app.js").send().await.unwrap()).await;
        assert_eq!(s, 200);
    }

    #[tokio::test]
    async fn the_index_redirects_to_a_code_without_a_cookie_and_healthz_needs_nothing() {
        let e = env(Script::new(|_, _| finish("x"))).await;
        let anon = |p: &str| e.http.get(e.url(p));

        for path in ["/", "/app.js", "/core.js", "/style.css"] {
            let r = anon(path).send().await.unwrap();
            assert_eq!(r.status(), 200, "{path}");
            assert!(r.headers().get("set-cookie").is_none(), "{path}");
        }
        let r = anon("/").send().await.unwrap();
        assert!(r.headers()["content-type"].to_str().unwrap().starts_with("text/html; charset=utf-8"));
        assert_eq!(r.text().await.unwrap(), ui::INDEX_HTML);

        let r = anon(&format!("/?token={}", e.token)).send().await.unwrap();
        assert_eq!(r.status(), 303);
        assert!(r.headers().get("set-cookie").is_none());
        assert_eq!(r.headers()["content-security-policy"], ui::CSP);
        assert_eq!(r.headers()["referrer-policy"], "no-referrer");
        let location = r.headers()["location"].to_str().unwrap().to_string();
        let code = location.strip_prefix("/#code=").unwrap();
        assert!(!location.contains(&e.token));
        // The code in the fragment is a working one.
        let (s, b) = json_of(e.http.post(e.url("/api/web-sessions")).json(&json!({ "code": code })).send().await.unwrap()).await;
        assert_eq!(s, 200, "{b}");

        let r = anon("/?token=wrong").send().await.unwrap();
        assert_eq!(r.status(), 401);
        assert!(r.headers().get("set-cookie").is_none());
        assert_eq!(r.text().await.unwrap(), "Open the UI with `loom open` (it carries the access token).");
        let r = anon(&format!("/?token={}", "0".repeat(64))).send().await.unwrap();
        assert_eq!(r.status(), 401);

        let r = anon("/healthz").send().await.unwrap();
        assert_eq!((r.status().as_u16(), r.text().await.unwrap()), (200, "ok".to_string()));
    }

    #[tokio::test]
    async fn healthz_with_a_nonce_proves_the_token_without_authentication() {
        use hmac::{Hmac, Mac};
        let e = env(Script::new(|_, _| finish("x"))).await;
        let nonce = "ab12".repeat(8);
        let r = e.http.get(e.url(&format!("/healthz?nonce={nonce}"))).send().await.unwrap();
        let (s, b) = json_of(r).await;
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(e.token.as_bytes()).unwrap();
        mac.update(format!("loom-healthz-v1:{nonce}").as_bytes());
        let expected = hex::encode(mac.finalize().into_bytes());
        assert_eq!((s, b["ok"].clone(), b["proof"].as_str().unwrap()), (200, json!(true), expected.as_str()));
        // The longest nonce is fine; a different nonce gives a different proof.
        let long = "F".repeat(128);
        let (s, b2) = json_of(e.http.get(e.url(&format!("/healthz?nonce={long}"))).send().await.unwrap()).await;
        assert_eq!(s, 200);
        assert_ne!(b2["proof"], b["proof"]);
        for bad in ["", "abc", &"a".repeat(31), &"a".repeat(129), &format!("{}g", "a".repeat(40))] {
            let r = e.http.get(e.url(&format!("/healthz?nonce={bad}"))).send().await.unwrap();
            assert_eq!(r.status(), 400, "nonce {bad:?}");
        }
        let r = e.http.get(e.url("/healthz")).send().await.unwrap();
        assert_eq!((r.status().as_u16(), r.text().await.unwrap()), (200, "ok".to_string()));
    }

    #[tokio::test]
    async fn the_index_expires_the_token_cookie_of_an_older_daemon_and_nothing_else_sets_one() {
        let e = env(Script::new(|_, _| finish("x"))).await;
        let stale = format!("theme=dark; loom_token={}", e.token);
        let with_cookie = |p: &str| e.http.get(e.url(p)).header("Cookie", stale.clone());

        // The page tells the browser to drop it: same name and path, no value, already expired.
        let r = with_cookie("/").send().await.unwrap();
        assert_eq!(r.status(), 200);
        let set: Vec<&str> = r.headers().get_all("set-cookie").iter().map(|v| v.to_str().unwrap()).collect();
        assert_eq!(set, ["loom_token=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"]);
        assert_eq!(r.text().await.unwrap(), ui::INDEX_HTML);

        // Nothing is sent to a browser that does not hold it.
        let r = e.http.get(e.url("/")).header("Cookie", "theme=dark; loom_tokens=1").send().await.unwrap();
        assert_eq!(r.status(), 200);
        assert!(r.headers().get("set-cookie").is_none());

        // Only the page does it: not the redirect, the refusals, the assets or the API, and the
        // cookie opens nothing.
        let redirect = format!("/?token={}", e.token);
        for (path, status) in [(redirect.as_str(), 303u16), ("/?token=wrong", 401), ("/app.js", 200), ("/api/status", 401)] {
            let r = with_cookie(path).send().await.unwrap();
            assert_eq!(r.status(), status, "{path}");
            assert!(r.headers().get("set-cookie").is_none(), "{path}");
        }
        let r = with_cookie("/api/status").bearer_auth(&e.token).send().await.unwrap();
        assert_eq!(r.status(), 200);
        assert!(r.headers().get("set-cookie").is_none());
    }

    #[tokio::test]
    async fn login_codes_are_minted_once_exchanged_once_and_expire() {
        let e = env(Script::new(|_, _| finish("x"))).await;
        let exchange = |code: String| {
            let req = e.http.post(e.url("/api/web-sessions")).json(&json!({ "code": code }));
            async move { json_of(req.send().await.unwrap()).await }
        };
        let message = "Missing or wrong access token. Run `loom open`, or send the token in ~/.loom/token as a Bearer token.";

        // Minting needs the API token.
        let (s, _) = json_of(e.http.post(e.url("/api/login-codes")).send().await.unwrap()).await;
        assert_eq!(s, 401);
        let (s, b) = e.post("/api/login-codes", json!({})).await;
        assert_eq!(s, 200, "{b}");
        assert_eq!(b["expires_in_s"], 60);
        let code = b["code"].as_str().unwrap().to_string();

        // The code is exchanged once.
        let (s, b) = exchange(code.clone()).await;
        assert_eq!(s, 200, "{b}");
        let secret = b["secret"].as_str().unwrap().to_string();
        let (s, b) = exchange(code).await;
        assert_eq!((s, b["error"].as_str().unwrap()), (401, message));
        let (s, b) = exchange("0".repeat(32)).await;
        assert_eq!((s, b["error"].as_str().unwrap()), (401, message));

        // The secret opens the API but cannot mint codes.
        let as_web = |m: Method, p: &str| e.http.request(m, e.url(p)).bearer_auth(&secret);
        let (s, _) = json_of(as_web(Method::GET, "/api/status").send().await.unwrap()).await;
        assert_eq!(s, 200);
        let (s, _) = json_of(as_web(Method::POST, "/api/login-codes").send().await.unwrap()).await;
        assert_eq!(s, 401);

        // An expired code is refused.
        let old = std::time::Instant::now().checked_sub(auth::CODE_TTL + Duration::from_secs(1)).unwrap();
        let (s, b) = exchange(e.logins.mint_code_at(old)).await;
        assert_eq!((s, b["error"].as_str().unwrap()), (401, message));

        // The exchange still has the Host and Origin checks.
        let code = e.logins.mint_code();
        let r = e.http.post(e.url("/api/web-sessions")).header("Origin", "http://evil.example").json(&json!({ "code": code }));
        assert_eq!(json_of(r.send().await.unwrap()).await.0, 403);
        let r = e.http.post(e.url("/api/web-sessions")).header("Host", "evil.example").json(&json!({ "code": code }));
        assert_eq!(json_of(r.send().await.unwrap()).await.0, 403);
        assert_eq!(exchange(code).await.0, 200);
    }

    #[tokio::test]
    async fn outstanding_codes_and_sessions_are_bounded() {
        let e = env(Script::new(|_, _| finish("x"))).await;
        let exchange = |code: String| {
            let req = e.http.post(e.url("/api/web-sessions")).json(&json!({ "code": code }));
            async move { json_of(req.send().await.unwrap()).await }
        };
        let mut codes = Vec::new();
        for _ in 0..=auth::MAX_CODES {
            codes.push(e.post("/api/login-codes", json!({})).await.1["code"].as_str().unwrap().to_string());
        }
        assert_eq!(exchange(codes[0].clone()).await.0, 401, "the oldest code was dropped");
        let mut secrets = Vec::new();
        for code in &codes[1..] {
            let (s, b) = exchange(code.clone()).await;
            assert_eq!(s, 200);
            secrets.push(b["secret"].as_str().unwrap().to_string());
        }
        for _ in 0..auth::MAX_SESSIONS {
            let (_, b) = exchange(e.logins.mint_code()).await;
            secrets.push(b["secret"].as_str().unwrap().to_string());
        }
        let status = |secret: &str| e.http.get(e.url("/api/status")).bearer_auth(secret).send();
        assert_eq!(status(&secrets[0]).await.unwrap().status(), 401, "the oldest session was dropped");
        assert_eq!(status(secrets.last().unwrap()).await.unwrap().status(), 200);
    }

    #[tokio::test]
    async fn ui_files_carry_the_csp_and_every_response_is_sealed() {
        let e = env(Script::new(|_, _| finish("x"))).await;
        for (path, content_type, body) in [
            ("/", "text/html; charset=utf-8", ui::INDEX_HTML),
            ("/app.js", "text/javascript; charset=utf-8", ui::APP_JS),
            ("/core.js", "text/javascript; charset=utf-8", ui::CORE_JS),
            ("/style.css", "text/css; charset=utf-8", ui::STYLE_CSS),
        ] {
            let r = e.rq(Method::GET, path).send().await.unwrap();
            assert_eq!(r.status(), 200, "{path}");
            assert_eq!(r.headers()["content-type"], content_type, "{path}");
            assert_eq!(r.headers()["content-security-policy"], ui::CSP, "{path}");
            assert_eq!(r.headers()["referrer-policy"], "no-referrer", "{path}");
            assert_eq!(r.text().await.unwrap(), body, "{path}");
        }
        let unauthorized = e.http.get(e.url("/?token=wrong")).send().await.unwrap();
        assert_eq!(unauthorized.status(), 401);
        assert_eq!(unauthorized.headers()["content-security-policy"], ui::CSP);
        assert_eq!(unauthorized.headers()["referrer-policy"], "no-referrer");

        let wrong_method = e.rq(Method::DELETE, "/api/status").send().await.unwrap();
        let responses = [
            e.rq(Method::GET, "/api/status").send().await.unwrap(),
            e.http.get(e.url("/api/status")).send().await.unwrap(),
            e.http.get(e.url("/api/status")).header("Host", "evil.example").send().await.unwrap(),
            e.rq(Method::GET, "/api/nothing-here").send().await.unwrap(),
            e.rq(Method::GET, "/api/sessions/s-nope").send().await.unwrap(),
            e.http.get(e.url("/healthz")).send().await.unwrap(),
            e.rq(Method::GET, "/app.js").send().await.unwrap(),
            e.http.get(e.url("/")).send().await.unwrap(),
            wrong_method,
        ];
        let statuses: Vec<u16> = responses.iter().map(|r| r.status().as_u16()).collect();
        assert_eq!(statuses, vec![200, 401, 403, 404, 404, 200, 200, 200, 405]);
        for r in responses {
            assert_eq!(r.headers()["cache-control"], "no-store");
            assert_eq!(r.headers()["x-content-type-options"], "nosniff");
            if r.status() != 200 && r.url().path() != "/" {
                let (_, b) = json_of(r).await;
                assert!(b["error"].is_string(), "{b}");
            }
        }
    }

    // --- sessions ----------------------------------------------------------------------------

    #[tokio::test]
    async fn a_session_is_created_listed_paged_and_described() {
        let e = env(Script::new(|_, _| finish("all good"))).await;
        let id = e.create("do the thing").await;
        e.wait_turn_ends(&id, 1).await;

        let (s, list) = e.get("/api/sessions").await;
        assert_eq!(s, 200);
        assert_eq!(list.as_array().unwrap().len(), 1);
        assert_eq!(list[0]["id"], id.as_str());
        assert_eq!(list[0]["title"], "do the thing");

        // Paging with limit=2 reaches every record once.
        let all = e.records(&id).await;
        assert!(all.len() > 4);
        let mut seen: Vec<Value> = Vec::new();
        let mut after: Option<u64> = None;
        let mut pages = 0;
        loop {
            let path = match after {
                Some(a) => format!("/api/sessions/{id}/records?limit=2&after={a}"),
                None => format!("/api/sessions/{id}/records?limit=2"),
            };
            let (s, page) = e.get(&path).await;
            assert_eq!(s, 200);
            let records = page["records"].as_array().unwrap().clone();
            assert!(records.len() <= 2);
            if records.len() == 2 {
                assert_eq!(page["next_after"], records[1]["seq"]);
            } else {
                assert!(page["next_after"].is_null());
            }
            seen.extend(records);
            pages += 1;
            assert!(pages < 100);
            match page["next_after"].as_u64() {
                Some(n) => after = Some(n),
                None => break,
            }
        }
        assert_eq!(seen, all);
        assert_eq!(all[0]["seq"], 0);
        assert_eq!(all[0]["kind"], "session_start");

        let (s, w) = e.get(&format!("/api/sessions/{id}/window")).await;
        assert_eq!(s, 200);
        assert!(w["est_tokens"].as_u64().unwrap() > 0 && !w["items"].as_array().unwrap().is_empty());

        let (s, net) = e.get(&format!("/api/sessions/{id}/net?limit=5")).await;
        assert_eq!((s, net), (200, json!([])));

        let (s, detail) = e.get(&format!("/api/sessions/{id}")).await;
        assert_eq!(s, 200);
        assert_eq!(detail["id"], id.as_str());
        assert_eq!(detail["children"], json!([]));

        let (s, missions) = e.get("/api/missions").await;
        assert_eq!(s, 200);
        let mission = missions[0]["id"].as_str().unwrap().to_string();
        assert_eq!(missions[0]["root"], id.as_str());
        let (s, ledger) = e.get(&format!("/api/missions/{mission}/ledger")).await;
        assert_eq!(s, 200, "{ledger}");
        assert!(ledger["markdown"].is_string());
        let (s, b) = e.get("/api/missions/m-nope/ledger").await;
        assert_eq!(s, 404, "{b}");

        let end = tokio::time::Instant::now() + WAIT;
        let status = loop {
            let (s, status) = e.get("/api/status").await;
            assert_eq!(s, 200);
            if status["sessions_running"] == 0 || tokio::time::Instant::now() > end {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        };
        assert_eq!(status["sessions_total"], 1);
        assert_eq!(status["sessions_running"], 0);
        assert_eq!(status["inbox_open"], 1);
        assert_eq!(status["bind"], format!("127.0.0.1:{}", e.port).as_str());
        assert_eq!(status["started_ms"], 1_234);
        assert_eq!(status["pid"], std::process::id());
        assert_eq!(status["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(status["home"], e.dir.path().join("home").display().to_string().as_str());
        assert_eq!(status["proxy_port"], e.rt.proxy_port());
        assert_eq!(status["models"].as_array().unwrap().len(), 1);
        assert_eq!(status["models"][0]["profile"], "mock");
        assert!(status["sessions_active"].as_u64().unwrap() <= 1);
        // The volume of the loom home, read now.
        let disk = &status["disk"];
        let (free, total) = (disk["free_bytes"].as_u64().unwrap(), disk["total_bytes"].as_u64().unwrap());
        assert!(total > 0 && free <= total, "{status}");
    }

    #[test]
    fn disk_space_reads_the_volume_and_is_none_for_a_path_that_cannot_be_read() {
        let dir = tempfile::tempdir().unwrap();
        let here = disk_space(dir.path()).unwrap();
        assert!(here.total_bytes > 0 && here.free_bytes <= here.total_bytes, "{here:?}");
        assert_eq!(disk_space(&dir.path().join("missing")), None);
        assert_eq!(disk_space(std::path::Path::new("bad\0path")), None);
    }

    #[tokio::test]
    async fn a_detail_lists_the_children_a_spawn_made() {
        let e = env(lead_script(json!({"question": "CHILDMARK find it"}))).await;
        let id = e.create("go").await;
        e.wait_turn_ends(&id, 1).await;
        let (s, detail) = e.get(&format!("/api/sessions/{id}")).await;
        assert_eq!(s, 200);
        let children = detail["children"].as_array().unwrap();
        assert_eq!(children.len(), 1);
        assert_eq!(children[0]["parent"], id.as_str());
        let child = children[0]["id"].as_str().unwrap().to_string();

        // Only a mission's lead takes messages, resumes and is archived.
        let (s, b) = e.post(&format!("/api/sessions/{child}/messages"), json!({"text": "hi"})).await;
        assert_eq!(s, 409);
        assert!(b["error"].as_str().unwrap().starts_with("Messages go to the lead session"), "{b}");
        let (s, _) = e.post(&format!("/api/sessions/{child}/resume"), json!({})).await;
        assert_eq!(s, 409);
        let (s, _) = e.post(&format!("/api/sessions/{child}/archive"), json!({"archived": true})).await;
        assert_eq!(s, 409);
    }

    #[tokio::test]
    async fn rule_routes_record_for_the_lead_refuse_bad_input_and_the_ledger_route_checks_its_id() {
        let e = env(lead_script(json!({"question": "CHILDMARK find it"}))).await;
        let id = e.create("go").await;
        e.wait_turn_ends(&id, 1).await;
        // Once the runtime has seen the lead's turn end, a receipt says the lead took the input at once.
        let end = tokio::time::Instant::now() + WAIT;
        let detail = loop {
            let (_, detail) = e.get(&format!("/api/sessions/{id}")).await;
            if detail["status"]["phase"] == "idle" {
                break detail;
            }
            assert!(tokio::time::Instant::now() < end, "timed out waiting for the lead to be idle");
            tokio::time::sleep(Duration::from_millis(25)).await;
        };
        let child = detail["children"][0]["id"].as_str().unwrap().to_string();
        let (_, missions) = e.get("/api/missions").await;
        let mission = missions[0]["id"].as_str().unwrap().to_string();
        // What every accepted request answers: the lead it went to, whatever session was named.
        let receipt = |stock: Value| json!({"lead": id, "queued": false, "ledger": true, "stock": stock});

        let (s, b) = e.post(&format!("/api/sessions/{child}/rules"), json!({"text": " no prod\n"})).await;
        assert_eq!((s, b), (202, receipt(Value::Null)));
        let state = e.ledger_state(&mission, "the rule", |s| s["constraints"].get(0).is_some()).await;
        assert_eq!(state["constraints"][0]["text"], "no prod");
        let rule_id = state["constraints"][0]["id"].as_str().unwrap().to_string();

        // The scope of an approval and the reason of a withdrawal may be left out, as the command
        // line and the page do: both are recorded all the same.
        let (s, b) = e.post(&format!("/api/sessions/{id}/approvals"), json!({"text": "ship it", "scope": "staging"})).await;
        assert_eq!((s, b), (202, receipt(Value::Null)));
        let (s, b) = e.post(&format!("/api/sessions/{id}/approvals"), json!({"text": "run the tests"})).await;
        assert_eq!((s, b), (202, receipt(json!("only what the approval says"))));
        let two = |s: &Value| s["approvals"].as_array().is_some_and(|a| a.len() == 2);
        let approvals = e.ledger_state(&mission, "the approvals", two).await["approvals"].clone();
        assert_eq!((&approvals[0]["text"], &approvals[0]["scope"]), (&json!("ship it"), &json!("staging")));
        assert_eq!(approvals[1]["id"], "a2");
        assert_eq!(approvals[1]["text"], "run the tests");
        assert_eq!(approvals[1]["scope"], "only what the approval says");

        let withdraw = format!("/api/sessions/{id}/rules/{rule_id}/withdraw");
        let (s, b) = e.post(&withdraw, json!({"reason": "done"})).await;
        assert_eq!((s, b), (202, receipt(Value::Null)));
        let state = e.ledger_state(&mission, "the withdrawal", |s| !s["constraints"][0]["retired"].is_null()).await;
        assert_eq!(state["constraints"][0]["retired"], "done");
        let (s, b) = e.post(&format!("/api/sessions/{child}/rules"), json!({"text": "ask first"})).await;
        assert_eq!((s, b), (202, receipt(Value::Null)));
        e.ledger_state(&mission, "the second rule", |s| s["constraints"].get(1).is_some()).await;
        let (s, b) = e.post(&format!("/api/sessions/{child}/rules/k2/withdraw"), json!({})).await;
        assert_eq!((s, b), (202, receipt(json!("no reason given"))));
        let retired = |s: &Value| !s["constraints"][1]["retired"].is_null();
        let state = e.ledger_state(&mission, "the second withdrawal", retired).await;
        assert_eq!(state["constraints"][1]["retired"], "no reason given");

        // A withdrawal that would change nothing is refused rather than accepted and dropped.
        let (s, b) = e.post(&withdraw, json!({})).await;
        assert_eq!((s, b["error"].as_str().unwrap()), (409, "Rule k1 is already withdrawn."));
        let (s, b) = e.post(&format!("/api/sessions/{id}/rules/k9/withdraw"), json!({"reason": "typo"})).await;
        let none = "There is no rule k9 in this mission; it has no rules in force.";
        assert_eq!((s, b["error"].as_str().unwrap()), (404, none));

        let (s, b) = e.post(&format!("/api/sessions/{id}/rules"), json!({"text": "  "})).await;
        assert_eq!((s, b["error"].as_str().unwrap()), (409, "Write the rule to set."));
        let (s, b) = e.post(&format!("/api/sessions/{id}/approvals"), json!({"text": ""})).await;
        assert_eq!((s, b["error"].as_str().unwrap()), (409, "Write what is approved."));
        let (s, b) = e.post("/api/sessions/s-nope/rules", json!({"text": "x"})).await;
        assert_eq!((s, b["error"].as_str().unwrap()), (404, "There is no session s-nope."));
        let (s, _) = e.post("/api/sessions/s-nope/rules/k1/withdraw", json!({})).await;
        assert_eq!(s, 404);
        let (s, _) = e.post(&format!("/api/sessions/{id}/rules"), json!({"text": "x", "extra": 1})).await;
        assert_eq!(s, 400);

        // A mission whose lead keeps no ledger: the receipt says the rule is a note only, and a
        // withdrawal by id is refused with what to do instead.
        let (s, chat) = e.post("/api/sessions", json!({"workspace": e.ws, "role": "chat"})).await;
        assert_eq!(s, 201, "{chat}");
        let chat = chat["id"].as_str().unwrap().to_string();
        let (s, b) = e.post(&format!("/api/sessions/{chat}/rules"), json!({"text": "no prod"})).await;
        assert_eq!((s, b), (202, json!({"lead": chat, "queued": false, "ledger": false, "stock": null})));
        let (s, b) = e.post(&format!("/api/sessions/{chat}/rules/k1/withdraw"), json!({})).await;
        assert_eq!(s, 404, "{b}");
        assert!(b["error"].as_str().unwrap().ends_with("Tell the lead in a message that the rule no longer applies."), "{b}");

        for bad in ["..%2F..%2Fetc", "..%2Fsessions%2Fx", "m-nope"] {
            let (s, b) = e.get(&format!("/api/missions/{bad}/ledger")).await;
            assert_eq!(s, 404, "{bad}: {b}");
            assert!(b["error"].as_str().unwrap().starts_with("There is no mission"), "{b}");
        }
    }

    #[tokio::test]
    async fn operations_round_trip_and_refusals_carry_the_runtimes_sentence() {
        let e = env(Script::new(|_, _| finish("done"))).await;
        let id = e.create("first").await;
        e.wait_turn_ends(&id, 1).await;

        // message: runs another turn
        let (s, b) = e.post(&format!("/api/sessions/{id}/messages"), json!({"text": "second"})).await;
        assert_eq!((s, b), (202, json!({})));
        e.wait_turn_ends(&id, 2).await;
        let (s, b) = e.post(&format!("/api/sessions/{id}/messages"), json!({"text": "   "})).await;
        assert_eq!((s, b["error"].as_str().unwrap()), (409, "Write a message to send."));

        // stop / resume / reweave
        let (s, b) = e.post(&format!("/api/sessions/{id}/stop"), json!({})).await;
        assert_eq!((s, b), (202, json!({})));
        let (s, b) = e.post(&format!("/api/sessions/{id}/resume"), json!({})).await;
        assert_eq!((s, b), (202, json!({})));
        let (s, b) = e.post(&format!("/api/sessions/{id}/reweave"), Value::Null).await;
        assert_eq!((s, b), (202, json!({})));
        e.wait_turn_ends(&id, 3).await;

        // archive: listing, refusal of messages, and back
        let (s, b) = e.post(&format!("/api/sessions/{id}/archive"), json!({"archived": true})).await;
        assert_eq!((s, b), (200, json!({})));
        assert_eq!(e.get("/api/sessions").await.1, json!([]));
        let (s, listed) = e.get("/api/sessions?archived=true").await;
        assert_eq!((s, listed.as_array().unwrap().len()), (200, 1));
        let (s, b) = e.post(&format!("/api/sessions/{id}/messages"), json!({"text": "x"})).await;
        assert_eq!((s, b["error"].as_str().unwrap()), (409, "This session is archived; unarchive it first."));
        let (s, _) = e.post(&format!("/api/sessions/{id}/archive"), json!({"archived": false})).await;
        assert_eq!(s, 200);
        assert_eq!(e.get("/api/sessions").await.1.as_array().unwrap().len(), 1);

        // answer: the finished session left an item
        let (s, inbox) = e.get("/api/inbox").await;
        assert_eq!(s, 200);
        let item = inbox[0]["item"]["item_id"].as_str().unwrap().to_string();
        assert_eq!(inbox[0]["session"], id.as_str());
        let (s, b) = e.post(&format!("/api/inbox/{item}"), json!({"answer": ""})).await;
        assert_eq!((s, b), (202, json!({})));
        // An empty answer to a finished item only dismisses it: no turn starts. The message behind it
        // starts the fourth turn; a turn started by the dismissal would carry the `inbox_answer` trigger.
        let (s, _) = e.post(&format!("/api/sessions/{id}/messages"), json!({"text": "third"})).await;
        assert_eq!(s, 202);
        e.wait_turn_ends(&id, 4).await;
        assert!(e.rt.inbox().iter().all(|i| i.item.item_id != item));
        let records = e.records(&id).await;
        let starts = records.iter().filter(|r| r["kind"] == "turn_start");
        let triggers: Vec<&Value> = starts.map(|r| &r["trigger"]).collect();
        assert!(triggers.iter().all(|t| **t != "inbox_answer"), "{triggers:?}");
        assert_eq!(triggers.last().copied(), Some(&json!("user")));
        let (s, b) = e.post("/api/inbox/i-nope", json!({"answer": "x"})).await;
        assert_eq!((s, b["error"].as_str().unwrap()), (404, "There is no open inbox item i-nope."));
    }

    #[tokio::test]
    async fn a_blocking_item_refuses_an_empty_answer_with_409() {
        let e = env(Script::new(|_, n| if n == 0 { call("ask_user", json!({"question": "which one?"})) } else { finish("fine") }))
            .await;
        let id = e.create("go").await;
        let end = tokio::time::Instant::now() + WAIT;
        while e.rt.inbox().is_empty() {
            assert!(tokio::time::Instant::now() < end, "no inbox item");
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let item = e.get("/api/inbox").await.1[0]["item"]["item_id"].as_str().unwrap().to_string();
        let (s, b) = e.post(&format!("/api/inbox/{item}"), json!({"answer": "  "})).await;
        assert_eq!((s, b["error"].as_str().unwrap()), (409, "This item is waiting for an answer; write one."));
        let (s, _) = e.post(&format!("/api/inbox/{item}"), json!({"answer": "the first"})).await;
        assert_eq!(s, 202);
        e.wait_turn_ends(&id, 2).await;
    }

    #[tokio::test]
    async fn unknown_things_are_404_and_bad_requests_are_400() {
        let e = env(Script::new(|_, _| finish("x"))).await;
        let missing = "There is no session s-nope.";
        for path in [
            "/api/sessions/s-nope",
            "/api/sessions/s-nope/records",
            "/api/sessions/s-nope/window",
            "/api/sessions/s-nope/net",
            "/api/sessions/s-nope/stream",
        ] {
            let (s, b) = e.get(path).await;
            assert_eq!((s, b["error"].as_str().unwrap()), (404, missing), "{path}");
        }
        for path in ["stop", "resume", "reweave"] {
            let (s, b) = e.post(&format!("/api/sessions/s-nope/{path}"), json!({})).await;
            assert_eq!((s, b["error"].as_str().unwrap()), (404, missing), "{path}");
        }
        let (s, b) = e.post("/api/sessions/s-nope/messages", json!({"text": "x"})).await;
        assert_eq!((s, b["error"].as_str().unwrap()), (404, missing));
        let (s, b) = e.post("/api/sessions/s-nope/archive", json!({"archived": true})).await;
        assert_eq!((s, b["error"].as_str().unwrap()), (404, missing));
        let (s, b) = e.get("/api/blobs/out:0123456789abcdef").await;
        assert_eq!((s, b["error"].as_str().unwrap()), (404, "There is no stored output out:0123456789abcdef."));
        let (s, b) = e.get("/api/not-a-route").await;
        assert_eq!(s, 404);
        assert!(b["error"].is_string());

        let id = e.create("hi").await;
        let bad = "The request body is not valid: ";
        for body in ["not json", "{\"text\": 5}", "{\"text\": \"x\", \"extra\": 1}", "", "{}"] {
            let (s, b) = e.post_text(&format!("/api/sessions/{id}/messages"), body).await;
            assert_eq!(s, 400, "{body}");
            assert!(b["error"].as_str().unwrap().starts_with(bad), "{b}");
        }
        let (s, b) = e.post_text(&format!("/api/sessions/{id}/archive"), "{\"archived\": \"yes\"}").await;
        assert_eq!(s, 400, "{b}");
        let (s, b) = e.post_text("/api/inbox/i-x", "{\"answers\": \"\"}").await;
        assert_eq!(s, 400, "{b}");
        let (s, b) = e.post("/api/sessions", json!({"workspace": e.ws, "bogus": 1})).await;
        assert_eq!(s, 400, "{b}");
        assert!(b["error"].as_str().unwrap().starts_with(bad));
        for path in [
            "/api/sessions?archived=maybe".to_string(),
            format!("/api/sessions/{id}/records?limit=many"),
            format!("/api/sessions/{id}/records?after=-1"),
            format!("/api/sessions/{id}/stream?after=x"),
            format!("/api/sessions/{id}/net?limit=x"),
            "/api/events?deltas=2".to_string(),
        ] {
            let (s, b) = e.get(&path).await;
            assert_eq!(s, 400, "{path}: {b}");
            assert!(b["error"].is_string());
        }
        // A limit above the maximum is clamped rather than refused.
        let (s, _) = e.get(&format!("/api/sessions/{id}/records?limit=99999")).await;
        assert_eq!(s, 200);
    }

    #[tokio::test]
    async fn gc_route_reports_dry_run_by_default_and_deletes_on_apply() {
        let e = env(Script::new(|_, _| slow_finish("ok", 0))).await;
        let blobs = e.rt.blobs();
        let (orphan, young) = (blobs.put_bytes(b"orphan\n").unwrap(), blobs.put_bytes(b"young\n").unwrap());
        let f = std::fs::OpenOptions::new().write(true).open(blobs.root().join(&orphan.id.0[..2]).join(&orphan.id.0)).unwrap();
        f.set_modified(std::time::SystemTime::now() - Duration::from_secs(7200)).unwrap();
        let fields = |r: &Value| [r["applied"].clone(), r["examined"].clone(), r["kept"].clone(), r["collected"].clone()];
        let (s, r) = e.post("/api/gc", json!({})).await;
        assert_eq!((s, fields(&r)), (200, [json!(false), json!(2), json!(1), json!(1)]));
        assert!(blobs.read_all(&orphan.id).is_ok());
        // The old orphan goes; a young blob is never collected.
        let (s, r) = e.post("/api/gc", json!({"apply": true})).await;
        assert_eq!((s, fields(&r)), (200, [json!(true), json!(2), json!(1), json!(1)]));
        assert!(blobs.read_all(&orphan.id).is_err() && blobs.read_all(&young.id).is_ok());
        let (s, r) = e.post_text("/api/gc", "{\"apply\": \"yes\"}").await;
        assert_eq!(s, 400, "{r}");
    }

    // --- streams -------------------------------------------------------------------------------

    #[tokio::test]
    async fn the_stream_replays_the_log_then_delivers_what_is_appended() {
        let e = env(Script::new(|_, n| slow_finish("an answer long enough to arrive in several pieces", if n == 0 { 0 } else { 60 })))
            .await;
        let id = e.create("first").await;
        e.wait_turn_ends(&id, 1).await;
        let log = e.records(&id).await;
        let log_seqs: Vec<u64> = log.iter().map(|r| r["seq"].as_u64().unwrap()).collect();

        let mut stream = e.sse(&format!("/api/sessions/{id}/stream"), &[]).await;
        let (_, first) = stream.next().await.unwrap();
        assert_eq!(first["type"], "status");
        assert_eq!(first["session"], id.as_str());
        assert!(first["status"]["phase"].is_string());

        let mut got = Vec::new();
        for _ in 0..log.len() {
            got.push(stream.next().await.unwrap());
        }
        assert_eq!(record_seqs(&got), log_seqs);
        for (id, ev) in &got {
            assert_eq!(ev["type"], "record");
            assert_eq!(id.as_deref(), Some(ev["record"]["seq"].to_string().as_str()));
            assert_eq!(ev["session"], first["session"]);
        }

        // A message sent now arrives live, after the replay.
        let (s, _) = e.post(&format!("/api/sessions/{id}/messages"), json!({"text": "second"})).await;
        assert_eq!(s, 202);
        let live = stream.until(is_turn_end).await;
        let live_seqs = record_seqs(&live);
        assert!(live_seqs.len() > 2);
        assert_contiguous_from(&live_seqs, log_seqs.len() as u64);
        for (id, ev) in &live {
            if ev["type"] == "record" {
                assert_eq!(id.as_deref(), Some(ev["record"]["seq"].to_string().as_str()));
            } else {
                assert!(["delta", "status"].contains(&ev["type"].as_str().unwrap()), "{ev}");
                assert!(id.is_none());
            }
        }
        // The whole stream is the log, once.
        let full = e.records(&id.clone()).await;
        let all: Vec<u64> = log_seqs.iter().chain(live_seqs.iter()).copied().collect();
        let full_seqs: Vec<u64> = full.iter().map(|r| r["seq"].as_u64().unwrap()).collect();
        assert_eq!(all, full_seqs[..all.len()]);
    }

    #[tokio::test]
    async fn after_and_last_event_id_skip_what_was_seen() {
        let e = env(Script::new(|_, _| finish("done"))).await;
        let id = e.create("first").await;
        e.wait_turn_ends(&id, 1).await;
        let total = e.records(&id).await.len() as u64;
        assert!(total > 6);
        let path = format!("/api/sessions/{id}/stream");

        let mut s = e.sse(&format!("{path}?after=2"), &[]).await;
        assert_eq!(s.next().await.unwrap().1["type"], "status");
        let events = s.until(is_turn_end).await;
        assert_contiguous_from(&record_seqs(&events), 3);

        let mut s = e.sse(&path, &[("Last-Event-ID", "3")]).await;
        assert_eq!(s.next().await.unwrap().1["type"], "status");
        let events = s.until(is_turn_end).await;
        assert_contiguous_from(&record_seqs(&events), 4);

        // The query parameter wins over the header.
        let mut s = e.sse(&format!("{path}?after=4"), &[("Last-Event-ID", "1")]).await;
        s.next().await.unwrap();
        let events = s.until(is_turn_end).await;
        assert_contiguous_from(&record_seqs(&events), 5);

        // Nothing newer than the last record: only live events follow the status.
        let mut s = e.sse(&format!("{path}?after={}", total - 1), &[]).await;
        assert_eq!(s.next().await.unwrap().1["type"], "status");
        let (st, _) = e.post(&format!("/api/sessions/{id}/messages"), json!({"text": "again"})).await;
        assert_eq!(st, 202);
        let events = s.until(is_turn_end).await;
        assert_contiguous_from(&record_seqs(&events), total);

        // A header that is not a number is ignored.
        let mut s = e.sse(&path, &[("Last-Event-ID", "abc")]).await;
        s.next().await.unwrap();
        assert_eq!(record_seqs(&[s.next().await.unwrap()]), vec![0]);
    }

    #[tokio::test]
    async fn no_record_is_skipped_or_repeated_across_the_replay_and_live_boundary() {
        let e = env(Script::new(|_, n| slow_finish("a reply split into a number of small pieces", if n == 0 { 0 } else { 30 }))).await;
        let id = e.create("first").await;
        e.wait_turn_ends(&id, 1).await;

        // Open the stream and send messages at the same moment, and keep sending while the replay
        // and the first live events are in flight.
        let path = format!("/api/sessions/{id}/stream");
        let open = e.sse(&path, &[]);
        let send = async {
            for n in 0..3 {
                let (s, b) = e.post(&format!("/api/sessions/{id}/messages"), json!({"text": format!("m{n}")})).await;
                assert!(s == 202 || s == 409, "{b}");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        let (mut stream, ()) = tokio::join!(open, send);
        let mut turns = 0;
        let mut events = Vec::new();
        let end = tokio::time::Instant::now() + WAIT;
        // Every message that was accepted ends one more turn; wait for the log to say how many.
        loop {
            let (idv, ev) = stream.next().await.unwrap();
            let end_of_turn = is_turn_end(&ev);
            events.push((idv, ev));
            if end_of_turn {
                turns += 1;
                let in_log = e.records(&id).await.iter().filter(|r| r["kind"] == "turn_end").count();
                if turns >= in_log && in_log >= 2 {
                    // Let anything still being written reach the stream, then stop at a turn end.
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    if e.records(&id).await.iter().filter(|r| r["kind"] == "turn_end").count() == turns {
                        break;
                    }
                }
            }
            assert!(tokio::time::Instant::now() < end, "the stream did not catch up");
        }
        let seqs = record_seqs(&events);
        assert_contiguous_from(&seqs, 0);
        let log = e.records(&id).await;
        assert_eq!(seqs.len(), log.len());
    }

    #[tokio::test]
    async fn a_lagging_subscriber_is_told_and_the_stream_goes_on() {
        let e = env(Script::new(|_, _| finish("x"))).await;
        let id = e.create("hi").await;
        e.wait_turn_ends(&id, 1).await;
        let info = e.rt.session(&SessionId::from(id.as_str())).unwrap();
        let sid = info.meta.id.clone();
        let total = e.records(&id).await.len();

        let (bus_tx, bus_rx) = broadcast::channel(2);
        for n in 0..5 {
            let delta = Delta::Text { text: format!("piece-{n}") };
            bus_tx.send(BusEvent::Delta { session: sid.clone(), req_id: "r".into(), delta }).unwrap();
        }
        // An event of another session and one that is not a record are not delivered. Dropping the
        // sender ends the stream once what was kept has been read.
        drop(bus_tx);
        let (tx, rx) = mpsc::channel(STREAM_BUFFER);
        tokio::spawn(pump_session(e.rt.clone(), info, None, bus_rx, tx, CancellationToken::new()));
        let bytes = axum::body::to_bytes(sse_response(rx).into_body(), usize::MAX).await.unwrap();
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        let events: Vec<Value> = text
            .split("\n\n")
            .filter_map(|b| b.lines().find_map(|l| l.strip_prefix("data:")))
            .map(|d| serde_json::from_str(d.trim()).unwrap())
            .collect();
        let types: Vec<&str> = events.iter().map(|v| v["type"].as_str().unwrap()).collect();
        assert_eq!(types[0], "status");
        let lagged = events.iter().position(|v| v["type"] == "lagged").expect("a lagged event");
        assert_eq!(events[lagged]["missed"], 3);
        assert_eq!(types.iter().filter(|t| **t == "record").count(), total);
        // The two events the bus still held follow.
        let tail: Vec<&Value> = events.iter().skip(lagged + 1).filter(|v| v["type"] == "delta").collect();
        assert_eq!(tail.len(), 2);
        assert_eq!(tail[0]["delta"]["text"], "piece-3");
        assert_eq!(tail[1]["delta"]["text"], "piece-4");
        assert!(!text.contains("piece-0"));
        // Lagged is not a record: it has no id.
        assert!(text.split("\n\n").filter(|b| b.contains("\"lagged\"")).all(|b| !b.contains("id:")));
    }

    #[tokio::test]
    async fn events_carry_deltas_only_when_asked() {
        let e = env(Script::new(|_, _| finish("an answer with enough text to stream in pieces"))).await;
        let mut plain = e.sse("/api/events", &[]).await;
        let mut with = e.sse("/api/events?deltas=true", &[]).await;
        let id = e.create("hi").await;

        let plain_events = plain.until(is_turn_end).await;
        let with_events = with.until(is_turn_end).await;
        let types = |evs: &[(Option<String>, Value)]| -> Vec<String> {
            evs.iter().map(|(_, v)| v["type"].as_str().unwrap().to_string()).collect()
        };
        let plain_types = types(&plain_events);
        let with_types = types(&with_events);
        assert!(!plain_types.contains(&"delta".to_string()), "{plain_types:?}");
        assert!(with_types.contains(&"delta".to_string()), "{with_types:?}");
        assert!(plain_types.contains(&"session".to_string()));
        assert!(plain_types.contains(&"record".to_string()));
        // Same stream otherwise.
        let without_deltas: Vec<&String> = with_types.iter().filter(|t| *t != "delta").collect();
        assert_eq!(without_deltas, plain_types.iter().collect::<Vec<_>>());
        assert!(plain_events.iter().any(|(_, v)| v["session"] == id.as_str()));
        // No event stream has an `event:` field.
        assert!(!String::from_utf8_lossy(&plain.buf).contains("event:"));
    }

    #[tokio::test]
    async fn stream_headers_are_those_of_an_event_stream() {
        let e = env(Script::new(|_, _| finish("x"))).await;
        let id = e.create("hi").await;
        for path in [format!("/api/sessions/{id}/stream"), "/api/events".to_string()] {
            let r = e.rq(Method::GET, &path).send().await.unwrap();
            assert_eq!(r.status(), 200);
            assert!(r.headers()["content-type"].to_str().unwrap().starts_with("text/event-stream"), "{path}");
            assert_eq!(r.headers()["cache-control"], "no-store");
            assert_eq!(r.headers()["x-accel-buffering"], "no");
            assert_eq!(r.headers()["x-content-type-options"], "nosniff");
        }
    }

    #[tokio::test]
    async fn streams_end_when_the_daemon_is_told_to_shut_down() {
        let e = env(Script::new(|_, _| finish("x"))).await;
        let mut events = e.sse("/api/events", &[]).await;
        let (s, b) = e.post("/api/shutdown", json!({})).await;
        assert_eq!((s, b), (202, json!({})));
        assert!(e.shutdown.is_cancelled());
        while events.next().await.is_some() {}
    }

    // --- stored outputs ------------------------------------------------------------------------

    #[tokio::test]
    async fn stored_outputs_are_described_downloaded_and_read_by_lines() {
        let e = env(Script::new(|_, _| finish("x"))).await;
        let small = e.rt.blobs().put_bytes(b"alpha\nbeta\ngamma\n").unwrap();
        let handle = small.handle();

        let (s, meta) = e.get(&format!("/api/blobs/{handle}")).await;
        assert_eq!(s, 200);
        assert_eq!(meta, json!({"id": small.id.as_str(), "bytes": 17, "lines": 3}));
        let (s, meta_full) = e.get(&format!("/api/blobs/{}", small.id)).await;
        assert_eq!((s, &meta_full), (200, &meta));

        let r = e.rq(Method::GET, &format!("/api/blobs/{handle}/raw")).send().await.unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(r.headers()["content-type"], "application/octet-stream");
        assert!(r.headers()["content-disposition"].to_str().unwrap().starts_with("attachment"));
        assert_eq!(r.headers()["cache-control"], "no-store");
        assert_eq!(r.bytes().await.unwrap().as_ref(), b"alpha\nbeta\ngamma\n");

        let (s, all) = e.get(&format!("/api/blobs/{handle}/lines")).await;
        assert_eq!(s, 200);
        assert_eq!(all, json!({"text": "alpha\nbeta\ngamma\n", "first": 1, "last": 3, "total": 3}));
        let (_, part) = e.get(&format!("/api/blobs/{handle}/lines?start=2&end=99")).await;
        assert_eq!(part, json!({"text": "beta\ngamma\n", "first": 2, "last": 3, "total": 3}));
        let (_, zero) = e.get(&format!("/api/blobs/{handle}/lines?start=0&end=1")).await;
        assert_eq!(zero["first"], 1);
        assert_eq!(zero["text"], "alpha\n");
        let (_, beyond) = e.get(&format!("/api/blobs/{handle}/lines?start=10")).await;
        assert_eq!(beyond["text"], "");
        assert_eq!(beyond["total"], 3);
        let (s, b) = e.get(&format!("/api/blobs/{handle}/lines?start=x")).await;
        assert_eq!(s, 400, "{b}");

        let big: String = (1..=6_000).map(|n| format!("line {n}\n")).collect();
        let big = e.rt.blobs().put_bytes(big.as_bytes()).unwrap();
        let (_, first) = e.get(&format!("/api/blobs/{}/lines", big.handle())).await;
        assert_eq!((first["first"].clone(), first["last"].clone(), first["total"].clone()), (json!(1), json!(2000), json!(6000)));
        let (_, capped) = e.get(&format!("/api/blobs/{}/lines?start=1&end=100000", big.handle())).await;
        assert_eq!(capped["last"], 5000);
        let (_, tail) = e.get(&format!("/api/blobs/{}/lines?start=5500&end=100000", big.handle())).await;
        assert_eq!((tail["first"].clone(), tail["last"].clone()), (json!(5500), json!(6000)));
        assert!(tail["text"].as_str().unwrap().starts_with("line 5500\n"));

        for path in ["zzz/raw", "zzz/lines", "zzz"] {
            let (s, b) = e.get(&format!("/api/blobs/{path}")).await;
            assert_eq!((s, b["error"].as_str().unwrap()), (404, "There is no stored output zzz."), "{path}");
        }
    }

    #[tokio::test]
    async fn an_ambiguous_blob_handle_is_a_409_that_lists_the_candidates() {
        let e = env(Script::new(|_, _| finish("x"))).await;
        let root = e.rt.blobs().root().join("ab");
        std::fs::create_dir_all(&root).unwrap();
        let (one, two) = (format!("abcdef01{}", "1".repeat(56)), format!("abcdef01{}", "2".repeat(56)));
        std::fs::write(root.join(&one), b"x\n").unwrap();
        std::fs::write(root.join(&two), b"y\n").unwrap();
        for tail in ["", "/raw", "/lines"] {
            let (s, b) = e.get(&format!("/api/blobs/abcdef01{tail}")).await;
            let text = b["error"].as_str().unwrap();
            assert_eq!(s, 409, "{tail}: {text}");
            assert!(text.contains(&one[..16]) && text.contains(&two[..16]), "{text}");
        }
        // A prefix that names none is still a 404.
        let (s, _) = e.get("/api/blobs/abcdef99").await;
        assert_eq!(s, 404);
    }

    #[tokio::test]
    async fn an_ambiguous_long_handle_lists_candidates_that_differ_and_several_means_more_than_listed() {
        let e = env(Script::new(|_, _| finish("x"))).await;
        let root = e.rt.blobs().root().join("cd");
        std::fs::create_dir_all(&root).unwrap();
        // Ids that share their first 20 characters: a 16-character shortening would show the same string.
        let id = |n: usize| format!("cd{}{n:02}{}", "7".repeat(18), "0".repeat(42));
        for n in 0..BLOB_CANDIDATES {
            std::fs::write(root.join(id(n)), b"x\n").unwrap();
        }
        let handle = &id(0)[..20];
        let (s, b) = e.get(&format!("/api/blobs/{handle}")).await;
        let text = b["error"].as_str().unwrap();
        assert_eq!(s, 409, "{text}");
        assert!(text.contains(&format!("matches {BLOB_CANDIDATES} stored outputs")), "{text}");
        for n in 0..BLOB_CANDIDATES {
            assert!(text.contains(&id(n)[..22]), "{text}");
        }
        std::fs::write(root.join(id(BLOB_CANDIDATES)), b"x\n").unwrap();
        let (_, b) = e.get(&format!("/api/blobs/{handle}")).await;
        assert!(b["error"].as_str().unwrap().contains("matches several stored outputs"), "{b}");
    }

    #[tokio::test]
    async fn shutdown_cancels_the_token() {
        let e = env(Script::new(|_, _| finish("x"))).await;
        assert!(!e.shutdown.is_cancelled());
        let (s, b) = e.post("/api/shutdown", json!({})).await;
        assert_eq!((s, b), (202, json!({})));
        assert!(e.shutdown.is_cancelled());
    }
}
