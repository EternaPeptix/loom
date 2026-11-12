//! The API as typed calls, for the command line.
//!
//! CONTRACT.
//! Routes and bodies: `crate::api`. Every error is a sentence for the operator.
//!
//! - `Client::new(base, token)`: `base` like `http://127.0.0.1:7878` (no trailing slash kept). The
//!   HTTP client uses no proxy (`no_proxy()`), a 5 s connect timeout, no overall timeout for
//!   streams and 60 s for everything else. Every request sends `Authorization: Bearer {token}`.
//! - `Client::from_home(paths)`: the bind address from `daemon.json` when it exists, else from the
//!   config (`Config::load`, default when missing); the token from `paths.token_file()`. No token
//!   file: `There is no access token at {path}; the daemon creates it the first time it starts
//!   (`loom up`).`
//! - Errors:
//!   - cannot connect: `The loom daemon is not running (nothing answers on {bind}). Start it with
//!     `loom up`.`
//!   - a non-2xx answer with an `ErrorBody`: its `error`, unchanged;
//!   - a non-2xx answer without one: `The daemon answered {status} to {METHOD} {path}.`
//!   - a body that does not parse: `The daemon's answer to {METHOD} {path} was not understood
//!     ({why}); the `loom` command and the daemon may be different versions.`
//! - `login_code()`: `POST /api/login-codes`, the `code` of the answer. A daemon from before login
//!   codes has no such route; its refusal becomes a sentence that says to restart the daemon.
//! - `resolve(word)`: the session a word on the command line means. `last` → the most recently
//!   created session that is not archived (`There are no sessions yet.`). Otherwise among all
//!   sessions (archived included): the one whose id equals `word`; else those whose id starts with
//!   `word` or with `s-{word}`. One → it. None → `No session matches `{word}`.` Several → `` `{word}`
//!   matches {n} sessions: {ids, at most 5, then "…"}. Give more of the id. ``
//! - `grant_scope(id, hosts, note)`: `POST /api/sessions/{id}/scope`, the `ScopeReceipt`. `release(id, reason)`:
//!   `POST /api/sessions/{id}/release`, the `RuleReceipt`. Both are the operator's, like `add_rule`.
//! - `mission_of(word)`: a word starting with `m-` is taken as a mission id as it is; otherwise
//!   `resolve(word)` and that session's mission.
//! - `stream(id, after)` / `events(deltas)`: open the event stream and return an [`EventStream`].
//!   `EventStream::next()` yields each event as a `BusEvent` (`loom_model::assemble::SseParser` over
//!   the body's chunks, each payload parsed as `BusEvent`; a `record` event whose record does not
//!   parse, one served as stored, has it read with `loom_core::log::record_from_value`, as
//!   `wire::RecordsPage` does; a payload that does not parse is skipped with `tracing::debug!`),
//!   `None` when the server closes the stream, `Some(Err(sentence))` when the connection breaks
//!   (`The connection to the daemon was lost.`).
//!
//! Tests required (against a small `axum` server in the test that plays the daemon — no runtime
//! needed): the bearer header is sent; each call hits the documented method and path and parses the
//! documented body; the four error forms; `resolve` (exact, prefix with and without `s-`, `last`,
//! none, several); `mission_of`; a stream delivering events split across chunks, a comment line and
//! an unparsable payload in between, then end of stream; a stream's record served as stored (an
//! opaque one) arriving as `Event::Unknown`; `from_home` preferring `daemon.json`.
//!
//! Beyond the contract: a stream that is silent for 60 s (the daemon sends a comment every 15 s) is
//! treated as a lost connection, so a daemon that hangs cannot hang a follower; `bind_from_home`
//! is public so the command line names the same address the client uses.
//!
//! The token goes only to a listener that has just proved it holds it. A `from_home` client asks
//! for a proof before every request that would carry the token, stream openings included (a proof
//! is never reused: the daemon may stop and something else take the address in between):
//! `GET /healthz?nonce=<64 fresh hex>` without the token, and the answer's `proof` compared in
//! constant time with `HMAC-SHA256(token, "loom-healthz-v1:" + nonce)` (`daemon_proves_identity`).
//! A missing or wrong proof stops the call before the token is sent, with `unproven_message`:
//! something listens on the address but did not prove it is this home's daemon; an older daemon is
//! to be restarted (`loom --unverified-daemon down`, then `loom up`); `--unverified-daemon` carries
//! on. With that global flag (`allow_unverified_daemon`) an unproven listener gets the token anyway,
//! and the client prints `unverified_warning` to stderr, once. `Client::new` alone does not ask.

use crate::wire::{
    AnswerBody, ApprovalBody, ArchiveBody, DaemonFile, ErrorBody, GcBody, LinesView, MessageBody, RecordsPage,
    ReleaseBody, RuleBody, ScopeBody, ScopeReceipt, SessionDetail, StatusView, WithdrawBody,
};
use loom_agent::runtime::{
    BusEvent, InboxEntry, LedgerView, MissionInfo, NetEntry, NewSession, RuleReceipt, SessionInfo, WindowView,
};
use loom_core::config::{Config, Paths};
use loom_core::event::Seq;
use loom_core::log::record_from_value;
use loom_core::{BlobRef, MissionId, SessionId};
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::io::Write;
use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const ALIVE_TIMEOUT: Duration = Duration::from_secs(2);
/// The daemon sends a keep-alive comment every 15 s; a stream silent for this long is dead.
const STREAM_IDLE: Duration = Duration::from_secs(60);
const LOST: &str = "The connection to the daemon was lost.";
/// What every daemon has answered to a path it does not have (`404`).
const NO_SUCH_PATH: &str = "There is no such path on the loom daemon.";
const OLDER_DAEMON: &str = "The running daemon is older than this `loom` and cannot issue login codes. Restart it (`loom down`, then `loom up`) and run `loom open` again.";

/// Set once by `--unverified-daemon`: talk to a listener that does not prove it is this home's daemon.
static UNVERIFIED_DAEMON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Accept, for the rest of this process, a daemon that cannot prove its identity (one from before `/healthz?nonce=`).
pub fn allow_unverified_daemon() {
    UNVERIFIED_DAEMON.store(true, std::sync::atomic::Ordering::Relaxed);
}

pub(crate) fn unverified_daemon_allowed() -> bool {
    UNVERIFIED_DAEMON.load(std::sync::atomic::Ordering::Relaxed)
}

/// What the operator is told when a listener on `bind` does not prove it is this home's daemon.
pub(crate) fn unproven_message(bind: &str) -> String {
    format!(
        "Something is listening on {bind} but it did not prove it is this home's loom daemon, so the access token was not sent. If the daemon is older than this `loom`, restart it with `loom --unverified-daemon down` and then `loom up`; otherwise find what holds the port. To carry on without the proof, add --unverified-daemon."
    )
}

/// The warning line printed when `--unverified-daemon` lets the token go to a listener that did not prove itself.
pub(crate) fn unverified_warning(bind: &str) -> String {
    format!("loom: warning: the listener on {bind} did not prove it is this home's loom daemon; sending the access token anyway (--unverified-daemon).")
}

/// Print [`unverified_warning`] (tests also collect it).
pub(crate) fn warn_unverified(bind: &str) {
    let line = unverified_warning(bind);
    let _ = writeln!(std::io::stderr(), "{line}");
    #[cfg(test)]
    WARNINGS.lock().unwrap_or_else(|e| e.into_inner()).push(line);
}

#[cfg(test)]
pub(crate) static WARNINGS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Ask the listener at `base` to prove it holds `token`: a fresh nonce to `/healthz?nonce=`, the answer's `proof`
/// compared in constant time. `Ok(false)` when it answers without a right proof; `Err` when it cannot be reached.
/// The token itself is never sent.
pub(crate) async fn daemon_proves_identity(
    http: &reqwest::Client,
    base: &str,
    token: &str,
    timeout: Duration,
) -> Result<bool, reqwest::Error> {
    let nonce = hex::encode(rand::random::<[u8; 32]>());
    let response =
        http.get(format!("{base}/healthz")).query(&[("nonce", nonce.as_str())]).timeout(timeout).send().await?;
    if !response.status().is_success() {
        return Ok(false);
    }
    let body = response.bytes().await?;
    let proof = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v.get("proof").and_then(|p| p.as_str()).map(str::to_string));
    Ok(proof.is_some_and(|p| crate::auth::healthz_proof_ok(token, &nonce, &p)))
}

/// A connection to one daemon.
#[derive(Clone)]
pub struct Client {
    base: String,
    token: String,
    http: reqwest::Client,
    /// Whether the listener must prove it is this home's daemon before the token is sent (`from_home`).
    verify: bool,
    /// Carry on when it does not (`--unverified-daemon`), with a warning.
    allow_unverified: bool,
    /// Set once that warning has been printed, so that it is printed once (shared by clones).
    warned: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// An open event stream.
pub struct EventStream {
    response: reqwest::Response,
    parser: loom_model::assemble::SseParser,
    ready: std::collections::VecDeque<BusEvent>,
    /// Longest silence tolerated between two chunks.
    idle: Duration,
    /// The stream ended or broke; nothing more will come.
    done: bool,
}

impl EventStream {
    /// The next event; `None` when the stream has ended.
    pub async fn next(&mut self) -> Option<Result<BusEvent, String>> {
        loop {
            if let Some(event) = self.ready.pop_front() {
                return Some(Ok(event));
            }
            if self.done {
                return None;
            }
            match tokio::time::timeout(self.idle, self.response.chunk()).await {
                Ok(Ok(Some(chunk))) => {
                    let payloads = match self.parser.feed(&chunk) {
                        Ok(p) => p,
                        Err(e) => {
                            self.done = true;
                            return Some(Err(e.to_string()));
                        }
                    };
                    for payload in payloads {
                        match bus_event(&payload) {
                            Ok(event) => self.ready.push_back(event),
                            Err(e) => tracing::debug!("skipping an event that did not parse: {e}"),
                        }
                    }
                }
                Ok(Ok(None)) => {
                    self.done = true;
                    return None;
                }
                Ok(Err(_)) | Err(_) => {
                    self.done = true;
                    return Some(Err(LOST.to_string()));
                }
            }
        }
    }
}

/// One stream payload as a `BusEvent`, or as [`stored_record`] reads it.
fn bus_event(payload: &str) -> Result<BusEvent, serde_json::Error> {
    serde_json::from_str::<BusEvent>(payload).or_else(|error| stored_record(payload).ok_or(error))
}

/// A `record` event whose record does not parse as one (a record the daemon served as stored because it could not
/// read it in full), with its record read as the log reader reads it, as `wire::RecordsPage` does:
/// `Event::Unknown` when its header is sound.
fn stored_record(payload: &str) -> Option<BusEvent> {
    let value: serde_json::Value = serde_json::from_str(payload).ok()?;
    if value.get("type").and_then(serde_json::Value::as_str) != Some("record") {
        return None;
    }
    let session = SessionId::deserialize(value.get("session")?).ok()?;
    let record = record_from_value(value.get("record")?)?;
    Some(BusEvent::Record { session, record: Box::new(record) })
}

/// The address the daemon listens on: `daemon.json` when it exists, else the configuration.
pub fn bind_from_home(paths: &Paths) -> Result<String, String> {
    let file = paths.home.join("daemon.json");
    if let Ok(text) = std::fs::read_to_string(&file) {
        if let Ok(parsed) = serde_json::from_str::<DaemonFile>(&text) {
            return Ok(parsed.bind);
        }
    }
    let config = Config::load(&paths.config_file()).map_err(|e| e.to_string())?;
    Ok(config.daemon.bind)
}

/// Percent-encode one path segment (letters, digits and `-._~:` stay as they are).
fn segment(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b':') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

impl Client {
    pub fn new(base: &str, token: &str) -> Client {
        // A builder that cannot be built (no TLS backend, say) falls back to the defaults, which
        // still have the 60 s per-request timeout set on every call below.
        let http = reqwest::Client::builder().no_proxy().connect_timeout(CONNECT_TIMEOUT).build().unwrap_or_default();
        Client {
            base: base.trim_end_matches('/').to_string(),
            token: token.to_string(),
            http,
            verify: false,
            allow_unverified: false,
            warned: Default::default(),
        }
    }

    /// Require the listener to prove it is this home's daemon before every request that carries the token.
    pub fn verifying(mut self) -> Client {
        self.verify = true;
        self
    }

    /// With [`Client::verifying`]: go on, with a warning, when the listener cannot prove it.
    pub fn allowing_unverified(mut self) -> Client {
        self.allow_unverified = true;
        self
    }

    pub fn from_home(paths: &Paths) -> Result<Client, String> {
        Client::from_home_allowing(paths, unverified_daemon_allowed())
    }

    fn from_home_allowing(paths: &Paths, allow_unverified: bool) -> Result<Client, String> {
        let bind = bind_from_home(paths)?;
        let token_file = paths.token_file();
        let token = match std::fs::read_to_string(&token_file) {
            Ok(t) => t.trim().to_string(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(format!(
                    "There is no access token at {}; the daemon creates it the first time it starts (`loom up`).",
                    token_file.display()
                ));
            }
            Err(e) => return Err(format!("Cannot read the access token at {}: {e}.", token_file.display())),
        };
        let client = Client::new(&format!("http://{bind}"), &token).verifying();
        Ok(if allow_unverified { client.allowing_unverified() } else { client })
    }

    /// Before every request that would carry the token (stream openings included): the listener must prove it holds
    /// the token. A proof is never reused: the daemon may stop and something else take its address while nothing is
    /// sent (a `loom chat` waits on the terminal for as long as the operator likes).
    async fn ensure_proven(&self) -> Result<(), String> {
        if !self.verify {
            return Ok(());
        }
        let bind = self.base.strip_prefix("http://").unwrap_or(&self.base);
        match daemon_proves_identity(&self.http, &self.base, &self.token, CONNECT_TIMEOUT).await {
            Ok(true) => Ok(()),
            Ok(false) if self.allow_unverified => {
                if !self.warned.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    warn_unverified(bind);
                }
                Ok(())
            }
            Ok(false) => Err(unproven_message(bind)),
            Err(e) => Err(self.transport_error(&Method::GET, "/healthz", e)),
        }
    }

    /// `http://127.0.0.1:7878`.
    pub fn base(&self) -> &str {
        &self.base
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    fn not_running(&self) -> String {
        let bind = self.base.strip_prefix("http://").unwrap_or(&self.base);
        format!("The loom daemon is not running (nothing answers on {bind}). Start it with `loom up`.")
    }

    fn transport_error(&self, method: &Method, path: &str, e: reqwest::Error) -> String {
        let e = e.without_url();
        if e.is_connect() {
            self.not_running()
        } else if e.is_timeout() {
            format!(
                "The daemon did not answer {method} {path} in time. Check `loom status` and ~/.loom/logs/loomd.log."
            )
        } else if e.is_body() || e.is_decode() {
            LOST.to_string()
        } else {
            format!("The request {method} {path} to the daemon failed ({e}).")
        }
    }

    /// Send one request; the response when its status is 2xx, else the operator's sentence.
    async fn send_raw(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<serde_json::Value>,
        timeout: Option<Duration>,
    ) -> Result<reqwest::Response, String> {
        self.ensure_proven().await?;
        let url = format!("{}{}", self.base, path);
        let mut req = self.http.request(method.clone(), url).bearer_auth(&self.token);
        if !query.is_empty() {
            req = req.query(query);
        }
        if let Some(body) = &body {
            req = req.json(body);
        }
        if let Some(timeout) = timeout {
            req = req.timeout(timeout);
        }
        let response = req.send().await.map_err(|e| self.transport_error(&method, path, e))?;
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        let bytes = match tokio::time::timeout(REQUEST_TIMEOUT, response.bytes()).await {
            Ok(Ok(b)) => b,
            _ => Default::default(),
        };
        match serde_json::from_slice::<ErrorBody>(&bytes) {
            Ok(e) => Err(e.error),
            Err(_) => Err(format!("The daemon answered {status} to {method} {path}.")),
        }
    }

    async fn call<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<serde_json::Value>,
    ) -> Result<T, String> {
        self.call_with_timeout(method, path, query, body, REQUEST_TIMEOUT).await
    }

    async fn call_with_timeout<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<serde_json::Value>,
        timeout: Duration,
    ) -> Result<T, String> {
        let response = self.send_raw(method.clone(), path, query, body, Some(timeout)).await?;
        let bytes = response.bytes().await.map_err(|e| self.transport_error(&method, path, e))?;
        serde_json::from_slice(&bytes).map_err(|e| {
            format!(
                "The daemon's answer to {method} {path} was not understood ({e}); the `loom` command and the daemon may be different versions."
            )
        })
    }

    /// A call whose answer is `{}` and is not looked at.
    async fn call_unit(&self, method: Method, path: &str, body: Option<serde_json::Value>) -> Result<(), String> {
        let response = self.send_raw(method.clone(), path, &[], body, Some(REQUEST_TIMEOUT)).await?;
        response.bytes().await.map_err(|e| self.transport_error(&method, path, e))?;
        Ok(())
    }

    /// Whether a daemon answers `/healthz` (2 s).
    pub async fn alive(&self) -> bool {
        let url = format!("{}/healthz", self.base);
        match self.http.get(url).timeout(ALIVE_TIMEOUT).send().await {
            Ok(r) => r.status().is_success(),
            Err(_) => false,
        }
    }

    pub async fn status(&self) -> Result<StatusView, String> {
        self.call(Method::GET, "/api/status", &[], None).await
    }

    pub async fn sessions(&self, archived: bool) -> Result<Vec<SessionInfo>, String> {
        let query: Vec<(&str, String)> = if archived { vec![("archived", "true".to_string())] } else { vec![] };
        self.call(Method::GET, "/api/sessions", &query, None).await
    }

    pub async fn session(&self, id: &SessionId) -> Result<SessionDetail, String> {
        self.call(Method::GET, &format!("/api/sessions/{}", segment(id.as_str())), &[], None).await
    }

    pub async fn create(&self, new: &NewSession) -> Result<SessionInfo, String> {
        let body = serde_json::to_value(new).map_err(|e| format!("The session request cannot be encoded ({e})."))?;
        self.call(Method::POST, "/api/sessions", &[], Some(body)).await
    }

    pub async fn send(&self, id: &SessionId, text: &str) -> Result<(), String> {
        let body = serde_json::to_value(MessageBody { text: text.to_string() })
            .map_err(|e| format!("The message cannot be encoded ({e})."))?;
        self.call_unit(Method::POST, &format!("/api/sessions/{}/messages", segment(id.as_str())), Some(body)).await
    }

    /// The receipt says which lead the rule went to and whether it is recorded yet (`queued`).
    pub async fn add_rule(&self, id: &SessionId, text: &str) -> Result<RuleReceipt, String> {
        let body = serde_json::to_value(RuleBody { text: text.to_string() })
            .map_err(|e| format!("The rule cannot be encoded ({e})."))?;
        self.call(Method::POST, &format!("/api/sessions/{}/rules", segment(id.as_str())), &[], Some(body)).await
    }

    pub async fn approve(&self, id: &SessionId, text: &str, scope: &str) -> Result<RuleReceipt, String> {
        let body = serde_json::to_value(ApprovalBody { text: text.to_string(), scope: scope.to_string() })
            .map_err(|e| format!("The approval cannot be encoded ({e})."))?;
        self.call(Method::POST, &format!("/api/sessions/{}/approvals", segment(id.as_str())), &[], Some(body)).await
    }

    pub async fn withdraw_rule(&self, id: &SessionId, rule_id: &str, reason: &str) -> Result<RuleReceipt, String> {
        let body = serde_json::to_value(WithdrawBody { reason: reason.to_string() })
            .map_err(|e| format!("The withdrawal cannot be encoded ({e})."))?;
        let path = format!("/api/sessions/{}/rules/{}/withdraw", segment(id.as_str()), segment(rule_id));
        self.call(Method::POST, &path, &[], Some(body)).await
    }

    /// Let the mission of `id` reach `hosts` (the operator's grant). The receipt names the lead it went to.
    pub async fn grant_scope(
        &self,
        id: &SessionId,
        hosts: &[String],
        note: Option<&str>,
    ) -> Result<ScopeReceipt, String> {
        let body = serde_json::to_value(ScopeBody { hosts: hosts.to_vec(), note: note.map(str::to_string) })
            .map_err(|e| format!("The grant cannot be encoded ({e})."))?;
        self.call(Method::POST, &format!("/api/sessions/{}/scope", segment(id.as_str())), &[], Some(body)).await
    }

    /// Close the mission of `id` without the goal established, for `reason`.
    pub async fn release(&self, id: &SessionId, reason: &str) -> Result<RuleReceipt, String> {
        let body = serde_json::to_value(ReleaseBody { reason: reason.to_string() })
            .map_err(|e| format!("The release cannot be encoded ({e})."))?;
        self.call(Method::POST, &format!("/api/sessions/{}/release", segment(id.as_str())), &[], Some(body)).await
    }

    pub async fn stop(&self, id: &SessionId) -> Result<(), String> {
        self.call_unit(Method::POST, &format!("/api/sessions/{}/stop", segment(id.as_str())), None).await
    }

    pub async fn resume(&self, id: &SessionId) -> Result<(), String> {
        self.call_unit(Method::POST, &format!("/api/sessions/{}/resume", segment(id.as_str())), None).await
    }

    pub async fn reweave(&self, id: &SessionId) -> Result<(), String> {
        self.call_unit(Method::POST, &format!("/api/sessions/{}/reweave", segment(id.as_str())), None).await
    }

    pub async fn archive(&self, id: &SessionId, archived: bool) -> Result<(), String> {
        let body = serde_json::to_value(ArchiveBody { archived })
            .map_err(|e| format!("The request cannot be encoded ({e})."))?;
        self.call_unit(Method::POST, &format!("/api/sessions/{}/archive", segment(id.as_str())), Some(body)).await
    }

    pub async fn records(&self, id: &SessionId, after: Option<Seq>, limit: usize) -> Result<RecordsPage, String> {
        let mut query = vec![("limit", limit.to_string())];
        if let Some(after) = after {
            query.push(("after", after.to_string()));
        }
        self.call(Method::GET, &format!("/api/sessions/{}/records", segment(id.as_str())), &query, None).await
    }

    pub async fn window(&self, id: &SessionId) -> Result<WindowView, String> {
        self.call(Method::GET, &format!("/api/sessions/{}/window", segment(id.as_str())), &[], None).await
    }

    pub async fn net(&self, id: &SessionId, limit: usize) -> Result<Vec<NetEntry>, String> {
        let query = [("limit", limit.to_string())];
        self.call(Method::GET, &format!("/api/sessions/{}/net", segment(id.as_str())), &query, None).await
    }

    pub async fn missions(&self) -> Result<Vec<MissionInfo>, String> {
        self.call(Method::GET, "/api/missions", &[], None).await
    }

    pub async fn ledger(&self, mission: &MissionId) -> Result<LedgerView, String> {
        self.call(Method::GET, &format!("/api/missions/{}/ledger", segment(mission.as_str())), &[], None).await
    }

    pub async fn inbox(&self) -> Result<Vec<InboxEntry>, String> {
        self.call(Method::GET, "/api/inbox", &[], None).await
    }

    pub async fn answer(&self, item_id: &str, answer: &str) -> Result<(), String> {
        let body = serde_json::to_value(AnswerBody { answer: answer.to_string() })
            .map_err(|e| format!("The answer cannot be encoded ({e})."))?;
        self.call_unit(Method::POST, &format!("/api/inbox/{}", segment(item_id)), Some(body)).await
    }

    pub async fn blob(&self, handle: &str) -> Result<BlobRef, String> {
        self.call(Method::GET, &format!("/api/blobs/{}", segment(handle)), &[], None).await
    }

    pub async fn blob_lines(&self, handle: &str, start: u64, end: u64) -> Result<LinesView, String> {
        let query = [("start", start.to_string()), ("end", end.to_string())];
        self.call(Method::GET, &format!("/api/blobs/{}/lines", segment(handle)), &query, None).await
    }

    /// A single-use code that opens the web UI (`POST /api/login-codes`).
    pub async fn login_code(&self) -> Result<String, String> {
        #[derive(serde::Deserialize)]
        struct Minted {
            code: String,
        }
        match self.call::<Minted>(Method::POST, "/api/login-codes", &[], None).await {
            Ok(minted) => Ok(minted.code),
            // Only a daemon from before login codes has no such route.
            Err(e) if e == NO_SUCH_PATH => Err(OLDER_DAEMON.to_string()),
            Err(e) => Err(e),
        }
    }

    /// Collect unreferenced stored outputs; a dry run unless `apply`. Walking a large store takes a while.
    pub async fn gc(&self, apply: bool) -> Result<loom_core::blob::SweepReport, String> {
        let body =
            serde_json::to_value(GcBody { apply }).map_err(|e| format!("The request cannot be encoded ({e})."))?;
        self.call_with_timeout(Method::POST, "/api/gc", &[], Some(body), Duration::from_secs(600)).await
    }

    pub async fn shutdown(&self) -> Result<(), String> {
        self.call_unit(Method::POST, "/api/shutdown", None).await
    }

    async fn open_stream(&self, path: &str, query: &[(&str, String)]) -> Result<EventStream, String> {
        let response = self.send_raw(Method::GET, path, query, None, None).await?;
        Ok(EventStream {
            response,
            parser: loom_model::assemble::SseParser::new(),
            ready: std::collections::VecDeque::new(),
            idle: STREAM_IDLE,
            done: false,
        })
    }

    pub async fn stream(&self, id: &SessionId, after: Option<Seq>) -> Result<EventStream, String> {
        let query: Vec<(&str, String)> = after.map(|a| vec![("after", a.to_string())]).unwrap_or_default();
        self.open_stream(&format!("/api/sessions/{}/stream", segment(id.as_str())), &query).await
    }

    pub async fn events(&self, deltas: bool) -> Result<EventStream, String> {
        let query: Vec<(&str, String)> = if deltas { vec![("deltas", "true".to_string())] } else { vec![] };
        self.open_stream("/api/events", &query).await
    }

    /// The session a word on the command line means.
    pub async fn resolve(&self, word: &str) -> Result<SessionId, String> {
        self.resolve_info(word).await.map(|info| info.meta.id)
    }

    async fn resolve_info(&self, word: &str) -> Result<SessionInfo, String> {
        if word == "last" {
            let list = self.sessions(false).await?;
            return list
                .into_iter()
                .filter(|s| !s.meta.archived)
                .max_by_key(|s| s.meta.created_ms)
                .ok_or_else(|| "There are no sessions yet.".to_string());
        }
        let list = self.sessions(true).await?;
        pick_session(list, word)
    }

    pub async fn mission_of(&self, word: &str) -> Result<MissionId, String> {
        if word.starts_with("m-") {
            return Ok(MissionId::from(word));
        }
        self.resolve_info(word).await.map(|info| info.meta.mission)
    }
}

/// The one session `word` names among `list`: an exact id, else a unique prefix (with or without
/// the `s-` the ids begin with).
fn pick_session(list: Vec<SessionInfo>, word: &str) -> Result<SessionInfo, String> {
    let none = || format!("No session matches `{word}`.");
    if let Some(i) = list.iter().position(|s| s.meta.id.as_str() == word) {
        return list.into_iter().nth(i).ok_or_else(none);
    }
    let prefixed = format!("s-{word}");
    let mut hits: Vec<SessionInfo> = list
        .into_iter()
        .filter(|s| s.meta.id.as_str().starts_with(word) || s.meta.id.as_str().starts_with(&prefixed))
        .collect();
    match hits.len() {
        0 => Err(none()),
        1 => hits.pop().ok_or_else(none),
        n => {
            let mut ids: Vec<String> = hits.iter().take(5).map(|s| s.meta.id.to_string()).collect();
            if n > 5 {
                ids.push("…".to_string());
            }
            Err(format!("`{word}` matches {n} sessions: {}. Give more of the id.", ids.join(", ")))
        }
    }
}

/// A scripted daemon for the tests of this module and of `cli`.
#[cfg(test)]
pub(crate) mod testkit {
    use super::*;
    use axum::body::{Body, Bytes};
    use axum::extract::State;
    use axum::http::{header, Request, StatusCode};
    use axum::response::Response;
    use axum::Router;
    use loom_agent::runtime::SessionMeta;
    use loom_agent::session::{Phase, Status};
    use loom_core::Record;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    /// One request the stub saw.
    #[derive(Clone, Debug)]
    pub struct Seen {
        pub method: String,
        /// Path and query.
        pub target: String,
        pub auth: Option<String>,
        pub body: String,
    }

    /// What an event stream does, in order.
    pub enum Piece {
        Data(String),
        Pause(u64),
        /// Break the connection.
        Abort,
    }

    #[derive(Default)]
    pub struct Script {
        /// (method, path without query, status, body)
        pub routes: Vec<(String, String, u16, String)>,
        /// One entry per stream request, in the order the requests come; `None` refuses it.
        pub streams: VecDeque<Option<Vec<Piece>>>,
        /// When set, `GET …/records` pages through these records like the daemon does.
        pub log: Option<Vec<Record>>,
        /// When set, `GET …/lines` serves a stored output of this many lines (`line {n}` + ESC).
        pub blob_total: Option<u64>,
        /// When set, `GET /healthz?nonce=…` proves this token like the daemon does.
        pub healthz_key: Option<String>,
        pub seen: Vec<Seen>,
    }

    pub type Shared = Arc<Mutex<Script>>;

    impl Script {
        pub fn route(mut self, method: &str, path: &str, status: u16, body: impl Into<String>) -> Script {
            self.routes.push((method.to_string(), path.to_string(), status, body.into()));
            self
        }
        pub fn stream(mut self, pieces: Vec<Piece>) -> Script {
            self.streams.push_back(Some(pieces));
            self
        }
        pub fn refuse_stream(mut self) -> Script {
            self.streams.push_back(None);
            self
        }
        pub fn blob_total(mut self, lines: u64) -> Script {
            self.blob_total = Some(lines);
            self
        }
        pub fn healthz_key(mut self, token: &str) -> Script {
            self.healthz_key = Some(token.to_string());
            self
        }
    }

    fn reply(status: u16, body: String) -> Response {
        let mut r = Response::new(Body::from(body));
        *r.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        r
    }

    async fn handle(State(shared): State<Shared>, req: Request<Body>) -> Response {
        let (parts, body) = req.into_parts();
        let bytes = axum::body::to_bytes(body, 1 << 20).await.unwrap_or_default();
        let path = parts.uri.path().to_string();
        let seen = Seen {
            method: parts.method.to_string(),
            target: parts.uri.path_and_query().map(|p| p.as_str().to_string()).unwrap_or_default(),
            auth: parts.headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).map(str::to_string),
            body: String::from_utf8_lossy(&bytes).into_owned(),
        };
        let mut script = shared.lock().unwrap();
        script.seen.push(seen);
        if path.ends_with("/stream") || path == "/api/events" {
            let pieces = match script.streams.pop_front() {
                Some(Some(pieces)) => pieces,
                Some(None) => return reply(503, String::new()),
                None => return reply(404, String::new()),
            };
            drop(script);
            let stream = futures_util::stream::unfold(pieces.into_iter(), |mut it| async move {
                loop {
                    match it.next()? {
                        Piece::Pause(ms) => tokio::time::sleep(Duration::from_millis(ms)).await,
                        Piece::Data(s) => return Some((Ok::<_, std::io::Error>(Bytes::from(s)), it)),
                        Piece::Abort => return Some((Err(std::io::Error::other("connection broken")), it)),
                    }
                }
            });
            let mut r = Response::new(Body::from_stream(stream));
            r.headers_mut().insert(header::CONTENT_TYPE, header::HeaderValue::from_static("text/event-stream"));
            return r;
        }
        let query = parts.uri.query().unwrap_or_default().to_string();
        if let (Some(key), "/healthz") = (&script.healthz_key, path.as_str()) {
            if let Some(nonce) = query.strip_prefix("nonce=") {
                let proof = crate::auth::healthz_proof(key, nonce).unwrap_or_default();
                return reply(200, json(&serde_json::json!({ "ok": true, "proof": proof })));
            }
        }
        let param = |name: &str| -> Option<u64> {
            query.split('&').find_map(|kv| kv.strip_prefix(name)?.strip_prefix('=')?.parse().ok())
        };
        if let (Some(log), true) = (&script.log, path.ends_with("/records")) {
            let limit = usize::try_from(param("limit").unwrap_or(500)).unwrap_or(500);
            let records: Vec<Record> =
                log.iter().filter(|r| param("after").is_none_or(|a| r.seq > a)).take(limit).cloned().collect();
            let next_after = if records.len() == limit { records.last().map(|r| r.seq) } else { None };
            return reply(200, json(&RecordsPage { records, next_after }));
        }
        if let (Some(total), true) = (script.blob_total, path.ends_with("/lines")) {
            let start = param("start").unwrap_or(1);
            let last = param("end").unwrap_or(2000).min(total);
            let text: String = (start..=last).map(|n| format!("line {n}\x1b\n")).collect();
            return reply(200, json(&LinesView { text, first: start, last, total }));
        }
        for (m, p, status, body) in &script.routes {
            if *m == parts.method.as_str() && *p == path {
                return reply(*status, body.clone());
            }
        }
        reply(404, String::new())
    }

    /// Start the stub on a free port; the client points at it with the token `tok-123`.
    pub async fn start(script: Script) -> (Client, Shared) {
        let shared: Shared = Arc::new(Mutex::new(script));
        let app = Router::new().fallback(handle).with_state(shared.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (Client::new(&format!("http://{addr}"), "tok-123"), shared)
    }

    /// An address nothing listens on.
    pub async fn dead_client() -> Client {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        Client::new(&format!("http://{addr}"), "tok-123")
    }

    pub fn status(phase: Phase) -> Status {
        Status {
            phase,
            step: 0,
            last_end: None,
            outcome: None,
            fork_point: None,
            epoch: 0,
            prompt_tokens: 0,
            cached_tokens: 0,
            completion_tokens_total: 0,
            open_inbox: 0,
        }
    }

    pub fn info(id: &str, created_ms: u64, archived: bool) -> SessionInfo {
        SessionInfo {
            meta: SessionMeta {
                id: SessionId::from(id),
                mission: MissionId::from(format!("m-of-{id}")),
                parent: None,
                workspace: "/w".into(),
                pack: "core".into(),
                role: "lead".into(),
                profile: "local".into(),
                model: "default".into(),
                context_window: None,
                title: String::new(),
                created_ms,
                mode: None,
                awaited: false,
                unattended: true,
                archived,
                gate: None,
            },
            active: false,
            status: status(Phase::Idle),
        }
    }

    pub fn json<T: serde::Serialize>(value: &T) -> String {
        serde_json::to_string(value).unwrap()
    }

    /// One `data:` event.
    pub fn sse(event: &BusEvent) -> String {
        format!("data: {}\n\n", json(event))
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;
    use crate::wire::ErrorBody;
    use loom_agent::runtime::ModelHealth;
    use loom_core::BlobId;
    use std::sync::{Arc, Mutex};

    fn status_view() -> StatusView {
        StatusView {
            version: "0.1.0".into(),
            pid: 42,
            started_ms: 1,
            bind: "127.0.0.1:7878".into(),
            proxy_port: 9000,
            home: "/h".into(),
            disk: Some(crate::wire::DiskSpace { free_bytes: 3 << 30, total_bytes: 1 << 40 }),
            models: vec![ModelHealth {
                profile: "local".into(),
                base_url: "http://m/v1".into(),
                model: "default".into(),
                reachable: true,
                detail: String::new(),
                context_window: Some(1000),
                max_concurrent: 4,
            }],
            sessions_total: 2,
            sessions_active: 1,
            sessions_running: 1,
            inbox_open: 0,
        }
    }

    #[test]
    fn base_loses_trailing_slashes_and_segments_are_encoded() {
        assert_eq!(Client::new("http://127.0.0.1:7878//", "t").base(), "http://127.0.0.1:7878");
        assert_eq!(segment("out:7f3a"), "out:7f3a");
        assert_eq!(segment("a b/c?d"), "a%20b%2Fc%3Fd");
    }

    #[tokio::test]
    async fn every_call_hits_its_route_with_the_bearer_token_and_parses_the_answer() {
        let one = info("s-1", 1, false);
        let detail = serde_json::json!({"children": []});
        let mut detail_obj = serde_json::to_value(&one).unwrap();
        if let (Some(o), Some(d)) = (detail_obj.as_object_mut(), detail.as_object()) {
            o.extend(d.clone());
        }
        let window = loom_agent::runtime::WindowView {
            epoch: 2,
            items: vec![],
            est_tokens: 10,
            target_tokens: 400,
            floor_tokens: 180,
            context_window: None,
            prompt_tokens: 5,
            cached_tokens: 4,
        };
        let ledger = loom_agent::runtime::LedgerView { markdown: "# ledger".into(), ..Default::default() };
        let blob = BlobRef { id: BlobId("ab".into()), bytes: 9, lines: 3 };
        let lines = LinesView { text: "a\nb\n".into(), first: 1, last: 2, total: 3 };
        let page = RecordsPage { records: vec![], next_after: Some(7) };
        let script = Script::default()
            .route("GET", "/api/status", 200, json(&status_view()))
            .route("GET", "/api/sessions", 200, json(&vec![one.clone()]))
            .route("POST", "/api/sessions", 201, json(&one))
            .route("GET", "/api/sessions/s-1", 200, detail_obj.to_string())
            .route("POST", "/api/sessions/s-1/messages", 202, "{}")
            .route("POST", "/api/sessions/s-1/stop", 202, "{}")
            .route("POST", "/api/sessions/s-1/resume", 202, "{}")
            .route("POST", "/api/sessions/s-1/reweave", 202, "{}")
            .route("POST", "/api/sessions/s-1/archive", 200, "{}")
            .route("GET", "/api/sessions/s-1/records", 200, json(&page))
            .route("GET", "/api/sessions/s-1/window", 200, json(&window))
            .route("GET", "/api/sessions/s-1/net", 200, "[]")
            .route("GET", "/api/missions", 200, "[]")
            .route("GET", "/api/missions/m-1/ledger", 200, json(&ledger))
            .route("GET", "/api/inbox", 200, "[]")
            .route("POST", "/api/inbox/i-1", 202, "{}")
            .route("GET", "/api/blobs/out:ab", 200, json(&blob))
            .route("GET", "/api/blobs/out:ab/lines", 200, json(&lines))
            .route("POST", "/api/shutdown", 202, "{}");
        let (client, shared) = start(script).await;
        let sid = SessionId::from("s-1");

        assert_eq!(client.status().await.unwrap(), status_view());
        // A daemon from before the disk figure leaves it out: unknown.
        let mut older = serde_json::to_value(status_view()).unwrap();
        older.as_object_mut().unwrap().remove("disk");
        assert_eq!(serde_json::from_value::<StatusView>(older).unwrap().disk, None);
        assert_eq!(client.sessions(false).await.unwrap(), vec![one.clone()]);
        assert_eq!(client.sessions(true).await.unwrap().len(), 1);
        let d = client.session(&sid).await.unwrap();
        assert_eq!(d.info, one);
        assert!(d.children.is_empty());
        let new = NewSession { workspace: "/w".into(), message: Some("hi".into()), ..Default::default() };
        assert_eq!(client.create(&new).await.unwrap(), one);
        client.send(&sid, "hello").await.unwrap();
        client.stop(&sid).await.unwrap();
        client.resume(&sid).await.unwrap();
        client.reweave(&sid).await.unwrap();
        client.archive(&sid, true).await.unwrap();
        assert_eq!(client.records(&sid, Some(3), 500).await.unwrap(), page);
        assert_eq!(client.window(&sid).await.unwrap(), window);
        assert!(client.net(&sid, 5).await.unwrap().is_empty());
        assert!(client.missions().await.unwrap().is_empty());
        assert_eq!(client.ledger(&MissionId::from("m-1")).await.unwrap(), ledger);
        assert!(client.inbox().await.unwrap().is_empty());
        client.answer("i-1", "yes").await.unwrap();
        assert_eq!(client.blob("out:ab").await.unwrap(), blob);
        assert_eq!(client.blob_lines("out:ab", 1, 5).await.unwrap(), lines);
        client.shutdown().await.unwrap();

        let seen = shared.lock().unwrap().seen.clone();
        let calls: Vec<(String, String)> = seen.iter().map(|s| (s.method.clone(), s.target.clone())).collect();
        let expected = [
            ("GET", "/api/status"),
            ("GET", "/api/sessions"),
            ("GET", "/api/sessions?archived=true"),
            ("GET", "/api/sessions/s-1"),
            ("POST", "/api/sessions"),
            ("POST", "/api/sessions/s-1/messages"),
            ("POST", "/api/sessions/s-1/stop"),
            ("POST", "/api/sessions/s-1/resume"),
            ("POST", "/api/sessions/s-1/reweave"),
            ("POST", "/api/sessions/s-1/archive"),
            ("GET", "/api/sessions/s-1/records?limit=500&after=3"),
            ("GET", "/api/sessions/s-1/window"),
            ("GET", "/api/sessions/s-1/net?limit=5"),
            ("GET", "/api/missions"),
            ("GET", "/api/missions/m-1/ledger"),
            ("GET", "/api/inbox"),
            ("POST", "/api/inbox/i-1"),
            ("GET", "/api/blobs/out:ab"),
            ("GET", "/api/blobs/out:ab/lines?start=1&end=5"),
            ("POST", "/api/shutdown"),
        ];
        let expected: Vec<(String, String)> = expected.iter().map(|(m, t)| (m.to_string(), t.to_string())).collect();
        assert_eq!(calls, expected);
        assert!(seen.iter().all(|s| s.auth.as_deref() == Some("Bearer tok-123")));
        let body = |n: usize| serde_json::from_str::<serde_json::Value>(&seen[n].body).unwrap();
        assert_eq!(body(4), serde_json::to_value(&new).unwrap());
        assert_eq!(body(5), serde_json::json!({"text": "hello"}));
        assert_eq!(body(9), serde_json::json!({"archived": true}));
        assert_eq!(body(16), serde_json::json!({"answer": "yes"}));
    }

    #[tokio::test]
    async fn rule_calls_hit_their_routes_with_their_bodies() {
        let receipt = |queued: bool, stock: Option<&str>| {
            serde_json::json!({"lead": "s-0", "queued": queued, "ledger": true, "stock": stock}).to_string()
        };
        let script = Script::default()
            .route("POST", "/api/sessions/s-1/rules", 202, receipt(true, None))
            .route("POST", "/api/sessions/s-1/approvals", 202, receipt(false, Some("only what the approval says")))
            .route("POST", "/api/sessions/s-1/rules/k1/withdraw", 202, receipt(false, None));
        let (client, shared) = start(script).await;
        let sid = SessionId::from("s-1");
        let lead = SessionId::from("s-0");
        let got = client.add_rule(&sid, "no prod").await.unwrap();
        assert_eq!(got, RuleReceipt { lead: lead.clone(), queued: true, ledger: true, stock: None });
        let got = client.approve(&sid, "ship", "staging").await.unwrap();
        assert_eq!((got.queued, got.stock.as_deref()), (false, Some("only what the approval says")));
        assert_eq!(client.withdraw_rule(&sid, "k1", "done").await.unwrap().lead, lead);
        let seen = shared.lock().unwrap().seen.clone();
        let body = |n: usize| serde_json::from_str::<serde_json::Value>(&seen[n].body).unwrap();
        assert_eq!(body(0), serde_json::json!({"text": "no prod"}));
        assert_eq!(body(1), serde_json::json!({"text": "ship", "scope": "staging"}));
        assert_eq!(body(2), serde_json::json!({"reason": "done"}));
    }

    #[tokio::test]
    async fn scope_and_release_calls_hit_their_routes_with_their_bodies() {
        let script = Script::default()
            .route(
                "POST",
                "/api/sessions/s-1/scope",
                202,
                serde_json::json!({"lead": "s-0", "hosts": ["a.test"], "ledger": true}).to_string(),
            )
            .route(
                "POST",
                "/api/sessions/s-1/release",
                202,
                serde_json::json!({"lead": "s-0", "queued": false, "ledger": true, "stock": null}).to_string(),
            );
        let (client, shared) = start(script).await;
        let sid = SessionId::from("s-1");
        let got = client.grant_scope(&sid, &["a.test".to_string()], Some("docs")).await.unwrap();
        assert_eq!((got.lead.as_str(), got.hosts, got.ledger), ("s-0", vec!["a.test".to_string()], true));
        client.grant_scope(&sid, &["a.test".to_string()], None).await.unwrap();
        assert_eq!(client.release(&sid, "gone").await.unwrap().lead.as_str(), "s-0");
        let seen = shared.lock().unwrap().seen.clone();
        let body = |n: usize| serde_json::from_str::<serde_json::Value>(&seen[n].body).unwrap();
        assert_eq!(body(0), serde_json::json!({"hosts": ["a.test"], "note": "docs"}));
        assert_eq!(body(1), serde_json::json!({"hosts": ["a.test"], "note": null}));
        assert_eq!(body(2), serde_json::json!({"reason": "gone"}));
    }

    #[tokio::test]
    async fn gc_posts_apply_and_reads_the_report() {
        let report =
            loom_core::blob::SweepReport { examined: 3, kept: 2, collected: 1, applied: true, ..Default::default() };
        let (client, shared) = start(Script::default().route("POST", "/api/gc", 200, json(&report))).await;
        assert_eq!(client.gc(true).await.unwrap(), report);
        let seen = shared.lock().unwrap().seen.clone();
        assert_eq!((seen[0].method.as_str(), seen[0].target.as_str()), ("POST", "/api/gc"));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&seen[0].body).unwrap(),
            serde_json::json!({"apply": true})
        );
        let refused = ErrorBody { error: "cannot read /h/sessions/s-1/x (denied); nothing was collected.".into() };
        let (client, _) = start(Script::default().route("POST", "/api/gc", 500, json(&refused))).await;
        assert_eq!(client.gc(false).await.unwrap_err(), refused.error);
    }

    #[tokio::test]
    async fn records_without_after_sends_only_the_limit_and_events_asks_for_deltas() {
        let script = Script::default()
            .route("GET", "/api/sessions/s-1/records", 200, json(&RecordsPage { records: vec![], next_after: None }))
            .stream(vec![])
            .stream(vec![]);
        let (client, shared) = start(script).await;
        client.records(&SessionId::from("s-1"), None, 2).await.unwrap();
        let mut a = client.events(true).await.unwrap();
        assert!(a.next().await.is_none());
        let mut b = client.events(false).await.unwrap();
        assert!(b.next().await.is_none());
        let targets: Vec<String> = shared.lock().unwrap().seen.iter().map(|s| s.target.clone()).collect();
        assert_eq!(targets, ["/api/sessions/s-1/records?limit=2", "/api/events?deltas=true", "/api/events"]);
    }

    #[tokio::test]
    async fn the_four_error_forms() {
        let dead = dead_client().await;
        let bind = dead.base().trim_start_matches("http://").to_string();
        assert_eq!(
            dead.status().await.unwrap_err(),
            format!("The loom daemon is not running (nothing answers on {bind}). Start it with `loom up`.")
        );
        assert!(dead.stream(&SessionId::from("s-1"), None).await.is_err_and(|e| e.contains("`loom up`")));
        assert!(!dead.alive().await);

        let script = Script::default()
            .route("GET", "/api/status", 409, json(&ErrorBody { error: "There is no session s-9.".into() }))
            .route("GET", "/api/inbox", 500, "")
            .route("GET", "/api/missions", 200, "[1]");
        let (client, _) = start(script).await;
        assert_eq!(client.status().await.unwrap_err(), "There is no session s-9.");
        assert_eq!(
            client.inbox().await.unwrap_err(),
            "The daemon answered 500 Internal Server Error to GET /api/inbox."
        );
        let e = client.missions().await.unwrap_err();
        assert!(e.starts_with("The daemon's answer to GET /api/missions was not understood ("), "{e}");
        assert!(e.ends_with("the `loom` command and the daemon may be different versions."), "{e}");
        assert_eq!(
            client.window(&SessionId::from("s-1")).await.unwrap_err(),
            "The daemon answered 404 Not Found to GET /api/sessions/s-1/window."
        );
    }

    #[tokio::test]
    async fn the_error_of_a_refused_request_does_not_contain_the_token() {
        let script = Script::default().route("POST", "/api/shutdown", 401, "not json");
        let (client, _) = start(script).await;
        let e = client.shutdown().await.unwrap_err();
        assert!(!e.contains("tok-123"));
        assert_eq!(e, "The daemon answered 401 Unauthorized to POST /api/shutdown.");
    }

    #[tokio::test]
    async fn a_login_code_is_asked_for_with_the_token_and_an_older_daemon_is_told_apart() {
        let script = Script::default().route("POST", "/api/login-codes", 200, r#"{"code":"c0de","expires_in_s":60}"#);
        let (client, shared) = start(script).await;
        assert_eq!(client.login_code().await.unwrap(), "c0de");
        let seen = shared.lock().unwrap().seen.clone();
        assert_eq!((seen[0].method.as_str(), seen[0].target.as_str()), ("POST", "/api/login-codes"));
        assert_eq!(seen[0].auth.as_deref(), Some("Bearer tok-123"));

        // A daemon from before login codes answers as it does to any unknown path: say what to do.
        let unknown = json(&ErrorBody { error: "There is no such path on the loom daemon.".into() });
        let (client, _) = start(Script::default().route("POST", "/api/login-codes", 404, unknown)).await;
        assert_eq!(
            client.login_code().await.unwrap_err(),
            "The running daemon is older than this `loom` and cannot issue login codes. Restart it (`loom down`, then `loom up`) and run `loom open` again."
        );

        // Any other refusal is the daemon's own sentence.
        let refused = json(&ErrorBody { error: "Missing or wrong access token.".into() });
        let (client, _) = start(Script::default().route("POST", "/api/login-codes", 401, refused)).await;
        assert_eq!(client.login_code().await.unwrap_err(), "Missing or wrong access token.");
    }

    #[tokio::test]
    async fn alive_asks_healthz() {
        let (client, shared) = start(Script::default().route("GET", "/healthz", 200, "ok")).await;
        assert!(client.alive().await);
        assert_eq!(shared.lock().unwrap().seen[0].target, "/healthz");
        let (client, _) = start(Script::default()).await;
        assert!(!client.alive().await);
    }

    fn auth_headers_seen(shared: &Shared) -> Vec<Option<String>> {
        shared.lock().unwrap().seen.iter().map(|s| s.auth.clone()).collect()
    }

    #[tokio::test]
    async fn a_listener_without_a_proof_never_sees_the_token() {
        let status_ok = json(&status_view());
        // Answers 200 to everything, as a plain `ok`, with no proof field, or with a wrong proof.
        let wrong = format!("{{\"ok\":true,\"proof\":\"{}\"}}", "0".repeat(64));
        for healthz in ["ok", "{\"ok\":true}", wrong.as_str()] {
            let script = Script::default().route("GET", "/healthz", 200, healthz).route(
                "GET",
                "/api/status",
                200,
                status_ok.clone(),
            );
            let (client, shared) = start(script).await;
            let client = client.verifying();
            let e = client.status().await.unwrap_err();
            assert!(
                e.contains("did not prove it is this home's loom daemon") && e.contains("--unverified-daemon"),
                "{e}"
            );
            assert!(e.contains("older daemon") || e.contains("older than this"), "{e}");
            // A second call asks again and is refused again; no request ever carried the token.
            assert!(client.sessions(false).await.is_err());
            assert!(auth_headers_seen(&shared).iter().all(Option::is_none), "{:?}", shared.lock().unwrap().seen);
            assert!(shared.lock().unwrap().seen.iter().all(|s| s.target.starts_with("/healthz?nonce=")));
        }
    }

    #[tokio::test]
    async fn the_override_sends_the_token_to_an_unproven_listener_and_a_proof_proceeds() {
        let status_ok = json(&status_view());
        let (client, shared) = start(Script::default().route("GET", "/healthz", 200, "ok").route(
            "GET",
            "/api/status",
            200,
            status_ok.clone(),
        ))
        .await;
        let bind = client.base().trim_start_matches("http://").to_string();
        let client = client.verifying().allowing_unverified();
        let warned = || WARNINGS.lock().unwrap().iter().filter(|w| **w == unverified_warning(&bind)).count();
        let before = warned();
        client.status().await.unwrap();
        client.clone().status().await.unwrap();
        let bearer = || Some("Bearer tok-123".to_string());
        assert_eq!(auth_headers_seen(&shared), vec![None, bearer(), None, bearer()]);
        // Asked each time, warned once.
        assert_eq!(warned() - before, 1, "{:?}", WARNINGS.lock().unwrap());

        // A correct proof: a check before every request, and the token goes along.
        let script = Script::default().healthz_key("tok-123").route("GET", "/api/status", 200, status_ok);
        let (client, shared) = start(script).await;
        let client = client.verifying();
        client.status().await.unwrap();
        client.status().await.unwrap();
        assert_eq!(auth_headers_seen(&shared), vec![None, bearer(), None, bearer()]);

        // The proof is for this token: a daemon that holds another one is refused.
        let (client, shared) = start(Script::default().healthz_key("other")).await;
        assert!(client.verifying().status().await.is_err());
        assert!(auth_headers_seen(&shared).iter().all(Option::is_none));
    }

    /// A stand-in listener on `addr`: answers `/healthz?nonce=` with a proof of `key` when it has one, and every
    /// other path `ok`; the `Authorization` header of each request it gets goes to `seen`. Stops on `stop`.
    async fn listener_on(
        addr: std::net::SocketAddr,
        key: Option<&'static str>,
        seen: Arc<Mutex<Vec<Option<String>>>>,
        stop: tokio_util::sync::CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        let app = axum::Router::new().fallback(move |req: axum::http::Request<axum::body::Body>| {
            let seen = seen.clone();
            async move {
                let auth = req.headers().get("authorization").and_then(|v| v.to_str().ok()).map(str::to_string);
                seen.lock().unwrap().push(auth);
                let nonce = req.uri().query().and_then(|q| q.strip_prefix("nonce=")).map(str::to_string);
                match (key, nonce) {
                    (Some(key), Some(nonce)) => {
                        let proof = crate::auth::healthz_proof(key, &nonce).unwrap_or_default();
                        format!("{{\"ok\":true,\"proof\":\"{proof}\"}}")
                    }
                    _ => "ok".to_string(),
                }
            }
        });
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).with_graceful_shutdown(async move { stop.cancelled().await }).await;
        })
    }

    #[tokio::test]
    async fn a_listener_that_takes_the_port_while_the_client_is_quiet_is_asked_for_a_proof_again() {
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        let (daemon_seen, impostor_seen) = (Arc::new(Mutex::new(Vec::new())), Arc::new(Mutex::new(Vec::new())));
        let stop = tokio_util::sync::CancellationToken::new();
        let daemon = listener_on(addr, Some("tok-123"), daemon_seen.clone(), stop.clone()).await;
        let client = Client::new(&format!("http://{addr}"), "tok-123").verifying();
        // The daemon proves itself and gets the token, for a request (its answer is not a status, which does not
        // matter here) and for a stream that is dropped unread, as a `loom chat` waiting for its next line does.
        let _ = client.status().await;
        drop(client.events(false).await.unwrap());
        let bearer = || Some("Bearer tok-123".to_string());
        assert_eq!(*daemon_seen.lock().unwrap(), vec![None, bearer(), None, bearer()]);

        // The daemon stops cleanly with nothing sent in between, and something else binds its port: the client's
        // next call is refused before the token goes out.
        stop.cancel();
        daemon.await.unwrap();
        let impostor = listener_on(addr, None, impostor_seen.clone(), tokio_util::sync::CancellationToken::new()).await;
        // The quiet time (in which the client also sees its idle connection to the daemon closed).
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(client.status().await.unwrap_err(), unproven_message(&addr.to_string()));
        assert_eq!(*impostor_seen.lock().unwrap(), vec![None]);
        impostor.abort();
    }

    fn listing() -> Script {
        Script::default().route(
            "GET",
            "/api/sessions",
            200,
            json(&vec![
                info("s-aaa1", 1, false),
                info("s-aab2", 9, true),
                info("s-bbb3", 3, false),
                info("s-ab", 4, false),
                info("s-abc", 5, false),
            ]),
        )
    }

    #[tokio::test]
    async fn resolve_exact_prefix_last_none_and_several() {
        let (client, _) = start(listing()).await;
        assert_eq!(client.resolve("s-aaa1").await.unwrap().as_str(), "s-aaa1");
        assert_eq!(client.resolve("bbb").await.unwrap().as_str(), "s-bbb3");
        assert_eq!(client.resolve("s-bb").await.unwrap().as_str(), "s-bbb3");
        assert_eq!(client.resolve("aaa").await.unwrap().as_str(), "s-aaa1");
        // An exact id wins even when it is also the beginning of another.
        assert_eq!(client.resolve("s-ab").await.unwrap().as_str(), "s-ab");
        // Archived sessions are found by id, but are not `last`.
        assert_eq!(client.resolve("s-aab2").await.unwrap().as_str(), "s-aab2");
        assert_eq!(client.resolve("last").await.unwrap().as_str(), "s-abc");
        assert_eq!(client.resolve("zzz").await.unwrap_err(), "No session matches `zzz`.");
        assert_eq!(
            client.resolve("aa").await.unwrap_err(),
            "`aa` matches 2 sessions: s-aaa1, s-aab2. Give more of the id."
        );
    }

    #[tokio::test]
    async fn resolve_lists_at_most_five_ids_and_last_needs_a_session() {
        let many: Vec<SessionInfo> = (1..=7).map(|n| info(&format!("s-x{n}"), n, false)).collect();
        let (client, _) = start(Script::default().route("GET", "/api/sessions", 200, json(&many))).await;
        assert_eq!(
            client.resolve("x").await.unwrap_err(),
            "`x` matches 7 sessions: s-x1, s-x2, s-x3, s-x4, s-x5, …. Give more of the id."
        );
        let (client, _) = start(Script::default().route("GET", "/api/sessions", 200, "[]")).await;
        assert_eq!(client.resolve("last").await.unwrap_err(), "There are no sessions yet.");
    }

    #[tokio::test]
    async fn mission_of_takes_mission_ids_as_they_are_and_otherwise_asks_the_session() {
        let (client, shared) = start(listing()).await;
        assert_eq!(client.mission_of("m-77").await.unwrap().as_str(), "m-77");
        assert!(shared.lock().unwrap().seen.is_empty());
        assert_eq!(client.mission_of("bbb").await.unwrap().as_str(), "m-of-s-bbb3");
    }

    fn lagged(n: u64) -> BusEvent {
        BusEvent::Lagged { missed: n }
    }

    #[tokio::test]
    async fn a_stream_yields_events_split_across_chunks_and_skips_comments_and_garbage() {
        let first = sse(&lagged(1));
        let (a, b) = first.split_at(first.len() / 2);
        let err = BusEvent::Error { session: None, message: "boom".into() };
        let script = Script::default().stream(vec![
            Piece::Data(a.to_string()),
            Piece::Pause(20),
            Piece::Data(format!("{b}: keep-alive\n\ndata: this is not json\n\n")),
            Piece::Pause(20),
            Piece::Data(sse(&err)),
        ]);
        let (client, shared) = start(script).await;
        let mut stream = client.stream(&SessionId::from("s-1"), Some(4)).await.unwrap();
        assert_eq!(stream.next().await.unwrap().unwrap(), lagged(1));
        assert_eq!(stream.next().await.unwrap().unwrap(), err);
        assert!(stream.next().await.is_none());
        assert!(stream.next().await.is_none());
        let seen = shared.lock().unwrap().seen.clone();
        assert_eq!(seen[0].target, "/api/sessions/s-1/stream?after=4");
        assert_eq!(seen[0].auth.as_deref(), Some("Bearer tok-123"));
    }

    #[tokio::test]
    async fn a_streamed_record_served_as_stored_arrives_as_the_log_reader_reads_it() {
        // A known kind holding a value this build does not know (an opaque record), as a replay sends it.
        let line = concat!(
            r#"{"seq":7,"ts_ms":8,"author":"harness","prev":"abc","kind":"harness_note","#,
            r#""note":"from_a_newer_loom","text":"x","more":[1]}"#
        );
        let stored = format!("data: {{\"type\":\"record\",\"session\":\"s-1\",\"record\":{line}}}\n\n");
        let not_a_record = "data: {\"type\":\"record\",\"session\":\"s-1\",\"record\":{\"kind\":\"user_message\"}}\n\n";
        let script = Script::default().stream(vec![
            Piece::Data(stored),
            Piece::Data(not_a_record.into()),
            Piece::Data(sse(&lagged(3))),
        ]);
        let (client, _) = start(script).await;
        let mut stream = client.stream(&SessionId::from("s-1"), None).await.unwrap();
        let Some(Ok(BusEvent::Record { session, record })) = stream.next().await else { panic!("no record came") };
        assert_eq!(session, SessionId::from("s-1"));
        let read = (record.seq, record.ts_ms, record.prev.as_str(), &record.event);
        assert_eq!(read, (7, 8, "abc", &loom_core::Event::Unknown));
        assert_eq!(stream.next().await.unwrap().unwrap(), lagged(3));
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn a_broken_connection_is_one_error_and_then_the_end() {
        let script = Script::default().stream(vec![Piece::Data(sse(&lagged(2))), Piece::Pause(20), Piece::Abort]);
        let (client, _) = start(script).await;
        let mut stream = client.stream(&SessionId::from("s-1"), None).await.unwrap();
        assert_eq!(stream.next().await.unwrap().unwrap(), lagged(2));
        assert_eq!(stream.next().await.unwrap().unwrap_err(), "The connection to the daemon was lost.");
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn a_silent_stream_is_a_lost_connection() {
        let script = Script::default().stream(vec![Piece::Data(": hi\n\n".into()), Piece::Pause(5_000)]);
        let (client, _) = start(script).await;
        let mut stream = client.events(false).await.unwrap();
        stream.idle = Duration::from_millis(150);
        assert_eq!(stream.next().await.unwrap().unwrap_err(), "The connection to the daemon was lost.");
    }

    #[tokio::test]
    async fn a_refused_stream_reports_the_daemons_sentence() {
        let (client, _) = start(Script::default()).await;
        let e = client.stream(&SessionId::from("s-1"), None).await.err().unwrap();
        assert_eq!(e, "The daemon answered 404 Not Found to GET /api/sessions/s-1/stream.");
    }

    #[test]
    fn from_home_prefers_daemon_json_then_config_then_the_default() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path());
        let e = Client::from_home(&paths).err().unwrap();
        assert_eq!(
            e,
            format!(
                "There is no access token at {}; the daemon creates it the first time it starts (`loom up`).",
                paths.token_file().display()
            )
        );
        std::fs::write(paths.token_file(), "  tok-abc\n").unwrap();
        let c = Client::from_home(&paths).unwrap();
        assert_eq!(c.base(), "http://127.0.0.1:7878");
        assert_eq!(c.token(), "tok-abc");
        assert!(c.verify, "a client for a home must ask the listener for its proof before sending the token");
        assert!(!c.allow_unverified);
        assert!(Client::from_home_allowing(&paths, true).unwrap().allow_unverified, "the flag reaches the client");
        std::fs::write(paths.config_file(), "[daemon]\nbind = \"127.0.0.1:1111\"\n").unwrap();
        assert_eq!(Client::from_home(&paths).unwrap().base(), "http://127.0.0.1:1111");
        let file = DaemonFile { pid: 1, bind: "127.0.0.1:9999".into(), started_ms: 0 };
        std::fs::write(dir.path().join("daemon.json"), serde_json::to_string(&file).unwrap()).unwrap();
        assert_eq!(Client::from_home(&paths).unwrap().base(), "http://127.0.0.1:9999");
        // A daemon.json that cannot be read is ignored.
        std::fs::write(dir.path().join("daemon.json"), "{").unwrap();
        assert_eq!(Client::from_home(&paths).unwrap().base(), "http://127.0.0.1:1111");
        // A config that does not load is reported with its path.
        std::fs::write(paths.config_file(), "not [toml").unwrap();
        let e = Client::from_home(&paths).err().unwrap();
        assert!(e.contains("config.toml"), "{e}");
    }
}
