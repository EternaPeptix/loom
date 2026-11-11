//! The API as typed calls, for the command line.
//!
//! CONTRACT (bodies are placeholders for the implementer; public signatures and types are fixed).
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
//! - `resolve(word)`: the session a word on the command line means. `last` → the most recently
//!   created session that is not archived (`There are no sessions yet.`). Otherwise among all
//!   sessions (archived included): the one whose id equals `word`; else those whose id starts with
//!   `word` or with `s-{word}`. One → it. None → `No session matches `{word}`.` Several → `` `{word}`
//!   matches {n} sessions: {ids, at most 5, then "…"}. Give more of the id. ``
//! - `mission_of(word)`: a word starting with `m-` is taken as a mission id as it is; otherwise
//!   `resolve(word)` and that session's mission.
//! - `stream(id, after)` / `events(deltas)`: open the event stream and return an [`EventStream`].
//!   `EventStream::next()` yields each event as a `BusEvent` (`loom_model::assemble::SseParser` over
//!   the body's chunks, each payload parsed as `BusEvent`; a payload that does not parse is skipped
//!   with `tracing::debug!`), `None` when the server closes the stream, `Some(Err(sentence))` when
//!   the connection breaks (`The connection to the daemon was lost.`).
//!
//! Tests required (against a small `axum` server in the test that plays the daemon — no runtime
//! needed): the bearer header is sent; each call hits the documented method and path and parses the
//! documented body; the four error forms; `resolve` (exact, prefix with and without `s-`, `last`,
//! none, several); `mission_of`; a stream delivering events split across chunks, a comment line and
//! an unparsable payload in between, then end of stream; `from_home` preferring `daemon.json`.

use crate::wire::{LinesView, RecordsPage, SessionDetail, StatusView};
use loom_agent::runtime::{
    BusEvent, InboxEntry, LedgerView, MissionInfo, NetEntry, NewSession, SessionInfo, WindowView,
};
use loom_core::config::Paths;
use loom_core::event::Seq;
use loom_core::{BlobRef, MissionId, SessionId};

/// A connection to one daemon.
#[derive(Clone)]
pub struct Client {
    base: String,
    token: String,
    http: reqwest::Client,
}

/// An open event stream.
pub struct EventStream {
    response: reqwest::Response,
    parser: loom_model::assemble::SseParser,
    ready: std::collections::VecDeque<BusEvent>,
}

impl EventStream {
    /// The next event; `None` when the stream has ended.
    pub async fn next(&mut self) -> Option<Result<BusEvent, String>> {
        let _ = (&mut self.response, &mut self.parser, &mut self.ready);
        todo!("implement per module contract")
    }
}

impl Client {
    pub fn new(base: &str, token: &str) -> Client {
        let _ = (base, token);
        todo!("implement per module contract")
    }

    pub fn from_home(paths: &Paths) -> Result<Client, String> {
        let _ = paths;
        todo!("implement per module contract")
    }

    /// `http://127.0.0.1:7878`.
    pub fn base(&self) -> &str {
        &self.base
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    /// Whether a daemon answers `/healthz` (2 s).
    pub async fn alive(&self) -> bool {
        let _ = &self.http;
        todo!("implement per module contract")
    }

    pub async fn status(&self) -> Result<StatusView, String> {
        todo!("implement per module contract")
    }

    pub async fn sessions(&self, archived: bool) -> Result<Vec<SessionInfo>, String> {
        let _ = archived;
        todo!("implement per module contract")
    }

    pub async fn session(&self, id: &SessionId) -> Result<SessionDetail, String> {
        let _ = id;
        todo!("implement per module contract")
    }

    pub async fn create(&self, new: &NewSession) -> Result<SessionInfo, String> {
        let _ = new;
        todo!("implement per module contract")
    }

    pub async fn send(&self, id: &SessionId, text: &str) -> Result<(), String> {
        let _ = (id, text);
        todo!("implement per module contract")
    }

    pub async fn stop(&self, id: &SessionId) -> Result<(), String> {
        let _ = id;
        todo!("implement per module contract")
    }

    pub async fn resume(&self, id: &SessionId) -> Result<(), String> {
        let _ = id;
        todo!("implement per module contract")
    }

    pub async fn reweave(&self, id: &SessionId) -> Result<(), String> {
        let _ = id;
        todo!("implement per module contract")
    }

    pub async fn archive(&self, id: &SessionId, archived: bool) -> Result<(), String> {
        let _ = (id, archived);
        todo!("implement per module contract")
    }

    pub async fn records(&self, id: &SessionId, after: Option<Seq>, limit: usize) -> Result<RecordsPage, String> {
        let _ = (id, after, limit);
        todo!("implement per module contract")
    }

    pub async fn window(&self, id: &SessionId) -> Result<WindowView, String> {
        let _ = id;
        todo!("implement per module contract")
    }

    pub async fn net(&self, id: &SessionId, limit: usize) -> Result<Vec<NetEntry>, String> {
        let _ = (id, limit);
        todo!("implement per module contract")
    }

    pub async fn missions(&self) -> Result<Vec<MissionInfo>, String> {
        todo!("implement per module contract")
    }

    pub async fn ledger(&self, mission: &MissionId) -> Result<LedgerView, String> {
        let _ = mission;
        todo!("implement per module contract")
    }

    pub async fn inbox(&self) -> Result<Vec<InboxEntry>, String> {
        todo!("implement per module contract")
    }

    pub async fn answer(&self, item_id: &str, answer: &str) -> Result<(), String> {
        let _ = (item_id, answer);
        todo!("implement per module contract")
    }

    pub async fn blob(&self, handle: &str) -> Result<BlobRef, String> {
        let _ = handle;
        todo!("implement per module contract")
    }

    pub async fn blob_lines(&self, handle: &str, start: u64, end: u64) -> Result<LinesView, String> {
        let _ = (handle, start, end);
        todo!("implement per module contract")
    }

    pub async fn shutdown(&self) -> Result<(), String> {
        todo!("implement per module contract")
    }

    pub async fn stream(&self, id: &SessionId, after: Option<Seq>) -> Result<EventStream, String> {
        let _ = (id, after);
        todo!("implement per module contract")
    }

    pub async fn events(&self, deltas: bool) -> Result<EventStream, String> {
        let _ = deltas;
        todo!("implement per module contract")
    }

    pub async fn resolve(&self, word: &str) -> Result<SessionId, String> {
        let _ = word;
        todo!("implement per module contract")
    }

    pub async fn mission_of(&self, word: &str) -> Result<MissionId, String> {
        let _ = word;
        todo!("implement per module contract")
    }
}
