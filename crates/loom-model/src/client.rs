//! [`ModelClient`]: one streamed chat completion, retried until it succeeds, is refused, or is
//! cancelled.
//!
//! CONTRACT (bodies are placeholders for the implementer; signatures and types are fixed).
//!
//! ## `complete`
//! One call = one logical completion. Per attempt:
//! 1. emit `StreamEvent::AttemptStart { attempt }` (attempts count from 1);
//! 2. `POST {base_url}/chat/completions` with `ChatRequest::body(profile.model, profile.extra_body)`,
//!    header `Authorization: Bearer {key}` when `profile.api_key_env` names a non-empty variable,
//!    `Accept: text/event-stream`. No request timeout is set on the whole request; instead:
//! 3. while reading (headers and every body chunk), waiting longer than `profile.stall_timeout_s`
//!    for the next bytes fails the attempt as a stall. Connecting has a 10 s timeout;
//! 4. feed the body through `SseParser` and `Assembler`, forwarding stream events to `events`;
//! 5. success = `Assembler::finish()` returns a completion. Fill `timing.ttft_ms` (request sent →
//!    first text/reasoning/tool-call event), `timing.total_ms`, and `attempts`. `timing.queue_ms`
//!    stays 0.
//!
//! Outcomes of a failed attempt:
//! - **retry**: connect/transport error, stall, HTTP 408/425/429/5xx, `AssembleError::Incomplete`,
//!   `AssembleError::Malformed`, `AssembleError::Server` (an error object inside a 200 stream);
//! - **context overflow** (no retry): HTTP 400 or 413 whose message matches the server's wording for
//!   an over-long prompt — any of `maximum context length`, `context length`, `too many tokens`,
//!   `prompt is too long`, `max_model_len`, case-insensitive → `ModelError::ContextOverflow`, with
//!   `limit`/`requested` parsed from the first two integers ≥ 1000 in the message when present;
//! - **rejected** (no retry): any other 4xx → `ModelError::Rejected { status, message }`. `message`
//!   is the server's `error.message` (or `message`, or `detail`) when the body is JSON, else the
//!   first 2000 characters of the body.
//!
//! Retry pacing: delays 0.5 s, 1 s, 2 s, 4 s, … capped at `profile.retry_max_delay_s`, each with
//! ±10% jitter. A `Retry-After` header (seconds) replaces the computed delay when it is larger, up to
//! 600 s. Before sleeping, emit `StreamEvent::Retrying`. `profile.retry_window_s == 0` retries until
//! cancelled; otherwise, when the time since the first failure of this call exceeds the window,
//! return `ModelError::Unavailable { attempts, last }`.
//!
//! Cancellation: `cancel` is observed while connecting, reading and sleeping; it returns
//! `ModelError::Cancelled` promptly (the HTTP request is dropped). Whatever text had streamed is
//! returned in `Cancelled { partial }` so the caller can record what the model had said.
//!
//! Nothing from a failed attempt is ever part of the returned completion.
//!
//! ## `discover`
//! `GET {base_url}/models`. Find the entry whose `id` equals `profile.model` (if none matches and
//! there is exactly one entry, use it and set `served_model` to its id). The window is the first of
//! `max_model_len`, `context_window`, `context_length`, `max_context_length` that is a positive
//! integer → `WindowSource::Server`. If the profile sets `context_window`, that value is used and the
//! source is `WindowSource::Config` — and when the server reports a smaller number,
//! `server_window` carries it so the caller can warn. With neither, `context_window` is `None`
//! (`WindowSource::Unknown`): the caller must refuse to start rather than guess.
//!
//! ## `health`
//! `GET {base_url}/models` with a 5 s timeout → true on 2xx.
//!
//! Tests required (all against `crate::mock::MockServer`): a plain reply; a tool-call reply; events
//! arrive in order with `AttemptStart` first; retry after 500 then success (attempts == 2, events of
//! the failed attempt precede a second `AttemptStart`); connection dropped mid-stream is retried and
//! the partial text does not leak into the result; stall detection (short `stall_timeout_s`);
//! `Retry-After` honoured; retry window exhausted → `Unavailable`; 400 → `Rejected` with the
//! server's message; overflow wording → `ContextOverflow` with parsed numbers; cancellation during
//! a stream and during a retry sleep; server unreachable then started later is picked up; bearer
//! header sent only when configured; `discover` for each source; `timing` is plausible.

use crate::assemble::{Completion, StreamEvent};
use crate::request::ChatRequest;
use loom_core::config::ModelProfile;
use tokio::sync::mpsc::UnboundedSender;
use tokio_util::sync::CancellationToken;

#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    #[error("cancelled")]
    Cancelled { partial: Option<Box<Completion>> },
    /// The prompt does not fit the server's window. The caller shrinks the request and tries again.
    #[error("the request is larger than the model's context window: {message}")]
    ContextOverflow { limit: Option<u64>, requested: Option<u64>, message: String },
    /// The server refused the request as malformed. Retrying the same request cannot help.
    #[error("the model server rejected the request (HTTP {status}): {message}")]
    Rejected { status: u16, message: String },
    #[error("the model server did not answer after {attempts} attempts: {last}")]
    Unavailable { attempts: u32, last: String },
    #[error("model profile: {0}")]
    Config(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowSource {
    Server,
    Config,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Discovered {
    /// The model id requests will carry.
    pub served_model: String,
    pub context_window: Option<u64>,
    pub source: WindowSource,
    /// What the server reported, when it reported anything.
    pub server_window: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct ModelClient {
    name: String,
    profile: ModelProfile,
    http: reqwest::Client,
}

impl ModelClient {
    /// `name` is the profile's name (for messages). Fails when `base_url` is not an http(s) URL.
    pub fn new(name: &str, profile: ModelProfile) -> Result<ModelClient, ModelError> {
        let _ = (name, profile);
        todo!("implement per module contract")
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn profile(&self) -> &ModelProfile {
        &self.profile
    }

    pub async fn complete(
        &self,
        request: &ChatRequest,
        events: Option<&UnboundedSender<StreamEvent>>,
        cancel: &CancellationToken,
    ) -> Result<Completion, ModelError> {
        let _ = (&self.http, request, events, cancel);
        todo!("implement per module contract")
    }

    pub async fn discover(&self) -> Result<Discovered, ModelError> {
        todo!("implement per module contract")
    }

    pub async fn health(&self) -> bool {
        todo!("implement per module contract")
    }
}
