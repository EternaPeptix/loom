//! [`ModelClient`]: one streamed chat completion, retried until it succeeds, is refused, or is
//! cancelled.
//!
//! CONTRACT.
//!
//! ## `complete`
//! One call = one logical completion. Per attempt:
//! 1. emit `StreamEvent::AttemptStart { attempt }` (attempts count from 1);
//! 2. `POST {base_url}/chat/completions` with `ChatRequest::body(model, profile.extra_body)`, where
//!    `model` is the id `discover` last selected, else `profile.model` (see **unknown model** below),
//!    header `Authorization: Bearer {key}` when the profile has a key (see **Keys**),
//!    `Accept: text/event-stream`. No request timeout is set on the whole request; instead:
//! 3. while reading (headers and every body chunk), waiting longer than `profile.stall_timeout_s`
//!    for the next bytes fails the attempt as a stall. Connecting has a 10 s timeout;
//! 4. feed the body through `SseParser` and `Assembler`, forwarding stream events to `events`;
//! 5. success = `Assembler::finish()` returns a completion. Fill `timing.ttft_ms` (request sent →
//!    first text/reasoning/tool-call event), `timing.total_ms`, and `attempts`. `timing.queue_ms`
//!    stays 0.
//!
//! Outcomes of a failed attempt:
//! - **retry**: connect/transport error, stall, HTTP 408/425/429/5xx, `AssembleError::Server` (an
//!   error object inside a 200 stream);
//! - **retry, until 3 attempts in a row have failed this way** (the third is the last: it returns
//!   `ModelError::Unavailable` whatever the window): a failure waiting cannot cure — a 200 whose body
//!   is not an event stream, `AssembleError::Malformed`, `AssembleError::Oversize` (a stream line, event
//!   or completion over its size limit), a clean end of stream with no
//!   `finish_reason`, and send errors that are not about reaching the server (request building, TLS
//!   certificate or protocol, an answer that is not HTTP). A send error is sorted by its causes, never
//!   by its own text, which carries the request URL. These count together; a failure of the plain
//!   retry kind in between resets the count;
//! - **redirect** (no retry): the client follows none; a 3xx → `ModelError::Rejected` naming
//!   `Location` and the `base_url` it implies (that address without `/chat/completions`);
//! - **unknown model**: on HTTP 404, ask the server what it serves, as `discover` does. A
//!   `ModelError::Config` from that (several served models, none the configured one) is returned.
//!   When the answer selects another id than the one sent, what follows depends on whether discovery
//!   has selected an id in this process before:
//!   - it has not (a session restored after a daemon restart, or begun while the server was down):
//!     the id is remembered and the request is sent again at once with it, once per call;
//!   - it has (a successful `discover`, or an id learned through this 404 path in the same process, since
//!     the id is shared by all clones), so the server was relaunched with another model: the 404 is
//!     **rejected** with a sentence naming the id now served, and the remembered id stays. What a
//!     session recorded at its start (model id, context window) describes the old model, so the move
//!     is the operator's: ferret never follows the new id on its own once an id is remembered, and only a
//!     daemon restart (or a new successful `discover`, which replaces the remembered id for every
//!     clone of the client) moves on to it.
//!
//!   In every other case the 404 is **rejected** as below;
//! - **context overflow** (no retry): HTTP 400, 413 or 422 whose message matches the server's wording
//!   for an over-long prompt — any of `maximum context length`, `context length`, `too many tokens`,
//!   `prompt is too long`, `max_model_len`, `exceeds the available context size` (llama.cpp),
//!   `input is too long`, case-insensitive — or whose JSON error object has a `type` or `code` (string)
//!   of `exceed_context_size_error` (llama.cpp) or `context_length_exceeded` → `ModelError::ContextOverflow`.
//!   `limit`/`requested`: the error object's `n_ctx` / `n_prompt_tokens` when they are positive
//!   integers. Otherwise from the message, in this order: the integer right after `maximum context
//!   length is ` or after `context size (` / `context size of ` (case-insensitive) is `limit`, and
//!   `requested` is then the first integer ≥ 1000 in the message larger than it, or `None` (vLLM's
//!   `max_tokens` refusal names `max_tokens` first: "…is too large: 32768. This model's maximum context
//!   length is 131072 tokens…"); else the wording `A > B` ("70000 > 65536") names the request first;
//!   else the first two integers ≥ 1000, `limit` the smaller and `requested` the larger (llama.cpp states
//!   the request first); with one such integer it is `limit`, with none both are `None`. The same applies to an error
//!   object inside a 200 stream (`AssembleError::Server`) whose message matches those phrases: it is
//!   an overflow (no retry), not a server error to retry;
//! - **rejected** (no retry): any other 4xx → `ModelError::Rejected { status, message }`. `message`
//!   is the server's `error.message` (or `message`, or `detail`) when the body is JSON, else the
//!   first 2000 characters of the body.
//!
//! Retry pacing: delays 0.5 s, 1 s, 2 s, 4 s, … capped at `profile.retry_max_delay_s`, each with
//! ±10% jitter. A `Retry-After` header (seconds) replaces the computed delay when it is larger, up to
//! 600 s. Before sleeping, emit `StreamEvent::Retrying`. `profile.retry_window_s == 0` retries until
//! cancelled (the capped cases above excepted, and nothing else: a failure of the plain retry kind
//! that never heals is retried for ever); otherwise, when the time since the first failure of this
//! call exceeds the window, return `ModelError::Unavailable { attempts, last }`.
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
//! ## `new(name, profile, keys_dir)`: keys and proxies
//! Fails with `ModelError::Config` when `base_url` is not an http(s) URL. `keys_dir` is where key files are
//! (`Paths::model_keys_dir()`, `<ferret home>/keys/models`). **Keys**, the bearer a request carries:
//! - `profile.api_key_file` set: the key `ferret_core::config::read_model_key(keys_dir, file)` returns, read
//!   once, here. Its refusal (missing file, a link, not this user's, any group or other permission bit, …) is
//!   `ModelError::Config` with `model profile '{name}': ` before its sentence, so the daemon does not start
//!   with a key it cannot send. The key is kept in this client's memory only, never put in an environment.
//! - else `profile.api_key_env` names a variable that is set and not empty: its value, read per request.
//! - else none, and no `Authorization` header is sent.
//!
//! **No proxy.** The HTTP client is built with `no_proxy()`: `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` in
//! either case, and the system's proxy settings, are ignored. `complete`, `discover` and `health` connect
//! only to `base_url` (DESIGN §2, principle 9), so a proxy exported in the shell that started the daemon
//! (an intercepting proxy, say) never receives a transcript or the bearer key, and a closed one cannot
//! make every step fail.
//!
//! Tests required (all against `crate::mock::MockServer`): a plain reply; a tool-call reply; events
//! arrive in order with `AttemptStart` first; retry after 500 then success (attempts == 2, events of
//! the failed attempt precede a second `AttemptStart`); connection dropped mid-stream is retried and
//! the partial text does not leak into the result; stall detection (short `stall_timeout_s`);
//! `Retry-After` honoured; retry window exhausted → `Unavailable`; 400 → `Rejected` with the
//! server's message; overflow wording → `ContextOverflow` with parsed numbers (each phrase; llama.cpp's
//! 400 body with `n_ctx`/`n_prompt_tokens`, and the same message without them, both giving limit =
//! the smaller; vLLM's `max_tokens` refusal giving the window as the limit; `A > B`; the type code alone;
//! a 422; an overflow error inside a 200 stream, sent once); a 422
//! without overflow wording stays `Rejected`; cancellation during
//! a stream and during a retry sleep; server unreachable then started later is picked up; bearer
//! header sent only when configured; `discover` for each source; `timing` is plausible. Keys: a key
//! file's trimmed content is the bearer (and wins over nothing else: `Config::check` refuses a profile
//! with both forms); a missing key file and one with mode 0644 make `new` fail with a `Config` naming the
//! profile and the path. Proxies, in a child process (the test binary run again for that one test, since
//! the variables are read when a client is built): with `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and their
//! lower-case forms all set to `http://127.0.0.1:{port}` of a port nothing listens on, `complete`,
//! `discover` and `health` against a `MockServer` succeed, and a `reqwest::Client::new()` GET of the same
//! mock URL in the same child fails (the control showing the variables are in force).

use crate::assemble::{AssembleError, Assembler, Completion, SseParser, StreamEvent};
use crate::request::ChatRequest;
use bytes::Bytes;
use ferret_core::config::{read_model_key, ModelProfile};
use ferret_core::event::{FinishReason, Timing, Usage};
use futures_util::StreamExt;
use rand::RngExt;
use serde_json::Value;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::UnboundedSender;
use tokio_util::sync::CancellationToken;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HEALTH_TIMEOUT: Duration = Duration::from_secs(5);
const DISCOVER_TIMEOUT: Duration = Duration::from_secs(15);
const FIRST_DELAY: Duration = Duration::from_millis(500);
/// How many attempts in a row may end in a failure that waiting cannot cure (a body that is not an
/// event stream, a malformed chunk, a stream that ends without a finish reason, a certificate error).
/// The attempt that reaches this number is the last, whatever the retry window.
const MAX_INCURABLE_ATTEMPTS: u32 = 3;
const MAX_RETRY_AFTER: Duration = Duration::from_secs(600);
/// Most of an error response that is read; the message is cut to 2000 characters anyway.
const ERROR_BODY_LIMIT: usize = 64 * 1024;
const MESSAGE_CHARS: usize = 2000;
/// Bytes of a response body kept to show what a server sent instead of an event stream.
const HEAD_BYTES: usize = 400;
/// Keys a server may report its context window under, in order of preference.
const WINDOW_KEYS: [&str; 4] = ["max_model_len", "context_window", "context_length", "max_context_length"];
/// Phrases (lower case) a server uses for "the prompt does not fit".
const OVERFLOW_PHRASES: [&str; 7] = [
    "maximum context length",
    "context length",
    "too many tokens",
    "prompt is too long",
    "max_model_len",
    "exceeds the available context size",
    "input is too long",
];
/// Values of an error object's `type` or `code` that mean "the prompt does not fit", whatever the message.
const OVERFLOW_CODES: [&str; 2] = ["exceed_context_size_error", "context_length_exceeded"];
/// HTTP statuses on which a body may be an overflow report (TGI answers 422).
const OVERFLOW_STATUSES: [u16; 3] = [400, 413, 422];

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
    /// Retrying ended without a completion: the window ran out, or the server kept answering with
    /// something that waiting cannot cure. `last` says which.
    #[error("the model request failed after {attempts} attempts: {last}")]
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

/// Timing knobs of the retry loop. Built from the profile; tests shorten them.
#[derive(Clone, Copy, Debug)]
struct Pacing {
    base_delay: Duration,
    max_delay: Duration,
    stall: Duration,
    /// `None` = retry until cancelled.
    window: Option<Duration>,
}

impl Pacing {
    fn from_profile(p: &ModelProfile) -> Pacing {
        Pacing {
            base_delay: FIRST_DELAY,
            // A zero cap would spin against a refused port.
            max_delay: Duration::from_secs(p.retry_max_delay_s).max(Duration::from_millis(50)),
            // A zero timeout would fail every attempt before the server could answer.
            stall: Duration::from_secs(p.stall_timeout_s.max(1)),
            window: (p.retry_window_s > 0).then(|| Duration::from_secs(p.retry_window_s)),
        }
    }

    /// Delay before the retry that follows failed attempt number `attempt` (from 1).
    fn backoff(&self, attempt: u32) -> Duration {
        let exp = i32::try_from(attempt.saturating_sub(1).min(30)).unwrap_or(30);
        let secs = (self.base_delay.as_secs_f64() * 2f64.powi(exp)).min(self.max_delay.as_secs_f64());
        let jitter: f64 = rand::rng().random_range(0.9..=1.1);
        Duration::try_from_secs_f64((secs * jitter).max(0.0)).unwrap_or(self.max_delay)
    }
}

/// Why an attempt did not produce a completion.
enum Fail {
    /// `sticky`: waiting cannot cure this failure, so attempts in a row that end this way are capped.
    Retry {
        reason: String,
        retry_after: Option<Duration>,
        sticky: bool,
    },
    Fatal(ModelError),
    Cancelled(Option<Box<Completion>>),
}

fn retry(reason: impl Into<String>) -> Fail {
    Fail::Retry { reason: reason.into(), retry_after: None, sticky: false }
}

fn sticky(reason: impl Into<String>) -> Fail {
    Fail::Retry { reason: reason.into(), retry_after: None, sticky: true }
}

/// True for send errors that are not about reaching the server: the request could not be built, the
/// TLS handshake failed on the certificate or protocol, or the answer was not HTTP. `causes` is the
/// text of the error's causes without the error's own, which carries the request URL.
///
/// A connection closed during the TLS handshake ("tls handshake eof") is left out on purpose: a
/// TCP-level proxy answers that way for as long as its backend is being relaunched.
fn is_local_failure(builder: bool, causes: &str) -> bool {
    const MARKERS: [&str; 11] = [
        "certificate",
        "invalid http",
        "unknown issuer",
        "peer is incompatible",
        "peer misbehaved",
        "received unexpected",
        "fatal alert",
        "protocol version",
        "wrong version number",
        "corrupt message",
        "invalid content type",
    ];
    let lower = causes.to_lowercase();
    builder || MARKERS.iter().any(|m| lower.contains(m))
}

/// What has streamed so far in the current attempt, for `Cancelled { partial }`.
#[derive(Default)]
struct Partial {
    text: String,
    reasoning: String,
}

impl Partial {
    fn note(&mut self, ev: &StreamEvent) {
        match ev {
            StreamEvent::Text(t) => self.text.push_str(t),
            StreamEvent::Reasoning(t) => self.reasoning.push_str(t),
            _ => {}
        }
    }

    fn into_completion(self, attempts: u32) -> Option<Box<Completion>> {
        if self.text.is_empty() && self.reasoning.is_empty() {
            return None;
        }
        Some(Box::new(Completion {
            text: self.text,
            reasoning: self.reasoning,
            tool_calls: Vec::new(),
            finish: FinishReason::Stop,
            usage: Usage::default(),
            timing: Timing::default(),
            attempts,
        }))
    }
}

/// A key held in memory; its `Debug` never shows it.
#[derive(Clone)]
struct Secret(Arc<str>);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(..)")
    }
}

#[derive(Clone, Debug)]
pub struct ModelClient {
    name: String,
    profile: ModelProfile,
    http: reqwest::Client,
    pacing: Pacing,
    /// The key `profile.api_key_file` held when this client was built; memory only.
    file_key: Option<Secret>,
    /// The model id `discover` last selected (or a 404 lookup learned); shared by all clones, and replaced
    /// by every successful `discover`. Requests carry it in place of
    /// `profile.model` once it is known. While it is not, a 404 has it looked up.
    served: Arc<Mutex<Option<String>>>,
}

impl ModelClient {
    /// `name` is the profile's name (for messages). Fails when `base_url` is not an http(s) URL, or when the
    /// profile's `api_key_file` (in `keys_dir`) cannot be used. Proxy variables are ignored.
    pub fn new(name: &str, profile: ModelProfile, keys_dir: &Path) -> Result<ModelClient, ModelError> {
        let ok = reqwest::Url::parse(&profile.base_url)
            .map(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some())
            .unwrap_or(false);
        if !ok {
            return Err(ModelError::Config(format!(
                "model profile '{name}' has base_url '{}', which is not an http(s) URL; set it to something like http://host:8000/v1.",
                profile.base_url
            )));
        }
        let file_key = match &profile.api_key_file {
            Some(file) => Some(Secret(
                read_model_key(keys_dir, file)
                    .map_err(|sentence| ModelError::Config(format!("model profile '{name}': {sentence}")))?
                    .into(),
            )),
            None => None,
        };
        let http = reqwest::Client::builder()
            // Requests go to `base_url` and nowhere else, whatever proxy the environment names.
            .no_proxy()
            .connect_timeout(CONNECT_TIMEOUT)
            // A redirect would re-post the whole conversation to another host.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| {
                ModelError::Config(format!("model profile '{name}': cannot build an HTTP client: {}", describe(&e)))
            })?;
        let pacing = Pacing::from_profile(&profile);
        Ok(ModelClient { name: name.to_string(), profile, http, pacing, file_key, served: Arc::new(Mutex::new(None)) })
    }

    #[cfg(test)]
    fn with_pacing(mut self, pacing: Pacing) -> ModelClient {
        self.pacing = pacing;
        self
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn profile(&self) -> &ModelProfile {
        &self.profile
    }

    /// The id discovery selected, when it has selected one in this process.
    fn discovered_id(&self) -> Option<String> {
        self.served.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn remember(&self, id: &str) {
        *self.served.lock().unwrap_or_else(|e| e.into_inner()) = Some(id.to_string());
    }

    fn url(&self, path: &str) -> String {
        format!("{}/{}", self.profile.base_url.trim_end_matches('/'), path)
    }

    fn api_key(&self) -> Option<String> {
        if let Some(key) = &self.file_key {
            return Some(key.0.to_string());
        }
        let var = self.profile.api_key_env.as_deref()?;
        std::env::var(var).ok().filter(|k| !k.is_empty())
    }

    pub async fn complete(
        &self,
        request: &ChatRequest,
        events: Option<&UnboundedSender<StreamEvent>>,
        cancel: &CancellationToken,
    ) -> Result<Completion, ModelError> {
        let encode = |model: &str| {
            serde_json::to_vec(&request.body(model, &self.profile.extra_body))
                .map(Bytes::from)
                .map_err(|e| ModelError::Config(format!("the request cannot be serialised: {e}")))
        };
        // Requests carry what discovery selected, else the configured name.
        let discovered = self.discovered_id();
        let known = discovered.is_some();
        let mut model = discovered.unwrap_or_else(|| self.profile.model.clone());
        let mut body = encode(&model)?;
        let url = self.url("chat/completions");
        let key = self.api_key();
        // Calls written into the text are taken only where the request asks for them.
        let text_calls =
            if request.text_calls { self.profile.text_tool_calls } else { ferret_core::config::TextToolCalls::Off };

        let mut attempts: u32 = 0;
        let mut first_failure: Option<Instant> = None;
        // Attempts in a row that ended in a failure waiting cannot cure.
        let mut incurable: u32 = 0;
        // Discovery is asked about a 404 once per call.
        let mut rediscovered = false;
        loop {
            if cancel.is_cancelled() {
                return Err(ModelError::Cancelled { partial: None });
            }
            attempts = attempts.saturating_add(1);
            let (reason, retry_after, sticky) = match self
                .attempt(&url, &body, key.as_deref(), attempts, text_calls, events, cancel)
                .await
            {
                Ok(mut done) => {
                    done.attempts = attempts;
                    return Ok(done);
                }
                Err(Fail::Cancelled(partial)) => return Err(ModelError::Cancelled { partial }),
                // 404 is what a server answers for a model id it does not serve.
                Err(Fail::Fatal(ModelError::Rejected { status: 404, message })) if !rediscovered => {
                    rediscovered = true;
                    let Some(id) = self.reselect(&model, cancel).await? else {
                        return Err(ModelError::Rejected { status: 404, message });
                    };
                    if known {
                        // The server was relaunched with another model since discovery. What a session
                        // recorded at its start (model id, context window) describes the old one, so
                        // nothing is sent to the new one and the remembered id stays.
                        tracing::warn!(
                            model = %self.name, sent = %model, served = %id,
                            "the server serves another model than discovery found; the request fails"
                        );
                        return Err(ModelError::Rejected {
                            status: 404,
                            message: format!(
                                "the server no longer serves '{model}', the model ferret found there earlier; it now serves '{id}'. ferret does not switch running sessions on this error: relaunch the server with '{model}', or restart the ferret daemon (or let the next successful model discovery, which happens when a session is created on this profile before discovery has succeeded, move every session of the profile) to carry on with '{id}'. The server said: {message}"
                            ),
                        });
                    }
                    // Discovery has selected nothing in this process yet: the session was restored
                    // after a daemon restart, or it began while the server was down.
                    self.remember(&id);
                    let reason = format!(
                        "the server does not serve model '{model}' but '{id}'; sending the request again with that id"
                    );
                    tracing::info!(model = %self.name, attempt = attempts, %reason, "model id corrected");
                    send(events, StreamEvent::Retrying { attempt: attempts, after_ms: 0, reason });
                    body = encode(&id)?;
                    model = id;
                    continue;
                }
                Err(Fail::Fatal(e)) => return Err(e),
                Err(Fail::Retry { reason, retry_after, sticky }) => (reason, retry_after, sticky),
            };

            incurable = if sticky { incurable.saturating_add(1) } else { 0 };
            if incurable >= MAX_INCURABLE_ATTEMPTS {
                let stopped = "attempts in a row failed in a way that waiting cannot fix, so ferret stopped retrying.";
                return Err(ModelError::Unavailable { attempts, last: format!("{reason} {incurable} {stopped}") });
            }

            let began = *first_failure.get_or_insert_with(Instant::now);
            let mut delay = self.pacing.backoff(attempts);
            if let Some(ra) = retry_after {
                delay = delay.max(ra.min(MAX_RETRY_AFTER));
            }
            if self.pacing.window.is_some_and(|w| {
                let elapsed = began.elapsed();
                elapsed > w || (w > Duration::ZERO && elapsed.saturating_add(delay) > w)
            }) {
                return Err(ModelError::Unavailable { attempts, last: reason });
            }
            tracing::debug!(model = %self.name, attempt = attempts, ?delay, %reason, "model attempt failed; retrying");
            let last_reason = reason.clone();
            send(events, StreamEvent::Retrying { attempt: attempts, after_ms: millis(delay), reason });
            tokio::select! {
                biased;
                () = cancel.cancelled() => return Err(ModelError::Cancelled { partial: None }),
                () = tokio::time::sleep(delay) => {}
            }
            if self.pacing.window.is_some_and(|w| began.elapsed() > w) {
                return Err(ModelError::Unavailable { attempts, last: last_reason });
            }
        }
    }

    /// After a 404 for a request that carried `sent`: asks the server what it serves. `Some(id)` when
    /// discovery would select another id than the one sent, `None` when the 404 stands. Nothing is
    /// remembered here.
    async fn reselect(&self, sent: &str, cancel: &CancellationToken) -> Result<Option<String>, ModelError> {
        let found = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(ModelError::Cancelled { partial: None }),
            r = self.lookup() => r,
        };
        match found {
            Ok(d) => Ok(Some(d.served_model).filter(|id| id != sent)),
            // Several models are served and the configured one is not among them.
            Err(e @ ModelError::Config(_)) => Err(e),
            // The 404 was about something else than the model id, or the server has gone away.
            Err(_) => Ok(None),
        }
    }

    /// One request/response cycle.
    #[allow(clippy::too_many_arguments)]
    async fn attempt(
        &self,
        url: &str,
        body: &Bytes,
        key: Option<&str>,
        attempt: u32,
        text_calls: ferret_core::config::TextToolCalls,
        events: Option<&UnboundedSender<StreamEvent>>,
        cancel: &CancellationToken,
    ) -> Result<Completion, Fail> {
        send(events, StreamEvent::AttemptStart { attempt });
        let stall = self.pacing.stall;
        let stall_text = format!("{:.1} s", stall.as_secs_f64());
        let sent = Instant::now();

        let mut req = self
            .http
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .body(body.clone());
        if let Some(k) = key {
            req = req.bearer_auth(k);
        }
        // A long silence before the headers is the normal sign of a server that is still loading;
        // it is bounded by the stall timeout like every body chunk.
        let resp = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(Fail::Cancelled(None)),
            r = tokio::time::timeout(stall, req.send()) => match r {
                Err(_) => return Err(retry(format!("the server sent no response headers within {stall_text}"))),
                Ok(Err(e)) => {
                    let text = describe(&e);
                    // Only the causes are sorted: the error's own text carries the request URL, whose
                    // host or path may contain one of the marker words.
                    let causes = std::error::Error::source(&e).map(describe).unwrap_or_default();
                    return Err(if is_local_failure(e.is_builder(), &causes) {
                        sticky(format!(
                            "the request to the server failed before any reply: {text}. Check base_url, the API key variable and the server's TLS certificate."
                        ))
                    } else {
                        retry(format!("cannot reach the server: {text}"))
                    });
                }
                Ok(Ok(resp)) => resp,
            },
        };

        let status = resp.status();
        if status.is_redirection() {
            let to = resp.headers().get(reqwest::header::LOCATION).and_then(|v| v.to_str().ok());
            return Err(Fail::Fatal(ModelError::Rejected {
                status: status.as_u16(),
                message: redirect_message(&self.profile.base_url, "chat/completions", to),
            }));
        }
        if !status.is_success() {
            let retry_after = resp
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u64>().ok())
                .map(Duration::from_secs);
            let text = read_error_body(resp, stall, cancel).await?;
            return Err(classify_status(status.as_u16(), &text, retry_after));
        }

        let content_type = resp_content_type(&resp);
        let mut stream = Box::pin(resp.bytes_stream());
        let mut parser = SseParser::new();
        let mut asm = Assembler::with_text_calls(text_calls);
        let mut partial = Partial::default();
        let mut ttft: Option<u64> = None;
        let mut finished = false;
        // How many event payloads arrived, and the first bytes of the body for the message when none did.
        let mut payloads: usize = 0;
        let mut head: Vec<u8> = Vec::new();
        while !finished {
            let next = tokio::select! {
                biased;
                () = cancel.cancelled() => return Err(Fail::Cancelled(partial.into_completion(attempt))),
                r = tokio::time::timeout(stall, stream.next()) => r,
            };
            let chunk = match next {
                // Silence after the finish reason loses nothing but the trailing usage chunk.
                Err(_) if asm.is_done() => break,
                Err(_) => return Err(retry(format!("the stream delivered nothing for {stall_text}"))),
                Ok(None) => break,
                Ok(Some(Err(e))) => return Err(retry(format!("the connection broke mid-stream: {}", describe(&e)))),
                Ok(Some(Ok(b))) => b,
            };
            if head.len() < HEAD_BYTES {
                head.extend(chunk.iter().take(HEAD_BYTES - head.len()));
            }
            for payload in parser.feed(&chunk).map_err(|e| classify_assemble(e, None))? {
                payloads = payloads.saturating_add(1);
                if payload.trim() == "[DONE]" {
                    finished = true;
                }
                let evs = match asm.push(&payload) {
                    Ok(evs) => evs,
                    Err(e) => return Err(classify_assemble(e, asm.last_error())),
                };
                for ev in evs {
                    if ttft.is_none() {
                        ttft = Some(millis(sent.elapsed()));
                    }
                    partial.note(&ev);
                    send(events, ev);
                }
            }
        }

        if payloads == 0 {
            let seen = clip(String::from_utf8_lossy(&head).trim(), 200);
            let what = if seen.is_empty() { "an empty body".to_string() } else { format!("\"{seen}\"") };
            return Err(sticky(format!(
                "the server answered HTTP {} with {content_type} but the body is not an event stream; it sent {what}. Check that base_url points at the OpenAI-compatible /v1 endpoint of a model server.",
                status.as_u16()
            )));
        }
        let mut done = asm.finish().map_err(|_| {
            sticky(
                "the server ended the stream cleanly without a finish_reason. Check the server's log; the model may be crashing or a proxy may be cutting the stream.",
            )
        })?;
        let total = millis(sent.elapsed());
        done.timing = Timing { queue_ms: 0, ttft_ms: ttft.unwrap_or(total), total_ms: total };
        Ok(done)
    }

    /// Asks the server what it serves (see *discover* above). A success replaces the remembered served
    /// id for this client and every clone of it, whatever id was remembered before; a failure leaves
    /// the remembered id as it was.
    pub async fn discover(&self) -> Result<Discovered, ModelError> {
        let found = self.lookup().await?;
        self.remember(&found.served_model);
        Ok(found)
    }

    /// What `discover` selects, without remembering it.
    async fn lookup(&self) -> Result<Discovered, ModelError> {
        let url = self.url("models");
        let mut req = self.http.get(&url).timeout(DISCOVER_TIMEOUT);
        if let Some(k) = self.api_key() {
            req = req.bearer_auth(k);
        }
        let unavailable = |last: String| ModelError::Unavailable { attempts: 1, last };
        let resp = req.send().await.map_err(|e| unavailable(format!("cannot reach {url}: {}", describe(&e))))?;
        let status = resp.status();
        if status.is_redirection() {
            let to = resp.headers().get(reqwest::header::LOCATION).and_then(|v| v.to_str().ok());
            return Err(ModelError::Rejected {
                status: status.as_u16(),
                message: redirect_message(&self.profile.base_url, "models", to),
            });
        }
        let text = resp.text().await.map_err(|e| unavailable(format!("cannot read {url}: {}", describe(&e))))?;
        if !status.is_success() {
            let message = error_message(&text);
            return Err(if status.is_client_error() {
                ModelError::Rejected { status: status.as_u16(), message }
            } else {
                unavailable(format!("HTTP {}: {message}", status.as_u16()))
            });
        }
        let json: Value = serde_json::from_str(&text)
            .map_err(|e| unavailable(format!("{url} did not return JSON ({e}); check that base_url ends in /v1")))?;
        pick_model(&self.name, &self.profile, &json)
    }

    pub async fn health(&self) -> bool {
        let mut req = self.http.get(self.url("models")).timeout(HEALTH_TIMEOUT);
        if let Some(k) = self.api_key() {
            req = req.bearer_auth(k);
        }
        matches!(req.send().await, Ok(r) if r.status().is_success())
    }
}

fn classify_assemble(e: AssembleError, error_chunk: Option<&Value>) -> Fail {
    match e {
        AssembleError::Malformed(m) => sticky(format!(
            "the server sent a stream chunk that is not valid JSON ({m}). Check that base_url points at an OpenAI-compatible /v1 endpoint."
        )),
        // A stream over a size limit is malformed too: it counts toward the same bounded retries.
        AssembleError::Oversize(m) => sticky(format!(
            "the server sent a malformed stream: {m}. Check that base_url points at an OpenAI-compatible /v1 endpoint."
        )),
        // An overflow reported inside a 200 stream cannot be cured by sending the same request again.
        AssembleError::Server(m) => {
            if let Some((limit, requested)) = read_overflow_chunk(error_chunk, &m) {
                Fail::Fatal(ModelError::ContextOverflow { limit, requested, message: m })
            } else {
                retry(AssembleError::Server(m).to_string())
            }
        }
        other => retry(other.to_string()),
    }
}

fn resp_content_type(resp: &reqwest::Response) -> String {
    match resp.headers().get(reqwest::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()) {
        Some(ct) => format!("content-type {}", clip(ct, 80)),
        None => "no content-type".to_string(),
    }
}

fn send(events: Option<&UnboundedSender<StreamEvent>>, ev: StreamEvent) {
    if let Some(tx) = events {
        // A listener that went away must not fail the request.
        let _ = tx.send(ev);
    }
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

fn describe(e: &(dyn std::error::Error + 'static)) -> String {
    let mut out = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        out.push_str(": ");
        out.push_str(&s.to_string());
        src = s.source();
    }
    out
}

fn clip(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// The sentence for a 3xx answer to `{base}/{path}`. `Location` names the whole endpoint, so the
/// base_url to set is that address without the request's own path.
fn redirect_message(base: &str, path: &str, location: Option<&str>) -> String {
    let base = base.trim_end_matches('/');
    let url = format!("{base}/{path}");
    let refusal = "ferret does not follow redirects, so that nothing is sent to a host the profile does not name";
    let Some(to) = location else {
        return format!(
            "{url} answered with a redirect without a Location; {refusal}. Check base_url in the model profile."
        );
    };
    // A relative Location is resolved against the request's address.
    let target = reqwest::Url::parse(&url).and_then(|u| u.join(to)).map_or_else(|_| to.to_string(), String::from);
    let target = target.split(['?', '#']).next().unwrap_or_default().trim_end_matches('/');
    let advice = match target.strip_suffix(path).and_then(|t| t.strip_suffix('/')) {
        Some(b) if b != base => {
            format!("set base_url in the model profile to {} (that address without /{path})", clip(b, 300))
        }
        _ => format!("set base_url in the model profile to its OpenAI-compatible address, the part before /{path}"),
    };
    format!("{url} redirected to {}; {refusal}. If that server is the right one, {advice}.", clip(to, 300))
}

async fn read_error_body(resp: reqwest::Response, stall: Duration, cancel: &CancellationToken) -> Result<String, Fail> {
    let mut stream = Box::pin(resp.bytes_stream());
    let mut buf: Vec<u8> = Vec::new();
    while buf.len() < ERROR_BODY_LIMIT {
        let next = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(Fail::Cancelled(None)),
            r = tokio::time::timeout(stall, stream.next()) => r,
        };
        match next {
            Ok(Some(Ok(b))) => buf.extend_from_slice(&b),
            // The status line already says what happened.
            _ => break,
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// The server's own message: `error.message`, `error` (a string), `message` or `detail` of a JSON
/// body, else the first 2000 characters of the body.
fn error_message(body: &str) -> String {
    let text = |v: &Value| match v {
        Value::String(s) => Some(s.clone()),
        Value::Null => None,
        other => Some(other.to_string()),
    };
    if let Ok(v) = serde_json::from_str::<Value>(body) {
        let found = v
            .get("error")
            .and_then(|e| e.get("message").and_then(text).or_else(|| e.as_str().map(str::to_string)))
            .or_else(|| v.get("message").and_then(text))
            .or_else(|| v.get("detail").and_then(text));
        if let Some(m) = found {
            return clip(&m, MESSAGE_CHARS);
        }
    }
    clip(body, MESSAGE_CHARS)
}

/// True when the message contains one of the overflow phrases, case-insensitively.
fn has_overflow_phrase(message: &str) -> bool {
    let lower = message.to_lowercase();
    OVERFLOW_PHRASES.iter().any(|p| lower.contains(p))
}

/// The integers of `message` that are at least 1000, in order.
fn big_numbers(message: &str) -> impl Iterator<Item = u64> + '_ {
    message.split(|c: char| !c.is_ascii_digit()).filter_map(|t| t.parse::<u64>().ok()).filter(|n| *n >= 1000)
}

/// The integer that starts `text` (after no characters at all).
fn leading_number(text: &str) -> Option<u64> {
    let end = text.find(|c: char| !c.is_ascii_digit()).unwrap_or(text.len());
    text.get(..end).and_then(|t| t.parse().ok())
}

/// The integer right after the first of `markers` found in `message` (ASCII case-insensitively).
fn number_after(message: &str, markers: &[&str]) -> Option<u64> {
    let lower = message.to_ascii_lowercase();
    markers.iter().find_map(|m| {
        let at = lower.find(m)?.checked_add(m.len())?;
        leading_number(message.get(at..)?)
    })
}

/// The integers either side of the first `A > B` in `message`.
fn greater_than_pair(message: &str) -> Option<(u64, u64)> {
    message.match_indices('>').find_map(|(at, _)| {
        let before = message.get(..at)?.trim_end();
        let start = before
            .char_indices()
            .rfind(|(_, c)| !c.is_ascii_digit())
            .map_or(0, |(i, c)| i.saturating_add(c.len_utf8()));
        let a = leading_number(before.get(start..)?)?;
        let b = leading_number(message.get(at.checked_add(1)?..)?.trim_start())?;
        (a > b).then_some((a, b))
    })
}

/// `limit` and `requested` from a message, in this order: the integer after `maximum context length
/// is ` or `context size (` / `context size of ` is the limit, and the request is the first integer
/// of at least 1000 larger than it, if any (vLLM's `max_tokens` refusal names `max_tokens` first); else the
/// wording `A` greater than `B` (`A > B`) names the request first; else the first two integers of at least 1000, the smaller the limit
/// and the larger the request (servers name them in either order); one integer is the limit.
fn overflow_numbers(message: &str) -> (Option<u64>, Option<u64>) {
    let named = number_after(message, &["maximum context length is ", "context size (", "context size of "]);
    if let Some(limit) = named {
        return (Some(limit), big_numbers(message).find(|n| *n > limit));
    }
    if let Some((requested, limit)) = greater_than_pair(message) {
        return (Some(limit), Some(requested));
    }
    let mut found = big_numbers(message);
    match (found.next(), found.next()) {
        (Some(a), Some(b)) => (Some(a.min(b)), Some(a.max(b))),
        (one, _) => (one, None),
    }
}

/// The `error` object inside a parsed response/chunk (or the value itself when it is an object).
fn error_object_from(v: &Value) -> Option<&Value> {
    match v.get("error") {
        Some(e) if e.is_object() => Some(e),
        _ => Some(v).filter(|v| v.is_object()),
    }
}

fn read_overflow_object(object: Option<&Value>, message: &str) -> Option<(Option<u64>, Option<u64>)> {
    let field = |k: &str| object.and_then(|o| o.get(k));
    let coded = ["type", "code"]
        .iter()
        .any(|k| field(k).and_then(Value::as_str).is_some_and(|c| OVERFLOW_CODES.contains(&c.to_lowercase().as_str())));
    if !coded && !has_overflow_phrase(message) {
        return None;
    }
    let positive = |k: &str| field(k).and_then(Value::as_u64).filter(|n| *n > 0);
    match (positive("n_ctx"), positive("n_prompt_tokens")) {
        (None, None) => Some(overflow_numbers(message)),
        (limit, requested) => Some((limit, requested)),
    }
}

fn read_overflow_chunk(chunk: Option<&Value>, message: &str) -> Option<(Option<u64>, Option<u64>)> {
    read_overflow_object(chunk.and_then(error_object_from), message)
}

/// Reads the overflow report in a 400/413/422 body: `Some((limit, requested))` when it is one.
/// It is one when the message has an overflow phrase or the error object's `type` or `code` is an
/// overflow code. `n_ctx` / `n_prompt_tokens` of the error object win over numbers in the message.
fn read_overflow(body: &str, message: &str) -> Option<(Option<u64>, Option<u64>)> {
    let v = serde_json::from_str::<Value>(body).ok();
    read_overflow_object(v.as_ref().and_then(error_object_from), message)
}

fn classify_status(status: u16, body: &str, retry_after: Option<Duration>) -> Fail {
    let message = error_message(body);
    if OVERFLOW_STATUSES.contains(&status) {
        if let Some((limit, requested)) = read_overflow(body, &message) {
            return Fail::Fatal(ModelError::ContextOverflow { limit, requested, message });
        }
    }
    let transient = matches!(status, 408 | 425 | 429) || !(400..500).contains(&status);
    if transient {
        let reason = if message.is_empty() {
            format!("the server answered HTTP {status}")
        } else {
            format!("the server answered HTTP {status}: {}", clip(&message, 300))
        };
        return Fail::Retry { reason, retry_after, sticky: false };
    }
    Fail::Fatal(ModelError::Rejected { status, message })
}

fn window_of(entry: &Value) -> Option<u64> {
    WINDOW_KEYS.iter().find_map(|k| entry.get(*k).and_then(Value::as_u64).filter(|n| *n > 0))
}

/// Chooses the served model from a `/models` response and decides where the window comes from.
fn pick_model(name: &str, profile: &ModelProfile, json: &Value) -> Result<Discovered, ModelError> {
    let entries: &[Value] = json.get("data").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]);
    let id_of = |e: &Value| e.get("id").and_then(Value::as_str).map(str::to_string);
    let entry = entries
        .iter()
        .find(|e| id_of(e).as_deref() == Some(profile.model.as_str()))
        .or(entries.iter().next().filter(|_| entries.len() == 1));
    if entry.is_none() && !entries.is_empty() {
        let ids: Vec<String> = entries.iter().filter_map(id_of).collect();
        return Err(ModelError::Config(format!(
            "the server for model profile '{name}' does not serve '{}'; it serves: {}. Set `model` to one of these.",
            profile.model,
            ids.join(", ")
        )));
    }
    let served_model = entry.and_then(id_of).unwrap_or_else(|| profile.model.clone());
    let server_window = entry.and_then(window_of);
    let (context_window, source) = match (profile.context_window, server_window) {
        (Some(c), _) => (Some(c), WindowSource::Config),
        (None, Some(s)) => (Some(s), WindowSource::Server),
        (None, None) => (None, WindowSource::Unknown),
    };
    Ok(Discovered { served_model, context_window, source, server_window })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{Action, MockServer, Reply, Script};
    use ferret_core::Message;
    use serde_json::json;
    use tokio::sync::mpsc::unbounded_channel;

    fn profile(base: &str) -> ModelProfile {
        ModelProfile { base_url: base.into(), model: "mock".into(), ..ModelProfile::default() }
    }

    fn fast_pacing() -> Pacing {
        Pacing {
            base_delay: Duration::from_millis(5),
            max_delay: Duration::from_millis(20),
            stall: Duration::from_millis(300),
            window: None,
        }
    }

    fn client_with(p: ModelProfile, pacing: Pacing) -> ModelClient {
        ModelClient::new("test", p, Path::new("/nonexistent-keys")).unwrap().with_pacing(pacing)
    }

    fn client(base: &str) -> ModelClient {
        client_with(profile(base), fast_pacing())
    }

    fn req(text: &str) -> ChatRequest {
        ChatRequest { messages: vec![Message::user(text)], ..ChatRequest::default() }
    }

    async fn server(actions: Vec<Action>) -> MockServer {
        MockServer::start(Script::sequence(actions)).await.unwrap()
    }

    fn drain(rx: &mut tokio::sync::mpsc::UnboundedReceiver<StreamEvent>) -> Vec<StreamEvent> {
        let mut out = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            out.push(ev);
        }
        out
    }

    #[tokio::test]
    async fn plain_reply() {
        let s =
            server(vec![Reply::text("hello there, this is a reply").with_reasoning("thinking it over").into()]).await;
        let c = client(&s.base_url()).complete(&req("hi"), None, &CancellationToken::new()).await.unwrap();
        assert_eq!(c.text, "hello there, this is a reply");
        assert_eq!(c.reasoning, "thinking it over");
        assert_eq!(c.finish, FinishReason::Stop);
        assert_eq!(c.attempts, 1);
        assert!(c.usage.prompt_tokens > 0);
        assert_eq!(s.requests().len(), 1);
        assert_eq!(s.requests()[0]["stream"], json!(true));
    }

    #[tokio::test]
    async fn tool_call_arguments_arrive_byte_for_byte() {
        let args = "{ \"path\" : \"a b.txt\",\n  \"n\":1.0 }";
        let s = server(vec![Reply::tool("read", args).into()]).await;
        let c = client(&s.base_url()).complete(&req("x"), None, &CancellationToken::new()).await.unwrap();
        assert_eq!(c.finish, FinishReason::ToolCalls);
        assert_eq!(c.tool_calls.len(), 1);
        assert_eq!(c.tool_calls[0].name, "read");
        assert_eq!(c.tool_calls[0].arguments, args);
        assert!(c.tool_calls[0].complete);
    }

    #[tokio::test]
    async fn events_arrive_in_order_attempt_start_first() {
        let s = server(vec![Reply::text("one two three four five six seven eight").into()]).await;
        let (tx, mut rx) = unbounded_channel();
        let c = client(&s.base_url()).complete(&req("x"), Some(&tx), &CancellationToken::new()).await.unwrap();
        let evs = drain(&mut rx);
        assert_eq!(evs.first(), Some(&StreamEvent::AttemptStart { attempt: 1 }));
        let joined: String =
            evs.iter().filter_map(|e| if let StreamEvent::Text(t) = e { Some(t.as_str()) } else { None }).collect();
        assert_eq!(joined, c.text);
        assert_eq!(evs.iter().filter(|e| matches!(e, StreamEvent::AttemptStart { .. })).count(), 1);
    }

    #[tokio::test]
    async fn retries_after_500_then_succeeds() {
        let s = server(vec![
            Action::Status { status: 500, body: "{\"error\":{\"message\":\"boom\"}}".into(), retry_after_s: None },
            Reply::text("fine now").into(),
        ])
        .await;
        let (tx, mut rx) = unbounded_channel();
        let c = client(&s.base_url()).complete(&req("x"), Some(&tx), &CancellationToken::new()).await.unwrap();
        assert_eq!(c.text, "fine now");
        assert_eq!(c.attempts, 2);
        let evs = drain(&mut rx);
        let pos = |f: &dyn Fn(&StreamEvent) -> bool| evs.iter().position(f);
        let first = pos(&|e| matches!(e, StreamEvent::AttemptStart { attempt: 1 })).unwrap();
        let retrying = pos(&|e| matches!(e, StreamEvent::Retrying { attempt: 1, .. })).unwrap();
        let second = pos(&|e| matches!(e, StreamEvent::AttemptStart { attempt: 2 })).unwrap();
        assert!(first < retrying && retrying < second);
        if let Some(StreamEvent::Retrying { reason, .. }) = evs.get(retrying) {
            assert!(reason.contains("500") && reason.contains("boom"), "{reason}");
        }
    }

    #[tokio::test]
    async fn dropped_stream_is_retried_and_partial_text_does_not_leak() {
        let long = Reply::text("PARTIAL-FIRST-ATTEMPT text that is cut off by the connection dropping");
        let s = server(vec![Action::DropAfter { reply: long, chunks: 3 }, Reply::text("the real answer").into()]).await;
        let (tx, mut rx) = unbounded_channel();
        let c = client(&s.base_url()).complete(&req("x"), Some(&tx), &CancellationToken::new()).await.unwrap();
        assert_eq!(c.text, "the real answer");
        assert_eq!(c.attempts, 2);
        let evs = drain(&mut rx);
        let second = evs.iter().position(|e| matches!(e, StreamEvent::AttemptStart { attempt: 2 })).unwrap();
        // The failed attempt's text came before the second AttemptStart, so a consumer discards it.
        assert!(evs.iter().take(second).any(|e| matches!(e, StreamEvent::Text(_))));
        assert!(!evs.iter().skip(second).any(|e| matches!(e, StreamEvent::Text(t) if t.contains("PARTIAL"))));
    }

    #[tokio::test]
    async fn ready_events_come_once_per_attempt_and_never_for_the_last_call() {
        let calls = || Reply::tools([("read", r#"{"path": "a"}"#), ("glob", r#"{"pattern": "*"}"#), ("bash", "{}")]);
        // The first attempt breaks right after the second call has begun.
        let s = server(vec![Action::DropAfter { reply: calls(), chunks: 4 }, calls().into()]).await;
        let (tx, mut rx) = unbounded_channel();
        let c = client(&s.base_url()).complete(&req("x"), Some(&tx), &CancellationToken::new()).await.unwrap();
        assert_eq!(c.attempts, 2);
        let evs = drain(&mut rx);
        let second = evs.iter().position(|e| matches!(e, StreamEvent::AttemptStart { attempt: 2 })).unwrap();
        let ready = |evs: &[StreamEvent]| -> Vec<(u32, String, String)> {
            evs.iter()
                .filter_map(|e| match e {
                    StreamEvent::ToolCallReady { index, name, arguments, .. } => {
                        Some((*index, name.clone(), arguments.clone()))
                    }
                    _ => None,
                })
                .collect()
        };
        let read = (0, "read".to_string(), r#"{"path": "a"}"#.to_string());
        assert_eq!(ready(&evs[..second]), std::slice::from_ref(&read));
        assert_eq!(ready(&evs[second..]), [read, (1, "glob".to_string(), r#"{"pattern": "*"}"#.to_string())]);
        assert_eq!(c.tool_calls.len(), 3);
    }

    #[tokio::test]
    async fn stream_ending_without_finish_reason_is_retried() {
        // The connection ends after the text chunks, before any finish_reason.
        let s =
            server(vec![Action::DropAfter { reply: Reply::text("abc"), chunks: 2 }, Reply::text("complete").into()])
                .await;
        let c = client(&s.base_url()).complete(&req("x"), None, &CancellationToken::new()).await.unwrap();
        assert_eq!(c.text, "complete");
        assert_eq!(c.attempts, 2);
    }

    #[tokio::test]
    async fn clean_end_of_stream_without_finish_reason_is_retried() {
        // Unlike DropAfter, the body ends with a proper terminating chunk.
        let s =
            server(vec![Action::Eof { reply: Reply::text("abc"), chunks: 2 }, Reply::text("complete").into()]).await;
        let c = client(&s.base_url()).complete(&req("x"), None, &CancellationToken::new()).await.unwrap();
        assert_eq!(c.text, "complete");
        assert_eq!(c.attempts, 2);
    }

    /// Runs a request with an unbounded window and returns its error. The timeout turns a hang into
    /// a failure.
    async fn gives_up(base: &str) -> ModelError {
        let c = client_with(profile(base), Pacing { window: None, ..fast_pacing() });
        tokio::time::timeout(Duration::from_secs(20), c.complete(&req("x"), None, &CancellationToken::new()))
            .await
            .expect("the request must give up instead of retrying for ever")
            .unwrap_err()
    }

    /// As `gives_up`, against a server that always fails the same way.
    async fn fails_with(action: Action) -> (ModelError, MockServer) {
        let s = MockServer::start(Script::new(move |_, _| action.clone())).await.unwrap();
        (gives_up(&s.base_url()).await, s)
    }

    #[tokio::test]
    async fn html_body_with_status_200_fails_after_three_attempts() {
        let html = "<html><body>Welcome to the router admin page</body></html>";
        let (err, s) = fails_with(Action::Status { status: 200, body: html.into(), retry_after_s: None }).await;
        // The sentence does not claim that a server which answered did not answer.
        let shown = err.to_string();
        assert!(
            shown.starts_with("the model request failed after 3 attempts: the server answered HTTP 200"),
            "{shown}"
        );
        match err {
            ModelError::Unavailable { attempts, last } => {
                assert_eq!(attempts, 3);
                assert!(
                    last.contains("not an event stream") && last.contains("<html>") && last.contains("base_url"),
                    "{last}"
                );
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(s.requests().len(), 3);
    }

    #[tokio::test]
    async fn clean_end_without_finish_reason_fails_after_three_attempts() {
        let (err, s) = fails_with(Action::Eof { reply: Reply::text("abc"), chunks: 2 }).await;
        match err {
            ModelError::Unavailable { attempts, last } => {
                assert_eq!(attempts, 3);
                assert!(last.contains("without a finish_reason"), "{last}");
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(s.requests().len(), 3);
    }

    #[tokio::test]
    async fn malformed_chunk_fails_after_three_attempts() {
        let (err, _s) =
            fails_with(Action::Status { status: 200, body: "data: {not json\n\n".into(), retry_after_s: None }).await;
        match err {
            ModelError::Unavailable { attempts, last } => {
                assert_eq!(attempts, 3);
                assert!(last.contains("not valid JSON"), "{last}");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_endless_line_fails_after_three_attempts_naming_the_limit() {
        let body = format!("data: {}", "x".repeat(9 * 1024 * 1024));
        let (err, s) = fails_with(Action::Status { status: 200, body, retry_after_s: None }).await;
        match err {
            ModelError::Unavailable { attempts, last } => {
                assert_eq!(attempts, 3);
                assert!(
                    last.contains("malformed stream") && last.contains("a line") && last.contains("8 MiB"),
                    "{last}"
                );
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(s.requests().len(), 3);
    }

    #[tokio::test]
    async fn incurable_failures_of_different_kinds_count_together() {
        // A proxy that cuts streams cleanly at a varying point: an empty body, then a few chunks.
        let s = MockServer::start(Script::new(|_, n| {
            if n % 2 == 0 {
                Action::Status { status: 200, body: String::new(), retry_after_s: None }
            } else {
                Action::Eof { reply: Reply::text("abc"), chunks: 2 }
            }
        }))
        .await
        .unwrap();
        match gives_up(&s.base_url()).await {
            ModelError::Unavailable { attempts, last } => {
                assert_eq!(attempts, 3);
                assert!(last.contains("an empty body") && last.contains("3 attempts in a row"), "{last}");
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(s.requests().len(), 3);
    }

    #[tokio::test]
    async fn tls_handshake_with_a_plain_http_port_fails_after_three_attempts() {
        // A real send error through `complete`: the mock speaks plain HTTP, the client TLS.
        let s = server(vec![]).await;
        match gives_up(&s.base_url().replacen("http://", "https://", 1)).await {
            ModelError::Unavailable { attempts, last } => {
                assert_eq!(attempts, 3);
                assert!(last.contains("failed before any reply") && last.contains("Check base_url"), "{last}");
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(s.requests().is_empty());
    }

    #[tokio::test]
    async fn an_answer_that_is_not_http_fails_after_three_attempts() {
        // base_url points at a port where something else listens.
        let (url, task) = answering("SSH-2.0-OpenSSH_9.6\r\n".into()).await;
        match gives_up(&url).await {
            ModelError::Unavailable { attempts, last } => {
                assert_eq!(attempts, 3);
                assert!(last.contains("invalid HTTP") && last.contains("Check base_url"), "{last}");
            }
            other => panic!("unexpected {other:?}"),
        }
        task.abort();
    }

    #[tokio::test]
    async fn a_different_failure_in_between_resets_the_count() {
        let eof = || Action::Eof { reply: Reply::text("abc"), chunks: 2 };
        let s = server(vec![
            eof(),
            eof(),
            Action::Status { status: 500, body: "boom".into(), retry_after_s: None },
            eof(),
            eof(),
            Reply::text("finally").into(),
        ])
        .await;
        let c = client(&s.base_url()).complete(&req("x"), None, &CancellationToken::new()).await.unwrap();
        assert_eq!(c.text, "finally");
        assert_eq!(c.attempts, 6);
    }

    #[tokio::test]
    async fn error_object_in_the_stream_stays_retryable_within_the_window() {
        let s =
            server(vec![Action::StreamError { message: "engine overloaded".into() }, Reply::text("ok").into()]).await;
        let (tx, mut rx) = unbounded_channel();
        let c = client(&s.base_url()).complete(&req("x"), Some(&tx), &CancellationToken::new()).await.unwrap();
        assert_eq!((c.text.as_str(), c.attempts), ("ok", 2));
        assert!(drain(&mut rx)
            .iter()
            .any(|e| matches!(e, StreamEvent::Retrying { reason, .. } if reason.contains("engine overloaded"))));

        let s = MockServer::start(Script::new(|_, _| Action::StreamError { message: "engine overloaded".into() }))
            .await
            .unwrap();
        let pacing = Pacing { window: Some(Duration::from_millis(250)), ..fast_pacing() };
        let err = client_with(profile(&s.base_url()), pacing)
            .complete(&req("x"), None, &CancellationToken::new())
            .await
            .unwrap_err();
        assert!(matches!(err, ModelError::Unavailable { attempts, .. } if attempts > 3), "{err:?}");
    }

    #[tokio::test]
    async fn refused_connection_is_retried_until_the_window_ends() {
        let s = server(vec![]).await;
        s.shutdown().await;
        let pacing = Pacing { window: Some(Duration::from_millis(300)), ..fast_pacing() };
        let err = client_with(profile(&s.base_url()), pacing)
            .complete(&req("x"), None, &CancellationToken::new())
            .await
            .unwrap_err();
        match err {
            ModelError::Unavailable { attempts, last } => {
                assert!(attempts > 3, "{attempts}");
                assert!(last.contains("cannot reach the server"), "{last}");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_marker_word_in_base_url_does_not_end_the_retries_of_a_refused_connection() {
        // The send error's text carries the URL; "certificate" in it must not read as a TLS failure.
        let s = server(vec![]).await;
        s.shutdown().await;
        let base = s.base_url().replacen("/v1", "/certificate/v1", 1);
        let pacing = Pacing { window: Some(Duration::from_millis(300)), ..fast_pacing() };
        let err =
            client_with(profile(&base), pacing).complete(&req("x"), None, &CancellationToken::new()).await.unwrap_err();
        match err {
            ModelError::Unavailable { attempts, last } => {
                assert!(attempts > 3, "{attempts}");
                assert!(last.starts_with("cannot reach the server") && last.contains("/certificate/v1/"), "{last}");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn local_failures_are_told_apart_from_unreachable_servers() {
        assert!(is_local_failure(true, "builder error"));
        assert!(is_local_failure(false, "error trying to connect: invalid peer certificate: UnknownIssuer"));
        assert!(is_local_failure(false, "tls: received fatal alert: ProtocolVersion"));
        assert!(is_local_failure(false, "client error (SendRequest): invalid HTTP version parsed"));
        // A TCP-level proxy hangs up like this while its backend is down, so waiting can cure it.
        assert!(!is_local_failure(false, "client error (Connect): tls handshake eof"));
        // rustls' wording for the other handshake failures that are not about reaching the server.
        for text in [
            "peer sent no certificates",
            "peer is incompatible: Tls12NotOfferedOrEnabled",
            "peer misbehaved: IllegalHelloRetryRequestWithEmptyCookie",
            "received unexpected message: got ApplicationData when expecting Handshake",
            "received unexpected handshake message: got Finished when expecting ServerHello",
            "received corrupt message of type InvalidContentType",
        ] {
            assert!(
                is_local_failure(false, &format!("error sending request: client error (Connect): {text}")),
                "{text}"
            );
        }
        assert!(!is_local_failure(
            false,
            "error trying to connect: tcp connect error: Connection refused (os error 61)"
        ));
        assert!(!is_local_failure(false, "connection reset by peer"));
    }

    #[test]
    fn default_window_is_300_seconds_and_zero_means_unbounded() {
        assert_eq!(ModelProfile::default().retry_window_s, 300);
        assert_eq!(Pacing::from_profile(&ModelProfile::default()).window, Some(Duration::from_secs(300)));
        let parse = |toml: &str| {
            let cfg =
                ferret_core::config::Config::parse(&format!("default_model = \"a\"\n[models.a]\n{toml}\n")).unwrap();
            cfg.models["a"].clone()
        };
        assert_eq!(parse("").retry_window_s, 300);
        let unbounded = parse("retry_window_s = 0");
        assert_eq!(unbounded.retry_window_s, 0);
        assert_eq!(Pacing::from_profile(&unbounded).window, None);
    }

    /// Answers every request with a 307 to `location`.
    async fn redirector(location: String) -> (String, tokio::task::JoinHandle<()>) {
        answering(format!(
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ))
        .await
    }

    /// Reads each request whole, answers it with `reply` byte for byte and closes the connection.
    async fn answering(reply: String) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/v1", l.local_addr().unwrap());
        let task = tokio::spawn(async move {
            while let Ok((mut sock, _)) = l.accept().await {
                let reply = reply.clone();
                tokio::spawn(async move {
                    // Read the whole request so the client is not reset while still sending.
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 8192];
                    loop {
                        let Ok(n) = sock.read(&mut chunk).await else { return };
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
                        let text = String::from_utf8_lossy(&buf).to_lowercase();
                        let Some(end) = text.find("\r\n\r\n") else { continue };
                        let want = text
                            .lines()
                            .find_map(|l| {
                                l.strip_prefix("content-length:").and_then(|v| v.trim().parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        if buf.len() >= end + 4 + want {
                            break;
                        }
                    }
                    let _ = sock.write_all(reply.as_bytes()).await;
                });
            }
        });
        (url, task)
    }

    #[tokio::test]
    async fn a_307_is_not_followed_and_names_the_location() {
        let other = server(vec![Reply::text("must never be asked").into()]).await;
        let location = format!("{}/chat/completions", other.base_url());
        let (url, task) = redirector(location.clone()).await;
        let err =
            client(&url).complete(&req("secret conversation"), None, &CancellationToken::new()).await.unwrap_err();
        match err {
            ModelError::Rejected { status: 307, message } => {
                assert!(message.contains(&format!("redirected to {location};")), "{message}");
                // The address to set is the base, not the endpoint the Location names.
                assert!(
                    message.contains(&format!("set base_url in the model profile to {} (", other.base_url())),
                    "{message}"
                );
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(other.requests().is_empty());
        let err = client(&url).discover().await.unwrap_err();
        assert!(
            matches!(err, ModelError::Rejected { status: 307, ref message } if message.contains(&location)),
            "{err:?}"
        );
        task.abort();
    }

    #[test]
    fn redirect_message_suggests_the_base_and_never_the_endpoint() {
        let m = redirect_message("http://a:8000/v1/", "chat/completions", Some("https://b/v1/chat/completions"));
        assert!(m.starts_with("http://a:8000/v1/chat/completions redirected to https://b/v1/chat/completions;"), "{m}");
        assert!(
            m.contains("set base_url in the model profile to https://b/v1 (that address without /chat/completions)"),
            "{m}"
        );
        // A relative Location is resolved against the request; a query string is not part of the base.
        let m = redirect_message("http://a:8000/v1", "models", Some("/api/v1/models?x=1"));
        assert!(
            m.contains("set base_url in the model profile to http://a:8000/api/v1 (that address without /models)"),
            "{m}"
        );
        // Nothing sensible to strip (a login page, the same address with a slash, no header): no address is suggested.
        for location in [Some("https://sso.example/login"), Some("http://a:8000/v1/models/"), None] {
            let m = redirect_message("http://a:8000/v1", "models", location);
            assert!(m.contains("base_url in the model profile") && !m.contains("profile to http"), "{m}");
        }
    }

    #[tokio::test]
    async fn stall_mid_stream_is_detected_and_retried() {
        let s = server(vec![Action::Stall { ms: 5000 }, Reply::text("after the stall").into()]).await;
        let (tx, mut rx) = unbounded_channel();
        let began = Instant::now();
        let c = client(&s.base_url()).complete(&req("x"), Some(&tx), &CancellationToken::new()).await.unwrap();
        assert!(began.elapsed() < Duration::from_secs(3));
        assert_eq!(c.text, "after the stall");
        assert_eq!(c.attempts, 2);
        let reasons: Vec<String> = drain(&mut rx)
            .into_iter()
            .filter_map(|e| if let StreamEvent::Retrying { reason, .. } = e { Some(reason) } else { None })
            .collect();
        assert!(reasons.iter().any(|r| r.contains("nothing")), "{reasons:?}");
    }

    /// Accepts connections and never answers.
    async fn silent_listener() -> (String, tokio::task::JoinHandle<()>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/v1", l.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((sock, _)) = l.accept().await {
                held.push(sock);
            }
        });
        (url, task)
    }

    #[tokio::test]
    async fn waiting_for_headers_counts_as_a_stall() {
        let (url, task) = silent_listener().await;
        let pacing =
            Pacing { window: Some(Duration::from_millis(250)), stall: Duration::from_millis(100), ..fast_pacing() };
        let err =
            client_with(profile(&url), pacing).complete(&req("x"), None, &CancellationToken::new()).await.unwrap_err();
        match err {
            ModelError::Unavailable { attempts, last } => {
                assert!(attempts >= 2);
                assert!(last.contains("no response headers"), "{last}");
            }
            other => panic!("unexpected {other:?}"),
        }
        task.abort();
    }

    #[tokio::test]
    async fn cancel_while_waiting_for_headers_is_prompt() {
        let (url, task) = silent_listener().await;
        let pacing = Pacing { stall: Duration::from_secs(60), ..fast_pacing() };
        let cancel = CancellationToken::new();
        let c = client_with(profile(&url), pacing);
        let canceller = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            canceller.cancel();
        });
        let began = Instant::now();
        let err = c.complete(&req("x"), None, &cancel).await.unwrap_err();
        assert!(matches!(err, ModelError::Cancelled { partial: None }));
        assert!(began.elapsed() < Duration::from_secs(2));
        task.abort();
    }

    #[tokio::test]
    async fn retry_after_is_honoured() {
        let s = server(vec![
            Action::Status { status: 503, body: "busy".into(), retry_after_s: Some(1) },
            Reply::text("ok").into(),
        ])
        .await;
        let began = Instant::now();
        let c = client(&s.base_url()).complete(&req("x"), None, &CancellationToken::new()).await.unwrap();
        assert!(began.elapsed() >= Duration::from_millis(950), "{:?}", began.elapsed());
        assert_eq!(c.attempts, 2);
    }

    #[tokio::test]
    async fn retry_window_exhausted_is_unavailable() {
        let s = MockServer::start(Script::new(|_, _| Action::Status {
            status: 500,
            body: "{\"error\":{\"message\":\"still down\"}}".into(),
            retry_after_s: None,
        }))
        .await
        .unwrap();
        let pacing = Pacing { window: Some(Duration::from_millis(200)), ..fast_pacing() };
        let err = client_with(profile(&s.base_url()), pacing)
            .complete(&req("x"), None, &CancellationToken::new())
            .await
            .unwrap_err();
        match err {
            ModelError::Unavailable { attempts, last } => {
                assert!(attempts >= 2);
                assert!(last.contains("500") && last.contains("still down"), "{last}");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn bad_request_is_rejected_with_the_servers_message() {
        let s = server(vec![Action::Status {
            status: 400,
            body: "{\"error\":{\"message\":\"tool schema is invalid\"}}".into(),
            retry_after_s: None,
        }])
        .await;
        let err = client(&s.base_url()).complete(&req("x"), None, &CancellationToken::new()).await.unwrap_err();
        assert!(
            matches!(err, ModelError::Rejected { status: 400, ref message } if message == "tool schema is invalid"),
            "{err:?}"
        );
        assert_eq!(s.requests().len(), 1);
    }

    #[tokio::test]
    async fn non_json_rejection_is_cut_to_2000_characters() {
        let s = server(vec![Action::Status { status: 404, body: "é".repeat(5000), retry_after_s: None }]).await;
        let err = client(&s.base_url()).complete(&req("x"), None, &CancellationToken::new()).await.unwrap_err();
        match err {
            ModelError::Rejected { status: 404, message } => assert_eq!(message.chars().count(), 2000),
            other => panic!("unexpected {other:?}"),
        }
        // The server does serve the id that was sent, so the 404 stands and nothing is sent again.
        assert_eq!(s.requests().len(), 1);
    }

    #[tokio::test]
    async fn context_overflow_parses_numbers() {
        let s = server(vec![Reply::text("unused").into()]).await;
        s.set_model("mock", Some(1000));
        let big = "word ".repeat(2000);
        let err = client(&s.base_url()).complete(&req(&big), None, &CancellationToken::new()).await.unwrap_err();
        match err {
            ModelError::ContextOverflow { limit, requested, message } => {
                assert_eq!(limit, Some(1000));
                assert!(requested.is_some_and(|r| r > 1000));
                assert!(message.contains("maximum context length"));
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(s.requests().len(), 1);
    }

    async fn overflow_of(status: u16, body: &str) -> (ModelError, usize) {
        let s = server(vec![Action::Status { status, body: body.into(), retry_after_s: None }]).await;
        let err = client(&s.base_url()).complete(&req("x"), None, &CancellationToken::new()).await.unwrap_err();
        (err, s.requests().len())
    }

    #[tokio::test]
    async fn each_overflow_phrase_is_recognised() {
        for phrase in OVERFLOW_PHRASES {
            let body = json!({"error": {"message": format!("Oops: {} (limit 8192, got 9000)", phrase.to_uppercase())}});
            let (err, sent) = overflow_of(400, &body.to_string()).await;
            assert!(
                matches!(err, ModelError::ContextOverflow { limit: Some(8192), requested: Some(9000), .. }),
                "{phrase}: {err:?}"
            );
            assert_eq!(sent, 1);
        }
    }

    #[tokio::test]
    async fn llama_cpp_body_with_fields_gives_limit_and_request_the_right_way_round() {
        let body = r#"{"error":{"code":400,"message":"the request exceeds the available context size, try increasing it","type":"exceed_context_size_error","n_prompt_tokens":70000,"n_ctx":65536}}"#;
        let (err, _) = overflow_of(400, body).await;
        assert!(
            matches!(err, ModelError::ContextOverflow { limit: Some(65536), requested: Some(70000), .. }),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn llama_cpp_message_alone_gives_the_same_numbers() {
        let body =
            r#"{"error":{"message":"request (70000 tokens) exceeds the available context size (65536 tokens)"}}"#;
        let (err, _) = overflow_of(400, body).await;
        assert!(
            matches!(err, ModelError::ContextOverflow { limit: Some(65536), requested: Some(70000), .. }),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn type_code_alone_is_an_overflow() {
        for (key, code) in [("type", "exceed_context_size_error"), ("code", "context_length_exceeded")] {
            let body = json!({"error": {"message": "something unrelated", key: code}});
            let (err, _) = overflow_of(400, &body.to_string()).await;
            assert!(matches!(err, ModelError::ContextOverflow { limit: None, requested: None, .. }), "{err:?}");
        }
    }

    #[tokio::test]
    async fn a_422_is_an_overflow_only_with_overflow_wording() {
        let (err, _) =
            overflow_of(422, r#"{"error":"Input is too long: 9000 > 8192","error_type":"validation"}"#).await;
        assert!(matches!(err, ModelError::ContextOverflow { limit: Some(8192), requested: Some(9000), .. }), "{err:?}");
        let (err, _) = overflow_of(422, r#"{"detail":"temperature must be positive"}"#).await;
        match err {
            ModelError::Rejected { status: 422, message } => assert_eq!(message, "temperature must be positive"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn overflow_inside_a_200_stream_is_fatal_and_sent_once() {
        let message = "request (70000 tokens) exceeds the available context size (65536 tokens)";
        let s = server(vec![Action::StreamError { message: message.into() }, Reply::text("ok").into()]).await;
        let err = client(&s.base_url()).complete(&req("x"), None, &CancellationToken::new()).await.unwrap_err();
        assert!(
            matches!(err, ModelError::ContextOverflow { limit: Some(65536), requested: Some(70000), .. }),
            "{err:?}"
        );
        assert_eq!(s.requests().len(), 1);
    }

    #[tokio::test]
    async fn vllm_max_tokens_overflow_names_the_window_as_the_limit() {
        // vLLM's wording when prompt + max_tokens passes max_model_len.
        let message = "'max_tokens' or 'max_completion_tokens' is too large: 32768. This model's maximum context length is 131072 tokens and your request has 100000 input tokens (32768 > 131072 - 100000).";
        let body = json!({"object": "error", "message": message, "type": "BadRequestError", "code": 400});
        let (err, _) = overflow_of(400, &body.to_string()).await;
        assert!(matches!(err, ModelError::ContextOverflow { limit: Some(131072), .. }), "{err:?}");
    }

    #[test]
    fn overflow_numbers_follow_the_named_window_then_the_ordering_rules() {
        // No larger number follows the named window: the request is unknown.
        assert_eq!(overflow_numbers("This model's maximum context length is 8192 tokens."), (Some(8192), None));
        assert_eq!(overflow_numbers("Maximum Context Length is 8192, you sent 9000"), (Some(8192), Some(9000)));
        assert_eq!(
            overflow_numbers("exceeds the available context size of 4096 (5000 requested)"),
            (Some(4096), Some(5000))
        );
        // `A > B` names the request first.
        assert_eq!(overflow_numbers("Prompt is too long: 70000 > 65536"), (Some(65536), Some(70000)));
        assert_eq!(overflow_numbers("too long: 70000>65536"), (Some(65536), Some(70000)));
        // The last resort: the first two large integers.
        assert_eq!(overflow_numbers("got 5000, limit 4096"), (Some(4096), Some(5000)));
        assert_eq!(overflow_numbers("only 4096 here"), (Some(4096), None));
    }

    #[tokio::test]
    async fn other_errors_inside_a_200_stream_are_still_retried() {
        let s =
            server(vec![Action::StreamError { message: "engine overloaded".into() }, Reply::text("ok").into()]).await;
        let done = client(&s.base_url()).complete(&req("x"), None, &CancellationToken::new()).await.unwrap();
        assert_eq!(done.attempts, 2);
        assert_eq!(s.requests().len(), 2);
    }

    #[tokio::test]
    async fn overflow_wording_on_413_and_other_phrasings() {
        let s = server(vec![Action::Status {
            status: 413,
            body: "{\"detail\":\"Prompt is too long: 70000 > 65536\"}".into(),
            retry_after_s: None,
        }])
        .await;
        let err = client(&s.base_url()).complete(&req("x"), None, &CancellationToken::new()).await.unwrap_err();
        assert!(
            matches!(err, ModelError::ContextOverflow { limit: Some(65536), requested: Some(70000), .. }),
            "{err:?}"
        );
        assert_eq!(overflow_numbers("no numbers 12 and 999"), (None, None));
        assert_eq!(overflow_numbers("limit 4096, got 5000 and 6000"), (Some(4096), Some(5000)));
        assert!(matches!(classify_status(400, "x", None), Fail::Fatal(ModelError::Rejected { .. })));
        assert!(matches!(classify_status(429, "x", None), Fail::Retry { .. }));
        assert!(matches!(classify_status(408, "x", None), Fail::Retry { .. }));
        assert!(matches!(classify_status(404, "x", None), Fail::Fatal(ModelError::Rejected { .. })));
    }

    #[tokio::test]
    async fn cancel_during_a_stream_returns_the_partial_text() {
        let text = "abcdefghij".repeat(30);
        let mut reply = Reply::text(text.clone()).with_delay_ms(100);
        reply.piece_chars = 5;
        let s = server(vec![reply.into()]).await;
        let cancel = CancellationToken::new();
        let canceller = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(450)).await;
            canceller.cancel();
        });
        let pacing = Pacing { stall: Duration::from_secs(5), ..fast_pacing() };
        let began = Instant::now();
        let err = client_with(profile(&s.base_url()), pacing).complete(&req("x"), None, &cancel).await.unwrap_err();
        assert!(began.elapsed() < Duration::from_millis(1500));
        match err {
            ModelError::Cancelled { partial: Some(p) } => {
                assert!(!p.text.is_empty() && text.starts_with(&p.text) && p.text.len() < text.len());
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn cancel_during_the_retry_sleep_is_prompt() {
        let s = MockServer::start(Script::new(|_, _| Action::Status {
            status: 500,
            body: String::new(),
            retry_after_s: None,
        }))
        .await
        .unwrap();
        let pacing =
            Pacing { base_delay: Duration::from_secs(30), max_delay: Duration::from_secs(30), ..fast_pacing() };
        let c = client_with(profile(&s.base_url()), pacing);
        let cancel = CancellationToken::new();
        let canceller = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            canceller.cancel();
        });
        let began = Instant::now();
        let err = c.complete(&req("x"), None, &cancel).await.unwrap_err();
        assert!(matches!(err, ModelError::Cancelled { partial: None }));
        assert!(began.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn already_cancelled_makes_no_request() {
        let s = server(vec![Reply::text("x").into()]).await;
        let cancel = CancellationToken::new();
        cancel.cancel();
        let err = client(&s.base_url()).complete(&req("x"), None, &cancel).await.unwrap_err();
        assert!(matches!(err, ModelError::Cancelled { .. }));
        assert!(s.requests().is_empty());
    }

    #[tokio::test]
    async fn unreachable_server_started_later_is_picked_up() {
        let s = server(vec![Reply::text("welcome back").into()]).await;
        s.shutdown().await;
        let c = client(&s.base_url());
        let (tx, mut rx) = unbounded_channel();
        let task = tokio::spawn(async move { c.complete(&req("x"), Some(&tx), &CancellationToken::new()).await });
        tokio::time::sleep(Duration::from_millis(250)).await;
        s.restart().await.unwrap();
        let done = tokio::time::timeout(Duration::from_secs(5), task).await.unwrap().unwrap().unwrap();
        assert_eq!(done.text, "welcome back");
        assert!(done.attempts >= 2);
        let evs = drain(&mut rx);
        assert!(evs.iter().any(|e| matches!(e, StreamEvent::Retrying { .. })));
    }

    #[tokio::test]
    async fn bearer_header_only_when_configured() {
        let s = server(vec![Reply::text("a").into(), Reply::text("b").into(), Reply::text("c").into()]).await;
        let cancel = CancellationToken::new();
        // PATH is always set and never empty; an unset name must send nothing.
        let mut p = profile(&s.base_url());
        client_with(p.clone(), fast_pacing()).complete(&req("x"), None, &cancel).await.unwrap();
        p.api_key_env = Some("PATH".into());
        client_with(p.clone(), fast_pacing()).complete(&req("x"), None, &cancel).await.unwrap();
        p.api_key_env = Some("FERRET_TEST_SURELY_UNSET_KEY_VAR".into());
        client_with(p, fast_pacing()).complete(&req("x"), None, &cancel).await.unwrap();
        let path = std::env::var("PATH").unwrap();
        assert_eq!(s.auth_headers(), vec![None, Some(format!("Bearer {path}")), None]);
    }

    fn write_key(dir: &Path, name: &str, content: &str, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(name);
        std::fs::write(&p, content).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[tokio::test]
    async fn a_key_file_is_the_bearer_and_is_read_once() {
        let s = server(vec![Reply::text("a").into(), Reply::text("b").into()]).await;
        let d = tempfile::tempdir().unwrap();
        write_key(d.path(), "m", "  sk-from-file\n", 0o600);
        let mut p = profile(&s.base_url());
        p.api_key_file = Some("m".into());
        let c = ModelClient::new("m", p, d.path()).unwrap().with_pacing(fast_pacing());
        assert!(!format!("{c:?}").contains("sk-from-file"));
        let cancel = CancellationToken::new();
        c.complete(&req("x"), None, &cancel).await.unwrap();
        std::fs::remove_file(d.path().join("m")).unwrap();
        c.complete(&req("x"), None, &cancel).await.unwrap();
        assert_eq!(
            s.auth_headers(),
            vec![Some("Bearer sk-from-file".to_string()), Some("Bearer sk-from-file".to_string())]
        );
    }

    #[test]
    fn a_missing_or_open_key_file_stops_new() {
        let d = tempfile::tempdir().unwrap();
        let mut p = profile("http://127.0.0.1:1/v1");
        p.api_key_file = Some("m".into());
        let e = ModelClient::new("m", p.clone(), d.path()).unwrap_err();
        let ModelError::Config(msg) = e else { panic!("expected Config") };
        assert!(msg.starts_with("model profile 'm': "), "{msg}");
        assert!(msg.contains(&d.path().join("m").display().to_string()), "{msg}");
        write_key(d.path(), "m", "sk-secret", 0o644);
        let ModelError::Config(msg) = ModelClient::new("m", p, d.path()).unwrap_err() else {
            panic!("expected Config")
        };
        assert!(msg.starts_with("model profile 'm': ") && msg.contains("chmod 600"), "{msg}");
        assert!(!msg.contains("sk-secret"));
    }

    /// The proxy variables are read when a client is built, and `set_var` in a threaded test binary is
    /// unsound, so this test runs the test binary again for itself with the variables in its environment.
    #[tokio::test]
    async fn model_requests_ignore_proxy_variables() {
        if std::env::var_os("FERRET_TEST_PROXY_CHILD").is_none() {
            let port = {
                let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                l.local_addr().unwrap().port()
            };
            let proxy = format!("http://127.0.0.1:{port}");
            let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
            cmd.args([
                "client::tests::model_requests_ignore_proxy_variables",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("FERRET_TEST_PROXY_CHILD", "1");
            for var in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"] {
                cmd.env(var, &proxy);
            }
            let out = cmd.output().unwrap();
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(out.status.success(), "child failed:\n{stdout}\n{}", String::from_utf8_lossy(&out.stderr));
            assert!(stdout.contains("FERRET_PROXY_CHILD_CHECKED"), "child did not run its checks:\n{stdout}");
            return;
        }
        let s = server(vec![Reply::text("hi").into()]).await;
        let c = client(&s.base_url());
        let done = c.complete(&req("x"), None, &CancellationToken::new()).await.unwrap();
        assert_eq!(done.text, "hi");
        c.discover().await.unwrap();
        assert!(c.health().await);
        let control = reqwest::Client::new().get(format!("{}/models", s.base_url())).send().await;
        assert!(control.is_err(), "the control request reached the mock, so the proxy variables are not in force");
        println!("FERRET_PROXY_CHILD_CHECKED");
        s.shutdown().await;
    }

    #[tokio::test]
    async fn timing_is_plausible() {
        let mut reply = Reply::text("0123456789".repeat(5)).with_delay_ms(30);
        reply.piece_chars = 10;
        let s = server(vec![reply.into()]).await;
        let pacing = Pacing { stall: Duration::from_secs(5), ..fast_pacing() };
        let c = client_with(profile(&s.base_url()), pacing)
            .complete(&req("x"), None, &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(c.timing.queue_ms, 0);
        assert!(c.timing.ttft_ms <= c.timing.total_ms);
        assert!(c.timing.total_ms >= 100, "{:?}", c.timing);
        assert!(c.timing.total_ms < 3000, "{:?}", c.timing);
    }

    #[tokio::test]
    async fn discover_from_server_config_and_unknown() {
        let s = server(vec![]).await;
        s.set_model("mock", Some(32768));
        let d = client(&s.base_url()).discover().await.unwrap();
        assert_eq!(
            d,
            Discovered {
                served_model: "mock".into(),
                context_window: Some(32768),
                source: WindowSource::Server,
                server_window: Some(32768)
            }
        );

        let mut p = profile(&s.base_url());
        p.context_window = Some(16000);
        let d = client_with(p, fast_pacing()).discover().await.unwrap();
        assert_eq!((d.context_window, d.source, d.server_window), (Some(16000), WindowSource::Config, Some(32768)));

        s.set_model("mock", None);
        let d = client(&s.base_url()).discover().await.unwrap();
        assert_eq!((d.context_window, d.source, d.server_window), (None, WindowSource::Unknown, None));

        // A single entry with another id is used, and its id becomes the served model.
        s.set_model("other-name", Some(2048));
        let d = client(&s.base_url()).discover().await.unwrap();
        assert_eq!((d.served_model.as_str(), d.context_window), ("other-name", Some(2048)));
    }

    #[tokio::test]
    async fn requests_carry_the_model_id_discovery_selected() {
        let s = server(vec![Reply::text("hello").into(), Reply::text("again").into()]).await;
        s.set_model("the-served-name", Some(32768));
        let c = client(&s.base_url());
        let d = c.discover().await.unwrap();
        assert_eq!(d.served_model, "the-served-name");
        let done = c.complete(&req("x"), None, &CancellationToken::new()).await.unwrap();
        assert_eq!((done.text.as_str(), done.attempts), ("hello", 1));
        // Clones share what discovery found.
        c.clone().complete(&req("x"), None, &CancellationToken::new()).await.unwrap();
        assert_eq!(models_sent(&s), ["the-served-name", "the-served-name"]);
    }

    /// The `model` field of every chat request the server received.
    fn models_sent(s: &MockServer) -> Vec<String> {
        s.requests().iter().map(|r| r["model"].as_str().unwrap_or_default().to_string()).collect()
    }

    #[tokio::test]
    async fn a_client_that_never_ran_discovery_finds_the_served_id() {
        // What a restored session meets after a daemon restart: the configured name is not served.
        let s = server(vec![Reply::text("hello").into(), Reply::text("again").into()]).await;
        s.set_model("the-served-name", Some(32768));
        let c = client(&s.base_url());
        let (tx, mut rx) = unbounded_channel();
        let done = c.complete(&req("x"), Some(&tx), &CancellationToken::new()).await.unwrap();
        assert_eq!((done.text.as_str(), done.attempts), ("hello", 2));
        assert_eq!(models_sent(&s), ["mock", "the-served-name"]);
        let evs = drain(&mut rx);
        let told = |e: &StreamEvent| matches!(e, StreamEvent::Retrying { attempt: 1, after_ms: 0, reason } if reason.contains("'the-served-name'"));
        assert!(evs.iter().any(told), "{evs:?}");
        // The id is remembered, by clones too: the next request is right the first time.
        let done = c.clone().complete(&req("x"), None, &CancellationToken::new()).await.unwrap();
        assert_eq!((done.text.as_str(), done.attempts), ("again", 1));
        assert_eq!(models_sent(&s), ["mock", "the-served-name", "the-served-name"]);
        // The id found this way counts as discovered: a later change of model is not followed.
        s.set_model("yet-another", Some(32768));
        let err = c.complete(&req("x"), None, &CancellationToken::new()).await.unwrap_err();
        assert!(
            matches!(err, ModelError::Rejected { status: 404, ref message } if message.contains("'yet-another'")),
            "{err:?}"
        );
        assert_eq!(models_sent(&s).len(), 4);
    }

    #[tokio::test]
    async fn the_served_id_is_found_when_the_server_starts_after_the_request() {
        let s = server(vec![Reply::text("welcome back").into()]).await;
        s.set_model("the-served-name", Some(32768));
        s.shutdown().await;
        let c = client(&s.base_url());
        // Discovery at session creation finds nobody home.
        assert!(matches!(c.discover().await, Err(ModelError::Unavailable { .. })));
        let task = tokio::spawn(async move { c.complete(&req("x"), None, &CancellationToken::new()).await });
        tokio::time::sleep(Duration::from_millis(250)).await;
        s.restart().await.unwrap();
        let done = tokio::time::timeout(Duration::from_secs(5), task).await.unwrap().unwrap().unwrap();
        assert_eq!(done.text, "welcome back");
        assert!(done.attempts >= 3, "{}", done.attempts);
        assert_eq!(models_sent(&s), ["mock", "the-served-name"]);
    }

    #[tokio::test]
    async fn a_server_relaunched_with_another_model_is_not_followed() {
        let s = server(vec![Reply::text("one").into(), Reply::text("two").into()]).await;
        s.set_model("first", Some(32768));
        let c = client(&s.base_url());
        assert_eq!(c.discover().await.unwrap().served_model, "first");
        c.complete(&req("x"), None, &CancellationToken::new()).await.unwrap();
        // The relaunched server serves another id (here the configured name); the session began with "first".
        s.set_model("mock", Some(32768));
        let (tx, mut rx) = unbounded_channel();
        let err = c.complete(&req("x"), Some(&tx), &CancellationToken::new()).await.unwrap_err();
        match err {
            ModelError::Rejected { status: 404, message } => {
                assert!(
                    message.contains("no longer serves 'first'") && message.contains("now serves 'mock'"),
                    "{message}"
                );
                assert!(message.contains("restart the ferret daemon"), "{message}");
                // What the server itself said is kept.
                assert!(message.ends_with("The server said: The model `first` does not exist."), "{message}");
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(!drain(&mut rx).iter().any(|e| matches!(e, StreamEvent::Retrying { .. })));
        // Nothing went out with the new id, and the next request, of a clone too, does not switch either.
        assert_eq!(models_sent(&s), ["first", "first"]);
        assert!(matches!(
            c.clone().complete(&req("x"), None, &CancellationToken::new()).await,
            Err(ModelError::Rejected { status: 404, .. })
        ));
        assert_eq!(models_sent(&s), ["first", "first", "first"]);
        // With the old model back the session carries on.
        s.set_model("first", Some(32768));
        let done = c.complete(&req("x"), None, &CancellationToken::new()).await.unwrap();
        assert_eq!((done.text.as_str(), done.attempts), ("two", 1));
    }

    #[tokio::test]
    async fn a_404_from_a_server_with_several_other_models_is_a_configuration_error() {
        let s = server(vec![Reply::text("unused").into()]).await;
        s.set_model("alpha", Some(32768));
        s.also_serve("beta");
        let err = client(&s.base_url()).complete(&req("x"), None, &CancellationToken::new()).await.unwrap_err();
        match err {
            ModelError::Config(m) => assert!(m.contains("'mock'") && m.contains("alpha, beta"), "{m}"),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(models_sent(&s), ["mock"]);
    }

    #[test]
    fn several_served_models_without_the_configured_one_is_a_configuration_error() {
        let p = profile("http://x/v1");
        let j = json!({"data": [{"id": "alpha"}, {"id": "beta"}]});
        match pick_model("t", &p, &j) {
            Err(ModelError::Config(m)) => {
                assert!(m.contains("'mock'") && m.contains("alpha, beta") && m.contains("Set `model`"), "{m}")
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn pick_model_reads_every_window_key_and_matches_by_id() {
        let p = profile("http://x/v1");
        for key in WINDOW_KEYS {
            let j = json!({"data": [{"id": "a"}, {"id": "mock", key: 777}]});
            let d = pick_model("t", &p, &j).unwrap();
            assert_eq!((d.context_window, d.source), (Some(777), WindowSource::Server), "{key}");
        }
        let j = json!({"data": [{"id": "mock", "max_model_len": 0, "context_length": 555}]});
        assert_eq!(pick_model("t", &p, &j).unwrap().context_window, Some(555));
        let j = json!({"data": [{"id": "a"}, {"id": "b"}]});
        assert!(matches!(pick_model("t", &p, &j), Err(ModelError::Config(m)) if m.contains("a, b")));
        let j = json!({"data": []});
        let d = pick_model("t", &p, &j).unwrap();
        assert_eq!((d.served_model.as_str(), d.source), ("mock", WindowSource::Unknown));
    }

    #[tokio::test]
    async fn health_follows_the_server() {
        let s = server(vec![]).await;
        let c = client(&s.base_url());
        assert!(c.health().await);
        s.shutdown().await;
        assert!(!c.health().await);
    }

    #[test]
    fn new_rejects_non_http_urls() {
        for bad in ["", "localhost:8000/v1", "ftp://host/v1", "not a url"] {
            let err = ModelClient::new("t", profile(bad), Path::new("/nonexistent-keys")).unwrap_err();
            assert!(matches!(err, ModelError::Config(_)), "{bad}");
        }
        assert!(ModelClient::new("t", profile("https://example.com/v1"), Path::new("/nonexistent-keys")).is_ok());
    }

    #[test]
    fn backoff_doubles_caps_and_jitters() {
        let p = Pacing {
            base_delay: FIRST_DELAY,
            max_delay: Duration::from_secs(4),
            stall: Duration::from_secs(1),
            window: None,
        };
        let within = |d: Duration, centre: f64| {
            let s = d.as_secs_f64();
            s >= centre * 0.9 - 1e-9 && s <= centre * 1.1 + 1e-9
        };
        for _ in 0..50 {
            assert!(within(p.backoff(1), 0.5));
            assert!(within(p.backoff(2), 1.0));
            assert!(within(p.backoff(3), 2.0));
            assert!(within(p.backoff(4), 4.0));
            assert!(within(p.backoff(40), 4.0));
        }
    }

    #[tokio::test]
    async fn retry_after_exceeding_window_does_not_sleep_past_window_or_retry() {
        let s = server(vec![
            Action::Status { status: 429, body: "slow down".into(), retry_after_s: Some(5) },
            Reply::text("must not be sent").into(),
        ])
        .await;
        let pacing = Pacing { window: Some(Duration::from_millis(200)), ..fast_pacing() };
        let began = Instant::now();
        let err = client_with(profile(&s.base_url()), pacing)
            .complete(&req("x"), None, &CancellationToken::new())
            .await
            .unwrap_err();
        assert!(began.elapsed() < Duration::from_millis(500), "slept past window: {:?}", began.elapsed());
        assert!(matches!(err, ModelError::Unavailable { attempts: 1, .. }), "{err:?}");
        assert_eq!(s.requests().len(), 1);
    }

    #[tokio::test]
    async fn coded_overflow_inside_a_200_stream_is_fatal_and_reads_fields() {
        let sse = concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\"},\"finish_reason\":null}]}\n\n",
            "data: {\"error\":{\"message\":\"prompt too large\",\"type\":\"exceed_context_size_error\",\"n_ctx\":8192,\"n_prompt_tokens\":9500}}\n\n",
        );
        let s = server(vec![
            Action::Status { status: 200, body: sse.into(), retry_after_s: None },
            Reply::text("must not retry").into(),
        ])
        .await;
        let err = client(&s.base_url()).complete(&req("x"), None, &CancellationToken::new()).await.unwrap_err();
        assert!(matches!(err, ModelError::ContextOverflow { limit: Some(8192), requested: Some(9500), .. }), "{err:?}");
        assert_eq!(s.requests().len(), 1);
    }

    #[test]
    fn greater_than_pair_handles_multibyte_utf8_prefix() {
        assert_eq!(greater_than_pair("输入70000 > 65536"), Some((70000, 65536)));
        assert_eq!(overflow_numbers("input —700 > 512"), (Some(512), Some(700)));
    }
}
