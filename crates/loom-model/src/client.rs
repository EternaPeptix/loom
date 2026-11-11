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

use crate::assemble::{Assembler, Completion, SseParser, StreamEvent};
use crate::request::ChatRequest;
use bytes::Bytes;
use futures_util::StreamExt;
use loom_core::config::ModelProfile;
use loom_core::event::{FinishReason, Timing, Usage};
use rand::Rng;
use serde_json::Value;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::UnboundedSender;
use tokio_util::sync::CancellationToken;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HEALTH_TIMEOUT: Duration = Duration::from_secs(5);
const DISCOVER_TIMEOUT: Duration = Duration::from_secs(15);
const FIRST_DELAY: Duration = Duration::from_millis(500);
const MAX_RETRY_AFTER: Duration = Duration::from_secs(600);
/// Most of an error response that is read; the message is cut to 2000 characters anyway.
const ERROR_BODY_LIMIT: usize = 64 * 1024;
const MESSAGE_CHARS: usize = 2000;
/// Keys a server may report its context window under, in order of preference.
const WINDOW_KEYS: [&str; 4] = ["max_model_len", "context_window", "context_length", "max_context_length"];
/// Phrases (lower case) a server uses for "the prompt does not fit".
const OVERFLOW_PHRASES: [&str; 5] =
    ["maximum context length", "context length", "too many tokens", "prompt is too long", "max_model_len"];

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
    Retry { reason: String, retry_after: Option<Duration> },
    Fatal(ModelError),
    Cancelled(Option<Box<Completion>>),
}

fn retry(reason: impl Into<String>) -> Fail {
    Fail::Retry { reason: reason.into(), retry_after: None }
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

#[derive(Clone, Debug)]
pub struct ModelClient {
    name: String,
    profile: ModelProfile,
    http: reqwest::Client,
    pacing: Pacing,
}

impl ModelClient {
    /// `name` is the profile's name (for messages). Fails when `base_url` is not an http(s) URL.
    pub fn new(name: &str, profile: ModelProfile) -> Result<ModelClient, ModelError> {
        let ok = reqwest::Url::parse(&profile.base_url)
            .map(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some())
            .unwrap_or(false);
        if !ok {
            return Err(ModelError::Config(format!(
                "model profile '{name}' has base_url '{}', which is not an http(s) URL; set it to something like http://host:8000/v1.",
                profile.base_url
            )));
        }
        let http = reqwest::Client::builder().connect_timeout(CONNECT_TIMEOUT).build().map_err(|e| {
            ModelError::Config(format!("model profile '{name}': cannot build an HTTP client: {}", describe(&e)))
        })?;
        let pacing = Pacing::from_profile(&profile);
        Ok(ModelClient { name: name.to_string(), profile, http, pacing })
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

    fn url(&self, path: &str) -> String {
        format!("{}/{}", self.profile.base_url.trim_end_matches('/'), path)
    }

    fn api_key(&self) -> Option<String> {
        let var = self.profile.api_key_env.as_deref()?;
        std::env::var(var).ok().filter(|k| !k.is_empty())
    }

    pub async fn complete(
        &self,
        request: &ChatRequest,
        events: Option<&UnboundedSender<StreamEvent>>,
        cancel: &CancellationToken,
    ) -> Result<Completion, ModelError> {
        let body = serde_json::to_vec(&request.body(&self.profile.model, &self.profile.extra_body))
            .map_err(|e| ModelError::Config(format!("the request cannot be serialised: {e}")))?;
        let body = Bytes::from(body);
        let url = self.url("chat/completions");
        let key = self.api_key();

        let mut attempts: u32 = 0;
        let mut first_failure: Option<Instant> = None;
        loop {
            if cancel.is_cancelled() {
                return Err(ModelError::Cancelled { partial: None });
            }
            attempts = attempts.saturating_add(1);
            let (reason, retry_after) = match self.attempt(&url, &body, key.as_deref(), attempts, events, cancel).await {
                Ok(mut done) => {
                    done.attempts = attempts;
                    return Ok(done);
                }
                Err(Fail::Cancelled(partial)) => return Err(ModelError::Cancelled { partial }),
                Err(Fail::Fatal(e)) => return Err(e),
                Err(Fail::Retry { reason, retry_after }) => (reason, retry_after),
            };

            let began = *first_failure.get_or_insert_with(Instant::now);
            if self.pacing.window.is_some_and(|w| began.elapsed() > w) {
                return Err(ModelError::Unavailable { attempts, last: reason });
            }
            let mut delay = self.pacing.backoff(attempts);
            if let Some(ra) = retry_after {
                delay = delay.max(ra.min(MAX_RETRY_AFTER));
            }
            tracing::debug!(model = %self.name, attempt = attempts, ?delay, %reason, "model attempt failed; retrying");
            send(events, StreamEvent::Retrying { attempt: attempts, after_ms: millis(delay), reason });
            tokio::select! {
                biased;
                () = cancel.cancelled() => return Err(ModelError::Cancelled { partial: None }),
                () = tokio::time::sleep(delay) => {}
            }
        }
    }

    /// One request/response cycle.
    async fn attempt(
        &self,
        url: &str,
        body: &Bytes,
        key: Option<&str>,
        attempt: u32,
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
                Ok(Err(e)) => return Err(retry(format!("cannot reach the server: {}", describe(&e)))),
                Ok(Ok(resp)) => resp,
            },
        };

        let status = resp.status();
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

        let mut stream = Box::pin(resp.bytes_stream());
        let mut parser = SseParser::new();
        let mut asm = Assembler::new();
        let mut partial = Partial::default();
        let mut ttft: Option<u64> = None;
        let mut finished = false;
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
            for payload in parser.feed(&chunk) {
                if payload.trim() == "[DONE]" {
                    finished = true;
                }
                let evs = asm.push(&payload).map_err(|e| retry(e.to_string()))?;
                for ev in evs {
                    if ttft.is_none() {
                        ttft = Some(millis(sent.elapsed()));
                    }
                    partial.note(&ev);
                    send(events, ev);
                }
            }
        }

        let mut done = asm.finish().map_err(|e| retry(e.to_string()))?;
        let total = millis(sent.elapsed());
        done.timing = Timing { queue_ms: 0, ttft_ms: ttft.unwrap_or(total), total_ms: total };
        Ok(done)
    }

    pub async fn discover(&self) -> Result<Discovered, ModelError> {
        let url = self.url("models");
        let mut req = self.http.get(&url).timeout(DISCOVER_TIMEOUT);
        if let Some(k) = self.api_key() {
            req = req.bearer_auth(k);
        }
        let unavailable = |last: String| ModelError::Unavailable { attempts: 1, last };
        let resp = req.send().await.map_err(|e| unavailable(format!("cannot reach {url}: {}", describe(&e))))?;
        let status = resp.status();
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

/// `limit` and `requested`: the first two integers >= 1000 in the message.
fn overflow_numbers(message: &str) -> (Option<u64>, Option<u64>) {
    let mut found = message
        .split(|c: char| !c.is_ascii_digit())
        .filter(|t| !t.is_empty())
        .filter_map(|t| t.parse::<u64>().ok())
        .filter(|n| *n >= 1000);
    (found.next(), found.next())
}

fn classify_status(status: u16, body: &str, retry_after: Option<Duration>) -> Fail {
    let message = error_message(body);
    if matches!(status, 400 | 413) {
        let lower = message.to_lowercase();
        if OVERFLOW_PHRASES.iter().any(|p| lower.contains(p)) {
            let (limit, requested) = overflow_numbers(&message);
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
        return Fail::Retry { reason, retry_after };
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
    use loom_core::Message;
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
        ModelClient::new("test", p).unwrap().with_pacing(pacing)
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
        let s = server(vec![Reply::text("hello there, this is a reply").with_reasoning("thinking it over").into()]).await;
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
        let joined: String = evs
            .iter()
            .filter_map(|e| if let StreamEvent::Text(t) = e { Some(t.as_str()) } else { None })
            .collect();
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
    async fn stream_ending_without_finish_reason_is_retried() {
        // The connection ends after the text chunks, before any finish_reason.
        let s = server(vec![
            Action::DropAfter { reply: Reply::text("abc"), chunks: 2 },
            Reply::text("complete").into(),
        ])
        .await;
        let c = client(&s.base_url()).complete(&req("x"), None, &CancellationToken::new()).await.unwrap();
        assert_eq!(c.text, "complete");
        assert_eq!(c.attempts, 2);
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
        let pacing = Pacing { window: Some(Duration::from_millis(250)), stall: Duration::from_millis(100), ..fast_pacing() };
        let err = client_with(profile(&url), pacing).complete(&req("x"), None, &CancellationToken::new()).await.unwrap_err();
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
        let err = client_with(profile(&s.base_url()), pacing).complete(&req("x"), None, &CancellationToken::new()).await.unwrap_err();
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
        assert!(matches!(err, ModelError::Rejected { status: 400, ref message } if message == "tool schema is invalid"), "{err:?}");
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
            matches!(err, ModelError::ContextOverflow { limit: Some(70000), requested: Some(65536), .. }),
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
        let s = MockServer::start(Script::new(|_, _| Action::Status { status: 500, body: String::new(), retry_after_s: None }))
            .await
            .unwrap();
        let pacing = Pacing { base_delay: Duration::from_secs(30), max_delay: Duration::from_secs(30), ..fast_pacing() };
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
        p.api_key_env = Some("LOOM_TEST_SURELY_UNSET_KEY_VAR".into());
        client_with(p, fast_pacing()).complete(&req("x"), None, &cancel).await.unwrap();
        let path = std::env::var("PATH").unwrap();
        assert_eq!(s.auth_headers(), vec![None, Some(format!("Bearer {path}")), None]);
    }

    #[tokio::test]
    async fn timing_is_plausible() {
        let mut reply = Reply::text("0123456789".repeat(5)).with_delay_ms(30);
        reply.piece_chars = 10;
        let s = server(vec![reply.into()]).await;
        let pacing = Pacing { stall: Duration::from_secs(5), ..fast_pacing() };
        let c = client_with(profile(&s.base_url()), pacing).complete(&req("x"), None, &CancellationToken::new()).await.unwrap();
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
        assert_eq!(d, Discovered { served_model: "mock".into(), context_window: Some(32768), source: WindowSource::Server, server_window: Some(32768) });

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
            let err = ModelClient::new("t", profile(bad)).unwrap_err();
            assert!(matches!(err, ModelError::Config(_)), "{bad}");
        }
        assert!(ModelClient::new("t", profile("https://example.com/v1")).is_ok());
    }

    #[test]
    fn backoff_doubles_caps_and_jitters() {
        let p = Pacing { base_delay: FIRST_DELAY, max_delay: Duration::from_secs(4), stall: Duration::from_secs(1), window: None };
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
}
