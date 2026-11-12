//! A scripted OpenAI-compatible server for tests and behavioural checks. Real HTTP on a loopback
//! port, so the client code under test is the real client code.
//!
//! CONTRACT.
//!
//! `MockServer::start(script)` binds `127.0.0.1:0` and serves:
//! - `GET /v1/models` → `{"object":"list","data":[{"id":<model>,"object":"model","max_model_len":<window>}]}`
//!   using the values set with `set_model` (defaults `mock`, 1_000_000). `set_model(_, None)` omits
//!   `max_model_len`. Each id added with `also_serve` follows as a further entry without a window.
//! - `POST /v1/chat/completions` → asks the script for an [`Action`], giving it the parsed request
//!   body and the 0-based request number, records the body (available through `requests()`), then:
//!   - `Action::Reply(reply)`: a 200 `text/event-stream` in vLLM's chunk shapes (see
//!     `assemble::fixtures`): a first chunk with `{"role":"assistant","content":""}`; reasoning split
//!     into pieces under `reasoning`; text split into pieces under `content`; each tool call as a
//!     chunk carrying `id`/`type`/`index`/`function.name` followed by its arguments split into
//!     pieces; the pieces of `reply.late_args`, each for the call it names, after every call has
//!     begun; a chunk with `finish_reason`; a usage-only chunk; `data: [DONE]`. Pieces are at most
//!     `reply.piece_chars` characters (default 24), split on character boundaries, with
//!     `reply.delay_ms` between chunks (default 0) and `reply.call_pauses` before the first chunk of
//!     the calls they name.
//!   - `Action::Status { status, body, retry_after_s }`: that HTTP status with the body verbatim.
//!   - `Action::DropAfter { reply, chunks }`: as `Reply` but the connection is closed after that
//!     many chunks, without `[DONE]`.
//!   - `Action::Stall { ms }`: send headers and the first chunk, then nothing for `ms`, then close.
//!   - `Action::Eof { reply, chunks }`: as `DropAfter` but the body ends cleanly.
//!   - `Action::StreamError { message }`: the first chunk, then `{"error":{"message":..}}`, then a clean end.
//! - A request whose `model` field is present and is not a served model (`set_model`, `also_serve`)
//!   gets HTTP 404 in vLLM's shape (`{"object":"error","message":"The model `X` does not exist.",
//!   "type":"NotFoundError","param":null,"code":404}`) before the script is consulted.
//! - Usage in a reply: `reply.usage` when set; otherwise computed — `prompt_tokens` =
//!   ceil(characters of the request's `messages` and `tools` JSON / 3.3), `cached_tokens` = the same
//!   measure over the longest prefix of the `messages` array (whole messages, compared as JSON) that
//!   equals the start of any earlier request's `messages`, `completion_tokens` = ceil(output
//!   characters / 3.3), `reasoning_tokens` = ceil(reasoning characters / 3.3). So a client that
//!   keeps its prefix stable sees high `cached_tokens`, and one that edits history sees it drop.
//! - A request whose computed `prompt_tokens` exceeds the window set with `set_model` gets HTTP 400
//!   `{"error":{"message":"This model's maximum context length is {window} tokens. However, you
//!   requested {n} tokens in the messages. Please reduce the length of the messages.","type":
//!   "BadRequestError","code":400}}` before the script is consulted.
//! - `Authorization` headers are recorded with each request (`auth_headers()`).
//!
//! `Script` is any `FnMut(&Value, usize) -> Action + Send`. `Script::sequence(actions)` plays a
//! fixed list and then repeats `Reply::text("(mock script exhausted)")`.
//!
//! `shutdown()` stops accepting and closes; `restart()` binds the same port again (for
//! server-relaunch tests). Dropping the server shuts it down.
//!
//! Helper constructors keep tests short: `Reply::text`, `Reply::tool(name, args_json)`,
//! `Reply::tools([...])`, `.with_reasoning(..)`, `.with_finish(..)`, `.with_usage(..)`.
//!
//! Tests required: each action through a plain `reqwest` client (not `ModelClient`) checking the
//! bytes on the wire parse as the documented chunks; computed usage including the cached-prefix
//! rule (a second request extending the first reports cached > 0; one that changes message 0
//! reports 0); the overflow 400; restart on the same port; request recording.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use axum::body::Body;
use axum::extract::State as AxState;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use bytes::Bytes;
use loom_core::event::{FinishReason, Usage};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, PartialEq)]
pub struct Reply {
    pub text: String,
    pub reasoning: String,
    /// `(name, arguments JSON text)`; ids are generated as `chatcmpl-tool-{16 hex}`.
    pub tool_calls: Vec<(String, String)>,
    /// `None` = `ToolCalls` when there are tool calls, else `Stop`.
    pub finish: Option<FinishReason>,
    pub usage: Option<Usage>,
    pub piece_chars: usize,
    pub delay_ms: u64,
    /// `(index of a tool call, ms)`: a pause before that call's first chunk.
    pub call_pauses: Vec<(usize, u64)>,
    /// `(index of a tool call, piece)`: arguments sent for that call once every call has begun, just
    /// before the finish chunk. The call's arguments are its text in `tool_calls` followed by these.
    pub late_args: Vec<(usize, String)>,
}

impl Reply {
    pub fn text(text: impl Into<String>) -> Reply {
        Reply {
            text: text.into(),
            reasoning: String::new(),
            tool_calls: Vec::new(),
            finish: None,
            usage: None,
            piece_chars: 24,
            delay_ms: 0,
            call_pauses: Vec::new(),
            late_args: Vec::new(),
        }
    }

    pub fn tool(name: impl Into<String>, arguments: impl Into<String>) -> Reply {
        let mut r = Reply::text("");
        r.tool_calls.push((name.into(), arguments.into()));
        r
    }

    pub fn tools<N: Into<String>, A: Into<String>>(calls: impl IntoIterator<Item = (N, A)>) -> Reply {
        let mut r = Reply::text("");
        r.tool_calls = calls.into_iter().map(|(n, a)| (n.into(), a.into())).collect();
        r
    }

    pub fn with_text(mut self, text: impl Into<String>) -> Reply {
        self.text = text.into();
        self
    }

    pub fn with_reasoning(mut self, reasoning: impl Into<String>) -> Reply {
        self.reasoning = reasoning.into();
        self
    }

    pub fn with_finish(mut self, finish: FinishReason) -> Reply {
        self.finish = Some(finish);
        self
    }

    pub fn with_usage(mut self, usage: Usage) -> Reply {
        self.usage = Some(usage);
        self
    }

    pub fn with_delay_ms(mut self, delay_ms: u64) -> Reply {
        self.delay_ms = delay_ms;
        self
    }

    /// Pause `ms` before the first chunk of tool call `index`.
    pub fn with_pause_before_call(mut self, index: usize, ms: u64) -> Reply {
        self.call_pauses.push((index, ms));
        self
    }

    /// Send `piece` for tool call `index` after every call has begun (see `late_args`).
    pub fn with_late_args(mut self, index: usize, piece: impl Into<String>) -> Reply {
        self.late_args.push((index, piece.into()));
        self
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Action {
    Reply(Reply),
    Status { status: u16, body: String, retry_after_s: Option<u64> },
    DropAfter { reply: Reply, chunks: usize },
    Stall { ms: u64 },
    /// As `DropAfter`, but the stream ends cleanly (a terminating chunk, no `[DONE]`, no
    /// `finish_reason` unless it is among the kept chunks).
    Eof { reply: Reply, chunks: usize },
    /// A first chunk, then an error object as a data event (vLLM's shape for a failure mid-stream),
    /// then a clean end.
    StreamError { message: String },
}

impl From<Reply> for Action {
    fn from(reply: Reply) -> Action {
        Action::Reply(reply)
    }
}

/// Decides the response to each request: `(request body, request number) -> Action`.
#[allow(clippy::type_complexity)]
pub struct Script(Box<dyn FnMut(&Value, usize) -> Action + Send>);

impl Script {
    pub fn new(f: impl FnMut(&Value, usize) -> Action + Send + 'static) -> Script {
        Script(Box::new(f))
    }

    pub fn sequence(actions: impl IntoIterator<Item = Action>) -> Script {
        let mut queue: std::collections::VecDeque<Action> = actions.into_iter().collect();
        Script::new(move |_, _| queue.pop_front().unwrap_or_else(|| Reply::text("(mock script exhausted)").into()))
    }

    pub(crate) fn next(&mut self, body: &Value, n: usize) -> Action {
        (self.0)(body, n)
    }
}

/// Mutable state shared by the server handle and every request handler.
struct State {
    script: Script,
    requests: Vec<Value>,
    auth: Vec<Option<String>>,
    model: String,
    window: Option<u64>,
    /// Further served ids (`also_serve`).
    also: Vec<String>,
}

struct Shared {
    state: Mutex<State>,
}

#[derive(Clone)]
struct App {
    shared: Arc<Shared>,
    /// Cancelled on shutdown: ends in-flight streams abruptly and starts the graceful stop.
    token: CancellationToken,
}

struct Running {
    token: CancellationToken,
    task: JoinHandle<()>,
}

pub struct MockServer {
    shared: Arc<Shared>,
    port: u16,
    running: Mutex<Option<Running>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn launch(listener: TcpListener, shared: &Arc<Shared>) -> Running {
    let token = CancellationToken::new();
    let app = App { shared: Arc::clone(shared), token: token.clone() };
    let router = Router::new()
        .route("/v1/models", get(models))
        .route("/v1/chat/completions", post(chat))
        .with_state(app);
    let stop = token.clone();
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router).with_graceful_shutdown(async move { stop.cancelled().await }).await;
    });
    Running { token, task }
}

impl MockServer {
    pub async fn start(script: Script) -> std::io::Result<MockServer> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let port = listener.local_addr()?.port();
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                script,
                requests: Vec::new(),
                auth: Vec::new(),
                model: "mock".to_string(),
                window: Some(1_000_000),
                also: Vec::new(),
            }),
        });
        let running = launch(listener, &shared);
        Ok(MockServer { shared, port, running: Mutex::new(Some(running)) })
    }

    /// `http://127.0.0.1:{port}/v1`
    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}/v1", self.port)
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn set_model(&self, id: &str, window: Option<u64>) {
        let mut st = lock(&self.shared.state);
        st.model = id.to_string();
        st.window = window;
    }

    /// Serve a further model id next to the one `set_model` names, as a multi-model server does.
    pub fn also_serve(&self, id: &str) {
        lock(&self.shared.state).also.push(id.to_string());
    }

    /// Bodies of every chat request received so far, in order.
    pub fn requests(&self) -> Vec<Value> {
        lock(&self.shared.state).requests.clone()
    }

    /// The `Authorization` header of every chat request received so far (`None` when absent).
    pub fn auth_headers(&self) -> Vec<Option<String>> {
        lock(&self.shared.state).auth.clone()
    }

    /// Stop accepting, cut every open connection, and return once the port is free.
    pub async fn shutdown(&self) {
        let running = lock(&self.running).take();
        if let Some(r) = running {
            r.token.cancel();
            let _ = r.task.await;
        }
    }

    /// Bind the same port again after `shutdown`. The script and recordings carry on.
    pub async fn restart(&self) -> std::io::Result<()> {
        if lock(&self.running).is_some() {
            return Ok(());
        }
        let mut last = None;
        for _ in 0..100 {
            match TcpListener::bind(("127.0.0.1", self.port)).await {
                Ok(listener) => {
                    *lock(&self.running) = Some(launch(listener, &self.shared));
                    return Ok(());
                }
                Err(e) => {
                    last = Some(e);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
        }
        Err(last.unwrap_or_else(|| std::io::Error::other("could not rebind the mock server port")))
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        if let Some(r) = lock(&self.running).take() {
            r.token.cancel();
        }
    }
}

async fn models(AxState(app): AxState<App>) -> Response {
    let st = lock(&app.shared.state);
    let mut entry = json!({"id": st.model, "object": "model"});
    if let (Some(w), Some(obj)) = (st.window, entry.as_object_mut()) {
        obj.insert("max_model_len".to_string(), json!(w));
    }
    let mut data = vec![entry];
    data.extend(st.also.iter().map(|id| json!({"id": id, "object": "model"})));
    axum::Json(json!({"object": "list", "data": data})).into_response()
}

/// ceil(chars / 3.3), in integers.
fn tokens(chars: usize) -> u64 {
    let c = u64::try_from(chars).unwrap_or(u64::MAX);
    c.saturating_mul(10).saturating_add(32) / 33
}

fn json_chars(v: &impl serde::Serialize) -> usize {
    serde_json::to_string(v).map(|s| s.chars().count()).unwrap_or(0)
}

fn messages_of(body: &Value) -> &[Value] {
    body.get("messages").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[])
}

/// `(prompt_tokens, cached_tokens)` for a request, given the requests received before it.
fn prompt_usage(body: &Value, earlier: &[Value]) -> (u64, u64) {
    let messages = messages_of(body);
    let mut chars = json_chars(&messages);
    if let Some(tools) = body.get("tools").filter(|t| !t.is_null()) {
        chars = chars.saturating_add(json_chars(tools));
    }
    let shared = earlier
        .iter()
        .map(|prev| messages.iter().zip(messages_of(prev)).take_while(|(a, b)| a == b).count())
        .max()
        .unwrap_or(0);
    let cached = match messages.get(..shared) {
        Some(prefix) if shared > 0 => tokens(json_chars(&prefix)),
        _ => 0,
    };
    (tokens(chars), cached)
}

fn error_response(status: StatusCode, body: String, retry_after_s: Option<u64>) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    if let Some(s) = retry_after_s {
        if let Ok(v) = HeaderValue::from_str(&s.to_string()) {
            headers.insert(header::RETRY_AFTER, v);
        }
    }
    (status, headers, Body::from(body)).into_response()
}

async fn chat(AxState(app): AxState<App>, headers: HeaderMap, body: Bytes) -> Response {
    let Ok(request) = serde_json::from_slice::<Value>(&body) else {
        let err = json!({"error": {"message": "The request body is not valid JSON.", "type": "BadRequestError", "code": 400}});
        return error_response(StatusCode::BAD_REQUEST, err.to_string(), None);
    };
    let auth = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).map(str::to_string);

    // Numbering, recording and the script call happen under one lock, so the script sees requests
    // in arrival order.
    let (action, prompt, cached, model, n) = {
        let mut st = lock(&app.shared.state);
        let n = st.requests.len();
        let (prompt, cached) = prompt_usage(&request, &st.requests);
        st.requests.push(request.clone());
        st.auth.push(auth);
        let asked = request.get("model").and_then(Value::as_str);
        if let Some(asked) = asked.filter(|m| *m != st.model && !st.also.iter().any(|a| a == m)) {
            let err = json!({
                "object": "error",
                "message": format!("The model `{asked}` does not exist."),
                "type": "NotFoundError",
                "param": null,
                "code": 404,
            });
            return error_response(StatusCode::NOT_FOUND, err.to_string(), None);
        }
        if let Some(window) = st.window {
            if prompt > window {
                let message = format!(
                    "This model's maximum context length is {window} tokens. However, you requested {prompt} tokens in the messages. Please reduce the length of the messages."
                );
                let err = json!({"error": {"message": message, "type": "BadRequestError", "code": 400}});
                return error_response(StatusCode::BAD_REQUEST, err.to_string(), None);
            }
        }
        let action = st.script.next(&request, n);
        (action, prompt, cached, st.model.clone(), n)
    };

    match action {
        Action::Status { status, body, retry_after_s } => {
            let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            error_response(status, body, retry_after_s)
        }
        Action::Reply(reply) => {
            let (all, pauses) = payloads(&reply, prompt, cached, &model, n);
            sse(plan(&all, reply.delay_ms, &pauses), &app.token)
        }
        Action::DropAfter { reply, chunks } => {
            let (all, pauses) = payloads(&reply, prompt, cached, &model, n);
            let kept = all.get(..chunks.min(all.len())).unwrap_or(&[]);
            let mut steps = plan(kept, reply.delay_ms, &pauses);
            // Let the status line and the chunks already queued reach the wire before the abort, so
            // the client sees a truncated body rather than a failed request.
            steps.push_back(Step::Sleep(25));
            steps.push_back(Step::Fail);
            sse(steps, &app.token)
        }
        Action::Eof { reply, chunks } => {
            let (all, pauses) = payloads(&reply, prompt, cached, &model, n);
            let kept = all.get(..chunks.min(all.len())).unwrap_or(&[]);
            sse(plan(kept, reply.delay_ms, &pauses), &app.token)
        }
        Action::StreamError { message } => {
            let (first, _) = payloads(&Reply::text(""), prompt, cached, &model, n);
            let mut all: Vec<String> = first.into_iter().take(1).collect();
            all.push(json!({"error": {"message": message, "type": "InternalServerError", "code": 500}}).to_string());
            sse(plan(&all, 0, &[]), &app.token)
        }
        Action::Stall { ms } => {
            let (first, _) = payloads(&Reply::text(""), prompt, cached, &model, n);
            let mut steps = plan(first.get(..1).unwrap_or(&[]), 0, &[]);
            steps.push_back(Step::Sleep(ms));
            steps.push_back(Step::Fail);
            sse(steps, &app.token)
        }
    }
}

enum Step {
    Data(Bytes),
    Sleep(u64),
    /// Abort the response body: the connection closes with no terminating chunk.
    Fail,
}

/// The steps that send `payloads`: `delay_ms` between them, and each pause of `pauses` (position of the
/// payload it precedes, ms) before its payload.
fn plan(payloads: &[String], delay_ms: u64, pauses: &[(usize, u64)]) -> VecDeque<Step> {
    let mut steps = VecDeque::new();
    for (i, p) in payloads.iter().enumerate() {
        if i > 0 && delay_ms > 0 {
            steps.push_back(Step::Sleep(delay_ms));
        }
        for (_, ms) in pauses.iter().filter(|(at, _)| *at == i) {
            steps.push_back(Step::Sleep(*ms));
        }
        steps.push_back(Step::Data(Bytes::from(format!("data: {p}\n\n"))));
    }
    steps
}

fn sse(steps: VecDeque<Step>, token: &CancellationToken) -> Response {
    fn cut() -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "mock server closed the stream")
    }
    let stream = futures_util::stream::unfold((steps, token.clone()), |(mut steps, token)| async move {
        loop {
            if token.is_cancelled() {
                return Some((Err(cut()), (VecDeque::new(), token)));
            }
            match steps.pop_front()? {
                Step::Data(b) => return Some((Ok::<Bytes, std::io::Error>(b), (steps, token))),
                Step::Fail => return Some((Err(cut()), (VecDeque::new(), token))),
                Step::Sleep(ms) => {
                    tokio::select! {
                        _ = token.cancelled() => {}
                        _ = tokio::time::sleep(Duration::from_millis(ms)) => {}
                    }
                }
            }
        }
    });
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/event-stream"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    (StatusCode::OK, headers, Body::from_stream(stream)).into_response()
}

fn pieces(s: &str, max_chars: usize) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    chars.chunks(max_chars.max(1)).map(|c| c.iter().collect()).collect()
}

fn finish_name(f: FinishReason) -> String {
    serde_json::to_value(f).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_else(|| "stop".to_string())
}

/// The data payloads of a full reply stream, in order, ending with `[DONE]`, and the reply's call
/// pauses as (position of the payload they precede, ms).
fn payloads(reply: &Reply, prompt: u64, cached: u64, model: &str, n: usize) -> (Vec<String>, Vec<(usize, u64)>) {
    let id = format!("chatcmpl-mock-{n}");
    let chunk = |delta: Value, finish: Option<String>| -> String {
        json!({
            "id": id, "object": "chat.completion.chunk", "created": 1, "model": model,
            "choices": [{"index": 0, "delta": delta, "logprobs": null, "finish_reason": finish}],
        })
        .to_string()
    };
    let mut out = vec![chunk(json!({"role": "assistant", "content": ""}), None)];
    for p in pieces(&reply.reasoning, reply.piece_chars) {
        out.push(chunk(json!({"reasoning": p}), None));
    }
    for p in pieces(&reply.text, reply.piece_chars) {
        out.push(chunk(json!({"content": p}), None));
    }
    let mut pauses = Vec::new();
    for (index, (name, args)) in reply.tool_calls.iter().enumerate() {
        let call_id = format!("chatcmpl-tool-{:016x}", rand::random::<u64>());
        pauses.extend(reply.call_pauses.iter().filter(|(at, _)| *at == index).map(|(_, ms)| (out.len(), *ms)));
        out.push(chunk(
            json!({"tool_calls": [{"id": call_id, "type": "function", "index": index, "function": {"name": name}}]}),
            None,
        ));
        for p in pieces(args, reply.piece_chars) {
            out.push(chunk(json!({"tool_calls": [{"index": index, "function": {"arguments": p}}]}), None));
        }
    }
    for (index, piece) in &reply.late_args {
        out.push(chunk(json!({"tool_calls": [{"index": index, "function": {"arguments": piece}}]}), None));
    }
    let default_finish = if reply.tool_calls.is_empty() { FinishReason::Stop } else { FinishReason::ToolCalls };
    out.push(chunk(json!({}), Some(finish_name(reply.finish.unwrap_or(default_finish)))));

    let usage = reply.usage.unwrap_or_else(|| {
        let output: usize = reply.text.chars().count()
            + reply.reasoning.chars().count()
            + reply.tool_calls.iter().map(|(a, b)| a.chars().count() + b.chars().count()).sum::<usize>()
            + reply.late_args.iter().map(|(_, p)| p.chars().count()).sum::<usize>();
        Usage {
            prompt_tokens: prompt,
            cached_tokens: cached,
            completion_tokens: tokens(output),
            reasoning_tokens: tokens(reply.reasoning.chars().count()),
        }
    });
    out.push(
        json!({
            "id": id, "object": "chat.completion.chunk", "created": 1, "model": model, "choices": [],
            "usage": {
                "prompt_tokens": usage.prompt_tokens,
                "total_tokens": usage.prompt_tokens.saturating_add(usage.completion_tokens),
                "completion_tokens": usage.completion_tokens,
                "prompt_tokens_details": {"cached_tokens": usage.cached_tokens},
                "completion_tokens_details": {"reasoning_tokens": usage.reasoning_tokens},
            },
        })
        .to_string(),
    );
    out.push("[DONE]".to_string());
    (out, pauses)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn client() -> reqwest::Client {
        reqwest::Client::builder().pool_max_idle_per_host(0).build().expect("client")
    }

    async fn post_chat(server: &MockServer, body: Value) -> reqwest::Response {
        client().post(format!("{}/chat/completions", server.base_url())).json(&body).send().await.expect("send")
    }

    /// Reads a body to its end or to the first transport error; returns the bytes and whether it
    /// ended cleanly.
    async fn read_all(mut resp: reqwest::Response) -> (String, bool) {
        let mut bytes = Vec::new();
        loop {
            match resp.chunk().await {
                Ok(Some(c)) => bytes.extend_from_slice(&c),
                Ok(None) => return (String::from_utf8(bytes).expect("utf8"), true),
                Err(_) => return (String::from_utf8(bytes).expect("utf8"), false),
            }
        }
    }

    fn events(body: &str) -> Vec<String> {
        body.split("\n\n")
            .filter(|e| !e.is_empty())
            .map(|e| e.strip_prefix("data: ").expect("data prefix").to_string())
            .collect()
    }

    fn parsed(body: &str) -> Vec<Value> {
        events(body).iter().filter(|e| *e != "[DONE]").map(|e| serde_json::from_str(e).expect("json chunk")).collect()
    }

    fn msgs(texts: &[&str]) -> Value {
        let m: Vec<Value> = texts
            .iter()
            .enumerate()
            .map(|(i, t)| json!({"role": if i % 2 == 0 { "user" } else { "assistant" }, "content": t}))
            .collect();
        json!({"model": "mock", "stream": true, "messages": m})
    }

    async fn server(actions: Vec<Action>) -> MockServer {
        MockServer::start(Script::sequence(actions)).await.expect("start")
    }

    #[tokio::test]
    async fn text_reply_wire_shape() {
        let mut r = Reply::text("abcdefghij");
        r.piece_chars = 4;
        let s = server(vec![r.into()]).await;
        let resp = post_chat(&s, msgs(&["hi"])).await;
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers()["content-type"], "text/event-stream");
        let (body, clean) = read_all(resp).await;
        assert!(clean);
        assert!(body.ends_with("data: [DONE]\n\n"));
        let chunks = parsed(&body);
        assert_eq!(chunks[0]["choices"][0]["delta"], json!({"role": "assistant", "content": ""}));
        let got: Vec<&str> =
            chunks.iter().skip(1).filter_map(|c| c["choices"][0]["delta"]["content"].as_str()).collect();
        assert_eq!(got, ["abcd", "efgh", "ij"]);
        let finish: Vec<&Value> = chunks.iter().filter(|c| !c["choices"][0]["finish_reason"].is_null()).collect();
        assert_eq!(finish.len(), 1);
        assert_eq!(finish[0]["choices"][0]["finish_reason"], "stop");
        let last = chunks.last().expect("chunk");
        assert_eq!(last["choices"], json!([]));
        assert!(last["usage"]["prompt_tokens"].as_u64().expect("prompt") > 0);
        assert_eq!(last["usage"]["completion_tokens"], 4);
    }

    #[tokio::test]
    async fn pieces_split_on_char_boundaries() {
        let mut r = Reply::text("日本語のテキスト");
        r.piece_chars = 3;
        let s = server(vec![r.into()]).await;
        let (body, _) = read_all(post_chat(&s, msgs(&["hi"])).await).await;
        let got: Vec<String> = parsed(&body)
            .iter()
            .skip(1)
            .filter_map(|c| c["choices"][0]["delta"]["content"].as_str().map(str::to_string))
            .collect();
        assert_eq!(got, ["日本語", "のテキ", "スト"]);
    }

    #[tokio::test]
    async fn reasoning_and_parallel_tool_calls() {
        let reply = Reply::tools([("note", r#"{"text": "hello world, this is long"}"#), ("read", "{}")])
            .with_reasoning("We need a note and a read.");
        let s = server(vec![reply.into(), Reply::text("cut").with_finish(FinishReason::Length).into()]).await;
        let (body, clean) = read_all(post_chat(&s, msgs(&["hi"])).await).await;
        assert!(clean);
        let chunks = parsed(&body);
        let reasoning: String =
            chunks.iter().filter_map(|c| c["choices"][0]["delta"]["reasoning"].as_str()).collect();
        assert_eq!(reasoning, "We need a note and a read.");
        let mut args = [String::new(), String::new()];
        let mut names = Vec::new();
        let mut ids = Vec::new();
        for c in &chunks {
            for tc in c["choices"][0]["delta"]["tool_calls"].as_array().into_iter().flatten() {
                let i = usize::try_from(tc["index"].as_u64().expect("index")).expect("usize");
                if let Some(name) = tc["function"]["name"].as_str() {
                    assert_eq!(tc["type"], "function");
                    names.push(name.to_string());
                    ids.push(tc["id"].as_str().expect("id").to_string());
                }
                if let Some(a) = tc["function"]["arguments"].as_str() {
                    args[i].push_str(a);
                }
            }
        }
        assert_eq!(names, ["note", "read"]);
        for id in &ids {
            let hex = id.strip_prefix("chatcmpl-tool-").expect("prefix");
            assert_eq!(hex.len(), 16);
            assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        }
        assert_ne!(ids[0], ids[1]);
        assert_eq!(args[0], r#"{"text": "hello world, this is long"}"#);
        assert_eq!(args[1], "{}");
        let finish = chunks.iter().find_map(|c| c["choices"][0]["finish_reason"].as_str()).expect("finish");
        assert_eq!(finish, "tool_calls");

        let (body, _) = read_all(post_chat(&s, msgs(&["hi"])).await).await;
        assert!(parsed(&body).iter().any(|c| c["choices"][0]["finish_reason"] == "length"));
    }

    #[tokio::test]
    async fn status_action_is_verbatim() {
        let s = server(vec![
            Action::Status { status: 429, body: "slow down".into(), retry_after_s: Some(7) },
            Action::Status { status: 503, body: r#"{"error":"x"}"#.into(), retry_after_s: None },
        ])
        .await;
        let r = post_chat(&s, msgs(&["a"])).await;
        assert_eq!(r.status(), 429);
        assert_eq!(r.headers()["retry-after"], "7");
        assert_eq!(r.text().await.expect("text"), "slow down");
        let r = post_chat(&s, msgs(&["a"])).await;
        assert_eq!(r.status(), 503);
        assert!(r.headers().get("retry-after").is_none());
        assert_eq!(r.text().await.expect("text"), r#"{"error":"x"}"#);
    }

    #[tokio::test]
    async fn drop_after_truncates_without_terminator() {
        let mut reply = Reply::text("0123456789012345678901234567890123456789");
        reply.piece_chars = 5;
        let s = server(vec![Action::DropAfter { reply, chunks: 3 }]).await;
        let (body, clean) = read_all(post_chat(&s, msgs(&["hi"])).await).await;
        assert!(!clean, "the body must end with a transport error, not a terminating chunk");
        assert!(!body.contains("[DONE]"));
        assert_eq!(events(&body).len(), 3);
        // The server itself keeps serving.
        let (body, clean) = read_all(post_chat(&s, msgs(&["hi"])).await).await;
        assert!(clean);
        assert!(body.contains("(mock script exhausted)"));
    }

    #[tokio::test]
    async fn eof_and_stream_error_end_cleanly() {
        let mut r = Reply::text("0123456789012345678901234567890123456789");
        r.piece_chars = 5;
        let s = server(vec![
            Action::Eof { reply: r, chunks: 3 },
            Action::StreamError { message: "engine overloaded".into() },
        ])
        .await;
        let (body, clean) = read_all(post_chat(&s, msgs(&["hi"])).await).await;
        assert!(clean);
        assert!(!body.contains("[DONE]") && !body.contains("finish_reason\":\"stop"));
        assert_eq!(events(&body).len(), 3);
        let (body, clean) = read_all(post_chat(&s, msgs(&["hi"])).await).await;
        assert!(clean);
        let evs = events(&body);
        assert_eq!(evs.len(), 2);
        let err: Value = serde_json::from_str(&evs[1]).expect("json");
        assert_eq!(err["error"]["message"], "engine overloaded");
    }

    #[tokio::test]
    async fn a_model_that_is_not_served_is_a_vllm_style_404_before_the_script() {
        let calls = Arc::new(Mutex::new(0usize));
        let seen = Arc::clone(&calls);
        let s = MockServer::start(Script::new(move |_, _| {
            *lock(&seen) += 1;
            Reply::text("ok").into()
        }))
        .await
        .expect("start");
        let mut body = msgs(&["hi"]);
        body["model"] = json!("not-served");
        let r = post_chat(&s, body).await;
        assert_eq!(r.status(), 404);
        let v: Value = r.json().await.expect("json");
        assert_eq!(v["object"], "error");
        assert_eq!(v["message"], "The model `not-served` does not exist.");
        assert_eq!(v["type"], "NotFoundError");
        assert_eq!(v["code"], 404);
        assert_eq!(*lock(&calls), 0);
        assert_eq!(post_chat(&s, msgs(&["hi"])).await.status(), 200);
        // A further served id is accepted once it is added.
        let mut body = msgs(&["hi"]);
        body["model"] = json!("second");
        assert_eq!(post_chat(&s, body.clone()).await.status(), 404);
        s.also_serve("second");
        assert_eq!(post_chat(&s, body).await.status(), 200);
    }

    #[tokio::test]
    async fn stall_sends_first_chunk_then_goes_quiet_then_closes() {
        let s = server(vec![Action::Stall { ms: 300 }]).await;
        let started = Instant::now();
        let mut resp = post_chat(&s, msgs(&["hi"])).await;
        assert_eq!(resp.status(), 200);
        let first = resp.chunk().await.expect("first").expect("some");
        let first = String::from_utf8(first.to_vec()).expect("utf8");
        assert!(first.contains(r#""role":"assistant""#));
        assert!(started.elapsed() < Duration::from_millis(250));
        let next = resp.chunk().await;
        assert!(started.elapsed() >= Duration::from_millis(290));
        assert!(!matches!(next, Ok(Some(_))), "nothing but the close may follow the stall");
    }

    #[tokio::test]
    async fn delay_spaces_chunks() {
        let mut reply = Reply::text("abcdef").with_delay_ms(40);
        reply.piece_chars = 2;
        let s = server(vec![reply.into()]).await;
        let started = Instant::now();
        let (body, clean) = read_all(post_chat(&s, msgs(&["hi"])).await).await;
        assert!(clean);
        // role + 3 content + finish + usage + DONE = 7 chunks, 6 gaps.
        assert_eq!(events(&body).len(), 7);
        assert!(started.elapsed() >= Duration::from_millis(230));
    }

    #[tokio::test]
    async fn a_pause_before_a_call_and_late_arguments() {
        let reply = Reply::tools([("read", r#"{"path": "a"}"#), ("bash", "{}")])
            .with_pause_before_call(1, 300)
            .with_late_args(0, " ")
            .with_late_args(1, "\n");
        let s = server(vec![reply.into()]).await;
        let started = Instant::now();
        let mut resp = post_chat(&s, msgs(&["hi"])).await;
        let mut text = String::new();
        // The body chunk (counted from 1) in which the first call is whole, and the one in which the
        // second call begins.
        let (mut chunks, mut first_call_done, mut second_call_begun) = (0usize, None, None);
        while let Some(c) = resp.chunk().await.expect("chunk") {
            chunks += 1;
            text.push_str(std::str::from_utf8(&c).expect("utf8"));
            if first_call_done.is_none() && text.contains(r#"\"a\"}"#) {
                first_call_done = Some(chunks);
            }
            if second_call_begun.is_none() && text.contains(r#""name":"bash""#) {
                second_call_begun = Some(chunks);
            }
        }
        let total = started.elapsed();
        // The first call is whole before the pause; the second call starts after it.
        let (done, begun) = (first_call_done.expect("first call"), second_call_begun.expect("second call"));
        assert!(done < begun, "the first call was whole in body chunk {done}, the second began in {begun}");
        assert!(total >= Duration::from_millis(290), "{total:?}");
        let mut args = [String::new(), String::new()];
        let mut order = Vec::new();
        for c in parsed(&text) {
            for tc in c["choices"][0]["delta"]["tool_calls"].as_array().into_iter().flatten() {
                let i = usize::try_from(tc["index"].as_u64().expect("index")).expect("usize");
                order.push(i);
                args[i].push_str(tc["function"]["arguments"].as_str().unwrap_or(""));
            }
        }
        assert_eq!(args, [r#"{"path": "a"} "#.to_string(), "{}\n".to_string()]);
        // The late pieces come after both calls have begun, in the order given.
        assert_eq!(&order[order.len() - 2..], [0, 1]);
    }

    async fn usage_of(s: &MockServer, body: Value) -> Value {
        let (text, clean) = read_all(post_chat(s, body).await).await;
        assert!(clean);
        parsed(&text).last().expect("chunk")["usage"].clone()
    }

    fn ceil_tokens(chars: usize) -> u64 {
        (chars as f64 / 3.3).ceil() as u64
    }

    #[tokio::test]
    async fn computed_usage_and_cached_prefix_rule() {
        let reply = |t: &str| Action::from(Reply::text(t).with_reasoning("think"));
        let s = server(vec![reply("one"), reply("two"), reply("three"), reply("four")]).await;
        let r1 = msgs(&["system-ish first message", "second"]);
        let u1 = usage_of(&s, r1.clone()).await;
        let chars1 = serde_json::to_string(&r1["messages"]).expect("json").chars().count();
        assert_eq!(u1["prompt_tokens"], ceil_tokens(chars1));
        assert_eq!(u1["prompt_tokens_details"]["cached_tokens"], 0);
        assert_eq!(u1["completion_tokens"], ceil_tokens(8));
        assert_eq!(u1["completion_tokens_details"]["reasoning_tokens"], ceil_tokens(5));
        assert_eq!(
            u1["total_tokens"].as_u64().expect("total"),
            u1["prompt_tokens"].as_u64().expect("p") + u1["completion_tokens"].as_u64().expect("c")
        );

        // Extending the first request keeps all of its messages as the cached prefix.
        let r2 = msgs(&["system-ish first message", "second", "third", "fourth"]);
        let u2 = usage_of(&s, r2).await;
        assert_eq!(u2["prompt_tokens_details"]["cached_tokens"], u1["prompt_tokens"]);
        assert!(
            u2["prompt_tokens"].as_u64().expect("p") > u2["prompt_tokens_details"]["cached_tokens"].as_u64().expect("c")
        );

        // Editing the second message keeps only the first.
        let u3 = usage_of(&s, msgs(&["system-ish first message", "EDITED", "third"])).await;
        let first_only = serde_json::to_string(&r1["messages"].as_array().expect("arr")[..1]).expect("json");
        assert_eq!(u3["prompt_tokens_details"]["cached_tokens"], ceil_tokens(first_only.chars().count()));

        // Editing message 0 caches nothing.
        let u4 = usage_of(&s, msgs(&["a different first message", "second", "third", "fourth"])).await;
        assert_eq!(u4["prompt_tokens_details"]["cached_tokens"], 0);
    }

    #[tokio::test]
    async fn tools_count_towards_prompt_and_explicit_usage_wins() {
        let fixed = Usage { prompt_tokens: 111, cached_tokens: 22, completion_tokens: 33, reasoning_tokens: 4 };
        let s = server(vec![Reply::text("x").into(), Reply::text("x").into(), Reply::text("x").with_usage(fixed).into()])
            .await;
        let plain = msgs(&["hello"]);
        let mut with_tools = msgs(&["other"]);
        with_tools["tools"] = json!([{"type": "function", "function": {"name": "note", "parameters": {}}}]);
        let a = usage_of(&s, plain).await;
        let b = usage_of(&s, with_tools.clone()).await;
        let tools_chars = serde_json::to_string(&with_tools["tools"]).expect("json").chars().count();
        let msg_chars = serde_json::to_string(&with_tools["messages"]).expect("json").chars().count();
        assert_eq!(b["prompt_tokens"], ceil_tokens(tools_chars + msg_chars));
        assert!(a["prompt_tokens"].as_u64().is_some());
        let u = usage_of(&s, msgs(&["hello", "x", "y"])).await;
        assert_eq!(u["prompt_tokens"], 111);
        assert_eq!(u["prompt_tokens_details"]["cached_tokens"], 22);
        assert_eq!(u["completion_tokens"], 33);
        assert_eq!(u["completion_tokens_details"]["reasoning_tokens"], 4);
    }

    #[tokio::test]
    async fn context_overflow_is_a_400_before_the_script() {
        let calls = Arc::new(Mutex::new(0usize));
        let seen = Arc::clone(&calls);
        let s = MockServer::start(Script::new(move |_, _| {
            *lock(&seen) += 1;
            Reply::text("ok").into()
        }))
        .await
        .expect("start");
        s.set_model("mock", Some(10));
        let big = msgs(&["this message is certainly longer than ten tokens of thirty-three characters"]);
        let n = tokens(json_chars(&big["messages"]));
        let r = post_chat(&s, big).await;
        assert_eq!(r.status(), 400);
        let v: Value = r.json().await.expect("json");
        assert_eq!(
            v["error"]["message"],
            format!(
                "This model's maximum context length is 10 tokens. However, you requested {n} tokens in the messages. Please reduce the length of the messages."
            )
        );
        assert_eq!(v["error"]["type"], "BadRequestError");
        assert_eq!(v["error"]["code"], 400);
        assert_eq!(*lock(&calls), 0);
        // A request that fits reaches the script.
        let r = post_chat(&s, json!({"messages": []})).await;
        assert_eq!(r.status(), 200);
        assert_eq!(*lock(&calls), 1);
    }

    #[tokio::test]
    async fn models_endpoint_follows_set_model() {
        let s = server(vec![]).await;
        let url = format!("{}/models", s.base_url());
        let get_json = || async { client().get(&url).send().await.expect("get").json::<Value>().await.expect("json") };
        assert_eq!(
            get_json().await,
            json!({"object": "list", "data": [{"id": "mock", "object": "model", "max_model_len": 1_000_000}]})
        );
        s.set_model("other", Some(4096));
        assert_eq!(get_json().await["data"][0], json!({"id": "other", "object": "model", "max_model_len": 4096}));
        s.set_model("bare", None);
        assert_eq!(get_json().await["data"][0], json!({"id": "bare", "object": "model"}));
        s.also_serve("second");
        assert_eq!(get_json().await["data"], json!([{"id": "bare", "object": "model"}, {"id": "second", "object": "model"}]));
    }

    #[tokio::test]
    async fn requests_and_auth_are_recorded_in_order() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        let s = MockServer::start(Script::new(move |body, n| {
            lock(&log).push((n, body["messages"][0]["content"].clone()));
            Reply::text("ok").into()
        }))
        .await
        .expect("start");
        let c = client();
        let url = format!("{}/chat/completions", s.base_url());
        for (i, auth) in [Some("Bearer k1"), None, Some("Bearer k3")].into_iter().enumerate() {
            let mut rb = c.post(&url).json(&msgs(&[&format!("m{i}")]));
            if let Some(a) = auth {
                rb = rb.header("authorization", a);
            }
            read_all(rb.send().await.expect("send")).await;
        }
        let reqs = s.requests();
        assert_eq!(reqs.len(), 3);
        assert_eq!(reqs[2]["messages"][0]["content"], "m2");
        assert_eq!(s.auth_headers(), [Some("Bearer k1".to_string()), None, Some("Bearer k3".to_string())]);
        assert_eq!(*lock(&seen), [(0, json!("m0")), (1, json!("m1")), (2, json!("m2"))]);
    }

    #[tokio::test]
    async fn shutdown_refuses_connections_and_restart_reuses_the_port() {
        let s = server(vec![Reply::text("first").into()]).await;
        let port = s.port();
        assert!(s.base_url().ends_with(&format!(":{port}/v1")));
        read_all(post_chat(&s, msgs(&["a"])).await).await;

        s.shutdown().await;
        let err = client()
            .post(format!("{}/chat/completions", s.base_url()))
            .json(&msgs(&["b"]))
            .send()
            .await
            .expect_err("refused");
        assert!(err.is_connect(), "{err:?}");
        assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_err());

        s.restart().await.expect("restart");
        assert_eq!(s.port(), port);
        let (body, clean) = read_all(post_chat(&s, msgs(&["a", "x", "c"])).await).await;
        assert!(clean);
        // The script carried on (sequence exhausted, not restarted) and recordings were kept.
        assert!(body.contains("(mock script exhausted)"));
        assert_eq!(s.requests().len(), 2);
    }

    #[tokio::test]
    async fn shutdown_cuts_a_stream_in_flight() {
        let s = server(vec![Action::Stall { ms: 60_000 }]).await;
        let mut resp = post_chat(&s, msgs(&["hi"])).await;
        assert!(resp.chunk().await.expect("first").is_some());
        s.shutdown().await;
        assert!(!matches!(resp.chunk().await, Ok(Some(_))));
    }
}
