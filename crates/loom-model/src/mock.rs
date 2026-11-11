//! A scripted OpenAI-compatible server for tests and behavioural checks. Real HTTP on a loopback
//! port, so the client code under test is the real client code.
//!
//! CONTRACT (bodies are placeholders for the implementer; signatures and types are fixed).
//!
//! `MockServer::start(script)` binds `127.0.0.1:0` and serves:
//! - `GET /v1/models` → `{"object":"list","data":[{"id":<model>,"object":"model","max_model_len":<window>}]}`
//!   using the values set with `set_model` (defaults `mock`, 1_000_000). `set_model(_, None)` omits
//!   `max_model_len`.
//! - `POST /v1/chat/completions` → asks the script for an [`Action`], giving it the parsed request
//!   body and the 0-based request number, records the body (available through `requests()`), then:
//!   - `Action::Reply(reply)`: a 200 `text/event-stream` in vLLM's chunk shapes (see
//!     `assemble::fixtures`): a first chunk with `{"role":"assistant","content":""}`; reasoning split
//!     into pieces under `reasoning`; text split into pieces under `content`; each tool call as a
//!     chunk carrying `id`/`type`/`index`/`function.name` followed by its arguments split into
//!     pieces; a chunk with `finish_reason`; a usage-only chunk; `data: [DONE]`. Pieces are at most
//!     `reply.piece_chars` characters (default 24), split on character boundaries, with
//!     `reply.delay_ms` between chunks (default 0).
//!   - `Action::Status { status, body, retry_after_s }`: that HTTP status with the body verbatim.
//!   - `Action::DropAfter { reply, chunks }`: as `Reply` but the connection is closed after that
//!     many chunks, without `[DONE]`.
//!   - `Action::Stall { ms }`: send headers and the first chunk, then nothing for `ms`, then close.
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

use loom_core::event::{FinishReason, Usage};
use serde_json::Value;

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
}

#[derive(Clone, Debug, PartialEq)]
pub enum Action {
    Reply(Reply),
    Status { status: u16, body: String, retry_after_s: Option<u64> },
    DropAfter { reply: Reply, chunks: usize },
    Stall { ms: u64 },
}

impl From<Reply> for Action {
    fn from(reply: Reply) -> Action {
        Action::Reply(reply)
    }
}

/// Decides the response to each request: `(request body, request number) -> Action`.
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

pub struct MockServer {
    _private: (),
}

impl MockServer {
    pub async fn start(script: Script) -> std::io::Result<MockServer> {
        let _ = script;
        todo!("implement per module contract (replace `_private` with real state; add Drop)")
    }

    /// `http://127.0.0.1:{port}/v1`
    pub fn base_url(&self) -> String {
        todo!("implement per module contract")
    }

    pub fn port(&self) -> u16 {
        todo!("implement per module contract")
    }

    pub fn set_model(&self, id: &str, window: Option<u64>) {
        let _ = (id, window);
        todo!("implement per module contract")
    }

    /// Bodies of every chat request received so far, in order.
    pub fn requests(&self) -> Vec<Value> {
        todo!("implement per module contract")
    }

    /// The `Authorization` header of every chat request received so far (`None` when absent).
    pub fn auth_headers(&self) -> Vec<Option<String>> {
        todo!("implement per module contract")
    }

    pub async fn shutdown(&self) {
        todo!("implement per module contract")
    }

    /// Bind the same port again after `shutdown`. The script and recordings carry on.
    pub async fn restart(&self) -> std::io::Result<()> {
        todo!("implement per module contract")
    }
}
