//! SSE framing and accumulation of streamed deltas into one [`Completion`].
//!
//! CONTRACT (bodies are placeholders for the implementer; signatures and types are fixed).
//!
//! ## `SseParser`
//! Fed arbitrary byte chunks; returns the `data:` payloads completed by each chunk. Events are
//! separated by a blank line (`\n\n` or `\r\n\r\n`); a chunk boundary can fall anywhere, including
//! inside a multi-byte character or between `\r` and `\n`. Lines starting with `:` are comments.
//! Several `data:` lines in one event are joined with `\n`. One optional space after `data:` is
//! removed. Fields other than `data` are ignored.
//!
//! ## `Assembler`
//! `push(payload)` takes one `data:` payload:
//! - `[DONE]` → marks the stream done;
//! - otherwise JSON. An object with an `error` member → `Err(AssembleError::Server(message))`.
//!   Unparseable JSON → `Err(AssembleError::Malformed(..))`.
//! - `choices[0].delta.content` (string) → appended to `text`, emits `StreamEvent::Text`;
//! - `choices[0].delta.reasoning` or `.reasoning_content` (string; whichever is present, and if both
//!   are present and equal only one is taken) → appended to `reasoning`, emits `Reasoning`;
//! - `choices[0].delta.tool_calls[]`: each element has `index` (default: position in the array);
//!   the first element seen for an index creates the call (`id`, `function.name`); every
//!   `function.arguments` string is appended. `function.name` arriving in several pieces is
//!   concatenated. Emits `ToolCallStart` once per index (when the name is first known) and
//!   `ToolCallArgs` for each non-empty arguments piece;
//! - `choices[0].finish_reason` (non-null) → recorded: `stop`→Stop, `tool_calls`/`function_call`→
//!   ToolCalls, `length`→Length, anything else→Stop;
//! - `usage` (object, on any chunk, the last one wins): `prompt_tokens`, `completion_tokens`,
//!   `prompt_tokens_details.cached_tokens`, `completion_tokens_details.reasoning_tokens`; missing
//!   members are 0.
//! - Empty strings emit nothing. Chunks with an empty `choices` array are fine (usage-only chunk).
//!
//! `finish()` returns the [`Completion`], or `Err(AssembleError::Incomplete)` when no
//! `finish_reason` was seen (the stream ended early — the caller retries). Rules for the result:
//! - tool calls are ordered by index. A call with no name is discarded.
//! - `call_id`: the server's id when present and unique within the response, otherwise
//!   `call-{12 random lowercase base32 characters}`.
//! - `arguments`: the concatenated string, except that an empty or whitespace-only string becomes
//!   `{}` when the finish reason is not `Length`.
//! - `complete`: true exactly when `arguments` parses as a JSON object.
//! - finish reason: if at least one tool call exists and the recorded reason is `Stop`, the result
//!   is `ToolCalls`. If the reason is `ToolCalls` and no call exists, the result is `Stop`.
//! - `text` and `reasoning` are returned exactly as received (no trimming).
//!
//! Tests required: parser with every split position of a sample stream (feed it in 1-byte chunks and
//! in random-sized chunks, same payloads out); CRLF; comments; multi-line data. Assembler: the exact
//! chunk shapes in `fixtures()` below (taken from a real vLLM stream); reasoning under both names;
//! two parallel tool calls with interleaved argument pieces; missing ids; duplicate ids; empty
//! arguments; arguments cut by `length` (complete == false); usage-only final chunk; error object;
//! early end.

use loom_core::event::{FinishReason, Timing, ToolCallRequest, Usage};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamEvent {
    /// An attempt is starting. Everything emitted for an earlier attempt of this request is void.
    AttemptStart { attempt: u32 },
    Text(String),
    Reasoning(String),
    ToolCallStart { index: u32, name: String },
    ToolCallArgs { index: u32, delta: String },
    /// The attempt failed and another will follow after `after_ms`.
    Retrying { attempt: u32, after_ms: u64, reason: String },
}

#[derive(Clone, Debug, PartialEq)]
pub struct Completion {
    pub text: String,
    pub reasoning: String,
    pub tool_calls: Vec<ToolCallRequest>,
    pub finish: FinishReason,
    pub usage: Usage,
    /// Filled in by the client (`queue_ms` by whoever held the limiter permit).
    pub timing: Timing,
    /// 1 when the first attempt succeeded.
    pub attempts: u32,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AssembleError {
    #[error("the server reported an error in the stream: {0}")]
    Server(String),
    #[error("unreadable stream chunk: {0}")]
    Malformed(String),
    #[error("the stream ended before the response was finished")]
    Incomplete,
}

#[derive(Debug, Default)]
pub struct SseParser {
    buf: Vec<u8>,
}

impl SseParser {
    pub fn new() -> SseParser {
        SseParser::default()
    }

    /// Feed bytes; get the data payloads of the events they complete.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<String> {
        let _ = (&mut self.buf, chunk);
        todo!("implement per module contract")
    }
}

#[derive(Debug, Default)]
pub struct Assembler {
    _private: (),
}

impl Assembler {
    pub fn new() -> Assembler {
        Assembler::default()
    }

    /// Apply one data payload; returns the events it produced, in order.
    pub fn push(&mut self, payload: &str) -> Result<Vec<StreamEvent>, AssembleError> {
        let _ = payload;
        todo!("implement per module contract (replace `_private` with real state)")
    }

    /// True once `[DONE]` or a `finish_reason` has been seen.
    pub fn is_done(&self) -> bool {
        todo!("implement per module contract")
    }

    pub fn finish(self) -> Result<Completion, AssembleError> {
        todo!("implement per module contract")
    }
}

/// Chunk payloads as produced by vLLM for a reasoning + tool-call response (shapes are real; ids are
/// shortened). Use these in tests.
#[cfg(test)]
pub(crate) fn fixtures() -> Vec<&'static str> {
    vec![
        r#"{"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"role":"assistant","content":""},"logprobs":null,"finish_reason":null}]}"#,
        r#"{"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"reasoning":"We"},"logprobs":null,"finish_reason":null,"token_ids":null}]}"#,
        r#"{"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"reasoning":" need a note."},"logprobs":null,"finish_reason":null,"token_ids":null}]}"#,
        r#"{"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"id":"chatcmpl-tool-83","type":"function","index":0,"function":{"name":"note"}}]},"logprobs":null,"finish_reason":null,"token_ids":null}]}"#,
        r#"{"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"text\": \""}}]},"logprobs":null,"finish_reason":null,"token_ids":null}]}"#,
        r#"{"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"hello\"}"}}]},"logprobs":null,"finish_reason":null,"token_ids":null}]}"#,
        r#"{"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{},"logprobs":null,"finish_reason":"tool_calls","stop_reason":null,"token_ids":null}]}"#,
        r#"{"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"m","choices":[],"usage":{"prompt_tokens":306,"total_tokens":385,"completion_tokens":79,"prompt_tokens_details":{"cached_tokens":0,"created_cache_tokens":256},"completion_tokens_details":{"reasoning_tokens":41}}}"#,
        "[DONE]",
    ]
}
