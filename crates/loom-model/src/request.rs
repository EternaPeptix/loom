//! A chat request and the body sent for it.
//!
//! CONTRACT (bodies are placeholders for the implementer; signatures and types are fixed).
//!
//! `body(model, profile_extra)` builds the JSON object that is POSTed. The server caches by the bytes
//! of the rendered prompt, and some chat templates render request fields into the prompt head, so the
//! body must be the same for the same inputs, key for key:
//!
//! 1. `"model"`
//! 2. `"messages"`: each `Message::to_openai()`, in order
//! 3. `"tools"`: each `ToolSpec::to_openai()`, in the order given — omitted when `tools` is empty
//! 4. `"tool_choice"`: omitted for `Auto`; `"required"`, `"none"`, or
//!    `{"type":"function","function":{"name":…}}` — omitted when `tools` is empty
//! 5. `"stream": true`, `"stream_options": {"include_usage": true}`
//! 6. `"max_tokens"` when set
//! 7. `"seed"` when set
//! 8. every key of `profile_extra`, then every key of `self.extra`, in their own order. A later
//!    value replaces an earlier one in place. Keys named in [`RESERVED`] are never taken from either
//!    map (they are skipped).
//!
//! Tests required: key order; omission rules; reserved keys skipped; `self.extra` overriding
//! `profile_extra`; two calls give identical strings.

use loom_core::event::ToolSpec;
use loom_core::Message;
use serde_json::{Map, Value};

/// Body keys that only this module sets.
pub const RESERVED: &[&str] = &["model", "messages", "tools", "stream", "stream_options"];

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum ToolChoice {
    #[default]
    Auto,
    /// The response must contain at least one tool call.
    Required,
    None,
    /// The response must call this tool.
    Named(String),
}

#[derive(Clone, Debug, Default)]
pub struct ChatRequest {
    pub messages: Vec<Message>,
    pub tools: Vec<ToolSpec>,
    pub tool_choice: ToolChoice,
    pub max_tokens: Option<u64>,
    pub seed: Option<u64>,
    /// Request-specific body fields (for example a guided-decoding schema).
    pub extra: Map<String, Value>,
}

impl ChatRequest {
    pub fn body(&self, model: &str, profile_extra: &Map<String, Value>) -> Value {
        let _ = (model, profile_extra);
        todo!("implement per module contract")
    }
}
