//! A chat request and the body sent for it.
//!
//! CONTRACT.
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
use serde_json::{json, Map, Value};

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
        let mut body = Map::new();
        body.insert("model".into(), Value::String(model.to_string()));
        body.insert("messages".into(), Value::Array(self.messages.iter().map(Message::to_openai).collect()));
        if !self.tools.is_empty() {
            body.insert("tools".into(), Value::Array(self.tools.iter().map(ToolSpec::to_openai).collect()));
            match &self.tool_choice {
                ToolChoice::Auto => {}
                ToolChoice::Required => {
                    body.insert("tool_choice".into(), Value::String("required".into()));
                }
                ToolChoice::None => {
                    body.insert("tool_choice".into(), Value::String("none".into()));
                }
                ToolChoice::Named(name) => {
                    body.insert("tool_choice".into(), json!({ "type": "function", "function": { "name": name } }));
                }
            }
        }
        body.insert("stream".into(), Value::Bool(true));
        body.insert("stream_options".into(), json!({ "include_usage": true }));
        if let Some(n) = self.max_tokens {
            body.insert("max_tokens".into(), json!(n));
        }
        if let Some(n) = self.seed {
            body.insert("seed".into(), json!(n));
        }
        // `insert` on an existing key keeps its position (serde_json has `preserve_order`), so a later
        // map replaces an earlier value in place.
        for extra in [profile_extra, &self.extra] {
            for (k, v) in extra {
                if !RESERVED.contains(&k.as_str()) {
                    body.insert(k.clone(), v.clone());
                }
            }
        }
        Value::Object(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loom_core::event::ToolClass;

    fn spec(name: &str) -> ToolSpec {
        ToolSpec {
            name: name.into(),
            description: format!("the {name} tool"),
            parameters: json!({"type": "object", "properties": {}}),
            class: ToolClass::Nav,
        }
    }

    fn keys(v: &Value) -> Vec<String> {
        v.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default()
    }

    fn map(v: Value) -> Map<String, Value> {
        v.as_object().cloned().unwrap_or_default()
    }

    fn full() -> ChatRequest {
        ChatRequest {
            messages: vec![Message::system("s"), Message::user("u")],
            tools: vec![spec("b"), spec("a")],
            tool_choice: ToolChoice::Required,
            max_tokens: Some(100),
            seed: Some(7),
            extra: map(json!({"top_p": 0.5})),
        }
    }

    #[test]
    fn key_order() {
        let body = full().body("m", &map(json!({"temperature": 0.1})));
        assert_eq!(
            keys(&body),
            ["model", "messages", "tools", "tool_choice", "stream", "stream_options", "max_tokens", "seed", "temperature", "top_p"]
        );
        assert_eq!(body["model"], "m");
        assert_eq!(body["messages"][1]["content"], "u");
        assert_eq!(body["tools"][0]["function"]["name"], "b");
        assert_eq!(body["tools"][1]["function"]["name"], "a");
        assert_eq!(body["stream"], true);
        assert_eq!(body["stream_options"], json!({"include_usage": true}));
        assert_eq!(body["max_tokens"], 100);
        assert_eq!(body["seed"], 7);
    }

    #[test]
    fn omission_rules() {
        let body = ChatRequest { messages: vec![Message::user("u")], ..Default::default() }.body("m", &Map::new());
        assert_eq!(keys(&body), ["model", "messages", "stream", "stream_options"]);

        // tool_choice without tools is dropped.
        let r = ChatRequest { tool_choice: ToolChoice::Required, ..Default::default() };
        assert!(r.body("m", &Map::new()).get("tool_choice").is_none());

        // Auto is omitted even with tools.
        let r = ChatRequest { tools: vec![spec("a")], ..Default::default() };
        let body = r.body("m", &Map::new());
        assert_eq!(keys(&body), ["model", "messages", "tools", "stream", "stream_options"]);
    }

    #[test]
    fn tool_choice_forms() {
        let mk = |tc| ChatRequest { tools: vec![spec("a")], tool_choice: tc, ..Default::default() }.body("m", &Map::new());
        assert_eq!(mk(ToolChoice::Required)["tool_choice"], "required");
        assert_eq!(mk(ToolChoice::None)["tool_choice"], "none");
        assert_eq!(
            mk(ToolChoice::Named("a".into()))["tool_choice"],
            json!({"type": "function", "function": {"name": "a"}})
        );
    }

    #[test]
    fn reserved_keys_skipped() {
        let profile = map(json!({"model": "x", "messages": [], "tools": [1], "stream": false, "stream_options": {}, "ok": 1}));
        let mut r = full();
        r.extra = map(json!({"model": "y", "stream": false, "ok2": 2}));
        let body = r.body("m", &profile);
        assert_eq!(body["model"], "m");
        assert_eq!(body["messages"].as_array().map(Vec::len), Some(2));
        assert_eq!(body["tools"].as_array().map(Vec::len), Some(2));
        assert_eq!(body["stream"], true);
        assert_eq!(body["stream_options"], json!({"include_usage": true}));
        assert_eq!(body["ok"], 1);
        assert_eq!(body["ok2"], 2);
    }

    #[test]
    fn reserved_keys_skipped_without_tools() {
        let profile = map(json!({"tools": [1]}));
        let body = ChatRequest::default().body("m", &profile);
        assert!(body.get("tools").is_none());
    }

    #[test]
    fn extra_overrides_profile_extra_in_place() {
        let profile = map(json!({"a": 1, "b": 2, "seed": 1}));
        let mut r = full();
        r.extra = map(json!({"c": 3, "a": 10}));
        let body = r.body("m", &profile);
        assert_eq!(body["a"], 10);
        let k = keys(&body);
        let tail: Vec<&str> = k.iter().skip(8).map(String::as_str).collect();
        // `seed` was set earlier and is replaced where it already stood; `a` keeps its profile slot.
        assert_eq!(body["seed"], 1);
        assert_eq!(tail, ["a", "b", "c"]);
        assert_eq!(k[7], "seed");
    }

    #[test]
    fn deterministic() {
        let profile = map(json!({"zz_k": 1, "aa_k": 2}));
        let a = full().body("m", &profile).to_string();
        let b = full().body("m", &profile).to_string();
        assert_eq!(a, b);
        assert!(a.find("zz_k") < a.find("aa_k"));
    }
}
