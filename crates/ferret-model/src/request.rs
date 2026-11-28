//! A chat request and the body sent for it.
//!
//! CONTRACT.
//!
//! `body(model, profile_extra)` builds the JSON object that is POSTed. The server caches by the bytes
//! of the rendered prompt, and some chat templates render request fields into the prompt head, so the
//! body must be the same for the same inputs, key for key:
//!
//! 1. `"model"`
//! 2. `"messages"`: `ferret_core::message::render_request(messages, resolver)`: each `Message::to_openai()` in
//!    order when `images` is `None` (a model that does not take images; a message's images are then a
//!    sentence in its text), and with `images` set the images of user messages and tool results as
//!    `image_url` content parts (see `message.rs`). The resolver reads each image's blob when the body is
//!    built and gives `data:{mime};base64,...`; an unreadable blob becomes a sentence.
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

use base64::Engine;
use ferret_core::blob::BlobStore;
use ferret_core::event::ToolSpec;
use ferret_core::ids::BlobId;
use ferret_core::message::render_request;
use ferret_core::{ImageRef, Message};
use serde_json::{json, Map, Value};
use std::fmt;
use std::sync::Arc;

type ResolveFn = dyn Fn(&ImageRef) -> Option<String> + Send + Sync;

/// Turns an image a record names into the `data:` URL of a request. Present on a request only for a model that
/// takes images.
#[derive(Clone, Default)]
pub struct ImageResolver(Option<Arc<ResolveFn>>);

impl ImageResolver {
    /// A resolver that reads the blobs of `store`.
    pub fn from_blobs(store: BlobStore) -> ImageResolver {
        ImageResolver(Some(Arc::new(move |image: &ImageRef| {
            let bytes = store.read_all(&BlobId::from(image.blob.clone())).ok()?;
            let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
            Some(format!("data:{};base64,{b64}", image.mime))
        })))
    }

    /// The resolver for a model: reads `store` when the model takes images, and is off otherwise.
    pub fn for_model(vision: bool, store: &BlobStore) -> ImageResolver {
        if vision {
            ImageResolver::from_blobs(store.clone())
        } else {
            ImageResolver::default()
        }
    }

    /// A resolver from a function (tests).
    pub fn from_fn(f: impl Fn(&ImageRef) -> Option<String> + Send + Sync + 'static) -> ImageResolver {
        ImageResolver(Some(Arc::new(f)))
    }
}

impl fmt::Debug for ImageResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.0.is_some() { "ImageResolver(on)" } else { "ImageResolver(off)" })
    }
}

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
    /// Set for a model that takes images (`vision`); off, images are sentences in the text.
    pub images: ImageResolver,
    /// Take tool calls the model wrote into the reply's text, in the profile's `text_tool_calls`
    /// format and only when they end the reply. Set for a step of a role that ends by calling a tool;
    /// off (the default) for everything else (a free-form role, a digest, a vote, a compaction),
    /// whose text is never run.
    pub text_calls: bool,
}

impl ChatRequest {
    pub fn body(&self, model: &str, profile_extra: &Map<String, Value>) -> Value {
        let mut body = Map::new();
        body.insert("model".into(), Value::String(model.to_string()));
        let resolve = self.images.0.as_deref().map(|f| f as &dyn Fn(&ImageRef) -> Option<String>);
        body.insert("messages".into(), Value::Array(render_request(&self.messages, resolve)));
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
    use ferret_core::event::ToolClass;

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
            images: ImageResolver::default(),
            text_calls: false,
        }
    }

    fn png_ref(store: &BlobStore, data: &[u8]) -> ImageRef {
        let stored = store.put_bytes(data).unwrap();
        ImageRef {
            blob: stored.id.as_str().to_string(),
            mime: "image/png".into(),
            bytes: data.len() as u64,
            width: 4,
            height: 3,
            name: Some("a.png".into()),
        }
    }

    fn image_request(vision: bool) -> Value {
        let dir = tempfile::tempdir().unwrap();
        let store = BlobStore::open(dir.path()).unwrap();
        let image = png_ref(&store, &[1, 2, 3]);
        let mut user = Message::user("look");
        user.images.push(image.clone());
        let mut asst = Message::assistant("");
        asst.tool_calls =
            vec![ferret_core::message::ToolCallMsg { id: "c1".into(), name: "read".into(), arguments: "{}".into() }];
        let mut tool = Message::tool("c1", "[read]");
        tool.images.push(ImageRef { name: Some("/w/a.png".into()), ..image });
        let req = ChatRequest {
            messages: vec![user, asst, tool],
            images: ImageResolver::for_model(vision, &store),
            ..ChatRequest::default()
        };
        req.body("m", &Map::new())["messages"].clone()
    }

    #[test]
    fn a_vision_model_gets_the_blob_as_a_data_url_in_user_and_after_tool_messages() {
        let m = image_request(true);
        let url = "data:image/png;base64,AQID";
        assert_eq!(
            m[0],
            json!({"role":"user","content":[{"type":"text","text":"look"},{"type":"image_url","image_url":{"url":url}}]})
        );
        assert_eq!(m[2], json!({"role":"tool","content":"[read]","tool_call_id":"c1"}));
        assert_eq!(
            m[3],
            json!({"role":"user","content":[
                {"type":"text","text":"Images from the tool results above:"},
                {"type":"text","text":"[read c1: /w/a.png]"},
                {"type":"image_url","image_url":{"url":url}}]})
        );
        assert_eq!(m.as_array().map(Vec::len), Some(4));
    }

    #[test]
    fn a_model_without_vision_gets_sentences_and_no_extra_messages() {
        let m = image_request(false);
        assert_eq!(m.as_array().map(Vec::len), Some(3));
        let note = "[image not shown: this model does not take images \u{2014} a.png 4x3 image/png]";
        assert_eq!(m[0]["content"], format!("look\n\n{note}"));
        assert_eq!(m[2]["content"], format!("[read]\n{}", note.replace("a.png", "/w/a.png")));
    }

    #[test]
    fn key_order() {
        let body = full().body("m", &map(json!({"temperature": 0.1})));
        assert_eq!(
            keys(&body),
            [
                "model",
                "messages",
                "tools",
                "tool_choice",
                "stream",
                "stream_options",
                "max_tokens",
                "seed",
                "temperature",
                "top_p"
            ]
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
        let mk =
            |tc| ChatRequest { tools: vec![spec("a")], tool_choice: tc, ..Default::default() }.body("m", &Map::new());
        assert_eq!(mk(ToolChoice::Required)["tool_choice"], "required");
        assert_eq!(mk(ToolChoice::None)["tool_choice"], "none");
        assert_eq!(
            mk(ToolChoice::Named("a".into()))["tool_choice"],
            json!({"type": "function", "function": {"name": "a"}})
        );
    }

    #[test]
    fn reserved_keys_skipped() {
        let profile =
            map(json!({"model": "x", "messages": [], "tools": [1], "stream": false, "stream_options": {}, "ok": 1}));
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
