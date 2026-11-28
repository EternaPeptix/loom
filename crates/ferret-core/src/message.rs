//! Chat messages as sent to the model (OpenAI chat-completions shape).
//!
//! CONTRACT.
//!
//! `Message::images` are the images a user message or a tool message carries (`ImageRef`s of the blob
//! store; empty for every other message, and skipped when empty). `to_openai()` cannot read blobs: it is the
//! form for a model that does not take images, so a message with images renders its text followed by
//! one `image::not_shown` line per image (after a blank line for a user message, a line break for a tool
//! message), and a message without images renders exactly as before. `stable_hash` and the prefix guard
//! use this form.
//!
//! `render_request(messages, resolve)` is the form that goes in the request body. With `resolve` `None` it is
//! `to_openai` of each message. With `Some(resolve)` (a model that takes images; `resolve` turns an image into a
//! `data:` URL, or `None` when its blob cannot be read):
//! - a user message with images has `content` = `[{type:"text",text}, {type:"image_url",image_url:{url}}...]`
//!   (the text part is left out when the text is empty; an unreadable image is a text part,
//!   `image::unreadable`);
//! - a tool message stays a text message, whatever its images; the images of the run of tool messages that
//!   follows an assistant message are sent in one `user` message placed right after the run, before whatever
//!   comes next: a text part `Images from the tool results above:` and, per image in order, a text part
//!   `[{tool} {call_id}: {label}]` (the tool's name is that of the call in the preceding assistant message,
//!   `tool` when there is none) followed by the image part. The calls' pairing with their results is
//!   untouched.
//!
//! Tests required: each rendering above, vision off with images on a user and a tool message, messages
//! without images unchanged byte for byte, a run of several tool messages giving one image message, an
//! image message before a following user message.

use crate::event::Seq;
use crate::image::{self, ImageRef};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::System => "system",
            Role::User => "user",
            Role::Assistant => "assistant",
            Role::Tool => "tool",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCallMsg {
    pub id: String,
    pub name: String,
    /// A JSON object, as text.
    pub arguments: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    pub role: Role,
    pub content: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ToolCallMsg>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    /// Replayed reasoning, when the session's replay policy includes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<String>,
    /// Log records this message was rendered from. Not sent to the model.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub origin: Vec<Seq>,
    /// Images of a user message or a tool message (see the module contract).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub images: Vec<ImageRef>,
}

impl Message {
    pub fn new(role: Role, content: impl Into<String>) -> Self {
        Self {
            role,
            content: content.into(),
            tool_calls: Vec::new(),
            tool_call_id: None,
            reasoning: None,
            origin: Vec::new(),
            images: Vec::new(),
        }
    }

    pub fn system(content: impl Into<String>) -> Self {
        Self::new(Role::System, content)
    }

    pub fn user(content: impl Into<String>) -> Self {
        Self::new(Role::User, content)
    }

    pub fn assistant(content: impl Into<String>) -> Self {
        Self::new(Role::Assistant, content)
    }

    pub fn tool(call_id: impl Into<String>, content: impl Into<String>) -> Self {
        let mut m = Self::new(Role::Tool, content);
        m.tool_call_id = Some(call_id.into());
        m
    }

    /// The request-body form. Key order is fixed, so equal messages give equal bytes.
    pub fn to_openai(&self) -> Value {
        let mut v = json!({ "role": self.role.as_str(), "content": self.text_without_images() });
        if let Some(obj) = v.as_object_mut() {
            if let Some(reasoning) = &self.reasoning {
                obj.insert("reasoning".into(), json!(reasoning));
            }
            if !self.tool_calls.is_empty() {
                let calls: Vec<Value> = self
                    .tool_calls
                    .iter()
                    .map(|c| json!({ "id": c.id, "type": "function", "function": { "name": c.name, "arguments": c.arguments } }))
                    .collect();
                obj.insert("tool_calls".into(), Value::Array(calls));
            }
            if let Some(id) = &self.tool_call_id {
                obj.insert("tool_call_id".into(), json!(id));
            }
        }
        v
    }

    /// The content for a model that does not take images: the text, then a line per image saying it is not shown.
    fn text_without_images(&self) -> String {
        if self.images.is_empty() || !matches!(self.role, Role::User | Role::Tool) {
            return self.content.clone();
        }
        let notes = self.images.iter().map(image::not_shown).collect::<Vec<_>>().join("\n");
        let sep = match (self.content.is_empty(), self.role) {
            (true, _) => "",
            (false, Role::Tool) => "\n",
            (false, _) => "\n\n",
        };
        format!("{}{sep}{notes}", self.content)
    }

    /// Characters that count toward the size estimate.
    pub fn chars(&self) -> usize {
        self.content.len()
            + self.reasoning.as_ref().map_or(0, |r| r.len())
            + self.tool_calls.iter().map(|c| c.name.len() + c.arguments.len() + 24).sum::<usize>()
            + 8
    }
}

fn image_part(image: &ImageRef, resolve: &dyn Fn(&ImageRef) -> Option<String>) -> Value {
    match resolve(image) {
        Some(url) => json!({ "type": "image_url", "image_url": { "url": url } }),
        None => json!({ "type": "text", "text": image::unreadable(image) }),
    }
}

/// Turns an image into the `data:` URL the request carries, or `None` when its blob cannot be read.
pub type ImageUrl<'a> = &'a dyn Fn(&ImageRef) -> Option<String>;

/// The `messages` of a request body (see the module contract). `resolve` is given only for a model that takes
/// images.
pub fn render_request(messages: &[Message], resolve: Option<ImageUrl<'_>>) -> Vec<Value> {
    let Some(resolve) = resolve else {
        return messages.iter().map(Message::to_openai).collect();
    };
    let mut out: Vec<Value> = Vec::with_capacity(messages.len());
    let mut names: HashMap<&str, &str> = HashMap::new();
    // The images of the tool messages in the run being rendered: (tool, call id, image).
    let mut pending: Vec<(&str, &str, &ImageRef)> = Vec::new();
    let flush = |out: &mut Vec<Value>, pending: &mut Vec<(&str, &str, &ImageRef)>| {
        if pending.is_empty() {
            return;
        }
        let mut parts = vec![json!({ "type": "text", "text": "Images from the tool results above:" })];
        for (tool, call_id, img) in pending.drain(..) {
            parts.push(json!({ "type": "text", "text": format!("[{tool} {call_id}: {}]", img.label()) }));
            parts.push(image_part(img, resolve));
        }
        out.push(json!({ "role": "user", "content": parts }));
    };
    for m in messages {
        if m.role != Role::Tool {
            flush(&mut out, &mut pending);
        }
        match m.role {
            Role::Assistant => {
                for c in &m.tool_calls {
                    names.insert(c.id.as_str(), c.name.as_str());
                }
                out.push(m.to_openai());
            }
            Role::Tool => {
                let id = m.tool_call_id.as_deref().unwrap_or("");
                let tool = names.get(id).copied().unwrap_or("tool");
                pending.extend(m.images.iter().map(|img| (tool, id, img)));
                let mut text = m.clone();
                text.images.clear();
                out.push(text.to_openai());
            }
            Role::User if !m.images.is_empty() => {
                let mut parts: Vec<Value> = Vec::new();
                if !m.content.is_empty() {
                    parts.push(json!({ "type": "text", "text": m.content }));
                }
                parts.extend(m.images.iter().map(|img| image_part(img, resolve)));
                out.push(json!({ "role": "user", "content": parts }));
            }
            _ => out.push(m.to_openai()),
        }
    }
    flush(&mut out, &mut pending);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openai_shape() {
        let mut m = Message::assistant("thinking aloud");
        m.tool_calls.push(ToolCallMsg {
            id: "c1".into(),
            name: "bash".into(),
            arguments: "{\"command\":\"ls\"}".into(),
        });
        let v = m.to_openai();
        assert_eq!(v["role"], "assistant");
        assert_eq!(v["tool_calls"][0]["function"]["name"], "bash");
        assert_eq!(v["tool_calls"][0]["type"], "function");
        let t = Message::tool("c1", "out").to_openai();
        assert_eq!(t["tool_call_id"], "c1");
        assert!(t.get("tool_calls").is_none());
    }

    #[test]
    fn serialization_is_stable() {
        let m = Message::user("hello");
        assert_eq!(m.to_openai().to_string(), Message::user("hello").to_openai().to_string());
        assert_eq!(m.to_openai().to_string(), "{\"role\":\"user\",\"content\":\"hello\"}");
    }

    fn img(name: &str) -> ImageRef {
        ImageRef {
            blob: "ab".repeat(32),
            mime: "image/png".into(),
            bytes: 10,
            width: 4,
            height: 3,
            name: Some(name.into()),
        }
    }

    fn url(i: &ImageRef) -> Option<String> {
        Some(format!("data:{};base64,AAAA", i.mime))
    }

    #[test]
    fn messages_without_images_render_as_they_always_did() {
        let msgs = vec![Message::system("s"), Message::user("u"), Message::tool("c1", "out")];
        let plain: Vec<Value> = msgs.iter().map(Message::to_openai).collect();
        assert_eq!(render_request(&msgs, None), plain);
        assert_eq!(render_request(&msgs, Some(&url)), plain);
    }

    #[test]
    fn a_user_message_with_an_image_is_content_parts() {
        let mut m = Message::user("look");
        m.images.push(img("a.png"));
        let v = render_request(&[m], Some(&url));
        assert_eq!(
            v[0],
            json!({"role":"user","content":[
                {"type":"text","text":"look"},
                {"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA"}}]})
        );
    }

    #[test]
    fn without_vision_the_text_says_the_image_is_not_shown() {
        let mut m = Message::user("look");
        m.images.push(img("a.png"));
        assert_eq!(
            m.to_openai()["content"],
            "look\n\n[image not shown: this model does not take images \u{2014} a.png 4x3 image/png]"
        );
        let mut t = Message::tool("c1", "[read]");
        t.images.push(img("/w/a.png"));
        assert_eq!(
            t.to_openai()["content"],
            "[read]\n[image not shown: this model does not take images \u{2014} /w/a.png 4x3 image/png]"
        );
        assert_eq!(render_request(&[m.clone(), t.clone()], None), vec![m.to_openai(), t.to_openai()]);
    }

    #[test]
    fn tool_images_follow_the_run_in_one_user_message() {
        let mut a = Message::assistant("");
        a.tool_calls = vec![
            ToolCallMsg { id: "c1".into(), name: "read".into(), arguments: "{}".into() },
            ToolCallMsg { id: "c2".into(), name: "bash".into(), arguments: "{}".into() },
            ToolCallMsg { id: "c3".into(), name: "read".into(), arguments: "{}".into() },
        ];
        let mut r1 = Message::tool("c1", "one");
        r1.images.push(img("/w/1.png"));
        let r2 = Message::tool("c2", "two");
        let mut r3 = Message::tool("c3", "three");
        r3.images.push(img("/w/3.png"));
        let v = render_request(&[a, r1, r2, r3, Message::user("next")], Some(&url));
        assert_eq!(v.len(), 6);
        assert_eq!(v[1], json!({"role":"tool","content":"one","tool_call_id":"c1"}));
        assert_eq!(v[3]["tool_call_id"], "c3");
        assert_eq!(
            v[4],
            json!({"role":"user","content":[
                {"type":"text","text":"Images from the tool results above:"},
                {"type":"text","text":"[read c1: /w/1.png]"},
                {"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA"}},
                {"type":"text","text":"[read c3: /w/3.png]"},
                {"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA"}}]})
        );
        assert_eq!(v[5], json!({"role":"user","content":"next"}));
    }

    #[test]
    fn an_unreadable_image_becomes_a_sentence() {
        let mut m = Message::user("");
        m.images.push(img("a.png"));
        let v = render_request(&[m], Some(&|_: &ImageRef| None));
        assert_eq!(v[0]["content"][0]["text"], "[image not shown: its stored copy could not be read \u{2014} a.png]");
    }
}
