//! Chat messages as sent to the model (OpenAI chat-completions shape).

use crate::event::Seq;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

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
        let mut v = json!({ "role": self.role.as_str(), "content": self.content });
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

    /// Characters that count toward the size estimate.
    pub fn chars(&self) -> usize {
        self.content.len()
            + self.reasoning.as_ref().map_or(0, |r| r.len())
            + self.tool_calls.iter().map(|c| c.name.len() + c.arguments.len() + 24).sum::<usize>()
            + 8
    }
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
}
