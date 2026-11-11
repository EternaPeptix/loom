//! A check against a real server, for a person to run:
//!
//! ```text
//! cargo run -p loom-model --example live -- http://host:8000/v1 model-id [reasoning_effort]
//! ```
//!
//! It holds a short tool conversation the way a session does — a stable prefix that only grows,
//! plus a state block that is different in every request — and prints, for each request, what came
//! back and how much of the request the server served from its prefix cache. Then it sends three
//! requests at once that share the whole prefix, the way forked agents and votes do. Nothing is
//! asserted; read the numbers.

use loom_core::config::ModelProfile;
use loom_core::event::{ToolClass, ToolSpec};
use loom_core::message::{Message, ToolCallMsg};
use loom_core::weave::hud_message;
use loom_model::assemble::Completion;
use loom_model::client::ModelClient;
use loom_model::request::ChatRequest;
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

fn cut(s: &str, n: usize) -> String {
    let flat: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= n {
        flat
    } else {
        format!("{}…", flat.chars().take(n).collect::<String>())
    }
}

fn show(label: &str, c: &Completion) {
    let u = &c.usage;
    let share = if u.prompt_tokens == 0 { 0.0 } else { 100.0 * u.cached_tokens as f64 / u.prompt_tokens as f64 };
    println!("== {label}");
    println!(
        "   prompt {} tokens, {} from cache ({share:.1}%); completion {} ({} reasoning); first token {} ms, total {} ms; attempts {}",
        u.prompt_tokens, u.cached_tokens, u.completion_tokens, u.reasoning_tokens, c.timing.ttft_ms, c.timing.total_ms, c.attempts
    );
    println!("   finish: {:?}", c.finish);
    if !c.reasoning.is_empty() {
        println!("   reasoning ({} chars): {}", c.reasoning.chars().count(), cut(&c.reasoning, 160));
    }
    if !c.text.is_empty() {
        println!("   text: {}", cut(&c.text, 200));
    }
    for t in &c.tool_calls {
        println!("   call {} {}({}){}", t.call_id, t.name, t.arguments, if t.complete { "" } else { "  [arguments incomplete]" });
    }
}

/// The reply as it is replayed in the next request.
fn replay(c: &Completion) -> Message {
    let mut m = Message::assistant(c.text.clone());
    if !c.reasoning.is_empty() {
        m.reasoning = Some(c.reasoning.clone());
    }
    m.tool_calls = c
        .tool_calls
        .iter()
        .map(|t| ToolCallMsg { id: t.call_id.to_string(), name: t.name.clone(), arguments: t.arguments.clone() })
        .collect();
    m
}

fn tool(name: &str, description: &str, param: &str, what: &str) -> ToolSpec {
    ToolSpec {
        name: name.to_string(),
        description: description.to_string(),
        parameters: json!({
            "type": "object",
            "properties": { param: { "type": "string", "description": what } },
            "required": [param],
            "additionalProperties": false
        }),
        class: ToolClass::State,
    }
}

fn request(stable: &[Message], tools: &[ToolSpec], state: &str) -> ChatRequest {
    let mut messages = stable.to_vec();
    messages.push(hud_message(state));
    ChatRequest { messages, tools: tools.to_vec(), ..ChatRequest::default() }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (Some(base_url), Some(model)) = (args.first(), args.get(1)) else {
        eprintln!("usage: live <base_url> <model> [reasoning_effort]");
        std::process::exit(2);
    };
    let mut profile = ModelProfile { base_url: base_url.clone(), model: model.clone(), retry_window_s: 60, ..ModelProfile::default() };
    if let Some(effort) = args.get(2) {
        profile.extra_body.insert("reasoning_effort".into(), Value::String(effort.clone()));
    }
    let client = ModelClient::new("live", profile)?;
    let found = client.discover().await?;
    println!(
        "server: model {}, window {:?} ({:?}), server-reported window {:?}",
        found.served_model, found.context_window, found.source, found.server_window
    );

    // A system prompt long enough for the cache to matter.
    let mut system = String::from(
        "You are a careful assistant working through tools.\n\
         To learn the value of a key, call `lookup` with the key. When you have a value, record it by calling `note` with the value. \
         After the note is recorded, reply with the single word: done.\n\nReference material (not needed for the task):\n",
    );
    for i in 0..1500 {
        system.push_str(&format!("Entry {i}: the quick brown fox number {i} jumps over lazy dog number {}.\n", i * 7 % 311));
    }
    let tools = vec![
        tool("lookup", "Look up the value of a key.", "key", "The key to look up."),
        tool("note", "Record a value.", "text", "The value to record."),
    ];
    let cancel = CancellationToken::new();
    let mut stable = vec![Message::system(system), Message::user("What is the value of key K-7? Record it.")];

    let c1 = client.complete(&request(&stable, &tools, "Now: 2026-01-01 10:00 UTC\nStep: 1"), None, &cancel).await?;
    show("request 1 (nothing cached yet, unless this was run before)", &c1);
    stable.push(replay(&c1));
    for t in &c1.tool_calls {
        stable.push(Message::tool(t.call_id.to_string(), "[lookup · ok]\nK-7 = marigold"));
    }

    let c2 = client.complete(&request(&stable, &tools, "Now: 2026-01-01 10:01 UTC\nStep: 2"), None, &cancel).await?;
    show("request 2 (request 1's stable part should come from cache; its state block is gone)", &c2);
    stable.push(replay(&c2));
    for t in &c2.tool_calls {
        stable.push(Message::tool(t.call_id.to_string(), "[note · ok]\nrecorded"));
    }

    let c3 = client.complete(&request(&stable, &tools, "Now: 2026-01-01 10:02 UTC\nStep: 3"), None, &cancel).await?;
    show("request 3", &c3);
    stable.push(replay(&c3));

    // Three requests at once over the same prefix, each with its own last message.
    stable.push(Message::user("One more question: which entry number in the reference material mentions dog number 0 first?"));
    let reqs: Vec<ChatRequest> =
        (1..=3).map(|i| request(&stable, &tools, &format!("Now: 2026-01-01 10:03 UTC\nStep: 4\nVoter: {i}"))).collect();
    let (a, b, c) = tokio::join!(
        client.complete(&reqs[0], None, &cancel),
        client.complete(&reqs[1], None, &cancel),
        client.complete(&reqs[2], None, &cancel)
    );
    show("parallel request A", &a?);
    show("parallel request B", &b?);
    show("parallel request C", &c?);
    Ok(())
}
