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
use loom_core::CallId;
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};

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
    /// Bytes of the line being received (no complete line is ever kept here).
    buf: Vec<u8>,
    /// `data:` values of the event being received.
    data: Vec<String>,
}

impl SseParser {
    pub fn new() -> SseParser {
        SseParser::default()
    }

    /// Feed bytes; get the data payloads of the events they complete.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<String> {
        let mut out = Vec::new();
        self.buf.extend_from_slice(chunk);
        let mut start = 0usize;
        while let Some(rel) = self.buf.get(start..).and_then(|rest| rest.iter().position(|&b| b == b'\n')) {
            let end = start + rel;
            let mut line = self.buf.get(start..end).unwrap_or_default();
            if let Some(stripped) = line.strip_suffix(b"\r") {
                line = stripped;
            }
            // A complete line is whole characters, so decoding it cannot split one.
            let line = String::from_utf8_lossy(line).into_owned();
            start = end + 1;
            if line.is_empty() {
                if !self.data.is_empty() {
                    let payload = self.data.join("\n");
                    self.data.clear();
                    if !payload.is_empty() {
                        out.push(payload);
                    }
                }
            } else if let Some(value) = line.strip_prefix("data:") {
                self.data.push(value.strip_prefix(' ').unwrap_or(value).to_string());
            }
            // Comments (`:`) and every other field are ignored.
        }
        self.buf.drain(..start);
        out
    }
}

#[derive(Debug, Default)]
struct CallAcc {
    id: Option<String>,
    name: String,
    arguments: String,
    started: bool,
}

#[derive(Debug, Default)]
pub struct Assembler {
    text: String,
    reasoning: String,
    calls: BTreeMap<u32, CallAcc>,
    finish: Option<FinishReason>,
    usage: Usage,
    done: bool,
}

fn str_member<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

fn count(v: Option<&Value>) -> u64 {
    v.and_then(Value::as_u64).unwrap_or(0)
}

fn error_message(e: &Value) -> String {
    match e {
        Value::String(s) => s.clone(),
        Value::Object(_) => str_member(e, "message").map_or_else(|| e.to_string(), str::to_string),
        other => other.to_string(),
    }
}

fn random_call_id() -> String {
    use rand::Rng;
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut rng = rand::rng();
    let mut id = String::from("call-");
    for _ in 0..12 {
        let pick = ALPHABET.get(rng.random_range(0..ALPHABET.len())).copied().unwrap_or(b'a');
        id.push(char::from(pick));
    }
    id
}

impl Assembler {
    pub fn new() -> Assembler {
        Assembler::default()
    }

    /// Apply one data payload; returns the events it produced, in order.
    pub fn push(&mut self, payload: &str) -> Result<Vec<StreamEvent>, AssembleError> {
        if payload.trim() == "[DONE]" {
            self.done = true;
            return Ok(Vec::new());
        }
        let v: Value = serde_json::from_str(payload).map_err(|e| AssembleError::Malformed(e.to_string()))?;
        if !v.is_object() {
            return Err(AssembleError::Malformed("the chunk is not a JSON object".into()));
        }
        if let Some(e) = v.get("error") {
            return Err(AssembleError::Server(error_message(e)));
        }
        let mut events = Vec::new();
        if let Some(choice) = v.get("choices").and_then(|c| c.get(0)) {
            if let Some(delta) = choice.get("delta") {
                self.apply_delta(delta, &mut events);
            }
            if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
                self.finish = Some(match reason {
                    "tool_calls" | "function_call" => FinishReason::ToolCalls,
                    "length" => FinishReason::Length,
                    _ => FinishReason::Stop,
                });
            }
        }
        if let Some(u) = v.get("usage").filter(|u| u.is_object()) {
            self.usage = Usage {
                prompt_tokens: count(u.get("prompt_tokens")),
                cached_tokens: count(u.get("prompt_tokens_details").and_then(|d| d.get("cached_tokens"))),
                completion_tokens: count(u.get("completion_tokens")),
                reasoning_tokens: count(u.get("completion_tokens_details").and_then(|d| d.get("reasoning_tokens"))),
            };
        }
        Ok(events)
    }

    fn apply_delta(&mut self, delta: &Value, events: &mut Vec<StreamEvent>) {
        if let Some(s) = str_member(delta, "content").filter(|s| !s.is_empty()) {
            self.text.push_str(s);
            events.push(StreamEvent::Text(s.to_string()));
        }
        let a = str_member(delta, "reasoning");
        let b = str_member(delta, "reasoning_content");
        let pieces: &[Option<&str>] = if a.is_some() && a == b { &[a] } else { &[a, b] };
        for s in pieces.iter().flatten().filter(|s| !s.is_empty()) {
            self.reasoning.push_str(s);
            events.push(StreamEvent::Reasoning((*s).to_string()));
        }
        let Some(calls) = delta.get("tool_calls").and_then(Value::as_array) else { return };
        for (pos, tc) in calls.iter().enumerate() {
            let index = tc
                .get("index")
                .and_then(Value::as_u64)
                .and_then(|i| u32::try_from(i).ok())
                .or_else(|| u32::try_from(pos).ok())
                .unwrap_or(u32::MAX);
            let acc = self.calls.entry(index).or_default();
            if acc.id.is_none() {
                acc.id = str_member(tc, "id").filter(|s| !s.is_empty()).map(str::to_string);
            }
            let function = tc.get("function");
            if let Some(name) = function.and_then(|f| str_member(f, "name")).filter(|s| !s.is_empty()) {
                acc.name.push_str(name);
                if !acc.started {
                    acc.started = true;
                    events.push(StreamEvent::ToolCallStart { index, name: name.to_string() });
                }
            }
            if let Some(args) = function.and_then(|f| str_member(f, "arguments")).filter(|s| !s.is_empty()) {
                acc.arguments.push_str(args);
                events.push(StreamEvent::ToolCallArgs { index, delta: args.to_string() });
            }
        }
    }

    /// True once `[DONE]` or a `finish_reason` has been seen.
    pub fn is_done(&self) -> bool {
        self.done || self.finish.is_some()
    }

    pub fn finish(self) -> Result<Completion, AssembleError> {
        let recorded = self.finish.ok_or(AssembleError::Incomplete)?;
        let mut used: HashSet<String> = HashSet::new();
        let mut tool_calls = Vec::new();
        for (_, acc) in self.calls {
            if acc.name.is_empty() {
                continue;
            }
            let id = match acc.id {
                Some(id) if !used.contains(&id) => id,
                _ => loop {
                    let candidate = random_call_id();
                    if !used.contains(&candidate) {
                        break candidate;
                    }
                },
            };
            used.insert(id.clone());
            let arguments =
                if acc.arguments.trim().is_empty() && recorded != FinishReason::Length { "{}".to_string() } else { acc.arguments };
            let complete = matches!(serde_json::from_str::<Value>(&arguments), Ok(Value::Object(_)));
            tool_calls.push(ToolCallRequest { call_id: CallId(id), name: acc.name, arguments, complete });
        }
        let finish = match recorded {
            FinishReason::Stop if !tool_calls.is_empty() => FinishReason::ToolCalls,
            FinishReason::ToolCalls if tool_calls.is_empty() => FinishReason::Stop,
            other => other,
        };
        Ok(Completion {
            text: self.text,
            reasoning: self.reasoning,
            tool_calls,
            finish,
            usage: self.usage,
            timing: Timing::default(),
            attempts: 1,
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sse(payloads: &[&str]) -> Vec<u8> {
        payloads.iter().map(|p| format!("data: {p}\n\n")).collect::<String>().into_bytes()
    }

    fn run(payloads: &[&str]) -> Result<Completion, AssembleError> {
        let mut a = Assembler::new();
        for p in payloads {
            a.push(p)?;
        }
        a.finish()
    }

    fn chunk(delta: &str, finish: &str) -> String {
        format!(r#"{{"choices":[{{"index":0,"delta":{delta},"finish_reason":{finish}}}]}}"#)
    }

    fn tc_chunk(calls: &str) -> String {
        chunk(&format!(r#"{{"tool_calls":{calls}}}"#), "null")
    }

    // ---- SseParser ----

    fn feed_all(chunks: &[&[u8]]) -> Vec<String> {
        let mut p = SseParser::new();
        chunks.iter().flat_map(|c| p.feed(c)).collect()
    }

    fn sample_stream() -> (Vec<u8>, Vec<String>) {
        let mut payloads: Vec<String> = fixtures().iter().map(|s| (*s).to_string()).collect();
        payloads.push(chunk(r#"{"content":"héllo wörld ✓ 日本語"}"#, "null"));
        let refs: Vec<&str> = payloads.iter().map(String::as_str).collect();
        (sse(&refs), payloads)
    }

    #[test]
    fn parser_whole_stream() {
        let (bytes, payloads) = sample_stream();
        assert_eq!(feed_all(&[&bytes]), payloads);
    }

    #[test]
    fn parser_every_split_position() {
        let (bytes, payloads) = sample_stream();
        for cut in 0..=bytes.len() {
            let (a, b) = bytes.split_at(cut);
            assert_eq!(feed_all(&[a, b]), payloads, "cut at {cut}");
        }
    }

    #[test]
    fn parser_one_byte_chunks() {
        let (bytes, payloads) = sample_stream();
        let mut p = SseParser::new();
        let got: Vec<String> = bytes.chunks(1).flat_map(|c| p.feed(c)).collect();
        assert_eq!(got, payloads);
    }

    #[test]
    fn parser_random_sized_chunks() {
        let (bytes, payloads) = sample_stream();
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        for _ in 0..50 {
            let mut p = SseParser::new();
            let mut got = Vec::new();
            let mut rest = bytes.as_slice();
            while !rest.is_empty() {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let n = usize::try_from(seed % 40).unwrap_or(1) + 1;
                let (head, tail) = rest.split_at(n.min(rest.len()));
                got.extend(p.feed(head));
                rest = tail;
            }
            assert_eq!(got, payloads);
        }
    }

    #[test]
    fn parser_crlf_in_every_split() {
        let raw = b"data: one\r\n\r\ndata: two\r\n\r\n";
        for cut in 0..=raw.len() {
            let (a, b) = raw.split_at(cut);
            assert_eq!(feed_all(&[a, b]), vec!["one", "two"], "cut at {cut}");
        }
    }

    #[test]
    fn parser_comments_and_other_fields() {
        let raw = b": keep-alive\n\nevent: message\nid: 4\nretry: 10\ndata: x\n: inline comment\n\n";
        assert_eq!(feed_all(&[raw]), vec!["x"]);
    }

    #[test]
    fn parser_multiline_data_and_space_rule() {
        let raw = b"data: a\ndata:b\ndata:  c\n\n";
        assert_eq!(feed_all(&[raw]), vec!["a\nb\n c"]);
    }

    #[test]
    fn parser_incomplete_event_is_held_back() {
        let mut p = SseParser::new();
        assert!(p.feed(b"data: partial\n").is_empty());
        assert_eq!(p.feed(b"\n"), vec!["partial"]);
    }

    // ---- Assembler ----

    #[test]
    fn fixtures_assemble() {
        let mut a = Assembler::new();
        let mut events = Vec::new();
        for p in fixtures() {
            events.extend(a.push(p).unwrap_or_default());
        }
        assert!(a.is_done());
        assert_eq!(
            events,
            vec![
                StreamEvent::Reasoning("We".into()),
                StreamEvent::Reasoning(" need a note.".into()),
                StreamEvent::ToolCallStart { index: 0, name: "note".into() },
                StreamEvent::ToolCallArgs { index: 0, delta: "{\"text\": \"".into() },
                StreamEvent::ToolCallArgs { index: 0, delta: "hello\"}".into() },
            ]
        );
        let c = a.finish().unwrap();
        assert_eq!(c.text, "");
        assert_eq!(c.reasoning, "We need a note.");
        assert_eq!(c.finish, FinishReason::ToolCalls);
        assert_eq!(c.attempts, 1);
        assert_eq!(c.usage, Usage { prompt_tokens: 306, cached_tokens: 0, completion_tokens: 79, reasoning_tokens: 41 });
        assert_eq!(c.tool_calls.len(), 1);
        let t = &c.tool_calls[0];
        assert_eq!(t.call_id.as_str(), "chatcmpl-tool-83");
        assert_eq!(t.name, "note");
        assert_eq!(t.arguments, "{\"text\": \"hello\"}");
        assert!(t.complete);
    }

    #[test]
    fn text_is_kept_exactly() {
        let c = run(&[
            &chunk(r#"{"content":"  lead"}"#, "null"),
            &chunk(r#"{"content":" and trail \n"}"#, "null"),
            &chunk("{}", r#""stop""#),
        ])
        .unwrap();
        assert_eq!(c.text, "  lead and trail \n");
        assert_eq!(c.finish, FinishReason::Stop);
        assert!(c.tool_calls.is_empty());
    }

    #[test]
    fn text_events_and_empty_strings() {
        let mut a = Assembler::new();
        assert!(a.push(&chunk(r#"{"content":"","reasoning":""}"#, "null")).unwrap().is_empty());
        let ev = a.push(&chunk(r#"{"content":"hi"}"#, "null")).unwrap();
        assert_eq!(ev, vec![StreamEvent::Text("hi".into())]);
        assert!(!a.is_done());
    }

    #[test]
    fn reasoning_under_both_names() {
        let mut a = Assembler::new();
        a.push(&chunk(r#"{"reasoning":"a"}"#, "null")).unwrap();
        a.push(&chunk(r#"{"reasoning_content":"b"}"#, "null")).unwrap();
        // Both present and equal: taken once.
        let ev = a.push(&chunk(r#"{"reasoning":"c","reasoning_content":"c"}"#, "null")).unwrap();
        assert_eq!(ev, vec![StreamEvent::Reasoning("c".into())]);
        // Both present and different: both are kept.
        a.push(&chunk(r#"{"reasoning":"d","reasoning_content":"e"}"#, "null")).unwrap();
        a.push(&chunk("{}", r#""stop""#)).unwrap();
        assert_eq!(a.finish().unwrap().reasoning, "abcde");
    }

    #[test]
    fn parallel_calls_with_interleaved_arguments() {
        let c = run(&[
            &tc_chunk(r#"[{"index":0,"id":"A","function":{"name":"read","arguments":""}},{"index":1,"id":"B","function":{"name":"bash"}}]"#),
            &tc_chunk(r#"[{"index":1,"function":{"arguments":"{\"command\": "}}]"#),
            &tc_chunk(r#"[{"index":0,"function":{"arguments":"{\"path\":"}}]"#),
            &tc_chunk(r#"[{"index":1,"function":{"arguments":"\"ls  \" }"}}]"#),
            &tc_chunk(r#"[{"index":0,"function":{"arguments":" \"a b\"}"}}]"#),
            &chunk("{}", r#""tool_calls""#),
        ])
        .unwrap();
        assert_eq!(c.tool_calls.len(), 2);
        assert_eq!(c.tool_calls[0].call_id.as_str(), "A");
        assert_eq!(c.tool_calls[0].name, "read");
        assert_eq!(c.tool_calls[0].arguments, "{\"path\": \"a b\"}");
        assert_eq!(c.tool_calls[1].call_id.as_str(), "B");
        assert_eq!(c.tool_calls[1].arguments, "{\"command\": \"ls  \" }");
        assert!(c.tool_calls.iter().all(|t| t.complete));
    }

    #[test]
    fn calls_are_ordered_by_index_and_default_index_is_position() {
        let c = run(&[
            &tc_chunk(r#"[{"index":2,"id":"C","function":{"name":"third","arguments":"{}"}}]"#),
            &tc_chunk(r#"[{"id":"X","function":{"name":"first","arguments":"{}"}},{"id":"Y","function":{"name":"second","arguments":"{}"}}]"#),
            &chunk("{}", r#""tool_calls""#),
        ])
        .unwrap();
        let names: Vec<&str> = c.tool_calls.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["first", "second", "third"]);
    }

    #[test]
    fn name_in_pieces_is_joined_and_started_once() {
        let mut a = Assembler::new();
        let e1 = a.push(&tc_chunk(r#"[{"index":0,"id":"A","function":{"name":"re"}}]"#)).unwrap();
        let e2 = a.push(&tc_chunk(r#"[{"index":0,"function":{"name":"ad","arguments":"{}"}}]"#)).unwrap();
        assert_eq!(e1, vec![StreamEvent::ToolCallStart { index: 0, name: "re".into() }]);
        assert_eq!(e2, vec![StreamEvent::ToolCallArgs { index: 0, delta: "{}".into() }]);
        a.push(&chunk("{}", r#""tool_calls""#)).unwrap();
        assert_eq!(a.finish().unwrap().tool_calls[0].name, "read");
    }

    #[test]
    fn missing_and_duplicate_ids_get_generated_ones() {
        let c = run(&[
            &tc_chunk(
                r#"[{"index":0,"id":"same","function":{"name":"a","arguments":"{}"}},
                    {"index":1,"id":"same","function":{"name":"b","arguments":"{}"}},
                    {"index":2,"function":{"name":"c","arguments":"{}"}}]"#,
            ),
            &chunk("{}", r#""tool_calls""#),
        ])
        .unwrap();
        let ids: Vec<&str> = c.tool_calls.iter().map(|t| t.call_id.as_str()).collect();
        assert_eq!(ids[0], "same");
        for id in &ids[1..] {
            let tail = id.strip_prefix("call-").unwrap();
            assert_eq!(tail.len(), 12);
            assert!(tail.chars().all(|ch| ch.is_ascii_lowercase() || ('2'..='7').contains(&ch)));
        }
        assert_ne!(ids[1], ids[2]);
    }

    #[test]
    fn nameless_call_is_discarded() {
        let c = run(&[
            &tc_chunk(r#"[{"index":0,"id":"A","function":{"arguments":"{}"}}]"#),
            &chunk("{}", r#""tool_calls""#),
        ])
        .unwrap();
        assert!(c.tool_calls.is_empty());
        assert_eq!(c.finish, FinishReason::Stop);
    }

    #[test]
    fn empty_arguments_become_an_empty_object() {
        for args in ["", "  \n"] {
            let body = format!(r#"[{{"index":0,"id":"A","function":{{"name":"t","arguments":{}}}}}]"#, Value::String(args.into()));
            let c = run(&[&tc_chunk(&body), &chunk("{}", r#""tool_calls""#)]).unwrap();
            assert_eq!(c.tool_calls[0].arguments, "{}");
            assert!(c.tool_calls[0].complete);
        }
        // No arguments member at all.
        let c = run(&[&tc_chunk(r#"[{"index":0,"id":"A","function":{"name":"t"}}]"#), &chunk("{}", r#""tool_calls""#)]).unwrap();
        assert_eq!(c.tool_calls[0].arguments, "{}");
    }

    #[test]
    fn arguments_are_never_repaired_or_trimmed() {
        let c = run(&[
            &tc_chunk(r#"[{"index":0,"id":"A","function":{"name":"t","arguments":" {\"a\" :  1 ,\"a\":2}\n"}}]"#),
            &chunk("{}", r#""tool_calls""#),
        ])
        .unwrap();
        assert_eq!(c.tool_calls[0].arguments, " {\"a\" :  1 ,\"a\":2}\n");
        assert!(c.tool_calls[0].complete);
    }

    #[test]
    fn non_object_or_invalid_arguments_are_incomplete() {
        for args in ["[1]", "\"s\"", "12", "{\"a\":", "{\"a\":1} x", "nonsense"] {
            let body = format!(r#"[{{"index":0,"id":"A","function":{{"name":"t","arguments":{}}}}}]"#, Value::String(args.into()));
            let c = run(&[&tc_chunk(&body), &chunk("{}", r#""tool_calls""#)]).unwrap();
            assert!(!c.tool_calls[0].complete, "{args}");
            assert_eq!(c.tool_calls[0].arguments, args);
            assert_eq!(c.finish, FinishReason::ToolCalls);
        }
    }

    #[test]
    fn arguments_cut_by_length() {
        let c = run(&[
            &tc_chunk(r#"[{"index":0,"id":"A","function":{"name":"write","arguments":"{\"path\": \"x\", \"content\": \"abc"}}]"#),
            &chunk("{}", r#""length""#),
        ])
        .unwrap();
        assert_eq!(c.finish, FinishReason::Length);
        assert_eq!(c.tool_calls.len(), 1);
        assert!(!c.tool_calls[0].complete);
        assert_eq!(c.tool_calls[0].arguments, "{\"path\": \"x\", \"content\": \"abc");

        // Empty arguments under `length` are not turned into `{}`.
        let c = run(&[&tc_chunk(r#"[{"index":0,"id":"A","function":{"name":"t"}}]"#), &chunk("{}", r#""length""#)]).unwrap();
        assert_eq!(c.tool_calls[0].arguments, "");
        assert!(!c.tool_calls[0].complete);
    }

    #[test]
    fn finish_reason_mapping() {
        let call = tc_chunk(r#"[{"index":0,"id":"A","function":{"name":"t","arguments":"{}"}}]"#);
        let of = |reason: &str, with_call: bool| {
            let mut p = Vec::new();
            if with_call {
                p.push(call.clone());
            }
            p.push(chunk("{}", reason));
            let refs: Vec<&str> = p.iter().map(String::as_str).collect();
            run(&refs).unwrap().finish
        };
        assert_eq!(of(r#""stop""#, false), FinishReason::Stop);
        assert_eq!(of(r#""stop""#, true), FinishReason::ToolCalls);
        assert_eq!(of(r#""tool_calls""#, true), FinishReason::ToolCalls);
        assert_eq!(of(r#""function_call""#, true), FinishReason::ToolCalls);
        assert_eq!(of(r#""tool_calls""#, false), FinishReason::Stop);
        assert_eq!(of(r#""length""#, true), FinishReason::Length);
        assert_eq!(of(r#""content_filter""#, false), FinishReason::Stop);
    }

    #[test]
    fn usage_only_final_chunk_and_last_usage_wins() {
        let c = run(&[
            &chunk(r#"{"content":"x"}"#, r#""stop""#),
            r#"{"choices":[],"usage":{"prompt_tokens":5,"completion_tokens":1}}"#,
            r#"{"choices":[],"usage":{"prompt_tokens":9,"completion_tokens":2,"prompt_tokens_details":{"cached_tokens":4}}}"#,
            r#"{"choices":[],"usage":null}"#,
            "[DONE]",
        ])
        .unwrap();
        assert_eq!(c.usage, Usage { prompt_tokens: 9, cached_tokens: 4, completion_tokens: 2, reasoning_tokens: 0 });
    }

    #[test]
    fn error_object() {
        let mut a = Assembler::new();
        let e = a.push(r#"{"error":{"message":"model is loading","type":"x","code":503}}"#).unwrap_err();
        assert_eq!(e, AssembleError::Server("model is loading".into()));
        let e = a.push(r#"{"error":"plain"}"#).unwrap_err();
        assert_eq!(e, AssembleError::Server("plain".into()));
        let e = a.push(r#"{"error":{"code":1}}"#).unwrap_err();
        assert_eq!(e, AssembleError::Server(r#"{"code":1}"#.into()));
    }

    #[test]
    fn malformed_payloads() {
        let mut a = Assembler::new();
        assert!(matches!(a.push("{not json"), Err(AssembleError::Malformed(_))));
        assert!(matches!(a.push("[1,2]"), Err(AssembleError::Malformed(_))));
        assert!(matches!(a.push(""), Err(AssembleError::Malformed(_))));
    }

    #[test]
    fn early_end_is_incomplete() {
        let mut a = Assembler::new();
        a.push(&chunk(r#"{"content":"partial"}"#, "null")).unwrap();
        assert!(!a.is_done());
        assert_eq!(a.finish().unwrap_err(), AssembleError::Incomplete);

        // [DONE] without a finish_reason is still an early end.
        let mut a = Assembler::new();
        a.push("[DONE]").unwrap();
        assert!(a.is_done());
        assert_eq!(a.finish().unwrap_err(), AssembleError::Incomplete);
    }

    #[test]
    fn end_to_end_through_the_parser() {
        let (bytes, _) = sample_stream();
        let mut p = SseParser::new();
        let mut a = Assembler::new();
        for b in bytes.chunks(3) {
            for payload in p.feed(b) {
                a.push(&payload).unwrap();
            }
        }
        let c = a.finish().unwrap();
        assert_eq!(c.text, "héllo wörld ✓ 日本語");
        assert_eq!(c.tool_calls[0].arguments, "{\"text\": \"hello\"}");
    }
}
