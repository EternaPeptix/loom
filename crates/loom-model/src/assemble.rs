//! SSE framing and accumulation of streamed deltas into one [`Completion`].
//!
//! CONTRACT.
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
//!   `ToolCallArgs` for each non-empty arguments piece. An element for an index makes every lower
//!   index that has a name complete: before that element is applied, `ToolCallReady` (index, the
//!   server's id if one came, name, the arguments so far) is emitted for each of them, in index order,
//!   at most once per index. The last call of a reply gets none (it is complete only when the whole
//!   reply is);
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
//! - `complete`: true when `arguments` parses as a JSON object (including after deterministic repair
//!   when `finish_reason` is not `Length`/`Error`/`Aborted`).
//! - finish reason: if at least one tool call exists (including structured calls recovered from `text`)
//!   and the recorded reason is `Stop`, the result is `ToolCalls`. If the reason is `ToolCalls` and no
//!   call exists, the result is `Stop`.
//! - `text` and `reasoning` are returned as received when no leaked calls are extracted from `text`.
//!
//! Tests required: parser with every split position of a sample stream (feed it in 1-byte chunks and
//! in random-sized chunks, same payloads out); CRLF; comments; multi-line data. Assembler: the exact
//! chunk shapes in `fixtures()` below (taken from a real vLLM stream); reasoning under both names;
//! two parallel tool calls with interleaved argument pieces; missing ids; duplicate ids; empty
//! arguments; arguments cut by `length` (complete == false); usage-only final chunk; error object;
//! early end.
//!
//! ## Limits
//! A misbehaving server cannot make the client buffer without bound. `SseParser::feed` fails with
//! `AssembleError::Oversize` for one line above `MAX_LINE_BYTES` (8 MiB) and for one event whose data
//! lines add up to more than `MAX_EVENT_BYTES` (16 MiB); `Assembler::push` fails the same way when the
//! accumulated content, the reasoning, or the tool-call names and arguments together pass
//! `MAX_COMPLETION_BYTES` (64 MiB) each. The parser is unusable after such an error.

use loom_core::event::{FinishReason, Timing, ToolCallRequest, Usage};
use loom_core::CallId;
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamEvent {
    /// An attempt is starting. Everything emitted for an earlier attempt of this request is void.
    AttemptStart {
        attempt: u32,
    },
    Text(String),
    Reasoning(String),
    ToolCallStart {
        index: u32,
        name: String,
    },
    ToolCallArgs {
        index: u32,
        delta: String,
    },
    /// The call at `index` is complete as far as this attempt goes: a later call has begun. `id` (the
    /// server's, as received so far), `name` and `arguments` are everything received for it. The final
    /// completion holds the call only if nothing more arrives for it; whoever acts on this event
    /// compares the two.
    ToolCallReady {
        index: u32,
        id: Option<String>,
        name: String,
        arguments: String,
    },
    /// The attempt failed and another will follow after `after_ms`.
    Retrying {
        attempt: u32,
        after_ms: u64,
        reason: String,
    },
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
    #[error("the stream is too large: {0}")]
    Oversize(String),
    #[error("the stream ended before the response was finished")]
    Incomplete,
}

/// Longest single line of an event stream (8 MiB).
pub const MAX_LINE_BYTES: usize = 8 * 1024 * 1024;
/// Largest single event: its `data:` lines together (16 MiB).
pub const MAX_EVENT_BYTES: usize = 16 * 1024 * 1024;
/// Most bytes of content, of reasoning, and of tool-call names and arguments one completion may accumulate (64 MiB each).
pub const MAX_COMPLETION_BYTES: usize = 64 * 1024 * 1024;

fn oversize(what: &str, limit: usize) -> AssembleError {
    AssembleError::Oversize(format!("{what} exceeds the limit of {} MiB", limit / (1024 * 1024)))
}

#[derive(Debug, Default)]
pub struct SseParser {
    /// Bytes of the line being received (no complete line is ever kept here).
    buf: Vec<u8>,
    /// `data:` values of the event being received, joined with `\n`.
    data: String,
    /// Whether the event being received has any `data:` line (its payload may still be empty).
    has_data: bool,
}

impl SseParser {
    pub fn new() -> SseParser {
        SseParser::default()
    }

    /// Feed bytes; get the data payloads of the events they complete. A line or an event above its limit
    /// is an `Oversize` error and the buffers are released.
    pub fn feed(&mut self, chunk: &[u8]) -> Result<Vec<String>, AssembleError> {
        let result = self.feed_inner(chunk);
        if result.is_err() {
            self.buf = Vec::new();
            self.data = String::new();
            self.has_data = false;
        }
        result
    }

    fn feed_inner(&mut self, chunk: &[u8]) -> Result<Vec<String>, AssembleError> {
        let mut out = Vec::new();
        self.buf.extend_from_slice(chunk);
        let mut start = 0usize;
        while let Some(rel) = self.buf.get(start..).and_then(|rest| rest.iter().position(|&b| b == b'\n')) {
            let end = start + rel;
            let mut line = self.buf.get(start..end).unwrap_or_default();
            if line.len() > MAX_LINE_BYTES {
                return Err(oversize("a line of the event stream", MAX_LINE_BYTES));
            }
            if let Some(stripped) = line.strip_suffix(b"\r") {
                line = stripped;
            }
            // A complete line is whole characters, so decoding it cannot split one.
            let line = String::from_utf8_lossy(line).into_owned();
            start = end + 1;
            if line.is_empty() {
                if self.has_data {
                    let payload = std::mem::take(&mut self.data);
                    self.has_data = false;
                    if !payload.is_empty() {
                        out.push(payload);
                    }
                }
            } else if let Some(value) = line.strip_prefix("data:") {
                let value = value.strip_prefix(' ').unwrap_or(value);
                let separator = usize::from(self.has_data);
                if self.data.len().saturating_add(separator).saturating_add(value.len()) > MAX_EVENT_BYTES {
                    return Err(oversize("an event of the event stream", MAX_EVENT_BYTES));
                }
                if self.has_data {
                    self.data.push('\n');
                }
                self.data.push_str(value);
                self.has_data = true;
            }
            // Comments (`:`) and every other field are ignored.
        }
        self.buf.drain(..start);
        if self.buf.len() > MAX_LINE_BYTES {
            return Err(oversize("a line of the event stream", MAX_LINE_BYTES));
        }
        Ok(out)
    }
}

#[derive(Debug, Default)]
struct CallAcc {
    id: Option<String>,
    name: String,
    arguments: String,
    started: bool,
    /// `ToolCallReady` has been emitted for this call.
    ready: bool,
}

#[derive(Debug, Default)]
pub struct Assembler {
    text: String,
    reasoning: String,
    calls: BTreeMap<u32, CallAcc>,
    finish: Option<FinishReason>,
    usage: Usage,
    done: bool,
    /// Bytes of tool-call names and arguments accumulated (a new call counts `CALL_OVERHEAD`).
    call_bytes: usize,
    /// Full JSON chunk of the last `{"error": ...}` payload seen, for structured classification.
    last_error: Option<Value>,
}

/// What an empty tool-call entry is counted as, so that endless new indices are bounded too.
const CALL_OVERHEAD: usize = 64;

/// `used + add` if it stays within `MAX_COMPLETION_BYTES`.
fn grow(used: usize, add: usize, what: &str) -> Result<usize, AssembleError> {
    used.checked_add(add).filter(|n| *n <= MAX_COMPLETION_BYTES).ok_or_else(|| oversize(what, MAX_COMPLETION_BYTES))
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
    use rand::RngExt;
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut rng = rand::rng();
    let mut id = String::from("call-");
    for _ in 0..12 {
        let pick = ALPHABET.get(rng.random_range(0..ALPHABET.len())).copied().unwrap_or(b'a');
        id.push(char::from(pick));
    }
    id
}

fn strip_outer_code_fence(s: &str) -> &str {
    let trimmed = s.trim();
    let Some(after_open) = trimmed.strip_prefix("```") else {
        return trimmed;
    };
    let Some(inner) = after_open.strip_suffix("```") else {
        return trimmed;
    };
    let body = if let Some(nl) = inner.find('\n') {
        let first = inner.get(..nl).unwrap_or("").trim();
        if !first.starts_with('{')
            && !first.starts_with('[')
            && first.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
        {
            inner.get(nl + 1..).unwrap_or("")
        } else {
            inner
        }
    } else {
        let lead = inner.trim_start();
        if lead.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("json")) {
            let after_lang = lead.get(4..).unwrap_or("").trim_start();
            if after_lang.starts_with('{') || after_lang.starts_with('[') {
                after_lang
            } else {
                inner
            }
        } else {
            inner
        }
    };
    body.trim()
}

fn strip_leaked_vendor_tokens(s: &str) -> String {
    const OPEN: &str = "<|open|>";
    const SEP: &str = "<|sep|>";
    if !s.contains(OPEN) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(open_idx) = rest.find(OPEN) {
        out.push_str(rest.get(..open_idx).unwrap_or(""));
        let after_open = rest.get(open_idx + OPEN.len()..).unwrap_or("");
        if let Some(sep_idx) = after_open.find(SEP) {
            let inside = after_open.get(..sep_idx).unwrap_or("");
            if !inside.contains(OPEN) && !inside.contains('\n') && !inside.contains('\r') {
                rest = after_open.get(sep_idx + SEP.len()..).unwrap_or("");
                continue;
            }
        }
        out.push_str(OPEN);
        rest = after_open;
    }
    out.push_str(rest);
    out
}

fn strip_trailing_commas(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_string = false;
    let mut escape = false;
    for (idx, ch) in s.char_indices() {
        if in_string {
            out.push(ch);
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        if ch == '"' {
            in_string = true;
            out.push(ch);
        } else if ch == ',' {
            let rest = s.get(idx + ch.len_utf8()..).unwrap_or("");
            let next_non_ws = rest.chars().find(|c| !matches!(c, ' ' | '\t' | '\n' | '\r'));
            if matches!(next_non_ws, Some('}' | ']')) {
                continue;
            }
            out.push(ch);
        } else {
            out.push(ch);
        }
    }
    out
}

/// Deterministically repair common non-truncated JSON object defects (outer code fences, leaked
/// vendor token prefixes, trailing commas). Returns `Some(repaired)` only when the repaired
/// string strictly parses as a JSON object.
fn repair_json_object(raw: &str) -> Option<String> {
    let unfenced = strip_outer_code_fence(raw);
    let devendored = strip_leaked_vendor_tokens(unfenced);
    let cleaned = strip_trailing_commas(&devendored);
    matches!(serde_json::from_str::<Value>(&cleaned), Ok(Value::Object(_))).then_some(cleaned)
}

fn parse_json_value_or_repaired_object(raw: &str) -> Option<Value> {
    if let Ok(v) = serde_json::from_str::<Value>(raw) {
        return Some(v);
    }
    let repaired = repair_json_object(raw)?;
    serde_json::from_str::<Value>(&repaired).ok()
}

fn extract_call_fields(v: &Value, allow_string_args: bool) -> Option<(String, Value)> {
    let obj = v.as_object()?;
    let name = obj.get("name").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty())?;
    let args_val = obj.get("arguments").or_else(|| obj.get("parameters"))?;
    let args = match args_val {
        Value::Object(_) => args_val.clone(),
        Value::String(s) if allow_string_args => {
            let parsed = parse_json_value_or_repaired_object(s)?;
            if !parsed.is_object() {
                return None;
            }
            parsed
        }
        _ => return None,
    };
    Some((name.to_string(), args))
}

fn find_tag_end(s: &str) -> Option<(usize, bool)> {
    let mut quote: Option<char> = None;
    for (idx, ch) in s.char_indices() {
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            }
            continue;
        }
        if ch == '"' || ch == '\'' {
            quote = Some(ch);
        } else if ch == '>' {
            let self_closing = s.get(..idx).is_some_and(|before| before.trim_end().ends_with('/'));
            return Some((idx, self_closing));
        }
    }
    None
}

fn parse_xml_attrs(s: &str) -> Option<Vec<(String, String)>> {
    let mut attrs = Vec::new();
    let mut rest = s.trim();
    while !rest.is_empty() {
        let eq = rest.find('=')?;
        let key = rest.get(..eq)?.trim();
        if key.is_empty() || key.chars().any(char::is_whitespace) {
            return None;
        }
        let after_eq = rest.get(eq + 1..)?.trim_start();
        let quote = after_eq.chars().next()?;
        if quote != '"' && quote != '\'' {
            return None;
        }
        let val_start = after_eq.get(quote.len_utf8()..)?;
        let close = val_start.find(quote)?;
        let val = val_start.get(..close)?;
        attrs.push((key.to_string(), val.to_string()));
        rest = val_start.get(close + quote.len_utf8()..)?.trim_start();
    }
    Some(attrs)
}

fn attr_value<'a>(attrs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    attrs.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

fn parse_param_value(raw: &str, force_string: bool) -> Value {
    if force_string {
        return Value::String(raw.to_string());
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Value::String(String::new());
    }
    serde_json::from_str::<Value>(trimmed).unwrap_or_else(|_| Value::String(raw.to_string()))
}

fn parse_xml_invoke(s: &str, open_prefix: &str, close_prefix: &str) -> Option<(usize, String, Value)> {
    let open_tag = format!("{open_prefix}invoke");
    let after_tag = s.strip_prefix(&open_tag)?;
    let next = after_tag.chars().next()?;
    if !next.is_whitespace() {
        return None;
    }
    let (end_gt, self_closing) = find_tag_end(after_tag)?;
    let attr_slice = after_tag.get(..end_gt)?;
    let attr_slice = if self_closing { attr_slice.trim_end().strip_suffix('/')? } else { attr_slice };
    let attrs = parse_xml_attrs(attr_slice)?;
    let name = attr_value(&attrs, "name").map(str::trim).filter(|n| !n.is_empty())?.to_string();
    let body_start = open_tag.len() + end_gt + 1;
    if self_closing {
        return Some((body_start, name, Value::Object(serde_json::Map::new())));
    }
    let close_invoke = format!("{close_prefix}invoke>");
    let rest = s.get(body_start..)?;
    let close_idx = rest.find(&close_invoke)?;
    let body = rest.get(..close_idx)?;

    let param_open = format!("{open_prefix}parameter");
    let param_close = format!("{close_prefix}parameter>");
    let mut map = serde_json::Map::new();
    let mut p_rest = body.trim_start();
    while !p_rest.is_empty() {
        let after_p = p_rest.strip_prefix(&param_open)?;
        let p_next = after_p.chars().next()?;
        if !p_next.is_whitespace() {
            return None;
        }
        let (p_gt, p_self_closing) = find_tag_end(after_p)?;
        if p_self_closing {
            let p_attrs = parse_xml_attrs(after_p.get(..p_gt)?.trim_end().strip_suffix('/')?)?;
            let p_name = attr_value(&p_attrs, "name").map(str::trim).filter(|n| !n.is_empty())?;
            map.insert(p_name.to_string(), Value::String(String::new()));
            p_rest = after_p.get(p_gt + 1..)?.trim_start();
            continue;
        }
        let p_attrs = parse_xml_attrs(after_p.get(..p_gt)?)?;
        let p_name = attr_value(&p_attrs, "name").map(str::trim).filter(|n| !n.is_empty())?;
        let force_string = attr_value(&p_attrs, "string") == Some("true");
        let after_p_open = after_p.get(p_gt + 1..)?;
        let p_end = after_p_open.find(&param_close)?;
        let raw_val = after_p_open.get(..p_end)?;
        map.insert(p_name.to_string(), parse_param_value(raw_val, force_string));
        p_rest = after_p_open.get(p_end + param_close.len()..)?.trim_start();
    }
    Some((body_start + close_idx + close_invoke.len(), name, Value::Object(map)))
}

fn parse_xml_function_calls(s: &str, open_prefix: &str, close_prefix: &str) -> Option<(usize, Vec<(String, Value)>)> {
    let open_wrap = format!("{open_prefix}function_calls>");
    let close_wrap = format!("{close_prefix}function_calls>");
    let after_open = s.strip_prefix(&open_wrap)?;
    let close_idx = after_open.find(&close_wrap)?;
    let mut body = after_open.get(..close_idx)?.trim_start();
    let mut calls = Vec::new();
    while !body.is_empty() {
        let (used, name, args) = parse_xml_invoke(body, open_prefix, close_prefix)?;
        calls.push((name, args));
        body = body.get(used..)?.trim_start();
    }
    if calls.is_empty() {
        return None;
    }
    Some((open_wrap.len() + close_idx + close_wrap.len(), calls))
}

fn try_parse_tool_call_tag(s: &str) -> Option<(usize, Vec<(String, Value)>)> {
    let after_tag = s.strip_prefix("<tool_call")?;
    let (end_gt, self_closing) = find_tag_end(after_tag)?;
    if self_closing || !after_tag.get(..end_gt)?.trim().is_empty() {
        return None;
    }
    let body_start = "<tool_call".len() + end_gt + 1;
    let rest = s.get(body_start..)?;
    let close_idx = rest.find("</tool_call>")?;
    let body = rest.get(..close_idx)?.trim();
    if !body.starts_with('{') {
        return None;
    }
    let v = parse_json_value_or_repaired_object(body)?;
    let (name, args) = extract_call_fields(&v, true)?;
    Some((body_start + close_idx + "</tool_call>".len(), vec![(name, args)]))
}

enum FencedStep {
    NotFence,
    SkipTo(usize),
    Matched { end: usize, name: String, args: Value },
}

fn try_fenced_tool_call(text: &str, line_start: usize) -> FencedStep {
    let after_start = text.get(line_start..).unwrap_or("");
    let indent = after_start.bytes().take_while(|b| *b == b' ' || *b == b'\t').count();
    let Some(after_ticks) = after_start.get(indent..).and_then(|r| r.strip_prefix("```")) else {
        return FencedStep::NotFence;
    };
    let Some(first_nl) = after_ticks.find('\n') else {
        return FencedStep::NotFence;
    };
    let info = after_ticks.get(..first_nl).unwrap_or("").trim();
    let body_offset = line_start + indent + 3 + first_nl + 1;
    let mut scan = body_offset;
    let mut closing: Option<(usize, usize)> = None;
    while scan <= text.len() {
        let rest = text.get(scan..).unwrap_or("");
        let line_len = rest.find('\n').unwrap_or(rest.len());
        let line = rest.get(..line_len).unwrap_or("").strip_suffix('\r').unwrap_or(rest.get(..line_len).unwrap_or(""));
        if line.trim() == "```" {
            closing = Some((scan, scan + line_len));
            break;
        }
        if scan + line_len >= text.len() {
            break;
        }
        scan += line_len + 1;
    }
    let Some((close_line_start, close_line_end)) = closing else {
        return FencedStep::SkipTo(body_offset);
    };
    let next_pos =
        if text.as_bytes().get(close_line_end) == Some(&b'\n') { close_line_end + 1 } else { close_line_end };
    if !info.is_empty() && !info.eq_ignore_ascii_case("json") {
        return FencedStep::SkipTo(next_pos);
    }
    let body = text.get(body_offset..close_line_start).unwrap_or("").trim();
    if let Ok(v) = serde_json::from_str::<Value>(body) {
        if let Some((name, args)) = extract_call_fields(&v, false) {
            return FencedStep::Matched { end: close_line_end, name, args };
        }
    }
    FencedStep::SkipTo(next_pos)
}

fn strip_extracted_spans(text: &str, spans: &[(usize, usize)]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    let mut pending_trim_space = false;
    for &(s, e) in spans {
        let line_start = text.get(..s).and_then(|b| b.rfind('\n')).map_or(0, |i| i + 1);
        let before_on_line = text.get(line_start..s).unwrap_or("");
        let after = text.get(e..).unwrap_or("");
        let after_nl = after.find('\n');
        let rest_of_line = after_nl.map_or(after, |i| after.get(..i).unwrap_or(""));
        let rest_of_line_no_cr = rest_of_line.strip_suffix('\r').unwrap_or(rest_of_line);
        let own_lines = line_start >= cursor
            && before_on_line.bytes().all(|b| b == b' ' || b == b'\t')
            && rest_of_line_no_cr.bytes().all(|b| b == b' ' || b == b'\t');

        let (rem_start, rem_end) = if own_lines {
            let end = after_nl.map_or(text.len(), |i| e + i + 1);
            (line_start, end)
        } else {
            (s, e)
        };

        let chunk = text.get(cursor..rem_start).unwrap_or("");
        let chunk = if pending_trim_space { chunk.strip_prefix(' ').unwrap_or(chunk) } else { chunk };
        pending_trim_space = false;

        if out.ends_with("\n\n") {
            let trimmed = chunk.trim_start_matches('\r').trim_start_matches('\n');
            out.push_str(trimmed);
        } else {
            out.push_str(chunk);
        }
        if !own_lines && out.ends_with(' ') {
            pending_trim_space = true;
        }
        cursor = rem_end;
    }
    let tail = text.get(cursor..).unwrap_or("");
    let tail = if pending_trim_space { tail.strip_prefix(' ').unwrap_or(tail) } else { tail };
    if out.ends_with("\n\n") {
        out.push_str(tail.trim_start_matches('\r').trim_start_matches('\n'));
    } else {
        out.push_str(tail);
    }
    out.trim().to_string()
}

fn extract_leaked_tool_calls(text: &str) -> Option<(Vec<ToolCallRequest>, String)> {
    let mut extracted: Vec<(String, Value)> = Vec::new();
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut pos = 0usize;
    while pos < text.len() {
        let at_line_start = pos == 0 || text.as_bytes().get(pos.saturating_sub(1)) == Some(&b'\n');
        if at_line_start {
            match try_fenced_tool_call(text, pos) {
                FencedStep::Matched { end, name, args } => {
                    spans.push((pos, end));
                    extracted.push((name, args));
                    pos = if text.as_bytes().get(end) == Some(&b'\n') { end + 1 } else { end };
                    continue;
                }
                FencedStep::SkipTo(end) => {
                    pos = end;
                    continue;
                }
                FencedStep::NotFence => {}
            }
        }
        let rest = text.get(pos..).unwrap_or("");
        if rest.starts_with('\n') {
            pos += 1;
            continue;
        }
        let matched = if rest.starts_with("<tool_call") {
            try_parse_tool_call_tag(rest)
        } else if rest.starts_with("<｜DSML｜function_calls>") {
            parse_xml_function_calls(rest, "<｜DSML｜", "</｜DSML｜")
        } else if rest.starts_with("<|DSML|function_calls>") {
            parse_xml_function_calls(rest, "<|DSML|", "</|DSML|")
        } else if rest.starts_with("<｜DSML｜invoke") {
            parse_xml_invoke(rest, "<｜DSML｜", "</｜DSML｜").map(|(len, n, a)| (len, vec![(n, a)]))
        } else if rest.starts_with("<|DSML|invoke") {
            parse_xml_invoke(rest, "<|DSML|", "</|DSML|").map(|(len, n, a)| (len, vec![(n, a)]))
        } else if rest.starts_with("<function_calls>") {
            parse_xml_function_calls(rest, "<", "</")
        } else if rest.starts_with("<invoke") {
            parse_xml_invoke(rest, "<", "</").map(|(len, n, a)| (len, vec![(n, a)]))
        } else {
            None
        };
        if let Some((len, calls)) = matched {
            spans.push((pos, pos + len));
            extracted.extend(calls);
            pos += len;
            continue;
        }
        let step = rest.chars().next().map_or(1, char::len_utf8);
        let after = text.get(pos + step..).unwrap_or("");
        let Some(rel) = after.find(['<', '\n']) else {
            break;
        };
        let jump = pos + step + rel;
        pos = if after.as_bytes().get(rel) == Some(&b'\n') { jump + 1 } else { jump };
    }
    if extracted.is_empty() {
        return None;
    }
    let tool_calls = extracted
        .into_iter()
        .enumerate()
        .map(|(i, (name, args))| ToolCallRequest {
            call_id: CallId(format!("rec_{i}")),
            name,
            arguments: serde_json::to_string(&args).unwrap_or_else(|_| "{}".to_string()),
            complete: true,
        })
        .collect();
    let cleaned = strip_extracted_spans(text, &spans);
    Some((tool_calls, cleaned))
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
            self.last_error = Some(v.clone());
            return Err(AssembleError::Server(error_message(e)));
        }
        let mut events = Vec::new();
        if let Some(choice) = v.get("choices").and_then(|c| c.get(0)) {
            if let Some(delta) = choice.get("delta") {
                self.apply_delta(delta, &mut events)?;
            }
            if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str).filter(|r| !r.is_empty()) {
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

    fn apply_delta(&mut self, delta: &Value, events: &mut Vec<StreamEvent>) -> Result<(), AssembleError> {
        if let Some(s) = str_member(delta, "content").filter(|s| !s.is_empty()) {
            grow(self.text.len(), s.len(), "the response content")?;
            self.text.push_str(s);
            events.push(StreamEvent::Text(s.to_string()));
        }
        let a = str_member(delta, "reasoning");
        let b = str_member(delta, "reasoning_content");
        let pieces: &[Option<&str>] = if a.is_some() && a == b { &[a] } else { &[a, b] };
        for s in pieces.iter().flatten().filter(|s| !s.is_empty()) {
            grow(self.reasoning.len(), s.len(), "the response reasoning")?;
            self.reasoning.push_str(s);
            events.push(StreamEvent::Reasoning((*s).to_string()));
        }
        let Some(calls) = delta.get("tool_calls").and_then(Value::as_array) else { return Ok(()) };
        for (pos, tc) in calls.iter().enumerate() {
            let index = tc
                .get("index")
                .and_then(Value::as_u64)
                .and_then(|i| u32::try_from(i).ok())
                .or_else(|| u32::try_from(pos).ok())
                .unwrap_or(u32::MAX);
            // A later call has begun, so every named call before it is complete.
            for (i, earlier) in self.calls.range_mut(..index) {
                if !earlier.ready && !earlier.name.is_empty() {
                    earlier.ready = true;
                    let (id, name, arguments) = (earlier.id.clone(), earlier.name.clone(), earlier.arguments.clone());
                    events.push(StreamEvent::ToolCallReady { index: *i, id, name, arguments });
                }
            }
            if !self.calls.contains_key(&index) {
                self.call_bytes = grow(self.call_bytes, CALL_OVERHEAD, "the tool-call arguments")?;
            }
            let acc = self.calls.entry(index).or_default();
            if acc.id.is_none() {
                if let Some(id) = str_member(tc, "id").filter(|s| !s.is_empty()) {
                    self.call_bytes = grow(self.call_bytes, id.len(), "the tool-call arguments")?;
                    acc.id = Some(id.to_string());
                }
            }
            let function = tc.get("function");
            if let Some(name) = function.and_then(|f| str_member(f, "name")).filter(|s| !s.is_empty()) {
                self.call_bytes = grow(self.call_bytes, name.len(), "the tool-call arguments")?;
                acc.name.push_str(name);
                if !acc.started {
                    acc.started = true;
                    events.push(StreamEvent::ToolCallStart { index, name: name.to_string() });
                }
            }
            if let Some(args) = function.and_then(|f| str_member(f, "arguments")).filter(|s| !s.is_empty()) {
                self.call_bytes = grow(self.call_bytes, args.len(), "the tool-call arguments")?;
                acc.arguments.push_str(args);
                events.push(StreamEvent::ToolCallArgs { index, delta: args.to_string() });
            }
        }
        Ok(())
    }

    /// True once `[DONE]` or a `finish_reason` has been seen.
    pub fn is_done(&self) -> bool {
        self.done || self.finish.is_some()
    }

    pub(crate) fn last_error(&self) -> Option<&Value> {
        self.last_error.as_ref()
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
            let raw_arguments = if acc.arguments.trim().is_empty() && recorded != FinishReason::Length {
                "{}".to_string()
            } else {
                acc.arguments
            };
            let (arguments, complete) = match serde_json::from_str::<Value>(&raw_arguments) {
                Ok(Value::Object(_)) => (raw_arguments, true),
                Ok(_) => (raw_arguments, false),
                Err(_) if recorded != FinishReason::Length => match repair_json_object(&raw_arguments) {
                    Some(repaired) => (repaired, true),
                    None => (raw_arguments, false),
                },
                Err(_) => (raw_arguments, false),
            };
            tool_calls.push(ToolCallRequest { call_id: CallId(id), name: acc.name, arguments, complete });
        }
        let mut text = self.text;
        if tool_calls.is_empty()
            && !matches!(recorded, FinishReason::Length | FinishReason::Error | FinishReason::Aborted)
        {
            if let Some((recovered, stripped_text)) = extract_leaked_tool_calls(&text) {
                tool_calls = recovered;
                text = stripped_text;
            }
        }
        let finish = match recorded {
            FinishReason::Stop if !tool_calls.is_empty() => FinishReason::ToolCalls,
            FinishReason::ToolCalls if tool_calls.is_empty() => FinishReason::Stop,
            other => other,
        };
        Ok(Completion {
            text,
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
        chunks.iter().flat_map(|c| p.feed(c).unwrap()).collect()
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
        let got: Vec<String> = bytes.chunks(1).flat_map(|c| p.feed(c).unwrap()).collect();
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
                got.extend(p.feed(head).unwrap());
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
        assert!(p.feed(b"data: partial\n").unwrap().is_empty());
        assert_eq!(p.feed(b"\n").unwrap(), vec!["partial"]);
    }

    #[test]
    fn parser_refuses_an_endless_line_after_bounded_buffering() {
        let chunk = vec![b'x'; 64 * 1024];
        let mut p = SseParser::new();
        let mut fed = 0usize;
        let err = loop {
            fed += chunk.len();
            match p.feed(&chunk) {
                Ok(out) => assert!(out.is_empty()),
                Err(e) => break e,
            }
            assert!(p.buf.len() <= MAX_LINE_BYTES, "held {} bytes", p.buf.len());
            assert!(fed <= MAX_LINE_BYTES + chunk.len(), "no error after {fed} bytes");
        };
        assert!(matches!(&err, AssembleError::Oversize(m) if m.contains("a line") && m.contains("8 MiB")), "{err}");
        assert!(fed > MAX_LINE_BYTES && p.buf.is_empty());
        // One chunk holding a whole oversized line is refused as well.
        let mut p = SseParser::new();
        let mut big = vec![b'y'; MAX_LINE_BYTES + 1];
        big.push(b'\n');
        assert!(matches!(p.feed(&big), Err(AssembleError::Oversize(_))));
    }

    #[test]
    fn parser_refuses_an_endless_event_after_bounded_buffering() {
        let line = format!("data: {}\n", "y".repeat(1000));
        let chunk = line.repeat(64).into_bytes();
        let mut p = SseParser::new();
        let mut fed = 0usize;
        let err = loop {
            fed += chunk.len();
            match p.feed(&chunk) {
                Ok(out) => assert!(out.is_empty()),
                Err(e) => break e,
            }
            assert!(
                p.data.len() <= MAX_EVENT_BYTES && p.buf.len() <= chunk.len(),
                "held {} + {}",
                p.data.len(),
                p.buf.len()
            );
            assert!(fed <= MAX_EVENT_BYTES + chunk.len(), "no error after {fed} bytes");
        };
        assert!(matches!(&err, AssembleError::Oversize(m) if m.contains("an event") && m.contains("16 MiB")), "{err}");
        assert!(p.data.capacity() == 0 && !p.has_data);
        // Events that do end do not add up.
        let mut p = SseParser::new();
        let ended = format!("{line}\n").repeat(64).into_bytes();
        for _ in 0..1000 {
            assert_eq!(p.feed(&ended).unwrap().len(), 64);
        }
    }

    #[test]
    fn parser_memory_for_an_endless_event_of_tiny_lines_is_bounded() {
        // Empty `data:` lines cost one byte each in the single event buffer, not an allocation each.
        let chunk = "data:\n".repeat(64 * 1024).into_bytes();
        let mut p = SseParser::new();
        let mut fed = 0usize;
        let err = loop {
            fed += chunk.len();
            match p.feed(&chunk) {
                Ok(out) => assert!(out.is_empty()),
                Err(e) => break e,
            }
            assert!(p.data.capacity() <= 2 * MAX_EVENT_BYTES, "capacity {}", p.data.capacity());
            assert!(fed <= 8 * MAX_EVENT_BYTES, "no error after {fed} bytes");
        };
        assert!(matches!(&err, AssembleError::Oversize(m) if m.contains("an event")), "{err}");
    }

    #[test]
    fn assembler_counts_tool_call_ids_toward_the_limit() {
        let id = "i".repeat(1024 * 1024);
        let mut a = Assembler::new();
        let mut accepted = 0usize;
        let err = loop {
            let delta = format!(r#"{{"tool_calls":[{{"index":{accepted},"id":"{id}"}}]}}"#);
            match a.push(&chunk(&delta, "null")) {
                Ok(_) => accepted += 1,
                Err(e) => break e,
            }
            assert!(accepted <= 70, "no error after {accepted} ids");
        };
        assert!(accepted <= 64 && matches!(err, AssembleError::Oversize(_)), "{accepted} {err}");
    }

    #[test]
    fn assembler_refuses_a_completion_over_the_limit() {
        let piece = "z".repeat(1024 * 1024);
        let deltas = [
            (r#"{"content":"P"}"#, "the response content"),
            (r#"{"reasoning":"P"}"#, "the response reasoning"),
            (r#"{"tool_calls":[{"index":0,"function":{"name":"n","arguments":"P"}}]}"#, "the tool-call arguments"),
        ];
        for (delta, what) in deltas {
            let payload = chunk(&delta.replace('P', &piece), "null");
            let mut a = Assembler::new();
            let mut accepted = 0usize;
            let err = loop {
                match a.push(&payload) {
                    Ok(_) => accepted += 1,
                    Err(e) => break e,
                }
                assert!(accepted <= 64, "{what}: no error after {accepted} MiB");
            };
            assert!((63..=64).contains(&accepted), "{what}: {accepted}");
            assert!(
                matches!(&err, AssembleError::Oversize(m) if m.contains(what) && m.contains("64 MiB")),
                "{what}: {err}"
            );
            assert!(
                a.text.len() <= MAX_COMPLETION_BYTES
                    && a.reasoning.len() <= MAX_COMPLETION_BYTES
                    && a.call_bytes <= MAX_COMPLETION_BYTES
            );
        }
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
        assert_eq!(
            c.usage,
            Usage { prompt_tokens: 306, cached_tokens: 0, completion_tokens: 79, reasoning_tokens: 41 }
        );
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
    fn a_later_call_makes_the_named_earlier_ones_ready_once() {
        let ready = |index: u32, id: Option<&str>, name: &str, arguments: &str| StreamEvent::ToolCallReady {
            index,
            id: id.map(str::to_string),
            name: name.into(),
            arguments: arguments.into(),
        };
        let mut a = Assembler::new();
        let mut events = Vec::new();
        for p in [
            tc_chunk(r#"[{"index":0,"id":"A","function":{"name":"re"}}]"#),
            tc_chunk(r#"[{"index":0,"function":{"name":"ad","arguments":"{\"path\":"}}]"#),
            // The second call comes without an id.
            tc_chunk(r#"[{"index":0,"function":{"arguments":" \"a\"}"}},{"index":1,"function":{"name":"glob"}}]"#),
            tc_chunk(r#"[{"index":1,"function":{"arguments":"{}"}}]"#),
            // A piece for a call that is already ready, and a call without a name.
            tc_chunk(r#"[{"index":0,"function":{"arguments":" "}},{"index":2,"function":{"arguments":"{}"}}]"#),
            tc_chunk(r#"[{"index":3,"id":"D","function":{"name":"bash","arguments":"{}"}}]"#),
            tc_chunk(r#"[{"index":3,"function":{"arguments":" "}}]"#),
            chunk("{}", r#""tool_calls""#),
        ] {
            events.extend(a.push(&p).unwrap());
        }
        let got: Vec<&StreamEvent> = events.iter().filter(|e| matches!(e, StreamEvent::ToolCallReady { .. })).collect();
        // Once each, with what had arrived; the nameless call and the last one are never ready.
        let first = ready(0, Some("A"), "read", "{\"path\": \"a\"}");
        assert_eq!(got, [&first, &ready(1, None, "glob", "{}")]);
        let at = |e: &StreamEvent| events.iter().position(|x| x == e).unwrap();
        assert_eq!(at(&first) + 1, at(&StreamEvent::ToolCallStart { index: 1, name: "glob".into() }));
        // What came after the ready event is part of the call: the completion is what decides.
        let c = a.finish().unwrap();
        assert_eq!(c.tool_calls[0].arguments, "{\"path\": \"a\"} ");
        assert_eq!(c.tool_calls.len(), 3);
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
            let body = format!(
                r#"[{{"index":0,"id":"A","function":{{"name":"t","arguments":{}}}}}]"#,
                Value::String(args.into())
            );
            let c = run(&[&tc_chunk(&body), &chunk("{}", r#""tool_calls""#)]).unwrap();
            assert_eq!(c.tool_calls[0].arguments, "{}");
            assert!(c.tool_calls[0].complete);
        }
        // No arguments member at all.
        let c = run(&[&tc_chunk(r#"[{"index":0,"id":"A","function":{"name":"t"}}]"#), &chunk("{}", r#""tool_calls""#)])
            .unwrap();
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
            let body = format!(
                r#"[{{"index":0,"id":"A","function":{{"name":"t","arguments":{}}}}}]"#,
                Value::String(args.into())
            );
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
        let c = run(&[&tc_chunk(r#"[{"index":0,"id":"A","function":{"name":"t"}}]"#), &chunk("{}", r#""length""#)])
            .unwrap();
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
            for payload in p.feed(b).unwrap() {
                a.push(&payload).unwrap();
            }
        }
        let c = a.finish().unwrap();
        assert_eq!(c.text, "héllo wörld ✓ 日本語");
        assert_eq!(c.tool_calls[0].arguments, "{\"text\": \"hello\"}");
    }

    #[test]
    fn empty_finish_reason_does_not_mark_stream_done() {
        let mut a = Assembler::new();
        a.push(&chunk(r#"{"content":"part"}"#, r#""""#)).unwrap();
        assert!(!a.is_done());
        assert_eq!(a.finish().unwrap_err(), AssembleError::Incomplete);

        let c =
            run(&[&chunk(r#"{"content":"part"}"#, r#""""#), &chunk(r#"{"content":" two"}"#, r#""length""#)]).unwrap();
        assert_eq!(c.text, "part two");
        assert_eq!(c.finish, FinishReason::Length);
    }

    #[test]
    fn error_chunk_preserves_structured_json() {
        let mut a = Assembler::new();
        let err = a
            .push(r#"{"error":{"message":"too big","type":"exceed_context_size_error","n_ctx":4096,"n_prompt_tokens":5000}}"#)
            .unwrap_err();
        assert_eq!(err, AssembleError::Server("too big".into()));
        let raw = a.last_error().expect("stored error chunk");
        assert_eq!(raw["error"]["type"], "exceed_context_size_error");
        assert_eq!(raw["error"]["n_ctx"], 4096);
        assert_eq!(raw["error"]["n_prompt_tokens"], 5000);
    }

    #[test]
    fn streamed_json_argument_repair_handles_fences_commas_and_vendor_tokens() {
        let cases = [
            ("```json\n{\"command\": \"ls -la\"}\n```", serde_json::json!({"command": "ls -la"})),
            ("```\n{\"path\": \"src/lib.rs\",}\n```", serde_json::json!({"path": "src/lib.rs"})),
            (
                "{\"items\": [1, 2,], \"note\": \"keep, } inside\",}",
                serde_json::json!({"items": [1, 2], "note": "keep, } inside"}),
            ),
            ("{\"command\": <|open|>argument key=\"command\"<|sep|>\"pwd\"}", serde_json::json!({"command": "pwd"})),
            (
                "{\"a\": \"<|open|>argument key=\"a\"<|sep|>one\", \"b\": \"<|open|>argument key=\"b\"<|sep|>two\"}",
                serde_json::json!({"a": "one", "b": "two"}),
            ),
            (
                "```json\n{\"path\": \"<|open|>argument key=\\\"path\\\"<|sep|>a.rs\", \"lines\": [1, 2,],}\n```",
                serde_json::json!({"path": "a.rs", "lines": [1, 2]}),
            ),
        ];
        for (raw, expected) in cases {
            let body = format!(
                r#"[{{"index":0,"id":"A","function":{{"name":"bash","arguments":{}}}}}]"#,
                Value::String(raw.into())
            );
            let c = run(&[&tc_chunk(&body), &chunk("{}", r#""tool_calls""#)]).unwrap();
            assert!(c.tool_calls[0].complete, "{raw}");
            assert_eq!(serde_json::from_str::<Value>(&c.tool_calls[0].arguments).unwrap(), expected);
        }

        // Fenced non-object JSON stays incomplete.
        let body = format!(
            r#"[{{"index":0,"id":"A","function":{{"name":"t","arguments":{}}}}}]"#,
            Value::String("```json\n[1, 2,]\n```".into())
        );
        let c = run(&[&tc_chunk(&body), &chunk("{}", r#""tool_calls""#)]).unwrap();
        assert!(!c.tool_calls[0].complete);
        assert_eq!(c.tool_calls[0].arguments, "```json\n[1, 2,]\n```");

        // FinishReason::Length must never be repaired.
        let cut = "```json\n{\"command\": \"ls\",}\n```";
        let body = format!(
            r#"[{{"index":0,"id":"A","function":{{"name":"bash","arguments":{}}}}}]"#,
            Value::String(cut.into())
        );
        let c = run(&[&tc_chunk(&body), &chunk("{}", r#""length""#)]).unwrap();
        assert_eq!(c.finish, FinishReason::Length);
        assert!(!c.tool_calls[0].complete);
        assert_eq!(c.tool_calls[0].arguments, cut);
    }

    fn text_reply(content: &str, finish_reason: &str) -> Completion {
        let delta = serde_json::json!({ "content": content }).to_string();
        run(&[&chunk(&delta, "null"), &chunk("{}", finish_reason)]).unwrap()
    }

    #[test]
    fn text_leaked_tool_call_tags_are_extracted_and_stripped() {
        let content = concat!(
            "Let me inspect both files.\n\n",
            "<tool_call>\n{\"name\": \"read\", \"arguments\": {\"path\": \"a.rs\",}}\n</tool_call>\n",
            "<tool_call>{\"name\": \"bash\", \"parameters\": {\"command\": \"pwd\"}}</tool_call>\n",
        );
        let c = text_reply(content, r#""stop""#);
        assert_eq!(c.finish, FinishReason::ToolCalls);
        assert_eq!(c.text, "Let me inspect both files.");
        assert_eq!(c.tool_calls.len(), 2);
        assert_eq!(c.tool_calls[0].call_id.as_str(), "rec_0");
        assert_eq!(c.tool_calls[0].name, "read");
        assert_eq!(
            serde_json::from_str::<Value>(&c.tool_calls[0].arguments).unwrap(),
            serde_json::json!({"path": "a.rs"})
        );
        assert!(c.tool_calls[0].complete);
        assert_eq!(c.tool_calls[1].call_id.as_str(), "rec_1");
        assert_eq!(c.tool_calls[1].name, "bash");
        assert_eq!(
            serde_json::from_str::<Value>(&c.tool_calls[1].arguments).unwrap(),
            serde_json::json!({"command": "pwd"})
        );
        assert!(c.tool_calls[1].complete);
    }

    #[test]
    fn text_leaked_dsml_calls_are_extracted_and_stripped() {
        let content = concat!(
            "Running search.\n",
            "<｜DSML｜function_calls>\n",
            "<｜DSML｜invoke name=\"read\">\n",
            "<｜DSML｜parameter name=\"path\" string=\"true\">42</｜DSML｜parameter>\n",
            "<｜DSML｜parameter name=\"start\" string=\"false\">10</｜DSML｜parameter>\n",
            "</｜DSML｜invoke>\n",
            "<｜DSML｜invoke name=\"wait\"></｜DSML｜invoke>\n",
            "</｜DSML｜function_calls>\n",
        );
        let c = text_reply(content, r#""stop""#);
        assert_eq!(c.finish, FinishReason::ToolCalls);
        assert_eq!(c.text, "Running search.");
        assert_eq!(c.tool_calls.len(), 2);
        assert_eq!(c.tool_calls[0].call_id.as_str(), "rec_0");
        assert_eq!(c.tool_calls[0].name, "read");
        assert_eq!(
            serde_json::from_str::<Value>(&c.tool_calls[0].arguments).unwrap(),
            serde_json::json!({"path": "42", "start": 10})
        );
        assert_eq!(c.tool_calls[1].call_id.as_str(), "rec_1");
        assert_eq!(c.tool_calls[1].name, "wait");
        assert_eq!(c.tool_calls[1].arguments, "{}");
    }

    #[test]
    fn text_leaked_generic_invoke_calls_are_extracted_and_stripped() {
        let content = concat!(
            "<invoke name=\"grep\">\n",
            "<parameter name=\"pattern\">TODO</parameter>\n",
            "<parameter name=\"limit\">5</parameter>\n",
            "<parameter name=\"case_sensitive\">false</parameter>\n",
            "</invoke>",
        );
        let c = text_reply(content, r#""tool_calls""#);
        assert_eq!(c.finish, FinishReason::ToolCalls);
        assert_eq!(c.text, "");
        assert_eq!(c.tool_calls.len(), 1);
        assert_eq!(c.tool_calls[0].call_id.as_str(), "rec_0");
        assert_eq!(c.tool_calls[0].name, "grep");
        assert_eq!(
            serde_json::from_str::<Value>(&c.tool_calls[0].arguments).unwrap(),
            serde_json::json!({"pattern": "TODO", "limit": 5, "case_sensitive": false})
        );
    }

    #[test]
    fn text_leaked_standalone_fenced_json_calls_are_extracted_and_stripped() {
        let content = concat!(
            "First step:\n\n",
            "```json\n{\"name\": \"bash\", \"arguments\": {\"command\": \"echo hi\"}}\n```\n\n",
            "After block.",
        );
        let c = text_reply(content, r#""stop""#);
        assert_eq!(c.finish, FinishReason::ToolCalls);
        assert_eq!(c.text, "First step:\n\nAfter block.");
        assert_eq!(c.tool_calls.len(), 1);
        assert_eq!(c.tool_calls[0].call_id.as_str(), "rec_0");
        assert_eq!(c.tool_calls[0].name, "bash");
        assert_eq!(
            serde_json::from_str::<Value>(&c.tool_calls[0].arguments).unwrap(),
            serde_json::json!({"command": "echo hi"})
        );

        // Consecutive fenced blocks where the first is arbitrary JSON and the second is a tool call.
        let mixed = concat!(
            "```json\n{\"status\": \"ok\"}\n```\n",
            "```json\n{\"name\": \"read\", \"parameters\": {\"path\": \"x\"}}\n```",
        );
        let c = text_reply(mixed, r#""stop""#);
        assert_eq!(c.finish, FinishReason::ToolCalls);
        assert_eq!(c.text, "```json\n{\"status\": \"ok\"}\n```");
        assert_eq!(c.tool_calls.len(), 1);
        assert_eq!(c.tool_calls[0].name, "read");
    }

    #[test]
    fn normal_prose_arbitrary_json_and_truncated_or_tool_replies_stay_untouched() {
        let untouched_cases = [
            "  Normal prose mentioning <invoke> and <tool_call> without valid call syntax. \n",
            "```json\n{\"status\": \"ok\", \"count\": 2}\n```\n",
            "```json\n{\"name\": \"alice\", \"role\": \"admin\"}\n```",
            "```json\n{\"name\": \"\", \"arguments\": {}}\n```",
            "```json\n{\"name\": \"bash\", \"arguments\": \"not-an-object\"}\n```",
            "Unfenced {\"name\": \"bash\", \"arguments\": {\"command\": \"ls\"}} in prose.",
            "```rust\nfn main() {}\n```",
        ];
        for text in untouched_cases {
            let c = text_reply(text, r#""stop""#);
            assert_eq!(c.finish, FinishReason::Stop, "{text}");
            assert!(c.tool_calls.is_empty(), "{text}");
            assert_eq!(c.text, text);
        }

        // FinishReason::Length skips text extraction.
        let leaked = "<tool_call>{\"name\": \"bash\", \"arguments\": {\"command\": \"ls\"}}</tool_call>";
        let c = text_reply(leaked, r#""length""#);
        assert_eq!(c.finish, FinishReason::Length);
        assert!(c.tool_calls.is_empty());
        assert_eq!(c.text, leaked);

        // Existing streamed tool calls prevent text extraction.
        let delta = serde_json::json!({ "content": leaked }).to_string();
        let c = run(&[
            &tc_chunk(r#"[{"index":0,"id":"A","function":{"name":"read","arguments":"{}"}}]"#),
            &chunk(&delta, r#""tool_calls""#),
        ])
        .unwrap();
        assert_eq!(c.tool_calls.len(), 1);
        assert_eq!(c.tool_calls[0].call_id.as_str(), "A");
        assert_eq!(c.text, leaked);
    }
}
