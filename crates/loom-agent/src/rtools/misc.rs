//! `pin` and `log_search`.
//!
//! CONTRACT.
//!
//! Both read this session's log with `loom_core::log::read_records(&shared.log_path)`.
//!
//! ## `pin`
//! Resolve `handle` with `ctx.blobs.resolve` (failure → error ``There is no stored output {handle};
//! handles are the out:… ids in result headers.``). Find every `tool_result` record in the log
//! whose `output` blob id is that blob, or whose `meta[META_OF_BLOB]` names it (the call that
//! produced the output and every later view of it); none → error ``{handle} was not produced in this
//! session, so it is not part of your context and cannot be pinned.`` Then, for each of them in log
//! order (one per call id), `shared.emit(Author::Model, Event::Pin { call_id, reason })`, or
//! `Event::Unpin { call_id }` when `unpin` is true: everything the session has been shown of that
//! output stays in view. `{tool}` below is the tool of the first of them. Outcome `pinned` /
//! `unpinned`; text ``{handle} ({tool}) will stay in view.`` / ``{handle} ({tool}) may be dropped
//! from view again.``
//!
//! ## `log_search`
//! Compile `pattern` (`regex`, case-sensitive; an invalid pattern → error with the regex error and
//! `Nothing was searched.`). Walk the records in order and collect matches, each one line:
//! - `user_message` → `#{seq} user: {line}`
//! - `harness_note` → `#{seq} harness {kind}: {line}`
//! - `model_response` text (never reasoning) → `#{seq} you: {line}`
//! - `tool_call` → `#{seq} call {name}: {arguments as compact JSON}` when the JSON text matches
//! - `tool_result` with a stored `output` → `ctx.blobs.grep(id, &re, 0, cap)`: one line per match
//!   `#{seq} {handle} line {n}: {excerpt}`; without a stored output, its `text` line by line →
//!   `#{seq} result {name}: {line}`
//! - `child_settled` → `#{seq} agent {child}: {line}`
//!
//! `in` narrows it: `messages` = user, harness, you, agent; `calls` = tool calls; `outputs` = tool
//! results; `all` (default) = everything. Each line is cut to 300 characters with `…`. At most `max`
//! lines are returned, the newest ones, in log order; the first line of the body is always
//! `{total} matching lines in {records} records` followed, when cut, by `; showing the newest {max}`.
//! When nothing matches: `No match for /{pattern}/ in {records} records of this session.` The output
//! is `ToolOutput::ok(outcome, Body::Raw(bytes))` with outcome `{total} matches` (so it is stored
//! and can be paged like any other output).
//!
//! Tests required: `pin` and `unpin` emit the right record for a stored output and for a view of
//! one; unknown handle; an output from elsewhere; `log_search` over a hand-built log covering every
//! record kind, the `in` filter, the cap and its header, line cutting, no match, invalid pattern.

use super::Shared;
use async_trait::async_trait;
use loom_core::event::{Author, Event, ToolClass, ToolSpec, META_OF_BLOB};
use loom_core::log::read_records;
use loom_tools::params::{opt, req, spec};
use loom_tools::{Body, Tool, ToolCtx, ToolOutput};
use regex::Regex;
use serde_json::{json, Map, Value};
use std::sync::Arc;

/// Longest line `log_search` returns, in characters (the cut included).
const LINE_CHARS: usize = 300;
/// Most matches taken from one stored output, so that "the newest" is not decided by a tiny `max`.
const PER_OUTPUT_CAP: usize = 2_000;

pub struct Pin(pub Arc<Shared>);
pub struct LogSearch(pub Arc<Shared>);

#[async_trait]
impl Tool for Pin {
    fn spec(&self) -> ToolSpec {
        spec(
            "pin",
            "Keep a tool output in view for the rest of the session. Pin what you will need to look at again: the output of a failing test, a file the whole task turns on. `handle` is the out:… id in the result's header. `unpin: true` releases it.",
            ToolClass::State,
            &[
                req("handle", "string", "The stored output, for example out:7f3a9c1e."),
                req("reason", "string", "Why it has to stay in view."),
                opt("unpin", "boolean", "true to release an output pinned earlier.").default(json!(false)),
            ],
        )
    }
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let handle = args.get("handle").and_then(Value::as_str).unwrap_or("");
        let reason = args.get("reason").and_then(Value::as_str).unwrap_or("").to_string();
        let unpin = args.get("unpin").and_then(Value::as_bool).unwrap_or(false);
        let Ok(blob) = ctx.blobs.resolve(handle) else {
            return ToolOutput::error(format!(
                "There is no stored output {handle}; handles are the out:… ids in result headers."
            ));
        };
        let report = match read_records(&self.0.log_path) {
            Ok(r) => r,
            Err(e) => return ToolOutput::error(log_fault(&e)),
        };
        // The call that produced the output and every view of it, in log order, one per call id.
        let mut shown: Vec<(loom_core::CallId, String)> = Vec::new();
        for rec in &report.records {
            if let Event::ToolResult(tr) = &rec.event {
                let own = tr.output.as_ref().is_some_and(|o| o.id == blob);
                let of = tr.meta.get(META_OF_BLOB).and_then(Value::as_str).is_some_and(|id| id == blob.as_str());
                if (own || of) && !shown.iter().any(|(id, _)| *id == tr.call_id) {
                    shown.push((tr.call_id.clone(), tr.name.clone()));
                }
            }
        }
        let Some(tool) = shown.first().map(|(_, name)| name.clone()) else {
            return ToolOutput::error(format!(
                "{handle} was not produced in this session, so it is not part of your context and cannot be pinned."
            ));
        };
        for (call_id, _) in shown {
            if unpin {
                self.0.emit(Author::Model, Event::Unpin { call_id });
            } else {
                self.0.emit(Author::Model, Event::Pin { call_id, reason: reason.clone() });
            }
        }
        if unpin {
            ToolOutput::ok("unpinned", Body::Message(format!("{handle} ({tool}) may be dropped from view again.")))
        } else {
            ToolOutput::ok("pinned", Body::Message(format!("{handle} ({tool}) will stay in view.")))
        }
    }
}

fn log_fault(e: &loom_core::log::LogError) -> String {
    format!("This session's log could not be read ({e}). This is a harness fault, not a problem with the call.")
}

/// `line` cut to [`LINE_CHARS`] characters, ending in `…` when it was cut.
fn cut(line: &str) -> String {
    if line.chars().count() <= LINE_CHARS {
        return line.to_string();
    }
    let mut out: String = line.chars().take(LINE_CHARS.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Which parts of the record a search covers.
#[derive(Clone, Copy)]
struct Scope {
    messages: bool,
    calls: bool,
    outputs: bool,
}

#[async_trait]
impl Tool for LogSearch {
    fn spec(&self) -> ToolSpec {
        spec(
            "log_search",
            "Search the complete record of this session for a regular expression: every message, every call you made and every output — including anything that is no longer in view. Matches in tool output come with the out:… handle and line number, which `out_read` opens.",
            ToolClass::Nav,
            &[
                req("pattern", "string", "A regular expression (Rust regex syntax, case-sensitive; prefix (?i) to ignore case)."),
                opt("in", "string", "Which part of the record to search.").one_of(&["all", "messages", "calls", "outputs"]).default(json!("all")),
                opt("max", "integer", "The most lines to return.").min(1).max(500).default(json!(60)),
            ],
        )
    }
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let pattern = args.get("pattern").and_then(Value::as_str).unwrap_or("");
        let max = args.get("max").and_then(Value::as_u64).unwrap_or(60).clamp(1, 500) as usize;
        let scope = match args.get("in").and_then(Value::as_str).unwrap_or("all") {
            "messages" => Scope { messages: true, calls: false, outputs: false },
            "calls" => Scope { messages: false, calls: true, outputs: false },
            "outputs" => Scope { messages: false, calls: false, outputs: true },
            _ => Scope { messages: true, calls: true, outputs: true },
        };
        let re = match Regex::new(pattern) {
            Ok(re) => re,
            Err(e) => {
                return ToolOutput::error(format!(
                    "The pattern is not a valid regular expression: {e}\nNothing was searched."
                ))
            }
        };
        let report = match read_records(&self.0.log_path) {
            Ok(r) => r,
            Err(e) => return ToolOutput::error(log_fault(&e)),
        };

        let mut lines: Vec<String> = Vec::new();
        // Matches beyond what was collected (a stored output with more matching lines than the cap).
        let mut uncollected: u64 = 0;
        for rec in &report.records {
            let seq = rec.seq;
            match &rec.event {
                Event::UserMessage { text } if scope.messages => {
                    push_text_matches(&mut lines, &re, text, |l| format!("#{seq} user: {l}"));
                }
                Event::HarnessNote { note, text } if scope.messages => {
                    let kind = serde_json::to_value(note)
                        .ok()
                        .and_then(|v| v.as_str().map(str::to_string))
                        .unwrap_or_default();
                    push_text_matches(&mut lines, &re, text, |l| format!("#{seq} harness {kind}: {l}"));
                }
                Event::ModelResponse(resp) if scope.messages => {
                    push_text_matches(&mut lines, &re, &resp.text, |l| format!("#{seq} you: {l}"));
                }
                Event::ChildSettled(done) if scope.messages => {
                    let child = &done.child;
                    push_text_matches(&mut lines, &re, &done.report, |l| format!("#{seq} agent {child}: {l}"));
                }
                Event::ToolCall(call) if scope.calls => {
                    let json_text = serde_json::to_string(&call.args).unwrap_or_default();
                    if re.is_match(&json_text) {
                        lines.push(cut(&format!("#{seq} call {}: {json_text}", call.name)));
                    }
                }
                Event::ToolResult(tr) if scope.outputs => match &tr.output {
                    Some(out) => {
                        let Ok(found) = ctx.blobs.grep(&out.id, &re, 0, max.max(PER_OUTPUT_CAP)) else { continue };
                        let handle = out.handle();
                        for m in &found.matches {
                            let prefix = format!("{}: ", m.line);
                            let body = m.excerpt.trim_end_matches('\n');
                            let body = body.strip_prefix(&prefix).unwrap_or(body);
                            lines.push(cut(&format!("#{seq} {handle} line {}: {body}", m.line)));
                        }
                        uncollected =
                            uncollected.saturating_add(found.total_matches.saturating_sub(found.matches.len() as u64));
                    }
                    None => {
                        let name = &tr.name;
                        push_text_matches(&mut lines, &re, &tr.text, |l| format!("#{seq} result {name}: {l}"));
                    }
                },
                _ => {}
            }
        }

        let records = report.records.len();
        let total = (lines.len() as u64).saturating_add(uncollected);
        if total == 0 {
            return ToolOutput::ok(
                "0 matches",
                Body::Message(format!("No match for /{pattern}/ in {records} records of this session.")),
            );
        }
        let skip = lines.len().saturating_sub(max);
        let mut text = format!("{total} matching lines in {records} records");
        if total > max as u64 {
            text.push_str(&format!("; showing the newest {max}"));
        }
        for line in lines.iter().skip(skip) {
            text.push('\n');
            text.push_str(line);
        }
        text.push('\n');
        ToolOutput::ok(format!("{total} matches"), Body::Raw(text.into_bytes()))
    }
}

/// One output line per line of `text` that matches, formatted by `fmt`, cut to the line limit.
fn push_text_matches(out: &mut Vec<String>, re: &Regex, text: &str, fmt: impl Fn(&str) -> String) {
    for line in text.lines().filter(|l| re.is_match(l)) {
        out.push(cut(&fmt(line)));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::super::testkit::{rig, Rig};
    use loom_core::event::{
        Author, ChildOutcome, ChildSettled, Event, NoteKind, ToolCall, ToolClass, ToolResult, ToolStatus,
    };
    use loom_core::log::{Durability, SessionLog};
    use loom_core::{BlobRef, CallId, SessionId};
    use serde_json::{json, Map, Value};

    fn result(call: &str, name: &str, text: &str, output: Option<BlobRef>, meta: Map<String, Value>) -> Event {
        Event::ToolResult(ToolResult {
            call_id: CallId::from(call),
            name: name.into(),
            status: ToolStatus::Ok,
            text: text.into(),
            output,
            cut: false,
            class: ToolClass::Exec,
            meta,
            duration_ms: 1,
        })
    }

    fn call(id: &str, name: &str, args: Value) -> Event {
        Event::ToolCall(ToolCall {
            call_id: CallId::from(id),
            req_id: "r1".into(),
            name: name.into(),
            args,
            class: ToolClass::Exec,
        })
    }

    fn response(text: &str, reasoning: &str) -> Event {
        serde_json::from_value(json!({
            "kind": "model_response", "req_id": "r1", "text": text, "reasoning": reasoning, "finish": "stop"
        }))
        .expect("model response")
    }

    /// A log with one record of every kind `log_search` reads. Returns the blob of call c1's output.
    fn build(rig: &Rig) -> BlobRef {
        let blob =
            rig.env.ctx.blobs.put_bytes(b"compiling\nerror: needle in output\nwarning: none\nneedle again\n").unwrap();
        let mut log = SessionLog::create(&rig.shared.log_path, Durability::Batch).unwrap();
        let mut put = |author: Author, event: Event| {
            log.append(author, event).unwrap();
        };
        put(Author::User, Event::UserMessage { text: "please find the needle\nsecond line".into() });
        put(Author::Harness, Event::HarnessNote { note: NoteKind::Nudge, text: "needle still open".into() });
        put(Author::Model, response("I will look for the needle", "secret needle reasoning"));
        put(Author::Model, call("c1", "bash", json!({"command": "grep needle src"})));
        put(Author::Tool, result("c1", "bash", "exit 1", Some(blob.clone()), Map::new()));
        put(Author::Model, call("c2", "out_read", json!({"handle": "x"})));
        let mut meta = Map::new();
        meta.insert(loom_core::event::META_OF_BLOB.into(), json!(blob.id.as_str()));
        put(Author::Tool, result("c2", "out_read", "view of the output", None, meta));
        put(Author::Tool, result("c3", "agent_spawn", "inline needle result\nother", None, Map::new()));
        put(
            Author::Agent(SessionId::from("s-kid")),
            Event::ChildSettled(ChildSettled {
                child: SessionId::from("s-kid"),
                outcome: ChildOutcome::Returned,
                report: "found a needle".into(),
                full: None,
                usage: Default::default(),
                steps: 1,
                inline: false,
            }),
        );
        blob
    }

    async fn search(rig: &Rig, args: Value) -> (ToolStatus, String) {
        let r = rig.call("log_search", args).await;
        let text = match &r.output {
            Some(o) => String::from_utf8(rig.env.ctx.blobs.read_all(&o.id).unwrap()).unwrap(),
            None => r.text.clone(),
        };
        (r.status, text)
    }

    #[tokio::test]
    async fn pin_and_unpin_for_output_and_view() {
        let rig = rig("lead", false, true);
        let blob = build(&rig);
        let h = blob.handle();
        let r = rig.call("pin", json!({"handle": h, "reason": "the failing run"})).await;
        assert_eq!(r.status, ToolStatus::Ok, "{}", r.text);
        assert!(r.text.contains(&format!("{h} (bash) will stay in view.")), "{}", r.text);
        // The call that produced the output (c1) and the later view of it (c2) are both pinned.
        let emitted = rig.shared.take_emitted();
        assert_eq!(
            emitted,
            vec![
                (Author::Model, Event::Pin { call_id: CallId::from("c1"), reason: "the failing run".into() }),
                (Author::Model, Event::Pin { call_id: CallId::from("c2"), reason: "the failing run".into() }),
            ]
        );

        let r = rig.call("pin", json!({"handle": h, "reason": "done", "unpin": true})).await;
        assert!(r.text.contains("may be dropped from view again."), "{}", r.text);
        assert_eq!(
            rig.shared.take_emitted(),
            vec![
                (Author::Model, Event::Unpin { call_id: CallId::from("c1") }),
                (Author::Model, Event::Unpin { call_id: CallId::from("c2") }),
            ]
        );
    }

    #[tokio::test]
    async fn pin_stored_output_without_a_later_view() {
        let rig = rig("lead", false, true);
        let blob = rig.env.ctx.blobs.put_bytes(b"only here\n").unwrap();
        let mut log = SessionLog::create(&rig.shared.log_path, Durability::Batch).unwrap();
        log.append(Author::Tool, result("c9", "bash", "only here", Some(blob.clone()), Map::new())).unwrap();
        let r = rig.call("pin", json!({"handle": blob.handle(), "reason": "r"})).await;
        assert_eq!(r.status, ToolStatus::Ok, "{}", r.text);
        assert_eq!(
            rig.shared.take_emitted(),
            vec![(Author::Model, Event::Pin { call_id: CallId::from("c9"), reason: "r".into() })]
        );
    }

    #[tokio::test]
    async fn pin_refusals() {
        let rig = rig("lead", false, true);
        build(&rig);
        let r = rig.call("pin", json!({"handle": "out:0123456789abcdef", "reason": "r"})).await;
        assert_eq!(r.status, ToolStatus::Error);
        assert!(
            r.text.contains(
                "There is no stored output out:0123456789abcdef; handles are the out:… ids in result headers."
            ),
            "{}",
            r.text
        );

        let elsewhere = rig.env.ctx.blobs.put_bytes(b"from another session\n").unwrap();
        let r = rig.call("pin", json!({"handle": elsewhere.handle(), "reason": "r"})).await;
        assert_eq!(r.status, ToolStatus::Error);
        assert!(r.text.contains("was not produced in this session"), "{}", r.text);
        assert!(rig.shared.take_emitted().is_empty());
    }

    #[tokio::test]
    async fn search_covers_every_record_kind() {
        let rig = rig("lead", false, true);
        let blob = build(&rig);
        let h = blob.handle();
        let (status, text) = search(&rig, json!({"pattern": "needle"})).await;
        assert_eq!(status, ToolStatus::Ok);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "8 matching lines in 9 records", "{text}");
        let want = [
            "#0 user: please find the needle",
            "#1 harness nudge: needle still open",
            "#2 you: I will look for the needle",
            "#3 call bash: {\"command\":\"grep needle src\"}",
            &format!("#4 {h} line 2: error: needle in output"),
            &format!("#4 {h} line 4: needle again"),
            "#7 result agent_spawn: inline needle result",
            "#8 agent s-kid: found a needle",
        ];
        assert_eq!(&lines[1..], &want, "{text}");
        assert!(!text.contains("secret"), "reasoning is never searched");
    }

    #[tokio::test]
    async fn search_in_filters() {
        let rig = rig("lead", false, true);
        build(&rig);
        let (_, text) = search(&rig, json!({"pattern": "needle", "in": "messages"})).await;
        assert!(text.starts_with("4 matching lines in 9 records"), "{text}");
        assert!(text.contains("#8 agent") && !text.contains(" call ") && !text.contains("line 2"), "{text}");
        let (_, text) = search(&rig, json!({"pattern": "needle", "in": "calls"})).await;
        assert!(text.starts_with("1 matching lines in 9 records"), "{text}");
        let (_, text) = search(&rig, json!({"pattern": "needle", "in": "outputs"})).await;
        assert!(text.starts_with("3 matching lines"), "{text}");
        assert!(!text.contains("user:") && !text.contains("call bash"), "{text}");
    }

    #[tokio::test]
    async fn search_cap_keeps_the_newest_and_says_so() {
        let rig = rig("lead", false, true);
        build(&rig);
        let (_, text) = search(&rig, json!({"pattern": "needle", "max": 2})).await;
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "8 matching lines in 9 records; showing the newest 2", "{text}");
        assert_eq!(lines.len(), 3);
        assert!(lines[1].starts_with("#7 result agent_spawn"), "{text}");
        assert!(lines[2].starts_with("#8 agent"), "{text}");
    }

    #[tokio::test]
    async fn search_cuts_long_lines() {
        let rig = rig("lead", false, true);
        let mut log = SessionLog::create(&rig.shared.log_path, Durability::Batch).unwrap();
        let long = format!("start {} end", "é".repeat(500));
        log.append(Author::User, Event::UserMessage { text: long }).unwrap();
        let (_, text) = search(&rig, json!({"pattern": "start"})).await;
        let line = text.lines().nth(1).unwrap();
        assert_eq!(line.chars().count(), 300);
        assert!(line.ends_with('…'));
    }

    #[tokio::test]
    async fn search_without_match_and_with_bad_pattern() {
        let rig = rig("lead", false, true);
        build(&rig);
        let (status, text) = search(&rig, json!({"pattern": "zebra"})).await;
        assert_eq!(status, ToolStatus::Ok);
        assert!(text.contains("No match for /zebra/ in 9 records of this session."), "{text}");
        // Case-sensitive.
        let (_, text) = search(&rig, json!({"pattern": "NEEDLE"})).await;
        assert!(text.contains("No match for /NEEDLE/"), "{text}");
        let (_, text) = search(&rig, json!({"pattern": "(?i)NEEDLE", "max": 1})).await;
        assert!(text.starts_with("8 matching lines"), "{text}");

        let (status, text) = search(&rig, json!({"pattern": "(unclosed"})).await;
        assert_eq!(status, ToolStatus::Error);
        assert!(text.contains("Nothing was searched."), "{text}");
    }
}
