//! `pin` and `log_search`.
//!
//! CONTRACT (the `run` bodies are placeholders for the implementer; specs and types are fixed).
//!
//! Both read this session's log with `loom_core::log::read_records(&shared.log_path)`.
//!
//! ## `pin`
//! Resolve `handle` with `ctx.blobs.resolve` (failure → error ``There is no stored output {handle};
//! handles are the out:… ids in result headers.``). Find the newest `tool_result` record in the log
//! whose `output` blob id is that blob, or whose `meta[META_OF_BLOB]` names it; none → error
//! ``{handle} was not produced in this session, so it is not part of your context and cannot be
//! pinned.`` Then `shared.emit(Author::Model, Event::Pin { call_id, reason })`, or `Event::Unpin {
//! call_id }` when `unpin` is true. Outcome `pinned` / `unpinned`; text ``{handle} ({tool}) will stay
//! in view.`` / ``{handle} ({tool}) may be dropped from view again.``
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
use loom_core::event::{ToolClass, ToolSpec};
use loom_tools::params::{opt, req, spec};
use loom_tools::{Tool, ToolCtx, ToolOutput};
use serde_json::{json, Map, Value};
use std::sync::Arc;

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
        let _ = (ctx, args, &self.0);
        todo!("implement per module contract")
    }
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
        let _ = (ctx, args, &self.0);
        todo!("implement per module contract")
    }
}
