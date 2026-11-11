//! `out_read` and `out_grep`: looking at stored tool output again.
//!
//! CONTRACT (bodies of `run` are placeholders for the implementer; `spec` is fixed).
//!
//! Both resolve `handle` with `BlobStore::resolve` (an unknown or ambiguous handle is an error
//! sentence that repeats the handle and says handles look like `out:1a2b3c4d`), and return
//! `Body::View` so the record states exactly which stored lines the text contains.
//!
//! `out_read`: `view::window(start, end, total, cfg.read_max_lines)`, then `view::numbered` with
//! `max_line_chars` 20_000. Outcome `ok`; facts: `view::range_fact`, and `{k} long lines shortened`
//! when any were. An empty output has the body `(no output)`.
//!
//! `out_grep`: `BlobStore::grep` with `context` (default 2, at most 50) and at most
//! `cfg.search_max_results` matches; an invalid pattern is an error sentence carrying the regex
//! error. Body: each match excerpt as returned by the store (lines numbered), groups separated by a
//! line `--`. Facts: `{shown} of {total} matching lines` and, when more matched than shown, `narrow
//! the pattern or read ranges with out_read`. No match → outcome `no match`, body `(no line
//! matches)`, and `shown` empty. `shown` covers every line present in the body (matches and
//! context). `ignore_case` prefixes the pattern with `(?i)`.
//!
//! Tests required: paging through an output larger than one page covers every line exactly once;
//! clamping and both `window` errors; unknown handle; grep with context, cap, no match, invalid
//! pattern; `shown` ranges are exact.

use crate::{params, Tool, ToolCtx, ToolOutput};
use async_trait::async_trait;
use loom_core::event::{ToolClass, ToolSpec};
use serde_json::{json, Map, Value};

pub struct OutRead;
pub struct OutGrep;

#[async_trait]
impl Tool for OutRead {
    fn spec(&self) -> ToolSpec {
        params::spec(
            "out_read",
            "Read lines of a stored tool output by its handle (the `out:…` id in a result header). Use it to see the part of a long output that was not shown, or to look at an earlier output again. Lines are numbered `N<TAB>text`.",
            ToolClass::Read,
            &[
                params::req("handle", "string", "The output's handle, e.g. `out:7f3a9c1e`."),
                params::opt("start", "integer", "First line to show (default 1).").min(1),
                params::opt("end", "integer", "Last line to show (default: as many lines as one call returns)."),
            ],
        )
    }

    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let _ = (ctx, args, json!(null));
        todo!("implement per module contract")
    }
}

#[async_trait]
impl Tool for OutGrep {
    fn spec(&self) -> ToolSpec {
        params::spec(
            "out_grep",
            "Search a stored tool output for a regular expression and show the matching lines with their line numbers and some context. Use it to find something in a long output without reading all of it.",
            ToolClass::Nav,
            &[
                params::req("handle", "string", "The output's handle, e.g. `out:7f3a9c1e`."),
                params::req("pattern", "string", "Regular expression (Rust/RE2 syntax), matched against single lines."),
                params::opt("context", "integer", "Lines of context before and after each match (default 2).").min(0),
                params::opt("ignore_case", "boolean", "Match case-insensitively (default false)."),
            ],
        )
    }

    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let _ = (ctx, args);
        todo!("implement per module contract")
    }
}
