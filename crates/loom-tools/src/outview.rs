//! `out_read` and `out_grep`: looking at stored tool output again.
//!
//! CONTRACT.
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

use crate::{params, view, Body, Tool, ToolCtx, ToolOutput};
use async_trait::async_trait;
use loom_core::event::{ToolClass, ToolSpec};
use loom_core::BlobId;
use regex::Regex;
use serde_json::{Map, Value};

/// Longest line shown, in characters, by both tools.
const MAX_LINE_CHARS: usize = 20_000;
const DEFAULT_CONTEXT: u64 = 2;
const MAX_CONTEXT: u64 = 50;

pub struct OutRead;
pub struct OutGrep;

/// A non-negative integer argument, if present.
pub(crate) fn uint(args: &Map<String, Value>, key: &str) -> Option<u64> {
    let v = args.get(key)?;
    v.as_u64().or_else(|| v.as_i64().map(|n| u64::try_from(n).unwrap_or(0)))
}

/// A string argument, empty when absent.
pub(crate) fn string<'a>(args: &'a Map<String, Value>, key: &str) -> &'a str {
    args.get(key).and_then(Value::as_str).unwrap_or("")
}

/// Find the stored output a handle names, or say what to do about it.
fn resolve(ctx: &ToolCtx, handle: &str) -> Result<BlobId, String> {
    ctx.blobs.resolve(handle).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            format!("There is no stored output for the handle `{handle}`. Handles look like `out:1a2b3c4d` and appear in the header of a result; copy one exactly.")
        } else if e.to_string().contains("ambiguous") {
            format!("The handle `{handle}` matches more than one stored output. Give more characters of it; handles look like `out:1a2b3c4d`.")
        } else {
            format!("`{handle}` is not an output handle. Handles look like `out:1a2b3c4d` and appear in the header of a result; copy one exactly.")
        }
    })
}

/// Sorted ranges with overlapping or adjacent ones joined.
fn merge(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::new();
    for (a, b) in ranges {
        match out.last_mut() {
            Some(last) if a <= last.1.saturating_add(1) => last.1 = last.1.max(b),
            _ => out.push((a, b)),
        }
    }
    out
}

/// Shorten any line of an excerpt (`12: text`) that is longer than `MAX_LINE_CHARS`.
fn shorten_lines(excerpt: &str) -> String {
    let body = excerpt.strip_suffix('\n').unwrap_or(excerpt);
    let mut out = String::with_capacity(body.len());
    for (i, line) in body.split('\n').enumerate() {
        if i > 0 {
            out.push('\n');
        }
        match line.char_indices().nth(MAX_LINE_CHARS) {
            Some((cut, _)) => {
                let (head, rest) = line.split_at(cut);
                out.push_str(head);
                out.push_str(&format!("…[+{} chars]", rest.chars().count()));
            }
            None => out.push_str(line),
        }
    }
    out
}

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

    fn speculative(&self) -> bool {
        true
    }

    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let handle = string(args, "handle");
        let id = match resolve(ctx, handle) {
            Ok(id) => id,
            Err(e) => return ToolOutput::error(e),
        };
        let total = match ctx.blobs.meta(&id) {
            Ok(m) => m.lines,
            Err(e) => {
                return ToolOutput::error(format!(
                    "The output `{handle}` could not be read ({e}). Check the handle and try again."
                ))
            }
        };
        let (first, last) = match view::window(uint(args, "start"), uint(args, "end"), total, ctx.cfg.read_max_lines) {
            Ok(Some(w)) => w,
            Ok(None) => {
                return ToolOutput::ok("ok", Body::View { of: id, text: "(no output)".into(), shown: Vec::new() })
            }
            Err(e) => return ToolOutput::error(e),
        };
        let (text, shortened) = match view::numbered(&ctx.blobs, &id, first, last, MAX_LINE_CHARS) {
            Ok(r) => r,
            Err(e) => return ToolOutput::error(format!("The output `{handle}` could not be read ({e}). Try again.")),
        };
        let mut out = ToolOutput::ok("ok", Body::View { of: id, text, shown: vec![(first, last)] })
            .with_more(view::range_fact(first, last, total));
        if shortened > 0 {
            out = out.with_more(format!("{shortened} long lines shortened"));
        }
        out
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

    fn speculative(&self) -> bool {
        true
    }

    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let handle = string(args, "handle");
        let id = match resolve(ctx, handle) {
            Ok(id) => id,
            Err(e) => return ToolOutput::error(e),
        };
        let pattern = string(args, "pattern");
        let ignore_case = args.get("ignore_case").and_then(Value::as_bool).unwrap_or(false);
        let full = if ignore_case { format!("(?i){pattern}") } else { pattern.to_string() };
        let re = match Regex::new(&full) {
            Ok(re) => re,
            Err(e) => {
                return ToolOutput::error(format!(
                    "The pattern `{pattern}` is not a valid regular expression: {e}\nFix it (Rust/RE2 syntax; escape literal special characters with a backslash) and call `out_grep` again."
                ))
            }
        };
        let context = uint(args, "context").unwrap_or(DEFAULT_CONTEXT).min(MAX_CONTEXT);
        let total_lines = match ctx.blobs.meta(&id) {
            Ok(m) => m.lines,
            Err(e) => {
                return ToolOutput::error(format!(
                    "The output `{handle}` could not be read ({e}). Check the handle and try again."
                ))
            }
        };
        let found = match ctx.blobs.grep(&id, &re, context as usize, ctx.cfg.search_max_results) {
            Ok(r) => r,
            Err(e) => {
                return ToolOutput::error(format!("The output `{handle}` could not be searched ({e}). Try again."))
            }
        };
        if found.matches.is_empty() {
            return ToolOutput::ok(
                "no match",
                Body::View { of: id, text: "(no line matches)".into(), shown: Vec::new() },
            );
        }
        let ranges: Vec<(u64, u64)> = found
            .matches
            .iter()
            .map(|m| {
                (m.line.saturating_sub(context).max(1), m.line.saturating_add(context).min(total_lines.max(m.line)))
            })
            .collect();
        let groups: Vec<String> = found.matches.iter().map(|m| shorten_lines(&m.excerpt)).collect();
        let shown_count = found.matches.len() as u64;
        let mut out = ToolOutput::ok("ok", Body::View { of: id, text: groups.join("\n--\n"), shown: merge(ranges) })
            .with_more(format!("{shown_count} of {} matching lines", found.total_matches));
        if found.total_matches > shown_count {
            out = out.with_more("narrow the pattern or read ranges with out_read");
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{env, env_with};
    use loom_core::config::{SandboxCfg, SandboxMode, ToolsCfg};
    use loom_core::event::{META_OF_BLOB, META_SHOWN};
    use serde_json::json;

    fn small_pages() -> crate::testutil::TestEnv {
        env_with(
            ToolsCfg { read_max_lines: 10, search_max_results: 3, ..ToolsCfg::default() },
            SandboxCfg { mode: SandboxMode::None, ..SandboxCfg::default() },
        )
    }

    fn put(e: &crate::testutil::TestEnv, text: &str) -> String {
        e.ctx.blobs.put_bytes(text.as_bytes()).expect("put").handle()
    }

    fn lines(n: usize) -> String {
        (1..=n).map(|i| format!("line {i}\n")).collect()
    }

    fn shown(r: &loom_core::event::ToolResult) -> Value {
        r.meta.get(META_SHOWN).cloned().unwrap_or(Value::Null)
    }

    #[tokio::test]
    async fn paging_covers_every_line_once() {
        let e = small_pages();
        let h = put(&e, &lines(25));
        let mut seen: Vec<u64> = Vec::new();
        let mut start = 1u64;
        while start <= 25 {
            let r = e.call("out_read", json!({"handle": h, "start": start})).await;
            let ranges = shown(&r);
            let (a, b) = (ranges[0][0].as_u64().unwrap(), ranges[0][1].as_u64().unwrap());
            assert_eq!(ranges.as_array().unwrap().len(), 1);
            assert!(
                r.text.contains(&format!("{a}\tline {a}")) && r.text.contains(&format!("{b}\tline {b}")),
                "{}",
                r.text
            );
            seen.extend(a..=b);
            start = b + 1;
        }
        assert_eq!(seen, (1..=25).collect::<Vec<u64>>());
    }

    #[tokio::test]
    async fn read_clamps_and_reports_exact_range() {
        let e = small_pages();
        let h = put(&e, &lines(25));
        let r = e.call("out_read", json!({"handle": h, "start": 5, "end": 500})).await;
        assert_eq!(shown(&r), json!([[5, 14]]));
        assert!(r.text.contains("lines 5-14 of 25"), "{}", r.text);
        let r = e.call("out_read", json!({"handle": h, "start": 20, "end": 22})).await;
        assert_eq!(shown(&r), json!([[20, 22]]));
        assert_eq!(r.meta.get(META_OF_BLOB).and_then(Value::as_str).map(str::len), Some(64));
        assert!(!r.text.contains("23\t"), "{}", r.text);
    }

    #[tokio::test]
    async fn read_window_errors() {
        let e = small_pages();
        let h = put(&e, &lines(25));
        let r = e.call("out_read", json!({"handle": h, "start": 40})).await;
        assert!(r.text.contains("25 lines"), "{}", r.text);
        assert_eq!(r.status, loom_core::event::ToolStatus::Error);
        let r = e.call("out_read", json!({"handle": h, "start": 10, "end": 5})).await;
        assert!(r.text.contains("end line 5"), "{}", r.text);
    }

    #[tokio::test]
    async fn empty_output() {
        let e = env();
        let h = put(&e, "");
        let r = e.call("out_read", json!({"handle": h})).await;
        assert!(r.text.contains("(no output)"), "{}", r.text);
        assert_eq!(shown(&r), json!([]));
    }

    #[tokio::test]
    async fn unknown_and_malformed_handles() {
        let e = env();
        let r = e.call("out_read", json!({"handle": "out:deadbeef"})).await;
        assert_eq!(r.status, loom_core::event::ToolStatus::Error);
        assert!(r.text.contains("out:deadbeef") && r.text.contains("out:1a2b3c4d"), "{}", r.text);
        let r = e.call("out_grep", json!({"handle": "nonsense", "pattern": "x"})).await;
        assert!(r.text.contains("nonsense") && r.text.contains("out:1a2b3c4d"), "{}", r.text);
    }

    #[tokio::test]
    async fn long_lines_are_counted() {
        let e = env();
        let h = put(&e, &format!("short\n{}\n", "x".repeat(20_005)));
        let r = e.call("out_read", json!({"handle": h})).await;
        assert!(r.text.contains("1 long lines shortened") && r.text.contains("…[+5 chars]"), "{}", r.text);
    }

    #[tokio::test]
    async fn grep_with_context_and_exact_shown() {
        let e = env();
        let h = put(&e, &lines(30));
        let r = e.call("out_grep", json!({"handle": h, "pattern": "^line (10|20)$", "context": 1})).await;
        assert_eq!(shown(&r), json!([[9, 11], [19, 21]]));
        assert!(r.text.contains("9- line 9\n10: line 10\n11- line 11\n--\n19- line 19"), "{}", r.text);
        assert!(r.text.contains("2 of 2 matching lines"), "{}", r.text);
        // Default context is 2 and overlapping contexts merge into one range.
        let r = e.call("out_grep", json!({"handle": h, "pattern": "^line (10|13)$"})).await;
        assert_eq!(shown(&r), json!([[8, 15]]));
        // Context is clamped at the ends of the output.
        let r = e.call("out_grep", json!({"handle": h, "pattern": "^line 1$", "context": 50})).await;
        assert_eq!(shown(&r), json!([[1, 30]]));
        let r = e.call("out_grep", json!({"handle": h, "pattern": "^line 30$", "context": 500})).await;
        assert_eq!(shown(&r), json!([[1, 30]]));
    }

    #[tokio::test]
    async fn grep_cap_ignore_case_no_match_and_bad_pattern() {
        let e = small_pages();
        let h = put(&e, &lines(30));
        let r = e.call("out_grep", json!({"handle": h, "pattern": "LINE 1", "ignore_case": true, "context": 0})).await;
        assert!(
            r.text.contains("3 of 11 matching lines")
                && r.text.contains("narrow the pattern or read ranges with out_read"),
            "{}",
            r.text
        );
        assert_eq!(shown(&r), json!([[1, 1], [10, 11]]));
        let r = e.call("out_grep", json!({"handle": h, "pattern": "LINE 1", "context": 0})).await;
        assert!(r.text.contains("no match") && r.text.contains("(no line matches)"), "{}", r.text);
        assert_eq!(shown(&r), json!([]));
        let r = e.call("out_grep", json!({"handle": h, "pattern": "(unclosed"})).await;
        assert_eq!(r.status, loom_core::event::ToolStatus::Error);
        assert!(r.text.contains("(unclosed") && r.text.contains("regular expression"), "{}", r.text);
    }
}
