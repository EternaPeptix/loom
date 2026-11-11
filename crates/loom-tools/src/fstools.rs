//! `read`, `write`, `edit`.
//!
//! CONTRACT (bodies of `run` are placeholders for the implementer; `spec` is fixed).
//!
//! Paths: `ctx.sandbox.resolve(path)`, then `check_read` / `check_write`; a refusal is a `denied`
//! result carrying the sandbox's sentence. Every result has meta `META_PATH` = the resolved path.
//!
//! ## `read`
//! A directory → error sentence suggesting `glob`. A missing file → error sentence; when files with
//! a similar name exist in the same directory (edit distance ≤ 2, or same name ignoring case), name
//! up to 3 of them. Otherwise: read the bytes, `ctx.files.note`, `view::store_text`, then exactly as
//! `out_read` (window with `cfg.read_max_lines`, numbered lines, `max_line_chars` 20_000) and return
//! `Body::View` of the stored text. Facts: the path as given, `view::range_fact`, the normalisation
//! notes when there are any. Binary content: the body is the one-line description from `normalize`.
//! An empty file: body `(empty file)`.
//!
//! ## `write`
//! `ctx.files.check`: `Unread` → error: the file exists and has not been read in this session — read
//! it first, or use `edit`; `Changed` → error: it changed on disk since it was read ({was} → {now}
//! bytes) — read it again. `Missing`/`Current` → write atomically (temp file in the same directory,
//! `sync_data`, rename; parent directories are created; the existing file's permissions are kept),
//! then `ctx.files.note`. Result: outcome `created` or `replaced`; facts: path, `{lines} lines`,
//! `{bytes} bytes`; for `replaced` the body is the unified diff (3 lines of context, `similar`
//! crate) of old → new as `Body::Raw`, so a long diff is stored and admitted like any output; for
//! `created` the body is `Body::Message("(new file)")`. Content is written byte-for-byte as given.
//!
//! ## `edit`
//! Freshness as for `write`, and `Missing` is an error. `old` empty, or `old == new` → error.
//! Count occurrences of `old` in the file text:
//! - exactly one, or `all` → replace, write atomically, note. Outcome `edited`; facts: path,
//!   `{n} replacement(s)`; body: the unified diff (3 lines of context) as `Body::Raw`.
//! - more than one without `all` → error: how many, the line number of each (first 10), and that
//!   `old` must be extended with surrounding lines or `all` set.
//! - none → error that helps the next attempt: if `old` matches after ignoring leading/trailing
//!   whitespace on each line, say so and show those file lines, numbered, exactly as they are in the
//!   file; else if the first line of `old` (trimmed) occurs in the file, show the numbered lines
//!   around its first occurrence (as many lines as `old` has, plus 2 either side); else say that
//!   nothing similar was found and that the file has N lines. Never guess and apply.
//! A file that is not valid UTF-8 → error (binary files are not edited).
//!
//! Tests required: read whole / range / past the end / missing with suggestion / directory / binary;
//! read then write then read round trip preserves bytes exactly (CRLF, no trailing newline,
//! unicode); write refusals (unread, changed) and acceptance after a read; atomicity leaves no temp
//! file; permissions kept; diff shown; edit unique / all / ambiguous / each no-match hint;
//! sandbox denial for read and write; `shown` ranges of read are exact.

use crate::{params, Tool, ToolCtx, ToolOutput};
use async_trait::async_trait;
use loom_core::event::{ToolClass, ToolSpec};
use serde_json::{Map, Value};

pub struct Read;
pub struct Write;
pub struct Edit;

#[async_trait]
impl Tool for Read {
    fn spec(&self) -> ToolSpec {
        params::spec(
            "read",
            "Read a text file. Lines are returned numbered as `N<TAB>text`. Without `start`/`end` you get the file from line 1, up to the number of lines one call returns; the result header says which lines you were shown and how many the file has, so you know whether there is more to read.",
            ToolClass::Read,
            &[
                params::req("path", "string", "Path of the file (absolute, or relative to the workspace)."),
                params::opt("start", "integer", "First line to show (default 1).").min(1),
                params::opt("end", "integer", "Last line to show."),
            ],
        )
    }

    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let _ = (ctx, args);
        todo!("implement per module contract")
    }
}

#[async_trait]
impl Tool for Write {
    fn spec(&self) -> ToolSpec {
        params::spec(
            "write",
            "Create a file, or replace the whole content of an existing one. To replace an existing file you must have read it in this session, and it must not have changed since. The result shows what changed. To change part of a file, use `edit` instead.",
            ToolClass::Write,
            &[
                params::req("path", "string", "Path of the file (absolute, or relative to the workspace)."),
                params::req("content", "string", "The complete new content of the file."),
            ],
        )
    }

    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let _ = (ctx, args);
        todo!("implement per module contract")
    }
}

#[async_trait]
impl Tool for Edit {
    fn spec(&self) -> ToolSpec {
        params::spec(
            "edit",
            "Replace text in a file. `old` must be copied exactly from the file (same indentation and line breaks, without the line-number prefix that `read` shows) and must occur exactly once, unless `all` is true. You must have read the file in this session. The result shows the change as a diff; if `old` is not found, the result shows the closest text in the file.",
            ToolClass::Write,
            &[
                params::req("path", "string", "Path of the file (absolute, or relative to the workspace)."),
                params::req("old", "string", "The exact text to replace."),
                params::req("new", "string", "The text to put in its place."),
                params::opt("all", "boolean", "Replace every occurrence of `old` (default false)."),
            ],
        )
    }

    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let _ = (ctx, args);
        todo!("implement per module contract")
    }
}
