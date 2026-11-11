//! `glob` and `grep`: both search the same set of files.
//!
//! CONTRACT (bodies of `run` are placeholders for the implementer; `spec` is fixed).
//!
//! ## The file set
//! Walk `path` (default: the workspace; `ctx.sandbox.resolve` + `check_read`; a file is allowed and
//! is then the only member) with the `ignore` crate: `.gitignore`/`.ignore`/global git excludes are
//! respected and hidden files skipped, unless `no_ignore` / `hidden` are set; `.git` directories are
//! always skipped; symlinks are not followed; entries the sandbox makes unreadable are skipped. The
//! walk runs on a blocking thread and stops early when `ctx.cancel` fires (result status
//! `Interrupted`, with what was found so far).
//!
//! ## `glob`
//! `pattern` is matched (`globset`, `literal_separator` on, so `*` does not cross `/`) against each
//! file's path relative to the search root; a pattern without `/` also matches against the file
//! name alone (`*.rs` finds files at any depth). Output: one relative path per line, most recently
//! modified first (ties by path), as `Body::Raw` — so a long list is stored whole and admitted.
//! Outcome `{n} files`; with no match: outcome `no match` and a body that says how many files were
//! searched and, when `hidden`/`no_ignore` were not set and would have changed the result, how many
//! more match with them.
//!
//! ## `grep`
//! `pattern` is a regex (`regex` crate; `ignore_case` → case-insensitive) matched per line. `glob`
//! filters files as above. Files that are binary (a NUL in the first 8 KiB) or not valid UTF-8 are
//! skipped and counted. Files are visited in path order. Output as `Body::Raw`:
//! - default: `path:line:text` per match; with `context` > 0 (at most 20), context lines are
//!   `path-line-text` and groups are separated by `--`;
//! - `files_only`: one path per line with its match count, `path (n)`.
//! Lines longer than 2000 characters are shown as the 2000 characters around the first match with
//! `…` at the cut ends. Outcome `{m} matches in {f} files`; facts: `{k} binary files skipped` when
//! any; `no match` handled as for `glob`. An invalid regex or glob is an error sentence carrying the
//! library's message.
//!
//! Tests required: the same tree searched by both tools yields the same file set under each
//! combination of `hidden` and `no_ignore`; `.git` always skipped; gitignore respected; glob
//! matching rules (basename vs path, `**`); newest-first order; grep output formats, context
//! grouping, `files_only`, binary skip, long-line windowing on multi-byte text; no-match messages
//! with the "would match with hidden/no_ignore" count; invalid patterns; a single file as `path`;
//! sandbox-unreadable entries skipped; cancellation.

use crate::{params, Tool, ToolCtx, ToolOutput};
use async_trait::async_trait;
use loom_core::event::{ToolClass, ToolSpec};
use serde_json::{Map, Value};

pub struct Glob;
pub struct Grep;

#[async_trait]
impl Tool for Glob {
    fn spec(&self) -> ToolSpec {
        params::spec(
            "glob",
            "List files whose path matches a glob pattern, most recently modified first. Examples: `*.rs` (any depth), `src/**/*.py`, `**/test_*`. Files ignored by git and hidden files are left out unless you ask for them. The header says how many files matched.",
            ToolClass::Nav,
            &[
                params::req("pattern", "string", "Glob pattern, matched against paths relative to `path`."),
                params::opt("path", "string", "Directory to search (default: the workspace)."),
                params::opt("hidden", "boolean", "Include hidden files and directories (default false)."),
                params::opt("no_ignore", "boolean", "Include files that .gitignore excludes (default false)."),
            ],
        )
    }

    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let _ = (ctx, args);
        todo!("implement per module contract")
    }
}

#[async_trait]
impl Tool for Grep {
    fn spec(&self) -> ToolSpec {
        params::spec(
            "grep",
            "Search the contents of files for a regular expression. Each match is shown as `path:line:text`. Searches the same files as `glob` (git-ignored and hidden files are left out unless you ask for them). The header says how many matches were found in how many files.",
            ToolClass::Nav,
            &[
                params::req("pattern", "string", "Regular expression (Rust/RE2 syntax), matched against single lines."),
                params::opt("path", "string", "File or directory to search (default: the workspace)."),
                params::opt("glob", "string", "Only search files matching this glob, e.g. `*.ts`."),
                params::opt("context", "integer", "Lines of context to show before and after each match (default 0).").min(0),
                params::opt("ignore_case", "boolean", "Match case-insensitively (default false)."),
                params::opt("files_only", "boolean", "Show only the paths of files with matches, with a count each (default false)."),
                params::opt("hidden", "boolean", "Include hidden files and directories (default false)."),
                params::opt("no_ignore", "boolean", "Include files that .gitignore excludes (default false)."),
            ],
        )
    }

    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let _ = (ctx, args);
        todo!("implement per module contract")
    }
}
