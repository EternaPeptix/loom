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
//!   Lines longer than 2000 characters are shown as the 2000 characters around the first match with
//!   `…` at the cut ends. Outcome `{m} matches in {f} files`; facts: `{k} binary files skipped` when
//!   any; `no match` handled as for `glob`. An invalid regex or glob is an error sentence carrying the
//!   library's message.
//!
//! Tests required: the same tree searched by both tools yields the same file set under each
//! combination of `hidden` and `no_ignore`; `.git` always skipped; gitignore respected; glob
//! matching rules (basename vs path, `**`); newest-first order; grep output formats, context
//! grouping, `files_only`, binary skip, long-line windowing on multi-byte text; no-match messages
//! with the "would match with hidden/no_ignore" count; invalid patterns; a single file as `path`;
//! sandbox-unreadable entries skipped; cancellation.

use crate::{params, Body, Tool, ToolCtx, ToolOutput};
use async_trait::async_trait;
use globset::{GlobBuilder, GlobMatcher};
use ignore::WalkBuilder;
use loom_core::event::{ToolClass, ToolSpec, ToolStatus};
use regex::{Regex, RegexBuilder};
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::SystemTime;
use tokio_util::sync::CancellationToken;

/// Most context lines `grep` shows around a match.
const MAX_CONTEXT: usize = 20;
/// Longest line shown whole; longer ones are cut to a window around the first match.
const MAX_LINE_CHARS: usize = 2000;
/// A NUL within this many leading bytes marks a file as binary.
const BINARY_PROBE: usize = 8192;

pub struct Glob;
pub struct Grep;

// ---------------------------------------------------------------------------------------------
// The file set, shared by both tools.
// ---------------------------------------------------------------------------------------------

struct Entry {
    abs: PathBuf,
    /// Path relative to the search root, `/`-separated.
    rel: String,
}

struct Found {
    /// Sorted by `rel`.
    files: Vec<Entry>,
    interrupted: bool,
    /// Entries the sandbox makes unreadable.
    unreadable: usize,
    /// Entries the walk could not read.
    errors: usize,
}

/// Where and how to walk. Cheap to clone into a blocking thread.
#[derive(Clone)]
struct Scan {
    sandbox: Arc<crate::sandbox::Sandbox>,
    cancel: CancellationToken,
    root: PathBuf,
    is_file: bool,
}

impl Scan {
    fn new(ctx: &ToolCtx, path: Option<&str>) -> Result<Scan, Box<ToolOutput>> {
        let given = path.map(str::trim).filter(|p| !p.is_empty()).unwrap_or(".");
        let root = ctx.sandbox.check_read(&ctx.sandbox.resolve(given)).map_err(|m| Box::new(ToolOutput::denied(m)))?;
        let meta = std::fs::metadata(&root).map_err(|e| {
            Box::new(ToolOutput::error(format!(
                "Cannot search {}: {e}. Check the path (relative paths are taken from the workspace {}) and call again.",
                root.display(),
                ctx.workspace.display()
            )))
        })?;
        Ok(Scan { sandbox: ctx.sandbox.clone(), cancel: ctx.cancel.clone(), root, is_file: meta.is_file() })
    }

    /// Every regular file under the root for the given options, sorted by relative path.
    fn collect(&self, hidden: bool, no_ignore: bool) -> Found {
        if self.is_file {
            let rel = self.root.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            return Found {
                files: vec![Entry { abs: self.root.clone(), rel }],
                interrupted: false,
                unreadable: 0,
                errors: 0,
            };
        }
        let skipped = Arc::new(AtomicUsize::new(0));
        let mut builder = WalkBuilder::new(&self.root);
        builder
            .hidden(!hidden)
            .ignore(!no_ignore)
            .git_ignore(!no_ignore)
            .git_global(!no_ignore)
            .git_exclude(!no_ignore)
            .parents(!no_ignore)
            .require_git(false)
            .follow_links(false);
        {
            let sandbox = self.sandbox.clone();
            let skipped = skipped.clone();
            builder.filter_entry(move |e| {
                if e.depth() == 0 {
                    return true;
                }
                if e.file_name() == ".git" {
                    return false;
                }
                if e.file_type().is_some_and(|t| t.is_dir()) && sandbox.check_read(e.path()).is_err() {
                    skipped.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
                true
            });
        }
        let mut found = Found { files: Vec::new(), interrupted: false, unreadable: 0, errors: 0 };
        for item in builder.build() {
            if self.cancel.is_cancelled() {
                found.interrupted = true;
                break;
            }
            let entry = match item {
                Ok(e) => e,
                Err(_) => {
                    found.errors += 1;
                    continue;
                }
            };
            if entry.depth() == 0 || !entry.file_type().is_some_and(|t| t.is_file()) {
                continue;
            }
            if self.sandbox.check_read(entry.path()).is_err() {
                found.unreadable += 1;
                continue;
            }
            let Ok(rel) = entry.path().strip_prefix(&self.root) else { continue };
            let rel = rel.components().map(|c| c.as_os_str().to_string_lossy()).collect::<Vec<_>>().join("/");
            found.files.push(Entry { abs: entry.into_path(), rel });
        }
        found.unreadable += skipped.load(Ordering::Relaxed);
        found.files.sort_by(|a, b| a.rel.cmp(&b.rel));
        found
    }
}

/// A glob matched against relative paths; a pattern without `/` also matches the file name alone.
struct PathGlob {
    matcher: GlobMatcher,
    name_too: bool,
}

impl PathGlob {
    fn new(pattern: &str) -> Result<PathGlob, String> {
        let pattern = pattern.strip_prefix("./").unwrap_or(pattern);
        let glob = GlobBuilder::new(pattern).literal_separator(true).build().map_err(|e| {
            format!("Invalid glob pattern `{pattern}`: {e}. Fix the pattern (`*` stays inside one directory, `**` crosses directories) and call again.")
        })?;
        Ok(PathGlob { matcher: glob.compile_matcher(), name_too: !pattern.contains('/') })
    }

    fn matches(&self, rel: &str) -> bool {
        if self.matcher.is_match(rel) {
            return true;
        }
        self.name_too && rel.rsplit('/').next().is_some_and(|name| self.matcher.is_match(name))
    }
}

fn flag(args: &Map<String, Value>, name: &str) -> bool {
    args.get(name).and_then(Value::as_bool).unwrap_or(false)
}

fn text<'a>(args: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    args.get(name).and_then(Value::as_str)
}

fn set_description(hidden: bool, no_ignore: bool) -> String {
    format!(
        "hidden files {}, git-ignored files {}",
        if hidden { "included" } else { "left out" },
        if no_ignore { "included" } else { "left out" }
    )
}

/// Header facts about the walk itself.
fn walk_facts(found: &Found, more: &mut Vec<String>) {
    if found.unreadable > 0 {
        more.push(format!("{} entries skipped (not readable under the sandbox)", found.unreadable));
    }
    if found.errors > 0 {
        more.push(format!("{} entries could not be read during the walk", found.errors));
    }
}

/// For a search that found nothing: what the same search would find with the hidden and ignored
/// files included. `count_new` counts the matches among the files that the current options leave out.
fn widened_hint(scan: &Scan, hidden: bool, no_ignore: bool, base: &Found, count_new: &dyn Fn(&[&Entry]) -> usize) -> String {
    let have: HashSet<&Path> = base.files.iter().map(|e| e.abs.as_path()).collect();
    let mut gains = Vec::new();
    let mut widened = false;
    let mut cut_short = false;
    for h in [hidden, true] {
        for n in [no_ignore, true] {
            if (h, n) == (hidden, no_ignore) {
                continue;
            }
            widened = true;
            let wider = scan.collect(h, n);
            cut_short |= wider.interrupted;
            let extra: Vec<&Entry> = wider.files.iter().filter(|e| !have.contains(e.abs.as_path())).collect();
            let k = count_new(&extra);
            if k > 0 {
                let label = match (h && !hidden, n && !no_ignore) {
                    (true, true) => "`hidden: true` and `no_ignore: true`",
                    (true, false) => "`hidden: true`",
                    _ => "`no_ignore: true`",
                };
                gains.push(format!("{k} more would match with {label}"));
            }
        }
    }
    if !widened {
        return String::new();
    }
    match (gains.is_empty(), cut_short) {
        (true, false) => " Including hidden and git-ignored files would not change this.".to_string(),
        (true, true) => " Whether hidden and git-ignored files would change this could not be checked (interrupted).".to_string(),
        (false, false) => format!(" {}.", gains.join("; ")),
        (false, true) => format!(" {}. (That check was interrupted, so the counts may be low.)", gains.join("; ")),
    }
}

fn with_status(status: ToolStatus, mut out: ToolOutput) -> ToolOutput {
    out.status = status;
    out
}

// ---------------------------------------------------------------------------------------------
// glob
// ---------------------------------------------------------------------------------------------

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
        let pattern = text(args, "pattern").unwrap_or_default().to_string();
        let glob = match PathGlob::new(&pattern) {
            Ok(g) => g,
            Err(e) => return ToolOutput::error(e),
        };
        let scan = match Scan::new(ctx, text(args, "path")) {
            Ok(s) => s,
            Err(out) => return *out,
        };
        let (hidden, no_ignore) = (flag(args, "hidden"), flag(args, "no_ignore"));
        let job = tokio::task::spawn_blocking(move || glob_job(&scan, &glob, &pattern, hidden, no_ignore));
        match job.await {
            Ok(out) => out,
            Err(e) => ToolOutput::error(format!(
                "The file walk failed internally ({e}). Call `glob` again; if it repeats, use `bash` with `find`."
            )),
        }
    }
}

fn glob_job(scan: &Scan, glob: &PathGlob, pattern: &str, hidden: bool, no_ignore: bool) -> ToolOutput {
    let found = scan.collect(hidden, no_ignore);
    let searched = found.files.len();
    let mut hits: Vec<(SystemTime, &Entry)> = found
        .files
        .iter()
        .filter(|e| glob.matches(&e.rel))
        .map(|e| (std::fs::metadata(&e.abs).and_then(|m| m.modified()).unwrap_or(SystemTime::UNIX_EPOCH), e))
        .collect();
    hits.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.rel.cmp(&b.1.rel)));
    let status = if found.interrupted { ToolStatus::Interrupted } else { ToolStatus::Ok };

    let mut more = vec![format!("{searched} files searched")];
    walk_facts(&found, &mut more);
    if found.interrupted {
        more.push("interrupted: the walk stopped early; results are partial".to_string());
    }

    let mut out = if hits.is_empty() {
        let outcome = if found.interrupted { "interrupted" } else { "no match" };
        let hint = if found.interrupted {
            String::new()
        } else {
            widened_hint(scan, hidden, no_ignore, &found, &|extra| extra.iter().filter(|e| glob.matches(&e.rel)).count())
        };
        let msg = format!(
            "No file matched `{pattern}` among the {searched} files searched under {} ({}).{hint}",
            scan.root.display(),
            set_description(hidden, no_ignore)
        );
        ToolOutput::ok(outcome, Body::Message(msg))
    } else {
        let mut body = String::new();
        for (_, e) in &hits {
            body.push_str(&e.rel);
            body.push('\n');
        }
        ToolOutput::ok(format!("{} files", hits.len()), Body::Raw(body.into_bytes()))
    };
    out.more = more;
    with_status(status, out)
}

// ---------------------------------------------------------------------------------------------
// grep
// ---------------------------------------------------------------------------------------------

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
        let pattern = text(args, "pattern").unwrap_or_default().to_string();
        let re = match RegexBuilder::new(&pattern).case_insensitive(flag(args, "ignore_case")).build() {
            Ok(r) => r,
            Err(e) => {
                return ToolOutput::error(format!(
                    "Invalid regular expression `{pattern}`: {e}. Fix the pattern (Rust regex syntax; escape literal metacharacters with `\\`) and call again."
                ))
            }
        };
        let filter = match text(args, "glob").filter(|g| !g.trim().is_empty()) {
            Some(g) => match PathGlob::new(g) {
                Ok(g) => Some(g),
                Err(e) => return ToolOutput::error(e),
            },
            None => None,
        };
        let scan = match Scan::new(ctx, text(args, "path")) {
            Ok(s) => s,
            Err(out) => return *out,
        };
        let requested = args.get("context").and_then(Value::as_u64).unwrap_or(0);
        let opts = GrepOpts {
            re,
            pattern,
            filter,
            context: usize::try_from(requested).unwrap_or(usize::MAX).min(MAX_CONTEXT),
            context_clamped: requested > MAX_CONTEXT as u64,
            files_only: flag(args, "files_only"),
            hidden: flag(args, "hidden"),
            no_ignore: flag(args, "no_ignore"),
        };
        match tokio::task::spawn_blocking(move || grep_job(&scan, &opts)).await {
            Ok(out) => out,
            Err(e) => ToolOutput::error(format!(
                "The search failed internally ({e}). Call `grep` again; if it repeats, use `bash` with `rg` or `grep -rn`."
            )),
        }
    }
}

struct GrepOpts {
    re: Regex,
    pattern: String,
    filter: Option<PathGlob>,
    context: usize,
    context_clamped: bool,
    files_only: bool,
    hidden: bool,
    no_ignore: bool,
}

enum Read {
    Text(String),
    Binary,
    Unreadable,
}

fn read_text(path: &Path) -> Read {
    let Ok(bytes) = std::fs::read(path) else { return Read::Unreadable };
    if bytes.iter().take(BINARY_PROBE).any(|b| *b == 0) {
        return Read::Binary;
    }
    match String::from_utf8(bytes) {
        Ok(s) => Read::Text(s),
        Err(_) => Read::Binary,
    }
}

/// `line`, or when it is longer than `MAX_LINE_CHARS` the characters around its first match.
fn windowed(line: &str, re: &Regex) -> String {
    let total = line.chars().count();
    if total <= MAX_LINE_CHARS {
        return line.to_string();
    }
    let first = re.find(line).map(|m| line.get(..m.start()).map_or(0, |p| p.chars().count())).unwrap_or(0);
    let end = first.saturating_sub(MAX_LINE_CHARS / 2).saturating_add(MAX_LINE_CHARS).min(total);
    let start = end.saturating_sub(MAX_LINE_CHARS);
    let mut out = String::new();
    if start > 0 {
        out.push('…');
    }
    out.extend(line.chars().skip(start).take(end - start));
    if end < total {
        out.push('…');
    }
    out
}

fn grep_job(scan: &Scan, opts: &GrepOpts) -> ToolOutput {
    let found = scan.collect(opts.hidden, opts.no_ignore);
    let candidates: Vec<&Entry> =
        found.files.iter().filter(|e| opts.filter.as_ref().is_none_or(|g| g.matches(&e.rel))).collect();

    let mut body = String::new();
    let mut groups_written = false;
    let (mut matches, mut files_with, mut scanned, mut binary, mut unreadable) = (0usize, 0usize, 0usize, 0usize, 0usize);
    let mut interrupted = found.interrupted;
    for entry in &candidates {
        if scan.cancel.is_cancelled() {
            interrupted = true;
            break;
        }
        let content = match read_text(&entry.abs) {
            Read::Text(t) => t,
            Read::Binary => {
                binary += 1;
                continue;
            }
            Read::Unreadable => {
                unreadable += 1;
                continue;
            }
        };
        scanned += 1;
        let lines: Vec<&str> = content.lines().collect();
        let hits: Vec<usize> = lines.iter().enumerate().filter(|(_, l)| opts.re.is_match(l)).map(|(i, _)| i).collect();
        if hits.is_empty() {
            continue;
        }
        matches += hits.len();
        files_with += 1;
        if opts.files_only {
            body.push_str(&format!("{} ({})\n", entry.rel, hits.len()));
        } else if opts.context == 0 {
            for &i in &hits {
                let line = lines.get(i).copied().unwrap_or_default();
                body.push_str(&format!("{}:{}:{}\n", entry.rel, i + 1, windowed(line, &opts.re)));
            }
        } else {
            let last_line = lines.len().saturating_sub(1);
            let mut ranges: Vec<(usize, usize)> = Vec::new();
            for &i in &hits {
                let (lo, hi) = (i.saturating_sub(opts.context), i.saturating_add(opts.context).min(last_line));
                match ranges.last_mut() {
                    Some(last) if lo <= last.1.saturating_add(1) => last.1 = last.1.max(hi),
                    _ => ranges.push((lo, hi)),
                }
            }
            for (lo, hi) in ranges {
                if groups_written {
                    body.push_str("--\n");
                }
                groups_written = true;
                for j in lo..=hi {
                    let sep = if hits.binary_search(&j).is_ok() { ':' } else { '-' };
                    let line = lines.get(j).copied().unwrap_or_default();
                    body.push_str(&format!("{}{sep}{}{sep}{}\n", entry.rel, j + 1, windowed(line, &opts.re)));
                }
            }
        }
    }

    let mut more = vec![format!("{scanned} files searched")];
    if binary > 0 {
        more.push(format!("{binary} binary files skipped"));
    }
    if unreadable > 0 {
        more.push(format!("{unreadable} files could not be read"));
    }
    walk_facts(&found, &mut more);
    if opts.context_clamped {
        more.push(format!("context limited to {MAX_CONTEXT} lines"));
    }
    let status = if interrupted { ToolStatus::Interrupted } else { ToolStatus::Ok };
    if interrupted {
        more.push(format!(
            "interrupted: {} of the {} files found were searched; results are partial",
            scanned + binary + unreadable,
            candidates.len()
        ));
    }

    let mut out = if matches == 0 {
        let outcome = if interrupted { "interrupted" } else { "no match" };
        let hint = if interrupted {
            String::new()
        } else {
            widened_hint(scan, opts.hidden, opts.no_ignore, &found, &|extra| {
                extra
                    .iter()
                    .filter(|e| opts.filter.as_ref().is_none_or(|g| g.matches(&e.rel)))
                    .filter(|e| match read_text(&e.abs) {
                        Read::Text(t) => t.lines().any(|l| opts.re.is_match(l)),
                        _ => false,
                    })
                    .count()
            })
        };
        let skipped = if binary > 0 { format!(", {binary} binary files skipped and not searched") } else { String::new() };
        let filtered = if opts.filter.is_some() { " matching the glob" } else { "" };
        let msg = format!(
            "No line matched `{}` in the {scanned} text files{filtered} searched under {} ({}){skipped}.{hint}",
            opts.pattern,
            scan.root.display(),
            set_description(opts.hidden, opts.no_ignore)
        );
        ToolOutput::ok(outcome, Body::Message(msg))
    } else {
        ToolOutput::ok(format!("{matches} matches in {files_with} files"), Body::Raw(body.into_bytes()))
    };
    out.more = more;
    with_status(status, out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{env, env_with, TestEnv};
    use loom_core::config::{SandboxCfg, SandboxMode, ToolsCfg};
    use serde_json::json;
    use std::collections::BTreeSet;

    fn put(e: &TestEnv, rel: &str, content: &str) {
        let p = e.ctx.workspace.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }

    /// A tree with a hidden file, a hidden directory, an ignored directory and a `.git` directory;
    /// every file contains the word `needle`.
    fn tree(e: &TestEnv) {
        put(e, "a.txt", "alpha needle\n");
        put(e, "src/b.rs", "fn needle() {}\n");
        put(e, "src/deep/c.rs", "// needle\n");
        put(e, ".hidden/d.txt", "needle\n");
        put(e, ".hidden_file", "needle\n");
        put(e, "ignored/e.txt", "needle\n");
        put(e, ".gitignore", "ignored/\n# needle\n");
        put(e, ".git/config", "needle\n");
    }

    fn lines(s: &str) -> Vec<String> {
        s.lines().map(str::to_string).collect()
    }

    fn set(v: &[&str]) -> BTreeSet<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[tokio::test]
    async fn both_tools_search_the_same_files() {
        let e = env();
        tree(&e);
        let base = ["a.txt", "src/b.rs", "src/deep/c.rs"];
        let hid = [".gitignore", ".hidden/d.txt", ".hidden_file"];
        let ign = ["ignored/e.txt"];
        for (hidden, no_ignore) in [(false, false), (true, false), (false, true), (true, true)] {
            let mut want: Vec<&str> = base.to_vec();
            if hidden {
                want.extend(hid);
            }
            if no_ignore {
                want.extend(ign);
            }
            let want = set(&want);
            let g = e.call("glob", json!({"pattern": "**", "hidden": hidden, "no_ignore": no_ignore})).await;
            let got_glob: BTreeSet<String> = lines(&e.stored(&g)).into_iter().collect();
            let r = e.call("grep", json!({"pattern": "needle", "files_only": true, "hidden": hidden, "no_ignore": no_ignore})).await;
            let got_grep: BTreeSet<String> =
                lines(&e.stored(&r)).into_iter().map(|l| l.rsplit_once(" (").unwrap().0.to_string()).collect();
            assert_eq!(got_glob, want, "glob hidden={hidden} no_ignore={no_ignore}");
            assert_eq!(got_grep, want, "grep hidden={hidden} no_ignore={no_ignore}");
            assert!(!got_glob.iter().any(|p| p.starts_with(".git/")));
        }
    }

    #[tokio::test]
    async fn glob_matching_rules() {
        let e = env();
        tree(&e);
        let run = |p: &'static str| {
            let e = &e;
            async move {
                let r = e.call("glob", json!({"pattern": p})).await;
                lines(&e.stored(&r)).into_iter().collect::<BTreeSet<_>>()
            }
        };
        assert_eq!(run("*.rs").await, set(&["src/b.rs", "src/deep/c.rs"]));
        assert_eq!(run("src/*.rs").await, set(&["src/b.rs"]));
        assert_eq!(run("src/**/*.rs").await, set(&["src/b.rs", "src/deep/c.rs"]));
        assert_eq!(run("**/c.rs").await, set(&["src/deep/c.rs"]));
        assert_eq!(run("a.txt").await, set(&["a.txt"]));
        assert_eq!(run("./a.txt").await, set(&["a.txt"]));
        let r = e.call("glob", json!({"pattern": "*.rs"})).await;
        assert!(r.text.contains("2 files"), "{}", r.text);
    }

    #[tokio::test]
    async fn glob_lists_newest_first() {
        let e = env();
        put(&e, "old.txt", "x");
        put(&e, "mid.txt", "x");
        put(&e, "new.txt", "x");
        let now = SystemTime::now();
        let set_time = |name: &str, ago: u64| {
            let f = std::fs::File::options().write(true).open(e.ctx.workspace.join(name)).unwrap();
            f.set_modified(now - std::time::Duration::from_secs(ago)).unwrap();
        };
        set_time("old.txt", 300);
        set_time("mid.txt", 200);
        set_time("new.txt", 100);
        let r = e.call("glob", json!({"pattern": "*.txt"})).await;
        assert_eq!(lines(&e.stored(&r)), vec!["new.txt", "mid.txt", "old.txt"]);
    }

    #[tokio::test]
    async fn no_match_says_how_many_files_and_what_hidden_would_add() {
        let e = env();
        tree(&e);
        put(&e, "plain.md", "nothing\n");
        put(&e, ".hidden/only.md", "x\n");
        put(&e, "ignored/only.md", "x\n");
        let r = e.call("glob", json!({"pattern": "only.md"})).await;
        assert!(r.text.contains("no match"), "{}", r.text);
        assert!(r.text.contains("among the 4 files searched"), "{}", r.text);
        assert!(r.text.contains("1 more would match with `hidden: true`"), "{}", r.text);
        assert!(r.text.contains("1 more would match with `no_ignore: true`"), "{}", r.text);
        assert!(r.text.contains("2 more would match with `hidden: true` and `no_ignore: true`"), "{}", r.text);

        let r = e.call("glob", json!({"pattern": "*.nothing"})).await;
        assert!(r.text.contains("would not change this"), "{}", r.text);

        let r = e.call("grep", json!({"pattern": "zzz"})).await;
        assert!(r.text.contains("no match"), "{}", r.text);
        assert!(r.text.contains("4 text files"), "{}", r.text);
        assert!(r.text.contains("would not change this"), "{}", r.text);
        put(&e, ".hidden/z.txt", "zzz\n");
        let r = e.call("grep", json!({"pattern": "zzz"})).await;
        assert!(r.text.contains("1 more would match with `hidden: true`"), "{}", r.text);
        let r = e.call("grep", json!({"pattern": "zzz", "hidden": true, "no_ignore": true})).await;
        assert!(r.text.contains("1 matches in 1 files"), "{}", r.text);
    }

    #[tokio::test]
    async fn grep_formats() {
        let e = env();
        put(&e, "f.txt", "one\ntwo hit\nthree\nfour\nfive\nsix\nseven hit\neight\nnine hit\nten\n");
        put(&e, "g.txt", "hit here\n");
        let r = e.call("grep", json!({"pattern": "hit"})).await;
        assert!(r.text.contains("4 matches in 2 files"), "{}", r.text);
        assert_eq!(e.stored(&r), "f.txt:2:two hit\nf.txt:7:seven hit\nf.txt:9:nine hit\ng.txt:1:hit here\n");

        let r = e.call("grep", json!({"pattern": "hit", "context": 1})).await;
        assert_eq!(
            e.stored(&r),
            "f.txt-1-one\nf.txt:2:two hit\nf.txt-3-three\n--\nf.txt-6-six\nf.txt:7:seven hit\nf.txt-8-eight\nf.txt:9:nine hit\nf.txt-10-ten\n--\ng.txt:1:hit here\n"
        );

        let r = e.call("grep", json!({"pattern": "hit", "files_only": true})).await;
        assert_eq!(e.stored(&r), "f.txt (3)\ng.txt (1)\n");

        let r = e.call("grep", json!({"pattern": "HIT", "ignore_case": true, "glob": "g.*"})).await;
        assert_eq!(e.stored(&r), "g.txt:1:hit here\n");
        let r = e.call("grep", json!({"pattern": "HIT"})).await;
        assert!(r.text.contains("no match"), "{}", r.text);
    }

    #[tokio::test]
    async fn context_is_capped_and_says_so() {
        let e = env();
        put(&e, "f.txt", "x\n");
        let r = e.call("grep", json!({"pattern": "x", "context": 50})).await;
        assert!(r.text.contains("context limited to 20 lines"), "{}", r.text);
    }

    #[tokio::test]
    async fn binary_and_non_utf8_files_are_skipped_and_counted() {
        let e = env();
        put(&e, "text.txt", "needle\n");
        std::fs::write(e.ctx.workspace.join("bin.dat"), b"needle\0\0\0").unwrap();
        std::fs::write(e.ctx.workspace.join("latin.txt"), b"needle \xff\xfe\n").unwrap();
        let r = e.call("grep", json!({"pattern": "needle"})).await;
        assert!(r.text.contains("1 matches in 1 files"), "{}", r.text);
        assert!(r.text.contains("2 binary files skipped"), "{}", r.text);
        assert_eq!(e.stored(&r), "text.txt:1:needle\n");
        let r = e.call("grep", json!({"pattern": "absent"})).await;
        assert!(r.text.contains("2 binary files skipped and not searched"), "{}", r.text);
    }

    #[tokio::test]
    async fn long_lines_are_windowed_around_the_match_on_characters() {
        let e = env();
        let line = format!("{}NEEDLE{}", "é".repeat(3000), "ü".repeat(3000));
        put(&e, "long.txt", &format!("{line}\nshort NEEDLE\n"));
        let r = e.call("grep", json!({"pattern": "NEEDLE"})).await;
        let stored = e.stored(&r);
        let first = stored.lines().next().unwrap();
        let shown = first.strip_prefix("long.txt:1:").unwrap();
        assert!(shown.starts_with('…') && shown.ends_with('…'), "{shown}");
        let inner: String = shown.trim_matches('…').to_string();
        assert_eq!(inner.chars().count(), 2000);
        assert!(inner.contains("NEEDLE"));
        assert!(stored.contains("long.txt:2:short NEEDLE") || stored.contains("long.txt:2"));

        // A match near the start keeps the start of the line (no leading cut mark).
        put(&e, "start.txt", &format!("NEEDLE{}\n", "x".repeat(3000)));
        let r = e.call("grep", json!({"pattern": "NEEDLE", "glob": "start.txt"})).await;
        let stored = e.stored(&r);
        let shown = stored.trim_end().strip_prefix("start.txt:1:").unwrap();
        assert!(shown.starts_with("NEEDLE") && shown.ends_with('…'));
        assert_eq!(shown.chars().count(), 2001);
    }

    #[tokio::test]
    async fn invalid_patterns_are_error_sentences() {
        let e = env();
        let r = e.call("grep", json!({"pattern": "(unclosed"})).await;
        assert_eq!(r.status, ToolStatus::Error);
        assert!(r.text.contains("Invalid regular expression") && r.text.contains("call again"), "{}", r.text);
        let r = e.call("glob", json!({"pattern": "[abc"})).await;
        assert_eq!(r.status, ToolStatus::Error);
        assert!(r.text.contains("Invalid glob pattern"), "{}", r.text);
        let r = e.call("grep", json!({"pattern": "x", "glob": "{a"})).await;
        assert_eq!(r.status, ToolStatus::Error);
    }

    #[tokio::test]
    async fn a_single_file_is_the_only_member() {
        let e = env();
        tree(&e);
        let r = e.call("grep", json!({"pattern": "needle", "path": "src/b.rs"})).await;
        assert_eq!(e.stored(&r), "b.rs:1:fn needle() {}\n");
        let r = e.call("glob", json!({"pattern": "*.rs", "path": "src/b.rs"})).await;
        assert_eq!(e.stored(&r), "b.rs\n");
        // A hidden file named directly is still searched.
        let r = e.call("grep", json!({"pattern": "needle", "path": ".hidden_file"})).await;
        assert!(r.text.contains("1 matches in 1 files"), "{}", r.text);
        let r = e.call("grep", json!({"pattern": "x", "path": "nope"})).await;
        assert_eq!(r.status, ToolStatus::Error);
    }

    #[tokio::test]
    async fn gitignore_is_respected_without_a_repository() {
        let e = env();
        put(&e, ".gitignore", "*.log\n");
        put(&e, "keep.txt", "x");
        put(&e, "drop.log", "x");
        let r = e.call("glob", json!({"pattern": "*"})).await;
        assert_eq!(lines(&e.stored(&r)), vec!["keep.txt"]);
        let r = e.call("glob", json!({"pattern": "*", "no_ignore": true})).await;
        assert_eq!(lines(&e.stored(&r)).into_iter().collect::<BTreeSet<_>>(), set(&["keep.txt", "drop.log"]));
    }

    #[tokio::test]
    async fn sandbox_unreadable_entries_are_skipped_and_counted() {
        let sandbox = SandboxCfg {
            mode: SandboxMode::None,
            unreadable_paths: vec!["secret".into(), "key.txt".into()],
            ..SandboxCfg::default()
        };
        let e = env_with(ToolsCfg::default(), sandbox);
        put(&e, "open.txt", "needle\n");
        put(&e, "secret/s.txt", "needle\n");
        put(&e, "key.txt", "needle\n");
        let r = e.call("grep", json!({"pattern": "needle"})).await;
        assert_eq!(e.stored(&r), "open.txt:1:needle\n");
        assert!(r.text.contains("2 entries skipped"), "{}", r.text);
        let r = e.call("glob", json!({"pattern": "**"})).await;
        assert_eq!(lines(&e.stored(&r)), vec!["open.txt"]);
        let r = e.call("grep", json!({"pattern": "needle", "path": "secret"})).await;
        assert_eq!(r.status, ToolStatus::Denied);
    }

    #[tokio::test]
    async fn cancellation_is_reported_as_interrupted() {
        let e = env();
        tree(&e);
        e.ctx.cancel.cancel();
        let r = e.call("glob", json!({"pattern": "*"})).await;
        assert_eq!(r.status, ToolStatus::Interrupted);
        assert!(r.text.contains("interrupted"), "{}", r.text);
        let r = e.call("grep", json!({"pattern": "needle"})).await;
        assert_eq!(r.status, ToolStatus::Interrupted);
        assert!(r.text.contains("results are partial"), "{}", r.text);
        assert!(!r.text.contains("no match"), "{}", r.text);
    }
}
