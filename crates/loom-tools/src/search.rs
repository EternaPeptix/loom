//! `glob` and `grep`: both search the same set of files.
//!
//! CONTRACT.
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
//! modified first (ties by path), as `Body::Raw`. At most `cfg.search_max_results` paths and `MAX_BODY_BYTES` of body are kept; a cut result
//! carries a `Showing N of [at least] M files found` notice at both ends (the totals keep counting; "at least"
//! when the search was interrupted).
//! Outcome `{n} files`; with no match: outcome `no match` and a body that says how many files were
//! searched and, when `hidden`/`no_ignore` were not set and would have changed the result, how many
//! more match with them.
//!
//! ## `grep`
//! `pattern` is a regex (`regex` crate; `ignore_case` → case-insensitive) matched per line. `glob`
//! filters files as above. Only regular files are opened. The first 8 KiB of a file are read and
//! checked for a NUL before the rest is read; files that are binary or not valid UTF-8 are skipped and
//! counted. A file above `MAX_GREP_FILE_BYTES` (16 MiB) is not read: it is counted, named (the first
//! few), and the result says the search is not complete and to search it with `bash`. Cancellation is
//! checked between files. Files are visited in path order. Output as `Body::Raw`:
//! - default: `path:line:text` per match; with `context` > 0 (at most 20), context lines are
//!   `path-line-text` and groups are separated by `--`; matching lines past the bound inside the context of
//!   the last kept match keep their `:` marker;
//! - `files_only`: one path per line with its match count, `path (n)`.
//!   At most `cfg.search_max_results` entries (matching lines, or files for `files_only`) and
//!   `MAX_BODY_BYTES` of body are kept; a cut result (also one whose trailing context the byte limit cut) carries
//!   the same `Showing N of [at least] M` notice at both ends, and the counts stay exact.
//!   Lines longer than 2000 characters are shown as the 2000 characters around the first match with
//!   `…` at the cut ends. Outcome `{m} matches in {f} files`; facts: `{k} binary files skipped` when
//!   any; `no match` handled as for `glob`. The "what would hidden/ignored files add" pass of a no-match
//!   result visits each wider combination of the two flags once, reads at most `HINT_MAX_FILES` files
//!   and runs for at most `HINT_MAX_TIME` (the walks included); when it is cut short, or by
//!   cancellation, the hint says so. An invalid regex or glob is an error sentence carrying the
//!   library's message.
//!
//! Tests required: the same tree searched by both tools yields the same file set under each
//! combination of `hidden` and `no_ignore`; `.git` always skipped; gitignore respected; glob
//! matching rules (basename vs path, `**`); newest-first order; grep output formats, context
//! grouping, `files_only`, binary skip, long-line windowing on multi-byte text; no-match messages
//! with the "would match with hidden/no_ignore" count; invalid patterns; a single file as `path`;
//! sandbox-unreadable entries skipped; cancellation.

use crate::files::open_regular;
use crate::{params, Body, Tool, ToolCtx, ToolOutput};
use async_trait::async_trait;
use globset::{GlobBuilder, GlobMatcher};
use ignore::WalkBuilder;
use loom_core::event::{ToolClass, ToolSpec, ToolStatus};
use regex::{Regex, RegexBuilder};
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::io::Read as IoRead;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio_util::sync::CancellationToken;

/// Most context lines `grep` shows around a match.
const MAX_CONTEXT: usize = 20;
/// Longest line shown whole; longer ones are cut to a window around the first match.
const MAX_LINE_CHARS: usize = 2000;
/// A NUL within this many leading bytes marks a file as binary.
const BINARY_PROBE: usize = 8192;
/// `grep` does not read a file larger than this (16 MiB); it counts it as skipped and says so.
const MAX_GREP_FILE_BYTES: u64 = 16 * 1024 * 1024;
/// The "what would hidden and ignored files add" pass examines at most this many files ...
const HINT_MAX_FILES: usize = 20_000;
/// ... and runs for at most this long; when either limit is reached the hint says it was cut short.
const HINT_MAX_TIME: Duration = Duration::from_secs(10);
/// Most bytes of result text `glob` and `grep` collect (4 MiB); the rest is counted, not kept.
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// How much result text a search keeps: at most `max_results` entries and `max_bytes` bytes.
#[derive(Clone, Copy)]
struct Bound {
    max_results: usize,
    max_bytes: usize,
}

impl Bound {
    fn new(max_results: usize) -> Bound {
        Bound { max_results: max_results.max(1), max_bytes: MAX_BODY_BYTES }
    }
}

/// The result text being collected. Lines that do not fit are refused, and so is everything after.
struct Sink {
    body: String,
    /// Entries (matches, paths or files) kept.
    shown: usize,
    full: bool,
    bound: Bound,
}

impl Sink {
    fn new(bound: Bound) -> Sink {
        Sink { body: String::new(), shown: 0, full: false, bound }
    }

    /// Entries that may still be added before the count bound is reached.
    fn room(&self) -> usize {
        if self.full {
            0
        } else {
            self.bound.max_results.saturating_sub(self.shown)
        }
    }

    /// Keep `line` (which carries its own newline) if the byte bound allows; `entry` lines are counted as shown.
    fn push(&mut self, line: &str, entry: bool) -> bool {
        if self.full || (entry && self.shown >= self.bound.max_results) {
            return false;
        }
        if self.body.len().saturating_add(line.len()) > self.bound.max_bytes {
            self.full = true;
            return false;
        }
        self.body.push_str(line);
        if entry {
            self.shown += 1;
        }
        true
    }

    /// The body, with a notice before and after it when the bound cut the result (`total` found).
    /// `advice` says how to narrow the search with the arguments this tool has.
    fn finish(self, total: usize, lower_bound: bool, unit: &str, advice: &str) -> String {
        if self.shown >= total && !self.full {
            return self.body;
        }
        let at_least = if lower_bound { "at least " } else { "" };
        let found = if lower_bound { "found before the search was interrupted" } else { "found" };
        let rest = if self.shown >= total {
            "the byte limit cut the context after the last one"
        } else {
            "the rest were counted but not listed"
        };
        let notice = format!(
            "[Showing {} of {at_least}{total} {unit} {found}; {rest}. Narrow the search ({advice}) to see them.]\n",
            self.shown
        );
        format!("{notice}{}{notice}", self.body)
    }
}

const GLOB_ADVICE: &str = "a more specific `pattern` or `path`";
const GREP_ADVICE: &str = "a more specific `pattern`, `path` or `glob`, or `files_only`";
const GREP_FILES_ADVICE: &str = "a more specific `pattern`, `path` or `glob`";

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
        self.collect_until(hidden, no_ignore, None)
    }

    /// [`Scan::collect`] that also stops (as `interrupted`) once `deadline` has passed.
    fn collect_until(&self, hidden: bool, no_ignore: bool, deadline: Option<Instant>) -> Found {
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
            if self.cancel.is_cancelled() || deadline.is_some_and(|d| Instant::now() >= d) {
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

/// How much work the hint pass may do.
#[derive(Clone, Copy)]
struct HintLimits {
    max_files: usize,
    max_time: Duration,
}

impl HintLimits {
    const STANDARD: HintLimits = HintLimits { max_files: HINT_MAX_FILES, max_time: HINT_MAX_TIME };
}

/// What is left of the hint pass's allowance, and why it stopped when it did.
struct Budget {
    cancel: CancellationToken,
    deadline: Instant,
    files_left: usize,
    max_files: usize,
    /// Why the pass was cut short, once it was.
    cut: Option<String>,
    /// Files the pass did not read because they are over the size limit (each counted once).
    too_large: HashSet<PathBuf>,
}

/// A deadline that is never reached in practice, for a time limit too large to add.
fn far_future() -> Instant {
    let now = Instant::now();
    now.checked_add(Duration::from_secs(365 * 24 * 3600)).unwrap_or(now)
}

impl Budget {
    fn new(cancel: CancellationToken, limits: HintLimits) -> Budget {
        Budget {
            cancel,
            deadline: Instant::now().checked_add(limits.max_time).unwrap_or_else(far_future),
            files_left: limits.max_files,
            max_files: limits.max_files,
            cut: None,
            too_large: HashSet::new(),
        }
    }

    /// Take one file from the allowance. False once the pass must stop (cancelled, out of time or files).
    fn spend(&mut self) -> bool {
        if self.cut.is_some() {
            return false;
        }
        if self.cancel.is_cancelled() {
            self.cut = Some("interrupted".to_string());
        } else if Instant::now() >= self.deadline {
            self.cut = Some("the time limit was reached".to_string());
        } else if self.files_left == 0 {
            self.cut = Some(format!("the limit of {} files was reached", self.max_files));
        } else {
            self.files_left -= 1;
            return true;
        }
        false
    }
}

/// For a search that found nothing: what the same search would find with the hidden and ignored
/// files included. `count_new` counts the matches among the files that the current options leave out;
/// it takes one file from the budget before reading each. Each wider combination is visited once.
fn widened_hint(
    scan: &Scan,
    hidden: bool,
    no_ignore: bool,
    base: &Found,
    limits: HintLimits,
    count_new: &dyn Fn(&[&Entry], &mut Budget) -> usize,
) -> String {
    let have: HashSet<&Path> = base.files.iter().map(|e| e.abs.as_path()).collect();
    let mut combos: Vec<(bool, bool)> = Vec::new();
    for h in [hidden, true] {
        for n in [no_ignore, true] {
            if (h, n) != (hidden, no_ignore) && !combos.contains(&(h, n)) {
                combos.push((h, n));
            }
        }
    }
    if combos.is_empty() {
        return String::new();
    }
    let mut budget = Budget::new(scan.cancel.clone(), limits);
    let mut gains = Vec::new();
    for (h, n) in combos {
        if budget.cut.is_some() {
            break;
        }
        if Instant::now() >= budget.deadline {
            budget.cut = Some("the time limit was reached".to_string());
            break;
        }
        let wider = scan.collect_until(h, n, Some(budget.deadline));
        if wider.interrupted && budget.cut.is_none() {
            budget.cut = Some(if scan.cancel.is_cancelled() { "interrupted" } else { "the time limit was reached" }.to_string());
        }
        let extra: Vec<&Entry> = wider.files.iter().filter(|e| !have.contains(e.abs.as_path())).collect();
        let k = count_new(&extra, &mut budget);
        if k > 0 {
            let label = match (h && !hidden, n && !no_ignore) {
                (true, true) => "`hidden: true` and `no_ignore: true`",
                (true, false) => "`hidden: true`",
                _ => "`no_ignore: true`",
            };
            gains.push(format!("{k} more would match with {label}"));
        }
    }
    let mut hint = match (gains.is_empty(), &budget.cut) {
        (true, None) if !budget.too_large.is_empty() => {
            " Hidden and git-ignored files that could be read would not change this, but some could not be checked.".to_string()
        }
        (true, None) => " Including hidden and git-ignored files would not change this.".to_string(),
        (true, Some(why)) => format!(" Whether hidden and git-ignored files would change this could not be fully checked ({why})."),
        (false, None) => format!(" {}.", gains.join("; ")),
        (false, Some(why)) => format!(" {}. (That check was cut short — {why} — so the counts may be low.)", gains.join("; ")),
    };
    if !budget.too_large.is_empty() {
        hint.push_str(&format!(
            " {} of those files are over the {MAX_GREP_FILE_BYTES} byte size limit and were not read; search them with `bash` (`grep -n PATTERN FILE`).",
            budget.too_large.len()
        ));
    }
    hint
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

    fn speculative(&self) -> bool {
        true
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
        let bound = Bound::new(ctx.cfg.search_max_results);
        let job = tokio::task::spawn_blocking(move || glob_job(&scan, &glob, &pattern, hidden, no_ignore, bound));
        match job.await {
            Ok(out) => out,
            Err(e) => ToolOutput::error(format!(
                "The file walk failed internally ({e}). Call `glob` again; if it repeats, use `bash` with `find`."
            )),
        }
    }
}

fn glob_job(scan: &Scan, glob: &PathGlob, pattern: &str, hidden: bool, no_ignore: bool, bound: Bound) -> ToolOutput {
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
            widened_hint(scan, hidden, no_ignore, &found, HintLimits::STANDARD, &|extra, _| {
                extra.iter().filter(|e| glob.matches(&e.rel)).count()
            })
        };
        let msg = format!(
            "No file matched `{pattern}` among the {searched} files searched under {} ({}).{hint}",
            scan.root.display(),
            set_description(hidden, no_ignore)
        );
        ToolOutput::ok(outcome, Body::Message(msg))
    } else {
        let mut sink = Sink::new(bound);
        for (_, e) in &hits {
            if !sink.push(&format!("{}\n", e.rel), true) {
                break;
            }
        }
        let total = hits.len();
        let body = sink.finish(total, found.interrupted, "files", GLOB_ADVICE);
        ToolOutput::ok(format!("{total} files"), Body::Raw(body.into_bytes()))
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

    fn speculative(&self) -> bool {
        true
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
            bound: Bound::new(ctx.cfg.search_max_results),
        };
        match tokio::task::spawn_blocking(move || grep_job(&scan, &opts, HintLimits::STANDARD)).await {
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
    bound: Bound,
}

enum Read {
    Text(String),
    Binary,
    /// Larger than `MAX_GREP_FILE_BYTES`: not read.
    TooLarge,
    Unreadable,
}

/// The text of a regular file of at most `cap` bytes. The first `BINARY_PROBE` bytes are read and
/// checked for a NUL before the rest is read, and a file over the cap is never read at all.
fn read_text(path: &Path, cap: u64) -> Read {
    // Only a regular file is opened (never a FIFO, device or socket), and the open does not block.
    let Ok((mut file, meta)) = open_regular(path) else { return Read::Unreadable };
    if meta.len() > cap {
        return Read::TooLarge;
    }
    let mut bytes = Vec::new();
    if (&mut file).take(BINARY_PROBE as u64).read_to_end(&mut bytes).is_err() {
        return Read::Unreadable;
    }
    if bytes.contains(&0) {
        return Read::Binary;
    }
    let rest = cap.saturating_add(1).saturating_sub(bytes.len() as u64);
    if (&mut file).take(rest).read_to_end(&mut bytes).is_err() {
        return Read::Unreadable;
    }
    if bytes.len() as u64 > cap {
        return Read::TooLarge;
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

/// The skipped files for a sentence: the first few by name, then a count, and what to do instead.
fn too_large_names(names: &[&str]) -> String {
    let shown = names.iter().take(5).copied().collect::<Vec<_>>().join(", ");
    let more = if names.len() > 5 { format!(" and {} more", names.len() - 5) } else { String::new() };
    format!("{shown}{more}; search them with `bash` (`grep -n PATTERN FILE`) or read them by line range with `read`")
}

fn grep_job(scan: &Scan, opts: &GrepOpts, hint_limits: HintLimits) -> ToolOutput {
    let found = scan.collect(opts.hidden, opts.no_ignore);
    let candidates: Vec<&Entry> =
        found.files.iter().filter(|e| opts.filter.as_ref().is_none_or(|g| g.matches(&e.rel))).collect();

    let mut sink = Sink::new(opts.bound);
    let mut groups_written = false;
    let (mut matches, mut files_with, mut scanned, mut binary, mut unreadable) = (0usize, 0usize, 0usize, 0usize, 0usize);
    let mut too_large: Vec<&str> = Vec::new();
    let mut interrupted = found.interrupted;
    for entry in &candidates {
        if scan.cancel.is_cancelled() {
            interrupted = true;
            break;
        }
        let content = match read_text(&entry.abs, MAX_GREP_FILE_BYTES) {
            Read::Text(t) => t,
            Read::Binary => {
                binary += 1;
                continue;
            }
            Read::TooLarge => {
                too_large.push(&entry.rel);
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
            sink.push(&format!("{} ({})\n", entry.rel, hits.len()), true);
            continue;
        }
        // Only as many matches as the bound still allows are written; the rest are counted above.
        let allowed = hits.get(..hits.len().min(sink.room())).unwrap_or_default();
        if opts.context == 0 {
            for &i in allowed {
                let line = lines.get(i).copied().unwrap_or_default();
                if !sink.push(&format!("{}:{}:{}\n", entry.rel, i + 1, windowed(line, &opts.re)), true) {
                    break;
                }
            }
        } else {
            let last_line = lines.len().saturating_sub(1);
            let mut ranges: Vec<(usize, usize)> = Vec::new();
            for &i in allowed {
                let (lo, hi) = (i.saturating_sub(opts.context), i.saturating_add(opts.context).min(last_line));
                match ranges.last_mut() {
                    Some(last) if lo <= last.1.saturating_add(1) => last.1 = last.1.max(hi),
                    _ => ranges.push((lo, hi)),
                }
            }
            for (lo, hi) in ranges {
                if groups_written && !sink.push("--\n", false) {
                    break;
                }
                groups_written = true;
                for j in lo..=hi {
                    // A match is marked as one even when it lies beyond the bound (inside the context of
                    // the last allowed match); only the allowed ones count as shown.
                    let sep = if hits.binary_search(&j).is_ok() { ':' } else { '-' };
                    let line = lines.get(j).copied().unwrap_or_default();
                    if !sink.push(&format!("{}{sep}{}{sep}{}\n", entry.rel, j + 1, windowed(line, &opts.re)), allowed.binary_search(&j).is_ok()) {
                        break;
                    }
                }
            }
        }
    }

    let mut more = vec![format!("{scanned} files searched")];
    if binary > 0 {
        more.push(format!("{binary} binary files skipped"));
    }
    if !too_large.is_empty() {
        more.push(format!(
            "{} files skipped as too large (over {MAX_GREP_FILE_BYTES} bytes); they were not searched, so the search is not complete: {}",
            too_large.len(),
            too_large_names(&too_large)
        ));
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
            scanned + binary + unreadable + too_large.len(),
            candidates.len()
        ));
    }

    let mut out = if matches == 0 {
        let outcome = if interrupted { "interrupted" } else { "no match" };
        let hint = if interrupted {
            String::new()
        } else {
            widened_hint(scan, opts.hidden, opts.no_ignore, &found, hint_limits, &|extra, budget| {
                extra
                    .iter()
                    .filter(|e| opts.filter.as_ref().is_none_or(|g| g.matches(&e.rel)))
                    .filter(|e| {
                        if !budget.spend() {
                            return false;
                        }
                        match read_text(&e.abs, MAX_GREP_FILE_BYTES) {
                            Read::Text(t) => t.lines().any(|l| opts.re.is_match(l)),
                            Read::TooLarge => {
                                budget.too_large.insert(e.abs.clone());
                                false
                            }
                            _ => false,
                        }
                    })
                    .count()
            })
        };
        let mut skipped = if binary > 0 { format!(", {binary} binary files skipped and not searched") } else { String::new() };
        if !too_large.is_empty() {
            skipped.push_str(&format!(
                ", {} files over {MAX_GREP_FILE_BYTES} bytes skipped as too large and not searched ({})",
                too_large.len(),
                too_large_names(&too_large)
            ));
        }
        let filtered = if opts.filter.is_some() { " matching the glob" } else { "" };
        let msg = format!(
            "No line matched `{}` in the {scanned} text files{filtered} searched under {} ({}){skipped}.{hint}",
            opts.pattern,
            scan.root.display(),
            set_description(opts.hidden, opts.no_ignore)
        );
        ToolOutput::ok(outcome, Body::Message(msg))
    } else {
        let (total, unit) = if opts.files_only { (files_with, "files with matches") } else { (matches, "matching lines") };
        let advice = if opts.files_only { GREP_FILES_ADVICE } else { GREP_ADVICE };
        let body = sink.finish(total, interrupted, unit, advice);
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
    async fn glob_stops_listing_at_the_result_bound_and_keeps_counting() {
        let e = capped(2);
        for i in 0..5 {
            put(&e, &format!("f{i}.txt"), "x");
        }
        let r = e.call("glob", json!({"pattern": "*.txt"})).await;
        assert!(r.text.contains("5 files"), "{}", r.text);
        let stored = e.stored(&r);
        let notice = "[Showing 2 of 5 files found; the rest were counted but not listed. Narrow the search (a more specific `pattern` or `path`) to see them.]\n";
        assert!(stored.starts_with(notice) && stored.ends_with(notice), "{stored}");
        assert_eq!(stored.lines().filter(|l| l.ends_with(".txt")).count(), 2, "{stored}");

        // The byte bound holds too, and a result under both bounds is just the paths.
        let scan = Scan::new(&e.ctx, None).unwrap();
        let glob = PathGlob::new("*.txt").unwrap();
        let out = glob_job(&scan, &glob, "*.txt", false, false, Bound { max_results: 100, max_bytes: 12 });
        let body = raw(&out);
        assert!(body.len() < 12 + 2 * 300 && body.starts_with("[Showing 1 of 5 files"), "{body}");
        let out = glob_job(&scan, &glob, "*.txt", false, false, Bound::new(5));
        assert_eq!(raw(&out).lines().count(), 5);
        assert!(!raw(&out).contains("Showing"));
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

    fn capped(max_results: usize) -> TestEnv {
        env_with(
            ToolsCfg { search_max_results: max_results, ..ToolsCfg::default() },
            SandboxCfg { mode: SandboxMode::None, ..SandboxCfg::default() },
        )
    }

    fn raw(out: &ToolOutput) -> String {
        match &out.body {
            Body::Raw(b) => String::from_utf8_lossy(b).into_owned(),
            other => panic!("not raw: {other:?}"),
        }
    }

    #[tokio::test]
    async fn grep_stops_listing_at_the_result_bound_and_keeps_counting() {
        let e = capped(3);
        put(&e, "a.txt", &"hit\n".repeat(4));
        put(&e, "b.txt", &"hit\n".repeat(6));
        let r = e.call("grep", json!({"pattern": "hit"})).await;
        assert!(r.text.contains("10 matches in 2 files"), "{}", r.text);
        let stored = e.stored(&r);
        let notice = "[Showing 3 of 10 matching lines found; the rest were counted but not listed. Narrow the search (a more specific `pattern`, `path` or `glob`, or `files_only`) to see them.]\n";
        assert_eq!(stored, format!("{notice}a.txt:1:hit\na.txt:2:hit\na.txt:3:hit\n{notice}"));

        // With context, only the allowed matches (and their context) are written.
        let e1 = capped(1);
        put(&e1, "c.txt", "hit\nx\nx\nx\nx\nx\nhit\n");
        let r = e1.call("grep", json!({"pattern": "hit", "path": "c.txt", "context": 1})).await;
        let stored = e1.stored(&r);
        assert!(stored.starts_with("[Showing 1 of 2 matching lines found;"), "{stored}");
        assert_eq!(stored.matches("c.txt:1:hit\nc.txt-2-x\n").count(), 1, "{stored}");
        assert_eq!(stored.matches("c.txt:7:").count(), 0, "{stored}");

        // files_only counts files.
        let e = capped(1);
        put(&e, "a.txt", "hit\n");
        put(&e, "b.txt", "hit\n");
        let r = e.call("grep", json!({"pattern": "hit", "files_only": true})).await;
        let stored = e.stored(&r);
        assert!(stored.starts_with("[Showing 1 of 2 files with matches found;") && stored.contains("\na.txt (1)\n[Showing 1 of 2"), "{stored}");
    }

    #[tokio::test]
    async fn grep_body_is_bounded_in_bytes() {
        let e = capped(1_000_000);
        put(&e, "big.txt", &format!("{}\n", "x".repeat(1000)).repeat(500));
        let scan = Scan::new(&e.ctx, None).unwrap();
        let mut opts = GrepOpts {
            re: Regex::new("x").unwrap(),
            pattern: "x".into(),
            filter: None,
            context: 0,
            context_clamped: false,
            files_only: false,
            hidden: false,
            no_ignore: false,
            bound: Bound { max_results: 1_000_000, max_bytes: 10_000 },
        };
        let out = grep_job(&scan, &opts, HintLimits::STANDARD);
        assert_eq!(out.outcome, "500 matches in 1 files");
        let body = raw(&out);
        assert!(body.len() < 10_000 + 2 * 300, "{}", body.len());
        assert!(body.starts_with("[Showing 9 of 500 matching lines found;") && body.ends_with("to see them.]\n"), "{}", &body[..80]);
        // The same bound with context.
        opts.context = 1;
        let body = raw(&grep_job(&scan, &opts, HintLimits::STANDARD));
        assert!(body.len() < 10_000 + 2 * 300 && body.starts_with("[Showing "), "{}", body.len());
    }

    #[tokio::test]
    async fn a_byte_limit_inside_trailing_context_is_announced() {
        let e = capped(100);
        put(&e, "f", "a\nhit\nb\n");
        let scan = Scan::new(&e.ctx, None).unwrap();
        let opts = GrepOpts {
            re: Regex::new("hit").unwrap(),
            pattern: "hit".into(),
            filter: None,
            context: 1,
            context_clamped: false,
            files_only: false,
            hidden: false,
            no_ignore: false,
            bound: Bound { max_results: 100, max_bytes: 16 },
        };
        let body = raw(&grep_job(&scan, &opts, HintLimits::STANDARD));
        assert!(body.starts_with("[Showing 1 of 1 matching lines found; the byte limit cut the context"), "{body}");
        assert!(body.contains("f-1-a\nf:2:hit\n") && !body.contains("f-3-b"), "{body}");
    }

    #[tokio::test]
    async fn a_match_inside_the_context_of_the_last_kept_one_keeps_its_marker() {
        let e = capped(1);
        put(&e, "f", "hit\nhit\nx\n");
        let r = e.call("grep", json!({"pattern": "hit", "context": 1})).await;
        let stored = e.stored(&r);
        assert!(stored.contains("f:1:hit\nf:2:hit\n") && !stored.contains("f-2-hit") && stored.starts_with("[Showing 1 of 2 "), "{stored}");
    }

    #[tokio::test]
    async fn a_cancelled_grep_and_glob_report_a_lower_bound() {
        let e = capped(1);
        put(&e, "a.txt", "hit\nhit\n");
        put(&e, "b.txt", "hit\n");
        let scan = Scan::new(&e.ctx, None).unwrap();
        let opts = GrepOpts {
            re: Regex::new("hit").unwrap(),
            pattern: "hit".into(),
            filter: None,
            context: 0,
            context_clamped: false,
            files_only: false,
            hidden: false,
            no_ignore: false,
            bound: Bound::new(1),
        };
        // Cancel after a first pass has proven the cut; the second search is interrupted before its first file.
        let mut sink = Sink::new(Bound::new(1));
        sink.push("x\n", true);
        sink.push("y\n", true);
        assert!(sink.finish(2, true, "files", GLOB_ADVICE).contains("of at least 2 files found before the search was interrupted"));
        e.ctx.cancel.cancel();
        let out = grep_job(&scan, &opts, HintLimits::STANDARD);
        assert_eq!(out.status, ToolStatus::Interrupted);
    }

    #[test]
    fn a_cut_by_an_interrupted_search_reports_a_lower_bound() {
        let mut sink = Sink::new(Bound::new(2));
        assert!(sink.push("a\n", true) && sink.push("b\n", true) && !sink.push("c\n", true));
        let text = sink.finish(9, true, "matching lines", GREP_ADVICE);
        assert!(text.starts_with("[Showing 2 of at least 9 matching lines found before the search was interrupted;"), "{text}");
        assert!(text.ends_with("to see them.]\n"), "{text}");
        // Under the bound the body is returned unchanged.
        let mut sink = Sink::new(Bound::new(2));
        sink.push("a\n", true);
        assert_eq!(sink.finish(1, true, "files", GLOB_ADVICE), "a\n");
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
    async fn oversized_and_binary_files_are_skipped_unread_and_reported() {
        let e = env();
        put(&e, "text.txt", "needle\n");
        // A sparse file over the cap: it is never read, so this is instant and needs no disk.
        let big = std::fs::File::create(e.ctx.workspace.join("model.bin")).unwrap();
        big.set_len(MAX_GREP_FILE_BYTES + 1).unwrap();
        // Binary at the very start: only the 8 KiB probe decides it.
        std::fs::write(e.ctx.workspace.join("bin.dat"), [0u8; 4096]).unwrap();
        let r = e.call("grep", json!({"pattern": "needle"})).await;
        assert!(r.text.contains("1 matches in 1 files"), "{}", r.text);
        assert!(r.text.contains("1 files skipped as too large") && r.text.contains("search is not complete"), "{}", r.text);
        assert!(r.text.contains("model.bin") && r.text.contains("`bash`"), "{}", r.text);
        assert!(r.text.contains("1 binary files skipped"), "{}", r.text);
        let r = e.call("grep", json!({"pattern": "absent"})).await;
        assert!(r.text.contains("1 files over") && r.text.contains("skipped as too large and not searched"), "{}", r.text);
        // read_text never returns the contents of a file over its cap.
        assert!(matches!(read_text(&e.ctx.workspace.join("model.bin"), MAX_GREP_FILE_BYTES), Read::TooLarge));
        assert!(matches!(read_text(&e.ctx.workspace.join("text.txt"), 3), Read::TooLarge));
        assert!(matches!(read_text(&e.ctx.workspace.join("bin.dat"), MAX_GREP_FILE_BYTES), Read::Binary));
        // The same holds for a single file named as the path.
        let r = e.call("grep", json!({"pattern": "needle", "path": "model.bin"})).await;
        assert!(r.text.contains("1 files skipped as too large"), "{}", r.text);
    }

    #[tokio::test]
    async fn no_match_hint_visits_each_combination_once() {
        let e = env();
        put(&e, "plain.txt", "nothing\n");
        put(&e, "ignored/only.txt", "zzz\n");
        put(&e, ".gitignore", "ignored/\n");
        for flags in [json!({"hidden": true}), json!({"no_ignore": false, "hidden": true})] {
            let mut args = json!({"pattern": "zzz"});
            args.as_object_mut().unwrap().extend(flags.as_object().unwrap().clone());
            let r = e.call("grep", args).await;
            assert_eq!(r.text.matches("more would match").count(), 1, "{}", r.text);
            assert!(r.text.contains("1 more would match with `no_ignore: true`"), "{}", r.text);
        }
        let r = e.call("grep", json!({"pattern": "qqq", "no_ignore": true})).await;
        assert_eq!(r.text.matches("would not change this").count(), 1, "{}", r.text);
        let r = e.call("glob", json!({"pattern": "only.txt", "hidden": true})).await;
        assert_eq!(r.text.matches("more would match").count(), 1, "{}", r.text);
    }

    #[tokio::test]
    async fn hint_pass_stops_on_cancellation_and_on_its_budget() {
        let e = env();
        tree(&e);
        let scan = Scan::new(&e.ctx, None).unwrap();
        let base = scan.collect(false, false);
        let limits = HintLimits { max_files: 1, max_time: Duration::from_secs(60) };
        let spent = std::cell::Cell::new(0usize);
        let hint = widened_hint(&scan, false, false, &base, limits, &|extra, budget| {
            let n = extra.iter().take_while(|_| budget.spend()).count();
            spent.set(spent.get() + n);
            n
        });
        assert_eq!(spent.get(), 1, "{hint}");
        assert!(hint.contains("limit of 1 files was reached") && hint.contains("counts may be low"), "{hint}");

        let spent = std::cell::Cell::new(0usize);
        let cancel = e.ctx.cancel.clone();
        let hint = widened_hint(&scan, false, false, &base, HintLimits::STANDARD, &|extra, budget| {
            cancel.cancel();
            let n = extra.iter().take_while(|_| budget.spend()).count();
            spent.set(spent.get() + n);
            n
        });
        assert_eq!(spent.get(), 0, "{hint}");
        assert!(hint.contains("interrupted"), "{hint}");
    }

    #[tokio::test]
    async fn grep_hint_honours_its_file_budget_and_counts_a_large_file_once() {
        let e = env();
        put(&e, "plain.txt", "nothing\n");
        for i in 0..4 {
            put(&e, &format!(".hidden/h{i}.txt"), "x\n");
        }
        let big = std::fs::File::create(e.ctx.workspace.join("ignored_big.bin")).unwrap();
        big.set_len(MAX_GREP_FILE_BYTES + 1).unwrap();
        put(&e, ".gitignore", "ignored_big.bin\n");
        let opts = GrepOpts {
            re: Regex::new("zzz").unwrap(),
            pattern: "zzz".into(),
            filter: None,
            context: 0,
            context_clamped: false,
            files_only: false,
            hidden: false,
            no_ignore: false,
            bound: Bound::new(200),
        };
        let scan = Scan::new(&e.ctx, None).unwrap();
        let hint_of = |limits| match grep_job(&scan, &opts, limits).body {
            Body::Message(m) => m,
            other => panic!("not a message: {other:?}"),
        };
        let m = hint_of(HintLimits { max_files: 2, max_time: Duration::from_secs(60) });
        assert!(m.contains("limit of 2 files was reached"), "{m}");
        // The large file is in two of the wider combinations, and is counted once.
        let m = hint_of(HintLimits::STANDARD);
        assert!(m.contains("1 of those files are over the"), "{m}");
        // A deadline that has passed ends the pass before any wider walk.
        let m = hint_of(HintLimits { max_files: 100, max_time: Duration::ZERO });
        assert!(m.contains("the time limit was reached"), "{m}");
    }

    #[tokio::test]
    async fn hint_does_not_claim_no_change_when_wider_files_were_too_large() {
        let e = env();
        put(&e, "plain.txt", "nothing\n");
        put(&e, ".gitignore", "ignored_big.bin\n");
        let big = std::fs::File::create(e.ctx.workspace.join("ignored_big.bin")).unwrap();
        big.set_len(MAX_GREP_FILE_BYTES + 1).unwrap();
        let r = e.call("grep", json!({"pattern": "zzz"})).await;
        assert!(!r.text.contains("Including hidden and git-ignored files would not change this"), "{}", r.text);
        assert!(r.text.contains("that could be read would not change this, but some could not be checked"), "{}", r.text);
        assert!(r.text.contains("1 of those files are over the"), "{}", r.text);
        // The time limit is added without the panicking operator.
        let budget = Budget::new(CancellationToken::new(), HintLimits { max_files: 1, max_time: Duration::MAX });
        assert!(budget.deadline > Instant::now());
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
