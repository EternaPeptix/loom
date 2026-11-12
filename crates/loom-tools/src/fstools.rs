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
//!
//! A file that is not valid UTF-8 → error (binary files are not edited).
//!
//! Tests required: read whole / range / past the end / missing with suggestion / directory / binary;
//! read then write then read round trip preserves bytes exactly (CRLF, no trailing newline,
//! unicode); write refusals (unread, changed) and acceptance after a read; atomicity leaves no temp
//! file; permissions kept; diff shown; edit unique / all / ambiguous / each no-match hint;
//! sandbox denial for read and write; `shown` ranges of read are exact.

use crate::files::{describe_type, open_probe, Freshness};
use crate::outview::{string, uint};
use crate::{params, schema, view, Body, Tool, ToolCtx, ToolOutput};
use async_trait::async_trait;
use loom_core::event::{ToolClass, ToolSpec, ToolStatus, META_PATH};
use serde_json::{json, Map, Value};
use similar::TextDiff;
use std::fs::{File, Metadata};
use std::io::{BufRead, BufReader, Read as IoRead, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio_util::sync::CancellationToken;

/// Longest line shown, in characters.
const MAX_LINE_CHARS: usize = 20_000;
/// Longest line shown inside an error hint, in characters.
const HINT_LINE_CHARS: usize = 500;
/// Most bytes `read`, `write` and `edit` load into memory from one file (64 MiB). A larger file can
/// still be read by line range, which streams it.
const READ_CAP: u64 = 64 * 1024 * 1024;
/// Size of one read from disk; cancellation is checked between reads.
const CHUNK: usize = 1 << 20;
/// A NUL within this many leading bytes marks a file as binary.
const BINARY_PROBE: usize = 8192;

/// Why a bounded read of a file did not produce its bytes.
enum Fail {
    Io(std::io::Error),
    NotRegular(&'static str),
    TooLarge(u64),
    Cancelled,
}

fn interrupted(message: String) -> ToolOutput {
    let mut out = ToolOutput::error(message);
    out.status = ToolStatus::Interrupted;
    out.outcome = "interrupted".into();
    out
}

/// Run blocking file work off the async workers and stop waiting when the call is cancelled. A read
/// stuck inside the kernel cannot be torn out, but the call returns at once as interrupted and the
/// work observes the same token between reads.
async fn off_thread<F>(ctx: &ToolCtx, tool: &str, work: F) -> ToolOutput
where
    F: FnOnce(ToolCtx) -> ToolOutput + Send + 'static,
{
    let owned = ctx.clone();
    let cancel = ctx.cancel.clone();
    let mut job = tokio::task::spawn_blocking(move || work(owned));
    tokio::select! {
        biased;
        done = &mut job => done.unwrap_or_else(|e| {
            ToolOutput::error(format!("The `{tool}` tool failed internally ({e}). Check the state of the file before repeating the call."))
        }),
        _ = cancel.cancelled() => interrupted(if tool == "read" {
            "The `read` call was interrupted before the file was read. Nothing was changed. Call `read` again if you still need it.".to_string()
        } else {
            format!("The `{tool}` call was interrupted, and the file may or may not have been changed. Read it again with `read` to see its current content before deciding what to do.")
        }),
    }
}

/// Read the rest of an open regular file, at most `cap` bytes, checking `cancel` between chunks.
fn read_open(mut file: File, len: u64, cap: u64, cancel: &CancellationToken) -> Result<Vec<u8>, Fail> {
    let mut bytes = Vec::with_capacity(usize::try_from(len.min(cap)).unwrap_or(0));
    let mut buf = vec![0u8; CHUNK];
    loop {
        if cancel.is_cancelled() {
            return Err(Fail::Cancelled);
        }
        let n = match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Fail::Io(e)),
        };
        bytes.extend_from_slice(buf.get(..n).unwrap_or_default());
        if bytes.len() as u64 > cap {
            return Err(Fail::TooLarge(bytes.len() as u64));
        }
    }
    Ok(bytes)
}

/// Open `path`, require a regular file of at most `cap` bytes, and read it.
fn read_bounded(path: &Path, cap: u64, cancel: &CancellationToken) -> Result<Vec<u8>, Fail> {
    let (file, meta) = open_probe(path).map_err(Fail::Io)?;
    if !meta.is_file() {
        return Err(Fail::NotRegular(describe_type(&meta.file_type())));
    }
    if meta.len() > cap {
        return Err(Fail::TooLarge(meta.len()));
    }
    read_open(file, meta.len(), cap, cancel)
}

fn not_regular(given: &str, tool: &str, kind: &str) -> ToolOutput {
    ToolOutput::error(format!(
        "{given} is {kind}, not a regular file, and `{tool}` works only on regular files. Name a regular file instead; to look at a device or pipe on purpose, use `bash` with a bounded command (for example `head -c 1000 {given}`)."
    ))
}

/// The error for a failed bounded read; `advice` says what to do about a file that is too large.
fn fail_output(fail: Fail, given: &str, tool: &str, advice: &str) -> ToolOutput {
    match fail {
        Fail::Io(e) => ToolOutput::error(format!("{given} cannot be read ({e}). Check the path and its permissions.")),
        Fail::NotRegular(kind) => not_regular(given, tool, kind),
        Fail::TooLarge(n) => ToolOutput::error(format!(
            "{given} is {n} bytes, above the {READ_CAP} byte limit `{tool}` loads into memory. {advice}"
        )),
        Fail::Cancelled => interrupted(format!(
            "The `{tool}` call was interrupted before it changed anything. Call `{tool}` again if you still need it."
        )),
    }
}

/// The error for a failed freshness check.
fn check_failed(given: &str, tool: &str, doing: &str, e: &std::io::Error) -> ToolOutput {
    if e.kind() == std::io::ErrorKind::InvalidInput {
        return ToolOutput::error(format!("{given} {e}, and `{tool}` works only on regular files. Name a regular file instead."));
    }
    ToolOutput::error(format!("{given} cannot be checked before {doing} ({e}). Check the path and its permissions."))
}

pub struct Read;
pub struct Write;
pub struct Edit;

/// Resolve and sandbox-check a path. A refusal is a `denied` result that already carries the path.
fn checked(ctx: &ToolCtx, given: &str, for_write: bool) -> Result<PathBuf, Box<ToolOutput>> {
    let resolved = ctx.sandbox.resolve(given);
    let verdict = if for_write { ctx.sandbox.check_write(&resolved) } else { ctx.sandbox.check_read(&resolved) };
    verdict.map_err(|msg| Box::new(ToolOutput::denied(msg).with_meta(META_PATH, json!(resolved.display().to_string()))))
}

fn with_path(out: ToolOutput, path: &Path) -> ToolOutput {
    out.with_meta(META_PATH, json!(path.display().to_string()))
}

/// Number of lines the way the blob store counts them: a final line without a newline counts.
fn count_lines(text: &str) -> u64 {
    let newlines = text.matches('\n').count() as u64;
    if text.is_empty() || text.ends_with('\n') {
        newlines
    } else {
        newlines + 1
    }
}

fn clip(line: &str) -> String {
    match line.char_indices().nth(HINT_LINE_CHARS) {
        Some((cut, _)) => format!("{}…[+{} chars]", &line[..cut], line[cut..].chars().count()),
        None => line.to_string(),
    }
}

/// The unified diff of `old` → `new` with 3 lines of context.
fn unified_diff(given: &str, old: &str, new: &str) -> String {
    let diff = TextDiff::from_lines(old, new).unified_diff().context_radius(3).header(given, given).to_string();
    if diff.is_empty() {
        "(no differences: the file already had exactly this content)".to_string()
    } else {
        diff
    }
}

/// Write `bytes` to `path` through a temporary file in the same directory, so that readers see the
/// old content or the new content and a failure leaves no partial file.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    std::fs::create_dir_all(parent)?;
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let tmp = parent.join(format!(".{name}.loom-{}-{}.tmp", std::process::id(), COUNTER.fetch_add(1, Ordering::Relaxed)));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_data()?;
        drop(file);
        if let Ok(meta) = std::fs::metadata(path) {
            std::fs::set_permissions(&tmp, meta.permissions())?;
        }
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Names in the directory of `path` that are close to its file name.
fn similar_names(path: &Path) -> Vec<String> {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name().map(|n| n.to_string_lossy().into_owned())) else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut near: Vec<(usize, String)> = entries
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| *n != name)
        .map(|n| (schema::distance(&name, &n), n))
        .filter(|(d, _)| *d <= 2)
        .collect();
    near.sort();
    near.into_iter().take(3).map(|(_, n)| dir.join(n).display().to_string()).collect()
}

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
        let given = string(args, "path");
        let path = match checked(ctx, given, false) {
            Ok(p) => p,
            Err(denied) => return *denied,
        };
        let (given, start, end) = (given.to_string(), uint(args, "start"), uint(args, "end"));
        let target = path.clone();
        let out = off_thread(ctx, "read", move |c| read_file(&c, &given, &target, start, end, READ_CAP)).await;
        with_path(out, &path)
    }
}

/// `cap` is the most bytes loaded whole; a larger file is read only by line range, streamed.
fn read_file(ctx: &ToolCtx, given: &str, path: &Path, start: Option<u64>, end: Option<u64>, cap: u64) -> ToolOutput {
    let (file, meta) = match open_probe(path) {
        Ok(x) => x,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut msg = format!("{given} does not exist.");
            let near = similar_names(path);
            if !near.is_empty() {
                msg.push_str(&format!(" Files with a similar name in that directory: {}.", near.join(", ")));
            }
            msg.push_str(" Check the path, or find the file with `glob`.");
            return ToolOutput::error(msg);
        }
        Err(e) => return ToolOutput::error(format!("{given} cannot be read ({e}). Check the path and its permissions.")),
    };
    if meta.is_dir() {
        return ToolOutput::error(format!(
            "{given} is a directory, not a file. List its files with `glob` (for example pattern `{}/*`) and read one of them.",
            given.trim_end_matches('/')
        ));
    }
    if !meta.is_file() {
        return not_regular(given, "read", describe_type(&meta.file_type()));
    }
    if meta.len() > cap {
        if start.is_none() && end.is_none() {
            return ToolOutput::error(format!(
                "{given} is {} bytes, above the {cap} byte limit `read` loads into memory. Pass `start` and `end` to read a range of its lines (the file is streamed), or use `grep` to find the lines you need.",
                meta.len()
            ));
        }
        return read_large_range(ctx, given, path, file, &meta, start, end);
    }
    let bytes = match read_open(file, meta.len(), cap, &ctx.cancel) {
        Ok(b) => b,
        Err(f) => {
            return fail_output(f, given, "read", "Pass `start` and `end` to read a range of its lines (the file is streamed), or use `grep` to find the lines you need.")
        }
    };
    ctx.files.note(path, &bytes);
    if bytes.is_empty() {
        return ToolOutput::ok("ok", Body::Message("(empty file)".into())).with_more(given.to_string());
    }
    let (stored, norm) = match view::store_text(&ctx.blobs, &bytes) {
        Ok(r) => r,
        Err(e) => return ToolOutput::error(format!("{given} was read but could not be stored for display ({e}). Try again.")),
    };
    if norm.binary {
        let notes = norm.notes();
        let mut out = ToolOutput::ok("ok", Body::View { of: stored.id, text: norm.text, shown: vec![(1, 1)] }).with_more(given.to_string());
        if let Some(notes) = notes {
            out = out.with_more(notes);
        }
        return out;
    }
    let total = stored.lines;
    let (first, last) = match view::window(start, end, total, ctx.cfg.read_max_lines) {
        Ok(Some(w)) => w,
        Ok(None) => return ToolOutput::ok("ok", Body::Message("(empty file)".into())).with_more(given.to_string()),
        Err(e) => return ToolOutput::error(e),
    };
    let (text, shortened) = match view::numbered(&ctx.blobs, &stored.id, first, last, MAX_LINE_CHARS) {
        Ok(r) => r,
        Err(e) => return ToolOutput::error(format!("{given} could not be shown ({e}). Try again.")),
    };
    let mut out = ToolOutput::ok("ok", Body::View { of: stored.id, text, shown: vec![(first, last)] })
        .with_more(given.to_string())
        .with_more(view::range_fact(first, last, total));
    if shortened > 0 {
        out = out.with_more(format!("{shortened} long lines shortened"));
    }
    if let Some(notes) = norm.notes() {
        out = out.with_more(notes);
    }
    if bytes.windows(2).any(|w| w == b"\r\n") {
        out = out.with_more("CRLF line endings (the CRs are not shown)");
    }
    out
}

/// The lines `first..=last` of a file, streamed, and what was learned about the rest of it.
struct Window {
    lines: Vec<(u64, String)>,
    shortened: u64,
    /// The number of lines in the file, known only when the scan reached its end.
    total: Option<u64>,
    more_below: bool,
    crlf: bool,
    binary: bool,
}

fn push_line(w: &mut Window, n: u64, cur: &[u8], full_bytes: u64) {
    let mut text = String::from_utf8_lossy(cur).into_owned();
    if full_bytes == cur.len() as u64 && text.ends_with('\r') {
        text.pop();
        w.crlf = true;
    }
    if full_bytes > cur.len() as u64 {
        let head: String = text.chars().take(MAX_LINE_CHARS).collect();
        text = format!("{head}…[line is {full_bytes} bytes; the rest is not shown]");
        w.shortened += 1;
    } else if let Some((cut, _)) = text.char_indices().nth(MAX_LINE_CHARS) {
        let rest = text.get(cut..).map_or(0, |r| r.chars().count());
        text = format!("{}…[+{rest} chars]", text.get(..cut).unwrap_or_default());
        w.shortened += 1;
    }
    w.lines.push((n, text));
}

/// Stream `file`, keeping only lines `first..=last` (each at most a bounded number of bytes).
fn stream_window(file: File, cancel: &CancellationToken, first: u64, last: u64) -> Result<Window, Fail> {
    let mut reader = BufReader::with_capacity(1 << 16, file);
    let keep = MAX_LINE_CHARS * 4;
    let mut w = Window { lines: Vec::new(), shortened: 0, total: None, more_below: false, crlf: false, binary: false };
    let mut lineno = 1u64;
    let mut cur: Vec<u8> = Vec::new();
    let mut cur_bytes = 0u64;
    let mut probed = false;
    loop {
        if cancel.is_cancelled() {
            return Err(Fail::Cancelled);
        }
        let buf = match reader.fill_buf() {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Fail::Io(e)),
        };
        if buf.is_empty() {
            break;
        }
        if !probed {
            probed = true;
            if buf.iter().take(BINARY_PROBE).any(|b| *b == 0) {
                w.binary = true;
                return Ok(w);
            }
        }
        let (take, ended) = match buf.iter().position(|b| *b == b'\n') {
            Some(i) => (i, true),
            None => (buf.len(), false),
        };
        let in_range = lineno >= first && lineno <= last;
        if in_range {
            let room = keep.saturating_sub(cur.len()).min(take);
            cur.extend_from_slice(buf.get(..room).unwrap_or_default());
        }
        cur_bytes += take as u64;
        reader.consume(take + usize::from(ended));
        if ended {
            if in_range {
                push_line(&mut w, lineno, &cur, cur_bytes);
            }
            cur.clear();
            cur_bytes = 0;
            if lineno >= last {
                w.more_below = !reader.fill_buf().map_err(Fail::Io)?.is_empty();
                if !w.more_below {
                    w.total = Some(lineno);
                }
                return Ok(w);
            }
            lineno += 1;
        }
    }
    if cur_bytes > 0 {
        if lineno >= first && lineno <= last {
            push_line(&mut w, lineno, &cur, cur_bytes);
        }
        w.total = Some(lineno);
    } else {
        w.total = Some(lineno - 1);
    }
    Ok(w)
}

/// A file above the whole-read cap, read by line range without loading it.
fn read_large_range(ctx: &ToolCtx, given: &str, path: &Path, file: File, meta: &Metadata, start: Option<u64>, end: Option<u64>) -> ToolOutput {
    let (first, last) = match view::window(start, end, u64::MAX, ctx.cfg.read_max_lines) {
        Ok(Some(w)) => w,
        Ok(None) => return ToolOutput::error("There is nothing to show for this range. Give a `start` of 1 or more."),
        Err(e) => return ToolOutput::error(e),
    };
    let w = match stream_window(file, &ctx.cancel, first, last) {
        Ok(w) => w,
        Err(f) => return fail_output(f, given, "read", "Use `grep` to find the lines you need."),
    };
    if w.binary {
        return ToolOutput::error(format!(
            "{given} is binary data of {} bytes, above the size limit for whole reads, so it cannot be shown as lines. Use `bash` with a bounded command such as `xxd -l 256 {given}`.",
            meta.len()
        ));
    }
    let Some(shown_last) = w.lines.last().map(|(n, _)| *n) else {
        return match view::window(start, end, w.total.unwrap_or(0), ctx.cfg.read_max_lines) {
            Err(e) => ToolOutput::error(e),
            _ => ToolOutput::ok("ok", Body::Message("(empty file)".into())).with_more(given.to_string()),
        };
    };
    ctx.files.note_stat(path, meta);
    let text = w.lines.iter().map(|(n, t)| format!("{n}\t{t}")).collect::<Vec<_>>().join("\n");
    let range = match w.total {
        Some(total) => view::range_fact(first, shown_last, total),
        None => format!(
            "lines {first}-{shown_last} — more below (the file is {} bytes, above the whole-read limit, so its lines are not counted)",
            meta.len()
        ),
    };
    let mut out = ToolOutput::ok("ok", Body::Message(text)).with_more(given.to_string()).with_more(range);
    if w.shortened > 0 {
        out = out.with_more(format!("{} long lines shortened", w.shortened));
    }
    if w.crlf {
        out = out.with_more("CRLF line endings (the CRs are not shown)");
    }
    out
}

/// Why a write or edit must not proceed on a file in this state, if it must not.
fn freshness_refusal(fresh: &Freshness, given: &str, tool: &str) -> Option<ToolOutput> {
    match fresh {
        Freshness::Unread => Some(ToolOutput::error(format!(
            "{given} exists and has not been read in this session, so `{tool}` could replace content you have not seen. Read it with `read` first, then call `{tool}` again."
        ))),
        Freshness::Changed { was_bytes, now_bytes } => Some(ToolOutput::error(format!(
            "{given} changed on disk since you read it ({was_bytes} → {now_bytes} bytes), so `{tool}` could overwrite someone else's change. Read it again with `read`, then call `{tool}` again."
        ))),
        Freshness::Missing | Freshness::Current => None,
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
        let given = string(args, "path");
        let path = match checked(ctx, given, true) {
            Ok(p) => p,
            Err(denied) => return *denied,
        };
        let (given, content) = (given.to_string(), string(args, "content").to_string());
        let target = path.clone();
        let out = off_thread(ctx, "write", move |c| write_file(&c, &given, &target, &content)).await;
        with_path(out, &path)
    }
}

fn write_file(ctx: &ToolCtx, given: &str, path: &Path, content: &str) -> ToolOutput {
    if path.is_dir() {
        return ToolOutput::error(format!("{given} is a directory. Give the path of a file to write."));
    }
    let fresh = match ctx.files.check(path) {
        Ok(f) => f,
        Err(e) => return check_failed(given, "write", "writing", &e),
    };
    if let Some(refusal) = freshness_refusal(&fresh, given, "write") {
        return refusal;
    }
    // The previous content is needed only for the diff; a file above the cap is replaced without one.
    let mut diff_omitted = false;
    let old = if fresh == Freshness::Current {
        match read_bounded(path, READ_CAP, &ctx.cancel) {
            Ok(b) => Some(b),
            Err(Fail::TooLarge(_)) => {
                diff_omitted = true;
                None
            }
            Err(f) => return fail_output(f, given, "write", ""),
        }
    } else {
        None
    };
    if let Err(e) = write_atomic(path, content.as_bytes()) {
        return ToolOutput::error(format!("{given} could not be written ({e}). Nothing was changed; check that the directory is writable and try again."));
    }
    ctx.files.note(path, content.as_bytes());
    let facts = [format!("{} lines", count_lines(content)), format!("{} bytes", content.len())];
    let mut out = match old {
        Some(old) => {
            let diff = unified_diff(given, &String::from_utf8_lossy(&old), content);
            ToolOutput::ok("replaced", Body::Raw(diff.into_bytes()))
        }
        None if diff_omitted => ToolOutput::ok(
            "replaced",
            Body::Message(format!("(no diff: the previous file was larger than {READ_CAP} bytes, so it was replaced without reading it back)")),
        ),
        None => ToolOutput::ok("created", Body::Message("(new file)".into())),
    };
    out = out.with_more(given.to_string());
    for f in facts {
        out = out.with_more(f);
    }
    out
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
        let given = string(args, "path");
        let path = match checked(ctx, given, true) {
            Ok(p) => p,
            Err(denied) => return *denied,
        };
        let all = args.get("all").and_then(Value::as_bool).unwrap_or(false);
        let (given, old, new) = (given.to_string(), string(args, "old").to_string(), string(args, "new").to_string());
        let target = path.clone();
        let out = off_thread(ctx, "edit", move |c| edit_file(&c, &given, &target, &old, &new, all)).await;
        with_path(out, &path)
    }
}

fn edit_file(ctx: &ToolCtx, given: &str, path: &Path, old: &str, new: &str, all: bool) -> ToolOutput {
    if old.is_empty() {
        return ToolOutput::error("`old` is empty, so there is nothing to find. Give the exact text to replace; to add text to an empty or new file use `write`.");
    }
    if old == new {
        return ToolOutput::error("`old` and `new` are identical, so the edit would change nothing. Give a `new` that differs from `old`.");
    }
    if path.is_dir() {
        return ToolOutput::error(format!("{given} is a directory. Give the path of a file to edit."));
    }
    let fresh = match ctx.files.check(path) {
        Ok(f) => f,
        Err(e) => return check_failed(given, "edit", "editing", &e),
    };
    if fresh == Freshness::Missing {
        return ToolOutput::error(format!("{given} does not exist, so there is nothing to edit. Create it with `write`, or check the path (`glob` finds files)."));
    }
    if let Some(refusal) = freshness_refusal(&fresh, given, "edit") {
        return refusal;
    }
    let bytes = match read_bounded(path, READ_CAP, &ctx.cancel) {
        Ok(b) => b,
        Err(f) => return fail_output(f, given, "edit", "Use `bash` for a change to a file this large."),
    };
    let text = match String::from_utf8(bytes) {
        Ok(t) => t,
        Err(_) => return ToolOutput::error(format!("{given} is not valid UTF-8 text, and binary files are not edited. Use `bash` for a binary change.")),
    };

    // A file that uses CRLF throughout shows the model lines without the CRs; the text it gives is
    // matched, and what it puts in, with the file's own line endings.
    let crlf = text.contains("\r\n") && text.matches('\n').count() == text.matches("\r\n").count() && !old.contains('\r') && !new.contains('\r');
    let (old, new) = if crlf { (old.replace('\n', "\r\n"), new.replace('\n', "\r\n")) } else { (old.to_string(), new.to_string()) };

    let positions: Vec<usize> = text.match_indices(old.as_str()).map(|(i, _)| i).collect();
    if positions.is_empty() {
        return ToolOutput::error(no_match_message(given, &text, &old));
    }
    if positions.len() > 1 && !all {
        let lines: Vec<String> = positions
            .iter()
            .take(10)
            .map(|&i| text.get(..i).map_or(0, |head| head.matches('\n').count() + 1).to_string())
            .collect();
        let more = if positions.len() > 10 { format!(" (the first 10 of {})", positions.len()) } else { String::new() };
        return ToolOutput::error(format!(
            "`old` occurs {} times in {given}, at lines {}{more}. Nothing was changed. Extend `old` with the surrounding lines so it matches exactly once, or set `all` to true to replace every occurrence.",
            positions.len(),
            lines.join(", ")
        ));
    }
    let updated = text.replace(old.as_str(), &new);
    if let Err(e) = write_atomic(path, updated.as_bytes()) {
        return ToolOutput::error(format!("{given} could not be written ({e}). Nothing was changed; check that the file is writable and try again."));
    }
    ctx.files.note(path, updated.as_bytes());
    let n = positions.len();
    let count = if n == 1 { "1 replacement".to_string() } else { format!("{n} replacements") };
    ToolOutput::ok("edited", Body::Raw(unified_diff(given, &text, &updated).into_bytes()))
        .with_more(given.to_string())
        .with_more(count)
}

/// What to tell the model when `old` is not in the file: the nearest real text, never a guess applied.
fn no_match_message(given: &str, text: &str, old: &str) -> String {
    let file_lines: Vec<&str> = text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l)).collect();
    let mut old_lines: Vec<&str> = old.split('\n').collect();
    if old_lines.len() > 1 && old_lines.last().is_some_and(|l| l.is_empty()) {
        old_lines.pop();
    }
    let numbered = |from: usize, to: usize| -> String {
        file_lines
            .iter()
            .enumerate()
            .take(to.saturating_add(1))
            .skip(from)
            .map(|(i, l)| format!("{}\t{}", i + 1, clip(l)))
            .collect::<Vec<_>>()
            .join("\n")
    };

    let wanted: Vec<&str> = old_lines.iter().map(|l| l.trim()).collect();
    let n = wanted.len();
    if n <= file_lines.len() {
        for start in 0..=(file_lines.len() - n) {
            let same = file_lines.iter().skip(start).take(n).map(|l| l.trim()).eq(wanted.iter().copied());
            if same {
                return format!(
                    "`old` was not found as written, but lines {}-{} of {given} match it when leading and trailing whitespace is ignored. Those lines, exactly as they are in the file:\n{}\nCopy `old` from them, keeping their exact whitespace, and call `edit` again. Nothing was changed.",
                    start + 1,
                    start + n,
                    numbered(start, start + n - 1)
                );
            }
        }
    }

    let first = wanted.first().copied().unwrap_or("");
    if !first.is_empty() {
        if let Some(at) = file_lines.iter().position(|l| l.contains(first)) {
            let from = at.saturating_sub(2);
            let to = (at + n + 1).min(file_lines.len().saturating_sub(1));
            return format!(
                "`old` was not found in {given}. Its first line does occur, at line {}; the file has this there (lines {}-{}):\n{}\nCompare it with your `old` and call `edit` again with text copied exactly from these lines. Nothing was changed.",
                at + 1,
                from + 1,
                to + 1,
                numbered(from, to)
            );
        }
    }
    format!(
        "`old` was not found in {given}, and nothing similar was found. The file has {} lines. Use `read` (or `grep`) to look at the part you mean to change, then call `edit` again with text copied exactly from it. Nothing was changed.",
        count_lines(text)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{env, env_with, TestEnv};
    use loom_core::config::{SandboxCfg, SandboxMode, ToolsCfg};
    use loom_core::event::{ToolResult, ToolStatus, META_SHOWN};

    fn ws(e: &TestEnv, name: &str) -> PathBuf {
        e.ctx.workspace.join(name)
    }

    fn put(e: &TestEnv, name: &str, bytes: &[u8]) -> PathBuf {
        let p = ws(e, name);
        std::fs::write(&p, bytes).expect("write fixture");
        p
    }

    fn shown(r: &ToolResult) -> Value {
        r.meta.get(META_SHOWN).cloned().unwrap_or(Value::Null)
    }

    fn is_err(r: &ToolResult) -> bool {
        r.status == ToolStatus::Error
    }

    fn numbered_file(n: usize) -> String {
        (1..=n).map(|i| format!("row {i}\n")).collect()
    }

    #[tokio::test]
    async fn read_whole_range_and_past_end() {
        let e = env_with(
            ToolsCfg { read_max_lines: 10, ..ToolsCfg::default() },
            SandboxCfg { mode: SandboxMode::None, ..SandboxCfg::default() },
        );
        put(&e, "f.txt", numbered_file(25).as_bytes());
        let r = e.call("read", json!({"path": "f.txt"})).await;
        assert_eq!(shown(&r), json!([[1, 10]]));
        assert!(r.text.contains("lines 1-10 of 25 — 15 more below") && r.text.contains("1\trow 1\n"), "{}", r.text);
        assert_eq!(r.meta.get(META_PATH).and_then(Value::as_str), Some(ws(&e, "f.txt").to_str().unwrap()));
        let r = e.call("read", json!({"path": "f.txt", "start": 12, "end": 14})).await;
        assert_eq!(shown(&r), json!([[12, 14]]));
        assert!(r.text.contains("12\trow 12\n13\trow 13\n14\trow 14") && !r.text.contains("15\trow"), "{}", r.text);
        let r = e.call("read", json!({"path": "f.txt", "start": 20, "end": 99})).await;
        assert_eq!(shown(&r), json!([[20, 25]]));
        let r = e.call("read", json!({"path": "f.txt", "start": 26})).await;
        assert!(is_err(&r) && r.text.contains("25 lines"), "{}", r.text);
    }

    #[tokio::test]
    async fn read_empty_directory_missing_and_binary() {
        let e = env();
        put(&e, "empty.txt", b"");
        let r = e.call("read", json!({"path": "empty.txt"})).await;
        assert!(r.text.contains("(empty file)") && !is_err(&r), "{}", r.text);

        std::fs::create_dir(ws(&e, "sub")).unwrap();
        let r = e.call("read", json!({"path": "sub"})).await;
        assert!(is_err(&r) && r.text.contains("directory") && r.text.contains("glob"), "{}", r.text);

        put(&e, "Readme.md", b"x");
        put(&e, "main.rs", b"x");
        put(&e, "zzzzzzzz", b"x");
        let r = e.call("read", json!({"path": "Readm.md"})).await;
        assert!(is_err(&r) && r.text.contains("does not exist") && r.text.contains("Readme.md"), "{}", r.text);
        let r = e.call("read", json!({"path": "man.rs"})).await;
        assert!(r.text.contains("main.rs") && !r.text.contains("zzzzzzzz"), "{}", r.text);
        let r = e.call("read", json!({"path": "nothing-like-it.txt"})).await;
        assert!(is_err(&r) && !r.text.contains("similar name"), "{}", r.text);

        put(&e, "bin.dat", &[0u8, 1, 2, 0xff, 0, 0, 7]);
        let r = e.call("read", json!({"path": "bin.dat"})).await;
        assert!(r.text.contains("binary data, 7 bytes") && r.text.contains("binary"), "{}", r.text);
        assert_eq!(shown(&r), json!([[1, 1]]));
    }

    fn message(o: &ToolOutput) -> String {
        match &o.body {
            Body::Message(m) => m.clone(),
            other => format!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn read_write_edit_refuse_devices_and_fifos_quickly() {
        let e = env();
        let fifo = ws(&e, "pipe");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let limit = std::time::Duration::from_secs(10);
        for target in ["/dev/zero".to_string(), fifo.display().to_string()] {
            let r = tokio::time::timeout(limit, e.call("read", json!({"path": target}))).await.expect("read must not hang");
            assert!(is_err(&r) && r.text.contains("not a regular file") && r.text.contains("bash"), "{}", r.text);
        }
        let r = tokio::time::timeout(limit, e.call("read", json!({"path": "pipe"}))).await.expect("read must not hang");
        assert!(r.text.contains("FIFO"), "{}", r.text);
        let r = tokio::time::timeout(limit, e.call("write", json!({"path": "pipe", "content": "x"}))).await.expect("write must not hang");
        assert!(is_err(&r) && r.text.contains("regular file"), "{}", r.text);
        let r = tokio::time::timeout(limit, e.call("edit", json!({"path": "pipe", "old": "a", "new": "b"}))).await.expect("edit must not hang");
        assert!(is_err(&r) && r.text.contains("regular file"), "{}", r.text);
        assert!(std::os::unix::fs::FileTypeExt::is_fifo(&std::fs::symlink_metadata(&fifo).unwrap().file_type()));
    }

    #[tokio::test]
    async fn file_above_the_cap_is_refused_whole_and_read_by_range() {
        let e = env();
        let path = put(&e, "huge.txt", numbered_file(200).as_bytes());
        let size = std::fs::metadata(&path).unwrap().len();
        let whole = read_file(&e.ctx, "huge.txt", &path, None, None, 100);
        assert_eq!(whole.status, ToolStatus::Error);
        let m = message(&whole);
        assert!(m.contains(&format!("{size} bytes")) && m.contains("`start` and `end`") && m.contains("grep"), "{m}");

        let part = read_file(&e.ctx, "huge.txt", &path, Some(5), Some(7), 100);
        assert_eq!(part.status, ToolStatus::Ok);
        assert_eq!(message(&part), "5\trow 5\n6\trow 6\n7\trow 7");
        assert!(part.more.iter().any(|f| f.contains("more below")), "{:?}", part.more);

        let tail = read_file(&e.ctx, "huge.txt", &path, Some(199), Some(900), 100);
        assert_eq!(message(&tail), "199\trow 199\n200\trow 200");
        assert!(tail.more.iter().any(|f| f.contains("lines 199-200 of 200")), "{:?}", tail.more);
        let past = read_file(&e.ctx, "huge.txt", &path, Some(300), None, 100);
        assert!(message(&past).contains("200 lines"), "{}", message(&past));

        std::fs::write(&path, [b'a', 0, b'b'].repeat(100)).unwrap();
        let bin = read_file(&e.ctx, "huge.txt", &path, Some(1), Some(2), 100);
        assert!(message(&bin).contains("binary"), "{}", message(&bin));
    }

    #[tokio::test]
    async fn write_and_edit_refuse_a_changed_file_that_was_read_by_range() {
        let e = env();
        let path = put(&e, "big.txt", numbered_file(50).as_bytes());
        let seen = read_file(&e.ctx, "big.txt", &path, Some(1), Some(2), 10);
        assert_eq!(seen.status, ToolStatus::Ok);
        // Unchanged since the ranged read: the freshness check passes without hashing the file.
        let r = e.call("edit", json!({"path": "big.txt", "old": "row 3\n", "new": "three\n"})).await;
        assert!(!is_err(&r), "{}", r.text);
        // A second ranged read, then someone else changes the file.
        read_file(&e.ctx, "big.txt", &path, Some(1), Some(2), 10);
        put(&e, "big.txt", b"changed elsewhere\n");
        let r = e.call("write", json!({"path": "big.txt", "content": "x"})).await;
        assert!(is_err(&r) && r.text.contains("changed on disk"), "{}", r.text);
        let r = e.call("edit", json!({"path": "big.txt", "old": "changed", "new": "x"})).await;
        assert!(is_err(&r) && r.text.contains("changed on disk"), "{}", r.text);
        assert_eq!(std::fs::read(&path).unwrap(), b"changed elsewhere\n");
    }

    #[tokio::test]
    async fn cancellation_returns_interrupted_even_while_the_work_is_stuck() {
        let e = env();
        let cancel = e.ctx.cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            cancel.cancel();
        });
        let started = std::time::Instant::now();
        let out = off_thread(&e.ctx, "read", |_c| {
            std::thread::sleep(std::time::Duration::from_millis(1500));
            ToolOutput::error("finished late")
        })
        .await;
        assert_eq!(out.status, ToolStatus::Interrupted);
        assert!(started.elapsed() < std::time::Duration::from_millis(1000), "{:?}", started.elapsed());

        // A call cancelled before it starts reading also ends as interrupted, whole or ranged.
        put(&e, "f.txt", numbered_file(20).as_bytes());
        let r = e.call("read", json!({"path": "f.txt"})).await;
        assert_eq!(r.status, ToolStatus::Interrupted, "{}", r.text);
        let path = ws(&e, "f.txt");
        let r = read_file(&e.ctx, "f.txt", &path, Some(1), Some(2), 10);
        assert_eq!(r.status, ToolStatus::Interrupted);
    }

    #[tokio::test]
    async fn round_trip_preserves_bytes() {
        let e = env();
        let cases: [(&str, &str); 4] = [
            ("crlf.txt", "one\r\ntwo\r\nthree\r\n"),
            ("nonl.txt", "no final newline"),
            ("uni.txt", "héllo wörld ✓ 日本語\n🦀\n"),
            ("mixed.txt", "a\r\nb\nc\r\n\n\n"),
        ];
        for (name, content) in cases {
            put(&e, name, b"old content\n");
            let r = e.call("read", json!({"path": name})).await;
            assert!(!is_err(&r));
            let r = e.call("write", json!({"path": name, "content": content})).await;
            assert!(!is_err(&r), "{}", r.text);
            assert_eq!(std::fs::read(ws(&e, name)).unwrap(), content.as_bytes(), "{name}");
            // The written file is current, so reading and writing it back again is allowed and exact.
            let r = e.call("read", json!({"path": name})).await;
            assert!(!is_err(&r) && !r.text.contains('\r'), "{}", r.text);
            let r = e.call("write", json!({"path": name, "content": content})).await;
            assert!(!is_err(&r), "{}", r.text);
            assert_eq!(std::fs::read(ws(&e, name)).unwrap(), content.as_bytes(), "{name}");
        }
    }

    #[tokio::test]
    async fn read_reports_crlf_and_missing_final_newline_shown() {
        let e = env();
        put(&e, "c.txt", b"a\r\nb");
        let r = e.call("read", json!({"path": "c.txt"})).await;
        assert!(r.text.contains("1\ta\n2\tb") && r.text.contains("CRLF"), "{}", r.text);
        assert_eq!(shown(&r), json!([[1, 2]]));
    }

    #[tokio::test]
    async fn write_creates_and_refuses_unread_and_changed() {
        let e = env();
        let r = e.call("write", json!({"path": "new/dir/a.txt", "content": "hi\nthere\n"})).await;
        assert!(r.text.contains("created") && r.text.contains("2 lines") && r.text.contains("9 bytes") && r.text.contains("(new file)"), "{}", r.text);
        assert_eq!(std::fs::read(ws(&e, "new/dir/a.txt")).unwrap(), b"hi\nthere\n");

        put(&e, "b.txt", b"existing\n");
        let r = e.call("write", json!({"path": "b.txt", "content": "x"})).await;
        assert!(is_err(&r) && r.text.contains("has not been read") && r.text.contains("`read`"), "{}", r.text);
        assert_eq!(std::fs::read(ws(&e, "b.txt")).unwrap(), b"existing\n");

        e.call("read", json!({"path": "b.txt"})).await;
        put(&e, "b.txt", b"changed elsewhere\n");
        let r = e.call("write", json!({"path": "b.txt", "content": "x"})).await;
        assert!(is_err(&r) && r.text.contains("9 → 18 bytes") && r.text.contains("Read it again"), "{}", r.text);
        assert_eq!(std::fs::read(ws(&e, "b.txt")).unwrap(), b"changed elsewhere\n");

        e.call("read", json!({"path": "b.txt"})).await;
        let r = e.call("write", json!({"path": "b.txt", "content": "changed elsewhere\nplus\n"})).await;
        assert!(r.text.contains("replaced"), "{}", r.text);
        assert!(r.text.contains("+plus") && r.text.contains(" changed elsewhere"), "{}", r.text);
    }

    #[tokio::test]
    async fn write_leaves_no_temp_file_and_keeps_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let e = env();
        let p = put(&e, "run.sh", b"#!/bin/sh\n");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        e.call("read", json!({"path": "run.sh"})).await;
        let r = e.call("write", json!({"path": "run.sh", "content": "#!/bin/sh\necho hi\n"})).await;
        assert!(!is_err(&r), "{}", r.text);
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o755);
        let names: Vec<String> = std::fs::read_dir(&e.ctx.workspace).unwrap().flatten().map(|d| d.file_name().to_string_lossy().into_owned()).collect();
        assert_eq!(names, vec!["run.sh".to_string()]);
    }

    #[tokio::test]
    async fn write_to_a_directory_is_refused() {
        let e = env();
        std::fs::create_dir(ws(&e, "d")).unwrap();
        let r = e.call("write", json!({"path": "d", "content": "x"})).await;
        assert!(is_err(&r) && r.text.contains("directory"), "{}", r.text);
    }

    #[tokio::test]
    async fn long_diff_is_stored_whole() {
        let e = env();
        put(&e, "big.txt", numbered_file(3000).as_bytes());
        e.call("read", json!({"path": "big.txt", "start": 1, "end": 2})).await;
        let new: String = (1..=3000).map(|i| format!("changed {i}\n")).collect();
        let r = e.call("write", json!({"path": "big.txt", "content": new})).await;
        assert!(r.output.is_some());
        let stored = e.stored(&r);
        assert!(stored.contains("-row 3000") && stored.contains("+changed 3000"));
    }

    #[tokio::test]
    async fn edit_unique_all_and_ambiguous() {
        let e = env();
        put(&e, "c.txt", b"alpha\nbeta\nalpha\ngamma\n");
        let r = e.call("edit", json!({"path": "c.txt", "old": "beta", "new": "BETA"})).await;
        assert!(is_err(&r) && r.text.contains("not been read"), "{}", r.text);
        e.call("read", json!({"path": "c.txt"})).await;

        let r = e.call("edit", json!({"path": "c.txt", "old": "alpha", "new": "A"})).await;
        assert!(is_err(&r) && r.text.contains("2 times") && r.text.contains("lines 1, 3") && r.text.contains("`all`"), "{}", r.text);
        assert_eq!(std::fs::read(ws(&e, "c.txt")).unwrap(), b"alpha\nbeta\nalpha\ngamma\n");

        let r = e.call("edit", json!({"path": "c.txt", "old": "beta", "new": "BETA"})).await;
        assert!(r.text.contains("edited") && r.text.contains("1 replacement") && r.text.contains("-beta") && r.text.contains("+BETA"), "{}", r.text);
        assert_eq!(std::fs::read(ws(&e, "c.txt")).unwrap(), b"alpha\nBETA\nalpha\ngamma\n");

        // The edit refreshed what the session has seen, so the next one needs no new read.
        let r = e.call("edit", json!({"path": "c.txt", "old": "alpha", "new": "A", "all": true})).await;
        assert!(r.text.contains("2 replacements"), "{}", r.text);
        assert_eq!(std::fs::read(ws(&e, "c.txt")).unwrap(), b"A\nBETA\nA\ngamma\n");
    }

    #[tokio::test]
    async fn edit_ambiguous_lists_ten_lines() {
        let e = env();
        put(&e, "m.txt", "x\n".repeat(12).as_bytes());
        e.call("read", json!({"path": "m.txt"})).await;
        let r = e.call("edit", json!({"path": "m.txt", "old": "x", "new": "y"})).await;
        assert!(r.text.contains("12 times") && r.text.contains("1, 2, 3, 4, 5, 6, 7, 8, 9, 10 (the first 10 of 12)"), "{}", r.text);
    }

    #[tokio::test]
    async fn edit_argument_and_state_errors() {
        let e = env();
        let r = e.call("edit", json!({"path": "none.txt", "old": "a", "new": "b"})).await;
        assert!(is_err(&r) && r.text.contains("does not exist"), "{}", r.text);
        put(&e, "f.txt", b"abc\n");
        e.call("read", json!({"path": "f.txt"})).await;
        let r = e.call("edit", json!({"path": "f.txt", "old": "", "new": "b"})).await;
        assert!(is_err(&r) && r.text.contains("empty"), "{}", r.text);
        let r = e.call("edit", json!({"path": "f.txt", "old": "abc", "new": "abc"})).await;
        assert!(is_err(&r) && r.text.contains("identical"), "{}", r.text);
        put(&e, "f.txt", b"abcd\n");
        let r = e.call("edit", json!({"path": "f.txt", "old": "abc", "new": "x"})).await;
        assert!(is_err(&r) && r.text.contains("4 → 5 bytes"), "{}", r.text);
        put(&e, "bad.bin", &[0xff, 0xfe, b'a', b'b']);
        e.call("read", json!({"path": "bad.bin"})).await;
        let r = e.call("edit", json!({"path": "bad.bin", "old": "ab", "new": "x"})).await;
        assert!(is_err(&r) && r.text.contains("UTF-8"), "{}", r.text);
    }

    #[tokio::test]
    async fn edit_no_match_whitespace_hint() {
        let e = env();
        put(&e, "w.py", b"def f():\n    if x:\n        return 1\n    return 2\n");
        e.call("read", json!({"path": "w.py"})).await;
        let r = e.call("edit", json!({"path": "w.py", "old": "if x:\n    return 1", "new": "pass"})).await;
        assert!(is_err(&r), "{}", r.text);
        assert!(r.text.contains("lines 2-3") && r.text.contains("whitespace"), "{}", r.text);
        assert!(r.text.contains("2\t    if x:\n3\t        return 1"), "{}", r.text);
        assert_eq!(std::fs::read(ws(&e, "w.py")).unwrap(), b"def f():\n    if x:\n        return 1\n    return 2\n");
    }

    #[tokio::test]
    async fn edit_no_match_first_line_hint_and_nothing_similar() {
        let e = env();
        put(&e, "g.txt", b"1\n2\n3\nfn main() {\n    run();\n}\n7\n8\n9\n");
        e.call("read", json!({"path": "g.txt"})).await;
        let r = e.call("edit", json!({"path": "g.txt", "old": "fn main() {\n    start();\n}", "new": "x"})).await;
        assert!(is_err(&r) && r.text.contains("first line does occur, at line 4"), "{}", r.text);
        assert!(r.text.contains("2\t2\n3\t3\n4\tfn main() {\n5\t    run();\n6\t}\n7\t7\n8\t8"), "{}", r.text);
        assert!(!r.text.contains("9\t9"), "{}", r.text);
        let r = e.call("edit", json!({"path": "g.txt", "old": "zebra", "new": "x"})).await;
        assert!(is_err(&r) && r.text.contains("nothing similar") && r.text.contains("9 lines"), "{}", r.text);
    }

    #[tokio::test]
    async fn edit_in_crlf_file_keeps_line_endings() {
        let e = env();
        put(&e, "w.txt", b"one\r\ntwo\r\nthree\r\n");
        e.call("read", json!({"path": "w.txt"})).await;
        let r = e.call("edit", json!({"path": "w.txt", "old": "one\ntwo", "new": "1\n2\n2b"})).await;
        assert!(!is_err(&r), "{}", r.text);
        assert_eq!(std::fs::read(ws(&e, "w.txt")).unwrap(), b"1\r\n2\r\n2b\r\nthree\r\n");
    }

    #[tokio::test]
    async fn edit_without_trailing_newline_is_exact() {
        let e = env();
        put(&e, "n.txt", b"keep\nlast");
        e.call("read", json!({"path": "n.txt"})).await;
        let r = e.call("edit", json!({"path": "n.txt", "old": "last", "new": "end"})).await;
        assert!(!is_err(&r), "{}", r.text);
        assert_eq!(std::fs::read(ws(&e, "n.txt")).unwrap(), b"keep\nend");
        assert!(r.text.contains("No newline at end of file"), "{}", r.text);
    }

    #[tokio::test]
    async fn sandbox_denial_for_read_and_write() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().canonicalize().unwrap().join("secret");
        std::fs::create_dir(&secret).unwrap();
        std::fs::write(secret.join("k.txt"), "key").unwrap();
        let cfg = SandboxCfg {
            mode: SandboxMode::None,
            unreadable_paths: vec![secret.display().to_string()],
            protected_paths: vec![secret.display().to_string()],
            ..SandboxCfg::default()
        };
        let e = env_with(ToolsCfg::default(), cfg);
        let target = secret.join("k.txt").display().to_string();
        let r = e.call("read", json!({"path": target})).await;
        assert_eq!(r.status, ToolStatus::Denied);
        assert_eq!(r.meta.get(META_PATH).and_then(Value::as_str), Some(target.as_str()));
        let r = e.call("write", json!({"path": target, "content": "x"})).await;
        assert_eq!(r.status, ToolStatus::Denied);
        let r = e.call("edit", json!({"path": target, "old": "key", "new": "x"})).await;
        assert_eq!(r.status, ToolStatus::Denied);
        assert_eq!(std::fs::read(secret.join("k.txt")).unwrap(), b"key");
    }
}
