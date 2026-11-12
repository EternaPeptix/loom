//! `read`, `write`, `edit`.
//!
//! CONTRACT.
//!
//! Paths: `ctx.sandbox.resolve(path)`, then `check_read` / `check_write`; a refusal is a `denied`
//! result carrying the sandbox's sentence. Every result has meta `META_PATH` = the resolved path.
//!
//! All three tools work only on regular files. A device, FIFO or socket → error sentence naming what
//! the path is and what to use instead; it is never opened (`files::open_regular`). At most `READ_CAP`
//! (64 MiB) of a file is loaded into memory.
//!
//! The file work runs on a blocking thread. A cancelled call returns `interrupted` at once, even
//! while that thread is stuck in a read. The work left behind checks the same token between reads
//! and immediately before it writes, and what the session has seen of the file is recorded only when
//! the call returns the work's own result: an interrupted call never counts as a read, and writes
//! nothing once it has seen the cancellation.
//!
//! ## `read`
//! A directory → error sentence suggesting `glob`. A missing file → error sentence; when files with
//! a similar name exist in the same directory (edit distance ≤ 2, or same name ignoring case), name
//! up to 3 of them. Otherwise: read the bytes, record them as seen, `view::store_text`, then exactly
//! as `out_read` (window with `cfg.read_max_lines`, numbered lines, `max_line_chars` 20_000) and
//! return `Body::View` of the stored text. Facts: the path as given, `view::range_fact`, the handle of
//! the stored text (`out:…`, whose line numbers are the ones shown; `evidence` quotes it), the
//! normalisation notes when there are any. Binary content: the body is the one-line description from
//! `normalize`. An empty file: body `(empty file)`.
//!
//! A file above `READ_CAP`: without `start`/`end` → error sentence stating its size, saying to pass a
//! range or to search it with `bash` (`grep` skips files of that size). With a range the file is
//! streamed and only the lines of the window are kept: at most 80_000 bytes of each line, and at most
//! `WINDOW_BYTES` (4 MiB) in all — a window that reaches that size ends after the line that reached it
//! and the range fact says so and where to continue. The window has no handle (its stored lines are
//! numbered from 1, the text shows the file's own numbers): a fact says to quote it from `bash`. The kept lines are normalised and stored like a
//! whole read and returned as `Body::View` of that stored window: the text numbers the lines as in
//! the file, `shown` counts them in the stored window. The file is then recorded as seen by size and
//! modification time. The lines of such a file are counted only when the scan reaches its end. A
//! window with binary content → error sentence.
//!
//! ## `write`
//! `ctx.files.freshness`: `Unread` → error: the file exists and has not been read in this session —
//! read it first, or use `edit`; `Changed` → error: it changed on disk since it was read ({was} →
//! {now} bytes) — read it again. `Missing`/`Current` → write atomically (temp file in the same
//! directory, `sync_data`, rename; parent directories are created; the existing file's permissions
//! are kept), then record the new content as seen. Result: outcome `created` or `replaced`; facts:
//! path, `{lines} lines`, `{bytes} bytes`; for `replaced` the body is the unified diff (3 lines of
//! context, `similar` crate) of old → new as `Body::Raw`, so a long diff is stored and admitted like
//! any output; for `created` the body is `Body::Message("(new file)")`. Content is written
//! byte-for-byte as given. A replaced file above `READ_CAP` is not read back: the body says that there
//! is no diff and why.
//!
//! ## `edit`
//! Freshness as for `write`, and `Missing` is an error. `old` empty, or `old == new` → error.
//! A file above `READ_CAP` → error sentence (use `bash`).
//! Count occurrences of `old` in the file text:
//! - exactly one, or `all` → replace, write atomically, record. Outcome `edited`; facts: path,
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
//! sandbox denial for read and write; `shown` ranges of read are exact; a device, a FIFO and a socket
//! refused by each tool without hanging; a file above the cap refused whole and read by range
//! (normalised, stored, cut by size); cancellation of a stuck read, and of a write and an edit before
//! they write; an interrupted read is not recorded.

use crate::files::{describe_type, open_regular, Freshness, NotOpened, Seen};
use crate::outview::{string, uint};
use crate::{params, schema, view, Body, Tool, ToolCtx, ToolOutput};
use async_trait::async_trait;
use loom_core::admit::normalize;
use loom_core::event::{ToolClass, ToolSpec, ToolStatus, META_PATH};
use serde_json::{json, Map, Value};
use similar::TextDiff;
use std::fs::{File, FileType, Metadata};
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
/// A file above the cap is judged binary or text on this many leading bytes before it is streamed.
const BINARY_PROBE: usize = 8192;
/// Most bytes kept of one line of a streamed read: room for `MAX_LINE_CHARS` characters.
const KEEP_LINE_BYTES: usize = MAX_LINE_CHARS * 4;
/// Most bytes kept of all the lines of one streamed read (4 MiB). The window ends after the line
/// that reaches it, so at most this much and one more line is held, normalised and stored.
const WINDOW_BYTES: usize = 4 * 1024 * 1024;

/// The size limits of a `read`. Tests lower them.
#[derive(Clone, Copy)]
struct ReadLimits {
    /// Most bytes loaded whole (`READ_CAP`).
    whole: u64,
    /// Most bytes kept of a streamed window (`WINDOW_BYTES`).
    window: usize,
}

const READ_LIMITS: ReadLimits = ReadLimits { whole: READ_CAP, window: WINDOW_BYTES };

/// Why a bounded read of a file did not produce its bytes.
enum Fail {
    Io(std::io::Error),
    NotRegular(FileType),
    TooLarge(u64),
    /// The file was within the cap when opened but grew past it (the cap) while being read.
    Grew(u64),
    Cancelled,
}

impl From<NotOpened> for Fail {
    fn from(e: NotOpened) -> Fail {
        match e {
            NotOpened::Io(e) => Fail::Io(e),
            NotOpened::NotRegular(kind) => Fail::NotRegular(kind),
        }
    }
}

/// What the blocking part of a call did: its result and, when the file was read or written, what the
/// session has now seen of it. That is recorded only if this result is the one the call returns.
struct Worked {
    out: ToolOutput,
    seen: Option<Seen>,
}

impl From<ToolOutput> for Worked {
    /// A result that leaves what the session has seen of the file as it was.
    fn from(out: ToolOutput) -> Worked {
        Worked { out, seen: None }
    }
}

fn interrupted(message: String) -> ToolOutput {
    let mut out = ToolOutput::error(message);
    out.status = ToolStatus::Interrupted;
    out.outcome = "interrupted".into();
    out
}

/// Run blocking file work on `path` off the async workers and stop waiting when the call is
/// cancelled. A read stuck inside the kernel cannot be torn out, but the call returns at once as
/// interrupted, and the work left behind observes the same token between reads and before it writes.
/// What the work saw of the file is recorded here, and only when its own result is returned, so a
/// call reported as interrupted never counts as a read.
async fn off_thread<F>(ctx: &ToolCtx, tool: &str, path: &Path, work: F) -> ToolOutput
where
    F: FnOnce(ToolCtx) -> Worked + Send + 'static,
{
    let owned = ctx.clone();
    let mut job = tokio::task::spawn_blocking(move || work(owned));
    tokio::select! {
        biased;
        done = &mut job => match done {
            Ok(Worked { out, seen }) => {
                if let Some(seen) = seen {
                    ctx.files.record(path, seen);
                }
                out
            }
            Err(e) => ToolOutput::error(format!(
                "The `{tool}` tool failed internally ({e}). Check the state of the file before repeating the call."
            )),
        },
        _ = ctx.cancel.cancelled() => interrupted(if tool == "read" {
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
            return Err(Fail::Grew(cap));
        }
    }
    Ok(bytes)
}

/// Open `path`, require a regular file of at most `cap` bytes, and read it.
fn read_bounded(path: &Path, cap: u64, cancel: &CancellationToken) -> Result<Vec<u8>, Fail> {
    let (file, meta) = open_regular(path)?;
    if meta.len() > cap {
        return Err(Fail::TooLarge(meta.len()));
    }
    read_open(file, meta.len(), cap, cancel)
}

/// The refusal of a path that is not a regular file: what it is, and what to use instead.
fn not_regular(given: &str, tool: &str, kind: &FileType) -> ToolOutput {
    use std::os::unix::fs::FileTypeExt;
    let instead = if tool != "read" {
        "to send data to it on purpose, use `bash`".to_string()
    } else if kind.is_socket() {
        format!("a socket has no content to read: to talk to it, connect to it from `bash` (for example `nc -U {given}`)")
    } else {
        format!("to look at it on purpose, use `bash` with a bounded command (for example `head -c 1000 {given}`)")
    };
    ToolOutput::error(format!(
        "{given} is {}, not a regular file, and `{tool}` works only on regular files. Name a regular file instead; {instead}.",
        describe_type(kind)
    ))
}

/// What `read` says to do about a file above the cap. The `grep` tool is not offered: it skips files
/// of this size.
fn too_large_advice(given: &str) -> String {
    format!(
        "Pass `start` and `end` to read a range of its lines (the file is streamed), or search it with `bash`, for example `grep -n PATTERN {given} | head -50`."
    )
}

/// The result of work that found the call cancelled before it had any effect.
fn cancelled(tool: &str) -> ToolOutput {
    interrupted(format!("The `{tool}` call was interrupted before it changed anything. Call `{tool}` again if you still need it."))
}

/// The error for a failed bounded read; `advice` says what to do about a file that is too large.
fn fail_output(fail: Fail, given: &str, tool: &str, advice: &str) -> ToolOutput {
    match fail {
        Fail::Io(e) => ToolOutput::error(format!("{given} cannot be read ({e}). Check the path and its permissions.")),
        Fail::NotRegular(kind) => not_regular(given, tool, &kind),
        Fail::TooLarge(n) => ToolOutput::error(format!(
            "{given} is {n} bytes, above the {READ_CAP} byte limit `{tool}` loads into memory. {advice}"
        )),
        Fail::Grew(cap) => ToolOutput::error(format!(
            "{given} grew while it was being read and is now above the {cap} byte limit `{tool}` loads into memory. {advice}"
        )),
        Fail::Cancelled => cancelled(tool),
    }
}

/// The error for a freshness check that could not be made.
fn check_failed(given: &str, tool: &str, doing: &str, e: NotOpened) -> ToolOutput {
    match e {
        NotOpened::NotRegular(kind) => not_regular(given, tool, &kind),
        NotOpened::Io(e) => ToolOutput::error(format!("{given} cannot be checked before {doing} ({e}). Check the path and its permissions.")),
    }
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

    fn speculative(&self) -> bool {
        true
    }

    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let given = string(args, "path");
        let path = match checked(ctx, given, false) {
            Ok(p) => p,
            Err(denied) => return *denied,
        };
        let (given, start, end) = (given.to_string(), uint(args, "start"), uint(args, "end"));
        let target = path.clone();
        let out = off_thread(ctx, "read", &path, move |c| read_file(&c, &given, &target, start, end, READ_LIMITS)).await;
        with_path(out, &path)
    }
}

/// Open the file `read` was asked for, or say why it cannot be read.
fn open_to_read(given: &str, path: &Path) -> Result<(File, Metadata), Box<ToolOutput>> {
    let refusal = match open_regular(path) {
        Ok(x) => return Ok(x),
        Err(NotOpened::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut msg = format!("{given} does not exist.");
            let near = similar_names(path);
            if !near.is_empty() {
                msg.push_str(&format!(" Files with a similar name in that directory: {}.", near.join(", ")));
            }
            msg.push_str(" Check the path, or find the file with `glob`.");
            ToolOutput::error(msg)
        }
        Err(NotOpened::NotRegular(kind)) if kind.is_dir() => ToolOutput::error(format!(
            "{given} is a directory, not a file. List its files with `glob` (for example pattern `{}/*`) and read one of them.",
            given.trim_end_matches('/')
        )),
        Err(e) => fail_output(e.into(), given, "read", ""),
    };
    Err(Box::new(refusal))
}

/// The blocking part of `read`. A file above `limits.whole` is read only by line range, streamed.
fn read_file(ctx: &ToolCtx, given: &str, path: &Path, start: Option<u64>, end: Option<u64>, limits: ReadLimits) -> Worked {
    let (file, meta) = match open_to_read(given, path) {
        Ok(x) => x,
        Err(refusal) => return (*refusal).into(),
    };
    if meta.len() > limits.whole {
        if start.is_none() && end.is_none() {
            return ToolOutput::error(format!(
                "{given} is {} bytes, above the {} byte limit `read` loads into memory. {}",
                meta.len(),
                limits.whole,
                too_large_advice(given)
            ))
            .into();
        }
        return read_large_range(ctx, given, file, &meta, start, end, limits.window);
    }
    let bytes = match read_open(file, meta.len(), limits.whole, &ctx.cancel) {
        Ok(b) => b,
        Err(f) => return fail_output(f, given, "read", &too_large_advice(given)).into(),
    };
    Worked { out: show_whole(ctx, given, &bytes, start, end), seen: Some(Seen::of_bytes(&bytes)) }
}

/// What `read` returns for the content of a file that was loaded whole.
fn show_whole(ctx: &ToolCtx, given: &str, bytes: &[u8], start: Option<u64>, end: Option<u64>) -> ToolOutput {
    if bytes.is_empty() {
        return ToolOutput::ok("ok", Body::Message("(empty file)".into())).with_more(given.to_string());
    }
    let (stored, norm) = match view::store_text(&ctx.blobs, bytes) {
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
    // The handle of the stored text: `evidence` quotes it, and its lines are the numbers shown here.
    let handle = stored.handle();
    let mut out = ToolOutput::ok("ok", Body::View { of: stored.id, text, shown: vec![(first, last)] })
        .with_more(given.to_string())
        .with_more(view::range_fact(first, last, total))
        .with_more(handle);
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
    /// The kept lines as they are in the file, each followed by `\n`. A line longer than
    /// `KEEP_LINE_BYTES` is cut there, on a character boundary.
    raw: Vec<u8>,
    /// How many lines `raw` holds.
    count: u64,
    /// The lines that were cut: position in `raw` (0-based, ascending) and full length in bytes.
    cut: Vec<(u64, u64)>,
    /// The number of lines in the file, known only when the scan reached its end.
    total: Option<u64>,
    /// The window ended before line `last` because it reached its size limit; the file goes on.
    full: bool,
    binary: bool,
}

/// The length of `bytes` without the start of a UTF-8 character that is cut off at their end.
fn whole_chars(bytes: &[u8]) -> usize {
    // A character is at most 4 bytes, so one that is cut off starts within the last 3.
    for back in 1..=bytes.len().min(3) {
        let at = bytes.len() - back;
        let lead = bytes.get(at).copied().unwrap_or(0);
        if lead & 0xC0 != 0x80 {
            let needs = match lead {
                0xF0..=0xFF => 4,
                0xE0..=0xEF => 3,
                0xC0..=0xDF => 2,
                _ => 1,
            };
            return if needs > back { at } else { bytes.len() };
        }
    }
    bytes.len()
}

/// Close the line of `full_bytes` bytes whose kept part starts at `line_start` in `w.raw`.
fn end_line(w: &mut Window, line_start: usize, full_bytes: u64) {
    let kept = w.raw.get(line_start..).unwrap_or_default();
    if full_bytes > kept.len() as u64 {
        // A character split by the cut is dropped, so that it is not taken for an invalid byte.
        let whole = whole_chars(kept);
        w.raw.truncate(line_start.saturating_add(whole));
        w.cut.push((w.count, full_bytes));
    }
    w.raw.push(b'\n');
    w.count += 1;
}

/// Stream `file`, keeping only lines `first..=last`: at most `KEEP_LINE_BYTES` bytes of each, and no
/// further line once `max_bytes` are kept.
fn stream_window(file: File, cancel: &CancellationToken, first: u64, last: u64, max_bytes: usize) -> Result<Window, Fail> {
    let mut reader = BufReader::with_capacity(1 << 16, file);
    let mut w = Window { raw: Vec::new(), count: 0, cut: Vec::new(), total: None, full: false, binary: false };
    let mut lineno = 1u64;
    // Where the kept part of the current line starts in `w.raw`, and the line's length so far.
    let mut line_start = 0usize;
    let mut line_bytes = 0u64;
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
            // The rule a whole read applies to the file (a NUL, or mostly not text), on its head.
            if normalize(buf.get(..buf.len().min(BINARY_PROBE)).unwrap_or(buf)).binary {
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
            let room = KEEP_LINE_BYTES.saturating_sub(w.raw.len().saturating_sub(line_start)).min(take);
            w.raw.extend_from_slice(buf.get(..room).unwrap_or_default());
        }
        line_bytes = line_bytes.saturating_add(take as u64);
        reader.consume(take + usize::from(ended));
        if ended {
            if in_range {
                end_line(&mut w, line_start, line_bytes);
                line_start = w.raw.len();
            }
            line_bytes = 0;
            let full = in_range && w.raw.len() >= max_bytes;
            if lineno >= last || full {
                if reader.fill_buf().map_err(Fail::Io)?.is_empty() {
                    w.total = Some(lineno);
                } else {
                    w.full = lineno < last;
                }
                return Ok(w);
            }
            lineno = lineno.saturating_add(1);
        }
    }
    if line_bytes > 0 {
        // The file ends without a final newline: what was collected is its last line.
        if lineno >= first && lineno <= last {
            end_line(&mut w, line_start, line_bytes);
        }
        w.total = Some(lineno);
    } else {
        w.total = Some(lineno.saturating_sub(1));
    }
    Ok(w)
}

/// The lines of a normalised window as `{n}\t{line}`, numbered from `first` and shortened the way
/// `view::numbered` shortens them; `cut` is `Window::cut`. Returns the text and how many lines were
/// shortened.
fn number_window(text: &str, first: u64, cut: &[(u64, u64)]) -> (String, u64) {
    let body = text.strip_suffix('\n').unwrap_or(text);
    let mut out = String::with_capacity(body.len() + 8);
    let mut shortened = 0u64;
    for (i, line) in body.split('\n').enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&first.saturating_add(i as u64).to_string());
        out.push('\t');
        let full_bytes = cut.binary_search_by_key(&(i as u64), |(at, _)| *at).ok().and_then(|j| cut.get(j)).map(|(_, bytes)| *bytes);
        let (head, rest) = match line.char_indices().nth(MAX_LINE_CHARS) {
            Some((at, _)) => line.split_at(at),
            None => (line, ""),
        };
        out.push_str(head);
        if let Some(bytes) = full_bytes {
            out.push_str(&format!("…[line is {bytes} bytes; the rest is not shown]"));
            shortened += 1;
        } else if !rest.is_empty() {
            out.push_str(&format!("…[+{} chars]", rest.chars().count()));
            shortened += 1;
        }
    }
    (out, shortened)
}

/// A file above the whole-read cap, read by line range without loading it. The window goes through
/// the same normalisation and store as a whole read, so what is shown is a view of stored text: the
/// text numbers the lines as in the file, and `shown` counts them in the stored window, which is
/// what coverage of that stored text is kept in.
fn read_large_range(ctx: &ToolCtx, given: &str, file: File, meta: &Metadata, start: Option<u64>, end: Option<u64>, max_bytes: usize) -> Worked {
    let (first, last) = match view::window(start, end, u64::MAX, ctx.cfg.read_max_lines) {
        Ok(Some(w)) => w,
        Ok(None) => return ToolOutput::error("There is nothing to show for this range. Give a `start` of 1 or more.").into(),
        Err(e) => return ToolOutput::error(e).into(),
    };
    let w = match stream_window(file, &ctx.cancel, first, last, max_bytes) {
        Ok(w) => w,
        Err(f) => return fail_output(f, given, "read", "").into(),
    };
    if w.binary {
        return ToolOutput::error(format!(
            "{given} is binary data of {} bytes, above the size limit for whole reads, so it cannot be shown as lines. Use `bash` with a bounded command such as `xxd -l 256 {given}`.",
            meta.len()
        ))
        .into();
    }
    if w.count == 0 {
        return match view::window(start, end, w.total.unwrap_or(0), ctx.cfg.read_max_lines) {
            Err(e) => ToolOutput::error(e),
            _ => ToolOutput::ok("ok", Body::Message("(empty file)".into())).with_more(given.to_string()),
        }
        .into();
    }
    let shown_last = first.saturating_add(w.count - 1);
    let (stored, norm) = match view::store_text(&ctx.blobs, &w.raw) {
        Ok(r) => r,
        Err(e) => return ToolOutput::error(format!("{given} was read but could not be stored for display ({e}). Try again.")).into(),
    };
    if norm.binary {
        return ToolOutput::error(format!(
            "Lines {first}-{shown_last} of {given} are binary data (they contain a NUL byte, or are mostly not text), so they are not shown as lines. Use `bash` with a bounded command that makes them printable, such as `sed -n '{first},{shown_last}p' {given} | cat -v | head -100`."
        ))
        .into();
    }
    let (text, shortened) = number_window(&norm.text, first, &w.cut);
    let range = match w.total {
        Some(total) => view::range_fact(first, shown_last, total),
        None if w.full => format!(
            "lines {first}-{shown_last} — more below: the window ended before line {last} because it reached its size limit of {max_bytes} bytes; continue with `start` {}",
            shown_last.saturating_add(1)
        ),
        None => format!(
            "lines {first}-{shown_last} — more below (the file is {} bytes, above the whole-read limit, so its lines are not counted)",
            meta.len()
        ),
    };
    let mut out = ToolOutput::ok("ok", Body::View { of: stored.id, text, shown: vec![(1, w.count)] })
        .with_more(given.to_string())
        .with_more(range)
        .with_more("this window of a large file has no handle: to cite lines of it as evidence, quote them from a bounded `bash` command instead");
    if shortened > 0 {
        out = out.with_more(format!("{shortened} long lines shortened"));
    }
    if let Some(notes) = norm.notes() {
        out = out.with_more(notes);
    }
    if w.raw.windows(2).any(|pair| pair == b"\r\n") {
        out = out.with_more("CRLF line endings (the CRs are not shown)");
    }
    Worked { out, seen: Some(Seen::of_stat(meta)) }
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
        let out = off_thread(ctx, "write", &path, move |c| write_file(&c, &given, &target, &content)).await;
        with_path(out, &path)
    }
}

/// The blocking part of `write`.
fn write_file(ctx: &ToolCtx, given: &str, path: &Path, content: &str) -> Worked {
    if path.is_dir() {
        return ToolOutput::error(format!("{given} is a directory. Give the path of a file to write.")).into();
    }
    let fresh = match ctx.files.freshness(path) {
        Ok(f) => f,
        Err(e) => return check_failed(given, "write", "writing", e).into(),
    };
    if let Some(refusal) = freshness_refusal(&fresh, given, "write") {
        return refusal.into();
    }
    // The previous content is needed only for the diff; a file above the cap is replaced without one.
    let mut diff_omitted = false;
    let old = if fresh == Freshness::Current {
        match read_bounded(path, READ_CAP, &ctx.cancel) {
            Ok(b) => Some(b),
            Err(Fail::TooLarge(_) | Fail::Grew(_)) => {
                diff_omitted = true;
                None
            }
            Err(f) => return fail_output(f, given, "write", "").into(),
        }
    } else {
        None
    };
    // A call that was cancelled has already been reported as interrupted: it must not write after that.
    if ctx.cancel.is_cancelled() {
        return cancelled("write").into();
    }
    if let Err(e) = write_atomic(path, content.as_bytes()) {
        return ToolOutput::error(format!("{given} could not be written ({e}). Nothing was changed; check that the directory is writable and try again.")).into();
    }
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
    Worked { out, seen: Some(Seen::of_bytes(content.as_bytes())) }
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
        let out = off_thread(ctx, "edit", &path, move |c| edit_file(&c, &given, &target, &old, &new, all)).await;
        with_path(out, &path)
    }
}

/// The blocking part of `edit`.
fn edit_file(ctx: &ToolCtx, given: &str, path: &Path, old: &str, new: &str, all: bool) -> Worked {
    if old.is_empty() {
        return ToolOutput::error("`old` is empty, so there is nothing to find. Give the exact text to replace; to add text to an empty or new file use `write`.").into();
    }
    if old == new {
        return ToolOutput::error("`old` and `new` are identical, so the edit would change nothing. Give a `new` that differs from `old`.").into();
    }
    if path.is_dir() {
        return ToolOutput::error(format!("{given} is a directory. Give the path of a file to edit.")).into();
    }
    let fresh = match ctx.files.freshness(path) {
        Ok(f) => f,
        Err(e) => return check_failed(given, "edit", "editing", e).into(),
    };
    if fresh == Freshness::Missing {
        return ToolOutput::error(format!("{given} does not exist, so there is nothing to edit. Create it with `write`, or check the path (`glob` finds files).")).into();
    }
    if let Some(refusal) = freshness_refusal(&fresh, given, "edit") {
        return refusal.into();
    }
    let bytes = match read_bounded(path, READ_CAP, &ctx.cancel) {
        Ok(b) => b,
        Err(f) => return fail_output(f, given, "edit", "Use `bash` for a change to a file this large.").into(),
    };
    let text = match String::from_utf8(bytes) {
        Ok(t) => t,
        Err(_) => return ToolOutput::error(format!("{given} is not valid UTF-8 text, and binary files are not edited. Use `bash` for a binary change.")).into(),
    };

    // A file that uses CRLF throughout shows the model lines without the CRs; the text it gives is
    // matched, and what it puts in, with the file's own line endings.
    let crlf = text.contains("\r\n") && text.matches('\n').count() == text.matches("\r\n").count() && !old.contains('\r') && !new.contains('\r');
    let (old, new) = if crlf { (old.replace('\n', "\r\n"), new.replace('\n', "\r\n")) } else { (old.to_string(), new.to_string()) };

    let positions: Vec<usize> = text.match_indices(old.as_str()).map(|(i, _)| i).collect();
    if positions.is_empty() {
        return ToolOutput::error(no_match_message(given, &text, &old)).into();
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
        ))
        .into();
    }
    let updated = text.replace(old.as_str(), &new);
    // As for `write`: nothing is written by a call that has been reported as interrupted.
    if ctx.cancel.is_cancelled() {
        return cancelled("edit").into();
    }
    if let Err(e) = write_atomic(path, updated.as_bytes()) {
        return ToolOutput::error(format!("{given} could not be written ({e}). Nothing was changed; check that the file is writable and try again.")).into();
    }
    let n = positions.len();
    let count = if n == 1 { "1 replacement".to_string() } else { format!("{n} replacements") };
    let out = ToolOutput::ok("edited", Body::Raw(unified_diff(given, &text, &updated).into_bytes()))
        .with_more(given.to_string())
        .with_more(count);
    Worked { out, seen: Some(Seen::of_bytes(updated.as_bytes())) }
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

    #[test]
    fn a_file_that_grows_during_the_read_names_the_limit_in_force() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("grow.txt");
        std::fs::write(&p, vec![b'x'; 100]).unwrap();
        // The size seen at open time (1) was within the cap (10); the read finds more.
        let fail = read_open(File::open(&p).unwrap(), 1, 10, &CancellationToken::new()).unwrap_err();
        let Body::Message(text) = fail_output(fail, "grow.txt", "read", "Use a range.").body else { panic!("not a message") };
        assert!(text.contains("grew while it was being read") && text.contains("above the 10 byte limit"), "{text}");
        assert!(!text.contains("is 11 bytes") && !text.contains(&READ_CAP.to_string()), "{text}");
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

    /// Of a result that is a view of stored text: its text, its `shown` ranges, and that stored text.
    fn view_of(e: &TestEnv, o: &ToolOutput) -> (String, Vec<(u64, u64)>, String) {
        match &o.body {
            Body::View { of, text, shown } => {
                let stored = String::from_utf8(e.ctx.blobs.read_all(of).expect("read blob")).expect("utf-8");
                (text.clone(), shown.clone(), stored)
            }
            other => panic!("not a view of stored text: {other:?}"),
        }
    }

    /// The limits of `read` with whole reads lowered to `whole` bytes.
    fn cap(whole: u64) -> ReadLimits {
        ReadLimits { whole, ..READ_LIMITS }
    }

    /// `read` with lowered limits, recorded the way the tool records a call that returns.
    fn read_limited(e: &TestEnv, name: &str, start: Option<u64>, end: Option<u64>, limits: ReadLimits) -> ToolOutput {
        let path = ws(e, name);
        let done = read_file(&e.ctx, name, &path, start, end, limits);
        if let Some(seen) = done.seen {
            e.ctx.files.record(&path, seen);
        }
        done.out
    }

    /// Run `scenario` on a thread of its own, with its own runtime, and return the channel its outcome
    /// arrives on. A call that blocks its thread then fails the test on `recv_timeout` instead of
    /// hanging it: nothing waits for that thread, or for the runtime it holds.
    fn on_own_thread<T, F, Fut>(scenario: F) -> std::sync::mpsc::Receiver<T>
    where
        T: Send + 'static,
        F: FnOnce() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = T>,
    {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
            let _ = tx.send(rt.block_on(scenario()));
        });
        rx
    }

    #[test]
    fn devices_fifos_and_sockets_are_refused_without_hanging() {
        use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;
        // In a directory of this thread's own, so that it can release a call stuck on the FIFO.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let (fifo, sock) = (root.join("pipe"), root.join("sock"));
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        // The device last: a read of it that is not refused never ends, and nothing can release it.
        let targets = [(fifo.display().to_string(), "FIFO"), (sock.display().to_string(), "a socket"), ("/dev/zero".to_string(), "character device")];

        let given_up = Arc::new(AtomicBool::new(false));
        let (paths, stop) = (targets.clone().map(|(path, _)| path), given_up.clone());
        let done = on_own_thread(move || async move {
            let e = env();
            let mut results = Vec::new();
            for path in &paths {
                for (tool, mut args) in [("read", json!({})), ("write", json!({"content": "x"})), ("edit", json!({"old": "a", "new": "b"}))] {
                    if stop.load(Ordering::SeqCst) {
                        return results;
                    }
                    args["path"] = json!(path);
                    results.push(e.call(tool, args).await);
                }
            }
            results
        });
        let results = match done.recv_timeout(std::time::Duration::from_secs(30)) {
            Ok(results) => results,
            Err(_) => {
                // A call is stuck. Opening the write end of the FIFO and closing it again gives a reader
                // blocked on it end-of-file, so the thread left behind ends instead of holding the pipe.
                given_up.store(true, Ordering::SeqCst);
                for _ in 0..50 {
                    if std::fs::OpenOptions::new().write(true).custom_flags(libc::O_NONBLOCK).open(&fifo).is_ok() {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                panic!("a file tool blocked on a FIFO, a socket or a device instead of refusing it");
            }
        };

        assert_eq!(results.len(), 9);
        for (calls, (path, kind)) in results.chunks(3).zip(&targets) {
            for r in calls {
                assert!(is_err(r), "{}", r.text);
                assert!(r.text.contains(&format!("{path} is ")) && r.text.contains(kind), "{}", r.text);
                assert!(r.text.contains(&format!("not a regular file, and `{}` works only on regular files", r.name)), "{}", r.text);
                assert!(r.text.contains("`bash`") && !r.text.contains("permissions"), "{}", r.text);
            }
        }
        assert!(results[3].text.contains("nc -U"), "{}", results[3].text);
        // Nothing was put in their place.
        assert!(std::fs::symlink_metadata(&fifo).unwrap().file_type().is_fifo());
        assert!(std::fs::symlink_metadata(&sock).unwrap().file_type().is_socket());
    }

    #[test]
    fn a_failed_freshness_check_blames_the_kind_of_file_only_when_that_is_the_fault() {
        // The standard library reports a NUL in a path as `InvalidInput`, which says nothing about
        // what the path is.
        let nul = std::io::Error::new(std::io::ErrorKind::InvalidInput, "file name contained an unexpected NUL byte");
        let m = message(&check_failed("a.txt", "write", "writing", NotOpened::Io(nul)));
        assert!(m.contains("a.txt cannot be checked before writing") && m.contains("NUL byte") && !m.contains("regular file"), "{m}");
    }

    #[tokio::test]
    async fn file_above_the_cap_is_refused_whole_and_read_by_range() {
        let e = env();
        let path = put(&e, "huge.txt", numbered_file(200).as_bytes());
        let size = std::fs::metadata(&path).unwrap().len();
        let whole = read_limited(&e, "huge.txt", None, None, cap(100));
        assert_eq!(whole.status, ToolStatus::Error);
        let m = message(&whole);
        assert!(m.contains(&format!("huge.txt is {size} bytes, above the 100 byte limit")), "{m}");
        // The advice is a range or `bash`; not the `grep` tool, which skips a file of this size.
        assert!(m.contains("`start` and `end`") && m.contains("`bash`"), "{m}");
        assert!(!m.contains("use `grep`") && !m.contains("`grep`"), "{m}");
        // A refused read is not a read.
        assert_eq!(e.ctx.files.check(&path).unwrap(), Freshness::Unread);

        let part = read_limited(&e, "huge.txt", Some(5), Some(7), cap(100));
        assert_eq!(part.status, ToolStatus::Ok);
        let (text, shown, stored) = view_of(&e, &part);
        assert_eq!(text, "5\trow 5\n6\trow 6\n7\trow 7");
        // What is stored is the window: `shown` counts its lines, the text numbers them as in the file.
        assert_eq!((shown, stored.as_str()), (vec![(1, 3)], "row 5\nrow 6\nrow 7\n"));
        assert!(part.more.iter().any(|f| f.starts_with("lines 5-7 — more below")), "{:?}", part.more);
        assert_eq!(e.ctx.files.check(&path).unwrap(), Freshness::Current);

        let tail = read_limited(&e, "huge.txt", Some(199), Some(900), cap(100));
        assert_eq!(view_of(&e, &tail).0, "199\trow 199\n200\trow 200");
        assert!(tail.more.iter().any(|f| f.contains("lines 199-200 of 200")), "{:?}", tail.more);
        let past = read_limited(&e, "huge.txt", Some(300), None, cap(100));
        assert!(past.status == ToolStatus::Error && message(&past).contains("200 lines"), "{}", message(&past));

        std::fs::write(&path, [b'a', 0, b'b'].repeat(100)).unwrap();
        let bin = read_limited(&e, "huge.txt", Some(1), Some(2), cap(100));
        assert!(bin.status == ToolStatus::Error && message(&bin).contains("binary"), "{}", message(&bin));
    }

    #[tokio::test]
    async fn a_range_of_a_file_above_the_cap_is_normalised_and_stored() {
        let e = env();
        // Clean beyond the first 8 KiB, which decide text or binary before the file is streamed; then
        // one line for each thing normalisation deals with, then a NUL.
        let mut bytes = "plain line\n".repeat(1000).into_bytes();
        bytes.extend_from_slice(b"\x1b[1mbold\x1b[0m\n");
        bytes.extend_from_slice(b"bell\x07 here\n");
        bytes.extend_from_slice(b"progress 1\rprogress 2\n");
        bytes.extend_from_slice(b"caf\xff\n");
        bytes.extend_from_slice(b"x\0y\n");
        bytes.extend_from_slice(b"after\n");
        let path = put(&e, "log.txt", &bytes);

        let out = read_limited(&e, "log.txt", Some(1000), Some(1004), cap(100));
        assert_eq!(out.status, ToolStatus::Ok, "{out:?}");
        let (text, shown, stored) = view_of(&e, &out);
        assert_eq!(text, "1000\tplain line\n1001\tbold\n1002\tbell\\x07 here\n1003\tprogress 2\n1004\tcaf\u{fffd}");
        assert_eq!(shown, vec![(1, 5)]);
        assert_eq!(stored, "plain line\nbold\nbell\\x07 here\nprogress 2\ncaf\u{fffd}\n");
        let facts = out.more.join(" · ");
        assert!(facts.contains("2 terminal escape sequences removed") && facts.contains("1 overwritten lines collapsed"), "{facts}");
        assert!(facts.contains("1 invalid bytes replaced") && facts.contains("1 control characters escaped"), "{facts}");

        // A NUL in the window: the lines are refused as binary, not shown raw, and it is not a read.
        e.ctx.files.forget(&path);
        let out = read_limited(&e, "log.txt", Some(1004), Some(1006), cap(100));
        assert_eq!(out.status, ToolStatus::Error);
        let m = message(&out);
        assert!(m.contains("Lines 1004-1006 of log.txt are binary data") && m.contains("`bash`") && !m.contains('\0'), "{m}");
        assert_eq!(e.ctx.files.check(&path).unwrap(), Freshness::Unread);
    }

    #[tokio::test]
    async fn a_streamed_window_is_bounded_in_bytes_and_says_where_to_continue() {
        let e = env();
        put(&e, "rows.txt", numbered_file(200).as_bytes());
        // `row 10` and the newline are 7 bytes: the third such line takes the window past 20 bytes.
        let limits = ReadLimits { whole: 100, window: 20 };
        let out = read_limited(&e, "rows.txt", Some(10), Some(50), limits);
        let (text, shown, _) = view_of(&e, &out);
        assert_eq!((text.as_str(), shown), ("10\trow 10\n11\trow 11\n12\trow 12", vec![(1, 3)]));
        let facts = out.more.join(" · ");
        assert!(facts.contains("lines 10-12 — more below") && facts.contains("before line 50"), "{facts}");
        assert!(facts.contains("size limit of 20 bytes") && facts.contains("continue with `start` 13"), "{facts}");
        // The stored window is numbered from 1 while the text shows the file's numbers: no handle, and it says so.
        assert!(facts.contains("has no handle") && facts.contains("bounded `bash` command") && !facts.contains("out:"), "{facts}");
        // A window that ends at the line asked for, or with the file, was not cut by its size.
        let out = read_limited(&e, "rows.txt", Some(10), Some(12), limits);
        assert!(view_of(&e, &out).0.ends_with("12\trow 12") && !out.more.join(" · ").contains("size limit"), "{:?}", out.more);
        let out = read_limited(&e, "rows.txt", Some(198), Some(900), limits);
        assert!(out.more.iter().any(|f| f.starts_with("lines 198-200 of 200")), "{:?}", out.more);

        // Of one line, 80,000 bytes are kept, cut on a character boundary, and 20,000 characters shown.
        put(&e, "long.txt", format!("short\na{}\nend\n", "é".repeat(60_000)).as_bytes());
        let out = read_limited(&e, "long.txt", Some(1), Some(3), cap(100));
        let (text, shown, stored) = view_of(&e, &out);
        assert_eq!(shown, vec![(1, 3)]);
        let lines: Vec<&str> = text.split('\n').collect();
        assert_eq!((lines[0], lines[2], lines.len()), ("1\tshort", "3\tend", 3));
        assert!(lines[1].starts_with("2\taéé") && lines[1].ends_with("é…[line is 120001 bytes; the rest is not shown]"), "{} bytes", lines[1].len());
        assert_eq!(lines[1].chars().filter(|c| *c == 'é').count(), 19_999);
        assert_eq!(stored.len(), "short\n".len() + 79_999 + "\nend\n".len());
        assert_eq!(out.more.iter().filter(|f| f.contains("shortened") || f.contains("invalid")).collect::<Vec<_>>(), vec!["1 long lines shortened"]);
    }

    #[tokio::test]
    async fn write_and_edit_refuse_a_changed_file_that_was_read_by_range() {
        let e = env();
        let path = put(&e, "big.txt", numbered_file(50).as_bytes());
        let seen = read_limited(&e, "big.txt", Some(1), Some(2), cap(10));
        assert_eq!(seen.status, ToolStatus::Ok);
        // Unchanged since the ranged read: the freshness check passes without hashing the file.
        let r = e.call("edit", json!({"path": "big.txt", "old": "row 3\n", "new": "three\n"})).await;
        assert!(!is_err(&r), "{}", r.text);
        // A second ranged read, then someone else changes the file.
        read_limited(&e, "big.txt", Some(1), Some(2), cap(10));
        put(&e, "big.txt", b"changed elsewhere\n");
        let r = e.call("write", json!({"path": "big.txt", "content": "x"})).await;
        assert!(is_err(&r) && r.text.contains("changed on disk"), "{}", r.text);
        let r = e.call("edit", json!({"path": "big.txt", "old": "changed", "new": "x"})).await;
        assert!(is_err(&r) && r.text.contains("changed on disk"), "{}", r.text);
        assert_eq!(std::fs::read(&path).unwrap(), b"changed elsewhere\n");
    }

    #[tokio::test]
    async fn an_interrupted_read_returns_at_once_and_is_not_recorded() {
        let e = env();
        let path = put(&e, "f.txt", numbered_file(20).as_bytes());
        // Work that reads the file and is then stuck, the way a read inside the kernel can be, until
        // the test lets it go. The call is cancelled once the file has been read.
        let (reached, at_work) = std::sync::mpsc::channel::<bool>();
        let (release, held) = std::sync::mpsc::channel::<()>();
        let cancel = e.ctx.cancel.clone();
        let canceller = std::thread::spawn(move || {
            let was_read = at_work.recv().unwrap_or(false);
            cancel.cancel();
            was_read
        });
        let (given, target) = ("f.txt".to_string(), path.clone());
        let out = off_thread(&e.ctx, "read", &path, move |c| {
            let done = read_file(&c, &given, &target, None, None, READ_LIMITS);
            let _ = reached.send(done.seen.is_some());
            let _ = held.recv();
            done
        })
        .await;
        assert_eq!(out.status, ToolStatus::Interrupted, "{out:?}");
        assert!(message(&out).contains("interrupted before the file was read"), "{out:?}");
        assert!(canceller.join().unwrap(), "the work had read the file when the call was cancelled");
        drop(release);

        // The model was not shown the file, so a write over it is refused as unread.
        assert_eq!(e.ctx.files.check(&path).unwrap(), Freshness::Unread);
        let mut later = e.ctx.clone();
        later.cancel = CancellationToken::new();
        let refused = write_file(&later, "f.txt", &path, "x").out;
        assert!(refused.status == ToolStatus::Error && message(&refused).contains("has not been read"), "{refused:?}");
        assert_eq!(std::fs::read(&path).unwrap(), numbered_file(20).as_bytes());

        // A call that is already cancelled when it starts also ends as interrupted, whole or ranged.
        let r = e.call("read", json!({"path": "f.txt"})).await;
        assert_eq!(r.status, ToolStatus::Interrupted, "{}", r.text);
        for limits in [READ_LIMITS, cap(10)] {
            let done = read_file(&e.ctx, "f.txt", &path, Some(1), Some(2), limits);
            assert!(done.out.status == ToolStatus::Interrupted && done.seen.is_none(), "{:?}", done.out);
        }
        assert_eq!(e.ctx.files.check(&path).unwrap(), Freshness::Unread);
    }

    #[tokio::test]
    async fn a_cancelled_write_or_edit_changes_nothing() {
        let e = env();
        let old = put(&e, "old.txt", b"one\ntwo\n");
        e.call("read", json!({"path": "old.txt"})).await;
        let new = ws(&e, "new.txt");
        e.ctx.cancel.cancel();

        // The work itself stops before it writes, whether or not it had a file to read first ...
        let attempts = [
            write_file(&e.ctx, "new.txt", &new, "x"),
            write_file(&e.ctx, "old.txt", &old, "x"),
            edit_file(&e.ctx, "old.txt", &old, "one", "1", false),
        ];
        for done in attempts {
            assert!(done.out.status == ToolStatus::Interrupted && done.seen.is_none(), "{:?}", done.out);
            assert!(message(&done.out).contains("interrupted before it changed anything"), "{:?}", done.out);
        }
        // ... and so does the work that a call leaves behind on its thread when it returns.
        let calls = [
            ("write", json!({"path": "new.txt", "content": "x"})),
            ("write", json!({"path": "old.txt", "content": "x"})),
            ("edit", json!({"path": "old.txt", "old": "one", "new": "1"})),
        ];
        for (tool, args) in calls {
            let r = e.call(tool, args).await;
            assert_eq!(r.status, ToolStatus::Interrupted, "{}", r.text);
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(!new.exists());
        assert_eq!(std::fs::read(&old).unwrap(), b"one\ntwo\n");
        // What the session has seen is as the read left it.
        assert_eq!(e.ctx.files.check(&old).unwrap(), Freshness::Current);
        assert_eq!(e.ctx.files.check(&new).unwrap(), Freshness::Missing);
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
