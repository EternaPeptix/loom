//! Append-only, hash-chained session log (one [`Record`] per line of `log.jsonl`).
//!
//! CONTRACT:
//!
//! - A line is the compact `serde_json` form of a `Record` followed by `\n`. `prev` is the lowercase
//!   hex SHA-256 of the previous line's bytes without the newline; the first record uses [`ZERO_HASH`].
//! - `append` assigns `seq` (previous + 1, starting at 0) and `ts_ms`, writes the whole line with one
//!   `write_all`, and with [`Durability::Always`] calls `sync_data` before returning. The file is
//!   opened in append mode. `Durability::Batch` skips the sync (tests, bulk import).
//! - `open` never fails because of damaged content. It reads lines in order and stops at the first
//!   line that is incomplete (no trailing newline), is not a JSON object with a `seq` and a `prev`, has
//!   the wrong `seq`, or has a `prev` that does not match. A line whose chain header is right but whose
//!   body this build cannot deserialize (written by a newer loom) is not damage: it is kept as an
//!   opaque record (`Event::Unknown`), advances the chain and is counted in `OpenReport::opaque`.
//!   Such a line must still be complete JSON, and the line after it must not disown it: when that
//!   line has the next `seq` but a `prev` that is not the unreadable line's hash, the unreadable
//!   line is not the one that was written, so it is damage and ends the prefix.
//!   `open` refuses to append to a log with opaque records (`LogError::Newer`) without touching the
//!   file, and so does a log whose `session_start` carries a schema above `event::SCHEMA`; reading
//!   such a log works. If anything follows the good prefix, those bytes are moved to
//!   `<path>.damaged-<now_ms>` and the log file is truncated to the good prefix; `OpenReport::damage`
//!   says what happened. A torn final line alone (crash mid-append) is the same case.
//! - `create` syncs the parent directory, and `create` and `open` take an exclusive, non-blocking advisory
//!   lock on the log file that the [`SessionLog`] holds until it is dropped: a second writer, in this
//!   process or another, gets [`LogError::Locked`]. The read-only functions take no lock.
//! - `read_records` is the read-only variant: same stopping rule, no file is modified.
//! - `read_page` and [`PageReader`] serve pages under the same stopping rule. A `PageReader` keeps
//!   checkpoints of what it verified, so pages fetched in sequence cost time proportional to the page.
//!   `PageReader::read_stored` serves the same page as [`StoredRecord`]s: a record read as
//!   `Event::Unknown` (a kind this build does not know, or an opaque record) comes with its line as
//!   stored, so that it can be served with every field; every other record comes without one.
//! - `record_from_value` reads one record from JSON (a record the API served) as `open` reads a line:
//!   one whose header is sound but whose body this build cannot read is opaque (`Event::Unknown`).
//! - `fork_file` creates a new log at `dest` whose first `upto_seq + 1` lines are byte-identical to
//!   those of the log at `src`, and returns it ready to append (`next_seq == upto_seq + 1`, chain
//!   continuing from the copied line) with the records copied; `fork_to` does the same from an open
//!   log. Each line is checked as `open` checks it before it is copied: a complete line, JSON this
//!   build reads in full (not opaque, no schema above `event::SCHEMA`), the expected `seq`, and a
//!   `prev` equal to the hash of the line before. The first line that fails ends the fork with
//!   [`LogError::ForkSource`], which names the record, and no file is left at `dest`.
//! - Lines can be large (a tool result is stored inline). There is no line-length limit.
//!
//! Tests required: round trip; chain values; torn tail; corrupted middle line (salvage file exists,
//! log truncated, appends continue); wrong seq; reopen-and-append; fork is byte-identical and chains;
//! a fork whose source has a line that does not chain, is torn or is opaque is refused and leaves no
//! file; `read_stored` keeps the line of unknown and opaque records only, and `record_from_value`
//! reads such a line back as `Unknown`;
//! `read_page` paging; `create` refuses an existing file; `Unknown` events survive rewrite-free;
//! an unreadable body with an intact chain is opaque, refuses append and leaves the file alone (also
//! in `session_start`, also as the last line); a higher schema refuses append and reads; a log from
//! before the schema field opens; damage with a right `seq` and `prev` (invalid UTF-8, nesting too
//! deep to read back, an unreadable line the next line disowns) is salvaged; `PageReader` equals
//! `read_page` for every window, follows appends, starts over after truncation, replacement and a
//! changed verified line, and does not rescan when paging in sequence.

use crate::event::{Author, Event, Record, Seq, SCHEMA};
use crate::{now_ms, sha256_hex};
use serde::Deserialize;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use serde_json::Value;
use std::path::{Path, PathBuf};

pub const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Durability {
    /// `sync_data` after every append.
    #[default]
    Always,
    /// Leave syncing to the OS.
    Batch,
}

#[derive(Debug, thiserror::Error)]
pub enum LogError {
    #[error("log i/o on {path}: {source}")]
    Io { path: PathBuf, #[source] source: std::io::Error },
    #[error("log already exists: {0}")]
    Exists(PathBuf),
    #[error(
        "the session log {0} is already open for writing (by this daemon or another loom process); wait until \
         that session stops, then try again"
    )]
    Locked(PathBuf),
    #[error("cannot encode record: {0}")]
    Encode(#[from] serde_json::Error),
    #[error("fork point {upto} is beyond the last record {last}")]
    ForkPoint { upto: Seq, last: Seq },
    #[error(
        "the session log {path} cannot be forked: its record {seq} {detail}, so a copy would not be a sound log. \
         Start the agent with mode `fresh` and put what it needs to know in the assignment"
    )]
    ForkSource { path: PathBuf, seq: Seq, detail: String },
    #[error(
        "the session log {0} was written by a newer loom (it holds records or a schema this build cannot read); \
         upgrade loom to resume this session. Reading it still works"
    )]
    Newer(PathBuf),
}

/// What `open` found past the readable prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Damage {
    /// Number of good records kept.
    pub good_records: u64,
    /// Bytes that were not readable.
    pub bad_bytes: u64,
    /// Where they were moved (`None` for `read_records`, which moves nothing).
    pub moved_to: Option<PathBuf>,
    /// Human-readable cause: `torn final line`, `line 41 is not a record: …`, `line 41 breaks the chain`.
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct OpenReport {
    pub records: Vec<Record>,
    pub damage: Option<Damage>,
    /// Records kept as `Event::Unknown` because this build cannot deserialize their body.
    pub opaque: u64,
}

/// A record as a reader found it in the log. `line` is the line as stored (newline excluded) when the
/// record was read as [`Event::Unknown`] (a kind this build does not know, or an opaque record), whose
/// other fields the parsed record does not carry; `None` for every other record.
#[derive(Clone, Debug, PartialEq)]
pub struct StoredRecord {
    pub record: Record,
    pub line: Option<String>,
}

#[derive(Debug)]
pub struct SessionLog {
    path: PathBuf,
    file: File,
    next_seq: Seq,
    last_hash: String,
    durability: Durability,
    /// Length in bytes of the readable log; a failed append is cut back to it.
    len: u64,
}

/// Take the exclusive advisory lock on a log file; a lock someone else holds is [`LogError::Locked`].
fn lock_log(file: &File, path: &Path) -> Result<(), LogError> {
    match fs2::FileExt::try_lock_exclusive(file) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == fs2::lock_contended_error().raw_os_error() => Err(LogError::Locked(path.to_path_buf())),
        Err(e) => Err(io_err(path)(e)),
    }
}

fn io_err(path: &Path) -> impl FnOnce(std::io::Error) -> LogError + '_ {
    move |source| LogError::Io { path: path.to_path_buf(), source }
}

/// Outcome of reading one line.
enum Step {
    Record(Box<StoredRecord>),
    End,
    /// The line at the current position ends the readable prefix; the string says why.
    Bad(String),
}

/// Reads a log front to back, checking each line against the chain. The hash is taken over the
/// bytes as stored, never over a re-serialisation.
struct Scanner<R> {
    reader: R,
    buf: Vec<u8>,
    next_seq: Seq,
    last_hash: String,
    /// Bytes of the good prefix, newlines included.
    good_len: u64,
    /// Records whose chain header was right but whose body this build could not read.
    opaque: u64,
    /// Highest schema number a `session_start` line declared (1 when none did).
    schema: u32,
    /// A line read ahead of its turn, to check the unreadable line before it; the next `step` takes it.
    ahead: Option<Vec<u8>>,
}

/// One stored line as this build reads it.
struct Parsed {
    record: Record,
    /// Why the body could not be read; `None` for a record this build understands.
    unreadable: Option<serde_json::Error>,
    /// The schema a `session_start` line declares; 1 for every other line.
    schema: u32,
}

/// Parse one line (newline excluded). A line this build cannot deserialize but that still places
/// itself in the chain comes back as an opaque record; anything else is an error.
fn parse_line(line: &[u8]) -> Result<Parsed, serde_json::Error> {
    match serde_json::from_slice::<Record>(line) {
        Ok(record) => {
            let schema = if let Event::SessionStart(s) = &record.event { s.schema } else { 1 };
            Ok(Parsed { record, unreadable: None, schema })
        }
        Err(e) => match opaque_record(line) {
            Some((record, schema)) => Ok(Parsed { record, unreadable: Some(e), schema }),
            None => Err(e),
        },
    }
}

/// Read a line this build cannot fully deserialize as an opaque record, plus the schema it declares.
/// The whole line must parse as a JSON object with a `seq` and a `prev`. Parsing all of it, not
/// only those two fields, keeps bytes that are not JSON at all (invalid UTF-8 inside a string,
/// nesting deeper than `serde_json` reads) on the damage side.
fn opaque_record(line: &[u8]) -> Option<(Record, u32)> {
    let Value::Object(map) = serde_json::from_slice::<Value>(line).ok()? else { return None };
    opaque_header(&map)
}

/// The opaque record a JSON object with a `seq` and a `prev` stands for, plus the schema it declares.
fn opaque_header(map: &serde_json::Map<String, Value>) -> Option<(Record, u32)> {
    let seq = map.get("seq").and_then(Value::as_u64)?;
    let prev = map.get("prev").and_then(Value::as_str)?.to_string();
    let author = map.get("author").and_then(|v| Author::deserialize(v).ok()).unwrap_or(Author::Harness);
    let is_start = map.get("kind").and_then(Value::as_str) == Some("session_start");
    let schema = match (is_start, map.get("schema").and_then(Value::as_u64)) {
        (true, Some(n)) => u32::try_from(n).unwrap_or(u32::MAX),
        _ => 1,
    };
    let ts_ms = map.get("ts_ms").and_then(Value::as_u64).unwrap_or(0);
    Some((Record { seq, ts_ms, author, prev, event: Event::Unknown }, schema))
}

/// Read one record from JSON already parsed (a record the API served, possibly a stored line written
/// by a newer loom) as `open` reads a line: one whose body this build cannot read but whose header is
/// sound comes back opaque (`Event::Unknown`). `None` when the value is not a record at all.
pub fn record_from_value(value: &Value) -> Option<Record> {
    match Record::deserialize(value) {
        Ok(record) => Some(record),
        Err(_) => value.as_object().and_then(opaque_header).map(|(record, _)| record),
    }
}

impl<R: BufRead> Scanner<R> {
    fn new(reader: R) -> Self {
        Scanner {
            reader,
            buf: Vec::new(),
            next_seq: 0,
            last_hash: ZERO_HASH.to_string(),
            good_len: 0,
            opaque: 0,
            schema: 1,
            ahead: None,
        }
    }

    fn step(&mut self) -> std::io::Result<Step> {
        match self.ahead.take() {
            Some(line) => self.buf = line,
            None => {
                self.buf.clear();
                self.reader.read_until(b'\n', &mut self.buf)?;
            }
        }
        if self.buf.is_empty() {
            return Ok(Step::End);
        }
        let Some((&b'\n', line)) = self.buf.split_last() else {
            return Ok(Step::Bad("torn final line".to_string()));
        };
        let total = self.buf.len() as u64;
        let line_no = self.next_seq.saturating_add(1);
        let Parsed { record, unreadable, schema } = match parse_line(line) {
            Ok(parsed) => parsed,
            Err(e) => return Ok(Step::Bad(format!("line {line_no} is not a record: {e}"))),
        };
        if record.seq != self.next_seq {
            return Ok(Step::Bad(format!(
                "line {line_no} has seq {} where {} was expected",
                record.seq, self.next_seq
            )));
        }
        if record.prev != self.last_hash {
            return Ok(Step::Bad(format!("line {line_no} breaks the chain")));
        }
        let hash = sha256_hex(line);
        // The parsed form of an unknown or opaque record holds only its header; the line holds the rest.
        let kept = matches!(record.event, Event::Unknown).then(|| String::from_utf8(line.to_vec()).ok()).flatten();
        if let Some(e) = &unreadable {
            // Only the next line can vouch for bytes this build cannot read.
            if self.next_line_disowns(&hash)? {
                return Ok(Step::Bad(format!("line {line_no} is not a record: {e}")));
            }
        }
        self.last_hash = hash;
        self.next_seq = self.next_seq.saturating_add(1);
        self.good_len = self.good_len.saturating_add(total);
        self.opaque = self.opaque.saturating_add(u64::from(unreadable.is_some()));
        self.schema = self.schema.max(schema);
        Ok(Step::Record(Box::new(StoredRecord { record, line: kept })))
    }

    /// Read the line after the current one and keep it for the next `step`. True when that line has
    /// the seq that follows but a `prev` other than `hash`, the current line's hash: it was chained
    /// to other bytes, so the current line is not the one that was written.
    fn next_line_disowns(&mut self, hash: &str) -> std::io::Result<bool> {
        let mut next = Vec::new();
        if self.reader.read_until(b'\n', &mut next)? == 0 {
            return Ok(false);
        }
        let follows = self.next_seq.saturating_add(1);
        let disowns = match next.split_last() {
            Some((&b'\n', line)) => parse_line(line).is_ok_and(|p| p.record.seq == follows && p.record.prev != hash),
            _ => false,
        };
        self.ahead = Some(next);
        Ok(disowns)
    }
}

/// The scanner's final state, the records read, and why reading stopped (`None` = clean end).
type Scanned = (Scanner<BufReader<File>>, Vec<Record>, Option<String>);

/// Read the whole readable prefix of `path`.
fn scan_file(path: &Path) -> Result<Scanned, LogError> {
    let file = File::open(path).map_err(io_err(path))?;
    let mut scanner = Scanner::new(BufReader::new(file));
    let mut records = Vec::new();
    loop {
        match scanner.step().map_err(io_err(path))? {
            Step::Record(r) => records.push(r.record),
            Step::End => return Ok((scanner, records, None)),
            Step::Bad(detail) => return Ok((scanner, records, Some(detail))),
        }
    }
}

/// A free name for the salvage file next to `path`.
fn damaged_name(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".damaged-{}", now_ms()));
    let mut candidate = PathBuf::from(&name);
    let mut n = 1u32;
    while candidate.exists() && n < 10_000 {
        let mut next = name.clone();
        next.push(format!("-{n}"));
        candidate = PathBuf::from(next);
        n += 1;
    }
    candidate
}

impl SessionLog {
    /// Create a new, empty log. Parent directories are created. Fails if the file exists.
    pub fn create(path: &Path, durability: Durability) -> Result<SessionLog, LogError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(io_err(parent))?;
        }
        let file = match OpenOptions::new().append(true).create_new(true).open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(LogError::Exists(path.to_path_buf()))
            }
            Err(e) => return Err(io_err(path)(e)),
        };
        lock_log(&file, path)?;
        // The new name must survive a crash, or the first records would be written to a file that is gone.
        let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
        File::open(dir).and_then(|d| d.sync_all()).map_err(io_err(dir))?;
        Ok(SessionLog {
            path: path.to_path_buf(),
            file,
            next_seq: 0,
            last_hash: ZERO_HASH.to_string(),
            durability,
            len: 0,
        })
    }

    /// Open an existing log for appending, salvaging damage as described in the module contract.
    pub fn open(path: &Path, durability: Durability) -> Result<(SessionLog, OpenReport), LogError> {
        Self::open_with(path, durability, true)
    }

    /// Open a log that another handle of this same process holds locked and will never write to
    /// again (a session task parked for good at shutdown). No lock is taken: the caller vouches that
    /// it is the only writer left. Everything else is as in [`SessionLog::open`].
    pub fn open_beside(path: &Path, durability: Durability) -> Result<(SessionLog, OpenReport), LogError> {
        Self::open_with(path, durability, false)
    }

    fn open_with(path: &Path, durability: Durability, lock: bool) -> Result<(SessionLog, OpenReport), LogError> {
        // The lock comes first: what is scanned below must not change before it is appended to.
        let file = OpenOptions::new().append(true).open(path).map_err(io_err(path))?;
        if lock {
            lock_log(&file, path)?;
        }
        let (scanner, records, cause) = scan_file(path)?;
        if scanner.opaque > 0 || scanner.schema > SCHEMA {
            return Err(LogError::Newer(path.to_path_buf()));
        }
        let file_len = std::fs::metadata(path).map_err(io_err(path))?.len();
        let good_len = scanner.good_len;
        let mut damage = None;
        if file_len > good_len {
            let moved_to = damaged_name(path);
            let mut src = File::open(path).map_err(io_err(path))?;
            src.seek(SeekFrom::Start(good_len)).map_err(io_err(path))?;
            let mut dst = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&moved_to)
                .map_err(io_err(&moved_to))?;
            std::io::copy(&mut src.take(file_len - good_len), &mut dst).map_err(io_err(&moved_to))?;
            dst.sync_all().map_err(io_err(&moved_to))?;
            file.set_len(good_len).map_err(io_err(path))?;
            file.sync_all().map_err(io_err(path))?;
            damage = Some(Damage {
                good_records: records.len() as u64,
                bad_bytes: file_len - good_len,
                moved_to: Some(moved_to),
                detail: cause.unwrap_or_else(|| "unreadable bytes after the last record".to_string()),
            });
        }
        let log = SessionLog {
            path: path.to_path_buf(),
            file,
            next_seq: scanner.next_seq,
            last_hash: scanner.last_hash,
            durability,
            len: good_len,
        };
        Ok((log, OpenReport { records, damage, opaque: 0 }))
    }

    /// Append one event and return the record as written.
    pub fn append(&mut self, author: Author, event: Event) -> Result<Record, LogError> {
        let record = Record { seq: self.next_seq, ts_ms: now_ms(), author, prev: self.last_hash.clone(), event };
        let mut line = serde_json::to_vec(&record)?;
        let hash = sha256_hex(&line);
        line.push(b'\n');
        let written = self.file.write_all(&line).and_then(|()| match self.durability {
            Durability::Always => self.file.sync_data(),
            Durability::Batch => Ok(()),
        });
        if let Err(e) = written {
            // Do not leave a partial line in front of the next append.
            let _ = self.file.set_len(self.len);
            return Err(io_err(&self.path)(e));
        }
        self.len = self.len.saturating_add(line.len() as u64);
        self.last_hash = hash;
        self.next_seq = self.next_seq.saturating_add(1);
        Ok(record)
    }

    /// The seq the next append will get.
    pub fn next_seq(&self) -> Seq {
        self.next_seq
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Copy records `0..=upto_seq` byte for byte into a new log at `dest` and return it open.
    pub fn fork_to(&self, dest: &Path, upto_seq: Seq, durability: Durability) -> Result<SessionLog, LogError> {
        if upto_seq >= self.next_seq {
            return Err(LogError::ForkPoint { upto: upto_seq, last: self.next_seq.saturating_sub(1) });
        }
        fork_file(&self.path, dest, upto_seq, durability).map(|(log, _)| log)
    }

    /// Copy the first `upto_seq + 1` stored lines of the log at `src_path` into `child`, set its chain
    /// state and return the records copied. Every line is checked as the scanner checks it before it
    /// is written, so the child never starts with a prefix its next `open` would cut back.
    fn copy_prefix(src_path: &Path, child: &mut SessionLog, upto_seq: Seq) -> Result<Vec<Record>, LogError> {
        let refuse =
            |seq: Seq, detail: &str| LogError::ForkSource { path: src_path.to_path_buf(), seq, detail: detail.to_string() };
        let src = File::open(src_path).map_err(io_err(src_path))?;
        let mut reader = BufReader::new(src);
        let mut out = BufWriter::new(&child.file);
        let mut buf = Vec::new();
        let mut records = Vec::new();
        let mut copied: u64 = 0;
        let mut last_hash = ZERO_HASH.to_string();
        let mut seq: Seq = 0;
        while seq <= upto_seq {
            buf.clear();
            let n = reader.read_until(b'\n', &mut buf).map_err(io_err(src_path))?;
            if n == 0 {
                return Err(refuse(seq, "is missing: the log ends before it"));
            }
            let Some((&b'\n', line)) = buf.split_last() else {
                return Err(refuse(seq, "is not a complete line"));
            };
            let parsed = parse_line(line).map_err(|e| refuse(seq, &format!("is not a record ({e})")))?;
            if parsed.unreadable.is_some() || parsed.schema > SCHEMA {
                return Err(refuse(seq, "was written by a newer loom and cannot be read by this one"));
            }
            if parsed.record.seq != seq {
                return Err(refuse(seq, &format!("is out of place (it says seq {})", parsed.record.seq)));
            }
            if parsed.record.prev != last_hash {
                return Err(refuse(seq, "does not chain to the record before it"));
            }
            out.write_all(&buf).map_err(io_err(&child.path))?;
            last_hash = sha256_hex(line);
            copied = copied.saturating_add(n as u64);
            records.push(parsed.record);
            seq = seq.saturating_add(1);
        }
        out.flush().map_err(io_err(&child.path))?;
        drop(out);
        if child.durability == Durability::Always {
            child.file.sync_data().map_err(io_err(&child.path))?;
        }
        child.next_seq = seq;
        child.last_hash = last_hash;
        child.len = copied;
        Ok(records)
    }
}

/// Fork the log file at `src` without holding it open for writing: copy records `0..=upto_seq`
/// byte for byte into a new log at `dest` and return that log open, with the records copied. `src` is
/// only read, so this is safe while another handle is appending to it (records up to `upto_seq` must
/// already be complete). A line that fails the checks of the module contract ends the fork with
/// [`LogError::ForkSource`] and nothing is left at `dest`.
pub fn fork_file(
    src: &Path,
    dest: &Path,
    upto_seq: Seq,
    durability: Durability,
) -> Result<(SessionLog, Vec<Record>), LogError> {
    let mut child = SessionLog::create(dest, durability)?;
    match SessionLog::copy_prefix(src, &mut child, upto_seq) {
        Ok(records) => Ok((child, records)),
        Err(e) => {
            drop(child);
            let _ = std::fs::remove_file(dest);
            Err(e)
        }
    }
}

/// Read every readable record without modifying anything.
pub fn read_records(path: &Path) -> Result<OpenReport, LogError> {
    let (scanner, records, cause) = scan_file(path)?;
    let file_len = std::fs::metadata(path).map_err(io_err(path))?.len();
    let damage = (file_len > scanner.good_len).then(|| Damage {
        good_records: records.len() as u64,
        bad_bytes: file_len - scanner.good_len,
        moved_to: None,
        detail: cause.unwrap_or_else(|| "unreadable bytes after the last record".to_string()),
    });
    Ok(OpenReport { records, damage, opaque: scanner.opaque })
}

/// Read up to `limit` records with `seq > after` (`None` = from the start), as stored lines parsed
/// back into records. Used by the API for paging; stops silently at damage.
pub fn read_page(path: &Path, after: Option<Seq>, limit: usize) -> Result<Vec<Record>, LogError> {
    let first = match after {
        None => 0,
        Some(a) => match a.checked_add(1) {
            Some(f) => f,
            None => return Ok(Vec::new()),
        },
    };
    let mut page = Vec::new();
    if limit == 0 {
        return Ok(page);
    }
    let file = File::open(path).map_err(io_err(path))?;
    let mut scanner = Scanner::new(BufReader::new(file));
    // Every line is checked against the chain, but only the page is kept in memory.
    while let Step::Record(r) = scanner.step().map_err(io_err(path))? {
        if r.record.seq >= first {
            page.push(r.record);
            if page.len() >= limit {
                break;
            }
        }
    }
    Ok(page)
}

/// Records between two checkpoints of a [`PageReader`].
const CHECKPOINT_EVERY: u64 = 256;

/// Verified chain state at a line boundary: the seq of the next line, its byte offset, and the hash
/// of the line before it.
#[derive(Clone, Debug)]
struct Mark {
    seq: Seq,
    offset: u64,
    hash: String,
}

impl Mark {
    fn origin() -> Mark {
        Mark { seq: 0, offset: 0, hash: ZERO_HASH.to_string() }
    }
}

/// Pages through one log file and remembers how far it has verified the chain, so that fetching
/// pages in sequence costs time proportional to the page, not to the log. Every record it serves
/// was chain-verified. It starts over when the file got shorter, when its last verified line
/// changed, and when a scan stops inside the part it had verified. A line changed in place below a
/// checkpoint, with the length and the last line as they were, is noticed by the first scan that
/// crosses it; until then pages above that checkpoint are served as verified before the change.
#[derive(Debug)]
pub struct PageReader {
    path: PathBuf,
    /// Verified state at every `CHECKPOINT_EVERY`-th record; `marks[i].seq == i * CHECKPOINT_EVERY`.
    marks: Vec<Mark>,
    /// Verified end of the log.
    end: Mark,
    /// Verified state after the last record served.
    cursor: Mark,
    /// Start offset and length (newline excluded) of the last verified line.
    tail: Option<(u64, u64)>,
    /// Lines hashed so far (chain steps and prefix checks); lets tests see that paging is not rescanning.
    lines_hashed: u64,
}

impl PageReader {
    pub fn new(path: &Path) -> PageReader {
        PageReader {
            path: path.to_path_buf(),
            marks: vec![Mark::origin()],
            end: Mark::origin(),
            cursor: Mark::origin(),
            tail: None,
            lines_hashed: 0,
        }
    }

    fn reset(&mut self) {
        *self = PageReader { lines_hashed: self.lines_hashed, ..PageReader::new(&self.path) };
    }

    /// True when the file still holds the prefix verified earlier.
    fn prefix_holds(&mut self, file: &mut File) -> std::io::Result<bool> {
        if file.metadata()?.len() < self.end.offset {
            return Ok(false);
        }
        let Some((start, len)) = self.tail else { return Ok(true) };
        let Ok(size) = usize::try_from(len.saturating_add(1)) else { return Ok(false) };
        let mut line = vec![0u8; size];
        file.seek(SeekFrom::Start(start))?;
        if file.read_exact(&mut line).is_err() {
            return Ok(false);
        }
        self.lines_hashed = self.lines_hashed.saturating_add(1);
        Ok(line.pop() == Some(b'\n') && sha256_hex(&line) == self.end.hash)
    }

    /// Up to `limit` records with `seq > after` (`None` = from the start); stops silently at damage.
    pub fn read_page(&mut self, after: Option<Seq>, limit: usize) -> Result<Vec<Record>, LogError> {
        Ok(self.read_stored(after, limit)?.into_iter().map(|stored| stored.record).collect())
    }

    /// The page `read_page` serves, each record with its stored line when it was read as
    /// [`Event::Unknown`].
    pub fn read_stored(&mut self, after: Option<Seq>, limit: usize) -> Result<Vec<StoredRecord>, LogError> {
        let first = match after {
            None => 0,
            Some(a) => match a.checked_add(1) {
                Some(f) => f,
                None => return Ok(Vec::new()),
            },
        };
        if limit == 0 {
            return Ok(Vec::new());
        }
        let path = self.path.clone();
        let mut file = File::open(&path).map_err(io_err(&path))?;
        if !self.prefix_holds(&mut file).map_err(io_err(&path))? {
            self.reset();
        }
        let (page, full) = self.scan(file, first, limit).map_err(io_err(&path))?;
        if full || self.cursor.seq >= self.end.seq {
            return Ok(page);
        }
        // The scan stopped at a line verified earlier, so the verified part has changed: forget it
        // and read again from the start of the file.
        self.reset();
        let file = File::open(&path).map_err(io_err(&path))?;
        Ok(self.scan(file, first, limit).map_err(io_err(&path))?.0)
    }

    /// Collect up to `limit` records from `first` on, scanning from the latest verified position at
    /// or before `first`. The flag says whether the page was filled (false: the scan reached the end
    /// of the readable log first).
    fn scan(&mut self, mut file: File, first: Seq, limit: usize) -> std::io::Result<(Vec<StoredRecord>, bool)> {
        let index = usize::try_from(first / CHECKPOINT_EVERY).unwrap_or(usize::MAX);
        let mut start = self.marks.get(index).or(self.marks.last()).cloned().unwrap_or_else(Mark::origin);
        for m in [&self.cursor, &self.end] {
            if m.seq <= first && m.seq > start.seq {
                start = m.clone();
            }
        }
        file.seek(SeekFrom::Start(start.offset))?;
        let mut scanner = Scanner::new(BufReader::new(file));
        scanner.next_seq = start.seq;
        scanner.last_hash = start.hash;
        scanner.good_len = start.offset;
        let mut page = Vec::new();
        let mut full = false;
        while !full {
            let before = scanner.good_len;
            let Step::Record(r) = scanner.step()? else { break };
            self.lines_hashed = self.lines_hashed.saturating_add(1);
            if scanner.next_seq > self.end.seq {
                self.end = Mark { seq: scanner.next_seq, offset: scanner.good_len, hash: scanner.last_hash.clone() };
                self.tail = Some((before, scanner.good_len.saturating_sub(before).saturating_sub(1)));
                if u64::try_from(self.marks.len()).ok().and_then(|n| n.checked_mul(CHECKPOINT_EVERY))
                    == Some(scanner.next_seq)
                {
                    self.marks.push(self.end.clone());
                }
            }
            if r.record.seq >= first {
                page.push(*r);
                full = page.len() >= limit;
            }
        }
        self.cursor = Mark { seq: scanner.next_seq, offset: scanner.good_len, hash: scanner.last_hash };
        Ok((page, full))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Trigger, TurnEndReason};

    fn msg(i: usize) -> Event {
        Event::UserMessage { text: format!("message {i}") }
    }

    fn fill(log: &mut SessionLog, n: usize) -> Vec<Record> {
        (0..n).map(|i| log.append(Author::User, msg(i)).unwrap()).collect()
    }

    fn new_log(dir: &tempfile::TempDir) -> (PathBuf, SessionLog) {
        let path = dir.path().join("s").join("log.jsonl");
        let log = SessionLog::create(&path, Durability::Batch).unwrap();
        (path, log)
    }

    fn lines(path: &Path) -> Vec<Vec<u8>> {
        let bytes = std::fs::read(path).unwrap();
        bytes.split_inclusive(|b| *b == b'\n').map(|l| l.to_vec()).collect()
    }

    #[test]
    fn round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let (path, mut log) = new_log(&dir);
        let written = fill(&mut log, 5);
        assert_eq!(log.next_seq(), 5);
        assert_eq!(log.path(), path.as_path());
        let report = read_records(&path).unwrap();
        assert_eq!(report.records, written);
        assert!(report.damage.is_none());
    }

    #[test]
    fn chain_values() {
        let dir = tempfile::tempdir().unwrap();
        let (path, mut log) = new_log(&dir);
        let written = fill(&mut log, 3);
        assert_eq!(written[0].prev, ZERO_HASH);
        let ls = lines(&path);
        for i in 1..3 {
            let line = &ls[i - 1];
            assert_eq!(written[i].prev, sha256_hex(&line[..line.len() - 1]));
        }
        for (i, r) in written.iter().enumerate() {
            assert_eq!(r.seq, i as u64);
        }
    }

    #[test]
    fn torn_tail_is_moved_aside() {
        let dir = tempfile::tempdir().unwrap();
        let (path, mut log) = new_log(&dir);
        fill(&mut log, 3);
        drop(log);
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"{\"seq\":3,\"ts_ms\"").unwrap();
        drop(f);
        let ro = read_records(&path).unwrap();
        assert_eq!(ro.records.len(), 3);
        let d = ro.damage.unwrap();
        assert_eq!((d.moved_to.clone(), d.detail.as_str()), (None, "torn final line"));
        let (mut log, report) = SessionLog::open(&path, Durability::Batch).unwrap();
        let d = report.damage.unwrap();
        assert_eq!(d.good_records, 3);
        assert_eq!(d.bad_bytes, 16);
        assert_eq!(d.detail, "torn final line");
        assert_eq!(std::fs::read(d.moved_to.unwrap()).unwrap(), b"{\"seq\":3,\"ts_ms\"");
        assert_eq!(log.next_seq(), 3);
        log.append(Author::Harness, msg(3)).unwrap();
        let again = read_records(&path).unwrap();
        assert_eq!(again.records.len(), 4);
        assert!(again.damage.is_none());
    }

    #[test]
    fn corrupted_middle_line_keeps_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let (path, mut log) = new_log(&dir);
        fill(&mut log, 5);
        drop(log);
        let ls = lines(&path);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ls[0]);
        bytes.extend_from_slice(&ls[1]);
        bytes.extend_from_slice(b"this is not json\n");
        bytes.extend_from_slice(&ls[3]);
        bytes.extend_from_slice(&ls[4]);
        std::fs::write(&path, &bytes).unwrap();
        let tail_len = (bytes.len() - ls[0].len() - ls[1].len()) as u64;

        let (mut log, report) = SessionLog::open(&path, Durability::Batch).unwrap();
        assert_eq!(report.records.len(), 2);
        let d = report.damage.unwrap();
        assert_eq!(d.good_records, 2);
        assert_eq!(d.bad_bytes, tail_len);
        assert!(d.detail.starts_with("line 3 is not a record"), "{}", d.detail);
        let moved = d.moved_to.unwrap();
        assert!(moved.exists());
        assert!(moved.file_name().unwrap().to_string_lossy().starts_with("log.jsonl.damaged-"));
        assert_eq!(std::fs::metadata(&path).unwrap().len(), (ls[0].len() + ls[1].len()) as u64);
        assert_eq!(log.next_seq(), 2);
        log.append(Author::Model, msg(9)).unwrap();
        let after = read_records(&path).unwrap();
        assert_eq!(after.records.len(), 3);
        assert!(after.damage.is_none());
    }

    #[test]
    fn wrong_seq_and_broken_chain_end_the_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let (path, mut log) = new_log(&dir);
        fill(&mut log, 3);
        drop(log);
        let ls = lines(&path);
        // Drop the middle line: line 2 now carries seq 2 where 1 is expected.
        std::fs::write(&path, [ls[0].clone(), ls[2].clone()].concat()).unwrap();
        let report = read_records(&path).unwrap();
        assert_eq!(report.records.len(), 1);
        assert_eq!(report.damage.unwrap().detail, "line 2 has seq 2 where 1 was expected");

        // Right seq, wrong prev.
        let first_hash = sha256_hex(&ls[0][..ls[0].len() - 1]);
        let text = String::from_utf8(ls[1].clone()).unwrap().replace(&first_hash, &"f".repeat(64));
        std::fs::write(&path, [ls[0].clone(), text.into_bytes()].concat()).unwrap();
        let report = read_records(&path).unwrap();
        assert_eq!(report.records.len(), 1);
        assert_eq!(report.damage.unwrap().detail, "line 2 breaks the chain");
    }

    #[test]
    fn reopen_and_append() {
        let dir = tempfile::tempdir().unwrap();
        let (path, mut log) = new_log(&dir);
        fill(&mut log, 2);
        drop(log);
        let (mut log, report) = SessionLog::open(&path, Durability::Always).unwrap();
        assert!(report.damage.is_none());
        assert_eq!(report.records.len(), 2);
        assert_eq!(log.next_seq(), 2);
        let r = log.append(Author::Tool, Event::TurnStart { trigger: Trigger::User }).unwrap();
        assert_eq!(r.seq, 2);
        let all = read_records(&path).unwrap();
        assert_eq!(all.records.len(), 3);
        assert_eq!(all.records[2], r);
        assert!(all.damage.is_none());
    }

    #[test]
    fn fork_is_byte_identical_and_chains() {
        let dir = tempfile::tempdir().unwrap();
        let (path, mut log) = new_log(&dir);
        fill(&mut log, 6);
        let dest = dir.path().join("child").join("log.jsonl");
        let mut child = log.fork_to(&dest, 3, Durability::Batch).unwrap();
        assert_eq!(child.next_seq(), 4);
        assert_eq!(lines(&dest), lines(&path)[..4].to_vec());
        let r = child.append(Author::Harness, Event::TurnEnd { reason: TurnEndReason::Stopped }).unwrap();
        assert_eq!(r.seq, 4);
        let ls = lines(&dest);
        assert_eq!(r.prev, sha256_hex(&ls[3][..ls[3].len() - 1]));
        let report = read_records(&dest).unwrap();
        assert_eq!(report.records.len(), 5);
        assert!(report.damage.is_none());
        // The parent is untouched and the fork point is checked.
        assert_eq!(log.next_seq(), 6);
        assert!(matches!(
            log.fork_to(&dir.path().join("x.jsonl"), 6, Durability::Batch),
            Err(LogError::ForkPoint { upto: 6, last: 5 })
        ));
        assert!(matches!(log.fork_to(&dest, 1, Durability::Batch), Err(LogError::Exists(_))));
    }

    #[test]
    fn a_fork_copies_unknown_kinds_verbatim_and_returns_the_records_it_copied() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        let bytes = hand_log(&[OK_MSG, r#""kind":"from_the_future", "x": [1, 2]"#, OK_MSG, OK_MSG]);
        std::fs::write(&path, &bytes).unwrap();
        let dest = dir.path().join("child").join("log.jsonl");
        let (mut child, records) = fork_file(&path, &dest, 2, Durability::Batch).unwrap();
        assert_eq!(lines(&dest), lines(&path)[..3].to_vec());
        assert_eq!(records, read_records(&path).unwrap().records[..3].to_vec());
        assert_eq!(records[1].event, Event::Unknown);
        assert_eq!(child.append(Author::Harness, msg(3)).unwrap().seq, 3);
        assert!(read_records(&dest).unwrap().damage.is_none());
    }

    #[test]
    fn a_fork_from_a_prefix_that_is_not_a_sound_chain_is_refused_and_leaves_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let (path, mut log) = new_log(&dir);
        fill(&mut log, 6);
        drop(log);
        let good = lines(&path);
        let dest = dir.path().join("child").join("log.jsonl");
        let fork = |upto: Seq| fork_file(&path, &dest, upto, Durability::Batch).map(|(_, records)| records.len());
        // Record 2 points at other bytes than record 1 (an edit, bad media, a failed cut-back).
        let first_hash = sha256_hex(&good[1][..good[1].len() - 1]);
        let wrong_prev = String::from_utf8(good[2].clone()).unwrap().replace(&first_hash, &"f".repeat(64));
        let mut ls = good.clone();
        ls[2] = wrong_prev.into_bytes();
        // Half of record 2 left in front of the record written again after it (a failed append whose
        // cut-back failed too), and a line of a newer loom.
        let mut torn = good.clone();
        torn.insert(2, good[2][..good[2].len() / 2].to_vec());
        let opaque = hand_log(&[OK_MSG, OK_MSG, FUTURE_NOTE, OK_MSG, OK_MSG]);
        let cases: Vec<(Vec<u8>, Seq, &str)> = vec![
            (ls.concat(), 2, "does not chain to the record before it"),
            (torn.concat(), 2, "is not a record"),
            (opaque, 2, "was written by a newer loom"),
            (good[..3].concat(), 3, "is missing"),
        ];
        for (bytes, bad, detail) in cases {
            std::fs::write(&path, &bytes).unwrap();
            let err = fork_file(&path, &dest, 4, Durability::Batch).err().unwrap();
            assert!(matches!(&err, LogError::ForkSource { seq, .. } if *seq == bad), "{err}");
            let text = err.to_string();
            assert!(text.contains(&format!("its record {bad} {detail}")), "{text}");
            assert!(text.contains("Start the agent with mode `fresh`"), "{text}");
            assert!(!dest.exists(), "{detail}: a refused fork leaves no file");
            assert_eq!(std::fs::read(&path).unwrap(), bytes, "the parent's log is only read");
            // Up to the record before the bad one, the fork goes through.
            assert_eq!(fork(bad - 1).unwrap(), bad as usize);
            std::fs::remove_file(&dest).unwrap();
        }
    }

    #[test]
    fn read_page_pages() {
        let dir = tempfile::tempdir().unwrap();
        let (path, mut log) = new_log(&dir);
        let all = fill(&mut log, 7);
        let seqs = |v: Vec<Record>| v.into_iter().map(|r| r.seq).collect::<Vec<_>>();
        assert_eq!(seqs(read_page(&path, None, 3).unwrap()), vec![0, 1, 2]);
        assert_eq!(seqs(read_page(&path, Some(2), 3).unwrap()), vec![3, 4, 5]);
        assert_eq!(seqs(read_page(&path, Some(5), 10).unwrap()), vec![6]);
        assert!(read_page(&path, Some(6), 10).unwrap().is_empty());
        assert!(read_page(&path, Some(u64::MAX), 10).unwrap().is_empty());
        assert!(read_page(&path, None, 0).unwrap().is_empty());
        assert_eq!(read_page(&path, None, 100).unwrap(), all);
        // Damage ends the page silently.
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"garbage\n").unwrap();
        assert_eq!(read_page(&path, Some(4), 10).unwrap().len(), 2);
    }

    #[test]
    fn page_reader_matches_read_page_for_every_window() {
        let dir = tempfile::tempdir().unwrap();
        let (path, mut log) = new_log(&dir);
        fill(&mut log, 600);
        let mut shared = PageReader::new(&path);
        let afters: Vec<Option<Seq>> =
            [None, Some(0), Some(1), Some(254), Some(255), Some(256), Some(300), Some(510), Some(511), Some(598), Some(599), Some(600), Some(u64::MAX)]
                .into_iter()
                .chain((0..600).step_by(37).map(Some))
                .collect();
        for after in afters {
            for limit in [0usize, 1, 7, 256, 1000] {
                let want = read_page(&path, after, limit).unwrap();
                assert_eq!(shared.read_page(after, limit).unwrap(), want, "shared reader, after {after:?} limit {limit}");
                assert_eq!(PageReader::new(&path).read_page(after, limit).unwrap(), want, "fresh reader, after {after:?}");
            }
        }
    }

    #[test]
    fn page_reader_follows_appends_and_resets_after_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let (path, mut log) = new_log(&dir);
        fill(&mut log, 10);
        let mut reader = PageReader::new(&path);
        assert_eq!(reader.read_page(None, 100).unwrap().len(), 10);
        assert!(reader.read_page(Some(9), 100).unwrap().is_empty());
        fill(&mut log, 5);
        let more = reader.read_page(Some(9), 100).unwrap();
        assert_eq!(more.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![10, 11, 12, 13, 14]);
        drop(log);
        // Cut back to eight records, then grown past the old length with other records. The reader
        // remembers where the fifteen it verified ended; a page asked for from there has to come
        // from the file as it is now.
        let old_len = std::fs::metadata(&path).unwrap().len();
        std::fs::write(&path, lines(&path)[..8].concat()).unwrap();
        let (mut log, _) = SessionLog::open(&path, Durability::Batch).unwrap();
        for i in 0..12 {
            log.append(Author::Model, msg(1000 + i)).unwrap();
        }
        drop(log);
        assert!(std::fs::metadata(&path).unwrap().len() >= old_len);
        let want = read_page(&path, Some(14), 100).unwrap();
        assert_eq!(want.len(), 5);
        assert_eq!(reader.read_page(Some(14), 100).unwrap(), want);
        assert_eq!(reader.read_page(Some(9), 100).unwrap(), read_page(&path, Some(9), 100).unwrap());
        // Cut back to eight records (a shorter file).
        let ls = lines(&path);
        let keep: Vec<u8> = ls[..8].concat();
        std::fs::write(&path, &keep).unwrap();
        let after_cut = reader.read_page(None, 100).unwrap();
        assert_eq!(after_cut.len(), 8);
        // Same length, different content: the verified prefix changed.
        let other = dir.path().join("other.jsonl");
        let mut o = SessionLog::create(&other, Durability::Batch).unwrap();
        for i in 0..8 {
            o.append(Author::Model, msg(1000 + i)).unwrap();
        }
        std::fs::write(&path, std::fs::read(&other).unwrap()).unwrap();
        let swapped = reader.read_page(None, 100).unwrap();
        assert_eq!(swapped, read_page(&path, None, 100).unwrap());
        assert_eq!(swapped[0].event, msg(1000));
        // Truncated to nothing.
        std::fs::write(&path, b"").unwrap();
        assert!(reader.read_page(None, 100).unwrap().is_empty());

        // A different, longer log under the name of one the reader had read to its end.
        let path = dir.path().join("replaced").join("log.jsonl");
        let mut log = SessionLog::create(&path, Durability::Batch).unwrap();
        fill(&mut log, 15);
        drop(log);
        let mut reader = PageReader::new(&path);
        assert_eq!(reader.read_page(None, 100).unwrap().len(), 15);
        let longer = dir.path().join("longer.jsonl");
        let mut l = SessionLog::create(&longer, Durability::Batch).unwrap();
        for i in 0..40 {
            l.append(Author::Model, msg(2000 + i)).unwrap();
        }
        drop(l);
        std::fs::write(&path, std::fs::read(&longer).unwrap()).unwrap();
        let want = read_page(&path, Some(14), 100).unwrap();
        assert_eq!(want.len(), 25);
        assert_eq!(reader.read_page(Some(14), 100).unwrap(), want);
    }

    #[test]
    fn page_reader_starts_over_when_a_verified_line_changed() {
        let dir = tempfile::tempdir().unwrap();
        let (path, mut log) = new_log(&dir);
        fill(&mut log, 600);
        drop(log);
        let mut reader = PageReader::new(&path);
        assert_eq!(reader.read_page(None, 1000).unwrap().len(), 600);
        // Line 100 altered in place: the length and the last line stay, line 101 no longer chains.
        let mut ls = lines(&path);
        let original = String::from_utf8(ls[100].clone()).unwrap();
        let altered = original.replace("message 100", "message 1oo");
        assert!(altered != original && altered.len() == original.len());
        ls[100] = altered.into_bytes();
        std::fs::write(&path, ls.concat()).unwrap();
        // A scan that crosses the altered line stops behind it, inside what was verified before...
        let want = read_page(&path, Some(50), 100).unwrap();
        assert_eq!(want.last().map(|r| r.seq), Some(100));
        assert_eq!(reader.read_page(Some(50), 100).unwrap(), want);
        // ...and from then on nothing is served from the checkpoints beyond it.
        assert!(reader.read_page(Some(299), 10).unwrap().is_empty());
        for after in [None, Some(98), Some(99), Some(100), Some(255), Some(256), Some(511), Some(598)] {
            for limit in [1usize, 10, 1000] {
                let want = read_page(&path, after, limit).unwrap();
                assert_eq!(reader.read_page(after, limit).unwrap(), want, "after {after:?} limit {limit}");
            }
        }
    }

    #[test]
    fn sequential_paging_does_not_rescan_the_log() {
        let dir = tempfile::tempdir().unwrap();
        let (path, mut log) = new_log(&dir);
        fill(&mut log, 1000);
        let mut reader = PageReader::new(&path);
        let mut after = None;
        let mut total = 0;
        let mut pages = 0u64;
        loop {
            let page = reader.read_page(after, 10).unwrap();
            let Some(last) = page.last() else { break };
            after = Some(last.seq);
            total += page.len();
            pages += 1;
        }
        assert_eq!(total, 1000);
        // One hash per record plus one prefix check per call; the old reader hashed ~50 000 lines.
        assert!(reader.lines_hashed <= 1000 + 2 * (pages + 1), "hashed {} lines", reader.lines_hashed);
        // Following new appends costs the new lines only.
        let before = reader.lines_hashed;
        fill(&mut log, 3);
        assert_eq!(reader.read_page(after, 10).unwrap().len(), 3);
        assert!(reader.lines_hashed - before <= 3 + 2, "hashed {} lines", reader.lines_hashed - before);
    }

    #[test]
    fn create_refuses_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let (path, log) = new_log(&dir);
        drop(log);
        assert!(matches!(SessionLog::create(&path, Durability::Batch), Err(LogError::Exists(_))));
    }

    #[test]
    fn a_log_open_for_append_cannot_be_opened_again_until_it_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let (path, mut log) = new_log(&dir);
        log.append(Author::Harness, msg(0)).unwrap();
        let err = SessionLog::open(&path, Durability::Batch).unwrap_err();
        assert!(matches!(err, LogError::Locked(_)), "{err}");
        assert!(err.to_string().contains("is already open for writing"), "{err}");
        // Reading takes no lock.
        assert_eq!(read_records(&path).unwrap().records.len(), 1);
        drop(log);
        let (mut again, report) = SessionLog::open(&path, Durability::Batch).unwrap();
        assert_eq!(report.records.len(), 1);
        again.append(Author::Harness, msg(1)).unwrap();
    }

    #[test]
    fn a_log_can_be_opened_beside_a_holder_that_writes_no_more() {
        let dir = tempfile::tempdir().unwrap();
        let (path, mut held) = new_log(&dir);
        held.append(Author::Harness, msg(0)).unwrap();
        // The holder keeps its lock and never writes again; the second handle continues the chain.
        let (mut beside, report) = SessionLog::open_beside(&path, Durability::Batch).unwrap();
        assert_eq!(report.records.len(), 1);
        beside.append(Author::Harness, msg(1)).unwrap();
        drop(beside);
        // The lock still belongs to the holder.
        assert!(matches!(SessionLog::open(&path, Durability::Batch).unwrap_err(), LogError::Locked(_)));
        drop(held);
        let read = read_records(&path).unwrap();
        assert_eq!(read.records.len(), 2);
        assert!(read.damage.is_none());
    }

    #[test]
    fn unknown_events_survive_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        // A line written by a newer build: extra field and unknown kind, spaces included.
        let first = format!(
            "{{\"seq\":0, \"ts_ms\":1,\"author\":\"harness\",\"prev\":\"{ZERO_HASH}\",\"kind\":\"from_the_future\",\"x\":[1, 2]}}"
        );
        std::fs::write(&path, format!("{first}\n")).unwrap();
        let (mut log, report) = SessionLog::open(&path, Durability::Batch).unwrap();
        assert!(report.damage.is_none());
        assert_eq!(report.records[0].event, Event::Unknown);
        let r = log.append(Author::Harness, msg(1)).unwrap();
        assert_eq!(r.prev, sha256_hex(first.as_bytes()));
        drop(log);
        assert_eq!(lines(&path)[0], format!("{first}\n").into_bytes());
        let (_, again) = SessionLog::open(&path, Durability::Batch).unwrap();
        assert!(again.damage.is_none());
        assert_eq!(again.records.len(), 2);
    }

    #[test]
    fn read_stored_keeps_the_line_of_unknown_and_opaque_records_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        let future = r#""kind":"from_the_future", "x": [1, 2],"y":{"z":"w"}"#;
        let bytes = hand_log(&[OK_MSG, future, FUTURE_NOTE, OK_MSG]);
        std::fs::write(&path, &bytes).unwrap();
        let stored_lines: Vec<String> = String::from_utf8(bytes).unwrap().lines().map(str::to_string).collect();
        let page = PageReader::new(&path).read_stored(None, 10).unwrap();
        let records = read_records(&path).unwrap().records;
        assert_eq!(page.iter().map(|s| s.record.clone()).collect::<Vec<_>>(), records);
        let kept: Vec<Option<&str>> = page.iter().map(|s| s.line.as_deref()).collect();
        assert_eq!(kept, vec![None, Some(stored_lines[1].as_str()), Some(stored_lines[2].as_str()), None]);
        // A stored line served as it is reads back as the record it was read as.
        for (stored, line) in page.iter().zip(&stored_lines) {
            let value: Value = serde_json::from_str(line).unwrap();
            assert_eq!(record_from_value(&value), Some(stored.record.clone()));
        }
        assert_eq!(record_from_value(&serde_json::json!({"kind": "user_message"})), None);
        // The weave behaves as if neither were there.
        let without: Vec<Record> = records.iter().filter(|r| r.event != Event::Unknown).cloned().collect();
        assert_eq!(without.len(), 2);
        assert_eq!(crate::weave::weave(&records), crate::weave::weave(&without));
    }

    /// A chain-correct line built by hand: `body` is the JSON after `prev`, e.g. `"kind":"user_message",...`.
    fn hand_line(seq: u64, prev: &str, body: &str) -> String {
        format!("{{\"seq\":{seq},\"ts_ms\":5,\"author\":\"harness\",\"prev\":\"{prev}\",{body}}}")
    }

    /// Lines for the bodies, chained, newline-terminated.
    fn hand_log(bodies: &[&str]) -> Vec<u8> {
        let mut out = String::new();
        let mut prev = ZERO_HASH.to_string();
        for (i, body) in bodies.iter().enumerate() {
            let line = hand_line(i as u64, &prev, body);
            prev = sha256_hex(line.as_bytes());
            out.push_str(&line);
            out.push('\n');
        }
        out.into_bytes()
    }

    const OK_MSG: &str = r#""kind":"user_message","text":"hi""#;
    const FUTURE_NOTE: &str = r#""kind":"harness_note","note":"from_a_newer_loom","text":"x""#;

    fn no_salvage_files(path: &Path) -> bool {
        let dir = path.parent().unwrap();
        std::fs::read_dir(dir).unwrap().all(|e| !e.unwrap().file_name().to_string_lossy().contains("damaged"))
    }

    #[test]
    fn unreadable_body_with_intact_chain_is_an_opaque_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        let bytes = hand_log(&[OK_MSG, OK_MSG, FUTURE_NOTE, OK_MSG, OK_MSG]);
        std::fs::write(&path, &bytes).unwrap();
        let report = read_records(&path).unwrap();
        assert!(report.damage.is_none());
        assert_eq!((report.records.len(), report.opaque), (5, 1));
        assert_eq!(report.records[2].event, Event::Unknown);
        assert_eq!(report.records[2].seq, 2);
        assert_eq!(report.records[4].event, Event::UserMessage { text: "hi".into() });
        // The weave behaves as if the record were not there.
        let without: Vec<Record> = report.records.iter().filter(|r| r.seq != 2).cloned().collect();
        assert_eq!(crate::weave::weave(&report.records), crate::weave::weave(&without));
        // Appending is refused with the newer-loom sentence and the file is untouched.
        let err = SessionLog::open(&path, Durability::Batch).unwrap_err();
        assert!(matches!(err, LogError::Newer(_)));
        assert!(err.to_string().contains("newer loom") && err.to_string().contains("upgrade"), "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert!(no_salvage_files(&path));
    }

    #[test]
    fn opaque_record_stands_unless_the_next_line_disowns_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        // As the last line, and in front of a torn line, nothing contradicts it: it stays opaque
        // and the file is left alone.
        let last = hand_log(&[OK_MSG, OK_MSG, FUTURE_NOTE]);
        let torn = [last.clone(), b"{\"seq\":3".to_vec()].concat();
        for bytes in [last.clone(), torn] {
            std::fs::write(&path, &bytes).unwrap();
            let report = read_records(&path).unwrap();
            assert_eq!((report.records.len(), report.opaque), (3, 1));
            assert_eq!(report.records[2].event, Event::Unknown);
            assert!(matches!(SessionLog::open(&path, Durability::Batch), Err(LogError::Newer(_))));
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
            assert!(no_salvage_files(&path));
        }
        // Opaque records in a row vouch for each other.
        std::fs::write(&path, hand_log(&[OK_MSG, FUTURE_NOTE, FUTURE_NOTE, OK_MSG])).unwrap();
        let report = read_records(&path).unwrap();
        assert!(report.damage.is_none());
        assert_eq!((report.records.len(), report.opaque), (4, 2));

        // In front of a line with the next seq that was chained to other bytes, the unreadable line
        // is where the damage starts, as it was before opaque records existed.
        let good = hand_log(&[OK_MSG, OK_MSG]);
        let stray = format!("{}\n", hand_line(3, &"f".repeat(64), OK_MSG)).into_bytes();
        let bytes = [last, stray].concat();
        std::fs::write(&path, &bytes).unwrap();
        let report = read_records(&path).unwrap();
        assert_eq!((report.records.len(), report.opaque), (2, 0));
        let d = report.damage.unwrap();
        assert!(d.detail.starts_with("line 3 is not a record"), "{}", d.detail);
        assert_eq!(d.bad_bytes, (bytes.len() - good.len()) as u64);
        // No reader serves the disowned line, wherever its page ends.
        assert_eq!(read_page(&path, None, 3).unwrap(), report.records);
        assert_eq!(PageReader::new(&path).read_page(None, 3).unwrap(), report.records);
        assert!(PageReader::new(&path).read_page(Some(1), 1).unwrap().is_empty());
        let (mut log, report) = SessionLog::open(&path, Durability::Batch).unwrap();
        assert_eq!((report.records.len(), log.next_seq()), (2, 2));
        assert_eq!(std::fs::read(&path).unwrap(), good);
        assert_eq!(std::fs::read(report.damage.unwrap().moved_to.unwrap()).unwrap(), bytes[good.len()..].to_vec());
        log.append(Author::User, msg(2)).unwrap();
        assert!(read_records(&path).unwrap().damage.is_none());
    }

    #[test]
    fn a_record_too_deep_to_read_back_is_damage_not_a_newer_record() {
        use crate::event::{ToolCall, ToolClass};
        use crate::ids::CallId;
        let dir = tempfile::tempdir().unwrap();
        let (path, mut log) = new_log(&dir);
        fill(&mut log, 2);
        // serde_json writes any depth and reads 127 levels; inside the record these arguments are
        // one level too deep, so this build cannot read its own line back.
        let mut args = Value::Null;
        for _ in 0..127 {
            args = Value::Array(vec![args]);
        }
        let call = ToolCall { call_id: CallId::from("c1"), req_id: "r1".into(), name: "t".into(), args, class: ToolClass::Exec };
        log.append(Author::Model, Event::ToolCall(call)).unwrap();
        fill(&mut log, 1);
        drop(log);
        let seen = read_records(&path).unwrap();
        assert_eq!((seen.records.len(), seen.opaque), (2, 0));
        let (log, report) = SessionLog::open(&path, Durability::Batch).unwrap();
        let d = report.damage.unwrap();
        assert!(d.detail.starts_with("line 3 is not a record"), "{}", d.detail);
        assert_eq!((report.records.len(), log.next_seq()), (2, 2));
        assert!(read_records(&path).unwrap().damage.is_none());
    }

    #[test]
    fn unknown_variant_in_session_start_does_not_truncate() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        let start = r#""kind":"session_start","session":"s-1","mission":"m-1","workspace":"/w","pack":"p","role":"r","termination":"quantum","model":{"profile":"p","model":"m","context_window":1},"system_prompt":"s","tools":[]"#;
        let bytes = hand_log(&[start, OK_MSG]);
        std::fs::write(&path, &bytes).unwrap();
        let report = read_records(&path).unwrap();
        assert!(report.damage.is_none());
        assert_eq!((report.records.len(), report.opaque), (2, 1));
        assert!(matches!(SessionLog::open(&path, Durability::Batch), Err(LogError::Newer(_))));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert!(no_salvage_files(&path));
    }

    fn start_event(schema: u32) -> Event {
        use crate::event::{Budget, ModelRef, ReasoningReplay, SessionStart, Termination};
        use crate::ids::{MissionId, SessionId};
        Event::SessionStart(SessionStart {
            session: SessionId::from("s-1"),
            mission: MissionId::from("m-1"),
            parent: None,
            workspace: "/w".into(),
            pack: "p".into(),
            role: "r".into(),
            termination: Termination::Free,
            model: ModelRef { profile: "p".into(), model: "m".into(), context_window: 1 },
            reasoning_replay: ReasoningReplay::All,
            system_prompt: "s".into(),
            tools: vec![],
            budget: Budget::default(),
            unattended: false,
            title: String::new(),
            schema,
        })
    }

    #[test]
    fn higher_schema_refuses_append_but_reads() {
        let dir = tempfile::tempdir().unwrap();
        let (path, mut log) = new_log(&dir);
        log.append(Author::Harness, start_event(SCHEMA + 1)).unwrap();
        log.append(Author::User, msg(1)).unwrap();
        drop(log);
        let bytes = std::fs::read(&path).unwrap();
        let report = read_records(&path).unwrap();
        assert!(report.damage.is_none());
        assert_eq!((report.records.len(), report.opaque), (2, 0));
        assert!(matches!(SessionLog::open(&path, Durability::Batch), Err(LogError::Newer(_))));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        // The current schema opens, and the number is written.
        let dir2 = tempfile::tempdir().unwrap();
        let (path2, mut log2) = new_log(&dir2);
        log2.append(Author::Harness, start_event(SCHEMA)).unwrap();
        drop(log2);
        assert!(std::fs::read_to_string(&path2).unwrap().contains("\"schema\":1"));
        assert!(SessionLog::open(&path2, Durability::Batch).is_ok());
    }

    #[test]
    fn log_written_by_the_base_version_opens_and_real_damage_is_still_salvaged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        // session_start as the base build wrote it: no schema field.
        let start = r##""kind":"session_start","session":"s-1","mission":"m-1","parent":null,"workspace":"/w","pack":"p","role":"r","termination":"free","model":{"profile":"p","model":"m","context_window":1},"reasoning_replay":"all","system_prompt":"s","tools":[],"budget":{"max_steps":null,"max_minutes":null},"unattended":false,"title":"""##;
        let good = hand_log(&[start, OK_MSG]);
        std::fs::write(&path, &good).unwrap();
        let (mut log, report) = SessionLog::open(&path, Durability::Batch).unwrap();
        assert!(report.damage.is_none());
        assert_eq!(report.opaque, 0);
        let Event::SessionStart(s) = &report.records[0].event else { panic!("not a session start") };
        assert_eq!(s.schema, 1);
        log.append(Author::User, msg(2)).unwrap();
        drop(log);

        // Real damage: not JSON, JSON without seq/prev, a JSON array, a broken chain, a torn tail.
        let mut chain_break = good.clone();
        chain_break.extend_from_slice(hand_line(2, &"f".repeat(64), OK_MSG).as_bytes());
        chain_break.push(b'\n');
        // Damage in a line whose seq and prev are right: an invalid UTF-8 byte inside a string (as
        // the last line, and in front of a line chained to the intact bytes), nesting deeper than
        // serde_json reads, and a mangled key in front of a line chained to the intact bytes.
        let tip = sha256_hex(good.strip_suffix(b"\n").unwrap().rsplit(|b| *b == b'\n').next().unwrap());
        let intact = hand_line(2, &tip, OK_MSG);
        let next = format!("{}\n", hand_line(3, &sha256_hex(intact.as_bytes()), OK_MSG)).into_bytes();
        let mut bad_utf8 = format!("{intact}\n").into_bytes();
        bad_utf8[intact.find("\"hi\"").unwrap() + 1] = 0xff;
        let mangled = format!("{}\n", intact.replace("\"text\"", "\"texu\"")).into_bytes();
        let nested = format!("{OK_MSG},\"x\":{}{}", "[".repeat(200), "]".repeat(200));
        let deep = format!("{}\n", hand_line(2, &tip, &nested)).into_bytes();
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("is not a record", [good.clone(), b"this is not json\n".to_vec()].concat()),
            ("is not a record", [good.clone(), b"{\"x\":1}\n".to_vec()].concat()),
            ("is not a record", [good.clone(), b"[2,\"abc\"]\n".to_vec()].concat()),
            ("breaks the chain", chain_break),
            ("torn final line", [good.clone(), b"{\"seq\":2".to_vec()].concat()),
            ("line 3 is not a record", [good.clone(), bad_utf8.clone()].concat()),
            ("line 3 is not a record", [good.clone(), bad_utf8, next.clone()].concat()),
            ("line 3 is not a record", [good.clone(), deep].concat()),
            ("line 3 is not a record", [good.clone(), mangled, next].concat()),
        ];
        for (detail, bytes) in cases {
            std::fs::write(&path, &bytes).unwrap();
            // Every reader stops in front of the damaged line and none calls it a newer record.
            let seen = read_records(&path).unwrap();
            assert_eq!((seen.records.len(), seen.opaque), (2, 0), "{detail}");
            assert!(seen.damage.unwrap().detail.contains(detail));
            assert_eq!(read_page(&path, None, 100).unwrap(), seen.records);
            assert_eq!(PageReader::new(&path).read_page(None, 100).unwrap(), seen.records);
            assert!(PageReader::new(&path).read_page(Some(1), 1).unwrap().is_empty());
            let (log, report) = SessionLog::open(&path, Durability::Batch).unwrap();
            let d = report.damage.unwrap();
            assert!(d.detail.contains(detail), "{} / {detail}", d.detail);
            assert_eq!((report.records.len(), log.next_seq()), (2, 2));
            assert_eq!(std::fs::read(&path).unwrap(), good);
            assert!(d.moved_to.unwrap().exists());
        }
    }

    #[test]
    fn large_lines_are_fine() {
        let dir = tempfile::tempdir().unwrap();
        let (path, mut log) = new_log(&dir);
        let big = "x".repeat(3_000_000);
        log.append(Author::Tool, Event::UserMessage { text: big.clone() }).unwrap();
        log.append(Author::Tool, msg(1)).unwrap();
        let report = read_records(&path).unwrap();
        assert_eq!(report.records.len(), 2);
        assert_eq!(report.records[0].event, Event::UserMessage { text: big });
    }
}
