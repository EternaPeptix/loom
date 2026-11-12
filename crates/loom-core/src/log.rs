//! Append-only, hash-chained session log (one [`Record`] per line of `log.jsonl`).
//!
//! CONTRACT (the bodies below are placeholders for the implementer; signatures are fixed):
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
//!   `open` then refuses to append (`LogError::Newer`) without touching the file, and so does a log
//!   whose `session_start` carries a schema above `event::SCHEMA`; reading such a log works. If anything follows the good prefix, those bytes are moved to
//!   `<path>.damaged-<now_ms>` and the log file is truncated to the good prefix; `OpenReport::damage`
//!   says what happened. A torn final line alone (crash mid-append) is the same case.
//! - `read_records` is the read-only variant: same stopping rule, no file is modified.
//! - `fork_to` creates a new log whose first `upto_seq + 1` lines are byte-identical to this log's, and
//!   returns it ready to append (`next_seq == upto_seq + 1`, chain continuing from the copied line).
//! - Lines can be large (a tool result is stored inline). There is no line-length limit.
//!
//! Tests required: round trip; chain values; torn tail; corrupted middle line (salvage file exists,
//! log truncated, appends continue); wrong seq; reopen-and-append; fork is byte-identical and chains;
//! `read_page` paging; `create` refuses an existing file; `Unknown` events survive rewrite-free.

use crate::event::{Author, Event, Record, Seq, SCHEMA};
use crate::{now_ms, sha256_hex};
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
    #[error("cannot encode record: {0}")]
    Encode(#[from] serde_json::Error),
    #[error("fork point {upto} is beyond the last record {last}")]
    ForkPoint { upto: Seq, last: Seq },
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

fn io_err(path: &Path) -> impl FnOnce(std::io::Error) -> LogError + '_ {
    move |source| LogError::Io { path: path.to_path_buf(), source }
}

/// Outcome of reading one line.
enum Step {
    Record(Box<Record>),
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
}

/// The part of a line every build can read: enough to place it in the chain.
#[derive(serde::Deserialize)]
struct Header {
    seq: Seq,
    prev: String,
    #[serde(default)]
    ts_ms: Option<Value>,
    #[serde(default)]
    author: Option<Value>,
    #[serde(default)]
    kind: Option<Value>,
    #[serde(default)]
    schema: Option<Value>,
}

/// Read a line this build cannot fully deserialize as an opaque record, plus the schema it declares.
fn opaque_record(line: &[u8]) -> Option<(Record, u32)> {
    if line.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
        return None;
    }
    let h: Header = serde_json::from_slice(line).ok()?;
    let author = h.author.and_then(|v| serde_json::from_value::<Author>(v).ok()).unwrap_or(Author::Harness);
    let is_start = h.kind.as_ref().and_then(Value::as_str) == Some("session_start");
    let schema = match (is_start, h.schema.as_ref().and_then(Value::as_u64)) {
        (true, Some(n)) => u32::try_from(n).unwrap_or(u32::MAX),
        _ => 1,
    };
    let ts_ms = h.ts_ms.as_ref().and_then(Value::as_u64).unwrap_or(0);
    Some((Record { seq: h.seq, ts_ms, author, prev: h.prev, event: Event::Unknown }, schema))
}

impl<R: BufRead> Scanner<R> {
    fn new(reader: R) -> Self {
        Scanner { reader, buf: Vec::new(), next_seq: 0, last_hash: ZERO_HASH.to_string(), good_len: 0, opaque: 0, schema: 1 }
    }

    fn step(&mut self) -> std::io::Result<Step> {
        self.buf.clear();
        if self.reader.read_until(b'\n', &mut self.buf)? == 0 {
            return Ok(Step::End);
        }
        let Some((&b'\n', line)) = self.buf.split_last() else {
            return Ok(Step::Bad("torn final line".to_string()));
        };
        let total = self.buf.len() as u64;
        let line_no = self.next_seq.saturating_add(1);
        let (record, is_opaque, schema) = match serde_json::from_slice::<Record>(line) {
            Ok(r) => {
                let schema = if let Event::SessionStart(s) = &r.event { s.schema } else { 1 };
                (r, false, schema)
            }
            Err(e) => match opaque_record(line) {
                Some((r, schema)) => (r, true, schema),
                None => return Ok(Step::Bad(format!("line {line_no} is not a record: {e}"))),
            },
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
        self.last_hash = sha256_hex(line);
        self.next_seq = self.next_seq.saturating_add(1);
        self.good_len = self.good_len.saturating_add(total);
        self.opaque = self.opaque.saturating_add(u64::from(is_opaque));
        self.schema = self.schema.max(schema);
        Ok(Step::Record(Box::new(record)))
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
            Step::Record(r) => records.push(*r),
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
        let (scanner, records, cause) = scan_file(path)?;
        if scanner.opaque > 0 || scanner.schema > SCHEMA {
            return Err(LogError::Newer(path.to_path_buf()));
        }
        let file_len = std::fs::metadata(path).map_err(io_err(path))?.len();
        let good_len = scanner.good_len;
        let file = OpenOptions::new().append(true).open(path).map_err(io_err(path))?;
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
        fork_file(&self.path, dest, upto_seq, durability)
    }

    /// Copy the first `upto_seq + 1` stored lines of the log at `src_path` into `child` and set its
    /// chain state.
    fn copy_prefix(src_path: &Path, child: &mut SessionLog, upto_seq: Seq) -> Result<(), LogError> {
        let src = File::open(src_path).map_err(io_err(src_path))?;
        let mut reader = BufReader::new(src);
        let mut out = BufWriter::new(&child.file);
        let mut buf = Vec::new();
        let mut copied: u64 = 0;
        let mut last_hash = ZERO_HASH.to_string();
        let mut seq: Seq = 0;
        while seq <= upto_seq {
            buf.clear();
            let n = reader.read_until(b'\n', &mut buf).map_err(io_err(src_path))?;
            let Some((&b'\n', line)) = buf.split_last() else {
                return Err(io_err(src_path)(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!("log ends before record {seq}; reopen the session so the log is repaired, then fork again"),
                )));
            };
            out.write_all(&buf).map_err(io_err(&child.path))?;
            last_hash = sha256_hex(line);
            copied = copied.saturating_add(n as u64);
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
        Ok(())
    }
}

/// Fork the log file at `src` without holding it open for writing: copy records `0..=upto_seq`
/// byte for byte into a new log at `dest` and return that log open. `src` is only read, so this is
/// safe while another handle is appending to it (records up to `upto_seq` must already be complete).
pub fn fork_file(src: &Path, dest: &Path, upto_seq: Seq, durability: Durability) -> Result<SessionLog, LogError> {
    let mut child = SessionLog::create(dest, durability)?;
    match SessionLog::copy_prefix(src, &mut child, upto_seq) {
        Ok(()) => Ok(child),
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
        if r.seq >= first {
            page.push(*r);
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
/// was chain-verified. It starts over when the file got shorter or its last verified line changed.
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
    pub lines_hashed: u64,
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
        let mut page = Vec::new();
        let first = match after {
            None => 0,
            Some(a) => match a.checked_add(1) {
                Some(f) => f,
                None => return Ok(page),
            },
        };
        if limit == 0 {
            return Ok(page);
        }
        let path = self.path.clone();
        let mut file = File::open(&path).map_err(io_err(&path))?;
        if !self.prefix_holds(&mut file).map_err(io_err(&path))? {
            self.reset();
        }
        // Resume from the latest verified position at or before the first wanted record.
        let index = usize::try_from(first / CHECKPOINT_EVERY).unwrap_or(usize::MAX);
        let mut start = self.marks.get(index).or(self.marks.last()).cloned().unwrap_or_else(Mark::origin);
        for m in [&self.cursor, &self.end] {
            if m.seq <= first && m.seq > start.seq {
                start = m.clone();
            }
        }
        file.seek(SeekFrom::Start(start.offset)).map_err(io_err(&path))?;
        let mut scanner = Scanner::new(BufReader::new(file));
        scanner.next_seq = start.seq;
        scanner.last_hash = start.hash;
        scanner.good_len = start.offset;
        loop {
            let before = scanner.good_len;
            let Step::Record(r) = scanner.step().map_err(io_err(&path))? else { break };
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
            if r.seq >= first {
                page.push(*r);
                if page.len() >= limit {
                    break;
                }
            }
        }
        self.cursor = Mark { seq: scanner.next_seq, offset: scanner.good_len, hash: scanner.last_hash };
        Ok(page)
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
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("is not a record", [good.clone(), b"this is not json\n".to_vec()].concat()),
            ("is not a record", [good.clone(), b"{\"x\":1}\n".to_vec()].concat()),
            ("is not a record", [good.clone(), b"[2,\"abc\"]\n".to_vec()].concat()),
            ("breaks the chain", chain_break),
            ("torn final line", [good.clone(), b"{\"seq\":2".to_vec()].concat()),
        ];
        for (detail, bytes) in cases {
            std::fs::write(&path, &bytes).unwrap();
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
