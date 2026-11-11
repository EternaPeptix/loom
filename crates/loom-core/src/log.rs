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
//!   line that is incomplete (no trailing newline), does not parse as a `Record`, has the wrong `seq`,
//!   or has a `prev` that does not match. If anything follows the good prefix, those bytes are moved to
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

use crate::event::{Author, Event, Record, Seq};
use crate::{now_ms, sha256_hex};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
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
}

impl<R: BufRead> Scanner<R> {
    fn new(reader: R) -> Self {
        Scanner { reader, buf: Vec::new(), next_seq: 0, last_hash: ZERO_HASH.to_string(), good_len: 0 }
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
        let record: Record = match serde_json::from_slice(line) {
            Ok(r) => r,
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
        self.last_hash = sha256_hex(line);
        self.next_seq = self.next_seq.saturating_add(1);
        self.good_len = self.good_len.saturating_add(total);
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
        Ok((log, OpenReport { records, damage }))
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
    Ok(OpenReport { records, damage })
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
