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
use std::fs::File;
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
}

impl SessionLog {
    /// Create a new, empty log. Parent directories are created. Fails if the file exists.
    pub fn create(path: &Path, durability: Durability) -> Result<SessionLog, LogError> {
        let _ = (path, durability);
        todo!("implement per module contract")
    }

    /// Open an existing log for appending, salvaging damage as described in the module contract.
    pub fn open(path: &Path, durability: Durability) -> Result<(SessionLog, OpenReport), LogError> {
        let _ = (path, durability);
        todo!("implement per module contract")
    }

    /// Append one event and return the record as written.
    pub fn append(&mut self, author: Author, event: Event) -> Result<Record, LogError> {
        let _ = (author, event, &self.file, &self.last_hash, self.durability);
        todo!("implement per module contract")
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
        let _ = (dest, upto_seq, durability);
        todo!("implement per module contract")
    }
}

/// Read every readable record without modifying anything.
pub fn read_records(path: &Path) -> Result<OpenReport, LogError> {
    let _ = path;
    todo!("implement per module contract")
}

/// Read up to `limit` records with `seq > after` (`None` = from the start), as stored lines parsed
/// back into records. Used by the API for paging; stops silently at damage.
pub fn read_page(path: &Path, after: Option<Seq>, limit: usize) -> Result<Vec<Record>, LogError> {
    let _ = (path, after, limit);
    todo!("implement per module contract")
}
