//! Derived facts about what a session has looked at. All functions are pure over log records.
//!
//! CONTRACT (bodies are placeholders for the implementer; signatures and types are fixed).
//!
//! ## Coverage
//! For every stored output, the set of its lines that some `tool` message in the given records put in
//! front of the model. Sources, per `tool_result` record:
//! - its own `output` blob with `meta[META_SHOWN]` ranges (admission wrote them); a result with an
//!   `output`, no `META_SHOWN` and `cut == false` counts as fully shown;
//! - a view of another blob: `meta[META_OF_BLOB]` (full id) with `meta[META_SHOWN]` ranges
//!   (`out_read`, `out_grep`).
//! Malformed meta is ignored. Ranges are merged; `total_lines` comes from the `BlobRef` when the
//! records contain one for that blob, else 0 (unknown).
//!
//! ## Unviewed output
//! `unviewed(records, min_lines)` lists `Exec` results whose own output has at least `min_lines`
//! lines never shown, newest first — the agent layer shows these in the HUD.
//!
//! ## Repetition
//! A repetition is the same tool name with the same canonical arguments (`serde_json` compact form of
//! `tool_call.args`) and the same output blob id, completed at least `min_count` times. Only calls of
//! class `Nav`, `Read` and `Exec` count.
//!
//! ## Staleness
//! Using `meta[META_PATH]` on results of class `Read` (a file was read) and `Write` (a file was
//! changed, status `Ok`):
//! - `StaleKind::ReadBeforeWrite`: a path whose latest read is older than its latest write;
//! - `StaleKind::ExecBeforeWrite`: the most recent `Exec` result with status `Ok` or `Error` is older
//!   than a later write (reported once, for the latest such `Exec`, naming the first write after it).
//! Records are compared by `seq`.
//!
//! ## Quote check
//! `quote_matches(haystack, quote)` — true when `quote` occurs in `haystack` after both are prepared
//! the same way: each line has trailing whitespace removed, and in `quote` only, a leading line-number
//! prefix as produced by the read tools (`^\s*\d+[:\-│|]\s?`) is removed from each line when removing
//! it from every line of the quote makes the match succeed. Leading/trailing blank lines of the quote
//! are ignored. An empty or whitespace-only quote never matches. No other leniency: case, inner
//! spacing and punctuation must be exact.
//! `nearest_line(haystack, quote)` returns the 1-based number and text of the haystack line sharing
//! the longest common prefix with the first non-blank quote line (for error messages), if any shares
//! at least 8 characters.
//!
//! Tests required: coverage from own output, from views, merged ranges, malformed meta; unviewed
//! ordering and threshold; repetition counting across different outputs; both staleness kinds and
//! their absence after a re-read / re-run; quote_matches positive, prefix-stripping, and negatives.

use crate::event::{Record, Seq};
use crate::ids::{BlobId, CallId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    /// 0 when unknown.
    pub total_lines: u64,
    /// Sorted, merged, 1-based inclusive.
    pub seen: Vec<(u64, u64)>,
}

impl Coverage {
    /// Add a range and keep `seen` sorted and merged. Ranges with `first > last` or `first == 0` are ignored.
    pub fn add(&mut self, first: u64, last: u64) {
        let _ = (first, last);
        todo!("implement per module contract")
    }

    /// True when every line in `first..=last` has been shown.
    pub fn covers(&self, first: u64, last: u64) -> bool {
        let _ = (first, last);
        todo!("implement per module contract")
    }

    pub fn seen_lines(&self) -> u64 {
        todo!("implement per module contract")
    }

    /// `total_lines - seen_lines`, or 0 when the total is unknown.
    pub fn unseen_lines(&self) -> u64 {
        todo!("implement per module contract")
    }

    /// The gaps within `1..=total_lines`.
    pub fn gaps(&self) -> Vec<(u64, u64)> {
        todo!("implement per module contract")
    }
}

/// Coverage of every stored output referenced by `records`, keyed by full blob id.
pub fn coverage(records: &[Record]) -> BTreeMap<BlobId, Coverage> {
    let _ = records;
    todo!("implement per module contract")
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unviewed {
    pub seq: Seq,
    pub call_id: CallId,
    pub tool: String,
    /// The handle (`out:…`).
    pub handle: String,
    pub total_lines: u64,
    pub unseen_lines: u64,
    pub gaps: Vec<(u64, u64)>,
}

pub fn unviewed(records: &[Record], min_lines: u64) -> Vec<Unviewed> {
    let _ = (records, min_lines);
    todo!("implement per module contract")
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Repetition {
    pub tool: String,
    /// Canonical arguments, cut to 200 characters.
    pub args: String,
    pub count: u32,
    pub last_seq: Seq,
}

pub fn repetitions(records: &[Record], min_count: u32) -> Vec<Repetition> {
    let _ = (records, min_count);
    todo!("implement per module contract")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StaleKind {
    ReadBeforeWrite,
    ExecBeforeWrite,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stale {
    pub kind: StaleKind,
    /// The read or run that is now out of date.
    pub seq: Seq,
    /// The later write.
    pub write_seq: Seq,
    /// The file (for `ReadBeforeWrite`: the file read; for `ExecBeforeWrite`: the file written).
    pub path: String,
}

pub fn stale(records: &[Record]) -> Vec<Stale> {
    let _ = records;
    todo!("implement per module contract")
}

pub fn quote_matches(haystack: &str, quote: &str) -> bool {
    let _ = (haystack, quote);
    todo!("implement per module contract")
}

pub fn nearest_line(haystack: &str, quote: &str) -> Option<(u64, String)> {
    let _ = (haystack, quote);
    todo!("implement per module contract")
}
