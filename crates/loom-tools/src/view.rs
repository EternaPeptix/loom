//! Numbered line views of stored output, shared by `read`, `out_read` and `out_grep`.
//!
//! CONTRACT (bodies are placeholders for the implementer; signatures and types are fixed).
//!
//! - [`store_text`]: normalise raw bytes (`loom_core::admit::normalize`) and store the normalised
//!   text. Line numbers everywhere refer to this stored text.
//! - [`window`]: which lines to show. `start` defaults to 1; `end` defaults to
//!   `start + max_lines - 1`; both are clamped to `1..=total`; a range longer than `max_lines` is
//!   shortened to `max_lines` from `start`. `start > total` (and total > 0) is an error sentence
//!   that states how many lines there are. `end < start` is an error sentence. Total 0 → `None`.
//! - [`numbered`]: the lines `first..=last` rendered as `{n}\t{line}` joined by `\n`, where a line
//!   longer than `max_line_chars` characters is shown as its first `max_line_chars` characters
//!   followed by `…[+{k} chars]`. Returns the text and how many lines were shortened.
//! - [`range_fact`]: `lines {first}-{last} of {total}` (or `line {n} of {total}`), followed by
//!   ` — {total-last} more below` when `last < total` and ` — {first-1} above` when `first > 1`.
//!
//! Tests required: defaults, clamping, the two errors, empty output, long-line shortening on
//! multi-byte text, the fact strings.

use loom_core::admit::Normalized;
use loom_core::{BlobId, BlobRef, BlobStore};
use std::io;

pub fn store_text(blobs: &BlobStore, raw: &[u8]) -> io::Result<(BlobRef, Normalized)> {
    let _ = (blobs, raw);
    todo!("implement per module contract")
}

pub fn window(start: Option<u64>, end: Option<u64>, total: u64, max_lines: u64) -> Result<Option<(u64, u64)>, String> {
    let _ = (start, end, total, max_lines);
    todo!("implement per module contract")
}

pub fn numbered(blobs: &BlobStore, id: &BlobId, first: u64, last: u64, max_line_chars: usize) -> io::Result<(String, u64)> {
    let _ = (blobs, id, first, last, max_line_chars);
    todo!("implement per module contract")
}

pub fn range_fact(first: u64, last: u64, total: u64) -> String {
    let _ = (first, last, total);
    todo!("implement per module contract")
}
