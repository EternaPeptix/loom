//! Admission: what the model is shown of a tool output.
//!
//! CONTRACT (bodies are placeholders for the implementer; signatures and types are fixed).
//!
//! The caller stores the complete output first (`BlobStore`), then calls [`admit`] to build the text
//! of the `tool` message. Nothing here discards anything; the stored output is always complete.
//!
//! ## `normalize(raw)`
//! Turns raw bytes into the text that is stored and shown. Every step keeps the number of `\n`
//! unchanged, so line numbers are the same before and after:
//! - invalid UTF-8 → U+FFFD (counted in `invalid_utf8`, one per replacement character);
//! - ANSI/VT escape sequences (CSI `ESC [ … final`, OSC `ESC ] … BEL|ESC \`, two-byte `ESC x`) removed
//!   (`ansi_removed` = number of sequences);
//! - within a line, text before the last `\r` that is not at the end of the line is removed, and a
//!   trailing `\r` is removed (`cr_collapsed` = number of lines changed by the first rule);
//! - remaining C0 control characters other than `\t` and `\n`, and DEL, are written as `\xNN`
//!   (`controls_escaped`).
//! - `binary` is true when the input contains a NUL byte or more than 30% of the first 8 KiB is
//!   neither printable ASCII, whitespace, nor part of valid UTF-8. For binary input `text` is a
//!   one-line description: `binary data, {n} bytes, starts with {first 32 bytes as hex}`.
//! `changed` is true when `text` differs from the input bytes.
//!
//! ## The envelope
//! `admit` returns `{header}\n{body}\n{footer}`:
//! - header: `[{tool} · {facts joined by " · "} · {lines} lines · {handle}]`; when the body is a cut the
//!   segment ` · CUT` follows the line count; when `normalized` notes exist they follow as
//!   ` · {notes}` (see `Normalized::notes`). With no facts the facts segment is omitted.
//! - body: see below. An output with zero bytes has the body `(no output)`.
//! - footer: `[end of {tool} output · {outcome}]` where `{outcome}` is `facts.outcome`.
//! `facts.outcome` is also the first fact in the header (the caller passes it separately so that it
//! appears both first and last).
//!
//! ## Body
//! Let `est` be the estimated tokens of the whole stored text.
//! - `est <= policy.max_inline_tokens`: the stored text, unmodified, without a trailing newline.
//!   `shown = [(1, lines)]` (empty for zero lines), `cut = false`.
//! - otherwise (`cut = true`): lines `1..=head_lines`, then the cut marker, then the last
//!   `tail_lines` lines. If `head_lines + tail_lines >= lines` the whole text would be shown, so the
//!   head and tail are both halved until the body fits `max_inline_tokens` (minimum 1 line each).
//!   In a cut body, a line longer than `max_line_chars` is shown as its first `max_line_chars`
//!   characters followed by `…[+{n} chars]` (`long_lines_cut` counts them). The marker is:
//!
//!   ```text
//!   [cut by harness: lines {a}-{b} of {total} are not shown here ({omitted_bytes} bytes). Nothing was discarded.
//!    Read them with out_read("{handle}", start, end) or search with out_grep("{handle}", pattern).]
//!   ```
//!
//!   followed, when the omitted region contains lines matching `policy.salient_patterns`, by:
//!
//!   ```text
//!   [pattern scan of the lines not shown — {k} of {m} matching lines, by line number; this is a text match, not a reading:]
//!   {line_no}: {line}
//!   …
//!   ```
//!
//!   with at most `policy.salient_max` lines, spread evenly over the matches when there are more
//!   (always including the first and the last match), each cut at `max_line_chars` like other lines.
//!   Lines listed by the scan count as shown: each adds `(n, n)` to `shown`.
//! - `shown` is sorted, merged, 1-based inclusive.
//! - Numbers in markers are plain digits (no thousands separators).
//!
//! `policy.salient_patterns` are regexes matched case-insensitively against single lines. An invalid
//! pattern is skipped (never an error). The defaults are in `AdmitPolicy::default`.
//!
//! Tests required: normalize (each rule, line-count preservation on random-ish inputs, binary); whole
//! admission is byte-identical to the stored text; envelope shape incl. empty output; cut boundaries
//! (exact line numbers in marker and `shown`); tiny head/tail when lines are huge; long-line cut;
//! scan lines present, capped, evenly spread, and included in `shown`; invalid pattern ignored;
//! multi-byte text never split inside a character.

use crate::blob::{BlobRef, BlobStore};
use crate::estimate::TokenEstimator;
use serde::{Deserialize, Serialize};
use std::io;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdmitPolicy {
    /// Outputs estimated at or below this many tokens are shown whole.
    pub max_inline_tokens: u64,
    pub head_lines: u64,
    pub tail_lines: u64,
    /// Longest line shown inside a cut body.
    pub max_line_chars: usize,
    /// Most lines listed by the pattern scan of the omitted region.
    pub salient_max: usize,
    pub salient_patterns: Vec<String>,
}

impl Default for AdmitPolicy {
    fn default() -> Self {
        Self {
            max_inline_tokens: 60_000,
            head_lines: 400,
            tail_lines: 400,
            max_line_chars: 4_000,
            salient_max: 40,
            salient_patterns: vec![
                r"\b(error|errors|failed|failure|fatal|panic|panicked|exception|traceback|denied|refused|forbidden|unauthorized|timed? ?out|segfault|abort(ed)?|cannot|unable to|not found|no such)\b".to_string(),
                r"\bwarn(ing)?\b".to_string(),
                r"^HTTP/\d(\.\d)? \d{3}\b".to_string(),
                r"\bexit(ed)? (code|status) [1-9]".to_string(),
            ],
        }
    }
}

/// Result of [`normalize`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Normalized {
    pub text: String,
    pub binary: bool,
    pub changed: bool,
    pub invalid_utf8: u64,
    pub ansi_removed: u64,
    pub cr_collapsed: u64,
    pub controls_escaped: u64,
}

impl Normalized {
    /// Header notes for the non-zero counts, joined by `, `:
    /// `{n} terminal escape sequences removed`, `{n} overwritten lines collapsed`,
    /// `{n} invalid bytes replaced`, `{n} control characters escaped`, `binary`. `None` when clean.
    pub fn notes(&self) -> Option<String> {
        todo!("implement per module contract")
    }
}

/// See the module contract.
pub fn normalize(raw: &[u8]) -> Normalized {
    let _ = raw;
    todo!("implement per module contract")
}

/// Facts for the envelope, supplied by whoever ran the tool.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Facts {
    /// Tool name.
    pub tool: String,
    /// The outcome in a few words: `exit 0`, `exit 1`, `killed by signal 9`, `ok`, `error`,
    /// `timed out after 300s — continues as job j3`, `denied`. Shown first in the header and in the footer.
    pub outcome: String,
    /// Further header facts in order, e.g. `3.4s`, `lines 1-200 of 950`, a path.
    pub more: Vec<String>,
    /// From [`Normalized::notes`], when normalisation changed the output.
    pub notes: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admitted {
    /// The complete text of the `tool` message.
    pub text: String,
    pub cut: bool,
    /// Line ranges of the stored output present in `text` (1-based, inclusive, sorted, merged).
    pub shown: Vec<(u64, u64)>,
    pub long_lines_cut: u64,
    /// Lines listed by the pattern scan, and how many lines matched in total.
    pub scan_listed: u64,
    pub scan_matched: u64,
}

/// Build the tool message text for the stored output `blob`. See the module contract.
pub fn admit(
    store: &BlobStore,
    blob: &BlobRef,
    facts: &Facts,
    policy: &AdmitPolicy,
    estimator: &TokenEstimator,
) -> io::Result<Admitted> {
    let _ = (store, blob, facts, policy, estimator);
    todo!("implement per module contract")
}

/// Envelope for a result that has no stored output (validation failures, denials, runtime-owned
/// tools): `[{tool} · {outcome}{ · more…}]\n{body}\n[end of {tool} output · {outcome}]`.
pub fn envelope_plain(facts: &Facts, body: &str) -> String {
    let _ = (facts, body);
    todo!("implement per module contract")
}
