//! Numbered line views of stored output, shared by `read`, `out_read` and `out_grep`.
//!
//! CONTRACT.
//!
//! - [`store_text`]: normalise raw bytes (`loom_core::admit::normalize`) and store the normalised
//!   text. Line numbers everywhere refer to this stored text.
//! - [`window`]: which lines to show. `start` defaults to 1; `end` defaults to
//!   `start + max_lines - 1`; both are clamped to `1..=total`; a range longer than `max_lines` is
//!   shortened to `max_lines` from `start`. `start > total` (and total > 0) is an error sentence
//!   that states how many lines there are. `end < start` is an error sentence. Total 0 → `None`.
//! - [`numbered`]: the lines `first..=last` rendered as `{n}\t{line}` joined by `\n`, where a line
//!   longer than `max_line_chars` characters is shown as its first `max_line_chars` characters
//!   followed by `…[+{k} chars]`, and no more lines than fit in `max_chars` characters: lines are
//!   added in order while the text, joining `\n`s included, stays within `max_chars`; the line that
//!   would pass it and every later one are left out, so the text always ends at a whole line. The first
//!   line is always included: when it alone would pass `max_chars`, it is shortened (as a long line is)
//!   to the most characters that keep `{n}\t{head}…[+{k} chars]` within `max_chars`, and never below
//!   one character of the line. Returns a [`Numbered`]: the text, how many lines were shortened, and
//!   `last`, the number of the last line included (`last` as asked when everything fit).
//! - [`ended_fact`]`(last)`: `window ended at line {last} to stay within the size one result may
//!   show; continue with start {last+1}` — the fact a caller adds when `Numbered::last` is below the
//!   last line it asked for, with `range_fact(first, Numbered::last, total)` as its range.
//! - [`range_fact`]: `lines {first}-{last} of {total}` (or `line {n} of {total}`), followed by
//!   ` — {total-last} more below` when `last < total` and ` — {first-1} above` when `first > 1`.
//!
//! Tests required: defaults, clamping, the two errors, empty output, long-line shortening on
//! multi-byte text, the fact strings; `max_chars` stops at a whole line and reports the last line
//! included, the text length never passes `max_chars` (multi-byte text), a first line longer than
//! `max_chars` is shortened to fit, and paging with `start = last + 1` covers every line once.

use loom_core::admit::{normalize, Normalized};
use loom_core::{BlobId, BlobRef, BlobStore};
use std::io;

/// Normalise `raw` and store the normalised text; its line numbers are the ones every view uses.
pub fn store_text(blobs: &BlobStore, raw: &[u8]) -> io::Result<(BlobRef, Normalized)> {
    let normalized = normalize(raw);
    let stored = blobs.put_bytes(normalized.text.as_bytes())?;
    Ok((stored, normalized))
}

/// Choose the lines to show, or `None` when the output is empty.
pub fn window(start: Option<u64>, end: Option<u64>, total: u64, max_lines: u64) -> Result<Option<(u64, u64)>, String> {
    if total == 0 {
        return Ok(None);
    }
    let max_lines = max_lines.max(1);
    let first = start.unwrap_or(1).max(1);
    if first > total {
        return Err(format!(
            "start line {first} is past the end: this output has {total} lines. Ask for a start between 1 and {total}."
        ));
    }
    let longest = first.saturating_add(max_lines - 1);
    let wanted = match end {
        Some(e) if e < first => {
            return Err(format!(
                "end line {e} is before start line {first}. Give an end that is {first} or more, or leave `end` out to get up to {max_lines} lines from line {first}."
            ));
        }
        Some(e) => e,
        None => longest,
    };
    let last = wanted.min(total).min(longest);
    Ok(Some((first, last)))
}

/// What [`numbered`] rendered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Numbered {
    /// The lines as `{n}\t{line}` joined by `\n`; never longer than the `max_chars` asked for (unless one
    /// character of the first line plus its number does not fit).
    pub text: String,
    /// How many of the lines shown were shortened.
    pub shortened: u64,
    /// The number of the last line included.
    pub last: u64,
}

/// `line` as at most `keep` of its `total` characters, followed by `…[+{k} chars]` when it was cut.
fn render_line(line: &str, total: usize, keep: usize) -> String {
    match line.char_indices().nth(keep) {
        Some((cut, _)) => {
            let (head, _) = line.split_at(cut);
            format!("{head}…[+{} chars]", total.saturating_sub(keep))
        }
        None => line.to_string(),
    }
}

/// Lines `first..=last` of a stored output as `{n}\t{line}`, long lines shortened, and no more lines than
/// fit in `max_chars` characters. The text ends at a whole line; the first line is always included,
/// shortened to fit when it alone would pass `max_chars`.
pub fn numbered(
    blobs: &BlobStore,
    id: &BlobId,
    first: u64,
    last: u64,
    max_line_chars: usize,
    max_chars: usize,
) -> io::Result<Numbered> {
    let slice = blobs.read_lines(id, first, last)?;
    if slice.text.is_empty() {
        return Ok(Numbered { text: String::new(), shortened: 0, last });
    }
    let body = slice.text.strip_suffix('\n').unwrap_or(&slice.text);
    let mut out = String::with_capacity(body.len().min(max_chars).saturating_add(8));
    let mut used = 0usize;
    let mut shortened = 0u64;
    let mut n = slice.first;
    let mut last_in = slice.first.saturating_sub(1);
    for (i, line) in body.split('\n').enumerate() {
        let prefix = format!("{n}\t");
        let prefix_chars = prefix.chars().count();
        let total = line.chars().count();
        let mut keep = total.min(max_line_chars);
        let sep = usize::from(i > 0);
        let rendered_len = |keep: usize| {
            let tail = if keep < total { 10usize.saturating_add(digits(total - keep)) } else { 0 };
            used.saturating_add(sep).saturating_add(prefix_chars).saturating_add(keep).saturating_add(tail)
        };
        if rendered_len(keep) > max_chars {
            if i > 0 {
                break;
            }
            // The first line alone passes the budget: keep as many of its characters as fit, at least one.
            let mut k = keep;
            while k > 1 && rendered_len(k) > max_chars {
                let over = rendered_len(k) - max_chars;
                k = if k > over { k - over } else { 1 };
            }
            keep = k.max(1).min(keep);
        }
        let new_used = rendered_len(keep);
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&prefix);
        out.push_str(&render_line(line, total, keep));
        if keep < total {
            shortened += 1;
        }
        used = new_used;
        last_in = n;
        n = n.saturating_add(1);
    }
    Ok(Numbered { text: out, shortened, last: last_in })
}

fn digits(n: usize) -> usize {
    n.to_string().len()
}

/// The fact that says a window ended early for size: `window ended at line {last} to stay within the
/// size one result may show; continue with start {last+1}`.
pub fn ended_fact(last: u64) -> String {
    format!(
        "window ended at line {last} to stay within the size one result may show; continue with start {}",
        last.saturating_add(1)
    )
}

/// `lines 3-9 of 40 — 31 more below — 2 above`.
pub fn range_fact(first: u64, last: u64, total: u64) -> String {
    let mut s =
        if first == last { format!("line {first} of {total}") } else { format!("lines {first}-{last} of {total}") };
    if last < total {
        s.push_str(&format!(" — {} more below", total - last));
    }
    if first > 1 {
        s.push_str(&format!(" — {} above", first - 1));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const BIG: usize = 1_000_000;

    fn store() -> (tempfile::TempDir, BlobStore) {
        let dir = tempfile::tempdir().unwrap();
        let blobs = BlobStore::open(dir.path().join("blobs")).unwrap();
        (dir, blobs)
    }

    #[test]
    fn window_defaults_and_clamping() {
        assert_eq!(window(None, None, 100, 10), Ok(Some((1, 10))));
        assert_eq!(window(None, None, 5, 10), Ok(Some((1, 5))));
        assert_eq!(window(Some(20), None, 100, 10), Ok(Some((20, 29))));
        assert_eq!(window(Some(95), None, 100, 10), Ok(Some((95, 100))));
        assert_eq!(window(Some(3), Some(5), 100, 10), Ok(Some((3, 5))));
        assert_eq!(window(Some(3), Some(500), 100, 10), Ok(Some((3, 12))));
        assert_eq!(window(Some(90), Some(500), 100, 50), Ok(Some((90, 100))));
        assert_eq!(window(Some(0), Some(2), 100, 10), Ok(Some((1, 2))));
        assert_eq!(window(Some(7), Some(7), 100, 10), Ok(Some((7, 7))));
        assert_eq!(window(Some(1), Some(100), 100, 0), Ok(Some((1, 1))));
    }

    #[test]
    fn window_errors_and_empty() {
        let e = window(Some(200), None, 100, 10).unwrap_err();
        assert!(e.contains("100 lines"), "{e}");
        let e = window(Some(10), Some(5), 100, 10).unwrap_err();
        assert!(e.contains("end line 5") && e.contains("start line 10"), "{e}");
        assert_eq!(window(None, None, 0, 10), Ok(None));
        assert_eq!(window(Some(5), Some(2), 0, 10), Ok(None));
    }

    #[test]
    fn store_text_normalises_and_numbers() {
        let (_d, blobs) = store();
        let (stored, norm) = store_text(&blobs, b"a\r\nb\x1b[31mred\x1b[0m\nc").unwrap();
        assert!(norm.changed);
        assert_eq!(stored.lines, 3);
        let n = numbered(&blobs, &stored.id, 1, 3, 100, BIG).unwrap();
        assert_eq!(n.text, "1\ta\n2\tbred\n3\tc");
        assert_eq!((n.shortened, n.last), (0, 3));
        let mid = numbered(&blobs, &stored.id, 2, 2, 100, BIG).unwrap();
        assert_eq!(mid.text, "2\tbred");
    }

    #[test]
    fn numbered_handles_trailing_newline_and_blank_lines() {
        let (_d, blobs) = store();
        let (stored, _) = store_text(&blobs, b"a\n\nb\n").unwrap();
        assert_eq!(stored.lines, 3);
        let n = numbered(&blobs, &stored.id, 1, 3, 10, BIG).unwrap();
        assert_eq!(n.text, "1\ta\n2\t\n3\tb");
    }

    #[test]
    fn numbered_empty_output() {
        let (_d, blobs) = store();
        let (stored, _) = store_text(&blobs, b"").unwrap();
        let n = numbered(&blobs, &stored.id, 1, 10, 10, BIG).unwrap();
        assert_eq!((n.text.as_str(), n.shortened), ("", 0));
    }

    #[test]
    fn long_lines_are_shortened_on_characters() {
        let (_d, blobs) = store();
        let long = "héllo wörld ✓✓✓✓";
        let raw = format!("short\n{long}\n");
        let (stored, _) = store_text(&blobs, raw.as_bytes()).unwrap();
        let n = numbered(&blobs, &stored.id, 1, 2, 7, BIG).unwrap();
        assert_eq!(n.shortened, 1);
        assert_eq!(n.text, "1\tshort\n2\théllo w…[+9 chars]");
        let exact = numbered(&blobs, &stored.id, 2, 2, long.chars().count(), BIG).unwrap();
        assert_eq!((exact.text.as_str(), exact.shortened), ("2\théllo wörld ✓✓✓✓", 0));
    }

    #[test]
    fn max_chars_stops_at_a_whole_line() {
        let (_d, blobs) = store();
        let raw: String = (1..=10).map(|i| format!("line number {i}\n")).collect();
        let (stored, _) = store_text(&blobs, raw.as_bytes()).unwrap();
        let all = numbered(&blobs, &stored.id, 1, 10, 100, BIG).unwrap();
        assert_eq!(all.last, 10);
        // Room for exactly three lines, joining newlines included.
        let three = "1\tline number 1\n2\tline number 2\n3\tline number 3";
        let n = numbered(&blobs, &stored.id, 1, 10, 100, three.chars().count()).unwrap();
        assert_eq!((n.text.as_str(), n.last, n.shortened), (three, 3, 0));
        // One character less drops the third line whole.
        let n = numbered(&blobs, &stored.id, 1, 10, 100, three.chars().count() - 1).unwrap();
        assert_eq!((n.text.as_str(), n.last), ("1\tline number 1\n2\tline number 2", 2));
    }

    #[test]
    fn text_never_passes_max_chars_on_multibyte_text() {
        let (_d, blobs) = store();
        let raw: String = (1..=30).map(|i| format!("日本語✓{i}{}\n", "é".repeat(i))).collect();
        let (stored, _) = store_text(&blobs, raw.as_bytes()).unwrap();
        for max in [40usize, 57, 100, 333] {
            let n = numbered(&blobs, &stored.id, 1, 30, 20, max).unwrap();
            assert!(n.text.chars().count() <= max, "{max}: {}", n.text.chars().count());
            assert!(n.last >= 1 && n.text.lines().count() as u64 == n.last);
        }
    }

    #[test]
    fn a_first_line_longer_than_max_chars_is_shortened_to_fit() {
        let (_d, blobs) = store();
        let raw = format!("{}\nsecond\n", "x".repeat(5000));
        let (stored, _) = store_text(&blobs, raw.as_bytes()).unwrap();
        let n = numbered(&blobs, &stored.id, 1, 2, 20_000, 100).unwrap();
        assert_eq!((n.last, n.shortened), (1, 1));
        assert!(n.text.starts_with("1\txxx") && n.text.contains("…[+"), "{}", n.text);
        assert!(n.text.chars().count() <= 100 && n.text.chars().count() >= 90, "{}", n.text.chars().count());
        // A budget too small for anything keeps one character of the line.
        let tiny = numbered(&blobs, &stored.id, 1, 2, 20_000, 5).unwrap();
        assert_eq!(tiny.last, 1);
        assert!(tiny.text.starts_with("1\tx…[+4999 chars]"), "{}", tiny.text);
    }

    #[test]
    fn paging_from_last_plus_one_covers_every_line_once() {
        let (_d, blobs) = store();
        let raw: String = (1..=50).map(|i| format!("row {i} {}\n", "z".repeat(i % 7 * 5))).collect();
        let (stored, _) = store_text(&blobs, raw.as_bytes()).unwrap();
        let mut start = 1u64;
        let mut seen = Vec::new();
        while start <= 50 {
            let n = numbered(&blobs, &stored.id, start, 50, 100, 120).unwrap();
            assert!(n.last >= start);
            seen.extend(start..=n.last);
            start = n.last + 1;
        }
        assert_eq!(seen, (1..=50).collect::<Vec<u64>>());
    }

    #[test]
    fn ended_fact_says_where_to_continue() {
        let f = ended_fact(12);
        assert!(f.starts_with("window ended at line 12 to stay within the size one result may show"), "{f}");
        assert!(f.ends_with("continue with start 13"), "{f}");
    }

    #[test]
    fn range_facts() {
        assert_eq!(range_fact(1, 10, 10), "lines 1-10 of 10");
        assert_eq!(range_fact(1, 10, 40), "lines 1-10 of 40 — 30 more below");
        assert_eq!(range_fact(5, 10, 10), "lines 5-10 of 10 — 4 above");
        assert_eq!(range_fact(5, 10, 40), "lines 5-10 of 40 — 30 more below — 4 above");
        assert_eq!(range_fact(7, 7, 7), "line 7 of 7 — 6 above");
        assert_eq!(range_fact(1, 1, 1), "line 1 of 1");
    }
}
