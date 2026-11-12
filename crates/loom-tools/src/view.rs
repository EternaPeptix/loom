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
//!   followed by `…[+{k} chars]`. Returns the text and how many lines were shortened.
//! - [`range_fact`]: `lines {first}-{last} of {total}` (or `line {n} of {total}`), followed by
//!   ` — {total-last} more below` when `last < total` and ` — {first-1} above` when `first > 1`.
//!
//! Tests required: defaults, clamping, the two errors, empty output, long-line shortening on
//! multi-byte text, the fact strings.

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

/// Lines `first..=last` of a stored output as `{n}\t{line}`, long lines shortened.
pub fn numbered(
    blobs: &BlobStore,
    id: &BlobId,
    first: u64,
    last: u64,
    max_line_chars: usize,
) -> io::Result<(String, u64)> {
    let slice = blobs.read_lines(id, first, last)?;
    if slice.text.is_empty() {
        return Ok((String::new(), 0));
    }
    let body = slice.text.strip_suffix('\n').unwrap_or(&slice.text);
    let mut out = String::with_capacity(body.len() + 8);
    let mut shortened = 0u64;
    let mut n = slice.first;
    for (i, line) in body.split('\n').enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&n.to_string());
        out.push('\t');
        match line.char_indices().nth(max_line_chars) {
            Some((cut, _)) => {
                let (head, rest) = line.split_at(cut);
                out.push_str(head);
                out.push_str(&format!("…[+{} chars]", rest.chars().count()));
                shortened += 1;
            }
            None => out.push_str(line),
        }
        n = n.saturating_add(1);
    }
    Ok((out, shortened))
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
        let (text, short) = numbered(&blobs, &stored.id, 1, 3, 100).unwrap();
        assert_eq!(text, "1\ta\n2\tbred\n3\tc");
        assert_eq!(short, 0);
        let (mid, _) = numbered(&blobs, &stored.id, 2, 2, 100).unwrap();
        assert_eq!(mid, "2\tbred");
    }

    #[test]
    fn numbered_handles_trailing_newline_and_blank_lines() {
        let (_d, blobs) = store();
        let (stored, _) = store_text(&blobs, b"a\n\nb\n").unwrap();
        assert_eq!(stored.lines, 3);
        let (text, _) = numbered(&blobs, &stored.id, 1, 3, 10).unwrap();
        assert_eq!(text, "1\ta\n2\t\n3\tb");
    }

    #[test]
    fn numbered_empty_output() {
        let (_d, blobs) = store();
        let (stored, _) = store_text(&blobs, b"").unwrap();
        assert_eq!(numbered(&blobs, &stored.id, 1, 10, 10).unwrap(), (String::new(), 0));
    }

    #[test]
    fn long_lines_are_shortened_on_characters() {
        let (_d, blobs) = store();
        let long = "héllo wörld ✓✓✓✓";
        let raw = format!("short\n{long}\n");
        let (stored, _) = store_text(&blobs, raw.as_bytes()).unwrap();
        let (text, short) = numbered(&blobs, &stored.id, 1, 2, 7).unwrap();
        assert_eq!(short, 1);
        assert_eq!(text, "1\tshort\n2\théllo w…[+9 chars]");
        let (exact, short) = numbered(&blobs, &stored.id, 2, 2, long.chars().count()).unwrap();
        assert_eq!((exact.as_str(), short), ("2\théllo wörld ✓✓✓✓", 0));
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
