//! The per-session egress audit file (`net.jsonl`) as a hash chain.
//!
//! Every line is one JSON object. Lines written by this module carry `prev`: the SHA-256 (hex) of the
//! previous line's bytes (without the newline), or 64 zeros for the first line of a file. Files whose
//! early lines have no `prev` (written before the chain existed) stay readable: the chain starts at
//! the first line that has the field, and that line must name the hash of the line before it.
//!
//! An append that fails leaves the file as it was. A file that ends in an unterminated fragment that
//! is not a JSON object (an append cut short by a crash) has the fragment cut off before the next
//! append, so the chain goes on from the last whole line.

use serde::Serialize;
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// `prev` of the first line of a file.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// The chain is broken at `line` (1-based).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainBreak {
    pub line: usize,
    pub why: String,
}

impl std::fmt::Display for ChainBreak {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}: {}", self.line, self.why)
    }
}

fn hash_line(line: &str) -> String {
    loom_core::sha256_hex(line.as_bytes())
}

/// Checks the chain of a whole file. `Ok(())` when every chained line names the hash of the line
/// before it; otherwise the first line at which it does not.
pub fn verify(text: &str) -> Result<(), ChainBreak> {
    let mut previous: Option<&str> = None;
    let mut chained = false;
    for (i, line) in text.lines().enumerate() {
        let n = i.saturating_add(1);
        if line.trim().is_empty() {
            continue;
        }
        let prev_field = serde_json::from_str::<serde_json::Value>(line)
            .ok()
            .and_then(|v| v.get("prev").and_then(|p| p.as_str().map(str::to_string)));
        match prev_field {
            Some(p) => {
                let expected = previous.map_or_else(|| GENESIS.to_string(), hash_line);
                if p != expected {
                    return Err(ChainBreak {
                        line: n,
                        why: "its `prev` does not match the line before it; the file was edited, truncated or reordered".into(),
                    });
                }
                chained = true;
            }
            None if chained => {
                return Err(ChainBreak { line: n, why: "it has no valid `prev` inside the chained part of the file".into() });
            }
            None => {}
        }
        previous = Some(line);
    }
    Ok(())
}

/// (file length, hash of its last line) as this writer left a file; `None` when it must be read.
type Tail = Option<(u64, String)>;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Appends chained lines. Appends to one file are serialised; appends to different files do not wait
/// for each other.
#[derive(Default)]
pub struct NetLogWriter {
    files: Mutex<HashMap<PathBuf, Arc<Mutex<Tail>>>>,
}

impl NetLogWriter {
    pub fn new() -> NetLogWriter {
        NetLogWriter::default()
    }

    /// Appends `entry` (a JSON object) with its `prev` field and syncs the data to disk before
    /// returning. The directory of `path` must exist. On failure the file is left as it was.
    pub fn append<T: Serialize>(&self, path: &Path, entry: &T) -> std::io::Result<()> {
        let slot = lock(&self.files).entry(path.to_path_buf()).or_default().clone();
        let mut tail = lock(&slot);
        let mut file = std::fs::OpenOptions::new().create(true).append(true).read(true).open(path)?;
        let mut len = file.metadata()?.len();
        let (prev, needs_newline) = match tail.as_ref() {
            Some((l, h)) if *l == len => (h.clone(), false),
            _ => {
                let (prev, needs_newline, good_len) = tail_of(&mut file, path, len)?;
                len = good_len;
                (prev, needs_newline)
            }
        };
        let mut value = serde_json::to_value(entry).map_err(std::io::Error::other)?;
        match value.as_object_mut() {
            Some(o) => o.insert("prev".to_string(), serde_json::Value::String(prev)),
            None => return Err(std::io::Error::other("an audit entry must be a JSON object")),
        };
        let line = serde_json::to_string(&value).map_err(std::io::Error::other)?;
        let mut bytes = Vec::with_capacity(line.len().saturating_add(2));
        if needs_newline {
            bytes.push(b'\n');
        }
        bytes.extend_from_slice(line.as_bytes());
        bytes.push(b'\n');
        // Forget the tail first: after a failure the file is read again.
        *tail = None;
        if let Err(e) = file.write_all(&bytes).and_then(|()| file.sync_data()) {
            // A line that is partial, or not known to be on disk, must not stay in front of the next one.
            let _ = file.set_len(len);
            return Err(e);
        }
        *tail = Some((len.saturating_add(bytes.len() as u64), hash_line(&line)));
        Ok(())
    }
}

/// The hash to chain from (zeros for an empty file), whether a newline must come before the next
/// line, and the length of the file to append at. An unterminated last fragment that is a JSON object
/// is a whole line without its newline; any other is cut off.
fn tail_of(file: &mut std::fs::File, path: &Path, len: u64) -> std::io::Result<(String, bool, u64)> {
    if len == 0 {
        return Ok((GENESIS.to_string(), false, 0));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let end = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i.saturating_add(1));
    let fragment = bytes.get(end..).unwrap_or(&[]);
    let mut needs_newline = false;
    if !fragment.is_empty() {
        if serde_json::from_slice::<serde_json::Value>(fragment).is_ok_and(|v| v.is_object()) {
            needs_newline = true;
        } else {
            tracing::warn!("{}: cutting off {} bytes of an unfinished last line", path.display(), fragment.len());
            file.set_len(end as u64)?;
            bytes.truncate(end);
        }
    }
    let text = String::from_utf8_lossy(&bytes);
    let last = text.lines().rev().find(|l| !l.trim().is_empty());
    Ok((last.map_or_else(|| GENESIS.to_string(), hash_line), needs_newline, bytes.len() as u64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn appended_lines_chain_and_verify() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("net.jsonl");
        let w = NetLogWriter::new();
        for i in 0..3 {
            w.append(&path, &json!({"n": i})).unwrap();
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let first: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(first["prev"], GENESIS);
        assert_eq!(verify(&text), Ok(()));
        // A second writer continues the same chain.
        NetLogWriter::new().append(&path, &json!({"n": 3})).unwrap();
        assert_eq!(verify(&std::fs::read_to_string(&path).unwrap()), Ok(()));
    }

    #[test]
    fn a_torn_last_line_is_cut_off_before_the_next_append() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("net.jsonl");
        let w = NetLogWriter::new();
        w.append(&path, &json!({"n": 0})).unwrap();
        let whole = std::fs::read_to_string(&path).unwrap();
        // An append cut short by a crash: half a line, no newline.
        std::fs::write(&path, format!("{whole}{{\"n\":1,\"pr")).unwrap();
        NetLogWriter::new().append(&path, &json!({"n": 2})).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(verify(&text), Ok(()), "{text}");
        assert_eq!(text.lines().count(), 2, "{text}");
        assert!(!text.contains("\"pr\n") && text.ends_with('\n'));
        // A whole object that only lacks its newline is kept and chained from.
        let unterminated = text.trim_end().to_string();
        std::fs::write(&path, &unterminated).unwrap();
        NetLogWriter::new().append(&path, &json!({"n": 3})).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(verify(&text), Ok(()), "{text}");
        assert_eq!(text.lines().count(), 3, "{text}");
    }

    #[test]
    fn appends_to_different_files_and_concurrent_appends_to_one_file_chain() {
        let dir = tempfile::tempdir().unwrap();
        let w = Arc::new(NetLogWriter::new());
        let paths = [dir.path().join("a.jsonl"), dir.path().join("b.jsonl")];
        let threads: Vec<_> = (0..8)
            .map(|i| {
                let (w, path) = (w.clone(), paths[i % 2].clone());
                std::thread::spawn(move || {
                    for n in 0..10 {
                        w.append(&path, &json!({"t": i, "n": n})).unwrap();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        for p in &paths {
            let text = std::fs::read_to_string(p).unwrap();
            assert_eq!(text.lines().count(), 40);
            assert_eq!(verify(&text), Ok(()));
        }
    }

    #[test]
    fn modified_line_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("net.jsonl");
        let w = NetLogWriter::new();
        for i in 0..4 {
            w.append(&path, &json!({"n": i})).unwrap();
        }
        let text = std::fs::read_to_string(&path).unwrap().replacen("\"n\":1", "\"n\":9", 1);
        assert_eq!(verify(&text).unwrap_err().line, 3);
        let dropped: String = std::fs::read_to_string(&path).unwrap().lines().skip(1).map(|l| format!("{l}\n")).collect();
        assert_eq!(verify(&dropped).unwrap_err().line, 1);
    }

    #[test]
    fn old_unchained_lines_then_chained_lines_verify() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("net.jsonl");
        std::fs::write(&path, "{\"n\":0}\n{\"n\":1}\n").unwrap();
        let w = NetLogWriter::new();
        w.append(&path, &json!({"n": 2})).unwrap();
        w.append(&path, &json!({"n": 3})).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(verify(&text), Ok(()));
        assert_eq!(verify("{\"n\":0}\n{\"n\":1}\n"), Ok(()));
        let tampered = text.replacen("\"n\":1", "\"n\":7", 1);
        assert_eq!(verify(&tampered).unwrap_err().line, 3);
    }
}
