//! The per-session egress audit file (`net.jsonl`) as a hash chain.
//!
//! Every line is one JSON object. Lines written by this module carry `prev`: the SHA-256 (hex) of the
//! previous line's bytes (without the newline), or 64 zeros for the first line of a file. Files whose
//! early lines have no `prev` (written before the chain existed) stay readable: the chain starts at
//! the first line that has the field, and that line must name the hash of the line before it.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

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
    let digest = Sha256::digest(line.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
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

/// Appends chained lines; appends to one file are serialised.
#[derive(Default)]
pub struct NetLogWriter {
    /// (file length, hash of its last line) as this writer left each file.
    tails: Mutex<HashMap<PathBuf, (u64, String)>>,
}

impl NetLogWriter {
    pub fn new() -> NetLogWriter {
        NetLogWriter::default()
    }

    /// Appends `entry` (a JSON object) with its `prev` field and syncs the data to disk before
    /// returning. The directory of `path` must exist.
    pub fn append<T: Serialize>(&self, path: &Path, entry: &T) -> std::io::Result<()> {
        let mut tails = self.tails.lock().unwrap_or_else(|e| e.into_inner());
        let mut file = std::fs::OpenOptions::new().create(true).append(true).read(true).open(path)?;
        let len = file.metadata()?.len();
        let (prev, needs_newline) = match tails.get(path) {
            Some((l, h)) if *l == len => (h.clone(), false),
            _ => tail_of(&mut file, len)?,
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
        // Forget the tail first: after a failed write the file is re-read.
        tails.remove(path);
        file.write_all(&bytes)?;
        file.sync_data()?;
        let new_len = len.saturating_add(bytes.len() as u64);
        tails.insert(path.to_path_buf(), (new_len, hash_line(&line)));
        Ok(())
    }
}

/// The hash to chain from (zeros for an empty file) and whether the file lacks a final newline.
fn tail_of(file: &mut std::fs::File, len: u64) -> std::io::Result<(String, bool)> {
    if len == 0 {
        return Ok((GENESIS.to_string(), false));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut text = Vec::new();
    file.read_to_end(&mut text)?;
    let text = String::from_utf8_lossy(&text);
    let needs_newline = !text.ends_with('\n');
    let last = text.lines().rev().find(|l| !l.trim().is_empty());
    Ok((last.map_or_else(|| GENESIS.to_string(), hash_line), needs_newline))
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
