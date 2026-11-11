//! What a session has read, so a write never lands on content the model has not seen.
//!
//! CONTRACT (bodies are placeholders for the implementer; signatures and types are fixed).
//!
//! The tracker maps a resolved path to the SHA-256 and size of the file's bytes as last read or
//! written by this session. `check(path)` compares that with the file on disk now:
//! - the file does not exist → `Missing`;
//! - it exists and was never read or written by this session → `Unread`;
//! - its bytes differ from what was recorded → `Changed { was_bytes, now_bytes }`;
//! - otherwise `Current`.
//!
//! `note(path, bytes)` records the content just read or written. `forget(path)` drops the entry.
//! State is in memory only: after a restart every file is `Unread` until read again.
//!
//! Tests required: each state; a rewrite with identical bytes stays `Current`; same size with
//! different bytes is `Changed`; `forget`; use from several threads.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Freshness {
    Missing,
    Unread,
    Changed { was_bytes: u64, now_bytes: u64 },
    Current,
}

#[derive(Debug, Default)]
pub struct FileTracker {
    seen: Mutex<HashMap<PathBuf, (String, u64)>>,
}

/// SHA-256 (hex) and length of `bytes`.
fn fingerprint(bytes: &[u8]) -> (String, u64) {
    (hex::encode(Sha256::digest(bytes)), bytes.len() as u64)
}

impl FileTracker {
    pub fn new() -> FileTracker {
        FileTracker::default()
    }

    fn map(&self) -> MutexGuard<'_, HashMap<PathBuf, (String, u64)>> {
        // Every update is a single insert or remove, so a poisoned lock still holds a whole map.
        self.seen.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Record that this session has seen `bytes` as the content of `path`.
    pub fn note(&self, path: &Path, bytes: &[u8]) {
        let fp = fingerprint(bytes);
        self.map().insert(path.to_path_buf(), fp);
    }

    pub fn forget(&self, path: &Path) {
        self.map().remove(path);
    }

    /// Compare the file on disk with what this session last saw.
    pub fn check(&self, path: &Path) -> io::Result<Freshness> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Freshness::Missing),
            Err(e) => return Err(e),
        };
        let recorded = self.map().get(path).cloned();
        let Some((hash, was_bytes)) = recorded else {
            return Ok(Freshness::Unread);
        };
        let (now_hash, now_bytes) = fingerprint(&bytes);
        if now_hash == hash {
            Ok(Freshness::Current)
        } else {
            Ok(Freshness::Changed { was_bytes, now_bytes })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn missing_unread_current_changed() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f.txt");
        let t = FileTracker::new();
        assert_eq!(t.check(&p).unwrap(), Freshness::Missing);
        std::fs::write(&p, "abc").unwrap();
        assert_eq!(t.check(&p).unwrap(), Freshness::Unread);
        t.note(&p, b"abc");
        assert_eq!(t.check(&p).unwrap(), Freshness::Current);
        std::fs::write(&p, "abcdef").unwrap();
        assert_eq!(t.check(&p).unwrap(), Freshness::Changed { was_bytes: 3, now_bytes: 6 });
        std::fs::remove_file(&p).unwrap();
        assert_eq!(t.check(&p).unwrap(), Freshness::Missing);
    }

    #[test]
    fn identical_rewrite_stays_current_and_same_size_change_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f.txt");
        let t = FileTracker::new();
        std::fs::write(&p, "abc").unwrap();
        t.note(&p, b"abc");
        std::fs::write(&p, "abc").unwrap();
        assert_eq!(t.check(&p).unwrap(), Freshness::Current);
        std::fs::write(&p, "abd").unwrap();
        assert_eq!(t.check(&p).unwrap(), Freshness::Changed { was_bytes: 3, now_bytes: 3 });
        t.note(&p, b"abd");
        assert_eq!(t.check(&p).unwrap(), Freshness::Current);
    }

    #[test]
    fn forget_makes_file_unread() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f.txt");
        let t = FileTracker::new();
        std::fs::write(&p, "x").unwrap();
        t.note(&p, b"x");
        t.forget(&p);
        assert_eq!(t.check(&p).unwrap(), Freshness::Unread);
        t.forget(&p);
    }

    #[test]
    fn use_from_several_threads() {
        let dir = tempfile::tempdir().unwrap();
        let t = Arc::new(FileTracker::new());
        let mut handles = Vec::new();
        for i in 0..8 {
            let t = Arc::clone(&t);
            let p = dir.path().join(format!("f{i}.txt"));
            handles.push(std::thread::spawn(move || {
                let body = format!("content {i}");
                std::fs::write(&p, &body).unwrap();
                t.note(&p, body.as_bytes());
                t.check(&p).unwrap()
            }));
        }
        for h in handles {
            assert_eq!(h.join().unwrap(), Freshness::Current);
        }
    }
}
