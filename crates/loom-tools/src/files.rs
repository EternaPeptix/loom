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
//! `note(path, bytes)` records the content just read or written. `forget(path)` drops the entry.
//! State is in memory only: after a restart every file is `Unread` until read again.
//!
//! Tests required: each state; a rewrite with identical bytes stays `Current`; same size with
//! different bytes is `Changed`; `forget`; use from several threads.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

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

impl FileTracker {
    pub fn new() -> FileTracker {
        FileTracker::default()
    }

    pub fn note(&self, path: &Path, bytes: &[u8]) {
        let _ = (path, bytes, &self.seen);
        todo!("implement per module contract")
    }

    pub fn forget(&self, path: &Path) {
        let _ = path;
        todo!("implement per module contract")
    }

    pub fn check(&self, path: &Path) -> io::Result<Freshness> {
        let _ = path;
        todo!("implement per module contract")
    }
}
