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
use std::fs::{File, FileType, Metadata};
use std::io::{self, Read};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::SystemTime;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Freshness {
    Missing,
    Unread,
    Changed { was_bytes: u64, now_bytes: u64 },
    Current,
}

/// What a session last saw of a file. A file read whole is recorded by content hash. A file too large
/// to read whole (read by line range) is recorded by size and modification time, so that detecting a
/// change never needs the whole file in memory or a full pass over it.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Seen {
    Hash(String, u64),
    Stat(u64, Option<SystemTime>),
}

#[derive(Debug, Default)]
pub struct FileTracker {
    seen: Mutex<HashMap<PathBuf, Seen>>,
}

/// SHA-256 (hex) and length of `bytes`.
fn fingerprint(bytes: &[u8]) -> Seen {
    Seen::Hash(hex::encode(Sha256::digest(bytes)), bytes.len() as u64)
}

/// Open `path` for reading without ever blocking on the open (a FIFO would otherwise wait for a
/// writer) and without becoming a controlling terminal, and return the open file with its metadata.
/// Judge the type from this metadata, not from a separate `stat`: it describes what was opened.
pub fn open_probe(path: &Path) -> io::Result<(File, Metadata)> {
    let file = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY).open(path)?;
    let meta = file.metadata()?;
    Ok((file, meta))
}

/// What a file that is not a regular file is, for a sentence ("a FIFO (named pipe)").
pub fn describe_type(t: &FileType) -> &'static str {
    if t.is_dir() {
        "a directory"
    } else if t.is_char_device() {
        "a character device"
    } else if t.is_block_device() {
        "a block device"
    } else if t.is_fifo() {
        "a FIFO (named pipe)"
    } else if t.is_socket() {
        "a socket"
    } else {
        "not a regular file"
    }
}

impl FileTracker {
    pub fn new() -> FileTracker {
        FileTracker::default()
    }

    fn map(&self) -> MutexGuard<'_, HashMap<PathBuf, Seen>> {
        // Every update is a single insert or remove, so a poisoned lock still holds a whole map.
        self.seen.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Record that this session has seen `bytes` as the content of `path`.
    pub fn note(&self, path: &Path, bytes: &[u8]) {
        let fp = fingerprint(bytes);
        self.map().insert(path.to_path_buf(), fp);
    }

    /// Record that this session has seen part of a file too large to read whole, identified by the
    /// size and modification time in `meta` (taken from the open file that was read).
    pub fn note_stat(&self, path: &Path, meta: &Metadata) {
        self.map().insert(path.to_path_buf(), Seen::Stat(meta.len(), meta.modified().ok()));
    }

    pub fn forget(&self, path: &Path) {
        self.map().remove(path);
    }

    /// Compare the file on disk with what this session last saw. A path that is not a regular file
    /// (device, FIFO, socket, directory) is an `InvalidInput` error whose message completes the sentence
    /// "{path} {message}".
    pub fn check(&self, path: &Path) -> io::Result<Freshness> {
        let (mut file, meta) = match open_probe(path) {
            Ok(x) => x,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Freshness::Missing),
            Err(e) => return Err(e),
        };
        if !meta.is_file() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("is {}, not a regular file", describe_type(&meta.file_type()))));
        }
        let recorded = self.map().get(path).cloned();
        let now_bytes = meta.len();
        match recorded {
            None => Ok(Freshness::Unread),
            Some(Seen::Stat(was_bytes, mtime)) => {
                if was_bytes == now_bytes && mtime == meta.modified().ok() {
                    Ok(Freshness::Current)
                } else {
                    Ok(Freshness::Changed { was_bytes, now_bytes })
                }
            }
            Some(Seen::Hash(hash, was_bytes)) => {
                if was_bytes != now_bytes {
                    return Ok(Freshness::Changed { was_bytes, now_bytes });
                }
                // Same size: hash the content in chunks, so memory stays bounded however large the file is.
                let mut hasher = Sha256::new();
                let mut buf = vec![0u8; 1 << 20];
                let mut streamed = 0u64;
                loop {
                    let n = match file.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(e) => return Err(e),
                    };
                    hasher.update(buf.get(..n).unwrap_or_default());
                    streamed += n as u64;
                }
                if hex::encode(hasher.finalize()) == hash {
                    Ok(Freshness::Current)
                } else {
                    Ok(Freshness::Changed { was_bytes, now_bytes: streamed })
                }
            }
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
    fn large_file_noted_by_stat_detects_change_and_non_regular_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("big.bin");
        std::fs::write(&p, "0123456789").unwrap();
        let t = FileTracker::new();
        let (_f, meta) = open_probe(&p).unwrap();
        t.note_stat(&p, &meta);
        assert_eq!(t.check(&p).unwrap(), Freshness::Current);
        std::fs::write(&p, "01234567890").unwrap();
        assert_eq!(t.check(&p).unwrap(), Freshness::Changed { was_bytes: 10, now_bytes: 11 });
        let e = t.check(dir.path()).unwrap_err();
        assert!(e.to_string().contains("a directory"), "{e}");
        let e = t.check(Path::new("/dev/zero")).unwrap_err();
        assert!(e.kind() == io::ErrorKind::InvalidInput && e.to_string().contains("character device"), "{e}");
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
