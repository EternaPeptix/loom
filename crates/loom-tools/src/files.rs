//! What a session has read, so a write never lands on content the model has not seen.
//!
//! CONTRACT.
//!
//! The tracker maps a resolved path to what this session last saw of the file (a [`Seen`]): the
//! SHA-256 and size of its bytes as last read whole or written, or, for a file too large to load that
//! was read by line range, its size and modification time. `freshness(path)` compares that with the
//! file on disk now:
//! - the file does not exist → `Missing`;
//! - it is not a regular file (device, FIFO, socket, directory) → `Err(NotOpened::NotRegular)`;
//! - it exists and was never read or written by this session → `Unread`;
//! - its bytes differ from what was recorded (for a size-and-time record: its size or modification
//!   time differs) → `Changed { was_bytes, now_bytes }`;
//! - otherwise `Current`.
//!
//! `check(path)` is `freshness` with the failure as an `io::Error` (`InvalidInput` for a path that is
//! not a regular file). Neither loads the file: a different size decides at once, otherwise the
//! content is hashed in 1 MiB chunks; a size-and-time record is compared without reading at all.
//!
//! `note(path, bytes)` records the content just read or written; `note_stat(path, meta)` records a
//! file read by range. `Seen::of_bytes` / `Seen::of_stat` make the same records without storing them
//! and `record(path, seen)` stores one, for a caller that reads on one thread and decides on another
//! whether the read counts. `forget(path)` drops the entry. `move_into(other)` moves every entry into
//! another tracker: a call run ahead of its turn reads into a tracker of its own, and what it saw
//! counts for the session only once the call is claimed.
//! State is in memory only: after a restart every file is `Unread` until read again.
//!
//! `open_regular` is how the file tools open a file to read it: only a regular file is opened, and
//! the open never blocks.
//!
//! Tests required: each state; a rewrite with identical bytes stays `Current`; same size with
//! different bytes is `Changed`; a size-and-time record with the same size and a different time is
//! `Changed`; devices, FIFOs, sockets and directories are refused by kind; `forget`; use from several
//! threads.

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
pub struct Seen(Record);

#[derive(Clone, Debug, PartialEq, Eq)]
enum Record {
    /// SHA-256 (hex) and length of the bytes.
    Hash(String, u64),
    /// Size and modification time.
    Stat(u64, Option<SystemTime>),
}

impl Seen {
    /// The record of a file whose whole content is `bytes`.
    pub fn of_bytes(bytes: &[u8]) -> Seen {
        Seen(Record::Hash(hex::encode(Sha256::digest(bytes)), bytes.len() as u64))
    }

    /// The record of a file too large to read whole, identified by the size and modification time in
    /// `meta` (taken from the open file that was read).
    pub fn of_stat(meta: &Metadata) -> Seen {
        Seen(Record::Stat(meta.len(), meta.modified().ok()))
    }
}

#[derive(Debug, Default)]
pub struct FileTracker {
    seen: Mutex<HashMap<PathBuf, Seen>>,
}

/// Why [`open_regular`] did not open a file.
#[derive(Debug)]
pub enum NotOpened {
    /// The path could not be examined or opened; it may not exist.
    Io(io::Error),
    /// The path is this kind of thing, not a regular file.
    NotRegular(FileType),
}

/// Open the regular file at `path` for reading and return it with the metadata of the open file.
/// Symlinks are followed. The path is examined first, so that a device, FIFO, socket or directory is
/// refused without being opened: opening a FIFO or a device has effects of its own, and a socket
/// cannot be opened at all. The open never blocks (the path may have become a FIFO in between, which
/// would wait for a writer) and never takes a controlling terminal, and the type is judged again from
/// the open file: that metadata describes what is actually read, so the type cannot change between
/// the check and the read.
pub fn open_regular(path: &Path) -> Result<(File, Metadata), NotOpened> {
    let before = std::fs::metadata(path).map_err(NotOpened::Io)?;
    if !before.is_file() {
        return Err(NotOpened::NotRegular(before.file_type()));
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
        .map_err(NotOpened::Io)?;
    let meta = file.metadata().map_err(NotOpened::Io)?;
    if !meta.is_file() {
        return Err(NotOpened::NotRegular(meta.file_type()));
    }
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
        "a special file"
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

    /// Record what this session has seen of `path`.
    pub fn record(&self, path: &Path, seen: Seen) {
        self.map().insert(path.to_path_buf(), seen);
    }

    /// Record that this session has seen `bytes` as the content of `path`.
    pub fn note(&self, path: &Path, bytes: &[u8]) {
        self.record(path, Seen::of_bytes(bytes));
    }

    /// Record that this session has seen part of a file too large to read whole, identified by the
    /// size and modification time in `meta` (taken from the open file that was read).
    pub fn note_stat(&self, path: &Path, meta: &Metadata) {
        self.record(path, Seen::of_stat(meta));
    }

    pub fn forget(&self, path: &Path) {
        self.map().remove(path);
    }

    /// Move every record of this tracker into `into`, in no particular order (a tracker holds one
    /// record per path), as if each had been recorded there now. This tracker is left empty.
    pub fn move_into(&self, into: &FileTracker) {
        let staged: Vec<(PathBuf, Seen)> = self.map().drain().collect();
        for (path, seen) in staged {
            into.record(&path, seen);
        }
    }

    /// [`FileTracker::freshness`] with the failure as an `io::Error`. A path that is not a regular
    /// file (device, FIFO, socket, directory) is an `InvalidInput` error whose message completes the
    /// sentence "{path} {message}".
    pub fn check(&self, path: &Path) -> io::Result<Freshness> {
        self.freshness(path).map_err(|e| match e {
            NotOpened::Io(e) => e,
            NotOpened::NotRegular(t) => io::Error::new(io::ErrorKind::InvalidInput, format!("is {}, not a regular file", describe_type(&t))),
        })
    }

    /// Compare the file on disk with what this session last saw.
    pub fn freshness(&self, path: &Path) -> Result<Freshness, NotOpened> {
        let (mut file, meta) = match open_regular(path) {
            Ok(x) => x,
            Err(NotOpened::Io(e)) if e.kind() == io::ErrorKind::NotFound => return Ok(Freshness::Missing),
            Err(e) => return Err(e),
        };
        let recorded = self.map().get(path).cloned();
        let now_bytes = meta.len();
        match recorded {
            None => Ok(Freshness::Unread),
            Some(Seen(Record::Stat(was_bytes, mtime))) => {
                if was_bytes == now_bytes && mtime == meta.modified().ok() {
                    Ok(Freshness::Current)
                } else {
                    Ok(Freshness::Changed { was_bytes, now_bytes })
                }
            }
            Some(Seen(Record::Hash(hash, was_bytes))) => {
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
                        Err(e) => return Err(NotOpened::Io(e)),
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
    fn a_file_recorded_by_size_and_time_changes_with_either() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("big.bin");
        std::fs::write(&p, "0123456789").unwrap();
        let t = FileTracker::new();
        let (_f, meta) = open_regular(&p).unwrap();
        t.note_stat(&p, &meta);
        assert_eq!(t.check(&p).unwrap(), Freshness::Current);

        // The same bytes written again at a later time: only the modification time tells.
        std::fs::write(&p, "0123456789").unwrap();
        let later = meta.modified().unwrap() + std::time::Duration::from_secs(10);
        File::options().write(true).open(&p).unwrap().set_modified(later).unwrap();
        assert_eq!(t.check(&p).unwrap(), Freshness::Changed { was_bytes: 10, now_bytes: 10 });

        // Recorded again, then a change of size with the time put back: only the size tells.
        t.record(&p, Seen::of_stat(&std::fs::metadata(&p).unwrap()));
        assert_eq!(t.check(&p).unwrap(), Freshness::Current);
        std::fs::write(&p, "01234567890").unwrap();
        File::options().write(true).open(&p).unwrap().set_modified(later).unwrap();
        assert_eq!(t.check(&p).unwrap(), Freshness::Changed { was_bytes: 10, now_bytes: 11 });
    }

    #[test]
    fn what_is_not_a_regular_file_is_refused_by_kind() {
        let dir = tempfile::tempdir().unwrap();
        let t = FileTracker::new();
        let e = t.check(dir.path()).unwrap_err();
        assert!(e.to_string().contains("a directory"), "{e}");
        let e = t.check(Path::new("/dev/zero")).unwrap_err();
        assert!(e.kind() == io::ErrorKind::InvalidInput && e.to_string().contains("character device"), "{e}");
        assert!(matches!(t.freshness(Path::new("/dev/zero")), Err(NotOpened::NotRegular(kind)) if kind.is_char_device()));

        let fifo = dir.path().join("pipe");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(matches!(open_regular(&fifo), Err(NotOpened::NotRegular(kind)) if kind.is_fifo()));

        // A socket cannot be opened at all; it is named from what the path is, not from the failed open.
        let sock = dir.path().join("sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let e = t.check(&sock).unwrap_err();
        assert!(e.kind() == io::ErrorKind::InvalidInput && e.to_string().contains("a socket"), "{e}");
        assert!(matches!(open_regular(&sock), Err(NotOpened::NotRegular(kind)) if kind.is_socket()));

        // A failure that is not about the kind of file stays an I/O error, whatever its kind: a NUL in
        // the path is `InvalidInput` from the standard library and says nothing about what the path is.
        assert!(matches!(open_regular(&dir.path().join("none")), Err(NotOpened::Io(e)) if e.kind() == io::ErrorKind::NotFound));
        assert!(matches!(t.freshness(Path::new("a\0b")), Err(NotOpened::Io(e)) if e.kind() == io::ErrorKind::InvalidInput));
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
    fn staged_records_count_only_once_moved() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("a.txt"), dir.path().join("b.txt"));
        std::fs::write(&a, "new").unwrap();
        std::fs::write(&b, "b").unwrap();
        let session = FileTracker::new();
        session.note(&a, b"old");
        let staged = FileTracker::new();
        staged.note(&a, b"new");
        staged.note(&b, b"b");
        assert_eq!(session.check(&a).unwrap(), Freshness::Changed { was_bytes: 3, now_bytes: 3 });
        assert_eq!(session.check(&b).unwrap(), Freshness::Unread);
        staged.move_into(&session);
        assert_eq!(session.check(&a).unwrap(), Freshness::Current);
        assert_eq!(session.check(&b).unwrap(), Freshness::Current);
        assert_eq!(staged.check(&b).unwrap(), Freshness::Unread);
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
