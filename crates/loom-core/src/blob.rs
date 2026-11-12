//! Content-addressed store for complete tool output.
//!
//! Every output is stored whole before the model sees any of it, so a cut or an eviction never loses
//! anything: the handle (`out:<id>`) pages and searches the original bytes.

use crate::ids::BlobId;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Temporary files in `tmp/` older than this are leftovers of a crashed writer and are removed when the store
/// opens; a younger one may belong to a writer in another process.
pub const STALE_TMP_AGE: Duration = Duration::from_secs(3600);

/// A blob younger than this is never collected: it may have been written just before the record that names it.
pub const DEFAULT_GC_MIN_AGE: Duration = Duration::from_secs(3600);

/// What a sweep found. With `applied == false` nothing was deleted and `collected*` are what would be.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SweepReport {
    pub examined: u64,
    pub examined_bytes: u64,
    pub kept: u64,
    pub kept_bytes: u64,
    pub collected: u64,
    pub collected_bytes: u64,
    pub applied: bool,
}

/// A stored output: its id and size.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobRef {
    pub id: BlobId,
    pub bytes: u64,
    pub lines: u64,
}

impl BlobRef {
    /// The handle shown to the model.
    pub fn handle(&self) -> String {
        format!("out:{}", &self.id.0[..self.id.0.len().min(16)])
    }
}

/// A run of lines read back from a blob. Line numbers are 1-based and inclusive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineSlice {
    pub text: String,
    pub first: u64,
    pub last: u64,
    pub total: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrepMatch {
    pub line: u64,
    /// The matching line with `context` lines either side, numbered.
    pub excerpt: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrepResult {
    pub matches: Vec<GrepMatch>,
    /// Matching lines in the whole blob (may exceed `matches.len()`).
    pub total_matches: u64,
}

#[derive(Clone, Debug)]
pub struct BlobStore {
    root: PathBuf,
}

/// Streams bytes into the store; the id is known only at `finish`.
pub struct BlobWriter {
    store: BlobStore,
    tmp: PathBuf,
    file: File,
    hasher: Sha256,
    bytes: u64,
    offsets: Vec<u64>,
    at_line_start: bool,
}

impl BlobStore {
    pub fn open(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(root.join("tmp"))?;
        remove_stale_tmp(&root.join("tmp"), STALE_TMP_AGE);
        Ok(Self { root })
    }

    /// Delete blobs (and their index files) whose id is not in `keep` and whose file is older than `min_age`.
    /// With `apply == false` only counts. Anything that cannot be deleted is kept.
    pub fn sweep(&self, keep: &HashSet<String>, min_age: Duration, apply: bool) -> io::Result<SweepReport> {
        let mut report = SweepReport { applied: apply, ..SweepReport::default() };
        let now = SystemTime::now();
        for shard in fs::read_dir(&self.root)?.flatten() {
            let name = shard.file_name().to_string_lossy().to_string();
            if name.len() != 2 || !name.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue;
            }
            let Ok(entries) = fs::read_dir(shard.path()) else { continue };
            for entry in entries.flatten() {
                let id = entry.file_name().to_string_lossy().to_string();
                if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                    continue;
                }
                let Ok(meta) = entry.metadata() else { continue };
                if !meta.is_file() {
                    continue;
                }
                report.examined += 1;
                report.examined_bytes = report.examined_bytes.saturating_add(meta.len());
                let old = meta.modified().ok().and_then(|m| now.duration_since(m).ok()).is_some_and(|age| age >= min_age);
                let mut keep_it = keep.contains(&id) || !old;
                if !keep_it && apply {
                    // Index first: a blob without an index is rebuilt on read, an index without a blob is inert.
                    let _ = fs::remove_file(self.idx_path(&BlobId(id.clone())));
                    keep_it = fs::remove_file(entry.path()).is_err();
                }
                if keep_it {
                    report.kept += 1;
                    report.kept_bytes = report.kept_bytes.saturating_add(meta.len());
                } else {
                    report.collected += 1;
                    report.collected_bytes = report.collected_bytes.saturating_add(meta.len());
                }
            }
        }
        Ok(report)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path_of(&self, id: &str) -> PathBuf {
        let shard = if id.len() >= 2 { &id[..2] } else { "00" };
        self.root.join(shard).join(id)
    }

    pub fn writer(&self) -> io::Result<BlobWriter> {
        let name = format!("{}-{}", crate::now_ms(), rand::random::<u64>());
        let tmp = self.root.join("tmp").join(name);
        let file = File::create(&tmp)?;
        Ok(BlobWriter { store: self.clone(), tmp, file, hasher: Sha256::new(), bytes: 0, offsets: Vec::new(), at_line_start: true })
    }

    pub fn put_bytes(&self, data: &[u8]) -> io::Result<BlobRef> {
        let mut w = self.writer()?;
        w.write_all(data)?;
        w.finish()
    }

    pub fn put_file(&self, path: &Path) -> io::Result<BlobRef> {
        let mut src = File::open(path)?;
        let mut w = self.writer()?;
        io::copy(&mut src, &mut w)?;
        w.finish()
    }

    /// Resolve a full id or an unambiguous prefix (the handle carries 16 chars). `out:` is accepted.
    pub fn resolve(&self, handle: &str) -> io::Result<BlobId> {
        let id = handle.trim().strip_prefix("out:").unwrap_or(handle.trim()).to_ascii_lowercase();
        if id.len() < 8 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("not an output handle: {handle}")));
        }
        if id.len() == 64 {
            return if self.path_of(&id).exists() { Ok(BlobId(id)) } else { Err(not_found(handle)) };
        }
        let dir = self.root.join(&id[..2]);
        let mut found: Option<String> = None;
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.len() == 64 && name.starts_with(&id) {
                    if found.is_some() {
                        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("ambiguous output handle: {handle}")));
                    }
                    found = Some(name);
                }
            }
        }
        found.map(BlobId).ok_or_else(|| not_found(handle))
    }

    pub fn meta(&self, id: &BlobId) -> io::Result<BlobRef> {
        let bytes = fs::metadata(self.path_of(&id.0))?.len();
        let lines = self.offsets(id)?.len() as u64;
        Ok(BlobRef { id: id.clone(), bytes, lines })
    }

    pub fn read_all(&self, id: &BlobId) -> io::Result<Vec<u8>> {
        fs::read(self.path_of(&id.0))
    }

    fn idx_path(&self, id: &BlobId) -> PathBuf {
        let mut p = self.path_of(&id.0).into_os_string();
        p.push(".idx");
        PathBuf::from(p)
    }

    fn offsets(&self, id: &BlobId) -> io::Result<Vec<u64>> {
        let blob = self.path_of(&id.0);
        let size = fs::metadata(&blob)?.len();
        let stored = fs::read(self.idx_path(id)).ok().filter(|raw| raw.len() % 8 == 0).map(|raw| {
            raw.chunks_exact(8).map(|c| u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]])).collect::<Vec<u64>>()
        });
        if let Some(offsets) = stored {
            if index_matches(&blob, &offsets, size)? {
                return Ok(offsets);
            }
        }
        // Missing, short or garbage index (a crash, a bad disk): the blob is the truth, so rebuild from it.
        let offsets = scan_offsets(&blob)?;
        let tmp = self.root.join("tmp").join(format!("rebuild-{}-{}.idx", crate::now_ms(), rand::random::<u64>()));
        if write_index(&tmp, &self.idx_path(id), &offsets).is_ok() {
            if let Some(dir) = blob.parent() {
                let _ = sync_dir(dir);
            }
        } else {
            let _ = fs::remove_file(&tmp);
        }
        Ok(offsets)
    }

    /// Lines `start..=end` (1-based). Out-of-range bounds are clamped; an empty range gives empty text.
    pub fn read_lines(&self, id: &BlobId, start: u64, end: u64) -> io::Result<LineSlice> {
        let offsets = self.offsets(id)?;
        let total = offsets.len() as u64;
        let first = start.max(1);
        let last = end.min(total);
        if total == 0 || first > last {
            return Ok(LineSlice { text: String::new(), first, last: first.saturating_sub(1), total });
        }
        let size = fs::metadata(self.path_of(&id.0))?.len();
        let corrupt = || io::Error::new(io::ErrorKind::InvalidData, format!("the line index of {} is inconsistent", id.0));
        let at = |n: u64| usize::try_from(n).ok().and_then(|n| offsets.get(n));
        let from = *at(first - 1).ok_or_else(corrupt)?;
        let to = if last < total { *at(last).ok_or_else(corrupt)? } else { size };
        let len = usize::try_from(to.checked_sub(from).ok_or_else(corrupt)?).map_err(|_| corrupt())?;
        let mut file = File::open(self.path_of(&id.0))?;
        file.seek(SeekFrom::Start(from))?;
        let mut buf = vec![0u8; len];
        file.read_exact(&mut buf)?;
        Ok(LineSlice { text: String::from_utf8_lossy(&buf).into_owned(), first, last, total })
    }

    /// Search line by line. Returns up to `max_matches` excerpts and the total number of matching lines.
    pub fn grep(&self, id: &BlobId, re: &Regex, context: usize, max_matches: usize) -> io::Result<GrepResult> {
        let reader = BufReader::new(File::open(self.path_of(&id.0))?);
        let mut lines: Vec<String> = Vec::new();
        for line in reader.split(b'\n') {
            lines.push(String::from_utf8_lossy(&line?).into_owned());
        }
        let mut matches = Vec::new();
        let mut total_matches = 0u64;
        for (i, line) in lines.iter().enumerate() {
            if !re.is_match(line) {
                continue;
            }
            total_matches += 1;
            if matches.len() >= max_matches {
                continue;
            }
            let lo = i.saturating_sub(context);
            let hi = (i + context).min(lines.len().saturating_sub(1));
            let mut excerpt = String::new();
            for (j, text) in lines.iter().enumerate().take(hi + 1).skip(lo) {
                let mark = if j == i { ':' } else { '-' };
                excerpt.push_str(&format!("{}{} {}\n", j + 1, mark, text));
            }
            matches.push(GrepMatch { line: (i + 1) as u64, excerpt });
        }
        Ok(GrepResult { matches, total_matches })
    }

    /// True when `needle` occurs verbatim within lines `start..=end`. Used to check quotes.
    pub fn contains_in_range(&self, id: &BlobId, start: u64, end: u64, needle: &str) -> io::Result<bool> {
        Ok(self.read_lines(id, start, end)?.text.contains(needle))
    }
}

/// Add to `found` every run of 64 hexadecimal characters in `reader`, lower-cased, whatever surrounds it. A longer
/// run (an id glued to other hex, up to 1024 characters) contributes every 64-character window, so an id is
/// found even when it is not delimited. This is how a garbage collection learns which blobs are in use without
/// knowing which record field holds an id.
pub fn scan_ids(reader: impl Read, found: &mut HashSet<String>) -> io::Result<()> {
    const MAX_RUN: usize = 1024;
    let mut reader = BufReader::new(reader);
    let mut run: Vec<u8> = Vec::new();
    let flush = |run: &mut Vec<u8>, found: &mut HashSet<String>| {
        for w in run.windows(64) {
            found.insert(String::from_utf8_lossy(w).into_owned());
        }
        run.clear();
    };
    loop {
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() {
            flush(&mut run, found);
            return Ok(());
        }
        for b in chunk {
            if b.is_ascii_hexdigit() {
                if run.len() < MAX_RUN {
                    run.push(b.to_ascii_lowercase());
                }
            } else {
                flush(&mut run, found);
            }
        }
        let n = chunk.len();
        reader.consume(n);
    }
}

/// Remove files in `dir` last modified more than `max_age` ago. Best effort.
fn remove_stale_tmp(dir: &Path, max_age: Duration) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    let now = SystemTime::now();
    for entry in entries.flatten() {
        let stale = entry
            .metadata()
            .ok()
            .filter(|m| m.is_file())
            .and_then(|m| m.modified().ok())
            .and_then(|m| now.duration_since(m).ok())
            .is_some_and(|age| age > max_age);
        if stale {
            let _ = fs::remove_file(entry.path());
        }
    }
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Write the index through `tmp` (synced) and rename it over `idx`.
fn write_index(tmp: &Path, idx: &Path, offsets: &[u64]) -> io::Result<()> {
    let mut raw = Vec::with_capacity(offsets.len().saturating_mul(8));
    for off in offsets {
        raw.extend_from_slice(&off.to_le_bytes());
    }
    let mut f = File::create(tmp)?;
    f.write_all(&raw)?;
    f.sync_all()?;
    drop(f);
    fs::rename(tmp, idx)
}

/// Line start offsets computed from the blob itself.
fn scan_offsets(blob: &Path) -> io::Result<Vec<u64>> {
    let mut reader = BufReader::new(File::open(blob)?);
    let (mut offsets, mut pos, mut at_start) = (Vec::new(), 0u64, true);
    loop {
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() {
            return Ok(offsets);
        }
        for b in chunk {
            if at_start {
                offsets.push(pos);
            }
            at_start = *b == b'\n';
            pos = pos.saturating_add(1);
        }
        let n = chunk.len();
        reader.consume(n);
    }
}

/// Cheap consistency check of a stored index against the blob: starts at 0, strictly increasing, inside the
/// blob, and the last line really is the last line (so a truncated index is noticed).
fn index_matches(blob: &Path, offsets: &[u64], size: u64) -> io::Result<bool> {
    let (Some(&first), Some(&last)) = (offsets.first(), offsets.last()) else { return Ok(size == 0) };
    if first != 0 || last >= size || offsets.windows(2).any(|w| w[0] >= w[1]) {
        return Ok(false);
    }
    let mut file = File::open(blob)?;
    file.seek(SeekFrom::Start(last))?;
    let mut reader = BufReader::new(file);
    let (mut newlines, mut final_byte) = (0u64, 0u8);
    loop {
        let chunk = reader.fill_buf()?;
        let Some(&tail) = chunk.last() else { break };
        newlines += chunk.iter().filter(|b| **b == b'\n').count() as u64;
        final_byte = tail;
        let n = chunk.len();
        reader.consume(n);
    }
    Ok(newlines == 0 || (newlines == 1 && final_byte == b'\n'))
}

fn not_found(handle: &str) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, format!("no stored output for handle {handle}"))
}

impl Write for BlobWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write_all(buf)?;
        self.hasher.update(buf);
        for (i, b) in buf.iter().enumerate() {
            if self.at_line_start {
                self.offsets.push(self.bytes + i as u64);
                self.at_line_start = false;
            }
            if *b == b'\n' {
                self.at_line_start = true;
            }
        }
        self.bytes += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Drop for BlobWriter {
    /// A writer that was abandoned or failed leaves nothing behind (after `finish` the files are gone already).
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.tmp);
        let mut idx_tmp = self.tmp.clone().into_os_string();
        idx_tmp.push(".idx");
        let _ = fs::remove_file(idx_tmp);
    }
}

impl BlobWriter {
    pub fn bytes_written(&self) -> u64 {
        self.bytes
    }

    pub fn finish(mut self) -> io::Result<BlobRef> {
        self.file.flush()?;
        self.file.sync_all()?;
        let id = hex::encode(std::mem::take(&mut self.hasher).finalize());
        let dest = self.store.path_of(&id);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        let blob = BlobRef { id: BlobId(id), bytes: self.bytes, lines: self.offsets.len() as u64 };
        let idx = self.store.idx_path(&blob.id);
        let mut idx_tmp = self.tmp.clone().into_os_string();
        idx_tmp.push(".idx");
        let idx_tmp = PathBuf::from(idx_tmp);
        let shard = dest.parent().map(Path::to_path_buf);
        if dest.exists() {
            // Same bytes are already stored. Trust the index only if it has the length the content implies.
            let want = (self.offsets.len() as u64).saturating_mul(8);
            if fs::metadata(&idx).map(|m| m.len()).ok() != Some(want) {
                write_index(&idx_tmp, &idx, &self.offsets)?;
                if let Some(dir) = &shard {
                    sync_dir(dir)?;
                }
            }
            // Refresh the age so a collection running now does not take a blob that is about to be referenced.
            if let Ok(f) = fs::OpenOptions::new().write(true).open(&dest) {
                let _ = f.set_modified(SystemTime::now());
            }
            let _ = fs::remove_file(&self.tmp);
            return Ok(blob);
        }
        write_index(&idx_tmp, &idx, &self.offsets)?;
        fs::rename(&self.tmp, &dest)?;
        if let Some(dir) = &shard {
            sync_dir(dir)?;
        }
        Ok(blob)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, BlobStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = BlobStore::open(dir.path().join("blobs")).unwrap();
        (dir, store)
    }

    #[test]
    fn put_is_content_addressed_and_idempotent() {
        let (_d, s) = store();
        let a = s.put_bytes(b"one\ntwo\nthree\n").unwrap();
        let b = s.put_bytes(b"one\ntwo\nthree\n").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.lines, 3);
        assert_eq!(a.bytes, 14);
        assert_eq!(a.id.0, crate::sha256_hex(b"one\ntwo\nthree\n"));
        assert_eq!(s.meta(&a.id).unwrap(), a);
        assert_eq!(s.read_all(&a.id).unwrap(), b"one\ntwo\nthree\n");
    }

    #[test]
    fn line_counts_without_trailing_newline_and_empty() {
        let (_d, s) = store();
        assert_eq!(s.put_bytes(b"a\nb").unwrap().lines, 2);
        assert_eq!(s.put_bytes(b"").unwrap().lines, 0);
        assert_eq!(s.put_bytes(b"\n\n").unwrap().lines, 2);
    }

    #[test]
    fn read_lines_pages_and_clamps() {
        let (_d, s) = store();
        let text: String = (1..=10).map(|i| format!("line {i}\n")).collect();
        let b = s.put_bytes(text.as_bytes()).unwrap();
        let mid = s.read_lines(&b.id, 3, 4).unwrap();
        assert_eq!(mid.text, "line 3\nline 4\n");
        assert_eq!((mid.first, mid.last, mid.total), (3, 4, 10));
        let tail = s.read_lines(&b.id, 9, 99).unwrap();
        assert_eq!(tail.text, "line 9\nline 10\n");
        assert_eq!(tail.last, 10);
        assert_eq!(s.read_lines(&b.id, 20, 30).unwrap().text, "");
        assert_eq!(s.read_lines(&b.id, 0, 1).unwrap().text, "line 1\n");
    }

    #[test]
    fn grep_counts_all_and_caps_excerpts() {
        let (_d, s) = store();
        let b = s.put_bytes(b"alpha\nbeta\nalpha beta\ngamma\nalpha\n").unwrap();
        let r = s.grep(&b.id, &Regex::new("alpha").unwrap(), 1, 2).unwrap();
        assert_eq!(r.total_matches, 3);
        assert_eq!(r.matches.len(), 2);
        assert_eq!(r.matches[0].line, 1);
        assert_eq!(r.matches[0].excerpt, "1: alpha\n2- beta\n");
        assert_eq!(r.matches[1].line, 3);
    }

    #[test]
    fn resolve_accepts_handle_and_rejects_junk() {
        let (_d, s) = store();
        let b = s.put_bytes(b"x\n").unwrap();
        assert_eq!(s.resolve(&b.handle()).unwrap(), b.id);
        assert_eq!(s.resolve(&b.id.0).unwrap(), b.id);
        assert!(s.resolve("out:zzzz").is_err());
        assert!(s.resolve("out:0000000000000000").is_err());
        assert!(s.resolve("../../etc/passwd").is_err());
    }

    #[test]
    fn quote_check_is_verbatim_and_range_bound() {
        let (_d, s) = store();
        let b = s.put_bytes(b"first\nsecond line here\nthird\n").unwrap();
        assert!(s.contains_in_range(&b.id, 2, 2, "second line").unwrap());
        assert!(!s.contains_in_range(&b.id, 1, 1, "second line").unwrap());
        assert!(!s.contains_in_range(&b.id, 1, 3, "Second line").unwrap());
    }

    #[test]
    fn streaming_writer_matches_put_bytes() {
        let (_d, s) = store();
        let mut w = s.writer().unwrap();
        w.write_all(b"ab").unwrap();
        w.write_all(b"c\nde").unwrap();
        w.write_all(b"f\n").unwrap();
        let streamed = w.finish().unwrap();
        assert_eq!(streamed, s.put_bytes(b"abc\ndef\n").unwrap());
        assert_eq!(s.read_lines(&streamed.id, 2, 2).unwrap().text, "def\n");
    }

    fn tmp_files(s: &BlobStore) -> Vec<PathBuf> {
        fs::read_dir(s.root().join("tmp")).unwrap().flatten().map(|e| e.path()).collect()
    }

    #[test]
    fn dropped_writer_leaves_no_temp_file() {
        let (_d, s) = store();
        let mut w = s.writer().unwrap();
        w.write_all(b"half a line").unwrap();
        assert_eq!(tmp_files(&s).len(), 1);
        drop(w);
        assert!(tmp_files(&s).is_empty());
        s.put_bytes(b"x\n").unwrap();
        assert!(tmp_files(&s).is_empty());
    }

    #[test]
    fn open_removes_old_temp_files_only() {
        let (_d, s) = store();
        let old = s.root().join("tmp").join("old-1");
        let fresh = s.root().join("tmp").join("fresh-1");
        fs::write(&old, b"x").unwrap();
        fs::write(&fresh, b"x").unwrap();
        let f = fs::OpenOptions::new().write(true).open(&old).unwrap();
        f.set_modified(SystemTime::now() - Duration::from_secs(2 * 3600)).unwrap();
        drop(f);
        let _s2 = BlobStore::open(s.root()).unwrap();
        assert!(!old.exists());
        assert!(fresh.exists());
    }

    #[test]
    fn damaged_index_is_repaired_on_store_and_on_read() {
        let (_d, s) = store();
        let data = b"one\ntwo\nthree\n";
        let b = s.put_bytes(data).unwrap();
        let idx = s.idx_path(&b.id);
        // Empty index: storing the same bytes again repairs it.
        fs::write(&idx, b"").unwrap();
        assert_eq!(s.put_bytes(data).unwrap(), b);
        assert_eq!(fs::metadata(&idx).unwrap().len(), 24);
        assert_eq!(s.meta(&b.id).unwrap().lines, 3);
        // Short (truncated) index: reading repairs it.
        fs::write(&idx, 0u64.to_le_bytes()).unwrap();
        assert_eq!(s.read_lines(&b.id, 2, 3).unwrap().text, "two\nthree\n");
        assert_eq!(fs::metadata(&idx).unwrap().len(), 24);
        // Garbage that would underflow, odd lengths, and a missing index do not panic.
        let mut garbage = Vec::new();
        for off in [0u64, 900, 5] {
            garbage.extend_from_slice(&off.to_le_bytes());
        }
        fs::write(&idx, &garbage).unwrap();
        assert_eq!(s.read_lines(&b.id, 1, 3).unwrap().text, "one\ntwo\nthree\n");
        fs::write(&idx, b"abc").unwrap();
        assert_eq!(s.meta(&b.id).unwrap().lines, 3);
        fs::remove_file(&idx).unwrap();
        assert!(s.contains_in_range(&b.id, 3, 3, "three").unwrap());
        assert!(idx.exists());
    }

    #[test]
    fn sweep_deletes_old_unreferenced_blobs_with_their_index() {
        let (_d, s) = store();
        let old_gone = s.put_bytes(b"gone\n").unwrap();
        let old_kept = s.put_bytes(b"kept\n").unwrap();
        let young = s.put_bytes(b"young\n").unwrap();
        for b in [&old_gone, &old_kept] {
            let f = fs::OpenOptions::new().write(true).open(s.path_of(&b.id.0)).unwrap();
            f.set_modified(SystemTime::now() - Duration::from_secs(7200)).unwrap();
        }
        let keep: HashSet<String> = [old_kept.id.0.clone()].into_iter().collect();
        let dry = s.sweep(&keep, DEFAULT_GC_MIN_AGE, false).unwrap();
        assert_eq!((dry.examined, dry.kept, dry.collected, dry.collected_bytes, dry.applied), (3, 2, 1, 5, false));
        assert!(s.path_of(&old_gone.id.0).exists());
        let real = s.sweep(&keep, DEFAULT_GC_MIN_AGE, true).unwrap();
        assert_eq!((real.examined, real.kept, real.collected, real.collected_bytes), (3, 2, 1, 5));
        assert!(!s.path_of(&old_gone.id.0).exists());
        assert!(!s.idx_path(&old_gone.id).exists());
        assert!(s.path_of(&old_kept.id.0).exists() && s.idx_path(&old_kept.id).exists());
        assert!(s.path_of(&young.id.0).exists());
    }

    #[test]
    fn scan_ids_finds_ids_in_any_text() {
        let a = "a".repeat(64);
        let b = "0123456789abcdef".repeat(4).to_uppercase();
        let text = format!("{{\"x\":\"{a}\"}} out:{b}\\n12345 {}", "f".repeat(63));
        let mut found = HashSet::new();
        scan_ids(text.as_bytes(), &mut found).unwrap();
        assert!(found.contains(&a));
        assert!(found.contains(&b.to_lowercase()));
        assert_eq!(found.len(), 2);
        // Glued to other hex still counts.
        let mut found = HashSet::new();
        scan_ids(format!("9{a}").as_bytes(), &mut found).unwrap();
        assert!(found.contains(&a));
    }

    #[test]
    fn restoring_existing_bytes_refreshes_their_age() {
        let (_d, s) = store();
        let b = s.put_bytes(b"again\n").unwrap();
        let f = fs::OpenOptions::new().write(true).open(s.path_of(&b.id.0)).unwrap();
        f.set_modified(SystemTime::now() - Duration::from_secs(7200)).unwrap();
        drop(f);
        s.put_bytes(b"again\n").unwrap();
        let r = s.sweep(&HashSet::new(), DEFAULT_GC_MIN_AGE, false).unwrap();
        assert_eq!((r.kept, r.collected), (1, 0));
    }
}
