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
use std::path::{Path, PathBuf};

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
        Ok(Self { root })
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
        let lines = fs::metadata(self.idx_path(id))?.len() / 8;
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
        let raw = fs::read(self.idx_path(id))?;
        Ok(raw.chunks_exact(8).map(|c| u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]])).collect())
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
        let from = offsets[(first - 1) as usize];
        let to = if last < total { offsets[last as usize] } else { size };
        let mut file = File::open(self.path_of(&id.0))?;
        file.seek(SeekFrom::Start(from))?;
        let mut buf = vec![0u8; (to - from) as usize];
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
        if dest.exists() && idx.exists() {
            let _ = fs::remove_file(&self.tmp);
            return Ok(blob);
        }
        let mut raw = Vec::with_capacity(self.offsets.len() * 8);
        for off in &self.offsets {
            raw.extend_from_slice(&off.to_le_bytes());
        }
        let mut idx_tmp = self.tmp.clone().into_os_string();
        idx_tmp.push(".idx");
        fs::write(&idx_tmp, raw)?;
        fs::rename(&idx_tmp, &idx)?;
        fs::rename(&self.tmp, &dest)?;
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
}
