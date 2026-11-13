//! Content-addressed store for complete tool output.
//!
//! Every output is stored whole before the model sees any of it, so a cut or an eviction never loses
//! anything: the handle (`out:<id>`) pages and searches the original bytes.

use crate::ids::BlobId;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Temporary files in `tmp/` older than this are leftovers of a crashed writer and are removed when the store
/// opens; a younger one may belong to a writer in another process.
pub const STALE_TMP_AGE: Duration = Duration::from_secs(3600);

/// A blob younger than this is never collected: it may have been written just before the record that names it.
pub const DEFAULT_GC_MIN_AGE: Duration = Duration::from_secs(3600);

/// The shortest id prefix `resolve` accepts as a handle.
const MIN_HANDLE_LEN: usize = 8;

/// The length of the id prefix in the handle shown to the model (`BlobRef::handle`).
const HANDLE_LEN: usize = 16;

/// What a sweep found. With `applied == false` nothing was deleted and `collected*` are what would be. The
/// counts are blobs; the byte figures include each blob's index file and any index whose blob is gone.
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
        format!("out:{}", &self.id.0[..self.id.0.len().min(HANDLE_LEN)])
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

/// The ids of the blobs a store holds, sorted, for finding references to them in text (`scan_ids`).
#[derive(Clone, Debug, Default)]
pub struct StoredIds(Vec<String>);

impl FromIterator<String> for StoredIds {
    fn from_iter<I: IntoIterator<Item = String>>(ids: I) -> Self {
        let mut sorted: Vec<String> = ids.into_iter().collect();
        sorted.sort_unstable();
        sorted.dedup();
        StoredIds(sorted)
    }
}

impl StoredIds {
    fn contains(&self, id: &str) -> bool {
        self.0.binary_search_by(|stored| stored.as_str().cmp(id)).is_ok()
    }

    /// The stored ids that begin with `prefix`.
    fn starting_with(&self, prefix: &str) -> &[String] {
        let from = self.0.partition_point(|id| id.as_str() < prefix);
        let rest = self.0.get(from..).unwrap_or_default();
        rest.get(..rest.partition_point(|id| id.starts_with(prefix))).unwrap_or_default()
    }
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
        crate::config::ensure_private_dir(&root)?;
        crate::config::ensure_private_dir(&root.join("tmp"))?;
        remove_stale_tmp(&root.join("tmp"), STALE_TMP_AGE);
        Ok(Self { root })
    }

    /// The ids of every blob in the store now. Anything that cannot be listed is an error, so a blob is never
    /// missing from the answer while it is on disk.
    pub fn ids(&self) -> io::Result<StoredIds> {
        let mut ids = Vec::new();
        for shard in self.shards()? {
            for entry in fs::read_dir(shard)? {
                let name = entry?.file_name().to_string_lossy().into_owned();
                if is_id(&name) {
                    ids.push(name);
                }
            }
        }
        Ok(ids.into_iter().collect())
    }

    /// Delete blobs (and their index files) whose id is not in `keep` and whose file is older than `min_age`,
    /// and index files older than `min_age` whose blob is gone. With `apply == false` only counts. Anything
    /// that cannot be deleted is kept.
    ///
    /// Storing bytes that are already here refreshes the blob's age, or stores the blob again as a new file when
    /// the age cannot be refreshed (`BlobWriter::finish`), and a blob is moved out of the way before its age is
    /// read again and it is deleted (`remove_if_still_old`), so a blob that a store has just returned is never
    /// deleted.
    pub fn sweep(&self, keep: &HashSet<String>, min_age: Duration, apply: bool) -> io::Result<SweepReport> {
        let mut report = SweepReport { applied: apply, ..SweepReport::default() };
        let now = SystemTime::now();
        let old = |meta: &fs::Metadata| is_older(meta, now, min_age);
        for shard in self.shards()? {
            let Ok(entries) = fs::read_dir(shard) else { continue };
            let (mut blobs, mut indexes) = (Vec::new(), HashMap::new());
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                let Ok(meta) = entry.metadata() else { continue };
                if !meta.is_file() {
                    continue;
                }
                match name.strip_suffix(".idx") {
                    Some(id) if is_id(id) => {
                        indexes.insert(id.to_string(), meta);
                    }
                    None if is_id(&name) => blobs.push((name, meta)),
                    _ => {}
                }
            }
            for (id, meta) in blobs {
                let bytes = meta.len().saturating_add(indexes.remove(&id).map_or(0, |idx| idx.len()));
                let mut keep_it = keep.contains(&id) || !old(&meta);
                if !keep_it && apply {
                    keep_it = !self.remove_if_still_old(&id, min_age);
                }
                report.examined += 1;
                report.examined_bytes = report.examined_bytes.saturating_add(bytes);
                if keep_it {
                    report.kept += 1;
                    report.kept_bytes = report.kept_bytes.saturating_add(bytes);
                } else {
                    report.collected += 1;
                    report.collected_bytes = report.collected_bytes.saturating_add(bytes);
                }
            }
            // What is left are indexes without a blob (a crash between the two renames of a store, or between
            // the two unlinks here). They are inert; a young one may belong to a store that is finishing.
            for (id, meta) in indexes {
                let mut keep_it = !old(&meta) || self.path_of(&id).exists();
                if !keep_it && apply {
                    keep_it = fs::remove_file(self.idx_path(&BlobId(id))).is_err();
                }
                report.examined_bytes = report.examined_bytes.saturating_add(meta.len());
                if keep_it {
                    report.kept_bytes = report.kept_bytes.saturating_add(meta.len());
                } else {
                    report.collected_bytes = report.collected_bytes.saturating_add(meta.len());
                }
            }
        }
        Ok(report)
    }

    /// Delete one blob, then its index, unless the blob's age was refreshed since the caller looked at it.
    /// True when the blob was deleted.
    ///
    /// The blob is claimed first (moved into `tmp/`) and its age read after that. A store that deduplicates onto
    /// it either refreshed the age before the move, and the blob goes back, or finds it gone and stores it
    /// again (`BlobWriter::finish`). Blob before index: an index without a blob is inert and a later sweep
    /// removes it.
    fn remove_if_still_old(&self, id: &str, min_age: Duration) -> bool {
        let blob = self.path_of(id);
        let claimed = self.root.join("tmp").join(format!("gc-{id}"));
        if fs::rename(&blob, &claimed).is_err() {
            return false;
        }
        let still_old = fs::symlink_metadata(&claimed).is_ok_and(|meta| is_older(&meta, SystemTime::now(), min_age));
        if !still_old {
            // Should this fail, a store of the same bytes writes the blob again; the claim is a stale temp file.
            let _ = fs::rename(&claimed, &blob);
            return false;
        }
        let _ = fs::remove_file(&claimed);
        if !blob.exists() {
            let _ = fs::remove_file(self.idx_path(&BlobId(id.to_string())));
        }
        true
    }

    /// The shard directories that exist (`00` to `ff`).
    fn shards(&self) -> io::Result<Vec<PathBuf>> {
        let mut shards = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.len() == 2 && is_lower_hex(&name) {
                shards.push(entry.path());
            }
        }
        Ok(shards)
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
        let file = create_private(&tmp)?;
        Ok(BlobWriter {
            store: self.clone(),
            tmp,
            file,
            hasher: Sha256::new(),
            bytes: 0,
            offsets: Vec::new(),
            at_line_start: true,
        })
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
        let Some(id) = handle_prefix(handle) else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("not an output handle: {handle}")));
        };
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
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("ambiguous output handle: {handle}"),
                        ));
                    }
                    found = Some(name);
                }
            }
        }
        found.map(BlobId).ok_or_else(|| not_found(handle))
    }

    /// The stored outputs a handle (full id or prefix, `out:` accepted) could mean, sorted; at most `limit`.
    /// More than one means `resolve` refused the handle as ambiguous.
    pub fn candidates(&self, handle: &str, limit: usize) -> Vec<BlobId> {
        let Some(id) = handle_prefix(handle) else { return Vec::new() };
        let mut found: Vec<String> = Vec::new();
        if let Ok(entries) = fs::read_dir(self.root.join(&id[..2])) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.len() == 64 && name.starts_with(&id) {
                    found.push(name);
                }
            }
        }
        found.sort();
        found.into_iter().take(limit).map(BlobId).collect()
    }

    /// The blob's size, and its line count from the length of its index (rebuilt when it fails the checks of
    /// [`BlobStore::line_index`]).
    pub fn meta(&self, id: &BlobId) -> io::Result<BlobRef> {
        let blob = self.path_of(&id.0);
        let bytes = fs::metadata(&blob)?.len();
        let lines = match self.line_index(id, &blob, bytes)? {
            Some(index) => index.lines,
            None => self.rebuild_index(id, &blob)?.len() as u64,
        };
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

    /// The blob's line index, opened for reading single entries, when it passes the checks that cost the same
    /// however long it is: a whole number of 8-byte entries, none for an empty blob, the first 0, and the last
    /// above the first (when there are two or more), inside the blob and starting its last line (so a truncated
    /// index is noticed). `None` when it is missing or fails them.
    fn line_index(&self, id: &BlobId, blob: &Path, size: u64) -> io::Result<Option<LineIndex>> {
        let Ok(file) = File::open(self.idx_path(id)) else { return Ok(None) };
        let Ok(len) = file.metadata().map(|m| m.len()) else { return Ok(None) };
        if len % 8 != 0 {
            return Ok(None);
        }
        let mut index = LineIndex { file, lines: len / 8, last_start: 0 };
        if index.lines == 0 {
            return Ok((size == 0).then_some(index));
        }
        let last = index.lines.saturating_sub(1);
        let (Some(0), Some(last_start)) = (index.entry(0), index.entry(last)) else { return Ok(None) };
        if (last > 0 && last_start == 0) || last_start >= size || !starts_last_line(blob, last_start)? {
            return Ok(None);
        }
        index.last_start = last_start;
        Ok(Some(index))
    }

    /// Rebuild the line index from the blob (a missing, short or garbage index: a crash, a bad disk; the blob
    /// is the truth) and return its entries. Writing the new index is best effort.
    fn rebuild_index(&self, id: &BlobId, blob: &Path) -> io::Result<Vec<u64>> {
        #[cfg(test)]
        INDEX_REBUILDS.with(|rebuilds| rebuilds.set(rebuilds.get().saturating_add(1)));
        let offsets = scan_offsets(blob)?;
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

    /// Lines `start..=end` (1-based). Out-of-range bounds are clamped; an empty range gives empty text. Only
    /// the index entries the range needs are read; an index that fails their checks, or whose entries do not
    /// bound whole lines (see `read_span`), is rebuilt from the blob.
    pub fn read_lines(&self, id: &BlobId, start: u64, end: u64) -> io::Result<LineSlice> {
        let blob = self.path_of(&id.0);
        let size = fs::metadata(&blob)?.len();
        let first = start.max(1);
        if let Some(span) = self.line_index(id, &blob, size)?.and_then(|mut index| index.span(first, end, size)) {
            if let Some(slice) = read_span(&blob, &span, first, size)? {
                return Ok(slice);
            }
        }
        let span = span_of(&self.rebuild_index(id, &blob)?, first, end, size);
        span.map(|span| read_span(&blob, &span, first, size)).transpose()?.flatten().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, format!("the line index of {} is inconsistent", id.0))
        })
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

/// Add to `found` every blob of `stored` that the text in `reader` refers to: by its full id (64 hexadecimal
/// characters in either case, whatever surrounds them, also inside a longer hexadecimal run) or by a handle
/// (`out:` and the first 8 to 16 characters of the id, which is what `resolve` accepts; every blob that begins
/// that way counts). This is how a garbage collection learns which blobs are in use without knowing which
/// record field holds an id. Only stored ids are recorded, so `found` never outgrows the store.
pub fn scan_ids(reader: impl Read, stored: &StoredIds, found: &mut HashSet<String>) -> io::Result<()> {
    let mut reader = BufReader::new(reader);
    let mut scan = IdScan { stored, found, run: String::new(), handle: false, last4: 0 };
    loop {
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() {
            scan.end_run();
            return Ok(());
        }
        for b in chunk {
            scan.byte(*b);
        }
        let n = chunk.len();
        reader.consume(n);
    }
}

/// The state of one `scan_ids` pass.
struct IdScan<'a> {
    stored: &'a StoredIds,
    found: &'a mut HashSet<String>,
    /// The hexadecimal run being read, lower-cased. Only its last 63 characters are kept once it is long.
    run: String,
    /// The run began right after `out:` and has not been looked up as a handle yet.
    handle: bool,
    /// The last four bytes read.
    last4: u32,
}

impl IdScan<'_> {
    fn byte(&mut self, b: u8) {
        if b.is_ascii_hexdigit() {
            if self.run.is_empty() {
                self.handle = self.last4 == u32::from_be_bytes(*b"out:");
            }
            self.run.push(char::from(b.to_ascii_lowercase()));
            if self.handle && self.run.len() == HANDLE_LEN {
                self.keep_handle();
            }
            if let Some(id) = self.run.len().checked_sub(64).and_then(|at| self.run.get(at..)) {
                if self.stored.contains(id) && !self.found.contains(id) {
                    self.found.insert(id.to_string());
                }
            }
            if self.run.len() >= 4096 {
                let head = self.run.len().saturating_sub(63);
                self.run.replace_range(..head, "");
            }
        } else {
            self.end_run();
        }
        self.last4 = (self.last4 << 8) | u32::from(b);
    }

    /// Keep every stored blob whose id begins with the run so far, read as the id prefix of a handle.
    fn keep_handle(&mut self) {
        self.handle = false;
        for id in self.stored.starting_with(&self.run) {
            if !self.found.contains(id) {
                self.found.insert(id.clone());
            }
        }
    }

    fn end_run(&mut self) {
        if self.handle && self.run.len() >= MIN_HANDLE_LEN {
            self.keep_handle();
        }
        self.handle = false;
        self.run.clear();
    }
}

fn is_lower_hex(name: &str) -> bool {
    name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Whether a file name is a blob id as the store writes it.
fn is_id(name: &str) -> bool {
    name.len() == 64 && is_lower_hex(name)
}

/// Whether a file was last modified at least `min_age` before `now`. An unreadable or future time is not old.
fn is_older(meta: &fs::Metadata, now: SystemTime, min_age: Duration) -> bool {
    meta.modified().ok().and_then(|m| now.duration_since(m).ok()).is_some_and(|age| age >= min_age)
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

/// Create or truncate `path` as a file only the owner may read or write (mode 0600 on Unix, set at creation).
fn create_private(path: &Path) -> io::Result<File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

/// Write the index through `tmp` (synced) and rename it over `idx`.
fn write_index(tmp: &Path, idx: &Path, offsets: &[u64]) -> io::Result<()> {
    let mut raw = Vec::with_capacity(offsets.len().saturating_mul(8));
    for off in offsets {
        raw.extend_from_slice(&off.to_le_bytes());
    }
    let mut f = create_private(tmp)?;
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

#[cfg(test)]
thread_local! {
    /// Bytes of line index read on this thread, so that tests can see a page read leave the rest unread.
    static INDEX_BYTES_READ: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// Line indexes rebuilt on this thread, so that tests can see a sound index used as it is.
    static INDEX_REBUILDS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// A blob's line index on disk, read one entry at a time.
struct LineIndex {
    file: File,
    /// Entries, one per line.
    lines: u64,
    /// The last entry: where the blob's last line starts.
    last_start: u64,
}

/// Where a range of lines lies in a blob.
struct Span {
    /// Lines in the blob.
    total: u64,
    /// The last line of the range after clamping (`first - 1` for an empty range).
    last: u64,
    /// Start and end offset of the range's bytes; `None` for an empty range.
    bytes: Option<(u64, u64)>,
}

impl LineIndex {
    /// Entry `n`: where line `n + 1` starts. `None` when it cannot be read.
    fn entry(&mut self, n: u64) -> Option<u64> {
        let mut raw = [0u8; 8];
        self.file.seek(SeekFrom::Start(n.checked_mul(8)?)).ok()?;
        self.file.read_exact(&mut raw).ok()?;
        #[cfg(test)]
        INDEX_BYTES_READ.with(|read| read.set(read.get().saturating_add(8)));
        Some(u64::from_le_bytes(raw))
    }

    /// Lines `first..=end` (`first >= 1`) by the entries they need. `None` when those entries, between entry 0
    /// and the last entry, do not rise with the line number as the entries of a sound index do.
    fn span(&mut self, first: u64, end: u64, size: u64) -> Option<Span> {
        let (total, last_start) = (self.lines, self.last_start);
        let span = locate(total, first, end, size, |n| self.entry(n))?;
        let Some((from, to)) = span.bytes else { return Some(span) };
        let mut entries = vec![(0, 0), (first.saturating_sub(1), from)];
        if span.last < total {
            entries.push((span.last, to));
        }
        entries.push((total.saturating_sub(1), last_start));
        let rises = entries.windows(2).all(|pair| match pair {
            [(i, a), (j, b)] => {
                if i == j {
                    a == b
                } else {
                    a < b
                }
            }
            _ => false,
        });
        rises.then_some(span)
    }
}

/// Where lines `first..=end` (`first >= 1`, `end` clamped to `total`) lie in a blob of `size` bytes with `total`
/// lines; `entry(n)` gives where line `n + 1` starts. `None` when an entry it needs cannot be had.
fn locate(total: u64, first: u64, end: u64, size: u64, mut entry: impl FnMut(u64) -> Option<u64>) -> Option<Span> {
    let last = end.min(total);
    if total == 0 || first > last {
        return Some(Span { total, last: first.saturating_sub(1), bytes: None });
    }
    let from = entry(first.checked_sub(1)?)?;
    let to = if last < total { entry(last)? } else { size };
    Some(Span { total, last, bytes: Some((from, to)) })
}

/// [`locate`] over index entries held in memory (a rebuilt index).
fn span_of(offsets: &[u64], first: u64, end: u64, size: u64) -> Option<Span> {
    let entry = |n: u64| usize::try_from(n).ok().and_then(|n| offsets.get(n)).copied();
    locate(offsets.len() as u64, first, end, size, entry).filter(|span| span.bytes.is_none_or(|(from, to)| from <= to))
}

/// Lines `first..=span.last` read from the blob, when the bytes `span` names are whole lines and as many as the
/// range has: the byte before them (if any) is a newline, and they end with a newline holding one per line, or
/// end the blob holding one fewer (a last line without its own). `None` when they are not, which an index entry
/// that is wrong but still in order gives.
fn read_span(blob: &Path, span: &Span, first: u64, size: u64) -> io::Result<Option<LineSlice>> {
    let lines = |text: String| LineSlice { text, first, last: span.last, total: span.total };
    let Some((from, to)) = span.bytes else { return Ok(Some(lines(String::new()))) };
    // From the byte before the range, which has to end the line before it.
    let at = from.saturating_sub(1);
    let len = usize::try_from(to.saturating_sub(at))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "the requested lines do not fit in memory"))?;
    let mut file = File::open(blob)?;
    file.seek(SeekFrom::Start(at))?;
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf)?;
    let range = if from == 0 {
        buf.as_slice()
    } else {
        let Some((&b'\n', rest)) = buf.split_first() else { return Ok(None) };
        rest
    };
    let newlines = range.iter().filter(|b| **b == b'\n').count() as u64;
    let wanted = span.last.saturating_sub(first).saturating_add(1);
    let whole = match range.last() {
        Some(&b'\n') => newlines == wanted,
        Some(_) => to == size && newlines.saturating_add(1) == wanted,
        None => false,
    };
    Ok(whole.then(|| lines(String::from_utf8_lossy(range).into_owned())))
}

/// Whether the blob's last line starts at `start`: the byte before it (if any) is a newline and no newline
/// follows it except as the blob's final byte. This reads the last line, whatever the length of the index.
fn starts_last_line(blob: &Path, start: u64) -> io::Result<bool> {
    let mut reader = BufReader::new(File::open(blob)?);
    if let Some(before) = start.checked_sub(1) {
        reader.seek(SeekFrom::Start(before))?;
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte)?;
        if byte != *b"\n" {
            return Ok(false);
        }
    }
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

/// The lowercase hex a handle (`out:` accepted) stands for, when it is long enough to be one.
fn handle_prefix(handle: &str) -> Option<String> {
    let id = handle.trim().strip_prefix("out:").unwrap_or(handle.trim()).to_ascii_lowercase();
    (id.len() >= MIN_HANDLE_LEN && id.bytes().all(|b| b.is_ascii_hexdigit())).then_some(id)
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
            crate::config::ensure_private_dir(parent)?;
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
            let refreshed =
                fs::OpenOptions::new().write(true).open(&dest).and_then(|f| f.set_modified(SystemTime::now())).is_ok();
            // Still here after the refresh: done. Gone (a sweep took it meanwhile), or its age could not be
            // refreshed (a read-only file, say): stored again below, as a new file whose age is now.
            if refreshed && dest.exists() {
                let _ = fs::remove_file(&self.tmp);
                return Ok(blob);
            }
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

    #[cfg(unix)]
    #[test]
    fn blob_index_and_directories_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, s) = store();
        let b = s.put_bytes(b"one\ntwo\n").unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let blob = s.path_of(&b.id.0);
        assert_eq!(mode(&blob), 0o600);
        assert_eq!(mode(&s.idx_path(&b.id)), 0o600);
        for dir in [s.root.clone(), s.root.join("tmp"), blob.parent().unwrap().to_path_buf()] {
            assert_eq!(mode(&dir), 0o700, "{}", dir.display());
        }
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

    fn index_bytes_read() -> u64 {
        INDEX_BYTES_READ.with(|read| read.get())
    }

    fn index_rebuilds() -> u64 {
        INDEX_REBUILDS.with(|rebuilds| rebuilds.get())
    }

    #[test]
    fn a_page_reads_only_the_index_entries_it_needs() {
        let (_d, s) = store();
        let n = 300_000u64;
        let line = |i: u64| format!("line {i}\n");
        let b = s.put_bytes((1..=n).map(line).collect::<String>().as_bytes()).unwrap();
        let idx = s.idx_path(&b.id);
        assert_eq!(fs::metadata(&idx).unwrap().len(), 8 * n);
        let pristine = fs::read(&idx).unwrap();
        let rebuilds = index_rebuilds();
        for (first, last) in [(1, 3), (n / 2, n / 2 + 4), (n - 2, n), (n - 1, n + 50)] {
            let before = index_bytes_read();
            let page = s.read_lines(&b.id, first, last).unwrap();
            assert_eq!(page.text, (first..=last.min(n)).map(line).collect::<String>());
            assert_eq!((page.first, page.last, page.total), (first, last.min(n), n));
            // Entry 0, the last entry and the two around the range: 32 of 2.4 million bytes.
            assert!(index_bytes_read() - before <= 32, "read {} bytes of index", index_bytes_read() - before);
        }
        let before = index_bytes_read();
        assert_eq!(s.meta(&b.id).unwrap(), b);
        assert!(index_bytes_read() - before <= 16);
        assert_eq!(index_rebuilds(), rebuilds, "a sound index is used as it is, not rebuilt from the blob");
        assert_eq!(fs::read(&idx).unwrap(), pristine, "a sound index is not rewritten");

        // An entry the page needs out of order, one in order that points into the middle of its line, and the
        // last entry pointing into the middle of the last line: each time the index is rebuilt, and the page
        // is right.
        let entry = |line: u64| usize::try_from(line - 1).unwrap() * 8;
        let start_of = |line: u64| u64::from_le_bytes(pristine[entry(line)..entry(line) + 8].try_into().unwrap());
        for (damaged_line, value, first) in
            [(n / 2, u64::MAX, n / 2), (n / 2, start_of(n / 2) + 2, n / 2), (n, start_of(n) + 2, n)]
        {
            let mut damaged = pristine.clone();
            damaged[entry(damaged_line)..entry(damaged_line) + 8].copy_from_slice(&value.to_le_bytes());
            fs::write(&idx, &damaged).unwrap();
            let rebuilds = index_rebuilds();
            let page = s.read_lines(&b.id, first, first + 1).unwrap();
            assert_eq!(page.text, (first..=(first + 1).min(n)).map(line).collect::<String>());
            assert_eq!(index_rebuilds(), rebuilds + 1, "line {damaged_line} starting at {value}");
            assert_eq!(fs::read(&idx).unwrap(), pristine);
        }
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
        // Empty or short (truncated) index: storing the same bytes again repairs it, and so does reading.
        for damaged in [&b""[..], &0u64.to_le_bytes()[..]] {
            fs::write(&idx, damaged).unwrap();
            assert_eq!(s.put_bytes(data).unwrap(), b);
            assert_eq!(fs::metadata(&idx).unwrap().len(), 24);
            assert_eq!(s.meta(&b.id).unwrap().lines, 3);
            fs::write(&idx, damaged).unwrap();
            assert_eq!(s.read_lines(&b.id, 2, 3).unwrap().text, "two\nthree\n");
            assert_eq!(fs::metadata(&idx).unwrap().len(), 24);
        }
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
        // Two entries for one line, both 0: the count `meta` takes from the index's length would be wrong, so
        // the index is rebuilt.
        let one = s.put_bytes(b"hello\n").unwrap();
        fs::write(s.idx_path(&one.id), [0u64.to_le_bytes(), 0u64.to_le_bytes()].concat()).unwrap();
        assert_eq!(s.meta(&one.id).unwrap().lines, 1);
        assert_eq!(fs::metadata(s.idx_path(&one.id)).unwrap().len(), 8);
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
        // An index whose blob is gone (a crash between the renames of a store): old ones go, young ones stay.
        let (lost_old, lost_young) = (s.idx_path(&BlobId("e".repeat(64))), s.idx_path(&BlobId("f".repeat(64))));
        for (idx, age) in [(&lost_old, 7200), (&lost_young, 0)] {
            fs::create_dir_all(idx.parent().unwrap()).unwrap();
            fs::write(idx, 0u64.to_le_bytes()).unwrap();
            let f = fs::OpenOptions::new().write(true).open(idx).unwrap();
            f.set_modified(SystemTime::now() - Duration::from_secs(age)).unwrap();
        }
        let keep: HashSet<String> = [old_kept.id.0.clone()].into_iter().collect();
        // The byte figures count each blob with its index (8 bytes a line) and the orphaned indexes.
        let dry = s.sweep(&keep, DEFAULT_GC_MIN_AGE, false).unwrap();
        let want = SweepReport {
            examined: 3,
            examined_bytes: 5 + 5 + 6 + 3 * 8 + 2 * 8,
            kept: 2,
            kept_bytes: 5 + 6 + 2 * 8 + 8,
            collected: 1,
            collected_bytes: 5 + 8 + 8,
            applied: false,
        };
        assert_eq!(dry, want);
        assert!(s.path_of(&old_gone.id.0).exists() && lost_old.exists());
        let real = s.sweep(&keep, DEFAULT_GC_MIN_AGE, true).unwrap();
        assert_eq!(real, SweepReport { applied: true, ..want });
        assert!(!s.path_of(&old_gone.id.0).exists());
        assert!(!s.idx_path(&old_gone.id).exists());
        assert!(!lost_old.exists() && lost_young.exists());
        assert!(s.path_of(&old_kept.id.0).exists() && s.idx_path(&old_kept.id).exists());
        assert!(s.path_of(&young.id.0).exists());
        assert!(tmp_files(&s).is_empty());
    }

    #[test]
    fn a_blob_refreshed_after_the_sweep_looked_is_put_back() {
        let (_d, s) = store();
        let b = s.put_bytes(b"busy\n").unwrap();
        // Young when the claim looks (a store deduplicated onto it after the sweep listed it): put back.
        assert!(!s.remove_if_still_old(&b.id.0, DEFAULT_GC_MIN_AGE));
        assert!(s.path_of(&b.id.0).exists() && s.idx_path(&b.id).exists());
        assert!(tmp_files(&s).is_empty());
        // Old: deleted with its index, nothing left in tmp/.
        let f = fs::OpenOptions::new().write(true).open(s.path_of(&b.id.0)).unwrap();
        f.set_modified(SystemTime::now() - Duration::from_secs(7200)).unwrap();
        drop(f);
        assert!(s.remove_if_still_old(&b.id.0, DEFAULT_GC_MIN_AGE));
        assert!(!s.path_of(&b.id.0).exists() && !s.idx_path(&b.id).exists());
        assert!(tmp_files(&s).is_empty());
        // Already gone (another sweep took it): nothing to do.
        assert!(!s.remove_if_still_old(&b.id.0, DEFAULT_GC_MIN_AGE));
    }

    #[test]
    fn storing_bytes_whose_old_blob_cannot_be_refreshed_stores_them_again() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, s) = store();
        let b = s.put_bytes(b"pinned\n").unwrap();
        let path = s.path_of(&b.id.0);
        let f = fs::OpenOptions::new().write(true).open(&path).unwrap();
        f.set_modified(SystemTime::now() - Duration::from_secs(7200)).unwrap();
        drop(f);
        // Read-only: its age cannot be refreshed through it (unless the tests run as root).
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
        assert_eq!(s.put_bytes(b"pinned\n").unwrap(), b);
        // What was returned is a blob that a sweep sees as young, whole, with its index.
        let r = s.sweep(&HashSet::new(), DEFAULT_GC_MIN_AGE, true).unwrap();
        assert_eq!((r.kept, r.collected), (1, 0));
        assert_eq!(s.read_all(&b.id).unwrap(), b"pinned\n");
        assert_eq!(s.meta(&b.id).unwrap(), b);
        assert!(tmp_files(&s).is_empty());
    }

    fn set(ids: &[&String]) -> HashSet<String> {
        ids.iter().map(|id| id.to_string()).collect()
    }

    #[test]
    fn scan_ids_finds_stored_ids_and_handles_in_any_text() {
        let a = "a".repeat(64);
        let b = "0123456789abcdef".repeat(4);
        // Two blobs that share a handle: a handle keeps both.
        let (c1, c2) =
            (format!("{}{}", "c".repeat(16), "1".repeat(48)), format!("{}{}", "c".repeat(16), "2".repeat(48)));
        let d = "d".repeat(64);
        let stored: StoredIds = [&a, &b, &c1, &c2, &d].into_iter().cloned().collect();
        let text = format!(
            "{{\"x\":\"{a}\"}} id={}\\n\"out:{}\" 12345 {} out:dddddd",
            b.to_uppercase(),
            &c1[..16],
            "f".repeat(63)
        );
        let mut found = HashSet::new();
        scan_ids(text.as_bytes(), &stored, &mut found).unwrap();
        assert_eq!(found, set(&[&a, &b, &c1, &c2]), "a 6-character handle is not one");
        // Glued to other hex still counts, and a handle of 8 characters (what `resolve` accepts) does.
        let mut found = HashSet::new();
        scan_ids(format!("9{a} out:{}.", &d[..8]).as_bytes(), &stored, &mut found).unwrap();
        assert_eq!(found, set(&[&a, &d]));
    }

    #[test]
    fn scan_ids_records_only_stored_ids_however_much_hex_it_reads() {
        let id = "b".repeat(64);
        let stored: StoredIds = [id.clone()].into_iter().collect();
        // Long hash lists and an endless run: nothing names a stored blob, so nothing is recorded.
        let text = format!("{}\n", "0123456789abcdef".repeat(16)).repeat(10_000) + &"a".repeat(100_000);
        let mut found = HashSet::new();
        scan_ids(text.as_bytes(), &stored, &mut found).unwrap();
        assert!(found.is_empty());
        // The stored id deep inside such a run is still found.
        let glued = format!("{}{id}{}", "a".repeat(5000), "a".repeat(5000));
        scan_ids(glued.as_bytes(), &stored, &mut found).unwrap();
        assert_eq!(found, set(&[&id]));
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
