//! A child's own copy of the workspace: making it, saying what the child changed in it, and bringing
//! one child's changes back.
//!
//! CONTRACT.
//!
//! ## Making a copy
//! `make(source, dest, limits)` copies the directory `source` to `dest`, which must not exist and
//! must not lie inside `source` (nor `source` inside it). Everything is copied, build output and
//! `.git` included, so that what ran in the workspace runs in the copy without a rebuild or a
//! download — but for `<source>/.loom` (harness state and oracle secrets), and for what is neither a
//! file, a directory nor a symbolic link. Files are copied with `std::fs::copy`, which clones them
//! (no bytes are duplicated) where the file system can, as APFS does; their permission bits and
//! modification times are kept. A symbolic link is made again with the same target text and never
//! followed. An entry that cannot be read, or whose name is not UTF-8, is left out and counted
//! (`Made::skipped`).
//!
//! One kind of file is left out on purpose: a `.git` that is a file (the pointer of a linked Git
//! worktree or of a submodule) whose `gitdir:` is an absolute path, leaves the tree, or cannot be
//! read. Copied, it would make every Git command run in the copy act on the repository of the
//! original — its index, its `HEAD` — which is what a copy exists to prevent. Its relative path is
//! listed in `Made::git_left_out`; with `.git` itself in that list the copy is not a Git repository.
//! A pointer that is relative and stays inside the tree (a submodule's) names the copy's own
//! repository once copied, and is copied.
//!
//! Before anything is copied the tree is measured: more than `limits.max_files` files and links, or
//! more than `limits.max_bytes` bytes of file content (0 = no limit), and nothing is copied. The
//! limit on bytes is there for file systems where a copy duplicates them. Where files are cloned it
//! does not apply: that is found out by cloning one file of the tree to a path beside where the copy
//! will be (macOS `clonefile`; the probe is named for the copy, so copies made at the same time do
//! not share it, and is removed again), and `Made::cloned` says how it came out. Elsewhere, and when
//! the probe fails for any reason, the limit holds. A copy that fails part-way removes what it made.
//! All refusals are sentences for the model.
//!
//! ## The manifest
//! `Made::manifest` records what the copy was made from: for every file and link that Git would
//! not ignore — the rules of the `.gitignore` files in the tree and of `.git/info/exclude`, applied
//! whether or not the tree is a repository; `.git` directories themselves and `.loom` are left out —
//! its relative path (`/`-separated) and
//! - for a file, its size, modification time and permission bits in the source and, as read back, in
//!   the copy (a file system may round a time, so the two are kept apart);
//! - for a link, its target.
//!
//! Ignored files are in the copy and are not in the manifest: what a build wrote is not what a child
//! changed.
//!
//! Changes are told by size and time, so `make` returns only when no file written from then on can
//! get a time the manifest has: when the clock is 20 ms past the newest of them (a file system
//! takes its times from a clock that moves every few milliseconds), or 2 s past one in whole seconds
//! (a file system that keeps no fractions may keep only even seconds). It waits at most 2.5 s for
//! that, which is no wait at all unless a file was written just before; a time in the future is not
//! waited for.
//!
//! ## What changed
//! `changes(manifest, copy)` walks the copy by the same rules (with the copy's own ignore files) and
//! compares with the manifest: `added` (not in the manifest), `modified` (a file whose size, time or
//! permission bits differ from the copy's recorded ones; a link whose target differs; a file that
//! became a link or the reverse), `deleted` (in the manifest and no longer in the copy at all — a
//! file that is still there but is now ignored counts as unchanged). Each list is sorted.
//! `newest_ms` is the latest modification time among the added and modified files. A comparison by
//! size and time, as `rsync` makes by default: a change that keeps both is not seen. That takes a
//! program that sets a file's time back, or one that rewrote the file while the copy was being made.
//!
//! ## Adopting
//! `adopt(manifest, copy, dest, may_write)` brings those changes into `dest` (the workspace the copy
//! was made from): the added and modified files and links are written, the deleted ones removed.
//! Nothing is merged, and it is all or nothing as far as that can be known beforehand:
//! - a path that is in `dest` as the copy has it — a link with the same target, a file with the same
//!   permission bits and the same bytes — is left alone (so adopting twice, or after a crash
//!   part-way, is harmless, and the same change made on both sides is no conflict). The bytes are
//!   compared, not the times: two files written at one moment have the same time;
//! - otherwise the path must be in `dest` as the manifest recorded the source (for an added path:
//!   must not exist). Any path that is not — it was changed in the workspace since the copy was made
//!   — is a conflict, and with one conflict nothing is written (`AdoptError::Conflicts`);
//! - `may_write(path)` is asked for every path to be written or removed; one refusal and nothing is
//!   written (`AdoptError::Refused`, with the refusals).
//!
//! Then each file is copied beside its place and renamed over it, with the copy's time and
//! permission bits; directories are made as needed, and a directory of `dest` that a removal left
//! empty and that the copy no longer has is removed. What Git stores (`.git`) is never touched:
//! commits a child made in its copy stay there. A failure while writing is `AdoptError::Io`, with
//! what had been written by then.
//!
//! Tests required (temp dirs): a copy holds files, links, modes and times, leaves out `.loom`, and
//! its manifest leaves out ignored files and `.git`; a Git pointer that leaves the tree is left out
//! and one that stays inside is copied; the limit on bytes holds unless the copy is cloned, and the
//! probe leaves nothing behind; copies made at the same time agree on whether files are cloned; the
//! limits refuse before anything is written; a destination inside the source is refused; when a
//! copy is made the clock is past the times it recorded, and a file rewritten at once to the same
//! size is seen as changed, in the copy and in the workspace; changes lists added, modified, deleted
//! and ignores build output; adopt writes and removes exactly those, is harmless when repeated,
//! refuses on a conflict or a refused path without writing anything — also when the file in the
//! workspace has the size and time of the copy's and other bytes — takes the same change on both
//! sides for no conflict, and does not touch `.git`.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// How large a workspace may be to be copied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Most files and links.
    pub max_files: u64,
    /// Most bytes of file content; 0 = no limit.
    pub max_bytes: u64,
}

/// Size, modification time and permission bits of a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stamp {
    pub size: u64,
    pub secs: i64,
    pub nanos: u32,
    pub mode: u32,
}

/// One path of the manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Entry {
    File { source: Stamp, copy: Stamp },
    Link { target: String },
}

/// What a copy was made from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// The directory that was copied.
    pub source: String,
    pub made_ms: u64,
    /// The files and links Git would not ignore, by relative path.
    pub files: BTreeMap<String, Entry>,
}

/// A copy that was made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Made {
    pub manifest: Manifest,
    /// Files and links copied, ignored ones included.
    pub files: u64,
    /// Bytes of file content copied (or cloned).
    pub bytes: u64,
    /// Entries left out because they could not be read or named.
    pub skipped: u64,
    /// Git pointer files left out because they name a repository outside the copy, by relative path.
    pub git_left_out: Vec<String>,
    /// The file system clones files, so the copy shares its bytes with the original until they change.
    pub cloned: bool,
}

/// What differs between a copy and what it was made from.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Changes {
    pub added: Vec<String>,
    pub modified: Vec<String>,
    pub deleted: Vec<String>,
    /// The latest modification time among the added and modified files.
    pub newest_ms: Option<u64>,
}

impl Changes {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.modified.is_empty() && self.deleted.is_empty()
    }

    pub fn count(&self) -> usize {
        self.added.len() + self.modified.len() + self.deleted.len()
    }

    /// One line per path, `A`, `M` or `D` first, sorted by path.
    pub fn lines(&self) -> Vec<String> {
        let mut all: Vec<(&String, char)> = Vec::new();
        all.extend(self.added.iter().map(|p| (p, 'A')));
        all.extend(self.modified.iter().map(|p| (p, 'M')));
        all.extend(self.deleted.iter().map(|p| (p, 'D')));
        all.sort();
        all.into_iter().map(|(p, kind)| format!("{kind} {p}")).collect()
    }
}

/// Why nothing, or not everything, was adopted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdoptError {
    /// Paths the workspace changed since the copy was made, each with what is there now.
    Conflicts(Vec<(String, String)>),
    /// Paths that may not be written, each with the reason.
    Refused(Vec<(String, String)>),
    /// Writing failed; `written` paths had been brought over by then.
    Io { message: String, written: Vec<String> },
}

/// Directory names never looked into when listing what Git would not ignore.
const UNLISTED: [&str; 2] = [".git", ".loom"];

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)).unwrap_or(0)
}

fn stamp(md: &std::fs::Metadata) -> Stamp {
    let (secs, nanos) = match md.modified() {
        Ok(t) => match t.duration_since(UNIX_EPOCH) {
            Ok(d) => (i64::try_from(d.as_secs()).unwrap_or(i64::MAX), d.subsec_nanos()),
            // Before 1970: whole seconds back, which is enough to tell two times apart.
            Err(e) => (-i64::try_from(e.duration().as_secs()).unwrap_or(i64::MAX), 0),
        },
        Err(_) => (0, 0),
    };
    Stamp { size: md.len(), secs, nanos, mode: md.permissions().mode() & 0o7777 }
}

fn stamp_ms(s: &Stamp) -> u64 {
    u64::try_from(s.secs).unwrap_or(0).saturating_mul(1000).saturating_add(u64::from(s.nanos / 1_000_000))
}

/// Set the modification time of the file at `path` (not following a link) to that of `s`.
fn set_mtime(path: &Path, s: &Stamp) -> std::io::Result<()> {
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "the path contains a NUL byte"))?;
    let omit = libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT };
    let modified = libc::timespec { tv_sec: s.secs as libc::time_t, tv_nsec: s.nanos as libc::c_long };
    let times = [omit, modified];
    // SAFETY: `c` is a NUL-terminated path that lives for the call, and `times` is the two-element
    // array utimensat(2) reads; the call has no other memory effects.
    let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), libc::AT_SYMLINK_NOFOLLOW) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// What is at a path, as far as two trees are compared.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Seen {
    Absent,
    File(Stamp),
    Link(String),
    Dir,
    Other,
}

fn seen(path: &Path) -> Seen {
    let Ok(md) = std::fs::symlink_metadata(path) else { return Seen::Absent };
    let ft = md.file_type();
    if ft.is_symlink() {
        match std::fs::read_link(path) {
            Ok(t) => Seen::Link(t.to_string_lossy().into_owned()),
            Err(_) => Seen::Other,
        }
    } else if ft.is_file() {
        Seen::File(stamp(&md))
    } else if ft.is_dir() {
        Seen::Dir
    } else {
        Seen::Other
    }
}

fn describe(s: &Seen) -> &'static str {
    match s {
        Seen::Absent => "it is no longer there",
        Seen::File(_) => "the file there has changed",
        Seen::Link(_) => "there is a symbolic link there now",
        Seen::Dir => "there is a directory there now",
        Seen::Other => "there is something there that is not a file",
    }
}

/// Count what `make` would copy; an error as soon as a limit is passed.
fn measure(dir: &Path, top: bool, limits: &Limits, files: &mut u64, bytes: &mut u64) -> Result<(), String> {
    let Ok(entries) = std::fs::read_dir(dir) else { return Ok(()) };
    for entry in entries.flatten() {
        if top && entry.file_name() == ".loom" {
            continue;
        }
        let Ok(md) = entry.metadata() else { continue };
        let ft = md.file_type();
        if ft.is_dir() {
            measure(&entry.path(), false, limits, files, bytes)?;
        } else if ft.is_file() || ft.is_symlink() {
            *files += 1;
            if ft.is_file() {
                *bytes = bytes.saturating_add(md.len());
            }
            if *files > limits.max_files {
                return Err(format!(
                    "The workspace has more than {} files, which is the most a copy is made of (`agents.copy_max_files`). Start the agent without `workspace: \"copy\"` (it then works in your workspace), or give it a smaller directory to work in.",
                    limits.max_files
                ));
            }
            if limits.max_bytes > 0 && *bytes > limits.max_bytes {
                return Err(format!(
                    "The workspace holds more than {} MiB, which is the most a copy is made of (`agents.copy_max_mb`). Start the agent without `workspace: \"copy\"` (it then works in your workspace), or remove build output that is not needed first.",
                    limits.max_bytes / (1024 * 1024)
                ));
            }
        }
    }
    Ok(())
}

/// A regular file of the tree to try a clone with: the first one found, looking into directories in
/// the order they are listed, not into `.loom` at the top.
fn sample_file(dir: &Path, top: bool) -> Option<PathBuf> {
    let mut later = Vec::new();
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        if top && entry.file_name() == ".loom" {
            continue;
        }
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_file() {
            return Some(entry.path());
        }
        if ft.is_dir() {
            later.push(entry.path());
        }
    }
    later.iter().find_map(|d| sample_file(d, false))
}

/// Whether a file of the tree can be cloned to `probe`, which is beside where the copy will be: both
/// are then on one file system that shares the bytes of a copy with its original.
#[cfg(target_os = "macos")]
fn clones_to(sample: &Path, probe: &Path) -> bool {
    // One left by a run that was killed would make the clone fail.
    let _ = std::fs::remove_file(probe);
    let (Ok(from), Ok(to)) =
        (std::ffi::CString::new(sample.as_os_str().as_bytes()), std::ffi::CString::new(probe.as_os_str().as_bytes()))
    else {
        return false;
    };
    // SAFETY: both arguments are NUL-terminated paths that live for the call; clonefile(2) reads
    // them and has no other memory effects.
    let cloned = unsafe { libc::clonefile(from.as_ptr(), to.as_ptr(), 0) } == 0;
    let _ = std::fs::remove_file(probe);
    cloned
}

#[cfg(not(target_os = "macos"))]
fn clones_to(_sample: &Path, _probe: &Path) -> bool {
    false
}

/// Where the clone is tried for the copy at `dest`: named for it, so that copies made at the same
/// time in one directory do not try at the same path.
fn probe_path(dest: &Path) -> Option<PathBuf> {
    let name = dest.file_name()?.to_string_lossy().into_owned();
    Some(dest.with_file_name(format!(".{name}.loom-clone-probe")))
}

/// How far the clock must be past a recorded time before a file written from then on cannot carry
/// it. A file system that keeps fractions of a second takes its times from a clock that moves every
/// few milliseconds; one that keeps whole seconds may keep only the even ones.
const TICK: Duration = Duration::from_millis(20);
const WHOLE_SECONDS: Duration = Duration::from_millis(2_020);
/// The longest `make` waits for that. A time that lies in the future is not waited for.
const SETTLE_MAX: Duration = Duration::from_millis(2_500);

/// When the clock is past every time recorded in `files`; `None` when none is recorded.
fn settled_at(files: &BTreeMap<String, Entry>) -> Option<SystemTime> {
    let past = |s: &Stamp| {
        let secs = u64::try_from(s.secs).ok()?;
        let margin = if s.nanos == 0 { WHOLE_SECONDS } else { TICK };
        UNIX_EPOCH.checked_add(Duration::new(secs, s.nanos))?.checked_add(margin)
    };
    files
        .values()
        .filter_map(|entry| match entry {
            Entry::File { source, copy } => past(source).max(past(copy)),
            Entry::Link { .. } => None,
        })
        .max()
}

/// Whether two files hold the same bytes. One that cannot be read is not the same as anything.
fn same_bytes(a: &Path, b: &Path) -> bool {
    use std::io::Read;
    fn fill(file: &mut std::fs::File, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut have = 0;
        while let Some(rest) = buf.get_mut(have..).filter(|r| !r.is_empty()) {
            match file.read(rest) {
                Ok(0) => break,
                Ok(n) => have += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(have)
    }
    let (Ok(mut fa), Ok(mut fb)) = (std::fs::File::open(a), std::fs::File::open(b)) else { return false };
    let (mut ba, mut bb) = (vec![0u8; 1 << 16], vec![0u8; 1 << 16]);
    loop {
        let (Ok(na), Ok(nb)) = (fill(&mut fa, &mut ba), fill(&mut fb, &mut bb)) else { return false };
        if na != nb || ba.get(..na) != bb.get(..nb) {
            return false;
        }
        if na == 0 {
            return true;
        }
    }
}

struct Copier {
    /// Source and copy stamps of every file copied, and the target of every link, by relative path.
    done: BTreeMap<String, Entry>,
    files: u64,
    bytes: u64,
    skipped: u64,
    git_left_out: Vec<String>,
}

/// Whether the Git pointer file `file`, at the relative path `rel` of the tree, names a repository
/// that is not inside the tree: an absolute `gitdir:`, one that climbs out, or a file that cannot be
/// read as a pointer.
fn points_outside(file: &Path, rel: &str) -> bool {
    let Ok(text) = std::fs::read_to_string(file) else { return true };
    let Some(target) = text.lines().find_map(|l| l.strip_prefix("gitdir:")).map(str::trim) else { return true };
    // How far below the root the directory of the pointer is; the target is relative to it.
    let mut depth = rel.split('/').count().saturating_sub(1);
    for part in Path::new(target).components() {
        match part {
            std::path::Component::CurDir => {}
            std::path::Component::Normal(_) => depth += 1,
            std::path::Component::ParentDir if depth > 0 => depth -= 1,
            _ => return true,
        }
    }
    false
}

impl Copier {
    fn dir(&mut self, source: &Path, dest: &Path, rel: &str) -> std::io::Result<()> {
        let entries = match std::fs::read_dir(source) {
            Ok(e) => e,
            Err(_) => {
                self.skipped += 1;
                return Ok(());
            }
        };
        for entry in entries {
            let Ok(entry) = entry else {
                self.skipped += 1;
                continue;
            };
            let name = entry.file_name();
            if rel.is_empty() && name == ".loom" {
                continue;
            }
            let (Some(name_text), Ok(md)) = (name.to_str(), entry.metadata()) else {
                self.skipped += 1;
                continue;
            };
            let child_rel = if rel.is_empty() { name_text.to_string() } else { format!("{rel}/{name_text}") };
            let (from, to) = (entry.path(), dest.join(&name));
            let ft = md.file_type();
            if ft.is_symlink() {
                match std::fs::read_link(&from) {
                    Ok(target) => {
                        std::os::unix::fs::symlink(&target, &to)?;
                        self.files += 1;
                        self.done.insert(child_rel, Entry::Link { target: target.to_string_lossy().into_owned() });
                    }
                    Err(_) => self.skipped += 1,
                }
            } else if ft.is_dir() {
                std::fs::create_dir(&to)?;
                self.dir(&from, &to, &child_rel)?;
                // After its contents: a directory nobody may write to can still be filled.
                let _ = std::fs::set_permissions(&to, md.permissions());
            } else if ft.is_file() {
                if name == ".git" && points_outside(&from, &child_rel) {
                    self.git_left_out.push(child_rel);
                    continue;
                }
                let source = stamp(&md);
                match std::fs::copy(&from, &to) {
                    Ok(_) => {}
                    // The file could not be read (or went away): the copy goes on without it.
                    Err(e)
                        if matches!(e.kind(), std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotFound) =>
                    {
                        let _ = std::fs::remove_file(&to);
                        self.skipped += 1;
                        continue;
                    }
                    Err(e) => return Err(e),
                }
                set_mtime(&to, &source)?;
                let copy = stamp(&std::fs::symlink_metadata(&to)?);
                self.files += 1;
                self.bytes = self.bytes.saturating_add(source.size);
                self.done.insert(child_rel, Entry::File { source, copy });
            }
        }
        Ok(())
    }
}

/// The relative paths of the files and links under `root` that Git would not ignore.
fn listed(root: &Path) -> Result<BTreeSet<String>, String> {
    let mut walk = ignore::WalkBuilder::new(root);
    walk.hidden(false)
        .parents(false)
        .ignore(false)
        .git_global(false)
        .git_ignore(true)
        .git_exclude(true)
        .require_git(false)
        .follow_links(false)
        .filter_entry(|e| !UNLISTED.iter().any(|n| e.file_name() == *n));
    let mut out = BTreeSet::new();
    for entry in walk.build() {
        let entry = entry.map_err(|e| format!("{} could not be read: {e}", root.display()))?;
        let Some(ft) = entry.file_type() else { continue };
        if !(ft.is_file() || ft.is_symlink()) {
            continue;
        }
        if let Some(rel) = entry.path().strip_prefix(root).ok().and_then(Path::to_str) {
            out.insert(rel.to_string());
        }
    }
    Ok(out)
}

/// See the module contract.
pub fn make(source: &Path, dest: &Path, limits: &Limits) -> Result<Made, String> {
    if !source.is_dir() {
        return Err(format!("{} is not a directory, so no copy of it can be made.", source.display()));
    }
    if dest.starts_with(source) || source.starts_with(dest) {
        return Err(format!(
            "A copy of {} cannot be made at {}: one lies inside the other. Ask the operator to set the loom home outside the workspace.",
            source.display(),
            dest.display()
        ));
    }
    if std::fs::symlink_metadata(dest).is_ok() {
        return Err(format!("{} exists already, so no copy can be made there. Try the call again.", dest.display()));
    }
    let failed = |e: std::io::Error| {
        let _ = std::fs::remove_dir_all(dest);
        format!("The copy of {} could not be made at {}: {e}. Nothing is left of it.", source.display(), dest.display())
    };
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(failed)?;
    }
    // Bytes that a copy shares with its original are not bytes to be afraid of.
    let cloned = match (probe_path(dest), sample_file(source, true)) {
        (Some(probe), Some(sample)) => clones_to(&sample, &probe),
        _ => false,
    };
    let measured = Limits { max_files: limits.max_files, max_bytes: if cloned { 0 } else { limits.max_bytes } };
    let (mut files, mut bytes) = (0u64, 0u64);
    measure(source, true, &measured, &mut files, &mut bytes)?;
    std::fs::create_dir(dest).map_err(failed)?;
    let mut copier = Copier { done: BTreeMap::new(), files: 0, bytes: 0, skipped: 0, git_left_out: Vec::new() };
    copier.dir(source, dest, "").map_err(failed)?;
    let keep = listed(dest).inspect_err(|_| {
        let _ = std::fs::remove_dir_all(dest);
    })?;
    let Copier { done, files, bytes, skipped, mut git_left_out } = copier;
    git_left_out.sort();
    let files_listed: BTreeMap<String, Entry> = done.into_iter().filter(|(rel, _)| keep.contains(rel)).collect();
    // From here on a file that is written gets a time that none of the recorded ones is.
    if let Some(wait) = settled_at(&files_listed).and_then(|at| at.duration_since(SystemTime::now()).ok()) {
        std::thread::sleep(wait.min(SETTLE_MAX));
    }
    Ok(Made {
        manifest: Manifest { source: source.display().to_string(), made_ms: now_ms(), files: files_listed },
        files,
        bytes,
        skipped,
        git_left_out,
        cloned,
    })
}

/// Whether what is at a path of the copy is what the manifest recorded for it.
fn unchanged_in_copy(entry: &Entry, now: &Seen) -> bool {
    match (entry, now) {
        (Entry::File { copy, .. }, Seen::File(s)) => copy == s,
        (Entry::Link { target }, Seen::Link(t)) => target == t,
        _ => false,
    }
}

/// Whether a path is in the workspace (`there`) as the copy has it (`here`): a link with the same
/// target, or a file with the same permission bits and bytes. Their times are not asked: two files
/// written at one moment have the same time, and a file system may round the one it is given.
fn as_the_copy_has_it(there: &Seen, here: &Seen, in_dest: &Path, in_copy: &Path) -> bool {
    match (there, here) {
        (Seen::Link(a), Seen::Link(b)) => a == b,
        (Seen::File(a), Seen::File(b)) => a.size == b.size && a.mode == b.mode && same_bytes(in_dest, in_copy),
        _ => false,
    }
}

/// Whether what is at a path of the workspace is what the copy was made from.
fn unchanged_in_source(entry: &Entry, now: &Seen) -> bool {
    match (entry, now) {
        (Entry::File { source, .. }, Seen::File(s)) => source == s,
        (Entry::Link { target }, Seen::Link(t)) => target == t,
        _ => false,
    }
}

/// See the module contract.
pub fn changes(manifest: &Manifest, copy: &Path) -> Result<Changes, String> {
    let now = listed(copy)?;
    let mut out = Changes::default();
    let mut newest = None::<u64>;
    for rel in &now {
        let state = seen(&copy.join(rel));
        let changed = match manifest.files.get(rel) {
            None => {
                out.added.push(rel.clone());
                true
            }
            Some(entry) if !unchanged_in_copy(entry, &state) => {
                out.modified.push(rel.clone());
                true
            }
            Some(_) => false,
        };
        if let (true, Seen::File(s)) = (changed, &state) {
            newest = newest.max(Some(stamp_ms(s)));
        }
    }
    for rel in manifest.files.keys() {
        // Still there but ignored now (the child changed an ignore file): not a deletion.
        if !now.contains(rel) && seen(&copy.join(rel)) == Seen::Absent {
            out.deleted.push(rel.clone());
        }
    }
    out.newest_ms = newest;
    Ok(out)
}

/// A path in `dest` that a removal may have left an empty directory at: removed, with its empty
/// parents, as far as the copy has no such directory either.
fn prune(dest: &Path, copy: &Path, rel: &str) {
    let mut dir = Path::new(rel).parent();
    while let Some(d) = dir.filter(|d| !d.as_os_str().is_empty()) {
        if copy.join(d).exists() || std::fs::remove_dir(dest.join(d)).is_err() {
            return;
        }
        dir = d.parent();
    }
}

/// Bring one path of the copy to `dest`: beside its place first, then renamed over it.
fn bring(copy: &Path, dest: &Path, rel: &str) -> std::io::Result<()> {
    let (from, to) = (copy.join(rel), dest.join(rel));
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let name = to.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let beside = to.with_file_name(format!(".{name}.loom-adopt"));
    let _ = std::fs::remove_file(&beside);
    let made = match seen(&from) {
        Seen::Link(target) => std::os::unix::fs::symlink(PathBuf::from(target), &beside),
        Seen::File(s) => std::fs::copy(&from, &beside).and_then(|_| set_mtime(&beside, &s)),
        _ => Err(std::io::Error::new(std::io::ErrorKind::NotFound, "it is no longer a file in the copy")),
    };
    let moved = made.and_then(|()| std::fs::rename(&beside, &to));
    if moved.is_err() {
        let _ = std::fs::remove_file(&beside);
    }
    moved
}

/// See the module contract. `Ok`: what was brought over (paths already as the copy has them are not
/// listed).
pub fn adopt(
    manifest: &Manifest,
    copy: &Path,
    dest: &Path,
    may_write: &dyn Fn(&Path) -> Result<(), String>,
) -> Result<Changes, AdoptError> {
    let all = changes(manifest, copy).map_err(|message| AdoptError::Io { message, written: Vec::new() })?;
    let mut todo = Changes { newest_ms: all.newest_ms, ..Changes::default() };
    let mut conflicts = Vec::new();
    for (rel, added) in all.added.iter().map(|r| (r, true)).chain(all.modified.iter().map(|r| (r, false))) {
        let (in_dest, in_copy) = (dest.join(rel), copy.join(rel));
        let there = seen(&in_dest);
        // Adopted already, or the same change was made on both sides.
        if as_the_copy_has_it(&there, &seen(&in_copy), &in_dest, &in_copy) {
            continue;
        }
        let as_copied = match manifest.files.get(rel) {
            None => there == Seen::Absent,
            Some(entry) => unchanged_in_source(entry, &there),
        };
        if !as_copied {
            let what = if there != Seen::Absent && !manifest.files.contains_key(rel) {
                "a path of that name has appeared there"
            } else {
                describe(&there)
            };
            conflicts.push((rel.clone(), what.to_string()));
        } else if added {
            todo.added.push(rel.clone());
        } else {
            todo.modified.push(rel.clone());
        }
    }
    for rel in &all.deleted {
        let there = seen(&dest.join(rel));
        if there == Seen::Absent {
            continue;
        }
        match manifest.files.get(rel) {
            Some(entry) if unchanged_in_source(entry, &there) => todo.deleted.push(rel.clone()),
            _ => conflicts.push((rel.clone(), describe(&there).to_string())),
        }
    }
    if !conflicts.is_empty() {
        return Err(AdoptError::Conflicts(conflicts));
    }
    let refused: Vec<(String, String)> = todo
        .added
        .iter()
        .chain(&todo.modified)
        .chain(&todo.deleted)
        .filter_map(|rel| may_write(&dest.join(rel)).err().map(|why| (rel.clone(), why)))
        .collect();
    if !refused.is_empty() {
        return Err(AdoptError::Refused(refused));
    }
    let mut written = Vec::new();
    for rel in todo.added.iter().chain(&todo.modified) {
        if let Err(e) = bring(copy, dest, rel) {
            return Err(AdoptError::Io { message: format!("{rel} could not be written: {e}"), written });
        }
        written.push(rel.clone());
    }
    for rel in &todo.deleted {
        if let Err(e) = std::fs::remove_file(dest.join(rel)) {
            return Err(AdoptError::Io { message: format!("{rel} could not be removed: {e}"), written });
        }
        written.push(rel.clone());
        prune(dest, copy, rel);
    }
    Ok(todo)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::fs;

    const ROOMY: Limits = Limits { max_files: 10_000, max_bytes: 0 };

    struct Fx {
        _dir: tempfile::TempDir,
        ws: PathBuf,
        copy: PathBuf,
    }

    /// A workspace with tracked files, a link, an executable, build output that is ignored, Git
    /// metadata and harness state.
    fn fx() -> Fx {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let ws = root.join("ws");
        for d in ["src", "target/debug", ".git", ".loom/oracle-secrets", "docs"] {
            fs::create_dir_all(ws.join(d)).unwrap();
        }
        fs::write(ws.join(".gitignore"), "target/\n*.log\n").unwrap();
        fs::write(ws.join("src/a.rs"), "fn a() {}\n").unwrap();
        fs::write(ws.join("src/b.rs"), "fn b() {}\n").unwrap();
        fs::write(ws.join("docs/old.md"), "old\n").unwrap();
        fs::write(ws.join("run.sh"), "#!/bin/sh\necho hi\n").unwrap();
        fs::set_permissions(ws.join("run.sh"), fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink("src/a.rs", ws.join("link")).unwrap();
        fs::write(ws.join("target/debug/app"), "binary").unwrap();
        fs::write(ws.join("build.log"), "log").unwrap();
        fs::write(ws.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(ws.join(".loom/oracle-secrets/key"), "secret").unwrap();
        Fx { copy: root.join("copies/m/c1"), ws, _dir: dir }
    }

    fn allow(_: &Path) -> Result<(), String> {
        Ok(())
    }

    fn mtime(p: &Path) -> SystemTime {
        fs::metadata(p).unwrap().modified().unwrap()
    }

    #[test]
    fn a_copy_holds_everything_but_harness_state_and_its_manifest_leaves_out_what_git_ignores() {
        let f = fx();
        let made = make(&f.ws, &f.copy, &ROOMY).unwrap();
        // Build output and Git metadata are there, so the copy runs as the workspace does.
        assert_eq!(fs::read_to_string(f.copy.join("target/debug/app")).unwrap(), "binary");
        assert_eq!(fs::read_to_string(f.copy.join(".git/HEAD")).unwrap(), "ref: refs/heads/main\n");
        assert_eq!(fs::read_to_string(f.copy.join("src/a.rs")).unwrap(), "fn a() {}\n");
        assert!(!f.copy.join(".loom").exists(), "harness state and oracle secrets are not copied");
        assert_eq!(fs::read_link(f.copy.join("link")).unwrap(), PathBuf::from("src/a.rs"));
        assert_eq!(fs::metadata(f.copy.join("run.sh")).unwrap().permissions().mode() & 0o777, 0o755);
        assert_eq!(mtime(&f.copy.join("src/a.rs")), mtime(&f.ws.join("src/a.rs")));
        assert_eq!(made.files, 9);
        assert_eq!(made.skipped, 0);
        let paths: Vec<&str> = made.manifest.files.keys().map(String::as_str).collect();
        assert_eq!(paths, [".gitignore", "docs/old.md", "link", "run.sh", "src/a.rs", "src/b.rs"]);
        assert_eq!(made.manifest.files.get("link"), Some(&Entry::Link { target: "src/a.rs".into() }));
        assert_eq!(made.manifest.source, f.ws.display().to_string());
        // Nothing has changed yet.
        assert!(changes(&made.manifest, &f.copy).unwrap().is_empty());
    }

    #[test]
    fn the_limits_and_a_bad_destination_refuse_before_anything_is_written() {
        let f = fx();
        let e = make(&f.ws, &f.copy, &Limits { max_files: 3, max_bytes: 0 }).unwrap_err();
        assert!(e.contains("more than 3 files") && e.contains("agents.copy_max_files"), "{e}");
        assert!(!f.copy.exists());
        fs::write(f.ws.join("big"), vec![0u8; 3 * 1024 * 1024]).unwrap();
        let tight = Limits { max_files: 1000, max_bytes: 2 * 1024 * 1024 };
        let (mut files, mut bytes) = (0, 0);
        let e = measure(&f.ws, true, &tight, &mut files, &mut bytes).unwrap_err();
        assert!(e.contains("more than 2 MiB") && e.contains("agents.copy_max_mb"), "{e}");
        // The limit on bytes holds exactly where a copy duplicates them.
        match make(&f.ws, &f.copy, &tight) {
            Ok(made) => {
                assert!(made.cloned, "a copy past the limit was made without cloning");
                fs::remove_dir_all(&f.copy).unwrap();
            }
            Err(e) => {
                assert!(e.contains("more than 2 MiB"), "{e}");
                assert!(!f.copy.exists());
            }
        }
        // The probe leaves nothing behind.
        let beside: Vec<_> = fs::read_dir(f.copy.parent().unwrap()).unwrap().flatten().map(|e| e.file_name()).collect();
        assert!(!beside.iter().any(|n| n.to_string_lossy().contains("clone-probe")), "{beside:?}");
        let e = make(&f.ws, &f.ws.join("inside"), &ROOMY).unwrap_err();
        assert!(e.contains("one lies inside the other"), "{e}");
        assert!(!f.ws.join("inside").exists());
        fs::create_dir_all(&f.copy).unwrap();
        let e = make(&f.ws, &f.copy, &ROOMY).unwrap_err();
        assert!(e.contains("exists already"), "{e}");
    }

    #[test]
    fn changes_lists_what_the_child_did_and_not_what_a_build_wrote() {
        let f = fx();
        let made = make(&f.ws, &f.copy, &ROOMY).unwrap();
        fs::write(f.copy.join("src/a.rs"), "fn a() { 1 }\n").unwrap();
        fs::write(f.copy.join("src/new.rs"), "fn n() {}\n").unwrap();
        fs::remove_file(f.copy.join("docs/old.md")).unwrap();
        fs::set_permissions(f.copy.join("src/b.rs"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::remove_file(f.copy.join("link")).unwrap();
        std::os::unix::fs::symlink("src/b.rs", f.copy.join("link")).unwrap();
        // A build and a commit in the copy.
        fs::write(f.copy.join("target/debug/app"), "rebuilt").unwrap();
        fs::write(f.copy.join("test.log"), "log").unwrap();
        fs::write(f.copy.join(".git/HEAD"), "0123\n").unwrap();
        let c = changes(&made.manifest, &f.copy).unwrap();
        assert_eq!(c.added, ["src/new.rs"]);
        assert_eq!(c.modified, ["link", "src/a.rs", "src/b.rs"]);
        assert_eq!(c.deleted, ["docs/old.md"]);
        assert_eq!(c.lines(), ["D docs/old.md", "M link", "M src/a.rs", "M src/b.rs", "A src/new.rs"]);
        assert_eq!(c.count(), 5);
        assert!(c.newest_ms.is_some());
        // A file the child made Git ignore is still there: not a deletion.
        fs::write(f.copy.join(".gitignore"), "target/\n*.log\nrun.sh\n").unwrap();
        let c = changes(&made.manifest, &f.copy).unwrap();
        assert!(!c.deleted.contains(&"run.sh".to_string()), "{c:?}");
    }

    #[test]
    fn adopt_brings_exactly_the_changes_and_is_harmless_when_repeated() {
        let f = fx();
        let made = make(&f.ws, &f.copy, &ROOMY).unwrap();
        fs::write(f.copy.join("src/a.rs"), "fn a() { 1 }\n").unwrap();
        fs::create_dir_all(f.copy.join("tests/deep")).unwrap();
        fs::write(f.copy.join("tests/deep/t.rs"), "#[test] fn t() {}\n").unwrap();
        fs::remove_file(f.copy.join("docs/old.md")).unwrap();
        fs::remove_dir(f.copy.join("docs")).unwrap();
        fs::write(f.copy.join("target/debug/app"), "rebuilt").unwrap();
        fs::write(f.copy.join(".git/HEAD"), "0123\n").unwrap();
        let asked = std::cell::RefCell::new(Vec::new());
        let may = |p: &Path| {
            asked.borrow_mut().push(p.to_path_buf());
            Ok(())
        };
        let done = adopt(&made.manifest, &f.copy, &f.ws, &may).unwrap();
        assert_eq!(done.lines(), ["D docs/old.md", "M src/a.rs", "A tests/deep/t.rs"]);
        assert_eq!(asked.borrow().len(), 3);
        assert_eq!(fs::read_to_string(f.ws.join("src/a.rs")).unwrap(), "fn a() { 1 }\n");
        assert_eq!(fs::read_to_string(f.ws.join("tests/deep/t.rs")).unwrap(), "#[test] fn t() {}\n");
        assert!(!f.ws.join("docs").exists(), "the directory the removal emptied is gone");
        // What the copy did not change, what Git ignores and what Git stores are as they were.
        assert_eq!(fs::read_to_string(f.ws.join("src/b.rs")).unwrap(), "fn b() {}\n");
        assert_eq!(fs::read_to_string(f.ws.join("target/debug/app")).unwrap(), "binary");
        assert_eq!(fs::read_to_string(f.ws.join(".git/HEAD")).unwrap(), "ref: refs/heads/main\n");
        assert_eq!(fs::read_to_string(f.ws.join(".loom/oracle-secrets/key")).unwrap(), "secret");
        assert!(fs::read_dir(f.ws.join("src"))
            .unwrap()
            .flatten()
            .all(|e| !e.file_name().to_string_lossy().contains("loom-adopt")));
        // A second time there is nothing left to bring.
        let again = adopt(&made.manifest, &f.copy, &f.ws, &allow).unwrap();
        assert!(again.is_empty(), "{again:?}");
    }

    #[test]
    fn adopt_writes_nothing_when_the_workspace_changed_too_or_a_path_is_refused() {
        let f = fx();
        let made = make(&f.ws, &f.copy, &ROOMY).unwrap();
        fs::write(f.copy.join("src/a.rs"), "fn a() { 1 }\n").unwrap();
        fs::write(f.copy.join("src/b.rs"), "fn b() { 2 }\n").unwrap();
        fs::write(f.copy.join("new.txt"), "from the copy\n").unwrap();
        fs::write(f.copy.join("run.sh"), "#!/bin/sh\necho yo\n").unwrap();
        fs::remove_file(f.copy.join("docs/old.md")).unwrap();
        // Meanwhile, in the workspace: two of those files were edited, another path of the same name
        // appeared, and the file the copy removed was changed.
        fs::write(f.ws.join("src/a.rs"), "fn a() { lead }\n").unwrap();
        fs::write(f.ws.join("new.txt"), "from the lead\n").unwrap();
        fs::write(f.ws.join("run.sh"), "#!/bin/sh\necho no\n").unwrap();
        fs::write(f.ws.join("docs/old.md"), "old, edited\n").unwrap();
        // Two of them have the size of the copy's and, as files written at one moment do, its time:
        // only their bytes say that they are not what the copy has.
        for same in ["new.txt", "run.sh"] {
            set_mtime(&f.ws.join(same), &stamp(&fs::metadata(f.copy.join(same)).unwrap())).unwrap();
            assert_eq!(seen(&f.ws.join(same)), seen(&f.copy.join(same)), "{same}");
        }
        let Err(AdoptError::Conflicts(conflicts)) = adopt(&made.manifest, &f.copy, &f.ws, &allow) else {
            panic!("conflicts expected")
        };
        let paths: Vec<&str> = conflicts.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(paths, ["new.txt", "run.sh", "src/a.rs", "docs/old.md"]);
        assert_eq!(conflicts[0].1, "a path of that name has appeared there");
        assert_eq!(conflicts[1].1, "the file there has changed");
        assert_eq!(conflicts[2].1, "the file there has changed");
        // Nothing was written, not even the file without a conflict.
        assert_eq!(fs::read_to_string(f.ws.join("src/b.rs")).unwrap(), "fn b() {}\n");
        assert_eq!(fs::read_to_string(f.ws.join("new.txt")).unwrap(), "from the lead\n");
        assert_eq!(fs::read_to_string(f.ws.join("run.sh")).unwrap(), "#!/bin/sh\necho no\n");

        // Without the conflicts, a path that may not be written stops everything as well.
        let g = fx();
        let made = make(&g.ws, &g.copy, &ROOMY).unwrap();
        fs::write(g.copy.join("src/a.rs"), "fn a() { 1 }\n").unwrap();
        fs::write(g.copy.join("run.sh"), "#!/bin/sh\necho changed\n").unwrap();
        let may = |p: &Path| if p.ends_with("run.sh") { Err("protected".to_string()) } else { Ok(()) };
        let Err(AdoptError::Refused(refused)) = adopt(&made.manifest, &g.copy, &g.ws, &may) else {
            panic!("a refusal expected")
        };
        assert_eq!(refused, [("run.sh".to_string(), "protected".to_string())]);
        assert_eq!(fs::read_to_string(g.ws.join("src/a.rs")).unwrap(), "fn a() {}\n");
    }

    #[test]
    fn the_same_change_on_both_sides_is_no_conflict_and_is_not_brought() {
        let f = fx();
        let made = make(&f.ws, &f.copy, &ROOMY).unwrap();
        for side in [&f.copy, &f.ws] {
            fs::write(side.join("src/a.rs"), "fn a() { same }\n").unwrap();
            fs::write(side.join("notes.txt"), "the same\n").unwrap();
        }
        fs::write(f.copy.join("src/b.rs"), "fn b() { 2 }\n").unwrap();
        let asked = std::cell::RefCell::new(Vec::new());
        let may = |p: &Path| {
            asked.borrow_mut().push(p.to_path_buf());
            Ok(())
        };
        let done = adopt(&made.manifest, &f.copy, &f.ws, &may).unwrap();
        assert_eq!(done.lines(), ["M src/b.rs"]);
        assert_eq!(*asked.borrow(), [f.ws.join("src/b.rs")]);
        assert_eq!(fs::read_to_string(f.ws.join("src/b.rs")).unwrap(), "fn b() { 2 }\n");
    }

    #[test]
    fn when_a_copy_is_made_the_clock_is_past_the_times_it_recorded() {
        let at = |secs: i64, nanos: u32| Stamp { size: 1, secs, nanos, mode: 0o644 };
        let file = |s: Stamp| Entry::File { source: s, copy: s };
        let mut files = BTreeMap::new();
        assert_eq!(settled_at(&files), None);
        files.insert("link".to_string(), Entry::Link { target: "x".into() });
        files.insert("old".to_string(), file(at(-5, 0)));
        assert_eq!(settled_at(&files), None);
        files.insert("a".to_string(), file(at(100, 5)));
        assert_eq!(settled_at(&files), Some(UNIX_EPOCH + Duration::new(100, 5) + TICK));
        // A time in whole seconds may be all its file system keeps of a later one.
        files.insert("b".to_string(), file(at(99, 0)));
        assert_eq!(settled_at(&files), Some(UNIX_EPOCH + Duration::from_secs(99) + WHOLE_SECONDS));
        // The time of the copy's file counts as that of the source's does.
        files.insert("c".to_string(), Entry::File { source: at(50, 1), copy: at(200, 1) });
        assert_eq!(settled_at(&files), Some(UNIX_EPOCH + Duration::new(200, 1) + TICK));

        // The files of the fixture were written a moment ago.
        let f = fx();
        let made = make(&f.ws, &f.copy, &ROOMY).unwrap();
        assert!(SystemTime::now() >= settled_at(&made.manifest.files).unwrap());
        // So a file rewritten at once, to the size it had, has another time: it is seen as changed in
        // the copy, and as changed in the workspace when the copy's is to replace it.
        fs::write(f.copy.join("src/a.rs"), "fn z() {}\n").unwrap();
        fs::write(f.copy.join("src/b.rs"), "fn y() {}\n").unwrap();
        assert_eq!(changes(&made.manifest, &f.copy).unwrap().modified, ["src/a.rs", "src/b.rs"]);
        fs::write(f.ws.join("src/a.rs"), "fn x() {}\n").unwrap();
        let Err(AdoptError::Conflicts(conflicts)) = adopt(&made.manifest, &f.copy, &f.ws, &allow) else {
            panic!("a conflict expected")
        };
        assert_eq!(conflicts, [("src/a.rs".to_string(), "the file there has changed".to_string())]);
        assert_eq!(fs::read_to_string(f.ws.join("src/a.rs")).unwrap(), "fn x() {}\n");
    }

    #[test]
    fn copies_made_at_the_same_time_agree_on_whether_files_are_cloned() {
        let f = fx();
        let beside = f.copy.parent().unwrap().to_path_buf();
        let cloned: Vec<bool> = std::thread::scope(|s| {
            let making: Vec<_> = (0..8)
                .map(|i| {
                    let (ws, dest) = (f.ws.clone(), beside.join(format!("at-once-{i}")));
                    s.spawn(move || make(&ws, &dest, &ROOMY).unwrap().cloned)
                })
                .collect();
            making.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert!(cloned.iter().all(|c| *c == cloned[0]), "{cloned:?}");
        let left: Vec<_> = fs::read_dir(&beside).unwrap().flatten().map(|e| e.file_name()).collect();
        assert!(!left.iter().any(|n| n.to_string_lossy().contains("clone-probe")), "{left:?}");
    }

    #[test]
    fn the_manifest_round_trips_as_json() {
        let f = fx();
        let made = make(&f.ws, &f.copy, &ROOMY).unwrap();
        let text = serde_json::to_string(&made.manifest).unwrap();
        let back: Manifest = serde_json::from_str(&text).unwrap();
        assert_eq!(back, made.manifest);
        assert!(text.contains("\"link\":{\"link\":{\"target\":\"src/a.rs\"}}"), "{text}");
    }

    #[test]
    fn a_git_pointer_that_leaves_the_tree_is_left_out_and_one_that_stays_is_copied() {
        let t = tempfile::tempdir().unwrap();
        let (src, dest) = (t.path().join("src"), t.path().join("dest"));
        std::fs::create_dir_all(src.join("sub/deep")).unwrap();
        std::fs::create_dir_all(src.join("vendored")).unwrap();
        std::fs::create_dir_all(src.join("odd")).unwrap();
        // A linked worktree: its repository is somewhere else.
        std::fs::write(src.join(".git"), "gitdir: /somewhere/else/.git/worktrees/src\n").unwrap();
        // A submodule: its repository is inside the tree, named relative to the pointer.
        std::fs::write(src.join("sub/deep/.git"), "gitdir: ../../.modules/deep\n").unwrap();
        // One that climbs out of the tree, and one that is no pointer at all.
        std::fs::write(src.join("vendored/.git"), "gitdir: ../../outside\n").unwrap();
        std::fs::write(src.join("odd/.git"), "not a pointer\n").unwrap();
        std::fs::write(src.join("a.txt"), "a\n").unwrap();
        let made = make(&src, &dest, &Limits { max_files: 100, max_bytes: 0 }).unwrap();
        assert_eq!(made.git_left_out, [".git", "odd/.git", "vendored/.git"]);
        assert!(!dest.join(".git").exists() && !dest.join("vendored/.git").exists() && !dest.join("odd/.git").exists());
        assert_eq!(std::fs::read_to_string(dest.join("sub/deep/.git")).unwrap(), "gitdir: ../../.modules/deep\n");
        assert!(dest.join("a.txt").is_file());
        // Leaving them out is not a change the agent made.
        assert!(changes(&made.manifest, &dest).unwrap().is_empty());
        // A repository of its own is copied whole.
        let (src2, dest2) = (t.path().join("src2"), t.path().join("dest2"));
        std::fs::create_dir_all(src2.join(".git")).unwrap();
        std::fs::write(src2.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        let made = make(&src2, &dest2, &Limits { max_files: 100, max_bytes: 0 }).unwrap();
        assert!(made.git_left_out.is_empty());
        assert!(dest2.join(".git/HEAD").is_file());
    }
}
