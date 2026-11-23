//! A child's own copy of the workspace: making it, saying what the child changed in it, and bringing
//! one child's changes back.
//!
//! CONTRACT.
//!
//! ## Making a copy
//! `make(source, dest, limits, readable)` copies the directory `source` to `dest`, which must not exist and
//! must not lie inside `source` (nor `source` inside it). Everything is copied, build output and
//! `.git` included, so that what ran in the workspace runs in the copy without a rebuild or a
//! download — but for `<source>/.loom` (harness state and oracle secrets), and for what is neither a
//! file, a directory nor a symbolic link. Files are copied from the open file, which is cloned
//! (`fclonefileat`: no bytes are duplicated) where the file system can, as APFS does, and otherwise copied; their permission bits and
//! modification times are kept. A symbolic link is made again with the same target text and never
//! followed. An entry that cannot be read, or whose name is not UTF-8, is left out and counted
//! (`Made::skipped`). Each file is opened (a regular file only, never blocking) and `readable` judges the
//! real path of what was opened, so a file that was swapped for a link to what the session may not read
//! (the loom home, a credential store) after it was listed is left out and counted, never copied; the
//! bytes are cloned or copied from the open file, not from its path.
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
//! `adopt(manifest, copy, dest, may_write, readable)` brings those changes into `dest` (the workspace the copy
//! was made from): the added and modified files and links are written, the deleted ones removed.
//! Nothing is merged, and it is all or nothing as far as that can be known beforehand:
//! - first, before anything in `dest` is looked at, `may_write(path)` is asked for every path the copy added,
//!   modified or deleted; one refusal and nothing is written (`AdoptError::Refused`, with the refusals). So a
//!   path that leads through a link to where the session may not write is refused, never examined: comparing
//!   it would tell whether names exist there (below the loom home or a credential store, say);
//! - a path that is in `dest` as the copy has it — a link with the same target, a file with the same
//!   permission bits and the same bytes — is left alone (so adopting twice, or after a crash
//!   part-way, is harmless, and the same change made on both sides is no conflict). The bytes are
//!   compared, not the times: two files written at one moment have the same time;
//! - otherwise the path must be in `dest` as the manifest recorded the source (for an added path:
//!   must not exist). Any path that is not — it was changed in the workspace since the copy was made
//!   — is a conflict, and with one conflict nothing is written (`AdoptError::Conflicts`).
//!
//! When a path in `dest` is compared with the copy's file (`as the copy has it`), the file in `dest` is opened
//! and judged by `readable` as the copy's is; one it refuses is not the same as anything.
//!
//! Then the changes are written. Adoption runs in the daemon, outside the sandbox, while the lead's commands
//! may still run (a background job), and one of them can swap a directory of `dest` for a link at any
//! moment, so nothing is written, made or removed by a path that was judged earlier: every step works
//! relative to a directory descriptor whose real path was judged (as `write` and `edit` do, through the
//! same `fstools` helper):
//! - the directory of each path is opened without following a link in its last component; missing ones are
//!   made one at a time below the nearest one that exists, each only after `may_write` accepted the real
//!   path of the open directory it is made in joined with its name, and opened without following a link.
//!   `may_write` then judges the real path of the open directory joined with the file name. A link where a
//!   directory is expected, or a refusal, fails the adoption as `AdoptError::Io` with a sentence that names
//!   the path and says that no link is followed there;
//! - a file is made beside its place under a fresh name that nothing may hold yet (exclusive create, no link
//!   followed), from the copy's file opened and judged by `readable` as in `make` (a file that is refused
//!   fails the adoption as `AdoptError::Io`, and what it names is not copied): on macOS cloned from that open
//!   file into the open directory (`fclonefileat`), otherwise its bytes copied from it. The new file is opened
//!   without following a link and given the copy's permission bits and modification time through that
//!   descriptor (`fchmod`, `futimens`), synced, and renamed over its place within the open directory
//!   (`renameat`). A link is made beside its place (`symlinkat`) and renamed the same way. Whatever fails
//!   after the new entry was made removes it again (`unlinkat`). A command may have moved the open directory
//!   meanwhile, to anywhere the sandbox let it: the entry goes with it, so once it is in place the real path
//!   of the open directory joined with the name is judged again, and a refusal removes the entry
//!   (`unlinkat`) and fails the adoption — what is left is an entry that existed only between the rename and
//!   that removal, in a directory the command could move there;
//! - a removal opens the directory the same way but makes nothing; `may_write` judges the real path joined
//!   with the name, and the entry is removed within that directory (`unlinkat`). A directory of `dest` that a
//!   removal left empty and that the copy no longer has is removed within its open, judged parent
//!   (`unlinkat` with `AT_REMOVEDIR`), and so on upwards.
//!
//! What Git stores (`.git`) is never touched: commits a child made in its copy stay there. A failure while
//! writing is `AdoptError::Io`, with what had been written by then.
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
//! sides for no conflict, and does not touch `.git`; a file swapped for a link to a file `readable`
//! refuses is not copied by `make` (it is counted as skipped) nor by `adopt`.
//!
//! Swap-race tests for `adopt`, each with a directory `outside` that `may_write` refuses (as the sandbox
//! refuses what lies outside its writable roots) and whose content is compared before and after, the swap
//! made deterministically from inside `may_write` after the up-front check of every path has passed: the
//! directory `x` of an added `x/f` swapped for a link to `outside` (the adoption fails, naming the link,
//! and nothing appears in `outside`); a directory above it (`x` of `x/y/f`) swapped the same way (refused,
//! as the real path judged lies in `outside`); `x` swapped after `x/a` was written and before `x/b` (what
//! follows lands in the directory that was opened and judged, or fails, never in `outside`); the `x` of a
//! deleted `x/old` swapped for a link to an `outside` that holds `old` (it is not removed); a missing
//! directory that is made by `adopt`, swapped for a link before it is entered; and a `.{name}…` file beside
//! the place planted in advance as a link to a file in `outside` (that file is unchanged). And one race left
//! to the scheduler: a thread swapping `x` for a link to `outside` and back in a tight loop while `adopt`
//! runs, repeated until enough runs met both states: nothing in `outside` changes, and every run either
//! adopted into `x` or failed. And: a link `k` to a directory `may_write` refuses (standing for the loom home)
//! with the copy adding `k/<name>` gives the same `AdoptError::Refused` whether or not `<name>` exists there
//! (never `Conflicts`); a directory moved, from inside `may_write`'s
//! judgement of the file's place, to where `may_write` refuses leaves no adopted file there and fails.

use crate::files::{open_readable, real_path, NotOpened, Readable};
use crate::fstools::{
    create_new_at, open_dir_creating, open_dir_existing, remove_at, remove_dir_at, rename_at, symlink_at, WriteFail,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// How large a workspace may be to be copied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Most files and links.
    pub max_files: u64,
    /// Most bytes of file content; 0 = no limit.
    pub max_bytes: u64,
}

/// Size, modification time and permission bits of a file, and which file it is (device and inode).
///
/// The identity matters where times are coarse: on Linux two files written within one clock tick can
/// have the same size, time and mode, and a different file put under a path (a directory swapped for a
/// link, say) must never pass for the one the copy was made from. A manifest written before the identity
/// was recorded has `id: None`, and then only the other fields are compared.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stamp {
    pub size: u64,
    pub secs: i64,
    pub nanos: u32,
    pub mode: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<(u64, u64)>,
}

impl Stamp {
    /// Whether `now` is the file this stamp was taken of, unchanged.
    fn matches(&self, now: &Stamp) -> bool {
        self.size == now.size
            && self.secs == now.secs
            && self.nanos == now.nanos
            && self.mode == now.mode
            && match (self.id, now.id) {
                (Some(a), Some(b)) => a == b,
                _ => true,
            }
    }
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
    use std::os::unix::fs::MetadataExt;
    Stamp { size: md.len(), secs, nanos, mode: md.permissions().mode() & 0o7777, id: Some((md.dev(), md.ino())) }
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

/// Whether two files hold the same bytes. Both are opened as `make` opens a file to copy and judged by
/// `readable`; one that cannot be opened, or that `readable` refuses, is not the same as anything.
fn same_bytes(a: &Path, b: &Path, readable: Readable<'_>) -> bool {
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
    let (Ok((mut fa, _)), Ok((mut fb, _))) = (open_readable(a, readable), open_readable(b, readable)) else {
        return false;
    };
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

/// Copy the regular file at `from` to the new file `to`, with its permission bits. `from` is opened first
/// and `readable` judges the real path of what was opened; the bytes come from that open file (cloned where the
/// file system can, as APFS does), never from the path again, so a link swapped in meanwhile leads nowhere.
fn copy_file(from: &Path, to: &Path, readable: Readable<'_>) -> Result<(), NotOpened> {
    use std::os::unix::fs::OpenOptionsExt;
    let (mut file, meta) = open_readable(from, readable)?;
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        if let Ok(dest) = std::ffi::CString::new(to.as_os_str().as_bytes()) {
            // SAFETY: `file` is open for the call, `dest` is a NUL-terminated path that lives for it, and
            // fclonefileat(2) has no other memory effects.
            let cloned = unsafe { libc::fclonefileat(file.as_raw_fd(), libc::AT_FDCWD, dest.as_ptr(), 0) } == 0;
            if cloned {
                return Ok(());
            }
        }
    }
    let mut out =
        std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(to).map_err(NotOpened::Io)?;
    std::io::copy(&mut file, &mut out).map_err(NotOpened::Io)?;
    out.set_permissions(meta.permissions()).map_err(NotOpened::Io)?;
    Ok(())
}

struct Copier<'a> {
    /// Judges the real path of each file opened to be copied.
    readable: Readable<'a>,
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

impl Copier<'_> {
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
                match copy_file(&from, &to, self.readable) {
                    Ok(()) => {}
                    // The file could not be read, went away, is no longer a file, or is now a link to what the
                    // session may not read: the copy goes on without it.
                    Err(NotOpened::Denied(_) | NotOpened::NotRegular(_)) => {
                        let _ = std::fs::remove_file(&to);
                        self.skipped += 1;
                        continue;
                    }
                    Err(NotOpened::Io(e))
                        if matches!(e.kind(), std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotFound) =>
                    {
                        let _ = std::fs::remove_file(&to);
                        self.skipped += 1;
                        continue;
                    }
                    Err(NotOpened::Io(e)) => return Err(e),
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
pub fn make(source: &Path, dest: &Path, limits: &Limits, readable: Readable<'_>) -> Result<Made, String> {
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
    let mut copier =
        Copier { readable, done: BTreeMap::new(), files: 0, bytes: 0, skipped: 0, git_left_out: Vec::new() };
    copier.dir(source, dest, "").map_err(failed)?;
    let keep = listed(dest).inspect_err(|_| {
        let _ = std::fs::remove_dir_all(dest);
    })?;
    let Copier { done, files, bytes, skipped, mut git_left_out, .. } = copier;
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
        (Entry::File { copy, .. }, Seen::File(s)) => copy.matches(s),
        (Entry::Link { target }, Seen::Link(t)) => target == t,
        _ => false,
    }
}

/// Whether a path is in the workspace (`there`) as the copy has it (`here`): a link with the same
/// target, or a file with the same permission bits and bytes. Their times are not asked: two files
/// written at one moment have the same time, and a file system may round the one it is given.
fn as_the_copy_has_it(there: &Seen, here: &Seen, in_dest: &Path, in_copy: &Path, readable: Readable<'_>) -> bool {
    match (there, here) {
        (Seen::Link(a), Seen::Link(b)) => a == b,
        (Seen::File(a), Seen::File(b)) => {
            a.size == b.size && a.mode == b.mode && same_bytes(in_dest, in_copy, readable)
        }
        _ => false,
    }
}

/// Whether what is at a path of the workspace is what the copy was made from.
fn unchanged_in_source(entry: &Entry, now: &Seen) -> bool {
    match (entry, now) {
        (Entry::File { source, .. }, Seen::File(s)) => source.matches(s),
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

/// The sentence for a link where a directory of `dest` is expected.
fn link_in_the_way(dir: &Path) -> String {
    format!(
        "{} is a symbolic link where a directory is expected, and no link is followed there, so nothing was \
         written or removed through it.",
        dir.display()
    )
}

/// A failure of the descriptor steps as the error `adopt` reports after the path.
fn io_of(fail: WriteFail) -> std::io::Error {
    match fail {
        WriteFail::Denied(why) => std::io::Error::new(std::io::ErrorKind::PermissionDenied, why),
        WriteFail::Refused(why) => std::io::Error::other(why),
        WriteFail::Io(e) => e,
    }
}

/// Judge the real path of the open directory `dir` joined with `name`.
fn judge_in(dir: &File, name: &OsStr, may_write: &dyn Fn(&Path) -> Result<(), String>) -> std::io::Result<()> {
    let real = real_path(dir.as_fd())?;
    may_write(&real.join(name)).map_err(|why| std::io::Error::new(std::io::ErrorKind::PermissionDenied, why))
}

/// A path in `dest` that a removal may have left an empty directory at: removed, with its empty
/// parents, as far as the copy has no such directory either. Each is removed within its parent, opened
/// without following a link and judged by its real path, never by the path it was reached by.
fn prune(dest: &Path, copy: &Path, rel: &str, may_write: &dyn Fn(&Path) -> Result<(), String>) {
    let mut dir = Path::new(rel).parent();
    while let Some(d) = dir.filter(|d| !d.as_os_str().is_empty()) {
        let Some(name) = d.file_name() else { return };
        if copy.join(d).exists() {
            return;
        }
        let parent = dest.join(d.parent().unwrap_or_else(|| Path::new("")));
        let Ok(open) = open_dir_existing(&parent, &link_in_the_way) else { return };
        if judge_in(&open, name, may_write).is_err() || remove_dir_at(&open, name).is_err() {
            return;
        }
        dir = d.parent();
    }
}

/// Set the modification time of the open file to that of `s`; its access time is left alone.
fn set_mtime_fd(file: &File, s: &Stamp) -> std::io::Result<()> {
    let omit = libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT };
    let modified = libc::timespec { tv_sec: s.secs as libc::time_t, tv_nsec: s.nanos as libc::c_long };
    let times = [omit, modified];
    // SAFETY: `file` is an open descriptor and `times` is the two-element array futimens(2) reads; the call
    // has no other memory effects.
    let rc = unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Make the file `tmp` in the open directory `dir` from the open file `from`, which has `mode`, and open
/// it without following a link. Nothing may exist under `tmp` (the call fails if it does). On macOS the file
/// is cloned where the file system can and the owner can read and write the clone; otherwise a file made
/// private (0600) gets the bytes. `Err((_, false))`: nothing was made; `Err((_, true))`: `tmp` exists.
fn make_file_in(dir: &File, tmp: &OsStr, from: &mut File, mode: u32) -> Result<File, (std::io::Error, bool)> {
    #[cfg(target_os = "macos")]
    if mode & 0o600 == 0o600 && crate::fstools::clone_at(from, dir, tmp).is_ok() {
        // A clone has the mode of its source, which here lets the owner open it. Another process may have
        // put something else under the name since: it is opened without following a link and must be a
        // file with no other name.
        use std::os::unix::fs::MetadataExt;
        let opened = crate::fstools::open_file_at(dir, tmp).map_err(|e| (e, true))?;
        let md = opened.metadata().map_err(|e| (e, true))?;
        if !md.is_file() || md.nlink() != 1 {
            let why = "what was made beside its place is not the new file any more";
            return Err((std::io::Error::other(why), true));
        }
        return Ok(opened);
    }
    #[cfg(not(target_os = "macos"))]
    let _ = mode;
    let mut out = create_new_at(dir, tmp, 0o600).map_err(|e| (e, false))?;
    std::io::copy(from, &mut out).map_err(|e| (e, true))?;
    Ok(out)
}

/// Makes the name of each file made beside its place different from every other made by this process.
static ADOPT_NAMES: AtomicU64 = AtomicU64::new(0);

/// What a path of the copy is, opened as far as it is a file.
enum Source {
    File { file: File, stamp: Stamp },
    Link(String),
}

/// Bring one path of the copy to `dest`: beside its place first, then renamed over it. Everything is
/// relative to the open directory of the path (see the module contract), not to a path judged earlier.
fn bring(
    copy: &Path,
    dest: &Path,
    rel: &str,
    may_write: &dyn Fn(&Path) -> Result<(), String>,
    readable: Readable<'_>,
) -> std::io::Result<()> {
    let (from, to) = (copy.join(rel), dest.join(rel));
    let (Some(name), Some(parent)) = (to.file_name(), to.parent()) else {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "it has no file name"));
    };
    let gone = || std::io::Error::new(std::io::ErrorKind::NotFound, "it is no longer a file in the copy");
    let mut source = match seen(&from) {
        Seen::Link(target) => Source::Link(target),
        Seen::File(_) => {
            let (file, meta) = open_readable(&from, readable).map_err(|e| match e {
                NotOpened::Io(e) => e,
                NotOpened::Denied(sentence) => std::io::Error::new(std::io::ErrorKind::PermissionDenied, sentence),
                NotOpened::NotRegular(_) => gone(),
            })?;
            Source::File { file, stamp: stamp(&meta) }
        }
        _ => return Err(gone()),
    };
    let dir = open_dir_creating(may_write, &link_in_the_way, parent).map_err(io_of)?;
    judge_in(&dir, name, may_write)?;
    let n = ADOPT_NAMES.fetch_add(1, Ordering::Relaxed);
    let tmp = OsString::from(format!(".{}.loom-adopt-{}-{n}", name.to_string_lossy(), std::process::id()));
    let finished = match &mut source {
        Source::Link(target) => {
            symlink_at(&dir, OsStr::new(target), &tmp)?;
            rename_at(&dir, &tmp, name)
        }
        Source::File { file, stamp } => {
            let made = match make_file_in(&dir, &tmp, file, stamp.mode) {
                Ok(made) => made,
                Err((e, false)) => return Err(e),
                Err((e, true)) => {
                    let _ = remove_at(&dir, &tmp);
                    return Err(e);
                }
            };
            (|| {
                set_mtime_fd(&made, stamp)?;
                made.set_permissions(std::fs::Permissions::from_mode(stamp.mode))?;
                made.sync_all()?;
                rename_at(&dir, &tmp, name)
            })()
        }
    };
    if finished.is_err() {
        let _ = remove_at(&dir, &tmp);
        return finished;
    }
    // A command may have moved the open directory since it was judged: judge where it is now, and take the
    // entry out again if that is a place the session may not write.
    if let Err(e) = judge_in(&dir, name, may_write) {
        let _ = remove_at(&dir, name);
        let why = format!("the directory was moved while the file was being put there, so it was removed again: {e}");
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, why));
    }
    Ok(())
}

/// Remove the file or link `rel` of `dest` within its directory, opened without following a link and
/// judged by its real path.
fn remove_entry(dest: &Path, rel: &str, may_write: &dyn Fn(&Path) -> Result<(), String>) -> std::io::Result<()> {
    let to = dest.join(rel);
    let (Some(name), Some(parent)) = (to.file_name(), to.parent()) else {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "it has no file name"));
    };
    let dir = open_dir_existing(parent, &link_in_the_way).map_err(io_of)?;
    judge_in(&dir, name, may_write)?;
    remove_at(&dir, name)
}

/// See the module contract. `Ok`: what was brought over (paths already as the copy has them are not
/// listed).
pub fn adopt(
    manifest: &Manifest,
    copy: &Path,
    dest: &Path,
    may_write: &dyn Fn(&Path) -> Result<(), String>,
    readable: Readable<'_>,
) -> Result<Changes, AdoptError> {
    let all = changes(manifest, copy).map_err(|message| AdoptError::Io { message, written: Vec::new() })?;
    // Before anything in `dest` is looked at: a path through a link to where the session may not write is
    // refused here and never examined, so a comparison cannot tell whether a name exists there.
    let refused: Vec<(String, String)> = all
        .added
        .iter()
        .chain(&all.modified)
        .chain(&all.deleted)
        .filter_map(|rel| may_write(&dest.join(rel)).err().map(|why| (rel.clone(), why)))
        .collect();
    if !refused.is_empty() {
        return Err(AdoptError::Refused(refused));
    }
    let mut todo = Changes { newest_ms: all.newest_ms, ..Changes::default() };
    let mut conflicts = Vec::new();
    for (rel, added) in all.added.iter().map(|r| (r, true)).chain(all.modified.iter().map(|r| (r, false))) {
        let (in_dest, in_copy) = (dest.join(rel), copy.join(rel));
        let there = seen(&in_dest);
        // Adopted already, or the same change was made on both sides.
        if as_the_copy_has_it(&there, &seen(&in_copy), &in_dest, &in_copy, readable) {
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
    let mut written = Vec::new();
    for rel in todo.added.iter().chain(&todo.modified) {
        if let Err(e) = bring(copy, dest, rel, may_write, readable) {
            return Err(AdoptError::Io { message: format!("{rel} could not be written: {e}"), written });
        }
        written.push(rel.clone());
    }
    for rel in &todo.deleted {
        if let Err(e) = remove_entry(dest, rel, may_write) {
            return Err(AdoptError::Io { message: format!("{rel} could not be removed: {e}"), written });
        }
        written.push(rel.clone());
        prune(dest, copy, rel, may_write);
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
        let made = make(&f.ws, &f.copy, &ROOMY, &allow).unwrap();
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
        let e = make(&f.ws, &f.copy, &Limits { max_files: 3, max_bytes: 0 }, &allow).unwrap_err();
        assert!(e.contains("more than 3 files") && e.contains("agents.copy_max_files"), "{e}");
        assert!(!f.copy.exists());
        fs::write(f.ws.join("big"), vec![0u8; 3 * 1024 * 1024]).unwrap();
        let tight = Limits { max_files: 1000, max_bytes: 2 * 1024 * 1024 };
        let (mut files, mut bytes) = (0, 0);
        let e = measure(&f.ws, true, &tight, &mut files, &mut bytes).unwrap_err();
        assert!(e.contains("more than 2 MiB") && e.contains("agents.copy_max_mb"), "{e}");
        // The limit on bytes holds exactly where a copy duplicates them.
        match make(&f.ws, &f.copy, &tight, &allow) {
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
        let e = make(&f.ws, &f.ws.join("inside"), &ROOMY, &allow).unwrap_err();
        assert!(e.contains("one lies inside the other"), "{e}");
        assert!(!f.ws.join("inside").exists());
        fs::create_dir_all(&f.copy).unwrap();
        let e = make(&f.ws, &f.copy, &ROOMY, &allow).unwrap_err();
        assert!(e.contains("exists already"), "{e}");
    }

    #[test]
    fn changes_lists_what_the_child_did_and_not_what_a_build_wrote() {
        let f = fx();
        let made = make(&f.ws, &f.copy, &ROOMY, &allow).unwrap();
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
        let made = make(&f.ws, &f.copy, &ROOMY, &allow).unwrap();
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
        let done = adopt(&made.manifest, &f.copy, &f.ws, &may, &allow).unwrap();
        assert_eq!(done.lines(), ["D docs/old.md", "M src/a.rs", "A tests/deep/t.rs"]);
        // Every path is asked once up front (added, modified, deleted), then for each directory made and for
        // each path written or removed, by its real path; a path written is judged once more when it is in
        // place.
        let ws = &f.ws;
        let up_front = [ws.join("tests/deep/t.rs"), ws.join("src/a.rs"), ws.join("docs/old.md")];
        let writing = [ws.join("tests"), ws.join("tests/deep"), ws.join("tests/deep/t.rs"), ws.join("tests/deep/t.rs")];
        let rest = [ws.join("src/a.rs"), ws.join("src/a.rs"), ws.join("docs/old.md"), ws.join("docs")];
        assert_eq!(*asked.borrow(), [up_front.as_slice(), writing.as_slice(), rest.as_slice()].concat());
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
        let again = adopt(&made.manifest, &f.copy, &f.ws, &allow, &allow).unwrap();
        assert!(again.is_empty(), "{again:?}");
    }

    #[test]
    fn adopt_writes_nothing_when_the_workspace_changed_too_or_a_path_is_refused() {
        let f = fx();
        let made = make(&f.ws, &f.copy, &ROOMY, &allow).unwrap();
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
            assert_eq!(alike(seen(&f.ws.join(same))), alike(seen(&f.copy.join(same))), "{same}");
        }
        let Err(AdoptError::Conflicts(conflicts)) = adopt(&made.manifest, &f.copy, &f.ws, &allow, &allow) else {
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
        let made = make(&g.ws, &g.copy, &ROOMY, &allow).unwrap();
        fs::write(g.copy.join("src/a.rs"), "fn a() { 1 }\n").unwrap();
        fs::write(g.copy.join("run.sh"), "#!/bin/sh\necho changed\n").unwrap();
        let may = |p: &Path| if p.ends_with("run.sh") { Err("protected".to_string()) } else { Ok(()) };
        let Err(AdoptError::Refused(refused)) = adopt(&made.manifest, &g.copy, &g.ws, &may, &allow) else {
            panic!("a refusal expected")
        };
        assert_eq!(refused, [("run.sh".to_string(), "protected".to_string())]);
        assert_eq!(fs::read_to_string(g.ws.join("src/a.rs")).unwrap(), "fn a() {}\n");
    }

    #[test]
    fn the_same_change_on_both_sides_is_no_conflict_and_is_not_brought() {
        let f = fx();
        let made = make(&f.ws, &f.copy, &ROOMY, &allow).unwrap();
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
        let done = adopt(&made.manifest, &f.copy, &f.ws, &may, &allow).unwrap();
        assert_eq!(done.lines(), ["M src/b.rs"]);
        // Every changed path is asked up front, those already as the copy has them too; `src/b.rs` is asked
        // again for its place and once more when it is in place.
        let ws = &f.ws;
        assert_eq!(
            *asked.borrow(),
            [ws.join("notes.txt"), ws.join("src/a.rs"), ws.join("src/b.rs"), ws.join("src/b.rs"), ws.join("src/b.rs")]
        );
        assert_eq!(fs::read_to_string(f.ws.join("src/b.rs")).unwrap(), "fn b() { 2 }\n");
    }

    /// What two different files share when they look alike: everything but their identity.
    fn alike(s: Seen) -> Seen {
        match s {
            Seen::File(st) => Seen::File(Stamp { id: None, ..st }),
            other => other,
        }
    }

    #[test]
    fn a_stamp_tells_another_file_with_the_same_size_time_and_mode_apart() {
        let a = Stamp { size: 4, secs: 100, nanos: 0, mode: 0o644, id: Some((1, 10)) };
        let other = Stamp { id: Some((1, 11)), ..a };
        assert!(a.matches(&a));
        assert!(!a.matches(&other), "another inode with the same size, time and mode is another file");
        // A manifest written before the identity was recorded still matches on the rest.
        let old = Stamp { id: None, ..a };
        assert!(old.matches(&other) && other.matches(&old));
        assert!(!old.matches(&Stamp { size: 5, ..other }));
        // The identity is left out of a manifest that has none, and an old one still parses.
        let json = serde_json::to_string(&old).unwrap();
        assert!(!json.contains("id"), "{json}");
        assert_eq!(serde_json::from_str::<Stamp>(&json).unwrap(), old);
    }

    #[test]
    fn when_a_copy_is_made_the_clock_is_past_the_times_it_recorded() {
        let at = |secs: i64, nanos: u32| Stamp { size: 1, secs, nanos, mode: 0o644, id: None };
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
        let made = make(&f.ws, &f.copy, &ROOMY, &allow).unwrap();
        assert!(SystemTime::now() >= settled_at(&made.manifest.files).unwrap());
        // So a file rewritten at once, to the size it had, has another time: it is seen as changed in
        // the copy, and as changed in the workspace when the copy's is to replace it.
        fs::write(f.copy.join("src/a.rs"), "fn z() {}\n").unwrap();
        fs::write(f.copy.join("src/b.rs"), "fn y() {}\n").unwrap();
        assert_eq!(changes(&made.manifest, &f.copy).unwrap().modified, ["src/a.rs", "src/b.rs"]);
        fs::write(f.ws.join("src/a.rs"), "fn x() {}\n").unwrap();
        let Err(AdoptError::Conflicts(conflicts)) = adopt(&made.manifest, &f.copy, &f.ws, &allow, &allow) else {
            panic!("a conflict expected")
        };
        assert_eq!(conflicts, [("src/a.rs".to_string(), "the file there has changed".to_string())]);
        assert_eq!(fs::read_to_string(f.ws.join("src/a.rs")).unwrap(), "fn x() {}\n");
    }

    /// A judge that refuses the real path of any file whose name is `secret`.
    fn refuse_secret(real: &Path) -> Result<(), String> {
        if real.file_name().is_some_and(|n| n == "secret") {
            Err(format!("{} is not readable", real.display()))
        } else {
            Ok(())
        }
    }

    #[test]
    fn a_file_that_leads_to_what_may_not_be_read_is_not_copied_by_make_or_adopt() {
        let f = fx();
        // The file is in the tree as the walk saw it; what it opens as is judged by its real path.
        fs::write(f.ws.join("src/secret"), "SECRET-BYTES").unwrap();
        let made = make(&f.ws, &f.copy, &ROOMY, &refuse_secret).unwrap();
        assert!(!f.copy.join("src/secret").exists(), "a refused file is not copied");
        assert!(made.skipped >= 1 && !made.manifest.files.contains_key("src/secret"));
        assert!(f.copy.join("src/a.rs").exists());
        // In adopt, a file of the copy that opens as a refused file is not brought over.
        fs::create_dir_all(f.copy.join("added")).unwrap();
        fs::write(f.copy.join("added/secret"), "SECRET-BYTES").unwrap();
        let Err(AdoptError::Io { message, .. }) = adopt(&made.manifest, &f.copy, &f.ws, &allow, &refuse_secret) else {
            panic!("an adoption that meets a refused file fails")
        };
        assert!(message.contains("added/secret") && message.contains("not readable"), "{message}");
        assert!(!f.ws.join("added/secret").exists());
    }

    #[test]
    fn copies_made_at_the_same_time_agree_on_whether_files_are_cloned() {
        let f = fx();
        let beside = f.copy.parent().unwrap().to_path_buf();
        let cloned: Vec<bool> = std::thread::scope(|s| {
            let making: Vec<_> = (0..8)
                .map(|i| {
                    let (ws, dest) = (f.ws.clone(), beside.join(format!("at-once-{i}")));
                    s.spawn(move || make(&ws, &dest, &ROOMY, &allow).unwrap().cloned)
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
        let made = make(&f.ws, &f.copy, &ROOMY, &allow).unwrap();
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
        let made = make(&src, &dest, &Limits { max_files: 100, max_bytes: 0 }, &allow).unwrap();
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
        let made = make(&src2, &dest2, &Limits { max_files: 100, max_bytes: 0 }, &allow).unwrap();
        assert!(made.git_left_out.is_empty());
        assert!(dest2.join(".git/HEAD").is_file());
    }

    // ---- Swap races for `adopt` -------------------------------------------------------------------

    /// A workspace, a copy of it and a directory `outside` that `may_write` refuses.
    struct Raced {
        _dir: tempfile::TempDir,
        ws: PathBuf,
        copy: PathBuf,
        outside: PathBuf,
    }

    /// The workspace holds `files` (their directories made); `outside` holds `outside_files`.
    fn raced(files: &[(&str, &str)], outside_files: &[(&str, &str)]) -> Raced {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let (ws, outside) = (root.join("ws"), root.join("outside"));
        for (base, list) in [(&ws, files), (&outside, outside_files)] {
            fs::create_dir_all(base).unwrap();
            for (rel, text) in list {
                fs::create_dir_all(base.join(rel).parent().unwrap()).unwrap();
                fs::write(base.join(rel), text).unwrap();
            }
        }
        Raced { copy: root.join("copies/c1"), ws, outside, _dir: dir }
    }

    /// Everything under `dir`: each path with its bytes, a directory with `None`.
    fn listing(dir: &Path) -> BTreeMap<String, Option<Vec<u8>>> {
        fn walk(base: &Path, at: &Path, out: &mut BTreeMap<String, Option<Vec<u8>>>) {
            for entry in fs::read_dir(at).unwrap().flatten() {
                let path = entry.path();
                let rel = path.strip_prefix(base).unwrap().display().to_string();
                if fs::symlink_metadata(&path).unwrap().is_dir() {
                    out.insert(rel, None);
                    walk(base, &path, out);
                } else {
                    out.insert(rel, Some(fs::read(&path).unwrap_or_default()));
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(dir, dir, &mut out);
        out
    }

    /// Replace the directory `dir` by a link to `to`; the directory is kept as `<dir>.orig`.
    fn swap_for_link(dir: &Path, to: &Path) {
        fs::rename(dir, dir.with_extension("orig")).unwrap();
        std::os::unix::fs::symlink(to, dir).unwrap();
    }

    /// A `may_write` that refuses what is not under `ws`, as the sandbox refuses what lies outside its
    /// writable roots, and runs `swap` after it has answered its `swap_at`-th call (the first is 1).
    fn judge<'a>(
        ws: &'a Path,
        calls: &'a std::cell::Cell<usize>,
        swap_at: usize,
        swap: &'a dyn Fn(),
    ) -> impl Fn(&Path) -> Result<(), String> + 'a {
        move |path: &Path| {
            calls.set(calls.get() + 1);
            let verdict = if path.starts_with(ws) {
                Ok(())
            } else {
                Err(format!("{} lies outside the writable roots", path.display()))
            };
            if calls.get() == swap_at {
                swap();
            }
            verdict
        }
    }

    fn io_message(result: Result<Changes, AdoptError>) -> (String, Vec<String>) {
        match result {
            Err(AdoptError::Io { message, written }) => (message, written),
            other => panic!("an I/O failure expected, got {other:?}"),
        }
    }

    #[test]
    fn a_directory_swapped_for_a_link_before_a_file_is_brought_gets_nothing_outside() {
        let r = raced(&[("x/seed", "s")], &[("keep", "k")]);
        let made = make(&r.ws, &r.copy, &ROOMY, &allow).unwrap();
        fs::write(r.copy.join("x/f"), "from the copy\n").unwrap();
        let before = listing(&r.outside);
        let calls = std::cell::Cell::new(0);
        // The only up-front call is the last of the check: the swap comes after the check has passed.
        let swap = || swap_for_link(&r.ws.join("x"), &r.outside);
        let may = judge(&r.ws, &calls, 1, &swap);
        let (message, written) = io_message(adopt(&made.manifest, &r.copy, &r.ws, &may, &allow));
        assert!(message.contains("x/f could not be written"), "{message}");
        assert!(message.contains("symbolic link") && message.contains("no link is followed"), "{message}");
        assert!(message.contains(&r.ws.join("x").display().to_string()), "{message}");
        assert!(written.is_empty());
        assert_eq!(listing(&r.outside), before);
    }

    /// A `may_write` that judges the real path of a path's directory, as the sandbox does: what leads through a
    /// link to somewhere outside `ws` is refused.
    fn real_judge(ws: &Path) -> impl Fn(&Path) -> Result<(), String> + '_ {
        move |p| match p.parent().map(fs::canonicalize) {
            Some(Ok(real)) if real.starts_with(ws) => Ok(()),
            _ => Err(format!("{} leads outside the writable roots", p.display())),
        }
    }

    #[test]
    fn a_path_through_a_link_to_where_nothing_may_be_written_is_refused_whatever_is_there() {
        // The name is not there; it is there with the copy's bytes; it is there with other bytes.
        for there in [None, Some("from the copy\n"), Some("something else\n")] {
            let r = raced(&[("seed", "s")], &[("keep", "k")]);
            let made = make(&r.ws, &r.copy, &ROOMY, &allow).unwrap();
            fs::create_dir_all(r.copy.join("k")).unwrap();
            fs::write(r.copy.join("k/name"), "from the copy\n").unwrap();
            std::os::unix::fs::symlink(&r.outside, r.ws.join("k")).unwrap();
            if let Some(text) = there {
                fs::write(r.outside.join("name"), text).unwrap();
            }
            let before = listing(&r.outside);
            let reads = std::cell::Cell::new(0);
            let counting = |_: &Path| {
                reads.set(reads.get() + 1);
                Ok(())
            };
            let result = adopt(&made.manifest, &r.copy, &r.ws, &real_judge(&r.ws), &counting);
            let Err(AdoptError::Refused(refused)) = result else {
                panic!("{there:?}: a refusal expected, got {result:?}")
            };
            assert_eq!(refused.len(), 1, "{there:?}");
            assert_eq!(refused[0].0, "k/name", "{there:?}");
            assert_eq!(reads.get(), 0, "{there:?}: nothing was read there");
            assert_eq!(listing(&r.outside), before, "{there:?}");
        }
    }

    #[test]
    fn a_directory_moved_to_where_nothing_may_be_written_while_its_file_is_judged_keeps_no_file() {
        let r = raced(&[("x/seed", "s")], &[("keep", "k")]);
        let made = make(&r.ws, &r.copy, &ROOMY, &allow).unwrap();
        fs::write(r.copy.join("x/f"), "from the copy\n").unwrap();
        let calls = std::cell::Cell::new(0);
        // Call 1 is the check, call 2 judges the place of `x/f` in the directory that was opened; the directory
        // is moved, with that open directory, to where `may_write` refuses.
        let moved = || fs::rename(r.ws.join("x"), r.outside.join("x")).unwrap();
        let may = judge(&r.ws, &calls, 2, &moved);
        let (message, written) = io_message(adopt(&made.manifest, &r.copy, &r.ws, &may, &allow));
        assert!(message.contains("x/f could not be written") && message.contains("moved"), "{message}");
        assert!(message.contains("lies outside the writable roots"), "{message}");
        assert!(written.is_empty());
        let names: Vec<String> = listing(&r.outside.join("x")).into_keys().collect();
        assert_eq!(names, ["seed"], "no adopted file, and nothing half-made, is left there");
    }

    #[test]
    fn a_directory_swapped_after_it_was_opened_takes_the_file_there_and_nothing_goes_outside() {
        let r = raced(&[("x/seed", "s")], &[("keep", "k")]);
        let made = make(&r.ws, &r.copy, &ROOMY, &allow).unwrap();
        fs::write(r.copy.join("x/f"), "from the copy\n").unwrap();
        let before = listing(&r.outside);
        let calls = std::cell::Cell::new(0);
        // The second call judges the real path of the directory that was opened, joined with the name.
        let swap = || swap_for_link(&r.ws.join("x"), &r.outside);
        let may = judge(&r.ws, &calls, 2, &swap);
        let done = adopt(&made.manifest, &r.copy, &r.ws, &may, &allow).unwrap();
        assert_eq!(done.added, ["x/f"]);
        assert_eq!(fs::read_to_string(r.ws.join("x.orig/f")).unwrap(), "from the copy\n");
        assert_eq!(listing(&r.outside), before);
    }

    #[test]
    fn a_directory_above_the_one_of_a_file_swapped_for_a_link_is_refused_by_the_real_path() {
        let r = raced(&[("x/y/seed", "s")], &[("y/keep", "k"), ("keep", "k")]);
        let made = make(&r.ws, &r.copy, &ROOMY, &allow).unwrap();
        fs::write(r.copy.join("x/y/f"), "from the copy\n").unwrap();
        let before = listing(&r.outside);
        let calls = std::cell::Cell::new(0);
        let swap = || swap_for_link(&r.ws.join("x"), &r.outside);
        let may = judge(&r.ws, &calls, 1, &swap);
        // `x/y` opens: it is no link itself. What is judged is where it really is.
        let (message, written) = io_message(adopt(&made.manifest, &r.copy, &r.ws, &may, &allow));
        assert!(message.contains("x/y/f could not be written"), "{message}");
        assert!(message.contains("lies outside the writable roots"), "{message}");
        assert!(message.contains(&r.outside.join("y/f").display().to_string()), "{message}");
        assert!(written.is_empty());
        assert_eq!(listing(&r.outside), before);
    }

    #[test]
    fn a_directory_swapped_between_two_files_is_not_followed_for_the_second() {
        let r = raced(&[("x/seed", "s")], &[("keep", "k")]);
        let made = make(&r.ws, &r.copy, &ROOMY, &allow).unwrap();
        fs::write(r.copy.join("x/a"), "a\n").unwrap();
        fs::write(r.copy.join("x/b"), "b\n").unwrap();
        let before = listing(&r.outside);
        let calls = std::cell::Cell::new(0);
        // Calls 1 and 2 are the check; the third judges `x/a` in the directory that was opened, and the
        // swap follows it: `x/a` lands in that directory, `x/b` meets the link.
        let swap = || swap_for_link(&r.ws.join("x"), &r.outside);
        let may = judge(&r.ws, &calls, 3, &swap);
        let (message, written) = io_message(adopt(&made.manifest, &r.copy, &r.ws, &may, &allow));
        assert!(message.contains("x/b could not be written") && message.contains("symbolic link"), "{message}");
        assert_eq!(written, ["x/a"]);
        assert_eq!(fs::read_to_string(r.ws.join("x.orig/a")).unwrap(), "a\n");
        assert_eq!(listing(&r.outside), before);
    }

    #[test]
    fn a_directory_swapped_for_a_link_does_not_get_a_file_removed_there() {
        for swap_at in [1, 2] {
            let r = raced(&[("x/old", "old\n"), ("x/seed", "s")], &[("old", "old\n"), ("keep", "k")]);
            // The file outside gets the size, time and mode of the workspace's, as two files written within
            // one tick of a coarse clock (Linux) do: only which file it is tells them apart.
            let st = stamp(&fs::symlink_metadata(r.ws.join("x/old")).unwrap());
            set_mtime(&r.outside.join("old"), &st).unwrap();
            fs::set_permissions(r.outside.join("old"), fs::Permissions::from_mode(st.mode)).unwrap();
            let made = make(&r.ws, &r.copy, &ROOMY, &allow).unwrap();
            fs::remove_file(r.copy.join("x/old")).unwrap();
            let before = listing(&r.outside);
            let calls = std::cell::Cell::new(0);
            let swap = || swap_for_link(&r.ws.join("x"), &r.outside);
            let may = judge(&r.ws, &calls, swap_at, &swap);
            let result = adopt(&made.manifest, &r.copy, &r.ws, &may, &allow);
            if swap_at == 1 {
                // Swapped after the check of the paths, before anything of `dest` was looked at: the file the
                // link leads to is not the one the copy was made from, so it is a conflict and nothing is touched.
                assert!(matches!(result, Err(AdoptError::Conflicts(_))), "{result:?}");
                assert!(r.ws.join("x.orig/old").exists(), "the file of the workspace was not touched either");
            } else {
                // Swapped once the directory was open and judged: the file goes from that directory.
                assert_eq!(result.unwrap().deleted, ["x/old"]);
                assert!(!r.ws.join("x.orig/old").exists());
            }
            assert_eq!(fs::read_to_string(r.outside.join("old")).unwrap(), "old\n", "swap at {swap_at}");
            assert_eq!(listing(&r.outside), before, "swap at {swap_at}");
        }
    }

    #[test]
    fn an_emptied_directory_swapped_for_a_link_is_not_removed_through_it() {
        let r = raced(&[("x/y/old", "old\n"), ("seed", "s")], &[("y/keep", "k")]);
        let made = make(&r.ws, &r.copy, &ROOMY, &allow).unwrap();
        fs::remove_file(r.copy.join("x/y/old")).unwrap();
        fs::remove_dir(r.copy.join("x/y")).unwrap();
        fs::remove_dir(r.copy.join("x")).unwrap();
        let before = listing(&r.outside);
        let calls = std::cell::Cell::new(0);
        // Call 1 is the check, 2 the removal; the swap comes with the judging of the directory `x/y`.
        let swap = || swap_for_link(&r.ws.join("x"), &r.outside);
        let may = judge(&r.ws, &calls, 3, &swap);
        let done = adopt(&made.manifest, &r.copy, &r.ws, &may, &allow).unwrap();
        assert_eq!(done.deleted, ["x/y/old"]);
        assert!(fs::symlink_metadata(r.ws.join("x")).unwrap().file_type().is_symlink());
        assert_eq!(listing(&r.outside), before);
    }

    #[test]
    fn a_missing_directory_swapped_for_a_link_before_it_is_entered_is_not_followed() {
        let r = raced(&[("seed", "s")], &[("keep", "k")]);
        let made = make(&r.ws, &r.copy, &ROOMY, &allow).unwrap();
        fs::create_dir_all(r.copy.join("n/m")).unwrap();
        fs::write(r.copy.join("n/m/f"), "from the copy\n").unwrap();
        let before = listing(&r.outside);
        let calls = std::cell::Cell::new(0);
        // Call 1 is the check; call 2 judges the making of `n`: a link is put there in its place.
        let plant = || std::os::unix::fs::symlink(&r.outside, r.ws.join("n")).unwrap();
        let may = judge(&r.ws, &calls, 2, &plant);
        let (message, written) = io_message(adopt(&made.manifest, &r.copy, &r.ws, &may, &allow));
        assert!(message.contains("n/m/f could not be written") && message.contains("symbolic link"), "{message}");
        assert!(message.contains(&r.ws.join("n").display().to_string()), "{message}");
        assert!(written.is_empty());
        assert_eq!(listing(&r.outside), before);
    }

    #[test]
    fn a_name_planted_beside_the_place_as_a_link_is_not_written_through() {
        let r = raced(&[("seed", "s")], &[("victim", "victim\n")]);
        let made = make(&r.ws, &r.copy, &ROOMY, &allow).unwrap();
        fs::write(r.copy.join("f"), "from the copy\n").unwrap();
        let before = listing(&r.outside);
        // The names the new file may get: the counter is shared by the tests that run at once, so many are
        // planted. A hit makes the exclusive create fail; a miss leaves the planted links alone.
        let victim = r.outside.join("victim");
        let next = ADOPT_NAMES.load(Ordering::Relaxed);
        std::os::unix::fs::symlink(&victim, r.ws.join(".f.loom-adopt")).unwrap();
        for n in next..next + 300 {
            let name = format!(".f.loom-adopt-{}-{n}", std::process::id());
            std::os::unix::fs::symlink(&victim, r.ws.join(name)).unwrap();
        }
        match adopt(&made.manifest, &r.copy, &r.ws, &allow_in(&r.ws), &allow) {
            Ok(done) => {
                assert_eq!(done.added, ["f"]);
                assert_eq!(fs::read_to_string(r.ws.join("f")).unwrap(), "from the copy\n");
            }
            Err(AdoptError::Io { message, .. }) => assert!(message.contains("exists"), "{message}"),
            Err(other) => panic!("{other:?}"),
        }
        assert_eq!(listing(&r.outside), before);
        assert_eq!(fs::read_to_string(&victim).unwrap(), "victim\n");
    }

    fn allow_in(ws: &Path) -> impl Fn(&Path) -> Result<(), String> + '_ {
        move |p| if p.starts_with(ws) { Ok(()) } else { Err(format!("{} is outside", p.display())) }
    }

    #[test]
    fn a_failure_after_the_new_file_was_made_removes_it_again() {
        let r = raced(&[("seed", "s")], &[]);
        let made = make(&r.ws, &r.copy, &ROOMY, &allow).unwrap();
        fs::write(r.copy.join("f"), "from the copy\n").unwrap();
        let calls = std::cell::Cell::new(0);
        // After the check a directory with something in it appears where the file is to be renamed to.
        let appear = || {
            fs::create_dir(r.ws.join("f")).unwrap();
            fs::write(r.ws.join("f/inside"), "i").unwrap();
        };
        let may = judge(&r.ws, &calls, 2, &appear);
        let (message, written) = io_message(adopt(&made.manifest, &r.copy, &r.ws, &may, &allow));
        assert!(message.contains("f could not be written"), "{message}");
        assert!(written.is_empty());
        let names: Vec<String> = listing(&r.ws).into_keys().collect();
        assert_eq!(names, ["f", "f/inside", "seed"], "no half-made file is left beside its place");
    }

    #[test]
    fn what_is_brought_has_the_mode_and_time_of_the_copys_file() {
        let r = raced(&[("seed", "s")], &[]);
        let made = make(&r.ws, &r.copy, &ROOMY, &allow).unwrap();
        // Modes that a clone of the file would not let its owner write, and an executable; and a link.
        for (name, mode) in [("ro", 0o400), ("exec", 0o755), ("plain", 0o644)] {
            fs::write(r.copy.join(name), format!("{name}\n")).unwrap();
            fs::set_permissions(r.copy.join(name), fs::Permissions::from_mode(mode)).unwrap();
        }
        std::os::unix::fs::symlink("seed", r.copy.join("lnk")).unwrap();
        let done = adopt(&made.manifest, &r.copy, &r.ws, &allow_in(&r.ws), &allow).unwrap();
        assert_eq!(done.added, ["exec", "lnk", "plain", "ro"]);
        for (name, mode) in [("ro", 0o400), ("exec", 0o755), ("plain", 0o644)] {
            let md = fs::metadata(r.ws.join(name)).unwrap();
            assert_eq!(md.permissions().mode() & 0o7777, mode, "{name}");
            assert_eq!(md.modified().unwrap(), mtime(&r.copy.join(name)), "{name}");
            assert_eq!(fs::read_to_string(r.ws.join(name)).unwrap(), format!("{name}\n"));
        }
        assert_eq!(fs::read_link(r.ws.join("lnk")).unwrap(), PathBuf::from("seed"));
        let left: Vec<String> = listing(&r.ws).into_keys().filter(|n| n.contains("loom-adopt")).collect();
        assert!(left.is_empty(), "{left:?}");
        // And once more: nothing is left to bring, so the files are seen as the copy has them.
        assert!(adopt(&made.manifest, &r.copy, &r.ws, &allow_in(&r.ws), &allow).unwrap().is_empty());
    }

    #[test]
    fn a_file_of_the_workspace_that_may_not_be_read_is_not_the_same_as_the_copys() {
        let f = fx();
        fs::write(f.ws.join("src/secret"), "A").unwrap();
        let made = make(&f.ws, &f.copy, &ROOMY, &allow).unwrap();
        // The file that `readable` refuses by name was edited alike on both sides, down to the time.
        fs::write(f.copy.join("src/secret"), "B").unwrap();
        fs::write(f.ws.join("src/secret"), "B").unwrap();
        set_mtime(&f.ws.join("src/secret"), &stamp(&fs::metadata(f.copy.join("src/secret")).unwrap())).unwrap();
        assert_eq!(alike(seen(&f.ws.join("src/secret"))), alike(seen(&f.copy.join("src/secret"))));
        // Judged fit to read, the two are the same and nothing is to be brought; refused, they are not.
        assert!(adopt(&made.manifest, &f.copy, &f.ws, &allow, &allow).unwrap().is_empty());
        let Err(AdoptError::Conflicts(conflicts)) = adopt(&made.manifest, &f.copy, &f.ws, &allow, &refuse_secret)
        else {
            panic!("a conflict expected")
        };
        assert_eq!(conflicts, [("src/secret".to_string(), "the file there has changed".to_string())]);
        assert_eq!(fs::read_to_string(f.ws.join("src/secret")).unwrap(), "B");
    }

    /// A thread that turns the directory `dir` into the link `link` and back, over and over: each turn
    /// renames the directory to `<dir>.real`, the link to `dir`, and both back, so `dir` names the
    /// directory, nothing, the link, nothing and the directory again (plain renames: they are fast). A
    /// directory that `adopt` makes at `dir` while it names nothing is moved aside to a new name first.
    struct Flipper {
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        turns: std::sync::Arc<AtomicU64>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Flipper {
        fn start(dir: PathBuf, link: PathBuf) -> Flipper {
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let turns = std::sync::Arc::new(AtomicU64::new(0));
            let (stopped, turned) = (stop.clone(), turns.clone());
            let thread = std::thread::spawn(move || {
                let real = dir.with_extension("real");
                let mut strays = 0u64;
                let mut rename = |from: &Path, to: &Path| {
                    let mut tries = 0;
                    while let Err(e) = fs::rename(from, to) {
                        tries += 1;
                        assert!(tries < 1000, "{} cannot be renamed to {}: {e}", from.display(), to.display());
                        strays += 1;
                        let _ = fs::rename(to, to.with_extension(format!("stray{strays}")));
                    }
                };
                while !stopped.load(Ordering::SeqCst) {
                    rename(&dir, &real);
                    rename(&link, &dir);
                    rename(&dir, &link);
                    rename(&real, &dir);
                    turned.fetch_add(1, Ordering::SeqCst);
                }
            });
            Flipper { stop, turns, thread: Some(thread) }
        }

        /// Stop at the end of the turn, so that `dir` is the directory again; how many turns were made.
        fn finish(mut self) -> u64 {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(thread) = self.thread.take() {
                thread.join().unwrap();
            }
            self.turns.load(Ordering::SeqCst)
        }
    }

    impl Drop for Flipper {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
        }
    }

    /// Where a file of that content is under `dir`, however the flipping moved its directory.
    fn found(dir: &Path, name: &str, text: &str) -> bool {
        listing(dir).iter().any(|(rel, bytes)| {
            Path::new(rel).file_name().is_some_and(|n| n == name) && bytes.as_deref() == Some(text.as_bytes())
        })
    }

    /// The scheduler decides when `x` is the directory, nothing or a link to `outside` while `adopt` runs
    /// (the adoptions are many, each in a fresh workspace). Nothing in `outside` ever changes; each run
    /// either brought its file into the workspace or failed. It ends on counts, not on time: once at least
    /// 40 runs have been made, the directory has been the link at least 400 times, and a run was adopted
    /// and a run was refused for the link or the path it really was at, so the runs met both states.
    #[test]
    fn a_directory_swapped_for_a_link_while_adopting_gets_no_file_outside() {
        let r = raced(&[], &[("keep", "k")]);
        let before = listing(&r.outside);
        let started = std::time::Instant::now();
        let (mut runs, mut turns, mut adopted, mut refused) = (0u64, 0u64, 0u64, 0u64);
        while runs < 40 || turns < 400 || adopted == 0 || refused == 0 {
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "the race did not run within 60 s: {runs} runs, {turns} turns, {adopted} adopted, {refused} refused"
            );
            let ws = r.ws.join(format!("run{runs}"));
            let copy = r.copy.join(format!("run{runs}"));
            fs::create_dir_all(ws.join("x")).unwrap();
            fs::write(ws.join("x/seed"), "s").unwrap();
            std::os::unix::fs::symlink(&r.outside, ws.join("x.link")).unwrap();
            let made = make(&ws, &copy, &ROOMY, &allow).unwrap();
            fs::write(copy.join("x/evil.txt"), "from the copy\n").unwrap();
            fs::create_dir_all(copy.join("x/n/deep")).unwrap();
            fs::write(copy.join("x/n/deep/evil.txt"), "from the copy\n").unwrap();
            let flipper = Flipper::start(ws.join("x"), ws.join("x.link"));
            let result = adopt(&made.manifest, &copy, &ws, &allow_in(&ws), &allow);
            turns += flipper.finish();
            match result {
                Ok(done) => {
                    assert_eq!(done.added, ["x/evil.txt", "x/n/deep/evil.txt"]);
                    assert!(found(&ws, "evil.txt", "from the copy\n"));
                    adopted += 1;
                }
                Err(AdoptError::Io { message, .. }) => {
                    if message.contains("symbolic link") || message.contains("outside") {
                        refused += 1;
                    }
                }
                // The workspace is changed under it, as the flipping does: a conflict is no harm either.
                Err(AdoptError::Conflicts(_)) => {}
                Err(other) => panic!("{other:?}"),
            }
            assert_eq!(listing(&r.outside), before, "run {runs} wrote outside the workspace");
            runs += 1;
        }
    }
}
