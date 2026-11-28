//! Read-only views of folders and files on the daemon's machine, for the web UI's folder picker and Files panel.
//!
//! CONTRACT. Every function is blocking (call it from `spawn_blocking`), takes no lock and writes nothing. They
//! return the operator's sentence as `Err`; `crate::api` maps a sentence that starts with `There is no` to `404`
//! and any other to `409`.
//!
//! - [`list_dirs`]`(home, path)`: the folders inside the absolute folder `path` (`~` and `~/x` expand to the
//!   daemon user's home; `None`: the home) as [`DirsView`]. Folders only: no file name, size or content is
//!   returned. Symlinks to folders are listed with `link: true` and the folder they resolve to as `path`;
//!   a link to anything else is left out. Sorted case-insensitively (ties by exact name), at most
//!   [`FS_MAX_ENTRIES`] with the rest counted in `more`. The ferret home is neither listed nor entered: asking for
//!   it or a folder inside it is refused, and an entry that is or resolves into it is left out.
//!   "Inside the ferret home" is judged by file identity (`ferret_tools::files::is_or_inside`), so the macOS
//!   `/System/Volumes/Data/...` spelling and links to it are refused too. The folder is opened once
//!   (`ferret_tools::files::list_dir_judged`: `O_DIRECTORY | O_NOFOLLOW`, then the real path of the open descriptor
//!   is judged and the entries are read and examined through that descriptor), so a link swapped in after the
//!   check lists nothing it should not; each entry's `path` is built from that real path.
//! - [`list_files`]`(root, ferret_home, rel)`: the entries of folder `rel` of the canonical workspace `root`, read
//!   through one descriptor in the same way: the real path of the open folder must lie inside `root`, outside
//!   `<root>/.ferret` (except `<root>/.ferret/uploads` and what is under it, where uploads are kept) and outside the
//!   ferret home, or the folder is refused and nothing is listed.
//! - [`read_file_lines`]`(root, ferret_home, rel, start, count)`: lines of the regular file `rel` of `root`, at most
//!   32 MiB of it read (a larger file is refused with a sentence saying so), `count` clamped to `1..=5000`. Only
//!   the requested lines are kept: no per-line index is built, so memory stays at the file's size.
//! - Path safety for both file functions ([`resolve_in`]): `rel` is relative; an absolute path, a `..` component
//!   and a NUL are refused; the target is resolved (links followed) and must lie inside `root`; a symlink that
//!   leads outside is refused, never followed; nothing inside `<root>/.ferret` except `.ferret/uploads` is reachable by any route, by name
//!   or through a link (the listing shows `.ferret` of the root as a closed entry); nothing that resolves into
//!   `ferret_home` (the daemon's token and keys) is reachable either, which matters for a workspace that holds the
//!   ferret home. A file is opened with
//!   `ferret_tools::files::open_readable`, which judges the real path of the open descriptor, so a link swapped in
//!   after the check reaches nothing outside either.
//! - Entries that cannot be examined carry `error`; an unreadable folder is refused as a whole with the
//!   system's reason.
//!
//! Tests required: sorting and the cap in both listings; hidden and link flags; the ferret home refused and left
//! out; `..`, absolute, NUL, symlink outside, link into `.ferret`, `.ferret` by name; the 32 MiB refusal; binary;
//! line paging and totals; a missing file or folder; a folder swapped for a link after the check, at its last
//! component and in the middle of its path, in both listings; a root that holds the ferret home; the memory
//! used by a 32 MiB file of newlines.

use crate::wire::{DirEntryView, DirsView, FileEntryView, FileLinesView, FilesView, FS_MAX_ENTRIES};
use ferret_agent::runtime::expand_home;
use ferret_core::config::Paths;
use ferret_tools::files::{
    describe_type, file_id, is_or_inside, list_dir_judged, open_readable, real_path, ItemKind, NotOpened,
};
use std::ffi::OsStr;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

/// The most of a file the viewer reads.
pub const READ_CAP: u64 = 32 * 1024 * 1024;
const LINES_DEFAULT: u64 = 2_000;
const LINES_MAX: u64 = 5_000;
const BINARY_PROBE: usize = 8 * 1024;
/// What the listing says of the root's `.ferret`.
pub const HARNESS_NOTE: &str = "harness files are not shown";

fn hidden(name: &str) -> bool {
    name.starts_with('.')
}

fn sort_key(name: &str) -> (String, String) {
    (name.to_lowercase(), name.to_string())
}

fn mtime_ms(meta: &std::fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn lossless(path: &Path) -> Option<String> {
    path.to_str().map(str::to_string)
}

/// The folders inside `path` (see the contract).
pub fn list_dirs(paths: &Paths, home: Option<&Path>, path: Option<&str>) -> Result<DirsView, String> {
    list_dirs_with(paths, home, path, &|| {})
}

fn ferret_home_refusal(ferret_home: &Path) -> String {
    format!(
        "The ferret home ({}) is not listed: it holds the daemon's keys and sessions. Choose another folder.",
        ferret_home.display()
    )
}

/// [`list_dirs`] with `after_check` run between the path check and the open (tests swap the folder there).
fn list_dirs_with(
    paths: &Paths,
    home: Option<&Path>,
    path: Option<&str>,
    after_check: &dyn Fn(),
) -> Result<DirsView, String> {
    let asked: PathBuf = match path.map(str::trim).filter(|p| !p.is_empty()) {
        Some(p) => expand_home(Path::new(p), home)?,
        None => home
            .map(Path::to_path_buf)
            .ok_or_else(|| "The daemon does not know your home directory. Give an absolute folder path.".to_string())?,
    };
    if !asked.is_absolute() {
        return Err(format!("{} is not an absolute path. Give a path that starts with / or ~/.", asked.display()));
    }
    let canonical = std::fs::canonicalize(&asked).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            format!("There is no folder {}.", asked.display())
        } else {
            format!("The folder {} cannot be read: {e}.", asked.display())
        }
    })?;
    if !canonical.is_dir() {
        return Err(format!("{} is not a folder.", canonical.display()));
    }
    let ferret_home = paths.home.as_path();
    if is_or_inside(&canonical, ferret_home) {
        return Err(ferret_home_refusal(ferret_home));
    }
    after_check();
    let judge = |real: &Path| -> Result<(), String> {
        if is_or_inside(real, ferret_home) {
            Err(ferret_home_refusal(ferret_home))
        } else {
            Ok(())
        }
    };
    let (real, items) = list_dir_judged(&canonical, &judge).map_err(|e| match e {
        NotOpened::Io(e) => format!("The folder {} cannot be listed: {e}.", canonical.display()),
        NotOpened::NotRegular(_) => format!("{} is not a folder.", canonical.display()),
        NotOpened::Denied(s) => s,
    })?;
    let home_id = file_id(ferret_home);
    let mut found: Vec<DirEntryView> = Vec::new();
    for item in items {
        let Ok(name) = item.name.into_string() else { continue };
        if item.error.is_some() {
            continue;
        }
        let (path, link) = match item.kind {
            ItemKind::Dir => {
                if home_id == Some((item.dev, item.ino)) {
                    continue;
                }
                (real.join(&name), false)
            }
            ItemKind::Link if item.link_to_dir => match std::fs::canonicalize(real.join(&name)) {
                Ok(target) if target.is_dir() && !is_or_inside(&target, ferret_home) => (target, true),
                _ => continue,
            },
            _ => continue,
        };
        let Some(path) = lossless(&path) else { continue };
        found.push(DirEntryView { hidden: hidden(&name), name, path, link });
    }
    found.sort_by_cached_key(|e| sort_key(&e.name));
    let more = found.len().saturating_sub(FS_MAX_ENTRIES) as u64;
    found.truncate(FS_MAX_ENTRIES);
    Ok(DirsView {
        path: lossless(&real).ok_or_else(|| "That folder's name is not text.".to_string())?,
        parent: real.parent().and_then(lossless),
        home: home.and_then(lossless),
        entries: found,
        more,
    })
}

/// `rel` as `/`-separated normal components. Refuses what cannot name something inside a workspace.
fn clean_rel(rel: &str) -> Result<Vec<&OsStr>, String> {
    if rel.contains('\0') {
        return Err("That path is not valid: it contains a NUL character.".to_string());
    }
    let mut parts = Vec::new();
    for c in Path::new(rel).components() {
        match c {
            Component::Normal(n) => parts.push(n),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(format!(
                    "The path {rel} uses `..`. Paths are relative to the workspace and stay inside it."
                ));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(format!("The path {rel} is absolute. Give a path relative to the workspace."));
            }
        }
    }
    Ok(parts)
}

/// Whether `p` lies inside `<root>/.ferret` (the first component under the root, whatever its case: a volume may
/// not tell `.ferret` from `.FERRET`), except `<root>/.ferret/uploads` and what is under it (`docs/UPLOADS.md`).
fn in_harness(root: &Path, p: &Path) -> bool {
    let Ok(rel) = p.strip_prefix(root) else { return false };
    let mut parts = rel.components().map(|c| c.as_os_str().to_string_lossy());
    parts.next().is_some_and(|c| c.eq_ignore_ascii_case(".ferret")) && parts.next().is_none_or(|c| c != UPLOADS_DIR)
}

/// The folder under `<root>/.ferret` that holds uploads.
const UPLOADS_DIR: &str = "uploads";

/// Whether the cleaned relative path `parts` is `.ferret/uploads` or inside it.
fn in_uploads(parts: &[&OsStr]) -> bool {
    parts.len() >= 2
        && parts.first().is_some_and(|p| p.to_string_lossy().eq_ignore_ascii_case(".ferret"))
        && parts.get(1).is_some_and(|p| p.to_string_lossy() == UPLOADS_DIR)
}

/// The sentence for a target that is, or leads into, the ferret home.
fn home_note(text: &str, ferret_home: &Path) -> String {
    let what = if text.is_empty() { "The workspace root" } else { text };
    format!("{what} is inside the ferret home ({}), which holds the daemon's keys: it is not shown.", ferret_home.display())
}

/// The target of `rel` inside `root` (canonical), resolved, with its normalised relative text.
pub fn resolve_in(root: &Path, ferret_home: &Path, rel: &str) -> Result<(PathBuf, String), String> {
    let parts = clean_rel(rel)?;
    let text = parts.iter().map(|p| p.to_string_lossy().into_owned()).collect::<Vec<_>>().join("/");
    if parts.first().is_some_and(|p| p.to_string_lossy().eq_ignore_ascii_case(".ferret")) && !in_uploads(&parts) {
        return Err(format!("{text} is not shown: {HARNESS_NOTE}."));
    }
    let mut joined = root.to_path_buf();
    joined.extend(&parts);
    let resolved = std::fs::canonicalize(&joined).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            format!("There is no file or folder {text} in the workspace.")
        } else {
            format!("{text} cannot be read: {e}.")
        }
    })?;
    if !resolved.starts_with(root) {
        return Err(format!(
            "{text} is a link that leads outside the workspace ({}); it is not followed.",
            resolved.display()
        ));
    }
    if in_harness(root, &resolved) {
        return Err(format!("{text} leads into the workspace's .ferret folder: {HARNESS_NOTE}."));
    }
    if is_or_inside(&resolved, ferret_home) {
        return Err(home_note(&text, ferret_home));
    }
    Ok((resolved, text))
}

/// The real path of the open workspace root, which may be spelled differently from `root` (macOS data volume).
fn real_root(root: &Path) -> PathBuf {
    use std::os::fd::AsFd;
    std::fs::File::open(root).ok().and_then(|f| real_path(f.as_fd()).ok()).unwrap_or_else(|| root.to_path_buf())
}

/// Judges the real path of what was opened: it must lie inside the workspace (under either spelling of the
/// root), outside `<root>/.ferret` and outside the ferret home.
fn judge_real<'a>(
    forms: &'a [PathBuf],
    ferret_home: &'a Path,
    text: String,
) -> impl Fn(&Path) -> Result<(), String> + 'a {
    move |real: &Path| {
        let shown = if text.is_empty() { "The workspace root" } else { text.as_str() };
        let Some(form) = forms.iter().find(|f| real.starts_with(f)) else {
            return Err(format!("{shown} leads outside the workspace; it is not opened."));
        };
        if in_harness(form, real) {
            return Err(format!("{shown} leads into the workspace's .ferret folder: {HARNESS_NOTE}."));
        }
        if is_or_inside(real, ferret_home) {
            return Err(home_note(&text, ferret_home));
        }
        Ok(())
    }
}

/// The entries of folder `rel` of `root`.
pub fn list_files(root: &Path, ferret_home: &Path, rel: &str) -> Result<FilesView, String> {
    list_files_with(root, ferret_home, rel, &|| {})
}

/// [`list_files`] with `after_check` run between the path check and the open (tests swap the folder there).
fn list_files_with(root: &Path, ferret_home: &Path, rel: &str, after_check: &dyn Fn()) -> Result<FilesView, String> {
    let (dir, text) = resolve_in(root, ferret_home, rel)?;
    let shown = if text.is_empty() { "the workspace root".to_string() } else { text.clone() };
    if !dir.is_dir() {
        return Err(format!("{shown} is a file, not a folder. Open it as a file to read its contents."));
    }
    after_check();
    let forms = [real_root(root), root.to_path_buf()];
    let judge = judge_real(&forms, ferret_home, text.clone());
    let (real, items) = list_dir_judged(&dir, &judge).map_err(|e| match e {
        NotOpened::Io(e) => format!("{shown} cannot be listed: {e}."),
        NotOpened::NotRegular(_) => {
            format!("{shown} is a file, not a folder. Open it as a file to read its contents.")
        }
        NotOpened::Denied(s) => s,
    })?;
    let at_root = forms.contains(&real);
    let mut found: Vec<FileEntryView> = Vec::new();
    for item in items {
        let Ok(name) = item.name.into_string() else { continue };
        let kind = match item.kind {
            ItemKind::Dir => "dir",
            ItemKind::File => "file",
            ItemKind::Link => "link",
            ItemKind::Other => "other",
        };
        let note = (at_root && name.eq_ignore_ascii_case(".ferret")).then(|| HARNESS_NOTE.to_string());
        found.push(FileEntryView {
            hidden: hidden(&name),
            name,
            kind: kind.to_string(),
            size: if note.is_some() { 0 } else { item.size },
            mtime_ms: if note.is_some() { 0 } else { item.mtime_ms },
            note,
            error: item.error,
        });
    }
    found.sort_by_cached_key(|e| (e.kind != "dir", sort_key(&e.name)));
    let more = found.len().saturating_sub(FS_MAX_ENTRIES) as u64;
    found.truncate(FS_MAX_ENTRIES);
    Ok(FilesView { root: lossless(root).unwrap_or_default(), path: text, entries: found, more })
}

fn read_bounded(file: std::fs::File, meta_bytes: u64, text: &str) -> Result<Vec<u8>, String> {
    let too_large = |size: u64| {
        format!(
            "{text} is {} MiB, more than the {} MiB the viewer reads. Look at part of it with `sed -n` or `head` in a terminal.",
            size.div_ceil(1024 * 1024),
            READ_CAP / (1024 * 1024)
        )
    };
    if meta_bytes > READ_CAP {
        return Err(too_large(meta_bytes));
    }
    let mut data = Vec::with_capacity(usize::try_from(meta_bytes).unwrap_or(0).saturating_add(1));
    file.take(READ_CAP.saturating_add(1)).read_to_end(&mut data).map_err(|e| format!("{text} cannot be read: {e}."))?;
    let size = data.len() as u64;
    if size > READ_CAP {
        return Err(too_large(size));
    }
    Ok(data)
}

/// Lines `start..start+count` of file `rel` of `root`.
pub fn read_file_lines(
    root: &Path,
    ferret_home: &Path,
    rel: &str,
    start: Option<u64>,
    count: Option<u64>,
) -> Result<FileLinesView, String> {
    let (path, text) = resolve_in(root, ferret_home, rel)?;
    if text.is_empty() {
        return Err("Name a file: the path is the workspace root.".to_string());
    }
    let forms = [real_root(root), root.to_path_buf()];
    let judge = judge_real(&forms, ferret_home, text.clone());
    let (file, meta) = open_readable(&path, &judge).map_err(|e| match e {
        NotOpened::Io(e) => format!("{text} cannot be opened: {e}."),
        NotOpened::NotRegular(t) => format!("{text} is {}, not a file that can be shown.", describe_type(&t)),
        NotOpened::Denied(s) => s,
    })?;
    let data = read_bounded(file, meta.len(), &text)?;
    let mtime = mtime_ms(&meta);
    let size = data.len() as u64;
    if data.iter().take(BINARY_PROBE).any(|b| *b == 0) {
        return Ok(FileLinesView {
            path: text,
            text: String::new(),
            first: 0,
            last: 0,
            total: 0,
            total_lines: 0,
            bytes: size,
            mtime_ms: mtime,
            binary: true,
        });
    }
    let first = start.unwrap_or(1).max(1);
    let count = count.unwrap_or(LINES_DEFAULT).clamp(1, LINES_MAX);
    let page = page_lines(&data, first, count);
    let body = if first > page.total {
        String::new()
    } else {
        String::from_utf8_lossy(data.get(page.from..page.to).unwrap_or_default()).into_owned()
    };
    Ok(FileLinesView {
        path: text,
        text: body,
        first,
        last: page.last,
        total: page.total,
        total_lines: page.total,
        bytes: size,
        mtime_ms: mtime,
        binary: false,
    })
}

/// Where lines `first..first+count` of `data` lie.
struct Page {
    total: u64,
    last: u64,
    from: usize,
    to: usize,
}

/// One pass over `data`: the number of lines, the last line of the page, and the byte range of the page. A final
/// newline does not start another line. Nothing is kept per line.
fn page_lines(data: &[u8], first: u64, count: u64) -> Page {
    let want_last = first.saturating_add(count.saturating_sub(1));
    let after = want_last.saturating_add(1);
    let mut total = 0u64;
    let (mut from, mut to) = (None, None);
    if !data.is_empty() {
        total = 1;
        if first == 1 {
            from = Some(0usize);
        }
    }
    for (i, b) in data.iter().enumerate() {
        if *b == b'\n' && i + 1 < data.len() {
            total += 1;
            if total == first {
                from = Some(i + 1);
            }
            if total == after {
                to = Some(i + 1);
            }
        }
    }
    Page { total, last: want_last.min(total), from: from.unwrap_or(data.len()), to: to.unwrap_or(data.len()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    /// The ferret home of `tree()`: a sibling of the workspace.
    fn lh(root: &Path) -> PathBuf {
        root.parent().unwrap().join("home")
    }

    fn tree() -> (tempfile::TempDir, PathBuf, PathBuf, Paths) {
        let d = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(d.path()).unwrap();
        let root = base.join("ws");
        std::fs::create_dir_all(root.join("src/deep")).unwrap();
        std::fs::create_dir_all(root.join(".ferret")).unwrap();
        std::fs::write(root.join(".ferret/secret"), "oracle").unwrap();
        std::fs::write(root.join("a.txt"), "one\ntwo\nthree\n").unwrap();
        std::fs::write(root.join("B.txt"), "no newline at end").unwrap();
        std::fs::write(root.join("bin.dat"), [1u8, 0, 2]).unwrap();
        std::fs::write(root.join("src/lib.rs"), "fn main() {}\n").unwrap();
        let outside = base.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("pw"), "x").unwrap();
        symlink(&outside, root.join("escape")).unwrap();
        symlink(outside.join("pw"), root.join("escape.txt")).unwrap();
        symlink(root.join("src"), root.join("inner")).unwrap();
        symlink(root.join(".ferret"), root.join("into-ferret")).unwrap();
        let paths = Paths::at(base.join("home"));
        std::fs::create_dir_all(&paths.home).unwrap();
        (d, root, base, paths)
    }

    #[test]
    fn dirs_are_folders_only_sorted_with_hidden_and_link_flags() {
        let (_d, root, base, paths) = tree();
        std::fs::create_dir_all(root.join("Zed")).unwrap();
        std::fs::create_dir_all(root.join("alpha")).unwrap();
        std::fs::create_dir_all(root.join(".hid")).unwrap();
        let v = list_dirs(&paths, Some(&base), Some(root.to_str().unwrap())).unwrap();
        let names: Vec<&str> = v.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, [".ferret", ".hid", "alpha", "escape", "inner", "into-ferret", "src", "Zed"]);
        assert!(v.entries[0].hidden && !v.entries[2].hidden);
        let escape = v.entries.iter().find(|e| e.name == "escape").unwrap();
        assert!(escape.link && escape.path == base.join("outside").to_str().unwrap());
        assert!(!v.entries.iter().any(|e| e.name.ends_with(".txt") || e.name == "bin.dat"), "files are not listed");
        assert_eq!(v.parent.as_deref(), base.to_str());
        assert_eq!(v.home.as_deref(), base.to_str());
        assert_eq!(v.more, 0);
        // Default is the home; `~` expands.
        assert_eq!(list_dirs(&paths, Some(&root), None).unwrap().path, root.to_str().unwrap());
        assert_eq!(list_dirs(&paths, Some(&root), Some("~/src")).unwrap().path, root.join("src").to_str().unwrap());
        assert!(list_dirs(&paths, None, None).unwrap_err().contains("home directory"));
    }

    #[test]
    fn dirs_refuses_relative_missing_files_and_the_ferret_home_and_leaves_links_to_it_out() {
        let (_d, root, base, paths) = tree();
        assert!(list_dirs(&paths, None, Some("rel/x")).unwrap_err().contains("not an absolute path"));
        let missing = root.join("nope");
        let err = list_dirs(&paths, None, Some(missing.to_str().unwrap())).unwrap_err();
        assert!(err.starts_with("There is no folder"), "{err}");
        let err = list_dirs(&paths, None, Some(root.join("a.txt").to_str().unwrap())).unwrap_err();
        assert!(err.contains("not a folder"), "{err}");
        for p in [paths.home.clone(), paths.home.join("sessions")] {
            std::fs::create_dir_all(&p).unwrap();
            let err = list_dirs(&paths, None, Some(p.to_str().unwrap())).unwrap_err();
            assert!(err.contains("ferret home"), "{err}");
        }
        // A link that leads into the home is refused, and an entry that leads there is not listed.
        symlink(&paths.home, base.join("homelink")).unwrap();
        let err = list_dirs(&paths, None, Some(base.join("homelink").to_str().unwrap())).unwrap_err();
        assert!(err.contains("ferret home"), "{err}");
        let v = list_dirs(&paths, None, Some(base.to_str().unwrap())).unwrap();
        assert!(!v.entries.iter().any(|e| e.name == "homelink" || e.name == "home"), "{:?}", v.entries);
        assert!(v.entries.iter().any(|e| e.name == "ws"));
    }

    #[test]
    fn dirs_caps_the_listing_and_counts_the_rest() {
        let (_d, root, _base, paths) = tree();
        let many = root.join("many");
        std::fs::create_dir_all(&many).unwrap();
        for i in 0..(FS_MAX_ENTRIES + 7) {
            std::fs::create_dir(many.join(format!("d{i:05}"))).unwrap();
        }
        let v = list_dirs(&paths, None, Some(many.to_str().unwrap())).unwrap();
        assert_eq!((v.entries.len(), v.more), (FS_MAX_ENTRIES, 7));
        assert_eq!(v.entries[0].name, "d00000");
    }

    #[test]
    fn files_list_dirs_first_sorted_with_kinds_and_the_closed_harness_entry() {
        let (_d, root, _base, _paths) = tree();
        let v = list_files(&root, &lh(&root), "").unwrap();
        assert_eq!((v.root.as_str(), v.path.as_str(), v.more), (root.to_str().unwrap(), "", 0));
        let got: Vec<(&str, &str)> = v.entries.iter().map(|e| (e.name.as_str(), e.kind.as_str())).collect();
        assert_eq!(
            got,
            [
                (".ferret", "dir"),
                ("src", "dir"),
                ("a.txt", "file"),
                ("B.txt", "file"),
                ("bin.dat", "file"),
                ("escape", "link"),
                ("escape.txt", "link"),
                ("inner", "link"),
                ("into-ferret", "link"),
            ]
        );
        let ferret = &v.entries[0];
        assert!(ferret.hidden && ferret.note.as_deref() == Some(HARNESS_NOTE));
        let a = v.entries.iter().find(|e| e.name == "a.txt").unwrap();
        assert_eq!(a.size, 14);
        assert!(a.mtime_ms > 0 && a.note.is_none() && a.error.is_none());
        let sub = list_files(&root, &lh(&root), "src/").unwrap();
        assert_eq!((sub.path.as_str(), sub.entries.len()), ("src", 2));
        assert_eq!(
            list_files(&root, &lh(&root), "inner").unwrap().entries.len(),
            2,
            "a link inside the workspace is followed"
        );
        let file_err = list_files(&root, &lh(&root), "a.txt").unwrap_err();
        assert!(file_err.contains("is a file") && !file_err.contains("files/lines route"), "{file_err}");
        assert!(list_files(&root, &lh(&root), "nope").unwrap_err().starts_with("There is no"));
    }

    #[test]
    fn uploads_under_the_harness_folder_are_listed_and_read_but_nothing_else_of_it() {
        let (_d, root, _base, _paths) = tree();
        let up = root.join(".ferret/uploads");
        std::fs::create_dir_all(up.join("sub")).unwrap();
        std::fs::write(up.join("r.csv"), "a,b\n1,2\n").unwrap();
        std::fs::write(up.join("sub/x.txt"), "x").unwrap();
        symlink(root.join(".ferret/secret"), up.join("peek")).unwrap();
        let lh = lh(&root);
        let v = list_files(&root, &lh, ".ferret/uploads").unwrap();
        let names: Vec<&str> = v.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["sub", "peek", "r.csv"]);
        assert_eq!(list_files(&root, &lh, ".ferret/uploads/sub").unwrap().entries.len(), 1);
        let f = read_file_lines(&root, &lh, ".ferret/uploads/r.csv", None, None).unwrap();
        assert_eq!((f.text.as_str(), f.total), ("a,b\n1,2\n", 2));
        // The rest of `.ferret` stays closed, and so does a link out of uploads into it.
        for rel in [".ferret", ".ferret/secret", ".ferret/uploadsx", ".ferret/Uploads2/a", ".ferret/uploads/peek"] {
            assert!(list_files(&root, &lh, rel).is_err(), "{rel}");
            assert!(read_file_lines(&root, &lh, rel, None, None).is_err(), "{rel}");
        }
        let root_listing = list_files(&root, &lh, "").unwrap();
        let ferret = root_listing.entries.iter().find(|e| e.name == ".ferret").unwrap();
        assert_eq!(ferret.note.as_deref(), Some(HARNESS_NOTE));
    }

    #[test]
    fn files_refuse_escapes_by_name_and_by_link() {
        let (_d, root, base, _paths) = tree();
        let abs = base.join("outside").display().to_string();
        for rel in ["..", "../outside", "src/../../outside", &abs, "a\0b"] {
            assert!(list_files(&root, &lh(&root), rel).is_err(), "{rel}");
            assert!(read_file_lines(&root, &lh(&root), rel, None, None).is_err(), "{rel}");
        }
        assert!(list_files(&root, &lh(&root), "escape").unwrap_err().contains("outside the workspace"));
        assert!(read_file_lines(&root, &lh(&root), "escape.txt", None, None)
            .unwrap_err()
            .contains("outside the workspace"));
        assert!(read_file_lines(&root, &lh(&root), "escape/pw", None, None)
            .unwrap_err()
            .contains("outside the workspace"));
        for rel in [".ferret", ".ferret/secret", ".FERRET/secret", "into-ferret", "into-ferret/secret", "./.ferret/secret"] {
            let e = list_files(&root, &lh(&root), rel).unwrap_err();
            assert!(e.contains(HARNESS_NOTE), "{rel}: {e}");
            let e = read_file_lines(&root, &lh(&root), rel, None, None).unwrap_err();
            assert!(e.contains(HARNESS_NOTE) || e.contains("not opened"), "{rel}: {e}");
        }
        // A file named like the harness folder deeper down is an ordinary file.
        std::fs::create_dir_all(root.join("src/.ferret")).unwrap();
        assert!(list_files(&root, &lh(&root), "src/.ferret").is_ok());
    }

    #[test]
    fn lines_page_count_and_report_totals_binary_and_the_cap() {
        let (_d, root, _base, _paths) = tree();
        let v = read_file_lines(&root, &lh(&root), "a.txt", None, None).unwrap();
        assert_eq!(
            (v.text.as_str(), v.first, v.last, v.total, v.total_lines, v.bytes),
            ("one\ntwo\nthree\n", 1, 3, 3, 3, 14)
        );
        assert!(!v.binary && v.mtime_ms > 0 && v.path == "a.txt");
        let v = read_file_lines(&root, &lh(&root), "./a.txt", Some(2), Some(1)).unwrap();
        assert_eq!((v.text.as_str(), v.first, v.last, v.total), ("two\n", 2, 2, 3));
        let v = read_file_lines(&root, &lh(&root), "a.txt", Some(3), Some(99)).unwrap();
        assert_eq!((v.text.as_str(), v.last), ("three\n", 3));
        let v = read_file_lines(&root, &lh(&root), "a.txt", Some(9), None).unwrap();
        assert_eq!((v.text.as_str(), v.total), ("", 3));
        let v = read_file_lines(&root, &lh(&root), "a.txt", Some(0), Some(0)).unwrap();
        assert_eq!((v.text.as_str(), v.first, v.last), ("one\n", 1, 1));
        let v = read_file_lines(&root, &lh(&root), "B.txt", None, None).unwrap();
        assert_eq!((v.text.as_str(), v.total), ("no newline at end", 1));
        let v = read_file_lines(&root, &lh(&root), "bin.dat", None, None).unwrap();
        assert!(v.binary && v.text.is_empty() && v.total == 0 && v.bytes == 3);
        let v = read_file_lines(&root, &lh(&root), "inner/lib.rs", None, None).unwrap();
        assert_eq!((v.path.as_str(), v.total), ("inner/lib.rs", 1));
        std::fs::write(root.join("empty"), "").unwrap();
        assert_eq!(read_file_lines(&root, &lh(&root), "empty", None, None).unwrap().total, 0);
        assert!(read_file_lines(&root, &lh(&root), "", None, None).is_err());
        assert!(read_file_lines(&root, &lh(&root), "src", None, None).unwrap_err().contains("not a file"));
        assert!(read_file_lines(&root, &lh(&root), "nope.txt", None, None).unwrap_err().starts_with("There is no"));
        let big = std::fs::File::create(root.join("big.bin")).unwrap();
        big.set_len(READ_CAP + 1).unwrap();
        let e = read_file_lines(&root, &lh(&root), "big.bin", None, None).unwrap_err();
        assert!(e.contains("33 MiB") && e.contains("32 MiB") && e.contains("sed -n"), "{e}");
    }

    #[test]
    fn a_listing_is_capped_with_the_rest_counted() {
        let (_d, root, _base, _paths) = tree();
        let many = root.join("many");
        std::fs::create_dir_all(&many).unwrap();
        for i in 0..(FS_MAX_ENTRIES + 3) {
            std::fs::write(many.join(format!("f{i:05}")), "").unwrap();
        }
        let v = list_files(&root, &lh(&root), "many").unwrap();
        assert_eq!((v.entries.len(), v.more), (FS_MAX_ENTRIES, 3));
    }
    #[test]
    fn a_folder_swapped_for_a_link_after_the_check_lists_nothing_it_should_not() {
        let (_d, root, base, paths) = tree();
        std::fs::create_dir_all(root.join("src/deep")).unwrap();
        std::fs::create_dir_all(root.join(".ferret/deep")).unwrap();
        // Last component: `src` becomes a link to `.ferret` between the check and the open.
        let swap_last = || {
            std::fs::rename(root.join("src"), root.join("src.moved")).unwrap();
            symlink(root.join(".ferret"), root.join("src")).unwrap();
        };
        let err = list_files_with(&root, &paths.home, "src", &swap_last).unwrap_err();
        assert!(!err.contains("secret") && !err.is_empty(), "{err}");
        std::fs::remove_file(root.join("src")).unwrap();
        std::fs::rename(root.join("src.moved"), root.join("src")).unwrap();
        // Middle component: `src` becomes a link to `.ferret`, and `.ferret/deep` exists.
        let swap_mid = || {
            std::fs::rename(root.join("src"), root.join("src.moved")).unwrap();
            symlink(root.join(".ferret"), root.join("src")).unwrap();
        };
        let err = list_files_with(&root, &paths.home, "src/deep", &swap_mid).unwrap_err();
        assert!(err.contains(".ferret") && err.contains(HARNESS_NOTE), "{err}");
        std::fs::remove_file(root.join("src")).unwrap();
        std::fs::rename(root.join("src.moved"), root.join("src")).unwrap();
        // A link to a folder outside the workspace reaches nothing either.
        let swap_out = || {
            std::fs::rename(root.join("src"), root.join("src.moved")).unwrap();
            symlink(base.join("outside"), root.join("src")).unwrap();
        };
        let err = list_files_with(&root, &paths.home, "src", &swap_out).unwrap_err();
        assert!(!err.is_empty());
        std::fs::remove_file(root.join("src")).unwrap();
        std::fs::rename(root.join("src.moved"), root.join("src")).unwrap();
        // Unswapped it still lists.
        assert_eq!(list_files_with(&root, &paths.home, "src", &|| {}).unwrap().entries.len(), 2);
        // The picker's listing has the same gap closed: `src` becomes a link to the ferret home.
        std::fs::create_dir_all(paths.home.join("sessions")).unwrap();
        let asked = root.join("src");
        let swap_home = || {
            std::fs::rename(root.join("src"), root.join("src.moved")).unwrap();
            symlink(&paths.home, root.join("src")).unwrap();
        };
        let err = list_dirs_with(&paths, None, asked.to_str(), &swap_home).unwrap_err();
        assert!(err.contains("cannot be listed") || err.contains("ferret home"), "{err}");
        assert!(!err.contains("sessions"), "{err}");
    }

    #[test]
    fn nothing_that_resolves_into_the_ferret_home_is_reachable_even_from_a_root_that_holds_it() {
        let (_d, root, base, paths) = tree();
        // A workspace that is the folder that holds the ferret home: `home/token` is not readable through it.
        std::fs::write(paths.home.join("token"), "permanent").unwrap();
        std::fs::create_dir_all(paths.home.join("keys")).unwrap();
        for rel in ["home", "home/token", "home/keys"] {
            let e = list_files(&base, &paths.home, rel)
                .err()
                .or_else(|| read_file_lines(&base, &paths.home, rel, None, None).err());
            assert!(e.is_some_and(|e| e.contains("ferret home")), "{rel}");
        }
        let e = read_file_lines(&base, &paths.home, "home/token", None, None).unwrap_err();
        assert!(e.contains("ferret home") && !e.contains("permanent"), "{e}");
        // A link inside the workspace to the home, and a workspace that is the home itself.
        symlink(&paths.home, root.join("homelink")).unwrap();
        assert!(read_file_lines(&root, &paths.home, "homelink/token", None, None)
            .is_err_and(|e| e.contains("outside") || e.contains("ferret home")));
        let e = list_files(&paths.home, &paths.home, "").unwrap_err();
        assert!(e.contains("ferret home"), "{e}");
        // Other files of the same root are still read.
        assert!(read_file_lines(&base, &paths.home, "ws/a.txt", None, None).is_ok());
        assert!(list_files(&base, &paths.home, "ws").is_ok());
    }

    #[test]
    fn dirs_judges_the_ferret_home_by_identity_not_by_spelling() {
        let (_d, _root, base, paths) = tree();
        #[cfg(target_os = "macos")]
        {
            let alias = Path::new("/System/Volumes/Data").join(paths.home.strip_prefix("/").unwrap());
            if alias.is_dir() {
                for p in [alias.clone(), alias.join("..").join("home")] {
                    let err = list_dirs(&paths, None, p.to_str()).unwrap_err();
                    assert!(err.contains("ferret home"), "{}: {err}", p.display());
                }
                let up = Path::new("/System/Volumes/Data").join(base.strip_prefix("/").unwrap());
                let v = list_dirs(&paths, None, up.to_str()).unwrap();
                assert!(!v.entries.iter().any(|e| e.name == "home"), "{:?}", v.entries);
            }
        }
        // A link that leads to a folder inside the home is left out of its parent's listing.
        std::fs::create_dir_all(paths.home.join("sessions")).unwrap();
        symlink(paths.home.join("sessions"), base.join("deeplink")).unwrap();
        let v = list_dirs(&paths, None, base.to_str()).unwrap();
        assert!(!v.entries.iter().any(|e| e.name == "deeplink"));
    }

    /// Bytes allocated and not yet freed on this thread, and the most that was ever outstanding since the reset.
    mod count {
        use std::alloc::{GlobalAlloc, Layout, System};
        use std::cell::Cell;

        thread_local! {
            static LIVE: Cell<i64> = const { Cell::new(0) };
            static PEAK: Cell<i64> = const { Cell::new(0) };
        }

        pub struct Counting;

        // SAFETY: every call is passed to the system allocator unchanged; the counters are thread-local plain cells.
        unsafe impl GlobalAlloc for Counting {
            unsafe fn alloc(&self, l: Layout) -> *mut u8 {
                let p = System.alloc(l);
                if !p.is_null() {
                    let _ = LIVE.try_with(|c| {
                        c.set(c.get().saturating_add(l.size() as i64));
                        let _ = PEAK.try_with(|k| k.set(k.get().max(c.get())));
                    });
                }
                p
            }
            unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
                System.dealloc(p, l);
                let _ = LIVE.try_with(|c| c.set(c.get().saturating_sub(l.size() as i64)));
            }
            unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
                let q = System.realloc(p, l, new);
                if !q.is_null() {
                    let _ = LIVE.try_with(|c| {
                        c.set(c.get().saturating_add(new as i64).saturating_sub(l.size() as i64));
                        let _ = PEAK.try_with(|k| k.set(k.get().max(c.get())));
                    });
                }
                q
            }
        }

        pub fn reset() {
            LIVE.with(|c| PEAK.with(|k| k.set(c.get())));
        }

        pub fn peak_above_reset(base: i64) -> i64 {
            PEAK.with(Cell::get) - base
        }

        pub fn live() -> i64 {
            LIVE.with(Cell::get)
        }
    }

    #[global_allocator]
    static COUNTING: count::Counting = count::Counting;

    #[test]
    fn paging_a_file_of_newlines_does_not_index_every_line() {
        let (_d, root, _base, _paths) = tree();
        let n = usize::try_from(READ_CAP).unwrap();
        std::fs::write(root.join("nl.txt"), vec![b'\n'; n]).unwrap();
        let base = count::live();
        count::reset();
        let v = read_file_lines(&root, &lh(&root), "nl.txt", Some(3), Some(5)).unwrap();
        let peak = count::peak_above_reset(base);
        assert_eq!((v.first, v.last, v.total), (3, 7, READ_CAP));
        assert_eq!(v.text, "\n\n\n\n\n");
        // The file itself (32 MiB) and a little more; a Vec of one usize per line would add 256 MiB.
        assert!(peak < 40 * 1024 * 1024, "peak {} MiB", peak / (1024 * 1024));
    }

    #[test]
    fn page_lines_matches_a_line_by_line_reading() {
        for data in [&b""[..], b"a", b"a\n", b"a\nb", b"a\nb\n", b"\n\n", b"x\ny\nz\nw"] {
            let lines: Vec<&[u8]> = data.split_inclusive(|b| *b == b'\n').collect();
            for first in 1..=5u64 {
                for count in 1..=4u64 {
                    let p = page_lines(data, first, count);
                    assert_eq!(p.total, lines.len() as u64, "{data:?}");
                    let want: Vec<u8> = lines
                        .iter()
                        .skip(usize::try_from(first - 1).unwrap())
                        .take(usize::try_from(count).unwrap())
                        .flat_map(|l| l.iter().copied())
                        .collect();
                    let got = if first > p.total { Vec::new() } else { data[p.from..p.to].to_vec() };
                    assert_eq!(got, want, "{data:?} {first} {count}");
                }
            }
        }
    }

    #[test]
    fn read_bounded_refuses_file_that_grew_past_cap_after_stat() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("growing.bin");
        let f = std::fs::File::create(&path).unwrap();
        f.set_len(READ_CAP + 1).unwrap();
        let opened = std::fs::File::open(&path).unwrap();
        // Simulate metadata captured when file was smaller than READ_CAP before it grew.
        let err = read_bounded(opened, 128, "growing.bin").unwrap_err();
        assert!(err.contains("32 MiB") && err.contains("sed -n"), "{err}");
    }
}
