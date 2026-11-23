//! Storing an uploaded file in a workspace (`POST /api/uploads`; `docs/UPLOADS.md`).
//!
//! CONTRACT. Blocking; takes no lock. [`store`]`(workspace, name, bytes, given_type)` writes `bytes` to
//! `<workspace>/.loom/uploads/<stored name>` and answers [`UploadView`] (or the operator's sentence as `Err`).
//! - `workspace` is a canonical existing folder (the caller has judged it as session creation does).
//! - [`clean_name`]: `/`, `\`, NUL and control characters of the given name become `_`, leading dots are
//!   stripped, the result is cut to [`NAME_MAX`] bytes on a character boundary; an empty result is refused.
//! - `.loom` and `.loom/uploads` are made with mode 0700 when absent; either being a link or a non-folder is
//!   refused (nothing is written through a link).
//! - The file is written to a temporary dot-file in the same folder (mode 0600; no stored name starts with a
//!   dot) and then hard-linked to its name and the temporary removed: the file appears whole or not at all,
//!   and an existing file is never replaced. A taken name becomes `<stem>-2.<ext>`, `-3`, ... (`<name>-2`
//!   when there is no extension).
//! - `mime` is the given Content-Type when it says something, else from the extension (`texts::mime_for`).
//!
//! Tests: sanitising, dedupe, modes, link refusal, no temporary file left.

use crate::wire::UploadView;
use loom_agent::texts;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// The longest stored name, in bytes.
pub const NAME_MAX: usize = 120;

/// The stored form of `given`, or `None` when nothing is left of it.
pub fn clean_name(given: &str) -> Option<String> {
    let swapped: String =
        given.chars().map(|c| if c == '/' || c == '\\' || c.is_control() { '_' } else { c }).collect();
    let trimmed = swapped.trim_start_matches('.');
    let mut end = trimmed.len().min(NAME_MAX);
    while !trimmed.is_char_boundary(end) {
        end -= 1;
    }
    let name = trimmed.get(..end).unwrap_or("");
    (!name.trim().is_empty()).then(|| name.to_string())
}

/// `name` for the `n`th time (`n >= 2`): `<stem>-<n>.<ext>`.
fn numbered(name: &str, n: u32) -> String {
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => format!("{stem}-{n}.{ext}"),
        _ => format!("{name}-{n}"),
    }
}

fn not_a_folder(what: &str, path: &Path) -> String {
    format!("{what} {} is a link or not a folder; uploads are not stored through it.", path.display())
}

/// A real folder (not a link) at `path`, made with mode 0700 when absent.
fn private_dir(path: &Path, what: &str) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_dir() => Ok(()),
        Ok(_) => Err(not_a_folder(what, path)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .or_else(|e| if e.kind() == std::io::ErrorKind::AlreadyExists { Ok(()) } else { Err(e) })
            .map_err(|e| format!("Cannot make {}: {e}.", path.display())),
        Err(e) => Err(format!("Cannot examine {}: {e}.", path.display())),
    }
}

/// The folder uploads of `workspace` go to, made when absent.
pub fn uploads_dir(workspace: &Path) -> Result<PathBuf, String> {
    let loom = workspace.join(".loom");
    private_dir(&loom, "The workspace's .loom")?;
    let dir = loom.join("uploads");
    private_dir(&dir, "The uploads folder")?;
    match std::fs::symlink_metadata(&dir) {
        Ok(m) if m.file_type().is_dir() => Ok(dir),
        _ => Err(not_a_folder("The uploads folder", &dir)),
    }
}

pub fn store(workspace: &Path, name: &str, bytes: &[u8], given_type: Option<&str>) -> Result<UploadView, String> {
    let wanted = clean_name(name).ok_or_else(|| {
        "The upload needs a file name: give `name` with at least one character that is not a dot or a separator."
            .to_string()
    })?;
    let dir = uploads_dir(workspace)?;
    let nanos =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or_default();
    let tmp = dir.join(format!(".part-{}-{nanos}", std::process::id()));
    let written = (|| -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("Cannot write the upload: {e}."));
    }
    let mut n = 1u32;
    let stored = loop {
        let candidate = if n == 1 { wanted.clone() } else { numbered(&wanted, n) };
        match std::fs::hard_link(&tmp, dir.join(&candidate)) {
            Ok(()) => break Ok(candidate),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && n < 10_000 => n += 1,
            Err(e) => break Err(format!("Cannot store the upload: {e}.")),
        }
    };
    let _ = std::fs::remove_file(&tmp);
    let name = stored?;
    let path = dir.join(&name);
    Ok(UploadView {
        path: path.to_string_lossy().into_owned(),
        mime: texts::mime_for(&name, given_type),
        name,
        bytes: bytes.len() as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_cleaned_numbered_and_never_replace() {
        assert_eq!(clean_name("a/b\\c\0d\n.txt").as_deref(), Some("a_b_c_d_.txt"));
        assert_eq!(clean_name("../../etc/passwd").as_deref(), Some("_.._etc_passwd"));
        assert_eq!(clean_name("...hidden").as_deref(), Some("hidden"));
        assert_eq!(clean_name("..."), None);
        assert_eq!(clean_name(""), None);
        let long = format!("{}é", "x".repeat(119));
        assert_eq!(clean_name(&long).map(|n| n.len()), Some(119), "cut on a character boundary");
        assert_eq!(numbered("r.csv", 2), "r-2.csv");
        assert_eq!(numbered("Makefile", 3), "Makefile-3");
        assert_eq!(numbered("a.tar.gz", 2), "a.tar-2.gz");

        let d = tempfile::tempdir().unwrap();
        let ws = std::fs::canonicalize(d.path()).unwrap();
        let a = store(&ws, "r.csv", b"one", None).unwrap();
        let b = store(&ws, "r.csv", b"two", None).unwrap();
        let c = store(&ws, "r.csv", b"three", Some("text/plain; charset=utf-8")).unwrap();
        assert_eq!((a.name.as_str(), b.name.as_str(), c.name.as_str()), ("r.csv", "r-2.csv", "r-3.csv"));
        assert_eq!((a.mime.as_str(), c.mime.as_str()), ("text/csv", "text/plain"));
        assert_eq!(std::fs::read(&a.path).unwrap(), b"one");
        assert_eq!(std::fs::read(&b.path).unwrap(), b"two");
        let uploads = ws.join(".loom/uploads");
        assert_eq!(a.path, uploads.join("r.csv").to_string_lossy());
        let mode = |p: &Path| std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(p).unwrap().permissions());
        assert_eq!((mode(&uploads) & 0o777, mode(&uploads.join("r.csv")) & 0o777), (0o700, 0o600));
        assert_eq!(std::fs::read_dir(&uploads).unwrap().count(), 3, "no temporary file is left");
    }

    #[test]
    fn nothing_is_stored_through_a_link() {
        let d = tempfile::tempdir().unwrap();
        let ws = std::fs::canonicalize(d.path()).unwrap();
        let elsewhere = ws.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::create_dir_all(ws.join(".loom")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, ws.join(".loom/uploads")).unwrap();
        let err = store(&ws, "x.txt", b"x", None).unwrap_err();
        assert!(err.contains("link or not a folder"), "{err}");
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
        std::fs::remove_file(ws.join(".loom/uploads")).unwrap();
        std::fs::remove_dir(ws.join(".loom")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, ws.join(".loom")).unwrap();
        assert!(store(&ws, "x.txt", b"x", None).unwrap_err().contains("link or not a folder"));
        assert!(store(&ws, "..", b"x", None).unwrap_err().contains("file name"));
    }
}
