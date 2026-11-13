//! Files between the workspace and a box: what may be sent (I6) and how what comes back is unpacked (I7).
//!
//! CONTRACT.
//!
//! No `tar` program and no archive library is involved on this side: the one reader and the one writer
//! below handle exactly the entries this module needs (ustar headers with the pax `path` and `size`
//! records and GNU long names on the reading side).
//!
//! ## Push (`build_push`, I6)
//! Walks the workspace without following a link and returns one tar stream of the files that changed since
//! the manifest of the last push (size and modification time), with `uid=gid=1000` and the file's
//! permission bits without setuid, setgid and sticky. A file is sent only when
//! - it is a regular file reached without a link (a symlink is neither followed nor sent, and neither is
//!   a device, FIFO or socket);
//! - it is not inside `<workspace>/.loom` or any directory or file named `.git`, and not inside a
//!   directory the sandbox refuses to let the agent read;
//! - it can be opened and the sandbox's read rule (`Sandbox::check_read`: unreadable paths, credential
//!   stores, oracle secrets) accepts the real path of the file that was opened, which is the file that is
//!   then read, so a link swapped in after the walk reaches nothing the agent could not read;
//! - it is at most `file` bytes (a larger one is named in a note, once per push, at most 5 names);
//! - the total of the push stays within `total` bytes (the files that did not fit go with the next push;
//!   the note says how many).
//!
//! A file that could not be opened, was refused, or did not fit is not put in the new manifest, so it is
//! tried again next time. The manifest holds exactly the files of this walk that were sent or unchanged.
//!
//! ## Unpack (`extract`, I7)
//! Takes the tar stream of `docker cp <container>:<path> -` and writes its regular files under `dest`,
//! all checked before the first byte is written:
//! - the names: not absolute, no `..` component, valid UTF-8, no NUL; a component `.` or an empty one is
//!   dropped; every entry starts with the same first component (what `docker cp` names the object); that
//!   component is replaced by `dest`'s own name, so `to` names the file or directory that results;
//! - the types: only regular files and directories. A symbolic link, a hard link, a device, a FIFO or any
//!   other type refuses the whole stream, and nothing is written;
//! - the caps: `total` bytes of file data in all and `entries` entries (at most 10,000), else nothing is
//!   written;
//! - every file is then written with [`crate::fstools::write_file_checked`], the path of the `write` tool
//!   (sandbox `check_write` on the path, descriptor-relative atomic write, directories made one at a time
//!   below the nearest existing one, the real path judged again), after a check that the nearest existing
//!   directory above the target really lies under `dest`, and that the target itself is not a link.
//!
//! Directories that hold no file are not made; permission bits are not applied (a file keeps the
//! permissions of the file it replaces, or the default of `write`).
//!
//! Tests required: the writer's output is read back by the reader (long names, pax); a push skips
//! `.loom`, `.git`, oracle secrets, `unreadable_paths`, credential stores, symlinks (also a link to an
//! unreadable file), files over the file limit, and what did not change; a push stops at the total;
//! `extract` refuses `../x`, `/etc/x`, `a/../../x`, a symlink entry, a hard link, a device, a FIFO, and
//! a file written through a symlink entry that came first, writing nothing in each case; refuses a stream
//! over the caps; refuses an existing link at the destination; writes through the sandbox, so a protected
//! or unreadable destination is refused; a plain tree is unpacked exactly.

use crate::files::open_readable;
use crate::sandbox::Sandbox;
use std::collections::HashMap;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// The files of the last push: workspace-relative path to (size, modification time in nanoseconds).
pub type Manifest = HashMap<PathBuf, (u64, i128)>;

/// Most entries `extract` takes from one stream.
pub const MAX_ENTRIES: usize = 10_000;
/// The owner of what is pushed.
const OWNER: u32 = 1000;
/// Most names of oversize files a push note lists.
const NOTE_NAMES: usize = 5;

#[derive(Clone, Copy, Debug)]
pub struct PushLimits {
    /// Bytes of file data in one push.
    pub total: u64,
    /// Bytes of one file.
    pub file: u64,
}

#[derive(Debug)]
pub struct Push {
    pub tar: Vec<u8>,
    pub manifest: Manifest,
    pub sent: usize,
    pub bytes: u64,
    pub notes: Vec<String>,
}

// ---- tar writer ----------------------------------------------------------------------------------

fn put(block: &mut [u8; 512], at: usize, bytes: &[u8]) {
    for (i, b) in bytes.iter().enumerate() {
        if let Some(slot) = block.get_mut(at + i) {
            *slot = *b;
        }
    }
}

fn octal(block: &mut [u8; 512], at: usize, width: usize, value: u64) {
    let text = format!("{value:0w$o}", w = width.saturating_sub(1));
    put(block, at, text.as_bytes());
}

/// One 512-byte ustar header.
fn header(name: &[u8], prefix: &[u8], size: u64, mode: u32, mtime: u64, typeflag: u8, linkname: &[u8]) -> [u8; 512] {
    let mut h = [0u8; 512];
    put(&mut h, 0, name);
    octal(&mut h, 100, 8, u64::from(mode));
    octal(&mut h, 108, 8, u64::from(OWNER));
    octal(&mut h, 116, 8, u64::from(OWNER));
    octal(&mut h, 124, 12, size);
    octal(&mut h, 136, 12, mtime);
    put(&mut h, 148, b"        ");
    if let Some(t) = h.get_mut(156) {
        *t = typeflag;
    }
    put(&mut h, 157, linkname);
    put(&mut h, 257, b"ustar\0");
    put(&mut h, 263, b"00");
    put(&mut h, 345, prefix);
    let sum: u64 = h.iter().map(|b| u64::from(*b)).sum();
    let text = format!("{sum:06o}\0 ");
    put(&mut h, 148, text.as_bytes());
    h
}

fn pad(out: &mut Vec<u8>) {
    let rest = out.len() % 512;
    if rest != 0 {
        out.resize(out.len() + (512 - rest), 0);
    }
}

/// A pax record `<len> path=<value>\n`, where `len` counts the whole record.
fn pax_path(path: &str) -> Vec<u8> {
    let body = format!(" path={path}\n");
    let mut len = body.len();
    loop {
        let total = len.to_string().len() + body.len();
        if total == len {
            break;
        }
        len = total;
    }
    format!("{len}{body}").into_bytes()
}

/// Splits `path` into a prefix of at most 155 bytes and a name of at most 100 at a `/`.
fn split_ustar(path: &str) -> Option<(&str, &str)> {
    if path.len() <= 100 {
        return Some(("", path));
    }
    path.match_indices('/').find_map(|(i, _)| {
        let (prefix, name) = (path.get(..i)?, path.get(i + 1..)?);
        (prefix.len() <= 155 && !name.is_empty() && name.len() <= 100).then_some((prefix, name))
    })
}

/// Appends a regular file to a tar stream.
pub fn append_file(out: &mut Vec<u8>, path: &str, mode: u32, mtime: u64, data: &[u8]) {
    let mode = mode & 0o777;
    match split_ustar(path) {
        Some((prefix, name)) => {
            out.extend_from_slice(&header(
                name.as_bytes(),
                prefix.as_bytes(),
                data.len() as u64,
                mode,
                mtime,
                b'0',
                b"",
            ));
        }
        None => {
            let record = pax_path(path);
            out.extend_from_slice(&header(b"PaxHeader", b"", record.len() as u64, 0o644, mtime, b'x', b""));
            out.extend_from_slice(&record);
            pad(out);
            let short: String = path.chars().take(50).collect();
            out.extend_from_slice(&header(short.as_bytes(), b"", data.len() as u64, mode, mtime, b'0', b""));
        }
    }
    out.extend_from_slice(data);
    pad(out);
}

/// The end of a tar stream.
pub fn finish_tar(out: &mut Vec<u8>) {
    out.resize(out.len() + 1024, 0);
}

// ---- push ----------------------------------------------------------------------------------------

fn mtime_ns(m: &std::fs::Metadata) -> i128 {
    i128::from(m.mtime()) * 1_000_000_000 + i128::from(m.mtime_nsec())
}

struct Walk<'a> {
    sandbox: &'a Sandbox,
    prev: &'a Manifest,
    lim: PushLimits,
    tar: Vec<u8>,
    manifest: Manifest,
    sent: usize,
    bytes: u64,
    deferred: usize,
    oversize: Vec<String>,
    oversize_n: usize,
}

impl Walk<'_> {
    fn dir(&mut self, abs: &Path, rel: &Path) {
        // A directory the agent could not read is not entered.
        if self.sandbox.check_read(abs).is_err() {
            return;
        }
        let Ok(read) = std::fs::read_dir(abs) else { return };
        let mut entries: Vec<_> = read.filter_map(Result::ok).collect();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let name = entry.file_name();
            let lossy = name.to_string_lossy();
            if lossy.eq_ignore_ascii_case(".git") || (rel.as_os_str().is_empty() && lossy == ".loom") {
                continue;
            }
            let Ok(kind) = entry.file_type() else { continue };
            let (abs_child, rel_child) = (abs.join(&name), rel.join(&name));
            if kind.is_dir() {
                self.dir(&abs_child, &rel_child);
            } else if kind.is_file() {
                self.file(&abs_child, rel_child, &entry);
            }
        }
    }

    fn file(&mut self, abs: &Path, rel: PathBuf, entry: &std::fs::DirEntry) {
        let Some(rel_text) = rel.to_str().map(str::to_string) else { return };
        let Ok(listed) = entry.metadata() else { return };
        let key = (listed.len(), mtime_ns(&listed));
        if self.prev.get(&rel) == Some(&key) {
            self.manifest.insert(rel, key);
            return;
        }
        if listed.len() > self.lim.file {
            self.oversize_n += 1;
            if self.oversize.len() < NOTE_NAMES {
                self.oversize.push(format!("{rel_text} ({} bytes)", listed.len()));
            }
            return;
        }
        if self.bytes.saturating_add(listed.len()) > self.lim.total {
            self.deferred += 1;
            return;
        }
        let sandbox = self.sandbox;
        let readable = |real: &Path| sandbox.check_read(real).map(|_| ());
        let Ok((file, meta)) = open_readable(abs, &readable) else { return };
        let key = (meta.len(), mtime_ns(&meta));
        if meta.len() > self.lim.file || self.bytes.saturating_add(meta.len()) > self.lim.total {
            self.deferred += 1;
            return;
        }
        let mut data = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
        let read = file.take(self.lim.file.saturating_add(1)).read_to_end(&mut data);
        if read.is_err() || data.len() as u64 > self.lim.file {
            return;
        }
        let mode = (meta.mode() & 0o777) | 0o600;
        append_file(&mut self.tar, &rel_text, mode, u64::try_from(meta.mtime()).unwrap_or(0), &data);
        self.bytes += data.len() as u64;
        self.sent += 1;
        self.manifest.insert(rel, (data.len() as u64, key.1));
    }
}

/// The files of `workspace` to send now (see the module contract).
pub fn build_push(sandbox: &Sandbox, workspace: &Path, prev: &Manifest, lim: PushLimits) -> Result<Push, String> {
    if !workspace.is_dir() {
        return Err(format!(
            "The workspace {} is not a directory, so nothing could be copied into the box.",
            workspace.display()
        ));
    }
    let mut w = Walk {
        sandbox,
        prev,
        lim,
        tar: Vec::new(),
        manifest: Manifest::new(),
        sent: 0,
        bytes: 0,
        deferred: 0,
        oversize: Vec::new(),
        oversize_n: 0,
    };
    w.dir(workspace, Path::new(""));
    finish_tar(&mut w.tar);
    let mut notes = Vec::new();
    if w.oversize_n > 0 {
        let more = w.oversize_n.saturating_sub(w.oversize.len());
        let tail = if more > 0 { format!(" and {more} more") } else { String::new() };
        notes.push(format!(
            "not copied into /work, over the {} MB file limit (sync_file_max_mb): {}{tail}",
            lim.file >> 20,
            w.oversize.join(", ")
        ));
    }
    if w.deferred > 0 {
        notes.push(format!(
            "{} changed file(s) were not copied this time because one copy is limited to {} MB (sync_max_mb); they are copied by the next box_exec",
            w.deferred,
            lim.total >> 20
        ));
    }
    Ok(Push { tar: w.tar, manifest: w.manifest, sent: w.sent, bytes: w.bytes, notes })
}

// ---- tar reader ----------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    File,
    Dir,
    Symlink,
    Hardlink,
    Device,
    Fifo,
    Other,
}

#[derive(Debug)]
struct Entry {
    name: String,
    kind: Kind,
    start: usize,
    len: usize,
}

fn field(h: &[u8], from: usize, to: usize) -> &[u8] {
    h.get(from..to).unwrap_or_default()
}

fn text(bytes: &[u8]) -> &[u8] {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    bytes.get(..end).unwrap_or_default()
}

fn number(bytes: &[u8]) -> Option<u64> {
    if bytes.first().is_some_and(|b| b & 0x80 != 0) {
        let mut v: u64 = u64::from(bytes.first()? & 0x7f);
        for b in bytes.get(1..)? {
            v = v.checked_mul(256)?.checked_add(u64::from(*b))?;
        }
        return Some(v);
    }
    let t: String = String::from_utf8_lossy(text(bytes)).trim().to_string();
    if t.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(&t, 8).ok()
}

/// The `path` and `size` records of a pax extended header.
fn pax_records(data: &[u8]) -> (Option<String>, Option<u64>) {
    let (mut path, mut size) = (None, None);
    let mut rest = data;
    while !rest.is_empty() {
        let Some(sp) = rest.iter().position(|b| *b == b' ') else { break };
        let Some(len) =
            std::str::from_utf8(rest.get(..sp).unwrap_or_default()).ok().and_then(|l| l.parse::<usize>().ok())
        else {
            break;
        };
        if len <= sp + 1 || len > rest.len() {
            break;
        }
        let record = rest.get(sp + 1..len.saturating_sub(1)).unwrap_or_default();
        if let Some(eq) = record.iter().position(|b| *b == b'=') {
            let (k, v) = (record.get(..eq).unwrap_or_default(), record.get(eq + 1..).unwrap_or_default());
            match k {
                b"path" => path = String::from_utf8(v.to_vec()).ok(),
                b"size" => size = std::str::from_utf8(v).ok().and_then(|s| s.parse().ok()),
                _ => {}
            }
        }
        rest = rest.get(len..).unwrap_or_default();
    }
    (path, size)
}

const NOT_TAR: &str = "What the box returned is not a tar stream. Nothing was written.";

fn parse(bytes: &[u8], max_entries: usize) -> Result<Vec<Entry>, String> {
    let mut entries = Vec::new();
    let mut at = 0usize;
    let (mut long_name, mut pax_size): (Option<String>, Option<u64>) = (None, None);
    loop {
        let Some(h) = bytes.get(at..at + 512) else {
            if at < bytes.len() {
                return Err(NOT_TAR.to_string());
            }
            break;
        };
        if h.iter().all(|b| *b == 0) {
            break;
        }
        let stored = number(field(h, 148, 156)).ok_or(NOT_TAR)?;
        let sum: u64 =
            h.iter().enumerate().map(|(i, b)| if (148..156).contains(&i) { 32 } else { u64::from(*b) }).sum();
        if sum != stored {
            return Err(NOT_TAR.to_string());
        }
        let mut size = number(field(h, 124, 136)).ok_or(NOT_TAR)?;
        let flag = h.get(156).copied().unwrap_or(b'0');
        if matches!(flag, b'0' | 0 | b'5') {
            if let Some(s) = pax_size.take() {
                size = s;
            }
        }
        let start = at + 512;
        let len = usize::try_from(size).map_err(|_| NOT_TAR.to_string())?;
        let end = start.checked_add(len).ok_or(NOT_TAR)?;
        if end > bytes.len() {
            return Err("What the box returned ends in the middle of a file. Nothing was written.".to_string());
        }
        let data = bytes.get(start..end).unwrap_or_default();
        at = start + len.div_ceil(512) * 512;
        match flag {
            b'x' => {
                let (path, size) = pax_records(data);
                if path.is_some() {
                    long_name = path;
                }
                pax_size = size;
                continue;
            }
            b'g' | b'K' => continue,
            b'L' => {
                long_name = Some(String::from_utf8_lossy(text(data)).to_string());
                continue;
            }
            _ => {}
        }
        let name = match long_name.take() {
            Some(n) => n,
            None => {
                let name = String::from_utf8(text(field(h, 0, 100)).to_vec()).map_err(|_| NOT_TAR.to_string())?;
                let prefix = text(field(h, 345, 500));
                if field(h, 257, 263) == b"ustar\0" && !prefix.is_empty() {
                    format!("{}/{name}", String::from_utf8(prefix.to_vec()).map_err(|_| NOT_TAR.to_string())?)
                } else {
                    name
                }
            }
        };
        let kind = match flag {
            b'0' | 0 | b'7' => Kind::File,
            b'5' => Kind::Dir,
            b'2' => Kind::Symlink,
            b'1' => Kind::Hardlink,
            b'3' | b'4' => Kind::Device,
            b'6' => Kind::Fifo,
            _ => Kind::Other,
        };
        if entries.len() >= max_entries {
            return Err(format!(
                "What the box returned has more than {max_entries} entries. Nothing was written. Fetch a smaller directory or pack it into one archive first."
            ));
        }
        entries.push(Entry { name, kind, start, len });
    }
    Ok(entries)
}

// ---- unpack --------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct GetLimits {
    /// Bytes of file data in all.
    pub total: u64,
    pub entries: usize,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Extracted {
    pub files: Vec<PathBuf>,
    pub bytes: u64,
    pub dirs: usize,
}

fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Symlink => "a symbolic link",
        Kind::Hardlink => "a hard link",
        Kind::Device => "a device",
        Kind::Fifo => "a FIFO",
        Kind::Other => "something that is neither a file nor a directory",
        Kind::File => "a file",
        Kind::Dir => "a directory",
    }
}

/// The components of an entry name, checked: no absolute name, no `..`, `.` and empty parts dropped.
fn components(name: &str) -> Result<Vec<&str>, String> {
    if name.starts_with('/') {
        return Err(format!("It holds the absolute name `{name}`."));
    }
    if name.contains('\0') {
        return Err("It holds a name with a NUL byte.".to_string());
    }
    let mut parts = Vec::new();
    for part in name.split('/') {
        match part {
            "" | "." => {}
            ".." => return Err(format!("It holds the name `{name}`, which goes up with `..`.")),
            p => parts.push(p),
        }
    }
    Ok(parts)
}

/// The nearest ancestor of `path` (or `path`) that exists.
fn nearest_existing(path: &Path) -> Option<&Path> {
    path.ancestors().find(|a| std::fs::symlink_metadata(a).is_ok())
}

/// Unpack `tar` so that what `docker cp` named becomes `dest` (see the module contract).
pub fn extract(sandbox: &Sandbox, dest: &Path, tar: &[u8], lim: GetLimits) -> Result<Extracted, String> {
    let refuse = |why: String| -> String { format!("{why} Nothing was written.") };
    let entries = parse(tar, lim.entries.min(MAX_ENTRIES))?;
    if entries.is_empty() {
        return Err("The box returned nothing for that path. Nothing was written.".to_string());
    }
    // Pass one: every entry is judged before anything is written.
    let mut root: Option<&str> = None;
    let mut plan: Vec<(Vec<&str>, &Entry)> = Vec::new();
    let mut total: u64 = 0;
    let mut dirs = 0usize;
    for e in &entries {
        if !matches!(e.kind, Kind::File | Kind::Dir) {
            return Err(refuse(format!(
                "The stream holds `{}`, which is {}. Only regular files and directories are taken from a box; pack links away first (for example `tar -ch` or copy the files) and fetch the result.",
                e.name,
                kind_name(e.kind)
            )));
        }
        let parts = components(&e.name)
            .map_err(|why| refuse(format!("{why} Only names below what was asked for are taken.")))?;
        let Some((first, rest)) = parts.split_first() else {
            if e.kind == Kind::Dir {
                continue;
            }
            return Err(refuse("It holds a file without a name.".to_string()));
        };
        match root {
            None => root = Some(first),
            Some(r) if r == *first => {}
            Some(r) => {
                return Err(refuse(format!(
                    "It holds `{}` beside `{r}`; a fetch is one file or one directory.",
                    e.name
                )));
            }
        }
        match e.kind {
            Kind::Dir => dirs += 1,
            _ => {
                total = total.saturating_add(e.len as u64);
                if total > lim.total {
                    return Err(refuse(format!(
                        "It holds more than {} MB of file data (get_max_mb). Fetch a smaller part, or pack and compress it in the box first.",
                        lim.total >> 20
                    )));
                }
                plan.push((rest.to_vec(), e));
            }
        }
    }
    // A single file at the top: `dest` is the file. Otherwise `dest` is the directory.
    let single_file = plan.len() == 1 && plan.first().is_some_and(|(rest, _)| rest.is_empty());
    if plan.iter().any(|(rest, _)| rest.is_empty()) && !single_file {
        return Err(refuse("It holds a file with the name of the directory itself.".to_string()));
    }
    // Pass two: where each file goes, and that the place really is inside `dest`.
    let dest_real = nearest_existing(dest).and_then(|a| std::fs::canonicalize(a).ok().map(|r| (a.to_path_buf(), r)));
    let mut targets: Vec<(PathBuf, &Entry)> = Vec::new();
    for (rest, e) in &plan {
        let mut target = dest.to_path_buf();
        for part in rest {
            target.push(part);
        }
        if let Ok(meta) = std::fs::symlink_metadata(&target) {
            if meta.file_type().is_symlink() {
                return Err(refuse(format!(
                    "{} is a symbolic link, and a fetch does not write through links. Remove it or fetch to another path.",
                    target.display()
                )));
            }
            if meta.is_dir() {
                return Err(refuse(format!(
                    "{} is a directory, and the stream holds a file of that name. Fetch to another path.",
                    target.display()
                )));
            }
        }
        if let (Some(parent), Some((existing, real))) = (target.parent(), &dest_real) {
            if let Some(a) = nearest_existing(parent) {
                if a.starts_with(existing) {
                    let real_a = std::fs::canonicalize(a)
                        .map_err(|e| refuse(format!("{} cannot be resolved ({e}).", a.display())))?;
                    let inside = match a.strip_prefix(existing) {
                        Ok(tail) => real_a == real.join(tail),
                        Err(_) => false,
                    };
                    if !inside {
                        return Err(refuse(format!(
                            "{} leads out of the destination through a link. Fetch to another path.",
                            parent.display()
                        )));
                    }
                }
            }
        }
        targets.push((target, e));
    }
    // Pass three: the writes, through the same path as the `write` tool.
    let mut done = Extracted { dirs, ..Extracted::default() };
    for (target, e) in targets {
        let data = tar.get(e.start..e.start + e.len).unwrap_or_default();
        crate::fstools::write_file_checked(sandbox, &target, data).map_err(|why| {
            format!(
                "{why} {} file(s) were written before this one; the rest of the stream was not written.",
                done.files.len()
            )
        })?;
        done.bytes += data.len() as u64;
        done.files.push(target);
    }
    Ok(done)
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    /// A tar stream with arbitrary entries, for hostile input: (name, typeflag, link name, data).
    pub fn raw_tar(entries: &[(&str, u8, &str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, flag, link, data) in entries {
            let (prefix, short) = split_ustar(name).unwrap_or(("", name));
            let size = if matches!(*flag, b'0' | 0) { data.len() as u64 } else { 0 };
            out.extend_from_slice(&header(short.as_bytes(), prefix.as_bytes(), size, 0o644, 0, *flag, link.as_bytes()));
            if size > 0 {
                out.extend_from_slice(data);
                pad(&mut out);
            }
        }
        finish_tar(&mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::testing::raw_tar;
    use super::*;
    use loom_core::config::{SandboxCfg, SandboxMode};

    struct Fix {
        _dir: tempfile::TempDir,
        ws: PathBuf,
        sb: Sandbox,
    }

    fn fix_with(cfg: SandboxCfg) -> Fix {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let (ws, tmp, home) = (root.join("ws"), root.join("tmp"), root.join("home"));
        for d in [&ws, &tmp, &home, &ws.join(".loom"), &home.join("keys")] {
            std::fs::create_dir_all(d).unwrap();
        }
        let sb = Sandbox::new(&cfg, &ws, &tmp, &home, None).unwrap();
        Fix { _dir: dir, ws, sb }
    }

    fn fix() -> Fix {
        fix_with(SandboxCfg { mode: SandboxMode::None, protect_credentials: false, ..SandboxCfg::default() })
    }

    const LIM: PushLimits = PushLimits { total: 1 << 20, file: 1 << 16 };
    const GET: GetLimits = GetLimits { total: 1 << 20, entries: 100 };

    fn names_in(tar: &[u8]) -> Vec<String> {
        parse(tar, 1000).unwrap().into_iter().map(|e| e.name).collect()
    }

    #[test]
    fn writer_and_reader_agree_on_short_long_and_pax_names() {
        let long = format!("{}/{}", "d".repeat(120), "f".repeat(90));
        let huge = format!("{}/x", "e/".repeat(200));
        let mut t = Vec::new();
        append_file(&mut t, "a.txt", 0o644, 5, b"hello");
        append_file(&mut t, &long, 0o600, 5, b"long");
        append_file(&mut t, &huge, 0o600, 5, b"pax");
        finish_tar(&mut t);
        let entries = parse(&t, 10).unwrap();
        let got: Vec<(&str, &[u8])> = entries.iter().map(|e| (e.name.as_str(), &t[e.start..e.start + e.len])).collect();
        assert_eq!(got, [("a.txt", &b"hello"[..]), (long.as_str(), &b"long"[..]), (huge.as_str(), &b"pax"[..])]);
    }

    #[test]
    fn a_push_sends_only_what_changed_and_only_regular_files() {
        let f = fix();
        std::fs::write(f.ws.join("a.txt"), "one").unwrap();
        std::fs::create_dir(f.ws.join("sub")).unwrap();
        std::fs::write(f.ws.join("sub/b.txt"), "two").unwrap();
        let first = build_push(&f.sb, &f.ws, &Manifest::new(), LIM).unwrap();
        assert_eq!(names_in(&first.tar), ["a.txt", "sub/b.txt"]);
        assert_eq!((first.sent, first.bytes), (2, 6));
        let again = build_push(&f.sb, &f.ws, &first.manifest, LIM).unwrap();
        assert_eq!(again.sent, 0, "nothing changed");
        assert_eq!(again.manifest, first.manifest);
        std::fs::write(f.ws.join("a.txt"), "three!").unwrap();
        let changed = build_push(&f.sb, &f.ws, &first.manifest, LIM).unwrap();
        assert_eq!(names_in(&changed.tar), ["a.txt"]);
    }

    #[test]
    fn i6_a_push_never_sends_what_the_agent_could_not_read() {
        let hidden = tempfile::tempdir().unwrap();
        let hidden_dir = hidden.path().canonicalize().unwrap();
        let cred = hidden_dir.join("cred");
        std::fs::create_dir_all(&cred).unwrap();
        std::fs::write(cred.join("token"), "TOPSECRET").unwrap();
        let cfg = SandboxCfg {
            mode: SandboxMode::None,
            protect_credentials: false,
            unreadable_paths: vec![cred.display().to_string()],
            ..SandboxCfg::default()
        };
        let f = fix_with(cfg);
        std::fs::write(f.ws.join("ok.txt"), "fine").unwrap();
        // The workspace's own control directory, and oracle secrets inside it.
        std::fs::write(f.ws.join(".loom/state.json"), "STATE").unwrap();
        std::fs::create_dir_all(f.ws.join(".loom/oracle-secrets")).unwrap();
        std::fs::write(f.ws.join(".loom/oracle-secrets/key"), "ORACLE").unwrap();
        // Git metadata, nested too.
        std::fs::create_dir_all(f.ws.join(".git")).unwrap();
        std::fs::write(f.ws.join(".git/config"), "GITCONF").unwrap();
        std::fs::create_dir_all(f.ws.join("vendor/.git")).unwrap();
        std::fs::write(f.ws.join("vendor/.git/config"), "GITCONF2").unwrap();
        std::fs::write(f.ws.join("vendor/code.c"), "int main;").unwrap();
        // A link to an unreadable file, a link to a directory, and a link that dangles.
        std::os::unix::fs::symlink(cred.join("token"), f.ws.join("innocent.txt")).unwrap();
        std::os::unix::fs::symlink(&cred, f.ws.join("linkdir")).unwrap();
        std::os::unix::fs::symlink("nowhere", f.ws.join("dangling")).unwrap();
        // The unreadable directory reached through a real path inside the workspace is not read either.
        let push = build_push(&f.sb, &f.ws, &Manifest::new(), LIM).unwrap();
        let names = names_in(&push.tar);
        assert_eq!(names, ["ok.txt", "vendor/code.c"], "{names:?}");
        let all = String::from_utf8_lossy(&push.tar);
        for secret in ["TOPSECRET", "STATE", "ORACLE", "GITCONF"] {
            assert!(!all.contains(secret), "{secret} was sent");
        }
    }

    #[test]
    fn i6_credential_stores_are_not_sent() {
        let home = tempfile::tempdir().unwrap();
        let home_dir = home.path().canonicalize().unwrap();
        // The workspace lies inside a home directory that holds a credential store.
        let ws = home_dir.join("proj");
        let ssh = home_dir.join(".ssh");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::create_dir_all(&ssh).unwrap();
        std::fs::write(ssh.join("id_ed25519"), "PRIVATEKEY").unwrap();
        std::fs::write(ws.join("a.txt"), "x").unwrap();
        let tmp = home_dir.join("tmp");
        let loom = home_dir.join("loomhome");
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::create_dir_all(&loom).unwrap();
        std::fs::create_dir_all(loom.join("keys")).unwrap();
        // A link from the workspace to the credential store must reach nothing.
        std::os::unix::fs::symlink(&ssh, ws.join("ssh-link")).unwrap();
        std::os::unix::fs::symlink(ssh.join("id_ed25519"), ws.join("key-link")).unwrap();
        let cfg = SandboxCfg { mode: SandboxMode::None, protect_credentials: true, ..SandboxCfg::default() };
        let sb = Sandbox::with_home(&cfg, &ws, &tmp, &loom, None, Some(home_dir.clone())).unwrap();
        assert!(sb.check_read(&ssh.join("id_ed25519")).is_err(), "the fixture must make the store unreadable");
        let push = build_push(&sb, &ws, &Manifest::new(), LIM).unwrap();
        assert_eq!(names_in(&push.tar), ["a.txt"]);
        assert!(!String::from_utf8_lossy(&push.tar).contains("PRIVATEKEY"));
    }

    #[test]
    fn i6_a_push_respects_the_file_and_total_limits_and_notes_what_it_left() {
        let f = fix();
        std::fs::write(f.ws.join("big.bin"), vec![1u8; 5000]).unwrap();
        std::fs::write(f.ws.join("a.txt"), vec![2u8; 600]).unwrap();
        std::fs::write(f.ws.join("b.txt"), vec![3u8; 600]).unwrap();
        let lim = PushLimits { total: 1000, file: 1000 };
        let first = build_push(&f.sb, &f.ws, &Manifest::new(), lim).unwrap();
        assert_eq!(names_in(&first.tar), ["a.txt"], "big.bin is over the file limit, b.txt over the total");
        assert!(
            first.notes.iter().any(|n| n.contains("big.bin (5000 bytes)") && n.contains("sync_file_max_mb")),
            "{:?}",
            first.notes
        );
        assert!(
            first.notes.iter().any(|n| n.contains("1 changed file(s)") && n.contains("sync_max_mb")),
            "{:?}",
            first.notes
        );
        // What did not fit goes next time.
        let second = build_push(&f.sb, &f.ws, &first.manifest, lim).unwrap();
        assert_eq!(names_in(&second.tar), ["b.txt"]);
    }

    fn dest_of(f: &Fix, rel: &str) -> PathBuf {
        f.ws.join(rel)
    }

    #[test]
    fn extract_unpacks_a_plain_tree_exactly() {
        let f = fix();
        let t = raw_tar(&[
            ("out", b'5', "", b""),
            ("out/a.txt", b'0', "", b"A"),
            ("out/d", b'5', "", b""),
            ("out/d/b.bin", b'0', "", &[0, 1, 2]),
        ]);
        let done = extract(&f.sb, &dest_of(&f, "got"), &t, GET).unwrap();
        assert_eq!(done.files.len(), 2);
        assert_eq!(std::fs::read(f.ws.join("got/a.txt")).unwrap(), b"A");
        assert_eq!(std::fs::read(f.ws.join("got/d/b.bin")).unwrap(), [0, 1, 2]);
        // One file: `to` is the file.
        let t = raw_tar(&[("x.txt", b'0', "", b"X")]);
        extract(&f.sb, &dest_of(&f, "renamed.txt"), &t, GET).unwrap();
        assert_eq!(std::fs::read(f.ws.join("renamed.txt")).unwrap(), b"X");
    }

    fn assert_refused_and_empty(f: &Fix, t: &[u8], needle: &str) {
        let err = extract(&f.sb, &dest_of(f, "dest"), t, GET).unwrap_err();
        assert!(err.contains(needle) && err.contains("Nothing was written"), "{err}");
        assert!(!f.ws.join("dest").exists(), "something was written: {err}");
        assert!(!f.ws.join("x").exists() && !f.ws.join("evil").exists());
    }

    #[test]
    fn i7_hostile_names_and_types_are_refused_before_anything_is_written() {
        let f = fix();
        assert_refused_and_empty(&f, &raw_tar(&[("out/a", b'0', "", b"ok"), ("../x", b'0', "", b"x")]), "`..`");
        assert_refused_and_empty(&f, &raw_tar(&[("out/a", b'0', "", b"ok"), ("out/../../x", b'0', "", b"x")]), "`..`");
        assert_refused_and_empty(&f, &raw_tar(&[("/etc/x", b'0', "", b"x")]), "absolute");
        // A symlink first and a file through it: the link itself is already refused.
        assert_refused_and_empty(
            &f,
            &raw_tar(&[("out", b'5', "", b""), ("out/l", b'2', "/etc", b""), ("out/l/x", b'0', "", b"x")]),
            "symbolic link",
        );
        assert_refused_and_empty(&f, &raw_tar(&[("out/h", b'1', "out/a", b"")]), "hard link");
        assert_refused_and_empty(&f, &raw_tar(&[("out/dev", b'3', "", b"")]), "device");
        assert_refused_and_empty(&f, &raw_tar(&[("out/dev", b'4', "", b"")]), "device");
        assert_refused_and_empty(&f, &raw_tar(&[("out/pipe", b'6', "", b"")]), "FIFO");
        assert_refused_and_empty(
            &f,
            &raw_tar(&[("out/a", b'0', "", b"1"), ("other/b", b'0', "", b"2")]),
            "one file or one directory",
        );
        assert_refused_and_empty(
            &f,
            b"this is not a tar stream at all, just text that is long enough to be a block".as_slice(),
            "not a tar",
        );
    }

    #[test]
    fn i7_the_caps_on_bytes_and_entries_refuse_the_whole_stream() {
        let f = fix();
        let t = raw_tar(&[("o/a", b'0', "", &[0u8; 600]), ("o/b", b'0', "", &[0u8; 600])]);
        let err = extract(&f.sb, &dest_of(&f, "dest"), &t, GetLimits { total: 1000, entries: 10 }).unwrap_err();
        assert!(err.contains("get_max_mb") && err.contains("Nothing was written"), "{err}");
        let many: Vec<(String, u8, &str, &[u8])> = (0..6).map(|i| (format!("o/f{i}"), b'0', "", &b"x"[..])).collect();
        let refs: Vec<(&str, u8, &str, &[u8])> = many.iter().map(|(n, k, l, d)| (n.as_str(), *k, *l, *d)).collect();
        let err = extract(&f.sb, &dest_of(&f, "dest"), &raw_tar(&refs), GetLimits { total: 1 << 20, entries: 5 })
            .unwrap_err();
        assert!(err.contains("more than 5 entries"), "{err}");
        assert!(!f.ws.join("dest").exists());
    }

    #[test]
    fn i7_a_link_already_in_the_destination_is_not_written_through() {
        let f = fix();
        let outside = tempfile::tempdir().unwrap();
        let outside_dir = outside.path().canonicalize().unwrap();
        // The destination directory exists and holds a link to a directory elsewhere.
        std::fs::create_dir_all(f.ws.join("dest")).unwrap();
        std::os::unix::fs::symlink(&outside_dir, f.ws.join("dest/sub")).unwrap();
        let t = raw_tar(&[("o/sub/file", b'0', "", b"escaped")]);
        let err = extract(&f.sb, &dest_of(&f, "dest"), &t, GET).unwrap_err();
        assert!(err.contains("leads out of the destination") || err.contains("symbolic link"), "{err}");
        assert!(!outside_dir.join("file").exists());
        // The destination file itself is a link.
        std::os::unix::fs::symlink(outside_dir.join("target"), f.ws.join("lnk")).unwrap();
        let t = raw_tar(&[("one", b'0', "", b"escaped")]);
        let err = extract(&f.sb, &dest_of(&f, "lnk"), &t, GET).unwrap_err();
        assert!(err.contains("symbolic link"), "{err}");
        assert!(!outside_dir.join("target").exists());
    }

    #[test]
    fn i7_writes_go_through_the_sandbox_so_protected_and_unreadable_paths_are_refused() {
        let hidden = tempfile::tempdir().unwrap();
        let hidden_dir = hidden.path().canonicalize().unwrap();
        let cfg = SandboxCfg {
            mode: SandboxMode::None,
            protect_credentials: false,
            unreadable_paths: vec![hidden_dir.display().to_string()],
            protected_paths: vec!["locked".into()],
            ..SandboxCfg::default()
        };
        let f = fix_with(cfg);
        std::fs::create_dir_all(f.ws.join("locked")).unwrap();
        let t = raw_tar(&[("o/a", b'0', "", b"x")]);
        // The workspace's own control directory.
        let err = extract(&f.sb, &f.ws.join(".loom/oracle"), &t, GET).unwrap_err();
        assert!(err.contains("protected"), "{err}");
        assert!(!f.ws.join(".loom/oracle").exists());
        // A path the config protects.
        let err = extract(&f.sb, &f.ws.join("locked/dir"), &t, GET).unwrap_err();
        assert!(err.contains("protected"), "{err}");
        // An unreadable path.
        let err = extract(&f.sb, &hidden_dir.join("d"), &t, GET).unwrap_err();
        assert!(err.contains("off limits") || err.contains("not writable"), "{err}");
        assert!(!hidden_dir.join("d").exists());
        // Git configuration.
        std::fs::create_dir_all(f.ws.join(".git")).unwrap();
        let err = extract(&f.sb, &f.ws.join(".git/hooks"), &t, GET).unwrap_err();
        assert!(err.contains("Git"), "{err}");
    }
}
