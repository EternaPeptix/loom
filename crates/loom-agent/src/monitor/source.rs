//! The monitor's cursors over the durable sources (`docs/MONITOR.md` §2.1, §2.3).
//!
//! CONTRACT.
//!
//! - A source is read by a `Cursor` (`log::Cursor`: byte offset, count, hash of the last line) and never by rescanning:
//!   `read_session` reads the complete lines after the cursor of a session log (`sessions/<id>/log.jsonl`), checks
//!   each record against the chain (`prev` is the SHA-256 of the previous line; 64 zeros for the first) and its seq
//!   (gapless from the cursor's count), and returns the records and the advanced cursor; `read_net` does the same for
//!   `net.jsonl` and `logs/net-unattributed.jsonl` (a line that carries `prev` is checked, an old line without one is
//!   not); `read_floor` for `logs/floor.jsonl`. At most `MAX_BYTES` are read per call, always to a line end; bytes
//!   after the last newline (a write in progress, or a torn tail) are left for the next call and are never a fault.
//!   Nothing is ever written, moved or locked: a source is read-only, and a session that writes while it is read is
//!   read up to its last whole line.
//! - A read that cannot continue returns a `fault` sentence and leaves the cursor where it was: the file is shorter
//!   than the cursor (it was cut or replaced), a line does not continue the chain, a seq is not the next. The caller
//!   records the fault once and stops reading that source; it never counts against an agent (I10), but a chain that does
//!   not hold is itself evidence the monitor shows (the operator sees "source faulty").
//! - A line that is not a record this build can read is skipped and counted in `opaque` (the log is additive: an
//!   unknown kind reads as `Event::Unknown` and is a record).
//! - `list_sessions(paths)` lists the session directories by name; `first_start_cursor(path)` is a cursor at the end of
//!   the source as it is now, for the first run (no retroactive pause).
//! - `prime(paths, dir)` finds who a session is: from `meta.json` when it is there (mission, parent, pack, role,
//!   workspace, profile, prior), else from the `session_start` record; and, for a forked child (whose log starts with a
//!   byte-for-byte copy of its parent's), the seq of its own `forked` record (the one whose `session` is this
//!   directory's): records before it are the parent's and are never observed as the child's (`skip_below`). A child
//!   primed before that record exists (the fork writes the copy first) has `skip_below = u64::MAX`, which the core
//!   resolves when the record is read.
//! - `read_journal(paths, mission, key)` reads a mission's journal as `Journal::read` does (verified) when the key is
//!   known, else as unverified lines (a replay of a copy); it returns the entries it understands and says which.
//! - `prime` also gives the mission's named target (`meta.json`'s, else the `session_start`'s). `last_shell_dir(log,
//!   upto)` is the one read back from a cursor: the meta `cwd` of the last `bash` result in the `SHELL_DIR_BYTES` before
//!   `upto` (where a restarted session's shell is, for the relative paths of its next commands).
//!
//! Tests required: records are read to the last whole line and the rest waits; the cursor advances and a second read
//! returns only the new records; a cut file, a broken chain and a skipped seq are faults that leave the cursor;
//! `first_start_cursor` sits at the end; a forked child's prefix is skipped; `meta.json` wins over `session_start`;
//! the journal reads verified with its key and is refused with a wrong one; a torn journal tail is ignored.

use crate::monitor::engine::SessionCtx;
use crate::monitor::log::Cursor;
use crate::runtime::{NetEntry, SessionMeta};
use loom_core::config::Paths;
use loom_core::event::{Event, Record};
use loom_core::ledger::Entry as LedgerEntry;
use loom_core::{MissionId, SessionId};
use serde::Deserialize;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// The most bytes one read takes.
pub const MAX_BYTES: u64 = 8 * 1024 * 1024;
const ZERO: &str = loom_core::log::ZERO_HASH;

/// What a read of a session log returned.
#[derive(Debug, Default)]
pub struct SessionRead {
    pub records: Vec<Record>,
    pub cursor: Cursor,
    pub fault: Option<String>,
    pub opaque: u64,
    /// Bytes of the file past the cursor that are not read yet (more to read now).
    pub more: bool,
}

/// What a read of a `net.jsonl` returned.
#[derive(Debug, Default)]
pub struct NetRead {
    pub entries: Vec<NetEntry>,
    /// The cursor after each entry of `entries`, in order.
    pub ends: Vec<Cursor>,
    pub cursor: Cursor,
    pub fault: Option<String>,
    pub more: bool,
}

/// What a read of `floor.jsonl` returned.
#[derive(Debug, Default)]
pub struct FloorRead {
    pub events: Vec<FloorLine>,
    pub cursor: Cursor,
    pub fault: Option<String>,
}

/// One line of `floor.jsonl` (`floor::FloorEvent` as it is written).
#[derive(Clone, Debug, Deserialize)]
pub struct FloorLine {
    pub at_ms: u64,
    pub kind: String,
    #[serde(default)]
    pub session: Option<String>,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub detail: String,
}

/// Complete lines after `off`: (lines with their end offsets, whether the file has more than was read).
fn read_complete(path: &Path, off: u64) -> Result<(Vec<(String, u64)>, bool), String> {
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        // A source that is not there yet (a session that has made no connection has no `net.jsonl`) has nothing in it.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && off == 0 => return Ok((Vec::new(), false)),
        Err(e) => return Err(format!("{} cannot be opened: {e}", path.display())),
    };
    let len = f.metadata().map_err(|e| format!("{} cannot be measured: {e}", path.display()))?.len();
    if len < off {
        return Err(format!(
            "{} is shorter ({len} bytes) than the monitor's cursor ({off}): it was cut or replaced",
            path.display()
        ));
    }
    if len == off {
        return Ok((Vec::new(), false));
    }
    f.seek(SeekFrom::Start(off)).map_err(|e| format!("{} cannot be read: {e}", path.display()))?;
    let want = len.saturating_sub(off).min(MAX_BYTES);
    let mut buf = Vec::with_capacity(want as usize);
    f.take(want).read_to_end(&mut buf).map_err(|e| format!("{} cannot be read: {e}", path.display()))?;
    let end = buf.iter().rposition(|b| *b == b'\n').map_or(0, |i| i.saturating_add(1));
    let mut lines = Vec::new();
    let mut start = 0usize;
    for (i, b) in buf.iter().enumerate().take(end) {
        if *b == b'\n' {
            let line = String::from_utf8_lossy(buf.get(start..i).unwrap_or(&[])).into_owned();
            lines.push((line, off.saturating_add(i as u64).saturating_add(1)));
            start = i.saturating_add(1);
        }
    }
    let more = len > off.saturating_add(end as u64) && (end > 0 || want < len.saturating_sub(off));
    Ok((lines, more))
}

fn hash_of(line: &str) -> String {
    loom_core::sha256_hex(line.as_bytes())
}

/// Read the session log at `path` after `cur` (see the contract).
pub fn read_session(path: &Path, cur: &Cursor) -> SessionRead {
    let mut out = SessionRead { cursor: cur.clone(), ..SessionRead::default() };
    let (lines, more) = match read_complete(path, cur.off) {
        Ok(x) => x,
        Err(e) => {
            out.fault = Some(e);
            return out;
        }
    };
    out.more = more;
    let mut c = cur.clone();
    for (line, end) in lines {
        let expected_prev = if c.off == 0 && c.seq == 0 { ZERO.to_string() } else { c.hash.clone() };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
            out.opaque = out.opaque.saturating_add(1);
            c.off = end;
            c.hash = hash_of(&line);
            continue;
        };
        let Some(rec) = loom_core::log::record_from_value(&v) else {
            out.opaque = out.opaque.saturating_add(1);
            c.off = end;
            c.hash = hash_of(&line);
            continue;
        };
        if !expected_prev.is_empty() && rec.prev != expected_prev {
            out.fault = Some(format!(
                "{} does not continue its chain at record {}: its prev is not the hash of the line before it",
                path.display(),
                rec.seq
            ));
            break;
        }
        if rec.seq != c.seq {
            out.fault = Some(format!("{} has record {} where {} was next", path.display(), rec.seq, c.seq));
            break;
        }
        c = Cursor { off: end, seq: c.seq.saturating_add(1), hash: hash_of(&line) };
        out.records.push(rec);
    }
    out.cursor = c;
    out
}

/// Read a `net.jsonl` (or the unattributed one) at `path` after `cur`.
pub fn read_net(path: &Path, cur: &Cursor) -> NetRead {
    let mut out = NetRead { cursor: cur.clone(), ..NetRead::default() };
    let (lines, more) = match read_complete(path, cur.off) {
        Ok(x) => x,
        Err(e) => {
            out.fault = Some(e);
            return out;
        }
    };
    out.more = more;
    let mut c = cur.clone();
    for (line, end) in lines {
        let prev_field = serde_json::from_str::<serde_json::Value>(&line)
            .ok()
            .and_then(|v| v.get("prev").and_then(|p| p.as_str().map(str::to_string)));
        if let Some(p) = &prev_field {
            let expected = if c.hash.is_empty() { ZERO.to_string() } else { c.hash.clone() };
            if *p != expected && !(c.off == 0 && c.seq == 0) {
                out.fault = Some(format!(
                    "{} does not continue its chain at line {}: the file was edited, truncated or reordered",
                    path.display(),
                    c.seq.saturating_add(1)
                ));
                break;
            }
        }
        c = Cursor { off: end, seq: c.seq.saturating_add(1), hash: hash_of(&line) };
        if let Ok(e) = serde_json::from_str::<NetEntry>(&line) {
            out.entries.push(e);
            out.ends.push(c.clone());
        }
    }
    out.cursor = c;
    out
}

/// Read `floor.jsonl` at `path` after `cur`.
pub fn read_floor(path: &Path, cur: &Cursor) -> FloorRead {
    let mut out = FloorRead { cursor: cur.clone(), ..FloorRead::default() };
    let (lines, _) = match read_complete(path, cur.off) {
        Ok(x) => x,
        Err(e) => {
            out.fault = Some(e);
            return out;
        }
    };
    let mut c = cur.clone();
    for (line, end) in lines {
        if let Ok(e) = serde_json::from_str::<FloorLine>(&line) {
            out.events.push(e);
        }
        c = Cursor { off: end, seq: c.seq.saturating_add(1), hash: String::new() };
    }
    out.cursor = c;
    out
}

/// A cursor at the end of `path` as it is now (the first run starts here). A source that is not there yet starts at 0.
pub fn first_start_cursor(path: &Path) -> Cursor {
    let Ok(mut f) = std::fs::File::open(path) else { return Cursor::default() };
    let Ok(len) = f.metadata().map(|m| m.len()) else { return Cursor::default() };
    // Only whole lines are behind the cursor: back up to the last newline.
    let tail = len.min(1 << 20);
    let mut buf = Vec::new();
    if f.seek(SeekFrom::Start(len.saturating_sub(tail))).is_err() || f.take(tail).read_to_end(&mut buf).is_err() {
        return Cursor::default();
    }
    let end = buf.iter().rposition(|b| *b == b'\n').map_or(0, |i| i.saturating_add(1));
    let off = len.saturating_sub(tail).saturating_add(end as u64);
    // The hash of the last line and the count are needed to continue the chain: take them from the lines that were read.
    let text = String::from_utf8_lossy(buf.get(..end).unwrap_or(&[])).into_owned();
    let last = text.lines().last().unwrap_or("").to_string();
    let seq = serde_json::from_str::<serde_json::Value>(&last)
        .ok()
        .and_then(|v| v.get("seq").and_then(serde_json::Value::as_u64))
        .map_or(0, |s| s.saturating_add(1));
    let count = if len == tail { text.lines().count() as u64 } else { seq };
    Cursor {
        off,
        seq: if seq > 0 { seq } else { count },
        hash: if last.is_empty() { String::new() } else { hash_of(&last) },
    }
}

/// The session directories under the home: (directory name, path).
pub fn list_sessions(paths: &Paths) -> Vec<(String, PathBuf)> {
    let Ok(rd) = std::fs::read_dir(paths.sessions_dir()) else { return Vec::new() };
    let mut v: Vec<(String, PathBuf)> = rd
        .filter_map(Result::ok)
        .filter(|e| e.path().join("log.jsonl").is_file())
        .map(|e| (e.file_name().to_string_lossy().into_owned(), e.path()))
        .collect();
    v.sort();
    v
}

/// The missions that have a directory under the home.
pub fn list_missions(paths: &Paths) -> Vec<MissionId> {
    let Ok(rd) = std::fs::read_dir(paths.missions_dir()) else { return Vec::new() };
    let mut v: Vec<MissionId> = rd
        .filter_map(Result::ok)
        .filter(|e| e.path().is_dir())
        .map(|e| MissionId::from(e.file_name().to_string_lossy().as_ref()))
        .collect();
    v.sort();
    v
}

/// The number of the last entry of a journal (0 when there is none), read from its tail without verifying it.
pub fn last_entry_n(path: &Path) -> u64 {
    let Ok(mut f) = std::fs::File::open(path) else { return 0 };
    let Ok(len) = f.metadata().map(|m| m.len()) else { return 0 };
    let tail = len.min(256 * 1024);
    let mut buf = Vec::new();
    if f.seek(SeekFrom::Start(len.saturating_sub(tail))).is_err() || f.take(tail).read_to_end(&mut buf).is_err() {
        return 0;
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    let whole = text.rfind('\n').map_or("", |i| text.get(..i).unwrap_or(""));
    whole.lines().rev().find_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()?.get("n")?.as_u64()).unwrap_or(0)
}

/// Who a session is, and where its own records start.
#[derive(Clone, Debug)]
pub struct Primed {
    pub ctx: SessionCtx,
    pub profile: String,
    pub prior: Vec<MissionId>,
    /// Records with a seq below this are the parent's copy.
    pub skip_below: u64,
    pub started_ms: u64,
    /// The mission's named target, as the session's `meta.json` (else its `session_start`) recorded it.
    pub target: Option<loom_core::event::TargetRef>,
}

/// Find out who the session in directory `dir` is (see the contract).
pub fn prime(dir: &Path, name: &str) -> Option<Primed> {
    let meta: Option<SessionMeta> =
        std::fs::read_to_string(dir.join("meta.json")).ok().and_then(|t| serde_json::from_str(&t).ok());
    let log = dir.join("log.jsonl");
    let mut cur = Cursor::default();
    let (mut start, mut forked): (Option<(Record, loom_core::event::SessionStart)>, Option<u64>) = (None, None);
    for _ in 0..16 {
        let r = read_session(&log, &cur);
        for rec in &r.records {
            match &rec.event {
                Event::SessionStart(s) if start.is_none() => start = Some((rec.clone(), s.clone())),
                Event::Forked(f) if forked.is_none() && f.session.as_str() == name => forked = Some(rec.seq),
                _ => {}
            }
        }
        cur = r.cursor;
        let copied = start.as_ref().is_some_and(|(_, s)| s.session.as_str() != name);
        if r.fault.is_some() || !r.more || (start.is_some() && (!copied || forked.is_some())) {
            break;
        }
    }
    let (start_rec, s) = start?;
    let copied = s.session.as_str() != name;
    let session = SessionId::from(name);
    let (mission, parent, pack, role, workspace, profile, prior) = match &meta {
        Some(m) => (
            m.mission.clone(),
            m.parent.clone(),
            m.pack.clone(),
            m.role.clone(),
            m.workspace.clone(),
            m.profile.clone(),
            m.prior.clone(),
        ),
        None => (
            s.mission.clone(),
            s.parent.clone(),
            s.pack.clone(),
            s.role.clone(),
            s.workspace.clone(),
            s.model.profile.clone(),
            Vec::new(),
        ),
    };
    let relaxed = s.model.lineage.as_ref().is_some_and(|l| l.alignment == loom_core::lineage::Alignment::Relaxed);
    let skip_below = if copied { forked.unwrap_or(u64::MAX) } else { 0 };
    let target = meta.as_ref().and_then(|m| m.target.clone()).or_else(|| s.target.clone());
    Some(Primed {
        ctx: SessionCtx { session, mission, parent, pack, role, relaxed, workspace },
        profile,
        prior,
        skip_below,
        started_ms: start_rec.ts_ms,
        target,
    })
}

/// The most bytes `last_shell_dir` reads back from the cursor.
const SHELL_DIR_BYTES: u64 = 1024 * 1024;

/// The directory the last `bash` result before byte `upto` of the session log at `path` left the shell in (its meta
/// `cwd`), read once from the last `SHELL_DIR_BYTES` before `upto` (records are not checked against the chain: this
/// is where relative paths are read from, not a record the monitor judges). `None` when none says.
pub fn last_shell_dir(path: &Path, upto: u64) -> Option<String> {
    let mut f = std::fs::File::open(path).ok()?;
    let from = upto.saturating_sub(SHELL_DIR_BYTES);
    f.seek(SeekFrom::Start(from)).ok()?;
    let mut buf = Vec::new();
    f.take(upto.saturating_sub(from)).read_to_end(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf);
    // A window that starts inside a line drops that line's tail.
    let whole = if from == 0 { text.as_ref() } else { text.split_once('\n').map_or("", |(_, rest)| rest) };
    whole.lines().rev().find_map(|line| {
        let v = serde_json::from_str::<serde_json::Value>(line).ok()?;
        match loom_core::log::record_from_value(&v)?.event {
            Event::ToolResult(r) if r.name == "bash" => {
                r.meta.get(loom_core::event::META_CWD).and_then(serde_json::Value::as_str).map(str::to_string)
            }
            _ => None,
        }
    })
}

/// What `read_journal` found.
#[derive(Debug, Default)]
pub struct JournalRead {
    pub entries: Vec<LedgerEntry>,
    /// The entries were checked against the journal key.
    pub verified: bool,
    pub fault: Option<String>,
}

/// Read a mission's journal (see the contract).
pub fn read_journal(paths: &Paths, mission: &MissionId, key: Option<&[u8]>) -> JournalRead {
    let path = paths.journal(mission);
    if !path.is_file() {
        return JournalRead { verified: key.is_some(), ..JournalRead::default() };
    }
    match key {
        Some(k) => match loom_core::journal::Journal::new(path, k.to_vec()).read() {
            Ok(entries) => JournalRead { entries, verified: true, fault: None },
            Err(e) => JournalRead {
                entries: Vec::new(),
                verified: true,
                fault: Some(format!("the journal of {} did not verify: {e}", mission.as_str())),
            },
        },
        None => {
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            let whole = text.rfind('\n').map_or("", |i| text.get(..=i).unwrap_or(""));
            let entries = whole.lines().filter_map(|l| serde_json::from_str::<LedgerEntry>(l).ok()).collect();
            JournalRead { entries, verified: false, fault: None }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loom_core::event::{Author, ToolCall, ToolClass};
    use loom_core::log::{Durability, SessionLog};

    fn tool_call(n: usize) -> Event {
        Event::ToolCall(ToolCall {
            call_id: loom_core::CallId::from(format!("c{n}")),
            req_id: "r".into(),
            name: "bash".into(),
            args: serde_json::json!({"command": format!("echo {n}")}),
            class: ToolClass::Exec,
        })
    }

    fn make(path: &Path, n: usize) -> SessionLog {
        let mut log = SessionLog::create(path, Durability::Batch).expect("create");
        for i in 0..n {
            log.append(Author::Model, tool_call(i)).expect("append");
        }
        log
    }

    #[test]
    fn records_are_read_to_the_last_whole_line_and_the_rest_waits() {
        let d = tempfile::tempdir().expect("dir");
        let p = d.path().join("log.jsonl");
        let mut log = make(&p, 3);
        let r = read_session(&p, &Cursor::default());
        assert_eq!((r.records.len(), r.cursor.seq, r.fault.is_none()), (3, 3, true));
        // A write in progress: a partial line is not read and is not a fault.
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(&p).expect("open");
        f.write_all(b"{\"seq\":3,\"ts").expect("partial");
        let again = read_session(&p, &r.cursor);
        assert!(again.records.is_empty() && again.fault.is_none());
        assert_eq!(again.cursor, r.cursor, "the partial line waits");
        let _ = &mut log;
    }

    #[test]
    fn a_second_read_returns_only_the_new_records() {
        let d = tempfile::tempdir().expect("dir");
        let p = d.path().join("log.jsonl");
        let mut log = make(&p, 2);
        let first = read_session(&p, &Cursor::default());
        assert_eq!(first.records.len(), 2);
        log.append(Author::Model, tool_call(2)).expect("append");
        log.append(Author::Model, tool_call(3)).expect("append");
        let second = read_session(&p, &first.cursor);
        assert_eq!(second.records.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![2, 3]);
        assert!(read_session(&p, &second.cursor).records.is_empty());
    }

    #[test]
    fn a_cut_file_a_broken_chain_and_a_skipped_seq_are_faults_that_leave_the_cursor() {
        let d = tempfile::tempdir().expect("dir");
        let p = d.path().join("log.jsonl");
        make(&p, 4);
        let all = read_session(&p, &Cursor::default());
        let text = std::fs::read_to_string(&p).expect("read");
        // Cut.
        std::fs::write(&p, text.lines().take(2).map(|l| format!("{l}\n")).collect::<String>()).expect("cut");
        let r = read_session(&p, &all.cursor);
        assert!(r.fault.as_deref().is_some_and(|f| f.contains("shorter")), "{:?}", r.fault);
        assert_eq!(r.cursor, all.cursor);
        // Broken chain: a line replaced by another record of the same seq.
        let lines: Vec<&str> = text.lines().collect();
        let swapped = format!("{}\n{}\n{}\n{}\n", lines[0], lines[2], lines[1], lines[3]);
        std::fs::write(&p, swapped).expect("swap");
        let r = read_session(&p, &Cursor::default());
        assert!(r.fault.is_some() && r.records.len() == 1, "{:?} {}", r.fault, r.records.len());
        // A skipped seq (the chain is right, the numbering is not).
        std::fs::write(&p, format!("{}\n", lines[1])).expect("skip");
        let r = read_session(&p, &Cursor::default());
        assert!(r.fault.is_some());
    }

    #[test]
    fn first_start_cursor_sits_at_the_end_and_continues_the_chain() {
        let d = tempfile::tempdir().expect("dir");
        let p = d.path().join("log.jsonl");
        let mut log = make(&p, 3);
        let c = first_start_cursor(&p);
        assert_eq!(c.seq, 3);
        assert!(read_session(&p, &c).records.is_empty());
        log.append(Author::Model, tool_call(3)).expect("append");
        let r = read_session(&p, &c);
        assert!(r.fault.is_none(), "{:?}", r.fault);
        assert_eq!(r.records.len(), 1);
        assert_eq!(first_start_cursor(&d.path().join("missing")), Cursor::default());
    }

    #[test]
    fn net_lines_are_read_with_their_chain_and_floor_lines_without() {
        let d = tempfile::tempdir().expect("dir");
        let p = d.path().join("net.jsonl");
        let w = loom_net::netlog::NetLogWriter::new();
        let e = |host: &str| NetEntry {
            ts_ms: 5,
            decision: loom_core::event::NetDecision {
                host: host.into(),
                port: 443,
                method: "CONNECT".into(),
                allowed: false,
                rule: "default deny".into(),
                resolved: None,
                sni: None,
            },
        };
        w.append(&p, &e("a.example")).expect("a");
        w.append(&p, &e("b.example")).expect("b");
        let r = read_net(&p, &Cursor::default());
        assert_eq!(r.entries.len(), 2);
        assert!(r.fault.is_none());
        w.append(&p, &e("c.example")).expect("c");
        let r2 = read_net(&p, &r.cursor);
        assert_eq!(r2.entries.iter().map(|x| x.decision.host.as_str()).collect::<Vec<_>>(), vec!["c.example"]);
        let text = std::fs::read_to_string(&p).expect("read");
        std::fs::write(&p, text.replace("b.example", "x.example")).expect("edit");
        let bad = read_net(&p, &Cursor::default());
        assert!(bad.fault.is_some(), "an edited line breaks the chain of the next one");
        let f = d.path().join("floor.jsonl");
        std::fs::write(
            &f,
            "{\"at_ms\":1,\"kind\":\"infrastructure\",\"session\":\"s-1\",\"label\":\"l\",\"detail\":\"d\"}\n",
        )
        .expect("floor");
        let fr = read_floor(&f, &Cursor::default());
        assert_eq!(fr.events.len(), 1);
        assert_eq!(fr.events[0].kind, "infrastructure");
    }

    #[test]
    fn a_forked_childs_copied_prefix_is_skipped_and_meta_wins() {
        let d = tempfile::tempdir().expect("dir");
        let dir = d.path().join("s-child");
        std::fs::create_dir_all(&dir).expect("dir");
        let start = |session: &str, mission: &str| {
            Event::SessionStart(loom_core::event::SessionStart {
                session: SessionId::from(session),
                mission: MissionId::from(mission),
                parent: None,
                workspace: "/w".into(),
                pack: "core".into(),
                role: "lead".into(),
                termination: loom_core::event::Termination::Explicit,
                model: loom_core::event::ModelRef {
                    profile: "p".into(),
                    model: "m".into(),
                    context_window: 10,
                    lineage: None,
                },
                reasoning_replay: Default::default(),
                system_prompt: String::new(),
                tools: vec![],
                budget: Default::default(),
                unattended: false,
                title: String::new(),
                project_instructions: Vec::new(),
                mcp: Vec::new(),
                intercept: false,
                target: None,
                creds: None,
                schema: loom_core::event::SCHEMA,
            })
        };
        let mut log = SessionLog::create(&dir.join("log.jsonl"), Durability::Batch).expect("create");
        log.append(Author::Harness, start("s-parent", "m-1")).expect("start");
        log.append(Author::Model, tool_call(0)).expect("call");
        log.append(
            Author::Harness,
            Event::Forked(loom_core::event::Forked {
                session: SessionId::from("s-child"),
                parent: SessionId::from("s-parent"),
                upto_seq: 1,
                role: "worker".into(),
                termination: loom_core::event::Termination::Explicit,
                budget: Default::default(),
                brief: Default::default(),
                contract: String::new(),
                allowed_tools: None,
                title: String::new(),
            }),
        )
        .expect("forked");
        let p = prime(&dir, "s-child").expect("primed");
        assert_eq!(p.skip_below, 2, "the parent's two records are not the child's");
        assert_eq!(p.ctx.session.as_str(), "s-child");
        assert_eq!(p.ctx.mission.as_str(), "m-1");
        // meta.json names another pack: it wins.
        let meta = serde_json::json!({"id": "s-child", "mission": "m-1", "workspace": "/copy", "pack": "ctf", "role": "worker", "profile": "q", "model": "m", "created_ms": 1, "parent": "s-parent"});
        std::fs::write(dir.join("meta.json"), meta.to_string()).expect("meta");
        let p = prime(&dir, "s-child").expect("primed");
        assert_eq!((p.ctx.pack.as_str(), p.ctx.workspace.as_str(), p.profile.as_str()), ("ctf", "/copy", "q"));
        assert_eq!(p.ctx.parent.as_ref().map(|s| s.as_str()), Some("s-parent"));
        // An ordinary session is not skipped.
        let own = d.path().join("s-own");
        std::fs::create_dir_all(&own).expect("dir");
        let mut l2 = SessionLog::create(&own.join("log.jsonl"), Durability::Batch).expect("create");
        l2.append(Author::Harness, start("s-own", "m-2")).expect("start");
        assert_eq!(prime(&own, "s-own").map(|p| p.skip_below), Some(0));
    }

    #[test]
    fn the_shell_directory_is_the_last_bash_result_before_the_cursor_and_the_target_is_primed() {
        let d = tempfile::tempdir().expect("dir");
        let dir = d.path().join("s-1");
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("log.jsonl");
        let mut log = SessionLog::create(&path, Durability::Batch).expect("create");
        let target = loom_core::event::TargetRef {
            name: "acme".into(),
            scope: vec!["*.acme.example".into()],
            exclude: vec!["sso.acme.example".into()],
            upstream_insecure: vec![],
            intercept_passthrough: vec![],
            summary: String::new(),
        };
        log.append(
            Author::Harness,
            Event::SessionStart(loom_core::event::SessionStart {
                session: SessionId::from("s-1"),
                mission: MissionId::from("m-1"),
                parent: None,
                workspace: "/w".into(),
                pack: "core".into(),
                role: "lead".into(),
                termination: loom_core::event::Termination::Explicit,
                model: loom_core::event::ModelRef {
                    profile: "p".into(),
                    model: "m".into(),
                    context_window: 10,
                    lineage: None,
                },
                reasoning_replay: Default::default(),
                system_prompt: String::new(),
                tools: vec![],
                budget: Default::default(),
                unattended: false,
                title: String::new(),
                project_instructions: Vec::new(),
                mcp: Vec::new(),
                intercept: false,
                target: Some(target.clone()),
                creds: None,
                schema: loom_core::event::SCHEMA,
            }),
        )
        .expect("start");
        assert_eq!(prime(&dir, "s-1").and_then(|p| p.target), Some(target), "the target of the session's start");
        let moved = |dir: &str| {
            let mut meta = serde_json::Map::new();
            meta.insert(loom_core::event::META_CWD.into(), serde_json::json!(dir));
            Event::ToolResult(loom_core::event::ToolResult {
                call_id: loom_core::CallId::from("c"),
                name: "bash".into(),
                status: loom_core::event::ToolStatus::Ok,
                text: String::new(),
                output: None,
                cut: false,
                class: ToolClass::Exec,
                meta,
                duration_ms: 1,
                images: Vec::new(),
                exchanges: Vec::new(),
            })
        };
        let none = std::fs::metadata(&path).expect("len").len();
        assert_eq!(last_shell_dir(&path, none), None, "no result moved the shell");
        log.append(Author::Tool, moved("/srv/a")).expect("a");
        log.append(Author::Model, tool_call(1)).expect("call");
        let after_a = std::fs::metadata(&path).expect("len").len();
        log.append(Author::Tool, moved("/srv/b")).expect("b");
        assert_eq!(last_shell_dir(&path, after_a).as_deref(), Some("/srv/a"), "only what is before the cursor");
        let end = std::fs::metadata(&path).expect("len").len();
        assert_eq!(last_shell_dir(&path, end).as_deref(), Some("/srv/b"));
    }

    #[test]
    fn the_journal_reads_verified_with_its_key_and_unverified_without() {
        let d = tempfile::tempdir().expect("dir");
        let paths = Paths::at(d.path());
        let m = MissionId::from("m-1");
        let key = vec![7u8; 32];
        let j = loom_core::journal::Journal::new(paths.journal(&m), key.clone());
        std::fs::create_dir_all(paths.mission_dir(&m)).expect("dir");
        j.append(&SessionId::from("s-1"), true, loom_core::ledger::LedgerOp::GoalSet { text: "g".into() }, &|_| Ok(()))
            .expect("append");
        let ok = read_journal(&paths, &m, Some(&key));
        assert!(ok.verified && ok.fault.is_none() && ok.entries.len() == 1);
        let wrong = read_journal(&paths, &m, Some(&[1u8; 32]));
        assert!(wrong.fault.is_some() && wrong.entries.is_empty());
        let plain = read_journal(&paths, &m, None);
        assert!(!plain.verified && plain.entries.len() == 1);
        let none = read_journal(&paths, &MissionId::from("m-none"), Some(&key));
        assert!(none.entries.is_empty() && none.fault.is_none());
    }
}
