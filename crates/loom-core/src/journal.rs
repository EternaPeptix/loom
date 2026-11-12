//! The sealed, append-only journal that stores a mission's ledger ops.
//!
//! CONTRACT (bodies are placeholders for the implementer; signatures and types are fixed).
//!
//! File: `journal.jsonl`, one [`Entry`] per line (compact JSON, `\n`-terminated).
//!
//! Seal: `mac = hex(HMAC-SHA256(key, prev_mac_hex_bytes || body_bytes))` where `prev_mac` is the
//! previous entry's `mac` (64 zeros for the first entry) and `body_bytes` is the compact JSON of the
//! entry with the `mac` field removed, exactly as it appears in the stored line (the stored line is
//! the body object with `"mac":"…"` appended as its last key). Verification recomputes over the bytes
//! on disk, so key order in the file is whatever was written.
//!
//! `append`:
//! 1. takes an exclusive advisory lock on `<path>.lock` (`fs2`), held until it returns;
//! 2. reads and verifies the whole journal (any failure → `JournalError::Tampered`, nothing written);
//! 3. folds it to a `LedgerState` and calls `LedgerState::validate(op, from_user)`; a refusal →
//!    `JournalError::Rule(message)`;
//! 4. calls the caller's `check(&state)` (runtime rules such as evidence attestation); a refusal →
//!    `JournalError::Rule(message)`;
//! 5. writes the entry with `n = last.n + 1` (1 for the first) and `ts_ms = now_ms()`, one
//!    `write_all`, then `sync_data`;
//! 6. returns the entry and the state after applying it.
//!    Two processes appending concurrently therefore get distinct, consecutive `n`.
//!
//! `read` takes a shared lock, verifies and returns all entries it understands. Bytes after the last
//! newline are a torn tail (a crash or full disk in the middle of an append): they are ignored,
//! reported by [`Journal::read_report`], and removed by the next `append`. A complete line that fails
//! verification is `Tampered`. An entry with a valid seal whose op this build cannot parse (written by
//! a newer loom) is skipped for folding but kept in the chain; `append` is refused with
//! [`JournalError::NewerVersion`], which names the entry, its op and the parse error. When the lock
//! file cannot be opened for writing (a read-only copy of a mission directory) it is opened read-only;
//! when it does not exist either, the read goes ahead without a lock.
//!
//! `append` is atomic from the caller's view: the file length is remembered, and any write or sync
//! error truncates back to it before the error is returned. If that truncation fails as well, the
//! error is [`JournalError::Unconfirmed`]: the entry may still be in the journal.
//!
//! Head record: `<journal>.head` (`journal.head`) holds `{n, mac, seal}` for the last entry, rewritten
//! atomically (temp file, sync, rename, sync of the directory) after every append while the lock is
//! held; `seal = HMAC(key, label, mission directory name, n, mac)`. On read, a head with a valid seal
//! requires entry `n` to exist with exactly that mac, so removing the last entries, deleting the
//! journal, or substituting another mission's journal (and head) is `Tampered`. The journal may be
//! ahead of the head by entries that verify (crash between the two writes); the next append repairs
//! it. A head whose seal fails is `Tampered`. A journal without a head (written before heads existed)
//! is accepted and gets one at its next append. A head write that fails does not fail the append (the
//! entry is durable, and an error would make the caller record it twice); it shows only as
//! [`JournalRead::ahead_of_head`] until a later append writes the head.
//!
//! NOT protected: truncation and substitution are caught only while the current head file is in
//! place. Deleting `journal.head` alone makes the journal look like one written before heads existed,
//! so it is then accepted at any length, and so is another mission's journal put in its place. Putting
//! back an older copy of the head (alone, or with the journal of that time) allows the journal to be
//! cut back to that head's `n`. Deleting the journal and the head together looks like a mission that
//! never had a ledger. Anyone holding the key can forge everything.
//!
//! Key: `load_or_create_key(path)` returns the 32-byte key stored at `path` as 64 hex characters,
//! creating it (random, file mode 0600, parent dirs 0700) when missing. A file that exists but does
//! not hold 64 hex characters is an error (never overwritten).
//!
//! Tests required: append/read round trip; ids consecutive; tamper detection for an edited body, a
//! removed line, a reordered pair, a truncated tail; wrong key; rule refusal writes nothing; `check`
//! refusal writes nothing; two threads appending 50 entries each yield 100 distinct consecutive `n`;
//! key file created with mode 0600 and reused.

use crate::ids::SessionId;
use crate::ledger::{Entry, LedgerOp, LedgerState};
use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::Sha256;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

type HmacSha256 = Hmac<Sha256>;

const ZERO_MAC: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// `,"mac":"` + 64 hex characters + `"}`: the tail every stored line ends with.
const MAC_KEY: &[u8] = b",\"mac\":\"";
const MAC_TAIL_LEN: usize = 8 + 64 + 2;
/// `EvidenceAdd` carries its own `session` (where the cited call ran), which would collide with the
/// entry's `session` in the flat line; on disk the evidence's one is stored under this key.
const EVIDENCE_SESSION_KEY: &str = "evidence_session";

#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("journal i/o on {path}: {source}")]
    Io { path: PathBuf, #[source] source: std::io::Error },
    /// The journal on disk does not verify. Ledger writes stay refused until the operator looks at it.
    #[error("the mission journal failed verification at entry {n}: {detail}")]
    Tampered { n: u64, detail: String },
    /// The op is not allowed in the current state. The message says what to do instead.
    #[error("{0}")]
    Rule(String),
    #[error("cannot encode journal entry: {0}")]
    Encode(#[from] serde_json::Error),
    /// The journal holds a validly sealed entry whose op this build cannot parse. `detail` names the
    /// op and gives the parse error.
    #[error("the mission journal was written by a newer loom (entry {n} is sealed correctly but this build cannot read it: {detail}); upgrade loom to record to this mission")]
    NewerVersion { n: u64, detail: String },
    /// An append failed after its bytes were written and they could not be removed again, so entry
    /// `n` may or may not be in the journal. Read the journal before repeating the op.
    #[error("journal i/o on {path}: {source}; removing the unconfirmed entry {n} failed as well ({undo}), so it may still be in the journal")]
    Unconfirmed { path: PathBuf, n: u64, #[source] source: std::io::Error, undo: std::io::Error },
}

/// What a verified read found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalRead {
    /// The entries this build understands, in order.
    pub entries: Vec<Entry>,
    /// Bytes after the last newline were ignored (an interrupted append); the next append removes them.
    pub torn_tail: bool,
    /// Number of validly sealed entries skipped because this build cannot parse their op.
    pub unknown: u64,
    /// The first skipped entry: its number, its op and why it could not be parsed.
    pub unknown_detail: Option<String>,
    /// Complete entries the head record does not vouch for: those after the head's `n`, or all of them
    /// when there is no head file. Removing them would go undetected. It is zero once an append has
    /// written its head; anything else means the head was not written for those entries (a journal
    /// from before heads existed, a crash between the two writes, or a head write that failed).
    pub ahead_of_head: u64,
}

/// A fully verified journal file.
struct Loaded {
    entries: Vec<Entry>,
    macs: Vec<String>,
    last_mac: String,
    /// The first entry whose op did not parse, and why.
    first_unknown: Option<(u64, String)>,
    unknown: u64,
    valid_len: u64,
    torn: bool,
    ahead: u64,
}

const HEAD_LABEL: &[u8] = b"loom-journal-head-v1\0";

#[cfg(test)]
thread_local! {
    /// Test hook: 1 = fail halfway through the line write, 2 = fail the sync after a full write,
    /// 3 = as 2, and the truncation that should undo the write fails too.
    static FAIL_WRITE: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}

fn write_line(file: &mut std::fs::File, line: &[u8]) -> std::io::Result<()> {
    #[cfg(test)]
    match FAIL_WRITE.with(|f| f.get()) {
        1 => {
            file.write_all(line.get(..line.len() / 2).unwrap_or(&[]))?;
            return Err(std::io::Error::other("injected write failure"));
        }
        2 | 3 => {
            file.write_all(line)?;
            return Err(std::io::Error::other("injected sync failure"));
        }
        _ => {}
    }
    file.write_all(line)?;
    file.sync_data()
}

/// Cut the file back to `len` after a failed append.
fn undo_write(file: &std::fs::File, len: u64) -> std::io::Result<()> {
    #[cfg(test)]
    if FAIL_WRITE.with(|f| f.get()) == 3 {
        return Err(std::io::Error::other("injected truncate failure"));
    }
    file.set_len(len)?;
    file.sync_data()
}

#[derive(Clone, Debug)]
pub struct Journal {
    path: PathBuf,
    key: Vec<u8>,
}

impl Journal {
    /// Bind to a journal file (created on first append; parent directories are created).
    pub fn new(path: impl Into<PathBuf>, key: Vec<u8>) -> Journal {
        Journal { path: path.into(), key }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Verify and return every entry this build understands. A missing file is an empty journal.
    pub fn read(&self) -> Result<Vec<Entry>, JournalError> {
        Ok(self.read_report()?.entries)
    }

    /// Like [`Journal::read`], also reporting an ignored torn tail and skipped unknown entries.
    /// Holds a shared lock for the duration of the read.
    pub fn read_report(&self) -> Result<JournalRead, JournalError> {
        let lock = self.lock_shared()?;
        let loaded = self.load()?;
        drop(lock);
        Ok(JournalRead {
            entries: loaded.entries,
            torn_tail: loaded.torn,
            unknown: loaded.unknown,
            unknown_detail: loaded.first_unknown.map(|(n, why)| format!("entry {n}: {why}")),
            ahead_of_head: loaded.ahead,
        })
    }

    /// Whether this mission keeps a ledger on disk: the journal or its head record exists. A head
    /// without its journal is a deleted journal, which a read reports as `Tampered`.
    pub fn exists(&self) -> bool {
        self.path.is_file() || self.head_path().is_file()
    }

    /// The shared lock a read holds. `None` when there is no lock file and none can be created: no
    /// mission directory yet, or a read-only copy of one that nothing has appended to in place.
    fn lock_shared(&self) -> Result<Option<std::fs::File>, JournalError> {
        use std::io::ErrorKind::{NotFound, PermissionDenied, ReadOnlyFilesystem};
        let lock_path = self.lock_path();
        let lock = match std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(&lock_path) {
            Ok(l) => l,
            Err(e) if e.kind() == NotFound => return Ok(None),
            // The journal can be readable where its directory is not writable; a read-only descriptor
            // is enough to hold the lock.
            Err(e) if matches!(e.kind(), PermissionDenied | ReadOnlyFilesystem) => {
                match std::fs::File::open(&lock_path) {
                    Ok(l) => l,
                    Err(e) if e.kind() == NotFound => return Ok(None),
                    Err(source) => return Err(JournalError::Io { path: lock_path, source }),
                }
            }
            Err(source) => return Err(JournalError::Io { path: lock_path, source }),
        };
        fs2::FileExt::lock_shared(&lock).map_err(|source| JournalError::Io { path: lock_path, source })?;
        Ok(Some(lock))
    }

    fn lock_path(&self) -> PathBuf {
        let mut p = self.path.clone().into_os_string();
        p.push(".lock");
        PathBuf::from(p)
    }

    fn head_path(&self) -> PathBuf {
        self.path.with_extension("head")
    }

    /// Read the file, verify the chain and the head record. The caller holds the lock, except for a
    /// read where none could be taken.
    fn load(&self) -> Result<Loaded, JournalError> {
        // The head is read first: appends write the journal before the head, so a read that could not
        // take the lock still never holds a head that is newer than the journal bytes it checks.
        let head_path = self.head_path();
        let head = match std::fs::read(&head_path) {
            Ok(h) => Some(h),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(source) => return Err(JournalError::Io { path: head_path, source }),
        };
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(self.io(e)),
        };
        let mut loaded = verify_all(&self.key, &bytes)?;
        let vouched = match head {
            Some(h) => self.check_head(&loaded, &h)?,
            None => 0,
        };
        loaded.ahead = u64::try_from(loaded.macs.len()).unwrap_or(u64::MAX).saturating_sub(vouched);
        Ok(loaded)
    }

    fn head_mac(&self, n: u64, mac: &str) -> std::io::Result<HmacSha256> {
        let dir = self.path.parent().and_then(|p| p.file_name()).map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        let mut m = new_mac(&self.key)?;
        m.update(HEAD_LABEL);
        m.update(dir.as_bytes());
        m.update(b"\0");
        m.update(n.to_string().as_bytes());
        m.update(b"\0");
        m.update(mac.as_bytes());
        Ok(m)
    }

    /// Check the journal against the bytes of its head record; returns the `n` the head vouches for.
    fn check_head(&self, loaded: &Loaded, text: &[u8]) -> Result<u64, JournalError> {
        let head_path = self.head_path();
        let bad = |why: &str| tampered(0, format!("the head record {} {why}; the journal's length can no longer be vouched for", head_path.display()));
        let Ok(Value::Object(map)) = serde_json::from_slice::<Value>(text) else {
            return Err(bad("is not a JSON object"));
        };
        let (Some(n), Some(mac), Some(seal)) = (
            map.get("n").and_then(|v| v.as_u64()),
            map.get("mac").and_then(|v| v.as_str()),
            map.get("seal").and_then(|v| v.as_str()).and_then(|s| hex::decode(s).ok()),
        ) else {
            return Err(bad("is missing `n`, `mac` or `seal`"));
        };
        let m = self.head_mac(n, mac).map_err(|e| tampered(0, format!("unusable key: {e}")))?;
        if m.verify_slice(&seal).is_err() {
            return Err(bad("does not verify (it was altered, copied from another mission, or sealed with a different key)"));
        }
        let idx = usize::try_from(n).ok().and_then(|n| n.checked_sub(1));
        let found = idx.and_then(|i| loaded.macs.get(i));
        if found.map(String::as_str) != Some(mac) {
            return Err(tampered(
                n,
                format!(
                    "the journal was truncated or replaced: the sealed head says entry {n} exists with a given seal, but the journal has {} complete entries and entry {n} does not match",
                    loaded.macs.len()
                ),
            ));
        }
        Ok(n)
    }

    /// Atomically record `{n, mac, seal}` of the last entry beside the journal.
    fn write_head(&self, n: u64, mac: &str) -> std::io::Result<()> {
        let seal = hex::encode(self.head_mac(n, mac)?.finalize().into_bytes());
        let body = serde_json::to_vec(&serde_json::json!({ "n": n, "mac": mac, "seal": seal }))?;
        let head = self.head_path();
        let tmp = head.with_extension("head.tmp");
        let mut options = std::fs::OpenOptions::new();
        options.create(true).write(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut f = options.open(&tmp)?;
        f.write_all(&body)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, &head)?;
        if let Some(dir) = head.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::File::open(dir)?.sync_all()?;
            }
        }
        Ok(())
    }

    /// Verify, fold and return the current state.
    pub fn state(&self) -> Result<LedgerState, JournalError> {
        Ok(LedgerState::fold(&self.read()?))
    }

    /// Append one op. See the module contract for the steps.
    pub fn append(
        &self,
        session: &SessionId,
        from_user: bool,
        op: LedgerOp,
        check: &dyn Fn(&LedgerState) -> Result<(), String>,
    ) -> Result<(Entry, LedgerState), JournalError> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| self.io(e))?;
            }
        }
        let lock_path = self.lock_path();
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .map_err(|source| JournalError::Io { path: lock_path.clone(), source })?;
        fs2::FileExt::lock_exclusive(&lock).map_err(|source| JournalError::Io { path: lock_path.clone(), source })?;
        // The lock is released when `lock` is dropped, on every return path.

        let loaded = self.load()?;
        if let Some((n, detail)) = &loaded.first_unknown {
            return Err(JournalError::NewerVersion { n: *n, detail: detail.clone() });
        }
        let mut state = LedgerState::fold(&loaded.entries);
        state.validate(&op, from_user).map_err(JournalError::Rule)?;
        check(&state).map_err(JournalError::Rule)?;

        let prev_mac = loaded.last_mac.as_str();
        let prev_n = u64::try_from(loaded.macs.len()).unwrap_or(u64::MAX);
        let mut entry = Entry {
            n: prev_n.saturating_add(1),
            ts_ms: crate::now_ms(),
            session: session.clone(),
            from_user,
            op,
            mac: String::new(),
        };
        let body = encode_body(&entry)?;
        entry.mac = mac_hex(&self.key, prev_mac, &body).map_err(|e| self.io(e))?;

        let mut line = body;
        line.truncate(line.len().saturating_sub(1)); // the closing `}`
        line.extend_from_slice(MAC_KEY);
        line.extend_from_slice(entry.mac.as_bytes());
        line.extend_from_slice(b"\"}\n");

        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(&self.path).map_err(|e| self.io(e))?;
        if loaded.torn {
            // Remove the bytes of an interrupted append before writing after them.
            file.set_len(loaded.valid_len).map_err(|e| self.io(e))?;
            file.sync_data().map_err(|e| self.io(e))?;
        }
        if let Err(source) = write_line(&mut file, &line) {
            // Leave no partial or unreported bytes behind: the caller is told nothing was recorded.
            // When they cannot be removed either, the caller is told the entry may be there.
            return Err(match undo_write(&file, loaded.valid_len) {
                Ok(()) => self.io(source),
                Err(undo) => JournalError::Unconfirmed { path: self.path.clone(), n: entry.n, source, undo },
            });
        }
        // The entry is durable. A failed head write only leaves the journal ahead of its head, which
        // reads accept and report (`JournalRead::ahead_of_head`) and the next append repairs; returning
        // it as an error would make the caller retry the op.
        let _ = self.write_head(entry.n, &entry.mac);
        drop(lock);

        state.apply(&entry);
        Ok((entry, state))
    }

    fn io(&self, source: std::io::Error) -> JournalError {
        JournalError::Io { path: self.path.clone(), source }
    }
}

fn tampered(n: u64, detail: impl Into<String>) -> JournalError {
    JournalError::Tampered { n, detail: detail.into() }
}

fn new_mac(key: &[u8]) -> std::io::Result<HmacSha256> {
    HmacSha256::new_from_slice(key).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))
}

fn mac_hex(key: &[u8], prev_mac: &str, body: &[u8]) -> std::io::Result<String> {
    let mut m = new_mac(key)?;
    m.update(prev_mac.as_bytes());
    m.update(body);
    Ok(hex::encode(m.finalize().into_bytes()))
}

/// Compact JSON of the entry without its `mac`: `n`, `ts_ms`, `session`, `from_user`, then the op.
fn encode_body(entry: &Entry) -> Result<Vec<u8>, serde_json::Error> {
    let mut map = Map::new();
    map.insert("n".into(), Value::from(entry.n));
    map.insert("ts_ms".into(), Value::from(entry.ts_ms));
    map.insert("session".into(), Value::from(entry.session.as_str()));
    map.insert("from_user".into(), Value::from(entry.from_user));
    if let Value::Object(op) = serde_json::to_value(&entry.op)? {
        for (k, v) in op {
            let k = if k == "session" && matches!(entry.op, LedgerOp::EvidenceAdd(_)) { EVIDENCE_SESSION_KEY.to_string() } else { k };
            map.insert(k, v);
        }
    }
    serde_json::to_vec(&Value::Object(map))
}

/// Parse a stored line (with its `mac`) back into an `Entry`.
/// `Err` as the entry means the line is well formed but this build cannot parse its op; the text
/// names the op and gives the parse error.
fn decode_line(line: &[u8], mac: &str) -> Result<(u64, Result<Entry, String>), String> {
    let Value::Object(mut map) = serde_json::from_slice::<Value>(line).map_err(|e| format!("line is not valid JSON: {e}"))? else {
        return Err("line is not a JSON object".to_string());
    };
    map.remove("mac");
    let n = map.remove("n").and_then(|v| v.as_u64()).ok_or("missing or invalid `n`")?;
    let ts_ms = map.remove("ts_ms").and_then(|v| v.as_u64()).ok_or("missing or invalid `ts_ms`")?;
    let session = match map.remove("session") {
        Some(Value::String(s)) => SessionId::from(s),
        _ => return Err("missing or invalid `session`".to_string()),
    };
    let from_user = match map.remove("from_user") {
        Some(Value::Bool(b)) => b,
        None => false,
        _ => return Err("invalid `from_user`".to_string()),
    };
    if let Some(v) = map.remove(EVIDENCE_SESSION_KEY) {
        map.insert("session".into(), v);
    }
    let op_name = map.get("op").and_then(Value::as_str).map(str::to_string);
    Ok(match serde_json::from_value::<LedgerOp>(Value::Object(map)) {
        Ok(op) => (n, Ok(Entry { n, ts_ms, session, from_user, op, mac: mac.to_string() })),
        Err(e) => (n, Err(op_name.map_or_else(|| e.to_string(), |name| format!("op `{name}`: {e}")))),
    })
}

/// Verify the chain over the bytes of the file and return the entries.
fn verify_all(key: &[u8], bytes: &[u8]) -> Result<Loaded, JournalError> {
    let mut loaded = Loaded {
        entries: Vec::new(),
        macs: Vec::new(),
        last_mac: ZERO_MAC.to_string(),
        first_unknown: None,
        unknown: 0,
        valid_len: 0,
        torn: false,
        ahead: 0,
    };
    let mut prev_mac = ZERO_MAC.to_string();
    let mut rest = bytes;
    let mut n: u64 = 0;
    while !rest.is_empty() {
        n = n.saturating_add(1);
        let Some(end) = rest.iter().position(|b| *b == b'\n') else {
            // An interrupted append: ignored here, removed by the next append.
            loaded.torn = true;
            break;
        };
        let (line, after) = rest.split_at(end);
        rest = after.get(1..).unwrap_or(&[]);

        let len = line.len();
        let tail_ok = len > MAC_TAIL_LEN
            && line.get(len - MAC_TAIL_LEN..len - MAC_TAIL_LEN + MAC_KEY.len()) == Some(MAC_KEY)
            && line.get(len - 2..) == Some(b"\"}");
        if !tail_ok {
            return Err(tampered(n, "the line does not end in a seal"));
        }
        let mac_str = line.get(len - 66..len - 2).and_then(|b| std::str::from_utf8(b).ok()).ok_or_else(|| tampered(n, "the seal is not text"))?;
        let mac_bytes = hex::decode(mac_str).map_err(|_| tampered(n, "the seal is not hexadecimal"))?;
        let mut body = line.get(..len - MAC_TAIL_LEN).unwrap_or(&[]).to_vec();
        body.push(b'}');

        let mut m = new_mac(key).map_err(|e| tampered(n, format!("unusable key: {e}")))?;
        m.update(prev_mac.as_bytes());
        m.update(&body);
        if m.verify_slice(&mac_bytes).is_err() {
            return Err(tampered(n, "the seal does not match: the entry was altered, removed, reordered, or sealed with a different key"));
        }
        let mac_lower = mac_str.to_ascii_lowercase();
        let (entry_n, entry) = decode_line(line, &mac_lower).map_err(|d| tampered(n, d))?;
        if entry_n != n {
            return Err(tampered(n, format!("entry numbered {entry_n} where {n} was expected")));
        }
        match entry {
            Ok(e) => loaded.entries.push(e),
            Err(why) => {
                loaded.unknown = loaded.unknown.saturating_add(1);
                loaded.first_unknown.get_or_insert((n, why));
            }
        }
        loaded.macs.push(mac_lower.clone());
        prev_mac = mac_lower;
        loaded.valid_len = loaded.valid_len.saturating_add(u64::try_from(line.len()).unwrap_or(0)).saturating_add(1);
    }
    loaded.last_mac = prev_mac;
    Ok(loaded)
}

/// Load the journal key, creating it when missing. See the module contract.
pub fn load_or_create_key(path: &Path) -> std::io::Result<Vec<u8>> {
    match read_key(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        other => return other,
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            let mut b = std::fs::DirBuilder::new();
            b.recursive(true);
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
            b.create(parent)?;
        }
    }
    let mut key = [0u8; 32];
    rand::Rng::fill(&mut rand::rng(), &mut key[..]);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    match options.open(path) {
        Ok(mut f) => {
            f.write_all(hex::encode(key).as_bytes())?;
            f.sync_all()?;
            Ok(key.to_vec())
        }
        // Another process created it first: use theirs.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => read_key(path),
        Err(e) => Err(e),
    }
}

fn read_key(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut text = String::new();
    std::fs::File::open(path)?.read_to_string(&mut text)?;
    let text = text.trim();
    let bad = || std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{} must hold 64 hexadecimal characters", path.display()));
    if text.len() != 64 {
        return Err(bad());
    }
    hex::decode(text).map_err(|_| bad())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::CallId;
    use crate::ledger::{EvidenceInput, EvidenceKind, StepStatus};

    fn sid() -> SessionId {
        SessionId::from("s-lead")
    }

    fn ok(_: &LedgerState) -> Result<(), String> {
        Ok(())
    }

    fn journal(dir: &tempfile::TempDir) -> Journal {
        Journal::new(dir.path().join("m-1").join("journal.jsonl"), vec![7u8; 32])
    }

    fn add(j: &Journal, op: LedgerOp) -> Entry {
        match j.append(&sid(), false, op, &ok) {
            Ok((e, _)) => e,
            Err(e) => panic!("append failed: {e}"),
        }
    }

    fn fill(j: &Journal, count: usize) {
        for i in 0..count {
            add(j, LedgerOp::PlanAdd { text: format!("step {i}") });
        }
    }

    fn lines(j: &Journal) -> Vec<String> {
        std::fs::read_to_string(j.path()).unwrap_or_default().lines().map(String::from).collect()
    }

    fn write_lines(j: &Journal, v: &[String]) {
        let mut s = v.join("\n");
        s.push('\n');
        std::fs::write(j.path(), s).unwrap_or_default();
    }

    fn tampered_at(r: Result<Vec<Entry>, JournalError>) -> u64 {
        match r {
            Err(JournalError::Tampered { n, .. }) => n,
            other => panic!("expected Tampered, got {other:?}"),
        }
    }

    #[test]
    fn append_and_read_round_trip() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let j = journal(&dir);
        assert!(j.read().unwrap_or_default().is_empty());
        assert_eq!(j.state().unwrap_or_default(), LedgerState::default());
        let user = SessionId::from("s-user");
        let (e1, s1) = j.append(&user, true, LedgerOp::GoalSet { text: "ship it".into() }, &ok).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!((e1.n, e1.from_user, e1.session.as_str()), (1, true, "s-user"));
        assert_eq!(s1.goal.as_deref(), Some("ship it"));
        let (e2, s2) = j.append(&sid(), false, LedgerOp::PlanSet { steps: vec!["a".into(), "b".into()] }, &ok).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(s2.plan.len(), 2);
        assert_eq!(s2.entries, 2);
        let read = j.read().unwrap_or_default();
        assert_eq!(read, vec![e1, e2]);
        assert_eq!(j.state().unwrap_or_default(), s2);
        // Each stored line is one compact object ending in the seal.
        for l in lines(&j) {
            assert!(l.starts_with("{\"n\":") && l.contains(",\"mac\":\"") && l.ends_with("\"}"), "{l}");
        }
    }

    #[test]
    fn evidence_keeps_its_own_session() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let j = journal(&dir);
        add(&j, LedgerOp::ClaimAdd { text: "works".into() });
        let input = EvidenceInput {
            claim: "c1".into(),
            kind: EvidenceKind::Static,
            supports: true,
            session: SessionId::from("s-child"),
            call_id: CallId::from("call-9"),
            blob: None,
            lines: Some((1, 2)),
            quote: Some("q \"quoted\"\nnext".into()),
            note: "read it".into(),
            attested: true,
        };
        let e = add(&j, LedgerOp::EvidenceAdd(input.clone()));
        assert_eq!(e.session.as_str(), "s-lead");
        let read = j.read().unwrap_or_default();
        assert_eq!(read.get(1), Some(&e));
        let state = j.state().unwrap_or_default();
        assert_eq!(state.evidence.first().map(|ev| ev.input.clone()), Some(input));
    }

    #[test]
    fn ids_are_consecutive() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let j = journal(&dir);
        fill(&j, 5);
        let ns: Vec<u64> = j.read().unwrap_or_default().iter().map(|e| e.n).collect();
        assert_eq!(ns, [1, 2, 3, 4, 5]);
        // A second handle on the same file continues the numbering.
        let j2 = Journal::new(j.path(), vec![7u8; 32]);
        assert_eq!(add(&j2, LedgerOp::PlanAdd { text: "more".into() }).n, 6);
    }

    #[test]
    fn edited_body_is_detected() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let j = journal(&dir);
        fill(&j, 4);
        let mut v = lines(&j);
        v[1] = v[1].replace("step 1", "step X");
        write_lines(&j, &v);
        assert_eq!(tampered_at(j.read()), 2);
        assert!(matches!(j.state(), Err(JournalError::Tampered { n: 2, .. })));
        // Writes are refused and leave the file as it is.
        let before = std::fs::read(j.path()).unwrap_or_default();
        assert!(matches!(j.append(&sid(), false, LedgerOp::PlanAdd { text: "x".into() }, &ok), Err(JournalError::Tampered { .. })));
        assert_eq!(std::fs::read(j.path()).unwrap_or_default(), before);
    }

    #[test]
    fn edited_seal_or_key_order_is_detected() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let j = journal(&dir);
        fill(&j, 2);
        let orig = lines(&j);
        // A forged mac.
        let mut v = orig.clone();
        let cut = v[1].len() - 6;
        v[1] = format!("{}0000\"}}", &v[1][..cut]);
        write_lines(&j, &v);
        assert_eq!(tampered_at(j.read()), 2);
        // A harmless-looking rewrite (whitespace) still changes the sealed bytes.
        let mut v = orig;
        v[0] = v[0].replacen("{\"n\":1,", "{\"n\": 1,", 1);
        write_lines(&j, &v);
        assert_eq!(tampered_at(j.read()), 1);
    }

    #[test]
    fn removed_line_is_detected() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let j = journal(&dir);
        fill(&j, 4);
        let mut v = lines(&j);
        v.remove(1);
        write_lines(&j, &v);
        assert_eq!(tampered_at(j.read()), 2);
        let mut v = lines(&j);
        v.remove(0);
        write_lines(&j, &v);
        assert_eq!(tampered_at(j.read()), 1);
    }

    #[test]
    fn reordered_pair_is_detected() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let j = journal(&dir);
        fill(&j, 4);
        let mut v = lines(&j);
        v.swap(1, 2);
        write_lines(&j, &v);
        assert_eq!(tampered_at(j.read()), 2);
    }

    #[test]
    fn truncated_tail_is_detected() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let j = journal(&dir);
        fill(&j, 3);
        let bytes = std::fs::read(j.path()).unwrap_or_default();
        // Cut into the middle of the last line.
        std::fs::write(j.path(), &bytes[..bytes.len() - 10]).unwrap_or_default();
        assert_eq!(tampered_at(j.read()), 3);
        // Only the newline missing is still an incomplete line.
        std::fs::write(j.path(), &bytes[..bytes.len() - 1]).unwrap_or_default();
        assert_eq!(tampered_at(j.read()), 3);
        let before = std::fs::read(j.path()).unwrap_or_default();
        assert!(matches!(j.append(&sid(), false, LedgerOp::PlanAdd { text: "x".into() }, &ok), Err(JournalError::Tampered { .. })));
        assert_eq!(std::fs::read(j.path()).unwrap_or_default(), before);
    }

    fn plus_op(j: &Journal) -> Result<(Entry, LedgerState), JournalError> {
        j.append(&sid(), false, LedgerOp::PlanAdd { text: "x".into() }, &ok)
    }

    fn head_file(j: &Journal) -> PathBuf {
        j.path().with_extension("head")
    }

    /// A stored line built by hand in the original format (no head involved).
    fn forge(key: &[u8], prev_mac: &str, body: &str) -> (String, String) {
        let mac = mac_hex(key, prev_mac, body.as_bytes()).unwrap_or_default();
        (format!("{},\"mac\":\"{mac}\"}}", &body[..body.len() - 1]), mac)
    }

    /// Two lines in the original format for key `[7; 32]`, sealed outside this module (HMAC-SHA256
    /// over the previous mac's 64 hex characters, zeros for the first line, followed by the body).
    /// A change to what the per-entry MAC covers or to the line layout no longer verifies them.
    const GOLDEN_BODY_1: &str = r#"{"n":1,"ts_ms":10,"session":"s-lead","from_user":false,"op":"plan_add","text":"old a"}"#;
    const GOLDEN_MAC_1: &str = "5cd8f498637502216122bfe874639bc769fe8ee0ba200be9f4972e4d4e23d07d";
    const GOLDEN_MAC_2: &str = "0744ce1bb0aebc84383e157b6df9988f482a605174353033d28f6656340ce120";
    const GOLDEN: &str = concat!(
        r#"{"n":1,"ts_ms":10,"session":"s-lead","from_user":false,"op":"plan_add","text":"old a","mac":"5cd8f498637502216122bfe874639bc769fe8ee0ba200be9f4972e4d4e23d07d"}"#,
        "\n",
        r#"{"n":2,"ts_ms":11,"session":"s-lead","from_user":false,"op":"plan_add","text":"old b","mac":"0744ce1bb0aebc84383e157b6df9988f482a605174353033d28f6656340ce120"}"#,
        "\n",
    );

    fn write_golden(j: &Journal) {
        std::fs::create_dir_all(j.path().parent().unwrap_or(Path::new("."))).unwrap_or_default();
        std::fs::write(j.path(), GOLDEN).unwrap_or_default();
    }

    fn fail_next_write(mode: u8) {
        FAIL_WRITE.with(|f| f.set(mode));
    }

    #[test]
    fn failed_append_leaves_the_file_untouched_and_the_next_succeeds() {
        for mode in [1u8, 2] {
            let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
            let j = journal(&dir);
            fill(&j, 2);
            let before = std::fs::read(j.path()).unwrap_or_default();
            let head_before = std::fs::read(head_file(&j)).unwrap_or_default();
            fail_next_write(mode);
            let r = plus_op(&j);
            fail_next_write(0);
            assert!(matches!(r, Err(JournalError::Io { .. })), "{r:?}");
            assert_eq!(std::fs::read(j.path()).unwrap_or_default(), before, "mode {mode}");
            assert_eq!(std::fs::read(head_file(&j)).unwrap_or_default(), head_before);
            assert_eq!(plus_op(&j).map(|(e, _)| e.n).ok(), Some(3));
            assert_eq!(j.read().map(|v| v.len()).ok(), Some(3));
        }
    }

    #[test]
    fn failed_append_that_cannot_be_undone_says_the_entry_may_be_recorded() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let j = journal(&dir);
        fill(&j, 2);
        fail_next_write(3);
        let r = plus_op(&j);
        fail_next_write(0);
        match r {
            Err(e @ JournalError::Unconfirmed { n: 3, .. }) => {
                let text = e.to_string();
                assert!(text.contains("injected sync failure") && text.contains("injected truncate failure"), "{text}");
                assert!(text.contains("entry 3") && text.contains("may still be in the journal"), "{text}");
            }
            other => panic!("expected Unconfirmed for entry 3, got {other:?}"),
        }
        // The error is not "nothing was recorded": the line did stay, and a read shows it.
        let r = j.read_report().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!((r.entries.len(), r.ahead_of_head), (3, 1));
    }

    #[test]
    fn failed_head_write_keeps_the_entry_and_shows_in_the_report() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let j = journal(&dir);
        fill(&j, 2);
        assert_eq!(j.read_report().map(|r| r.ahead_of_head).ok(), Some(0));
        // A directory where the head's temporary file goes: the head cannot be rewritten.
        let in_the_way = head_file(&j).with_extension("head.tmp");
        std::fs::create_dir(&in_the_way).unwrap_or_else(|e| panic!("{e}"));
        let head_before = std::fs::read(head_file(&j)).unwrap_or_default();
        assert_eq!(plus_op(&j).map(|(e, _)| e.n).ok(), Some(3));
        assert_eq!(std::fs::read(head_file(&j)).unwrap_or_default(), head_before);
        let r = j.read_report().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!((r.entries.len(), r.ahead_of_head), (3, 1));
        // Once the head can be written again the next append brings it up to date.
        std::fs::remove_dir(&in_the_way).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(plus_op(&j).map(|(e, _)| e.n).ok(), Some(4));
        let r = j.read_report().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!((r.entries.len(), r.ahead_of_head), (4, 0));
    }

    #[test]
    fn torn_tail_is_ignored_reported_and_removed_by_the_next_append() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let j = journal(&dir);
        fill(&j, 3);
        // A legacy journal (no head) whose last append was cut mid-line.
        let _ = std::fs::remove_file(head_file(&j));
        let bytes = std::fs::read(j.path()).unwrap_or_default();
        std::fs::write(j.path(), &bytes[..bytes.len() - 10]).unwrap_or_default();
        let r = j.read_report().unwrap_or_else(|e| panic!("{e}"));
        assert!(r.torn_tail);
        assert_eq!(r.entries.len(), 2);
        assert!(plus_op(&j).is_ok());
        let r = j.read_report().unwrap_or_else(|e| panic!("{e}"));
        assert!(!r.torn_tail);
        assert_eq!(r.entries.iter().map(|e| e.n).collect::<Vec<_>>(), [1, 2, 3]);
        assert!(std::fs::read(j.path()).unwrap_or_default().ends_with(b"\n"));
    }

    #[test]
    fn torn_tail_after_the_head_is_ignored_and_removed_by_the_next_append() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let j = journal(&dir);
        fill(&j, 2);
        // What a crash in the middle of the third append leaves: the head vouches for entry 2 and
        // the journal ends in part of a line.
        let complete = std::fs::read(j.path()).unwrap_or_default();
        let mut torn = complete.clone();
        torn.extend_from_slice(br#"{"n":3,"ts_ms":12,"session":"s-lead","from_user":false,"op":"plan_a"#);
        std::fs::write(j.path(), &torn).unwrap_or_default();
        let r = j.read_report().unwrap_or_else(|e| panic!("{e}"));
        assert!(r.torn_tail);
        assert_eq!((r.entries.iter().map(|e| e.n).collect::<Vec<_>>(), r.ahead_of_head), (vec![1, 2], 0));
        assert_eq!(j.state().map(|s| s.plan.len()).ok(), Some(2));

        assert_eq!(plus_op(&j).map(|(e, _)| e.n).ok(), Some(3));
        let bytes = std::fs::read(j.path()).unwrap_or_default();
        assert!(bytes.starts_with(&complete) && bytes.ends_with(b"\n"));
        assert_eq!(bytes.iter().filter(|b| **b == b'\n').count(), 3);
        let r = j.read_report().unwrap_or_else(|e| panic!("{e}"));
        assert!(!r.torn_tail);
        assert_eq!((r.entries.iter().map(|e| e.n).collect::<Vec<_>>(), r.ahead_of_head), (vec![1, 2, 3], 0));
        // The head now vouches for entry 3: going back to the two entries is detected.
        std::fs::write(j.path(), &complete).unwrap_or_default();
        let r = j.read();
        assert!(matches!(&r, Err(JournalError::Tampered { detail, .. }) if detail.contains("truncated or replaced")), "{r:?}");
    }

    #[test]
    fn tail_removal_deletion_and_substitution_are_detected() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let j = journal(&dir);
        assert!(!j.exists());
        fill(&j, 4);
        assert!(j.exists());
        let orig = lines(&j);
        for keep in [3usize, 1] {
            write_lines(&j, &orig[..keep]);
            let r = j.read();
            assert!(matches!(&r, Err(JournalError::Tampered { detail, .. }) if detail.contains("truncated or replaced")), "{keep}: {r:?}");
            assert!(matches!(plus_op(&j), Err(JournalError::Tampered { .. })));
        }
        // Deleting the journal while the head remains: the mission still counts as having a ledger.
        let _ = std::fs::remove_file(j.path());
        assert!(matches!(j.read(), Err(JournalError::Tampered { .. })));
        assert!(j.exists());
        // Another mission's journal and head, sealed with the same key.
        let other = Journal::new(dir.path().join("m-2").join("journal.jsonl"), vec![7u8; 32]);
        fill(&other, 6);
        let _ = std::fs::copy(other.path(), j.path());
        let _ = std::fs::copy(head_file(&other), head_file(&j));
        assert!(matches!(j.read(), Err(JournalError::Tampered { .. })));
        // A tampered head fails its own seal.
        let ok_j = Journal::new(dir.path().join("m-3").join("journal.jsonl"), vec![7u8; 32]);
        fill(&ok_j, 2);
        let head = std::fs::read_to_string(head_file(&ok_j)).unwrap_or_default();
        std::fs::write(head_file(&ok_j), head.replacen("\"n\":2", "\"n\":1", 1)).unwrap_or_default();
        assert!(matches!(ok_j.read(), Err(JournalError::Tampered { .. })));
    }

    #[test]
    fn journal_ahead_of_its_head_is_accepted_and_repaired() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let j = journal(&dir);
        fill(&j, 2);
        let old_head = std::fs::read(head_file(&j)).unwrap_or_default();
        fill(&j, 1);
        std::fs::write(head_file(&j), &old_head).unwrap_or_default();
        assert_eq!(j.read_report().map(|r| (r.entries.len(), r.ahead_of_head)).ok(), Some((3, 1)));
        assert!(plus_op(&j).is_ok());
        assert_ne!(std::fs::read(head_file(&j)).unwrap_or_default(), old_head);
        assert_eq!(j.read_report().map(|r| (r.entries.len(), r.ahead_of_head)).ok(), Some((4, 0)));
        // Now truncating to the old length is detected.
        let v = lines(&j);
        write_lines(&j, &v[..2]);
        assert!(matches!(j.read(), Err(JournalError::Tampered { .. })));
    }

    #[test]
    fn legacy_journal_without_a_head_loads_and_gains_one() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let j = journal(&dir);
        write_golden(&j);
        assert!(!head_file(&j).exists());
        let r = j.read_report().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(r.entries.iter().map(|e| e.mac.as_str()).collect::<Vec<_>>(), [GOLDEN_MAC_1, GOLDEN_MAC_2]);
        assert_eq!(r.entries.get(1).map(|e| &e.op), Some(&LedgerOp::PlanAdd { text: "old b".into() }));
        // Without a head nothing vouches for any of the entries.
        assert_eq!((r.torn_tail, r.unknown, r.ahead_of_head), (false, 0, 2));
        assert_eq!(j.state().map(|s| s.plan.len()).ok(), Some(2));
        assert_eq!(plus_op(&j).map(|(e, _)| e.n).ok(), Some(3));
        assert!(head_file(&j).exists());
        assert_eq!(j.read_report().map(|r| (r.entries.len(), r.ahead_of_head)).ok(), Some((3, 0)));
        assert!(std::fs::read_to_string(j.path()).unwrap_or_default().starts_with(GOLDEN));
    }

    #[test]
    fn the_seal_format_is_pinned_by_a_golden_line() {
        // The writer still produces the golden bytes and seal for the same entry.
        let entry = Entry {
            n: 1,
            ts_ms: 10,
            session: sid(),
            from_user: false,
            op: LedgerOp::PlanAdd { text: "old a".into() },
            mac: String::new(),
        };
        let body = encode_body(&entry).unwrap_or_default();
        assert_eq!(String::from_utf8_lossy(&body), GOLDEN_BODY_1);
        assert_eq!(mac_hex(&[7u8; 32], ZERO_MAC, &body).ok().as_deref(), Some(GOLDEN_MAC_1));
        // The reader accepts them as they are, and not with one sealed byte changed.
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let j = journal(&dir);
        write_golden(&j);
        assert_eq!(j.read().map(|v| v.iter().map(|e| e.n).collect::<Vec<_>>()).ok(), Some(vec![1, 2]));
        std::fs::write(j.path(), GOLDEN.replacen("old b", "old c", 1)).unwrap_or_default();
        assert_eq!(tampered_at(j.read()), 2);
    }

    #[test]
    fn unknown_op_is_skipped_on_read_and_refuses_appends() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let j = journal(&dir);
        let key = vec![7u8; 32];
        let (l1, m1) = forge(&key, ZERO_MAC, r#"{"n":1,"ts_ms":10,"session":"s-lead","from_user":false,"op":"plan_add","text":"a"}"#);
        let (l2, m2) = forge(&key, &m1, r#"{"n":2,"ts_ms":11,"session":"s-lead","from_user":false,"op":"hologram_set","depth":3}"#);
        let (l3, _) = forge(&key, &m2, r#"{"n":3,"ts_ms":12,"session":"s-lead","from_user":false,"op":"plan_add","text":"c"}"#);
        std::fs::create_dir_all(j.path().parent().unwrap_or(dir.path())).unwrap_or_default();
        write_lines(&j, &[l1, l2, l3]);
        let r = j.read_report().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!((r.entries.iter().map(|e| e.n).collect::<Vec<_>>(), r.unknown), (vec![1, 3], 1));
        let why = r.unknown_detail.unwrap_or_default();
        assert!(why.starts_with("entry 2: op `hologram_set`: "), "{why}");
        let before = std::fs::read(j.path()).unwrap_or_default();
        match plus_op(&j) {
            Err(e @ JournalError::NewerVersion { n: 2, .. }) => {
                let text = e.to_string();
                assert!(text.contains("newer loom") && text.contains("entry 2") && text.contains("`hologram_set`"), "{text}");
            }
            other => panic!("expected NewerVersion at entry 2, got {other:?}"),
        }
        assert_eq!(std::fs::read(j.path()).unwrap_or_default(), before);
    }

    #[test]
    fn known_op_that_does_not_parse_says_which_and_why() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let j = journal(&dir);
        let key = vec![7u8; 32];
        // `plan_add` without its `text`: the op name is known, the fields are not what this build reads.
        let (l1, _) = forge(&key, ZERO_MAC, r#"{"n":1,"ts_ms":10,"session":"s-lead","from_user":false,"op":"plan_add","words":"a"}"#);
        std::fs::create_dir_all(j.path().parent().unwrap_or(dir.path())).unwrap_or_default();
        write_lines(&j, &[l1]);
        let r = j.read_report().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!((r.entries.len(), r.unknown), (0, 1));
        let why = r.unknown_detail.unwrap_or_default();
        assert!(why.contains("entry 1") && why.contains("`plan_add`") && why.contains("`text`"), "{why}");
        match plus_op(&j) {
            Err(JournalError::NewerVersion { n: 1, detail }) => {
                assert!(detail.contains("`plan_add`") && detail.contains("`text`"), "{detail}");
            }
            other => panic!("expected NewerVersion at entry 1, got {other:?}"),
        }
    }

    #[test]
    fn read_works_where_the_directory_cannot_be_written() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let j = journal(&dir);
        fill(&j, 2);
        let mission = j.path().parent().unwrap_or(dir.path()).to_path_buf();
        let lock = j.lock_path();
        let set = |p: &Path, mode: u32| std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap_or_default();

        // The lock file is there but cannot be opened for writing: it is held through a read-only descriptor.
        set(&lock, 0o444);
        set(&mission, 0o555);
        let with_lock = j.read_report();
        // A copy that has no lock file: the read goes ahead without one and creates nothing.
        set(&mission, 0o755);
        std::fs::remove_file(&lock).unwrap_or_default();
        set(&mission, 0o555);
        // Modes do not bind a privileged user; then the lock file is simply created.
        let enforced = std::fs::File::create(mission.join("probe")).is_err();
        let without_lock = j.read_report();
        let created = lock.exists();
        set(&mission, 0o755);

        assert_eq!(with_lock.map(|r| (r.entries.len(), r.torn_tail)).ok(), Some((2, false)));
        assert_eq!(without_lock.map(|r| (r.entries.len(), r.torn_tail)).ok(), Some((2, false)));
        if enforced {
            assert!(!created, "the read created {}", lock.display());
        }
        // Appends still work once the directory is writable again.
        assert_eq!(plus_op(&j).map(|(e, _)| e.n).ok(), Some(3));
    }

    #[test]
    fn garbage_lines_are_detected() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let j = journal(&dir);
        fill(&j, 1);
        let mut v = lines(&j);
        v.push("not json".into());
        write_lines(&j, &v);
        assert_eq!(tampered_at(j.read()), 2);
        std::fs::write(j.path(), "\n").unwrap_or_default();
        assert_eq!(tampered_at(j.read()), 1);
    }

    #[test]
    fn wrong_key_is_detected() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let j = journal(&dir);
        fill(&j, 2);
        let other = Journal::new(j.path(), vec![8u8; 32]);
        assert_eq!(tampered_at(other.read()), 1);
        assert!(matches!(other.append(&sid(), false, LedgerOp::PlanAdd { text: "x".into() }, &ok), Err(JournalError::Tampered { n: 1, .. })));
        assert_eq!(j.read().unwrap_or_default().len(), 2);
    }

    #[test]
    fn rule_refusal_writes_nothing() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let j = journal(&dir);
        fill(&j, 1);
        let before = std::fs::read(j.path()).unwrap_or_default();
        match j.append(&sid(), false, LedgerOp::GoalSet { text: "mine".into() }, &ok) {
            Err(JournalError::Rule(m)) => assert!(m.contains("cannot be written by a tool call"), "{m}"),
            other => panic!("expected Rule, got {other:?}"),
        }
        match j.append(&sid(), false, LedgerOp::PlanUpdate { id: "p9".into(), status: StepStatus::Doing, note: String::new(), evidence: vec![] }, &ok) {
            Err(JournalError::Rule(m)) => assert!(m.contains("p1"), "{m}"),
            other => panic!("expected Rule, got {other:?}"),
        }
        assert_eq!(std::fs::read(j.path()).unwrap_or_default(), before);
        // A refusal on an empty journal does not create the file.
        let j2 = Journal::new(dir.path().join("other").join("journal.jsonl"), vec![1u8; 32]);
        assert!(j2.append(&sid(), false, LedgerOp::GoalSet { text: "x".into() }, &ok).is_err());
        assert!(!j2.path().exists());
    }

    #[test]
    fn check_refusal_writes_nothing() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let j = journal(&dir);
        fill(&j, 1);
        let before = std::fs::read(j.path()).unwrap_or_default();
        let seen = std::cell::Cell::new(0u64);
        let check = |s: &LedgerState| {
            seen.set(s.entries);
            Err("the cited call does not exist; pick a call id from the session".to_string())
        };
        match j.append(&sid(), false, LedgerOp::PlanAdd { text: "x".into() }, &check) {
            Err(JournalError::Rule(m)) => assert!(m.contains("cited call"), "{m}"),
            other => panic!("expected Rule, got {other:?}"),
        }
        assert_eq!(seen.get(), 1, "check sees the state before the op");
        assert_eq!(std::fs::read(j.path()).unwrap_or_default(), before);
    }

    #[test]
    fn concurrent_appends_get_distinct_consecutive_ids() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let path = dir.path().join("journal.jsonl");
        let handles: Vec<_> = (0..2)
            .map(|t| {
                let j = Journal::new(path.clone(), vec![3u8; 32]);
                std::thread::spawn(move || {
                    for i in 0..50 {
                        let r = j.append(&SessionId::from(format!("s-{t}")), false, LedgerOp::PlanAdd { text: format!("t{t} i{i}") }, &ok);
                        assert!(r.is_ok(), "{r:?}");
                    }
                })
            })
            .collect();
        for h in handles {
            assert!(h.join().is_ok());
        }
        let j = Journal::new(path, vec![3u8; 32]);
        let entries = j.read().unwrap_or_else(|e| panic!("{e}"));
        let ns: Vec<u64> = entries.iter().map(|e| e.n).collect();
        assert_eq!(ns, (1..=100).collect::<Vec<u64>>());
        assert_eq!(j.state().unwrap_or_default().plan.len(), 100);
    }

    #[test]
    fn readers_never_see_a_partial_append() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let path = dir.path().join("m-1").join("journal.jsonl");
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let readers: Vec<_> = (0..2)
            .map(|_| {
                let j = Journal::new(path.clone(), vec![3u8; 32]);
                let done = done.clone();
                std::thread::spawn(move || {
                    while !done.load(std::sync::atomic::Ordering::SeqCst) {
                        let r = j.read_report();
                        assert!(matches!(&r, Ok(rep) if !rep.torn_tail), "{r:?}");
                    }
                })
            })
            .collect();
        let writer = Journal::new(path, vec![3u8; 32]);
        for i in 0..60 {
            let r = writer.append(&sid(), false, LedgerOp::PlanAdd { text: format!("i{i}") }, &ok);
            assert!(r.is_ok(), "{r:?}");
        }
        done.store(true, std::sync::atomic::Ordering::SeqCst);
        for h in readers {
            assert!(h.join().is_ok());
        }
    }

    #[test]
    fn key_file_is_created_private_and_reused() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let path = dir.path().join("keys").join("deep").join("journal.key");
        let k1 = load_or_create_key(&path).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(k1.len(), 32);
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        assert_eq!(text.len(), 64);
        assert!(text.chars().all(|c| c.is_ascii_hexdigit()));
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).map(|m| m.permissions().mode() & 0o777).unwrap_or(0);
            assert_eq!(mode(&path), 0o600);
            assert_eq!(mode(path.parent().unwrap_or(&path)), 0o700);
        }
        let k2 = load_or_create_key(&path).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(k1, k2);
    }

    #[test]
    fn malformed_key_file_is_an_error_and_is_not_overwritten() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let path = dir.path().join("journal.key");
        for content in ["", "abc", &"z".repeat(64), &"a".repeat(63)] {
            std::fs::write(&path, content).unwrap_or_default();
            let err = load_or_create_key(&path);
            assert!(matches!(&err, Err(e) if e.kind() == std::io::ErrorKind::InvalidData), "{content:?}: {err:?}");
            assert_eq!(std::fs::read_to_string(&path).unwrap_or_default(), content);
        }
        // A trailing newline is tolerated.
        std::fs::write(&path, format!("{}\n", "ab".repeat(32))).unwrap_or_default();
        assert_eq!(load_or_create_key(&path).map(|k| k.len()).ok(), Some(32));
    }
}
