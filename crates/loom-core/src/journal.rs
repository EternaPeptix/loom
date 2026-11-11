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
//! Two processes appending concurrently therefore get distinct, consecutive `n`.
//!
//! `read` verifies and returns all entries. An incomplete final line (no newline) is reported as
//! `Tampered` — the journal is never silently repaired.
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
use std::path::{Path, PathBuf};

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

    /// Verify and return every entry. A missing file is an empty journal.
    pub fn read(&self) -> Result<Vec<Entry>, JournalError> {
        let _ = &self.key;
        todo!("implement per module contract")
    }

    /// Verify, fold and return the current state.
    pub fn state(&self) -> Result<LedgerState, JournalError> {
        todo!("implement per module contract")
    }

    /// Append one op. See the module contract for the steps.
    pub fn append(
        &self,
        session: &SessionId,
        from_user: bool,
        op: LedgerOp,
        check: &dyn Fn(&LedgerState) -> Result<(), String>,
    ) -> Result<(Entry, LedgerState), JournalError> {
        let _ = (session, from_user, op, check);
        todo!("implement per module contract")
    }
}

/// Load the journal key, creating it when missing. See the module contract.
pub fn load_or_create_key(path: &Path) -> std::io::Result<Vec<u8>> {
    let _ = path;
    todo!("implement per module contract")
}
