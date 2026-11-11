//! Running a command so that its output and exit status survive whatever happens to this process.
//!
//! CONTRACT (bodies are placeholders for the implementer; signatures and types are fixed).
//!
//! A command writes its output to a file and its exit status to another, both opened by us and
//! inherited as file descriptors (so they can live where the sandbox forbids the command to open
//! files). Nothing depends on this process staying alive: a restarted daemon can pick the command up
//! again with [`Running::adopt`].
//!
//! ## `spawn`
//! Runs, via `Sandbox::command`, this wrapper script with `spec.script` as `$0`:
//!
//! ```text
//! /bin/bash -c "$0" 2>&1; echo $? >&2
//! ```
//!
//! with stdin `/dev/null`, stdout = `out_path` (created, append), stderr = `exit_path` (created,
//! truncated), working directory `spec.cwd`, environment exactly `spec.env` (cleared first), and its
//! own process group (`process_group(0)`). So `out_path` holds stdout and stderr of the command in
//! the order they were written, and `exit_path` ends up holding the status as a decimal number.
//! Anything else in `exit_path` (the sandbox launcher or the shell complaining) means the command did
//! not start properly: [`Ended::Failed`] carries that text.
//!
//! ## `poll`
//! Non-blocking. If we are the parent, reap the child when it has exited (`try_wait`). The command
//! has ended when the child was reaped or — adopted commands — `kill(pid, 0)` says the process is
//! gone. Then the status comes from `exit_path`: a number `n < 128` → `Exit(n)`; `n >= 128` →
//! `Signal(n - 128)`; empty → `Signal(sig)` if the reaped status carries a signal, else `Unknown`;
//! other text → `Failed(text)`. Until then `None`. Once it has returned `Some`, it keeps returning
//! the same value.
//!
//! ## `wait`
//! Polls every 50 ms (25 ms for the first second) until the command ends, `cancel` fires, `deadline`
//! elapses, or the output file is larger than `max_bytes` — whichever happens first — and says
//! which. It never kills anything.
//!
//! ## `terminate`
//! Sends TERM to the process group; polls for up to `grace`; if anything in the group is still alive
//! (`kill(-pgid, 0)`), sends KILL to the group and waits for the leader to go. Returns what `poll`
//! then reports. Safe to call on a command that has already ended (does nothing).
//!
//! ## Output
//! `output_len` is the current size of the output file; `read_output(from)` returns its bytes from
//! offset `from` to the end (empty when `from` is at or past the end).
//!
//! Tests required (real processes, `Sandbox` in mode `none`, everything under a `tempfile` dir):
//! exit 0 and non-zero; stdout/stderr interleaved in order; a command killed by a signal; a command
//! that does not exist (exit 127); `wait` ending by deadline, by cancel and by size; `terminate`
//! kills a whole tree (`sleep 300 & sleep 300 & wait`) and a process that ignores TERM; environment
//! is exactly what was given; cwd; output readable incrementally while running; `adopt` of a running
//! command sees it end and reads its status; scripts with quotes, newlines and `$` reach bash intact.

use crate::sandbox::Sandbox;
use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug)]
pub struct Spawn {
    pub script: String,
    pub cwd: PathBuf,
    pub env: BTreeMap<String, String>,
    pub out_path: PathBuf,
    pub exit_path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ended {
    Exit(i32),
    Signal(i32),
    /// The process is gone and left no status.
    Unknown,
    /// The command could not be started; the text says why.
    Failed(String),
}

impl Ended {
    /// `exit 0`, `exit 3`, `killed by signal 9 (KILL)`, `ended without a status`, `could not start`.
    pub fn outcome(&self) -> String {
        todo!("implement per module contract")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WaitEnd {
    Ended(Ended),
    Deadline,
    Cancelled,
    TooMuchOutput,
}

#[derive(Debug)]
pub struct Running {
    pub pid: u32,
    pub out_path: PathBuf,
    pub exit_path: PathBuf,
    pub started_ms: u64,
    child: Option<tokio::process::Child>,
    ended: Option<Ended>,
}

pub fn spawn(sandbox: &Sandbox, spec: &Spawn) -> io::Result<Running> {
    let _ = (sandbox, spec);
    todo!("implement per module contract")
}

impl Running {
    /// A command started by an earlier run of this program.
    pub fn adopt(pid: u32, out_path: PathBuf, exit_path: PathBuf, started_ms: u64) -> Running {
        Running { pid, out_path, exit_path, started_ms, child: None, ended: None }
    }

    pub fn poll(&mut self) -> Option<Ended> {
        let _ = (&self.child, &self.ended);
        todo!("implement per module contract")
    }

    pub async fn wait(&mut self, cancel: &CancellationToken, deadline: Option<Duration>, max_bytes: u64) -> WaitEnd {
        let _ = (cancel, deadline, max_bytes);
        todo!("implement per module contract")
    }

    pub async fn terminate(&mut self, grace: Duration) -> Ended {
        let _ = grace;
        todo!("implement per module contract")
    }

    pub fn output_len(&self) -> u64 {
        todo!("implement per module contract")
    }

    pub fn read_output(&self, from: u64) -> io::Result<Vec<u8>> {
        let _ = from;
        todo!("implement per module contract")
    }
}
