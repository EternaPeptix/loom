//! Background jobs: commands that outlive the tool call that started them.
//!
//! CONTRACT (bodies are placeholders for the implementer; signatures and types are fixed).
//!
//! A job is a [`crate::proc::Running`] command with an id (`j1`, `j2`, … per table). The table owns
//! it from `register` on. A watcher task per job waits for it to end; when it does, the watcher
//! normalises and stores the job's complete output (`view::store_text`), marks the job ended, and
//! sends [`JobEvent::Settled`] — exactly once per job, whether it ended by itself or was killed.
//! `register` sends [`JobEvent::Registered`] first. The runtime turns these events into log records,
//! ledger obligations and a wake-up for the session; this module only reports.
//!
//! - `allocate()`: the next id and its output/status file paths, `<dir>/<id>.out` and `<dir>/<id>.status`
//!   (creates `dir`). Ids are never reused within a table; `resume_from(n)` makes the next id `j{n+1}`
//!   (used after a restart).
//! - `wait(id, timeout, cancel)`: returns when the job has ended, the timeout elapsed, or `cancel`
//!   fired. The view contains the output written since the previous `wait`/`peek` of this job
//!   (`new_output`, raw bytes; the read position advances), the byte offset it starts at, and the
//!   state. Unknown id → a sentence listing the known job ids (or saying there are none).
//! - `peek(id)`: like `wait` with no waiting.
//! - `kill(id, grace)`: `Running::terminate`; the job settles as `Killed`. Killing an ended job is not
//!   an error: the view simply shows its state.
//! - `kill_all(grace)`: every running job, concurrently; returns when all have settled.
//! - `list()`: all jobs, in id order.
//! - A job whose output passes `max_output_bytes` is killed by its watcher and settles as
//!   `Killed` with `detail` saying the output limit was reached.
//!
//! Tests required (real processes, sandbox mode `none`, tempfile): a job that finishes sends
//! Registered then Settled with its stored output and exit status; `wait` returns early on end and on
//! timeout; successive waits return disjoint, contiguous output; `kill`; `kill_all` with several
//! jobs; output-limit kill; unknown id; `list`; `resume_from`; no event is sent twice.

use crate::proc::{Ended, Running};
use loom_core::{BlobRef, BlobStore, CallId};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobState {
    Running,
    Ended(Ended),
    Killed,
}

impl JobState {
    /// `running`, `exit 0`, `killed`, ….
    pub fn outcome(&self) -> String {
        match self {
            JobState::Running => "running".to_string(),
            JobState::Ended(e) => e.outcome(),
            JobState::Killed => "killed".to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobInfo {
    pub id: String,
    pub call_id: CallId,
    pub command: String,
    pub pid: u32,
    pub started_ms: u64,
    pub out_path: PathBuf,
    pub exit_path: PathBuf,
    pub state: JobState,
    pub output_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobView {
    pub info: JobInfo,
    /// Output written since this job was last looked at.
    pub new_output: Vec<u8>,
    /// Byte offset of `new_output` in the job's whole output.
    pub from: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobEvent {
    Registered(JobInfo),
    Settled {
        info: JobInfo,
        /// The complete output, stored. `None` only when storing failed.
        output: Option<BlobRef>,
        /// Why it ended, when that needs saying (output limit, storage failure).
        detail: String,
    },
}

pub struct JobTable {
    dir: PathBuf,
    blobs: BlobStore,
    events: UnboundedSender<JobEvent>,
    max_output_bytes: u64,
    inner: Arc<tokio::sync::Mutex<Inner>>,
}

#[derive(Default)]
struct Inner {
    next: u64,
}

impl JobTable {
    pub fn new(dir: PathBuf, blobs: BlobStore, events: UnboundedSender<JobEvent>, max_output_bytes: u64) -> JobTable {
        JobTable { dir, blobs, events, max_output_bytes, inner: Arc::new(tokio::sync::Mutex::new(Inner::default())) }
    }

    pub async fn resume_from(&self, n: u64) {
        let _ = n;
        todo!("implement per module contract")
    }

    pub async fn allocate(&self) -> std::io::Result<(String, PathBuf, PathBuf)> {
        let _ = (&self.dir, &self.inner);
        todo!("implement per module contract")
    }

    pub async fn register(&self, id: &str, call_id: &CallId, command: &str, running: Running) -> JobInfo {
        let _ = (id, call_id, command, running, &self.blobs, &self.events, self.max_output_bytes);
        todo!("implement per module contract")
    }

    pub async fn list(&self) -> Vec<JobInfo> {
        todo!("implement per module contract")
    }

    pub async fn peek(&self, id: &str) -> Result<JobView, String> {
        let _ = id;
        todo!("implement per module contract")
    }

    pub async fn wait(&self, id: &str, timeout: Duration, cancel: &CancellationToken) -> Result<JobView, String> {
        let _ = (id, timeout, cancel);
        todo!("implement per module contract")
    }

    pub async fn kill(&self, id: &str, grace: Duration) -> Result<JobView, String> {
        let _ = (id, grace);
        todo!("implement per module contract")
    }

    pub async fn kill_all(&self, grace: Duration) {
        let _ = grace;
        todo!("implement per module contract")
    }
}
