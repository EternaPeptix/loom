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
//! Additions beyond the contract (this file only): `register_from` (a job whose first bytes the model
//! was already shown), `output_blob` and `elapsed_ms` (what the job tools report). A table that is
//! dropped kills every job still running.
//!
//! Tests required (real processes, sandbox mode `none`, tempfile): a job that finishes sends
//! Registered then Settled with its stored output and exit status; `wait` returns early on end and on
//! timeout; successive waits return disjoint, contiguous output; `kill`; `kill_all` with several
//! jobs; output-limit kill; unknown id; `list`; `resume_from`; no event is sent twice.

use crate::proc::{Ended, Running, WaitEnd};
use loom_core::{BlobRef, BlobStore, CallId};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
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

/// Longest a job gets between TERM and KILL when the harness stops it for its output size.
const OUTPUT_LIMIT_GRACE: Duration = Duration::from_secs(2);

/// How long `kill` waits, beyond the grace period, for the watcher to report the job settled.
const KILL_REPORT_SLACK: Duration = Duration::from_secs(15);

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)).unwrap_or(0)
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn id_number(id: &str) -> Option<u64> {
    id.strip_prefix('j').and_then(|n| n.parse().ok())
}

fn id_order(id: &str) -> (u64, String) {
    (id_number(id).unwrap_or(u64::MAX), id.to_string())
}

fn file_len(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

/// The bytes of `path` from offset `from` to the end.
fn read_from(path: &Path, from: u64) -> std::io::Result<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path)?;
    if from >= f.metadata()?.len() {
        return Ok(Vec::new());
    }
    f.seek(SeekFrom::Start(from))?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    Ok(buf)
}

struct St {
    info: JobInfo,
    read_pos: u64,
    ended_ms: Option<u64>,
    blob: Option<BlobRef>,
}

/// One job, shared by the table and its watcher.
struct Shared {
    st: Mutex<St>,
    /// Becomes true, once, after the job has settled and its event has been sent.
    ended: tokio::sync::watch::Sender<bool>,
    /// Cancelled to ask the watcher to stop the job.
    stop: CancellationToken,
    grace: Mutex<Duration>,
}

pub struct JobTable {
    dir: PathBuf,
    blobs: BlobStore,
    events: UnboundedSender<JobEvent>,
    max_output_bytes: u64,
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    /// The number of the last id handed out.
    last: u64,
    jobs: Vec<Arc<Shared>>,
}

fn unknown(id: &str, known: &[String]) -> String {
    if known.is_empty() {
        format!("There is no job `{id}`: no background job has been started in this session. Start one with bash and `background: true`.")
    } else {
        format!("There is no job `{id}`. The jobs of this session are: {}. Call the tool again with one of them (job_list shows their state).", known.join(", "))
    }
}

impl JobTable {
    pub fn new(dir: PathBuf, blobs: BlobStore, events: UnboundedSender<JobEvent>, max_output_bytes: u64) -> JobTable {
        JobTable { dir, blobs, events, max_output_bytes, inner: Mutex::new(Inner::default()) }
    }

    /// The next id will be `j{n+1}` (never lower than ids already handed out).
    pub async fn resume_from(&self, n: u64) {
        let mut inner = lock(&self.inner);
        inner.last = inner.last.max(n);
    }

    /// The next id and the paths of its output and status files.
    pub async fn allocate(&self) -> std::io::Result<(String, PathBuf, PathBuf)> {
        std::fs::create_dir_all(&self.dir)?;
        let mut inner = lock(&self.inner);
        inner.last = inner.last.saturating_add(1);
        let id = format!("j{}", inner.last);
        let out = self.dir.join(format!("{id}.out"));
        let status = self.dir.join(format!("{id}.status"));
        Ok((id, out, status))
    }

    pub async fn register(&self, id: &str, call_id: &CallId, command: &str, running: Running) -> JobInfo {
        self.register_from(id, call_id, command, running, 0).await
    }

    /// Like [`JobTable::register`], for a job whose first `read_from` bytes of output the model has
    /// already been shown: the first `job_wait` starts after them.
    pub async fn register_from(&self, id: &str, call_id: &CallId, command: &str, running: Running, read_from: u64) -> JobInfo {
        let info = JobInfo {
            id: id.to_string(),
            call_id: call_id.clone(),
            command: command.to_string(),
            pid: running.pid,
            started_ms: running.started_ms,
            out_path: running.out_path.clone(),
            exit_path: running.exit_path.clone(),
            state: JobState::Running,
            output_bytes: running.output_len(),
        };
        let (ended, _) = tokio::sync::watch::channel(false);
        let shared = Arc::new(Shared {
            st: Mutex::new(St { info: info.clone(), read_pos: read_from, ended_ms: None, blob: None }),
            ended,
            stop: CancellationToken::new(),
            grace: Mutex::new(Duration::from_secs(5)),
        });
        {
            let mut inner = lock(&self.inner);
            if let Some(n) = id_number(id) {
                inner.last = inner.last.max(n);
            }
            inner.jobs.push(shared.clone());
        }
        let _ = self.events.send(JobEvent::Registered(info.clone()));
        tokio::spawn(watch(shared, running, self.blobs.clone(), self.events.clone(), self.max_output_bytes));
        info
    }

    fn find(&self, id: &str) -> Result<Arc<Shared>, String> {
        let inner = lock(&self.inner);
        if let Some(j) = inner.jobs.iter().find(|j| lock(&j.st).info.id == id) {
            return Ok(j.clone());
        }
        let mut ids: Vec<(u64, String)> = inner.jobs.iter().map(|j| id_order(&lock(&j.st).info.id)).collect();
        ids.sort();
        let known: Vec<String> = ids.into_iter().map(|(_, i)| i).collect();
        Err(unknown(id, &known))
    }

    /// All jobs, in id order.
    pub async fn list(&self) -> Vec<JobInfo> {
        let jobs: Vec<Arc<Shared>> = lock(&self.inner).jobs.clone();
        let mut out: Vec<JobInfo> = jobs.iter().map(|j| snapshot(j)).collect();
        out.sort_by_key(|i| id_order(&i.id));
        out
    }

    /// Milliseconds the job ran (so far, while it is running). `None` for an unknown id.
    pub fn elapsed_ms(&self, id: &str) -> Option<u64> {
        let j = self.find(id).ok()?;
        let st = lock(&j.st);
        Some(st.ended_ms.unwrap_or_else(now_ms).saturating_sub(st.info.started_ms))
    }

    /// The stored complete output of a job that has settled (`None` while it runs or when storing failed).
    pub fn output_blob(&self, id: &str) -> Option<BlobRef> {
        let j = self.find(id).ok()?;
        let blob = lock(&j.st).blob.clone();
        blob
    }

    pub async fn peek(&self, id: &str) -> Result<JobView, String> {
        let j = self.find(id)?;
        Ok(view_of(&j))
    }

    pub async fn wait(&self, id: &str, timeout: Duration, cancel: &CancellationToken) -> Result<JobView, String> {
        let j = self.find(id)?;
        let mut rx = j.ended.subscribe();
        tokio::select! {
            _ = rx.wait_for(|ended| *ended) => {}
            () = tokio::time::sleep(timeout) => {}
            () = cancel.cancelled() => {}
        }
        Ok(view_of(&j))
    }

    pub async fn kill(&self, id: &str, grace: Duration) -> Result<JobView, String> {
        let j = self.find(id)?;
        stop(&j, grace).await;
        Ok(view_of(&j))
    }

    /// Stops every running job at once and returns when each has settled.
    pub async fn kill_all(&self, grace: Duration) {
        let jobs: Vec<Arc<Shared>> = lock(&self.inner).jobs.clone();
        futures_util::future::join_all(jobs.iter().map(|j| stop(j, grace))).await;
    }
}

impl Drop for JobTable {
    /// A table that goes away takes its running jobs with it.
    fn drop(&mut self) {
        let jobs: Vec<Arc<Shared>> = lock(&self.inner).jobs.clone();
        for j in jobs {
            let st = lock(&j.st);
            if st.ended_ms.is_none() {
                *lock(&j.grace) = Duration::ZERO;
                j.stop.cancel();
                crate::proc::kill_recorded_group(st.info.pid, &st.info.exit_path);
            }
        }
    }
}

async fn stop(j: &Arc<Shared>, grace: Duration) {
    let mut rx = j.ended.subscribe();
    if *rx.borrow() {
        return;
    }
    *lock(&j.grace) = grace;
    j.stop.cancel();
    let _ = tokio::time::timeout(grace + KILL_REPORT_SLACK, rx.wait_for(|ended| *ended)).await;
}

fn snapshot(j: &Shared) -> JobInfo {
    let mut st = lock(&j.st);
    if st.ended_ms.is_none() {
        st.info.output_bytes = file_len(&st.info.out_path);
    }
    st.info.clone()
}

/// The output written since the last look; advances the read position.
fn view_of(j: &Shared) -> JobView {
    let mut st = lock(&j.st);
    if st.ended_ms.is_none() {
        st.info.output_bytes = file_len(&st.info.out_path);
    }
    let from = st.read_pos;
    let new_output = read_from(&st.info.out_path, from).unwrap_or_default();
    st.read_pos = from.saturating_add(new_output.len() as u64);
    JobView { info: st.info.clone(), new_output, from }
}

/// Owns the process until it is over, then stores the output and reports, once.
async fn watch(shared: Arc<Shared>, mut running: Running, blobs: BlobStore, events: UnboundedSender<JobEvent>, max_output_bytes: u64) {
    let mut detail = String::new();
    let end = running.wait(&shared.stop, None, max_output_bytes).await;
    let state = match end {
        WaitEnd::Ended(Ended::TrackingFailed(error)) => {
            detail = error.clone();
            JobState::Ended(Ended::TrackingFailed(error))
        }
        WaitEnd::Ended(e) => JobState::Ended(e),
        WaitEnd::Cancelled | WaitEnd::Deadline => {
            let grace = *lock(&shared.grace);
            match running.terminate(grace).await {
                Ended::TrackingFailed(error) => {
                    detail = error.clone();
                    JobState::Ended(Ended::TrackingFailed(error))
                }
                _ => JobState::Killed,
            }
        }
        WaitEnd::TooMuchOutput => {
            detail = format!("stopped by the harness: the output passed the limit of {max_output_bytes} bytes");
            match running.terminate(OUTPUT_LIMIT_GRACE).await {
                Ended::TrackingFailed(error) => {
                    detail.push_str(&format!("; {error}"));
                    JobState::Ended(Ended::TrackingFailed(error))
                }
                _ => JobState::Killed,
            }
        }
    };
    // Only a complete group has final output. A failed ownership/inspection check is reported as
    // a failure, with the available snapshot and its explicit detail, rather than a successful kill.
    let path = lock(&shared.st).info.out_path.clone();
    let stored = read_from(&path, 0)
        .and_then(|raw| crate::view::store_text(&blobs, &raw).map(|(b, _)| b))
        .map_err(|e| format!("the complete output could not be stored ({e}); it is still in the file {}", path.display()));
    let output = match stored {
        Ok(b) => Some(b),
        Err(msg) => {
            if !detail.is_empty() {
                detail.push_str("; ");
            }
            detail.push_str(&msg);
            None
        }
    };
    let info = {
        let mut st = lock(&shared.st);
        st.info.state = state;
        st.info.output_bytes = file_len(&path);
        st.ended_ms = Some(now_ms());
        st.blob = output.clone();
        st.info.clone()
    };
    let _ = events.send(JobEvent::Settled { info, output, detail });
    shared.ended.send_replace(true);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proc::{spawn, Spawn};
    use crate::sandbox::Sandbox;
    use loom_core::config::{SandboxCfg, SandboxMode};
    use tokio::sync::mpsc::{error::TryRecvError, UnboundedReceiver};

    struct Fx {
        _dir: tempfile::TempDir,
        root: PathBuf,
        sb: Sandbox,
        table: JobTable,
        rx: UnboundedReceiver<JobEvent>,
        blobs: BlobStore,
    }

    fn fx_with(max_output: u64) -> Fx {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().canonicalize().expect("canonical");
        for d in ["ws", "tmp", "home"] {
            std::fs::create_dir_all(root.join(d)).expect("mkdir");
        }
        let cfg = SandboxCfg { mode: SandboxMode::None, ..SandboxCfg::default() };
        let sb = Sandbox::new(&cfg, &root.join("ws"), &root.join("tmp"), &root.join("home"), None).expect("sandbox");
        let blobs = BlobStore::open(root.join("home/blobs")).expect("blobs");
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let table = JobTable::new(root.join("home/jobs"), blobs.clone(), tx, max_output);
        Fx { _dir: dir, root, sb, table, rx, blobs }
    }

    fn fx() -> Fx {
        fx_with(1 << 20)
    }

    impl Fx {
        async fn start(&self, script: &str) -> JobInfo {
            self.start_from(script, 0).await
        }

        async fn start_from(&self, script: &str, read_from: u64) -> JobInfo {
            let (id, out_path, exit_path) = self.table.allocate().await.expect("allocate");
            let env = [("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")].iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
            let spec = Spawn { script: script.to_string(), cwd: self.root.clone(), env, out_path, exit_path };
            let running = spawn(&self.sb, &spec).expect("spawn");
            self.table.register_from(&id, &CallId::from("call-1"), script, running, read_from).await
        }

        async fn event(&mut self) -> JobEvent {
            tokio::time::timeout(Duration::from_secs(20), self.rx.recv()).await.expect("event in time").expect("channel open")
        }

        fn stored(&self, blob: &BlobRef) -> String {
            String::from_utf8(self.blobs.read_all(&blob.id).expect("read blob")).expect("utf-8")
        }

        /// No further event arrives.
        async fn assert_quiet(&mut self) {
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert!(matches!(self.rx.try_recv(), Err(TryRecvError::Empty)));
        }
    }

    fn never() -> CancellationToken {
        CancellationToken::new()
    }

    fn alive(pid: u32) -> bool {
        // SAFETY: signal 0 only tests for existence.
        unsafe { libc::kill(i32::try_from(pid).expect("pid"), 0) == 0 }
    }

    #[tokio::test]
    async fn a_job_that_finishes_sends_registered_then_settled_once() {
        let mut f = fx();
        let info = f.start("echo hi; echo oops >&2; exit 3").await;
        assert_eq!(info.id, "j1");
        assert_eq!(info.state, JobState::Running);
        let JobEvent::Registered(reg) = f.event().await else { panic!("Registered must come first") };
        assert_eq!(reg.id, "j1");
        let JobEvent::Settled { info, output, detail } = f.event().await else { panic!("Settled must follow") };
        assert_eq!(info.state, JobState::Ended(Ended::Exit(3)));
        assert_eq!(info.state.outcome(), "exit 3");
        assert_eq!(f.stored(&output.expect("stored")), "hi\noops\n");
        assert_eq!(detail, "");
        assert_eq!(info.output_bytes, 8);
        f.assert_quiet().await;
        // Killing it and waiting for it send nothing more.
        f.table.kill("j1", Duration::from_millis(100)).await.expect("kill ended job");
        f.table.wait("j1", Duration::from_millis(10), &never()).await.expect("wait");
        f.assert_quiet().await;
    }

    #[tokio::test]
    async fn settlement_waits_for_late_output_after_the_shell_exits() {
        let mut f = fx();
        f.start("(sleep 0.6; echo late) & echo first; exit 7").await;
        let _ = f.event().await;
        let view = f.table.wait("j1", Duration::from_millis(150), &never()).await.expect("first view");
        assert_eq!(view.info.state, JobState::Running);
        assert!(f.table.output_blob("j1").is_none());
        let JobEvent::Settled { info, output, .. } = f.event().await else { panic!("settled") };
        assert_eq!(info.state, JobState::Ended(Ended::Exit(7)));
        assert_eq!(f.stored(&output.expect("output")), "first\nlate\n");
        f.assert_quiet().await;
    }

    #[tokio::test]
    async fn job_kill_reaches_a_group_whose_shell_already_exited() {
        let mut f = fx();
        let info = f.start("sleep 300 & echo $!; exit 0").await;
        let _ = f.event().await;
        for _ in 0..100 {
            if std::fs::read_to_string(&info.exit_path).unwrap_or_default().trim() == "0" { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(std::fs::read_to_string(&info.exit_path).expect("status").trim(), "0");
        let output = std::fs::read_to_string(&info.out_path).expect("pid output");
        let child: u32 = output.trim().parse().expect("descendant pid");
        assert!(alive(child), "the descendant outlives its shell");
        assert_eq!(f.table.peek("j1").await.expect("peek").info.state, JobState::Running);
        let view = f.table.kill("j1", Duration::from_millis(100)).await.expect("kill descendants");
        assert_eq!(view.info.state, JobState::Killed);
        let JobEvent::Settled { output, .. } = f.event().await else { panic!("settled") };
        assert_eq!(f.stored(&output.expect("stored")), format!("{child}\n"));
        for _ in 0..200 {
            if !alive(child) { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(!alive(child), "job_kill must stop the descendant");
        f.assert_quiet().await;
    }

    #[tokio::test]
    async fn late_descendant_output_still_triggers_a_job_limit() {
        let mut f = fx_with(2000);
        f.start("(sleep 0.3; head -c 5000 /dev/zero; sleep 300) & exit 0").await;
        let _ = f.event().await;
        let JobEvent::Settled { info, output, detail } = f.event().await else { panic!("settled") };
        assert_eq!(info.state, JobState::Killed);
        assert!(info.output_bytes > 2000);
        assert!(output.is_some());
        assert!(detail.contains("limit of 2000 bytes"));
        f.assert_quiet().await;
    }

    #[tokio::test]
    async fn wait_returns_when_the_job_ends_and_when_the_time_is_up() {
        let f = fx();
        f.start("sleep 0.3; echo done").await;
        let t = std::time::Instant::now();
        let v = f.table.wait("j1", Duration::from_secs(20), &never()).await.expect("wait");
        assert!(t.elapsed() < Duration::from_secs(10));
        assert_eq!(v.info.state, JobState::Ended(Ended::Exit(0)));
        assert_eq!(v.new_output, b"done\n");
        assert_eq!(v.from, 0);
        assert!(f.table.output_blob("j1").is_some());

        f.start("sleep 300").await;
        let t = std::time::Instant::now();
        let v = f.table.wait("j2", Duration::from_millis(200), &never()).await.expect("wait");
        assert!(t.elapsed() >= Duration::from_millis(190) && t.elapsed() < Duration::from_secs(10));
        assert_eq!(v.info.state, JobState::Running);
        assert_eq!(v.info.state.outcome(), "running");
        assert!(v.new_output.is_empty());
        assert!(f.table.output_blob("j2").is_none());

        // A fired cancel token ends the wait; the job keeps running.
        let c = never();
        c.cancel();
        let v = f.table.wait("j2", Duration::from_secs(60), &c).await.expect("wait");
        assert_eq!(v.info.state, JobState::Running);
        f.table.kill_all(Duration::from_millis(200)).await;
    }

    #[tokio::test]
    async fn successive_waits_return_contiguous_disjoint_output() {
        let f = fx();
        f.start("echo one; sleep 1; echo two; sleep 1; echo three").await;
        let mut got = Vec::new();
        let mut next = 0u64;
        for _ in 0..200 {
            let v = f.table.wait("j1", Duration::from_millis(300), &never()).await.expect("wait");
            assert_eq!(v.from, next, "each view starts where the previous one ended");
            next += v.new_output.len() as u64;
            got.extend_from_slice(&v.new_output);
            if v.info.state != JobState::Running {
                break;
            }
        }
        assert_eq!(String::from_utf8(got).expect("utf-8"), "one\ntwo\nthree\n");
        let v = f.table.peek("j1").await.expect("peek");
        assert!(v.new_output.is_empty());
        assert_eq!(v.from, 14);
        assert_eq!(v.info.output_bytes, 14);
    }

    #[tokio::test]
    async fn registered_from_skips_what_was_shown() {
        let f = fx();
        f.start_from("echo shown; echo rest", 6).await;
        let v = f.table.wait("j1", Duration::from_secs(20), &never()).await.expect("wait");
        assert_eq!((v.from, v.new_output.as_slice()), (6, b"rest\n".as_slice()));
    }

    #[tokio::test]
    async fn kill_stops_the_job_and_everything_it_started() {
        let mut f = fx();
        let info = f.start("sleep 300 & sleep 300 & echo started; wait").await;
        let _ = f.event().await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let v = f.table.kill("j1", Duration::from_secs(2)).await.expect("kill");
        assert_eq!(v.info.state, JobState::Killed);
        assert_eq!(v.info.state.outcome(), "killed");
        assert!(!alive(info.pid));
        let JobEvent::Settled { info, output, .. } = f.event().await else { panic!("Settled") };
        assert_eq!(info.state, JobState::Killed);
        assert_eq!(f.stored(&output.expect("stored")), "started\n");
        // The group is gone, not just its leader.
        // SAFETY: signal 0 only tests for existence.
        assert_ne!(unsafe { libc::kill(-i32::try_from(info.pid).expect("pid"), 0) }, 0);
        f.assert_quiet().await;
        // Killing it again is not an error.
        let v = f.table.kill("j1", Duration::from_millis(100)).await.expect("kill again");
        assert_eq!(v.info.state, JobState::Killed);
    }

    #[tokio::test]
    async fn kill_all_stops_every_running_job() {
        let mut f = fx();
        let mut pids = Vec::new();
        for _ in 0..3 {
            pids.push(f.start("sleep 300").await.pid);
        }
        f.start("exit 0").await;
        f.table.wait("j4", Duration::from_secs(20), &never()).await.expect("wait");
        f.table.kill_all(Duration::from_secs(2)).await;
        let list = f.table.list().await;
        let states: Vec<String> = list.iter().map(|i| i.state.outcome()).collect();
        assert_eq!(states, ["killed", "killed", "killed", "exit 0"]);
        assert!(pids.iter().all(|p| !alive(*p)));
        let mut settled = 0;
        let mut registered = 0;
        while let Ok(Some(e)) = tokio::time::timeout(Duration::from_millis(300), f.rx.recv()).await {
            match e {
                JobEvent::Registered(_) => registered += 1,
                JobEvent::Settled { .. } => settled += 1,
            }
        }
        assert_eq!((registered, settled), (4, 4));
    }

    #[tokio::test]
    async fn output_past_the_limit_kills_the_job() {
        let mut f = fx_with(2_000);
        let info = f.start("yes").await;
        let _ = f.event().await;
        let JobEvent::Settled { info: settled, output, detail } = f.event().await else { panic!("Settled") };
        assert_eq!(settled.state, JobState::Killed);
        assert!(detail.contains("limit of 2000 bytes"), "{detail}");
        assert!(output.is_some());
        assert!(!alive(info.pid));
        let v = f.table.peek("j1").await.expect("peek");
        assert_eq!(v.info.state, JobState::Killed);
        assert!(v.info.output_bytes > 2_000);
    }

    #[tokio::test]
    async fn unknown_ids_get_a_sentence_that_names_the_known_ones() {
        let f = fx();
        let e = f.table.peek("j9").await.expect_err("unknown");
        assert!(e.contains("no job `j9`") && e.contains("background"), "{e}");
        f.start("exit 0").await;
        f.start("exit 0").await;
        for e in [
            f.table.peek("j9").await.expect_err("unknown"),
            f.table.wait("j9", Duration::from_millis(1), &never()).await.expect_err("unknown"),
            f.table.kill("j9", Duration::from_millis(1)).await.expect_err("unknown"),
        ] {
            assert!(e.contains("`j9`") && e.contains("j1, j2"), "{e}");
        }
    }

    #[tokio::test]
    async fn ids_are_sequential_and_never_reused() {
        let f = fx();
        let (a, out, status) = f.table.allocate().await.expect("allocate");
        assert_eq!(a, "j1");
        assert!(out.ends_with("jobs/j1.out") && status.ends_with("jobs/j1.status"));
        assert_eq!(f.table.allocate().await.expect("allocate").0, "j2");
        f.table.resume_from(41).await;
        assert_eq!(f.table.allocate().await.expect("allocate").0, "j42");
        f.table.resume_from(3).await;
        assert_eq!(f.table.allocate().await.expect("allocate").0, "j43");
    }

    #[tokio::test]
    async fn list_is_in_id_order_with_state_and_size() {
        let f = fx();
        assert!(f.table.list().await.is_empty());
        f.start("echo abc").await;
        f.start("sleep 300").await;
        f.table.wait("j1", Duration::from_secs(20), &never()).await.expect("wait");
        let list = f.table.list().await;
        let ids: Vec<&str> = list.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(ids, ["j1", "j2"]);
        assert_eq!(list[0].state, JobState::Ended(Ended::Exit(0)));
        assert_eq!(list[0].output_bytes, 4);
        assert_eq!(list[1].state, JobState::Running);
        assert_eq!(list[1].command, "sleep 300");
        f.table.kill_all(Duration::from_millis(200)).await;
    }

    #[tokio::test]
    async fn dropping_the_table_kills_running_jobs() {
        let f = fx();
        let pid = f.start("sleep 300").await.pid;
        assert!(alive(pid));
        let Fx { table, .. } = f;
        drop(table);
        for _ in 0..200 {
            if !alive(pid) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("the job outlived its table");
    }
}
