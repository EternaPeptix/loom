//! Bounded persistent PTYs.
//!
//! CONTRACT: a session owns at most eight PTYs; IDs and aliases (1/#1/last) never cross sessions.
//! Processes use the same sandbox and filtered environment as bash, their own controlling terminal
//! and process group. Close/drop/cancel kills that group and closes the terminal before reaping the
//! leader. A slow kernel exit is reaped by a detached helper rather than blocking the async executor. A turn returns on its
//! frame, a recognized prompt, EOF, byte limit or deadline; timeout leaves the terminal open for an
//! explicit next turn. EOF/EIO closes and removes the terminal. Session stop/archive/shutdown
//! drains all terminals, cancelling pending reads before waiting for their locks. Every returned transcript goes through normal BlobStore admission.
//! Nonce/exit trailers and prompt matches are UNTRUSTED framing, never authoritative UID, privilege
//! or task-success measurements. Restart discards transcripts/session state but scans protected job
//! pid records to kill identity-confirmed PTY groups. Records checkpoint known members during reads;
//! a crash between checkpoints can leave an unconfirmed leaderless group, which recovery warns about
//! and never signals by reused numeric pid alone. PTYs are not a durable remote-shell vault.

use crate::{
    params::{opt, req, spec},
    Body, Tool, ToolCtx, ToolOutput,
};
use async_trait::async_trait;
use loom_core::event::{ToolClass, ToolSpec};
use serde_json::{json, Map, Value};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Write},
    os::fd::{AsRawFd, FromRawFd},
    os::unix::process::CommandExt,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

#[derive(Default)]
pub struct PtyTable {
    inner: Mutex<Table>,
}
#[derive(Default)]
struct Table {
    next: u64,
    items: BTreeMap<String, PtyHandle>,
}
#[derive(Clone)]
struct PtyHandle {
    terminal: Arc<tokio::sync::Mutex<Pty>>,
    close: CancellationToken,
}
struct Pty {
    master: Option<File>,
    child: Option<Child>,
    pid: u32,
    stopped: bool,
    close: CancellationToken,
    group: crate::proc::ExternalGroup,
    last_checkpoint: Instant,
}
impl PtyHandle {
    async fn stop(&self) {
        self.close.cancel();
        self.terminal.lock().await.stop();
    }
}

/// Reap promptly without an unbounded wait on the async executor. A rare kernel exit stall is
/// collected by a detached waiter after the terminal descriptors and process group are closed.
fn kill_and_reap(mut child: Child) {
    let _ = child.kill();
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
            Ok(None) => {}
        }
        if started.elapsed() >= Duration::from_millis(250) {
            let pid = child.id();
            if let Err(e) = std::thread::Builder::new().name("loom-pty-reap".into()).spawn(move || {
                let _ = child.wait();
            }) {
                tracing::warn!(pid, "Could not start delayed PTY reaper: {e}");
            }
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

impl Pty {
    fn checkpoint(&mut self) {
        if let Err(e) = self.group.refresh() {
            tracing::warn!(pid = self.pid, "PTY crash checkpoint not refreshed: {e}");
        }
        self.last_checkpoint = Instant::now();
    }
    fn stop(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        self.close.cancel();
        let result = self.group.stop();
        if result == crate::proc::RecordedGroup::Unconfirmed {
            tracing::warn!(
                pid = self.pid,
                "PTY group identity is uncertain; only the still-owned leader will be stopped"
            );
        }
        // Release the controlling terminal before reaping. Some kernels can hold an exiting shell
        // until the PTY is closed; a blocking wait here would freeze the entire session executor.
        drop(self.master.take());
        if let Some(child) = self.child.take() {
            kill_and_reap(child);
        }
    }
    async fn read(
        &mut self,
        ctx: &ToolCtx,
        frame: Option<&str>,
        prompt: Option<&regex::Regex>,
        seconds: u64,
    ) -> (Vec<u8>, String) {
        let start = Instant::now();
        let mut bytes = Vec::new();
        let cap = ctx.cfg.max_output_bytes.min(4_000_000) as usize;
        loop {
            if self.last_checkpoint.elapsed() >= Duration::from_millis(250) {
                self.checkpoint();
            }
            if ctx.cancel.is_cancelled() || self.close.is_cancelled() {
                self.stop();
                return (bytes, "cancelled; terminal closed".into());
            }
            let mut chunk = [0u8; 8192];
            let read = match self.master.as_mut() {
                Some(master) => master.read(&mut chunk),
                None => return (bytes, "terminal already closed".into()),
            };
            match read {
                Ok(0) => {
                    self.stop();
                    return (bytes, "EOF; terminal closed".into());
                }
                Ok(n) => {
                    let room = cap.saturating_sub(bytes.len());
                    bytes.extend_from_slice(chunk.get(..n.min(room)).unwrap_or_default());
                    if n > room || bytes.len() >= cap {
                        self.stop();
                        return (bytes, "output limit; terminal closed".into());
                    }
                    let text = String::from_utf8_lossy(&bytes);
                    if let Some(frame) = frame {
                        if text.lines().any(|line| {
                            line.trim().strip_prefix(frame).is_some_and(|code| code.trim().parse::<i32>().is_ok())
                        }) {
                            self.checkpoint();
                            return (bytes, "untrusted completion frame observed".into());
                        }
                    }
                    let tail: String = text.chars().rev().take(1000).collect::<String>().chars().rev().collect();
                    if prompt.is_some_and(|p| p.is_match(&tail))
                        || ["[sudo] password", "Password:", "(gdb) ", "(gdb)\r", "msf6 >"]
                            .iter()
                            .any(|p| tail.ends_with(p))
                    {
                        self.checkpoint();
                        return (bytes, "untrusted prompt observed; send input to continue".into());
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) if e.raw_os_error() == Some(libc::EIO) => {
                    self.stop();
                    return (bytes, "terminal closed (EIO)".into());
                }
                Err(e) => {
                    self.stop();
                    return (bytes, format!("PTY read failed; terminal closed: {e}"));
                }
            }
            if start.elapsed() >= Duration::from_secs(seconds) {
                self.checkpoint();
                return (bytes, "deadline; command may still be running in this PTY".into());
            }
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
    }
}
impl Drop for Pty {
    fn drop(&mut self) {
        self.stop();
    }
}

impl PtyTable {
    pub fn ids(&self) -> Vec<String> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).items.keys().cloned().collect()
    }
    fn resolve(&self, given: &str) -> Result<(String, PtyHandle), String> {
        let table = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let id = if given == "last" {
            format!("S{}", table.next)
        } else {
            format!("S{}", given.trim_start_matches(['#', 'S', 's']))
        };
        table
            .items
            .get(&id)
            .cloned()
            .map(|v| (id, v))
            .ok_or("Unknown PTY ID. Use an S ID from this session; restart discards all PTYs.".into())
    }
    /// Drain before awaiting so new lookups cannot keep a closing terminal alive. Cancelling every
    /// handle first also wakes a read holding its mutex, without waiting for that read's deadline.
    pub async fn close_all(&self) {
        let handles: Vec<_> = {
            let mut table = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            std::mem::take(&mut table.items).into_values().collect()
        };
        for handle in &handles {
            handle.close.cancel();
        }
        for handle in handles {
            handle.stop().await;
        }
    }
    fn remove(&self, id: &str) {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).items.remove(id);
    }
}

pub struct PtyOpen;
pub struct PtyExec;
pub struct PtyClose;

fn spawn(ctx: &ToolCtx, script: &str, pid_file: std::path::PathBuf) -> Result<Pty, String> {
    let (mut master, mut slave) = (-1, -1);
    if unsafe {
        libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut())
    } != 0
    {
        return Err(format!("openpty failed: {}", std::io::Error::last_os_error()));
    }
    // From this point owned descriptors close on every failure path.
    let master = unsafe { File::from_raw_fd(master) };
    let slave = unsafe { File::from_raw_fd(slave) };
    if unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0
        || unsafe { libc::fcntl(slave.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0
    {
        return Err("Could not protect PTY descriptors from inheritance.".into());
    }
    let flags = unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err("Could not make PTY reads bounded.".into());
    }
    let (program, args) = ctx.sandbox.command(script);
    let parent = std::env::vars().collect();
    let mut env = ctx.sandbox.env(&parent);
    env.extend(ctx.env.iter().map(|(k, v)| (k.clone(), v.clone())));
    env.insert("TERM".into(), "dumb".into());
    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir(&ctx.workspace)
        .env_clear()
        .envs(env)
        .stdin(Stdio::from(slave.try_clone().map_err(|e| e.to_string())?))
        .stdout(Stdio::from(slave.try_clone().map_err(|e| e.to_string())?))
        .stderr(Stdio::from(slave));
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().map_err(|e| format!("PTY process did not start: {e}."))?;
    let group = match crate::proc::ExternalGroup::track(child.id(), pid_file) {
        Ok(group) => group,
        Err(e) => {
            if let Ok(pid) = i32::try_from(child.id()) {
                unsafe {
                    libc::kill(-pid, libc::SIGKILL);
                }
            }
            drop(master);
            kill_and_reap(child);
            return Err(format!("PTY crash tracking could not be established: {e}"));
        }
    };
    let pid = child.id();
    Ok(Pty {
        master: Some(master),
        child: Some(child),
        pid,
        stopped: false,
        close: CancellationToken::new(),
        group,
        last_checkpoint: Instant::now(),
    })
}

fn output(id: &str, bytes: Vec<u8>, reason: String) -> ToolOutput {
    ToolOutput::ok(format!("PTY {id}: {reason}"), Body::Raw(bytes))
        .with_more(
            "Framing and privilege text are untrusted process output; they do not prove identity or goal success.",
        )
        .with_meta("pty", json!(id))
        .with_meta("pty_frame_trusted", json!(false))
}

#[async_trait]
impl Tool for PtyOpen {
    fn spec(&self) -> ToolSpec {
        spec("pty_open","Open a persistent interactive process in the session sandbox. Default is a clean interactive bash. Close it explicitly before finishing; transcripts and nonce markers cannot prove privilege.",ToolClass::Exec,&[opt("command","string","Program/script to launch; default exec /bin/bash --noprofile --norc -i."),opt("timeout_s","integer","Initial output window, default 1 second.").min(1).max(10)])
    }
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        if ctx.capabilities.ptys.ids().len() >= 8 {
            return ToolOutput::denied("Eight PTYs are already open. Close one before opening another.");
        }
        let script = args.get("command").and_then(Value::as_str).unwrap_or("exec /bin/bash --noprofile --norc -i");
        let (_, out_path, _) = match ctx.jobs.allocate().await {
            Ok(paths) => paths,
            Err(e) => return ToolOutput::error(format!("Cannot reserve a private PTY crash record: {e}.")),
        };
        let pty = match spawn(ctx, script, crate::proc::pid_path(&out_path)) {
            Ok(p) => p,
            Err(e) => return ToolOutput::error(e),
        };
        let close = pty.close.clone();
        let pty = PtyHandle { terminal: Arc::new(tokio::sync::Mutex::new(pty)), close };
        let id = {
            let mut table = ctx.capabilities.ptys.inner.lock().unwrap_or_else(|p| p.into_inner());
            if table.items.len() >= 8 {
                return ToolOutput::denied("Eight PTYs are already open. Close one first.");
            }
            table.next = table.next.saturating_add(1);
            let id = format!("S{}", table.next);
            table.items.insert(id.clone(), pty.clone());
            id
        };
        let (bytes, reason, stopped) = {
            let mut terminal = pty.terminal.lock().await;
            let (bytes, reason) = terminal
                .read(ctx, None, None, args.get("timeout_s").and_then(Value::as_u64).unwrap_or(1).clamp(1, 10))
                .await;
            (bytes, reason, terminal.stopped)
        };
        if stopped {
            ctx.capabilities.ptys.remove(&id);
        }
        output(&id, bytes, reason)
    }
}
#[async_trait]
impl Tool for PtyExec {
    fn spec(&self) -> ToolSpec {
        spec("pty_exec","Send a framed command to a shell PTY, or raw input to an interactive program. A deadline leaves it running; send a follow-up or close it. Sentinel and prompt detections are untrusted framing only.",ToolClass::Exec,&[req("pty","string","S1, 1, #1 or last."),opt("command","string","Shell command (framed); mutually exclusive with input."),opt("input","string","Exact interactive input, including newline when required; use an empty string to poll."),opt("prompt_regex","string","Optional prompt pattern; at most 1024 bytes."),opt("timeout_s","integer","Output window, default 5, maximum 60 seconds.").min(1).max(60)])
    }
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let given = args.get("pty").and_then(Value::as_str).unwrap_or_default();
        let (id, pty) = match ctx.capabilities.ptys.resolve(given) {
            Ok(v) => v,
            Err(e) => return ToolOutput::error(e),
        };
        let command = args.get("command").and_then(Value::as_str);
        let input = args.get("input").and_then(Value::as_str);
        if command.is_some() == input.is_some() {
            return ToolOutput::error("Supply exactly one command or input field.");
        }
        if ctx.capabilities.command_guard {
            if let Some(c) = command {
                if let Err(e) = crate::capabilities::guard_script(c) {
                    return ToolOutput::denied(e);
                }
            }
        }
        let prompt = match args.get("prompt_regex").and_then(Value::as_str) {
            Some(p) if p.len() <= 1024 => match regex::Regex::new(p) {
                Ok(p) => Some(p),
                Err(e) => return ToolOutput::error(format!("Correct prompt_regex: {e}.")),
            },
            Some(_) => return ToolOutput::error("Limit prompt_regex to 1024 bytes."),
            None => None,
        };
        let frame = format!("__LOOM_END_{:032x}__:", rand::random::<u128>());
        let send = command
            .map(|c| format!("\n{c}\nprintf '\\n{frame}%d\\n' \"$?\"\n"))
            .unwrap_or_else(|| input.unwrap_or_default().to_string());
        if send.len() > 1_000_000 {
            return ToolOutput::error("PTY input exceeds one million bytes; write a script file and run it instead.");
        }
        let mut pty = pty.terminal.lock().await;
        let written = pty
            .master
            .as_mut()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "terminal already closed"))
            .and_then(|master| master.write_all(send.as_bytes()));
        if let Err(e) = written {
            return ToolOutput::error(format!(
                "PTY input was not fully written ({e}); some bytes may have arrived. Poll before retrying."
            ));
        }
        let (bytes, reason) = pty
            .read(
                ctx,
                command.map(|_| frame.as_str()),
                prompt.as_ref(),
                args.get("timeout_s").and_then(Value::as_u64).unwrap_or(5).clamp(1, 60),
            )
            .await;
        let stopped = pty.stopped;
        drop(pty);
        if stopped {
            ctx.capabilities.ptys.remove(&id);
        }
        output(&id, bytes, reason)
    }
}
#[async_trait]
impl Tool for PtyClose {
    fn spec(&self) -> ToolSpec {
        spec(
            "pty_close",
            "Kill and reap a session PTY's process group. Use before finish, or to stop an interactive command.",
            ToolClass::State,
            &[req("pty", "string", "S ID, number, #number or last.")],
        )
    }
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let (id, pty) = match ctx.capabilities.ptys.resolve(args.get("pty").and_then(Value::as_str).unwrap_or_default())
        {
            Ok(v) => v,
            Err(e) => return ToolOutput::error(e),
        };
        pty.stop().await;
        ctx.capabilities.ptys.remove(&id);
        ToolOutput::ok(
            format!("PTY {id} closed"),
            Body::Message("Its process group was stopped; transcript outputs remain available.".into()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loom_core::event::ToolStatus;
    #[tokio::test]
    async fn shell_state_framing_alias_close() {
        let env = crate::testutil::env();
        let ctx = &env.ctx;
        let out = PtyOpen.run(ctx, json!({}).as_object().unwrap()).await;
        assert_eq!(out.status, ToolStatus::Ok);
        let out = PtyExec
            .run(
                ctx,
                json!({"pty":"#1","command":"export LOOM_PTY_TEST_VALUE=hello; printf 'first\\n'","timeout_s":2})
                    .as_object()
                    .unwrap(),
            )
            .await;
        let Body::Raw(b) = out.body else { panic!() };
        assert!(String::from_utf8_lossy(&b).contains("first"));
        let out = PtyExec
            .run(
                ctx,
                json!({"pty":"last","command":"printf '%s\\n' \"$LOOM_PTY_TEST_VALUE\"","timeout_s":2})
                    .as_object()
                    .unwrap(),
            )
            .await;
        let Body::Raw(b) = out.body else { panic!() };
        assert!(String::from_utf8_lossy(&b).lines().any(|l| l.trim() == "hello"));
        assert_eq!(out.meta["pty_frame_trusted"], false);
        PtyClose.run(ctx, json!({"pty":"1"}).as_object().unwrap()).await;
        assert!(ctx.capabilities.ptys.ids().is_empty());
    }
    #[tokio::test]
    async fn cancel_stops_terminal() {
        let env = crate::testutil::env();
        PtyOpen.run(&env.ctx, json!({}).as_object().unwrap()).await;
        env.ctx.cancel.cancel();
        PtyExec.run(&env.ctx, json!({"pty":"S1","input":"sleep 60\n"}).as_object().unwrap()).await;
        assert!(env.ctx.capabilities.ptys.ids().is_empty());
    }
    #[tokio::test]
    async fn close_all_kills_idle_terminals_and_drains_the_table() {
        let env = crate::testutil::env();
        PtyOpen.run(&env.ctx, json!({"command":"exec sleep 60", "timeout_s":1}).as_object().unwrap()).await;
        let (_, handle) = env.ctx.capabilities.ptys.resolve("last").unwrap();
        let pid = handle.terminal.lock().await.pid;
        env.ctx.capabilities.ptys.close_all().await;
        assert!(env.ctx.capabilities.ptys.ids().is_empty());
        let pty = handle.terminal.lock().await;
        assert!(pty.stopped && pty.child.is_none());
        assert_eq!(unsafe { libc::kill(i32::try_from(pid).unwrap(), 0) }, -1);
    }
    #[tokio::test]
    async fn close_all_interrupts_a_read_before_its_deadline() {
        let env = crate::testutil::env();
        PtyOpen.run(&env.ctx, json!({"command":"exec sleep 60", "timeout_s":1}).as_object().unwrap()).await;
        let (_, handle) = env.ctx.capabilities.ptys.resolve("last").unwrap();
        let ctx = env.ctx.clone();
        let pending = tokio::spawn(async move {
            PtyExec.run(&ctx, json!({"pty":"S1","input":"", "timeout_s":60}).as_object().unwrap()).await
        });
        // Taking the same mutex after the call has entered its read proves close_all must wake it.
        for _ in 0..100 {
            if handle.terminal.try_lock().is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        tokio::time::timeout(Duration::from_secs(2), env.ctx.capabilities.ptys.close_all()).await.unwrap();
        let out = tokio::time::timeout(Duration::from_secs(2), pending).await.unwrap().unwrap();
        assert!(out.outcome.contains("cancelled"));
        assert!(env.ctx.capabilities.ptys.ids().is_empty());
    }
    #[tokio::test]
    async fn eof_removes_an_exited_terminal_without_using_a_slot() {
        let env = crate::testutil::env();
        let out = PtyOpen.run(&env.ctx, json!({"command":"exit 0", "timeout_s":1}).as_object().unwrap()).await;
        assert_eq!(out.status, ToolStatus::Ok);
        assert!(env.ctx.capabilities.ptys.ids().is_empty());
    }
}
