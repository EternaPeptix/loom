//! `box_exec`, `box_get`, `box_reset`: what a session can do with its mission's box.
//!
//! CONTRACT.
//!
//! The box is a container on a Docker host that the operator configured (`[box]`, see
//! `loom_tools::boxctl`). These three tools are the only way a session reaches it, and none of them gives
//! the session anything of Docker: the daemon runs the docker command line client with arguments that loom
//! builds, and the session's text is only ever the script that `/bin/bash -c` in the container runs. The
//! box is asked for through `Orchestrator::box_access`, which is where the runtime answers for the
//! session's mission.
//!
//! ## `box_exec` {command, timeout_s, background, wake_on, wake_every_s, idle_timeout_s, cwd}
//! Class `Exec` (counts toward `max_exec_calls`; refused in wrap-up like `bash`).
//! 1. Without `command`: an error sentence. Without a configured box: the error `No box is configured. The
//!    operator sets [box] in config.toml.` In a session that works in its own copy of the workspace:
//!    `box_exec is not available in an agent copy yet; work in the shared workspace.`
//! 2. `cwd` is relative to `/work` and cannot leave it (an error sentence otherwise).
//! 3. The box is made when there is no running container (network, egress rules, container; an error
//!    sentence when the Docker host cannot do it), then the workspace files that changed since the last call
//!    are copied into `/work` (`MissionBox::push`: only files the session could read itself, I6).
//! 4. The command runs through `loom_tools::bash::run_launched`: the same procedure, limits, jobs,
//!    `background`, `wake_on`, `job_wait` and `job_kill` as `bash`. Its result is `bash`'s, with the fact
//!    `in box loom-<id>` first, then the usual facts, then notes: files the copy left out, and once per
//!    session the one-sentence note that wildcard grants are not applied to the box.
//!
//! ## `box_get` {path, to}
//! Class `Write`. `path` is a file or directory in the box (absolute, or relative to `/work`); `to` is where
//! it goes in the workspace (default: its own name, in the workspace). The box's tar stream is unpacked by
//! `boxfs::extract` (I7): regular files and directories only, nothing outside `to`, `get_max_mb` and
//! 10,000 entries at most, every file written by the path of the `write` tool. An error sentence says
//! what refused it and that nothing was written. Without a running box: an error that says to start one
//! with `box_exec`. Result: outcome `fetched {n} file(s)`, facts `{bytes} bytes`, the path, body the list
//! of files (at most 20). Meta `META_PATH` is the destination.
//!
//! ## `box_reset` {}
//! Class `Exec`. Removes the container and makes a new one: everything in `/work` and `/tmp` is lost (the
//! outcome says so); the next `box_exec` copies the workspace files again.
//!
//! Tests required: each error sentence; the whole path of a command (fake docker, the result's header and
//! the verbatim script); files copied before the call and not again when unchanged; the wildcard note once;
//! `box_get` of a file and of a tree, and a hostile stream refused; `box_reset`; the wrap-up refusal and the
//! exec class (in `session`); refusal in an agent copy and without a box (in `runtime`).

use super::Shared;
use async_trait::async_trait;
use loom_core::event::{ToolClass, ToolSpec, META_PATH};
use loom_tools::boxctl::MissionBox;
use loom_tools::boxfs::{self, GetLimits};
use loom_tools::{params, Body, Tool, ToolCtx, ToolOutput};
use serde_json::{json, Map, Value};
use std::sync::Arc;

/// What the tools answer when the operator has not enabled a box.
pub const NO_BOX: &str = "No box is configured. The operator sets [box] in config.toml.";
/// What `box_exec` and the others answer in a session that works in its own copy of the workspace.
pub const BOX_IN_COPY: &str = "box_exec is not available in an agent copy yet; work in the shared workspace.";
/// What the tools answer after the mission was stopped, ended or archived, until it is resumed.
pub use loom_tools::boxctl::BOX_CLOSED;

/// Most files `box_get` lists in its result.
const LISTED: usize = 20;

pub struct BoxExec(pub Arc<Shared>);
pub struct BoxGet(pub Arc<Shared>);
pub struct BoxReset(pub Arc<Shared>);

fn with_box(mut out: ToolOutput, b: &MissionBox) -> ToolOutput {
    out.more.insert(0, format!("in box {}", b.names().container));
    out
}

#[async_trait]
impl Tool for BoxExec {
    fn spec(&self) -> ToolSpec {
        params::spec(
            "box_exec",
            "Run a shell command with bash inside this mission's box: a container on a separate Linux host that is yours to use freely and that can reach the hosts that were granted to the mission, including raw TCP, which `bash` cannot. stdout and stderr are captured together in the order they were written; the result is shown as for `bash` (start and end of a long output, `out_read` and `out_grep` for the rest). Before each call the files of the workspace that changed are copied into `/work`, the directory the command starts in; files the command creates there stay in the box (use box_get to bring one back to the workspace) and are lost when the box is reset. Each call starts a new shell, so `cd` and variables do not carry over. The box has no other network access than the granted hosts and addresses; it runs as an unprivileged user.",
            ToolClass::Exec,
            &[
                params::req("command", "string", "The command line to run in the box."),
                params::opt("timeout_s", "integer", "Stop the command if it has not finished after this many seconds. Leave it out to let the command run as long as it needs.").min(1),
                params::opt("background", "boolean", "Start the command as a background job and return immediately (default false). Use for servers and long runs; read its output with job_wait."),
                params::opt("cwd", "string", "Directory to run in, relative to /work (default: /work)."),
                params::opt("idle_timeout_s", "integer", "Stop a foreground command after this many seconds without output. Silent computation can also trigger it; omitted means no idle watchdog.").min(1).max(300),
                params::opt("wake_on", "string", "For a background job: a regular expression. When a line of the job's output matches it you are told at once, with the matching lines and the handle of that part of the output, and if you had ended your turn with `wait` you are resumed, as when a job ends. Use it for a fuzzer, cracker, scan or listener that runs for hours and matters only when it finds something, e.g. `(?i)crash|panic|FOUND`. Rust regex syntax, matched line by line."),
                params::opt("wake_every_s", "integer", "With `wake_on`: tell you at most once in this many seconds; lines that match in between come with the next notice (default 30).").min(1).max(3600),
            ],
        )
    }

    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let Some(command) = args.get("command").and_then(Value::as_str) else {
            return ToolOutput::error(
                "No command was given. Call box_exec again with `command` set to the command line to run.",
            );
        };
        let b = match self.0.orch.box_access(&ctx.session).await {
            Ok(b) => b,
            Err(e) => return ToolOutput::error(e),
        };
        let cwd = args.get("cwd").and_then(Value::as_str);
        let launch = match b.launch(ctx.call_id.as_str(), cwd, command) {
            Ok(l) => l,
            Err(e) => return ToolOutput::error(e),
        };
        if let Err(e) = b.ready().await {
            return ToolOutput::error(format!("The box could not be made ready, so nothing was run. {e}"));
        }
        let pushed = match b.push(ctx.sandbox.clone(), ctx.workspace.clone()).await {
            Ok(p) => p,
            Err(e) => {
                return ToolOutput::error(format!(
                    "The workspace could not be copied into the box, so nothing was run. {e}"
                ))
            }
        };
        let mut out = loom_tools::bash::run_launched(ctx, args, &launch).await;
        out = with_box(out, &b);
        if pushed.files > 0 {
            out = out.with_more(format!("{} file(s) copied into /work first", pushed.files));
        }
        for note in pushed.notes {
            out = out.with_more(note);
        }
        if let Some(line) = pending_hosts_line(&b.pending_hosts().await) {
            out = out.with_more(line);
        }
        if let Some(notice) = b.take_notice(ctx.session.as_str()) {
            out = out.with_more(notice);
        }
        out
    }
}

/// The line under a `box_exec` result while names granted after the box was made are not yet in its
/// `/etc/hosts`: their addresses are reachable (the rules are current), their names resolve after `box_reset`.
pub(crate) fn pending_hosts_line(pending: &[(String, Vec<std::net::Ipv4Addr>)]) -> Option<String> {
    if pending.is_empty() {
        return None;
    }
    let names: Vec<String> = pending
        .iter()
        .map(|(name, ips)| format!("{name} ({})", ips.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")))
        .collect();
    Some(format!(
        "Not resolvable inside the box until box_reset: {}. Their addresses are reachable now.",
        names.join("; ")
    ))
}

/// A path of `box_get` (`which` names the parameter) with a `.` or `..` component is refused: the box's own
/// path rules and the workspace's are not to be played against each other.
fn plain_components(which: &str, given: &str) -> Result<(), String> {
    match given.split('/').find(|part| matches!(*part, "." | "..")) {
        Some(part) => Err(format!(
            "`{which}` contains a `{part}` component ({given}). Give a path without `.` and `..`: absolute, or relative to {}.",
            if which == "path" { "/work in the box" } else { "the workspace" }
        )),
        None => Ok(()),
    }
}

/// The path in the container: relative paths start at `/work`; a trailing `/` is dropped.
fn container_path(given: &str) -> Result<String, String> {
    let g = given.trim();
    if g.is_empty() || g.contains('\0') || g.chars().any(char::is_control) {
        return Err("Give the path of a file or directory in the box, absolute or relative to /work.".to_string());
    }
    plain_components("path", g)?;
    let mut p = if g.starts_with('/') { g.to_string() } else { format!("{}/{g}", loom_tools::boxctl::WORK) };
    while p.len() > 1 && p.ends_with('/') {
        p.truncate(p.len() - 1);
    }
    if p == "/" || p.is_empty() {
        return Err("Name a file or directory below `/`; the whole box root cannot be fetched.".to_string());
    }
    Ok(p)
}

#[async_trait]
impl Tool for BoxGet {
    fn spec(&self) -> ToolSpec {
        params::spec(
            "box_get",
            "Bring a file or directory from the box into the workspace. Only regular files and directories come back (no links, devices or special files), at most the operator's size limit, and every file is written the way the `write` tool writes it: it cannot go where `write` cannot. Use it for results (a dump, a built binary, a captured file) that you want to read or edit with the other tools.",
            ToolClass::Write,
            &[
                params::req("path", "string", "The file or directory in the box: absolute, or relative to /work."),
                params::opt("to", "string", "Where it goes in the workspace: the file or directory that results (default: its own name, in the workspace)."),
            ],
        )
    }

    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let Some(given) = args.get("path").and_then(Value::as_str) else {
            return ToolOutput::error(
                "No path was given. Call box_get again with `path` set to a file or directory in the box.",
            );
        };
        let b = match self.0.orch.box_access(&ctx.session).await {
            Ok(b) => b,
            Err(e) => return ToolOutput::error(e),
        };
        let path = match container_path(given) {
            Ok(p) => p,
            Err(e) => return ToolOutput::error(e),
        };
        let name = path.rsplit('/').next().unwrap_or_default().to_string();
        let to = match args.get("to").and_then(Value::as_str).map(str::trim).filter(|t| !t.is_empty()) {
            Some(t) => {
                if let Err(e) = plain_components("to", t) {
                    return ToolOutput::error(e);
                }
                ctx.sandbox.resolve(t)
            }
            None => ctx.workspace.join(&name),
        };
        if !b.running().await {
            return ToolOutput::error("There is no running box for this mission, so there is nothing to fetch. box_exec starts one (files in /work live only while it runs).");
        }
        let cfg = b.cfg();
        let max = cfg.get_max_mb.saturating_mul(1 << 20);
        // Room for tar headers and padding beyond the file data the cap allows.
        let wire = usize::try_from(max.saturating_add(16 << 20)).unwrap_or(usize::MAX);
        let tar = match b.get_tar(&path, wire).await {
            Ok(t) => t,
            Err(e) => return with_box(ToolOutput::error(e), &b),
        };
        let sandbox = ctx.sandbox.clone();
        let dest = to.clone();
        let lim = GetLimits { total: max, entries: boxfs::MAX_ENTRIES };
        let unpacked = tokio::task::spawn_blocking(move || boxfs::extract(&sandbox, &dest, &tar, lim)).await;
        let out = match unpacked {
            Ok(Ok(done)) => {
                let shown: Vec<String> = done.files.iter().take(LISTED).map(|p| p.display().to_string()).collect();
                let more = done.files.len().saturating_sub(shown.len());
                let mut body = if shown.is_empty() {
                    format!("{path} holds no file, only {} empty director(ies); nothing was written.", done.dirs)
                } else {
                    shown.join("\n")
                };
                if more > 0 {
                    body.push_str(&format!("\n… and {more} more"));
                }
                ToolOutput::ok(format!("fetched {} file(s)", done.files.len()), Body::Message(body))
                    .with_more(format!("{} bytes", done.bytes))
                    .with_more(format!("from {path} in the box"))
            }
            Ok(Err(e)) => {
                if e.contains("is protected") || e.contains("off limits") || e.contains("outside the writable") {
                    ToolOutput::denied(e)
                } else {
                    ToolOutput::error(e)
                }
            }
            Err(e) => ToolOutput::error(format!("The files could not be unpacked ({e}). Nothing was changed that you can rely on; check the destination and try again.")),
        };
        with_box(out, &b).with_meta(META_PATH, json!(to.display().to_string()))
    }
}

#[async_trait]
impl Tool for BoxReset {
    fn spec(&self) -> ToolSpec {
        params::spec(
            "box_reset",
            "Remove this mission's box and make a fresh one. Everything the box holds (the files in /work and /tmp, installed tools, running jobs of the box) is lost; the workspace files are copied in again by the next box_exec. Use it when the box is broken or full.",
            ToolClass::Exec,
            &[],
        )
    }

    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let _ = args;
        let b = match self.0.orch.box_access(&ctx.session).await {
            Ok(b) => b,
            Err(e) => return ToolOutput::error(e),
        };
        match b.reset().await {
            Ok(()) => with_box(
                ToolOutput::ok(
                    "reset",
                    Body::Message(
                        "The box was removed and made again. Everything that was in /work and /tmp is gone, and so are commands that were running in it; the next box_exec copies the workspace files in again."
                            .to_string(),
                    ),
                ),
                &b,
            ),
            Err(e) => with_box(ToolOutput::error(format!("The box could not be reset. {e}")), &b),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtools::testkit::{box_rig, Rig};
    use loom_core::event::ToolStatus;
    use loom_net::policy::Policy;
    use loom_tools::boxctl::fake::FakeDocker;
    use loom_tools::boxctl::EgressSource;

    fn source(grants: &[&str]) -> EgressSource {
        let g: Vec<String> = grants.iter().map(|s| s.to_string()).collect();
        Arc::new(move || {
            Ok((g.clone(), Policy::new(&loom_core::config::NetworkCfg::default()).map_err(|e| e.to_string())?))
        })
    }

    fn with_box(grants: &[&str]) -> (Rig, FakeDocker, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let fake = FakeDocker::new(dir.path());
        let rig = box_rig();
        let b = MissionBox::new(fake.host(), "m-test", source(grants));
        *rig.orch.boxed.lock().unwrap() = Some(Ok(b));
        (rig, fake, dir)
    }

    fn header(r: &loom_core::event::ToolResult) -> &str {
        r.text.lines().next().unwrap_or_default()
    }

    #[tokio::test]
    async fn without_a_configured_box_every_tool_says_so() {
        let rig = box_rig();
        for (tool, args) in
            [("box_exec", json!({"command": "id"})), ("box_get", json!({"path": "x"})), ("box_reset", json!({}))]
        {
            let r = rig.call(tool, args).await;
            assert_eq!(r.status, ToolStatus::Error, "{tool}");
            assert!(r.text.contains("No box is configured. The operator sets [box] in config.toml."), "{}", r.text);
        }
        // In an agent copy.
        *rig.orch.boxed.lock().unwrap() = Some(Err(BOX_IN_COPY.to_string()));
        let r = rig.call("box_exec", json!({"command": "id"})).await;
        assert!(
            r.text.contains("box_exec is not available in an agent copy yet; work in the shared workspace."),
            "{}",
            r.text
        );
        // A call without its argument.
        assert!(rig.call("box_exec", json!({})).await.text.contains("command"));
    }

    #[tokio::test]
    async fn box_exec_copies_changed_files_runs_the_script_verbatim_and_names_the_box() {
        let (rig, fake, _d) = with_box(&[]);
        std::fs::write(rig.env.ctx.workspace.join("a.txt"), "alpha").unwrap();
        let script = "echo '; docker ps; '; echo $((6*7)); echo --privileged";
        let r = rig.call("box_exec", json!({"command": script, "timeout_s": 20})).await;
        assert_eq!(r.status, ToolStatus::Ok, "{}", r.text);
        assert!(header(&r).starts_with("[box_exec · exit 0 · in box loom-m-test"), "{}", header(&r));
        assert!(r.text.contains("; docker ps; \n42\n--privileged"), "{}", r.text);
        assert!(r.text.contains("1 file(s) copied into /work first"), "{}", r.text);
        // The file went in as a tar stream, once; the script was one argument of exactly one docker call.
        let tars: Vec<_> = std::fs::read_dir(&fake.dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with("cp-in."))
            .collect();
        assert_eq!(tars.len(), 1);
        assert!(String::from_utf8_lossy(&std::fs::read(tars[0].path()).unwrap()).contains("a.txt"));
        assert_eq!(fake.calls().iter().filter(|c| c.iter().any(|a| a == script)).count(), 1);
        // Nothing changed: nothing is copied again.
        let r = rig.call("box_exec", json!({"command": "true", "timeout_s": 20})).await;
        assert!(!r.text.contains("copied into /work"), "{}", r.text);
        assert_eq!(
            std::fs::read_dir(&fake.dir)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|e| e.file_name().to_string_lossy().starts_with("cp-in."))
                .count(),
            1
        );
        // A change is.
        std::fs::write(rig.env.ctx.workspace.join("a.txt"), "alpha two").unwrap();
        let r = rig.call("box_exec", json!({"command": "true", "timeout_s": 20})).await;
        assert!(r.text.contains("1 file(s) copied into /work first"), "{}", r.text);
        // The directory cannot leave /work.
        let r = rig.call("box_exec", json!({"command": "true", "cwd": "../etc"})).await;
        assert_eq!(r.status, ToolStatus::Error);
        assert!(r.text.contains("relative to /work"), "{}", r.text);
    }

    #[tokio::test]
    async fn the_wildcard_note_is_given_once_per_session() {
        let (rig, _fake, _d) = with_box(&["*.wild.test", "203.0.113.9"]);
        let first = rig.call("box_exec", json!({"command": "true", "timeout_s": 20})).await;
        assert!(first.text.contains("these wildcard grants are not applied to it: *.wild.test"), "{}", first.text);
        let second = rig.call("box_exec", json!({"command": "true", "timeout_s": 20})).await;
        assert!(!second.text.contains("wildcard"), "{}", second.text);
    }

    #[tokio::test]
    async fn a_name_granted_after_the_box_exists_is_flagged_in_box_exec_until_box_reset() {
        let dir = tempfile::tempdir().unwrap();
        let fake = FakeDocker::new(dir.path());
        let rig = box_rig();
        let grants = Arc::new(std::sync::Mutex::new(vec!["203.0.113.9".to_string()]));
        let g = grants.clone();
        let source: EgressSource = Arc::new(move || {
            let cfg = loom_core::config::NetworkCfg { allow_private: vec!["127.0.0.0/8".into()], ..Default::default() };
            Ok((g.lock().unwrap().clone(), Policy::new(&cfg).map_err(|e| e.to_string())?))
        });
        let b = MissionBox::new(fake.host(), "m-test", source);
        *rig.orch.boxed.lock().unwrap() = Some(Ok(b.clone()));
        let r = rig.call("box_exec", json!({"command": "true", "timeout_s": 20})).await;
        assert!(!r.text.contains("Not resolvable"), "{}", r.text);
        grants.lock().unwrap().push("localhost".to_string());
        b.resync().await;
        let line =
            "Not resolvable inside the box until box_reset: localhost (127.0.0.1). Their addresses are reachable now.";
        for _ in 0..2 {
            let r = rig.call("box_exec", json!({"command": "true", "timeout_s": 20})).await;
            assert_eq!(r.text.matches(line).count(), 1, "{}", r.text);
        }
        let r = rig.call("box_reset", json!({})).await;
        assert_eq!(r.status, ToolStatus::Ok, "{}", r.text);
        let r = rig.call("box_exec", json!({"command": "true", "timeout_s": 20})).await;
        assert!(!r.text.contains("Not resolvable"), "{}", r.text);
        assert!(fake.sub("run").last().unwrap().windows(2).any(|w| w == ["--add-host", "localhost:127.0.0.1"]));
    }

    #[test]
    fn the_pending_line_lists_each_name_with_its_addresses() {
        assert_eq!(pending_hosts_line(&[]), None);
        let ip = |s: &str| s.parse::<std::net::Ipv4Addr>().unwrap();
        assert_eq!(
            pending_hosts_line(&[
                ("a.test".into(), vec![ip("203.0.113.5"), ip("203.0.113.6")]),
                ("b.test".into(), vec![ip("198.51.100.9")])
            ])
            .unwrap(),
            "Not resolvable inside the box until box_reset: a.test (203.0.113.5, 203.0.113.6); b.test (198.51.100.9). Their addresses are reachable now."
        );
    }

    #[tokio::test]
    async fn a_box_job_runs_in_the_background_and_is_followed_with_the_job_tools() {
        let (rig, _fake, _d) = with_box(&[]);
        let r = rig
            .call("box_exec", json!({"command": "echo started; sleep 1; echo done-marker", "background": true}))
            .await;
        assert!(r.text.contains("started as job j1"), "{}", r.text);
        let w = rig.call("job_wait", json!({"job": "j1", "timeout_s": 20})).await;
        assert!(w.text.contains("done-marker") && w.text.contains("exit 0"), "{}", w.text);
    }

    #[tokio::test]
    async fn box_get_brings_back_a_tree_through_the_write_path_and_refuses_what_write_would() {
        let (rig, fake, _d) = with_box(&[]);
        rig.call("box_exec", json!({"command": "true", "timeout_s": 20})).await;
        let mut tar = Vec::new();
        loom_tools::boxfs::append_file(&mut tar, "out/a.txt", 0o644, 0, b"A");
        loom_tools::boxfs::append_file(&mut tar, "out/sub/b.bin", 0o755, 0, &[0, 1, 2]);
        loom_tools::boxfs::finish_tar(&mut tar);
        std::fs::write(fake.dir.join("cp-out.tar"), &tar).unwrap();
        let r = rig.call("box_get", json!({"path": "out", "to": "got"})).await;
        assert_eq!(r.status, ToolStatus::Ok, "{}", r.text);
        assert!(r.text.contains("fetched 2 file(s)") && r.text.contains("in box loom-m-test"), "{}", r.text);
        let ws = &rig.env.ctx.workspace;
        assert_eq!(std::fs::read(ws.join("got/a.txt")).unwrap(), b"A");
        assert_eq!(std::fs::read(ws.join("got/sub/b.bin")).unwrap(), [0, 1, 2]);
        // The call asked docker for exactly `<container>:/work/out`.
        assert!(fake.sub("cp").iter().any(|c| c.iter().any(|a| a == "loom-m-test:/work/out")));
        // Where `write` is refused, so is `box_get`.
        let r = rig.call("box_get", json!({"path": "out", "to": ".loom/oracle"})).await;
        assert_eq!(r.status, ToolStatus::Denied, "{}", r.text);
        assert!(!ws.join(".loom/oracle").exists());
        // A stream that goes up out of the destination is refused whole.
        let mut evil = Vec::new();
        loom_tools::boxfs::append_file(&mut evil, "out/ok.txt", 0o644, 0, b"fine");
        loom_tools::boxfs::append_file(&mut evil, "out/../../escaped.txt", 0o644, 0, b"bad");
        loom_tools::boxfs::finish_tar(&mut evil);
        std::fs::write(fake.dir.join("cp-out.tar"), &evil).unwrap();
        let r = rig.call("box_get", json!({"path": "out", "to": "got2"})).await;
        assert_eq!(r.status, ToolStatus::Error);
        assert!(r.text.contains("Nothing was written"), "{}", r.text);
        assert!(!ws.join("got2").exists() && !ws.parent().unwrap().join("escaped.txt").exists());
        // Paths in the box are checked before docker is asked.
        let r = rig.call("box_get", json!({"path": "/"})).await;
        assert!(r.text.contains("Name a file or directory below"), "{}", r.text);
    }

    #[tokio::test]
    async fn box_get_without_a_running_box_says_to_start_one() {
        let (rig, _fake, _d) = with_box(&[]);
        let r = rig.call("box_get", json!({"path": "x"})).await;
        assert!(r.text.contains("no running box") && r.text.contains("box_exec"), "{}", r.text);
    }

    #[tokio::test]
    async fn box_reset_makes_a_new_container_and_says_what_is_lost() {
        let (rig, fake, _d) = with_box(&[]);
        rig.call("box_exec", json!({"command": "true", "timeout_s": 20})).await;
        let before = fake.sub("run").len();
        let r = rig.call("box_reset", json!({})).await;
        assert_eq!(r.status, ToolStatus::Ok, "{}", r.text);
        assert!(r.text.contains("Everything that was in /work and /tmp is gone"), "{}", r.text);
        assert_eq!(fake.sub("run").len(), before + 2);
        assert!(fake.running("loom-m-test"));
        // The next call copies the workspace again.
        std::fs::write(rig.env.ctx.workspace.join("a.txt"), "x").unwrap();
        let r = rig.call("box_exec", json!({"command": "true", "timeout_s": 20})).await;
        assert!(r.text.contains("1 file(s) copied into /work first"), "{}", r.text);
    }

    #[tokio::test]
    async fn r8_box_get_refuses_dot_and_dotdot_components_in_path_and_to() {
        let (rig, fake, _d) = with_box(&[]);
        rig.call("box_exec", json!({"command": "true", "timeout_s": 20})).await;
        let mut tar = Vec::new();
        loom_tools::boxfs::append_file(&mut tar, "out/a.txt", 0o644, 0, b"A");
        loom_tools::boxfs::finish_tar(&mut tar);
        std::fs::write(fake.dir.join("cp-out.tar"), &tar).unwrap();
        let before = fake.sub("cp").len();
        for (args, which) in [
            (json!({"path": "../etc/passwd"}), "`path`"),
            (json!({"path": "out/../../etc"}), "`path`"),
            (json!({"path": "/work/./out"}), "`path`"),
            (json!({"path": "out/."}), "`path`"),
            (json!({"path": "out", "to": "../escaped"}), "`to`"),
            (json!({"path": "out", "to": "a/../b"}), "`to`"),
            (json!({"path": "out", "to": "./here"}), "`to`"),
        ] {
            let r = rig.call("box_get", args.clone()).await;
            assert_eq!(r.status, ToolStatus::Error, "{args}: {}", r.text);
            assert!(r.text.contains(which) && r.text.contains("component"), "{args}: {}", r.text);
        }
        assert_eq!(fake.sub("cp").len(), before, "docker was not asked for any of them");
        // Plain paths still work, also with a trailing slash.
        let r = rig.call("box_get", json!({"path": "out/", "to": "got"})).await;
        assert_eq!(r.status, ToolStatus::Ok, "{}", r.text);
    }

    #[test]
    fn container_paths_are_made_absolute_and_never_empty() {
        assert_eq!(container_path("out").unwrap(), "/work/out");
        assert_eq!(container_path("out/").unwrap(), "/work/out");
        assert_eq!(container_path("/etc/hosts").unwrap(), "/etc/hosts");
        assert!(container_path("/work/dir/.").is_err(), "no `.` component anywhere");
        assert!(container_path("").is_err() && container_path("/").is_err() && container_path("a\0b").is_err());
    }
}
