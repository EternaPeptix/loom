//! `rootbox_exec`: what a granted role can do with the operator's root box.
//!
//! CONTRACT.
//!
//! The root box is a disposable, sealed, root-capable Linux VM that the operator made and reaches over ssh
//! (`[rootbox]`, see `loom_tools::rootbox`). It exists so that a finding can be *observed* where the local
//! sandbox forbids it (a planted interpreter that runs as uid 0, say). The safety model is the box's: the
//! daemon runs a fixed `ssh` command, the session's text is only ever the script that the remote
//! `/bin/bash -s` reads on stdin, and the session holds no credential, host address or ssh flag. The root
//! box is asked for through `Orchestrator::rootbox_access`. Like `box_exec` it is not in [`super::NAMES`]:
//! only a role that lists it has it, and none of the default roles does.
//!
//! ## `rootbox_exec` {command, timeout_s}
//! Class `Exec` (counts toward `max_exec_calls`; refused in wrap-up like `bash` and `box_exec`).
//! 1. Without `command`: an error sentence. Without a configured root box: the error `No root box is
//!    configured. The operator sets [rootbox] in config.toml.` There is no workspace copy, so the call is
//!    open to a session in an agent copy too.
//! 2. The script runs through `loom_tools::bash::run_launched` on the launcher of `RootBox::launch`: the
//!    result is `bash`'s (output as it was written, stdout and stderr together, start and end of a long
//!    output with `out_read` and `out_grep` for the rest, the exit status), with the fact `in root box
//!    <label>` first. There are no background jobs: a call ends, or is stopped after `timeout_s`, at most
//!    `rootbox.exec_timeout_s`. A stopped call says so and that nothing further ran from it.
//! 3. When ssh itself failed (status 255: unreachable, host key or authentication), the output is not shown
//!    (it names addresses and key files) and the call is an error sentence: nothing ran, and the class of
//!    the failure, never the address or the key.
//!
//! Tests required: the error sentences; the whole path of a command (fake ssh: the argv, the script on stdin
//! verbatim, merged output, exit status); the timeout clamp; a transport failure; the exec class and the
//! wrap-up refusal (in `session`); the refusal without a root box (here and in `runtime`).

use super::Shared;
use async_trait::async_trait;
use loom_core::event::{ToolClass, ToolSpec, META_EXIT_CODE};
use loom_tools::rootbox::RootBox;
use loom_tools::{params, Tool, ToolCtx, ToolOutput};
use serde_json::{json, Map, Value};
use std::sync::Arc;

/// What the tool answers when the operator has not enabled a root box.
pub use loom_tools::rootbox::NO_ROOTBOX;

pub struct RootBoxExec(pub Arc<Shared>);

/// What a call answers when ssh itself failed.
const UNREACHABLE: &str = "The root box could not be reached (the ssh connection or login failed), so nothing ran. Say so in your report and do not retry in a loop; the operator has to check that the VM is up and reachable.";

fn with_name(mut out: ToolOutput, b: &RootBox) -> ToolOutput {
    out.more.insert(0, format!("in root box {}", b.name()));
    out
}

#[async_trait]
impl Tool for RootBoxExec {
    fn spec(&self) -> ToolSpec {
        params::spec(
            "rootbox_exec",
            "Run a shell command with bash on the root box: a disposable, sealed Linux VM that the operator made for observing privileged behavior that your local sandbox forbids (for example a planted interpreter that runs as uid 0). You run as a sudo-capable user, so `sudo <cmd>` runs as uid 0. The VM has no network egress: it is isolated, and nothing in it can reach the real host, the fleet or the internet. It is disposable, and reaching it, or running anything as root in it, proves nothing about the real host; do not report a result here as a result on the real system. Each call starts a new shell, so `cd` and variables do not carry over (files in the VM stay until the operator destroys it). stdout and stderr are captured together in the order they were written; the result is shown as for `bash` (start and end of a long output, `out_read` and `out_grep` for the rest). The command text reaches the VM only as the script of its shell; there are no background jobs, and a call is stopped when it has run for the time limit.",
            ToolClass::Exec,
            &[
                params::req("command", "string", "The command line to run on the root box."),
                params::opt("timeout_s", "integer", "Stop the command if it has not finished after this many seconds. It cannot be more than the operator's limit; leave it out to use that limit.").min(1),
            ],
        )
    }

    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let Some(command) = args.get("command").and_then(Value::as_str) else {
            return ToolOutput::error(
                "No command was given. Call rootbox_exec again with `command` set to the command line to run.",
            );
        };
        let b = match self.0.orch.rootbox_access(&ctx.session).await {
            Ok(b) => b,
            Err(e) => return ToolOutput::error(e),
        };
        let timeout_s = b.timeout_s(args.get("timeout_s").and_then(Value::as_u64));
        let launch = match b.launch(ctx.call_id.as_str(), command) {
            Ok(l) => l,
            Err(e) => return with_name(ToolOutput::error(e), &b),
        };
        // Only the script and the clamped time go on: no `background`, `wake_on` or `cwd` of the session.
        let mut call = Map::new();
        call.insert("command".into(), json!(command));
        call.insert("timeout_s".into(), json!(timeout_s));
        let mut limited = ctx.clone();
        let mut cfg = (*ctx.cfg).clone();
        cfg.max_output_bytes = cfg.max_output_bytes.min(b.max_output_bytes());
        limited.cfg = Arc::new(cfg);
        let out = loom_tools::bash::run_launched(&limited, &call, &launch).await;
        if out.meta.get(META_EXIT_CODE).and_then(Value::as_i64) == Some(255) {
            return with_name(ToolOutput::error(UNREACHABLE), &b);
        }
        let stopped = out.status == loom_core::event::ToolStatus::Timeout;
        let out = with_name(out, &b);
        if stopped {
            return out.with_more(format!("stopped after {timeout_s}s; nothing further ran from this call"));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtools::testkit::rootbox_rig;
    use loom_core::event::ToolStatus;
    use loom_tools::rootbox::fake::FakeSsh;

    fn with_root(
        f: impl FnOnce(&mut loom_core::config::RootBoxCfg),
    ) -> (crate::rtools::testkit::Rig, FakeSsh, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let fake = FakeSsh::new(dir.path());
        let mut cfg = fake.cfg();
        f(&mut cfg);
        let rig = rootbox_rig();
        *rig.orch.rootbox.lock().unwrap() = Some(Ok(RootBox::new(&cfg, &fake.dir).unwrap()));
        (rig, fake, dir)
    }

    fn header(r: &loom_core::event::ToolResult) -> &str {
        r.text.lines().next().unwrap_or_default()
    }

    #[tokio::test]
    async fn without_a_configured_root_box_the_tool_says_so_and_a_call_needs_its_command() {
        let rig = rootbox_rig();
        let r = rig.call("rootbox_exec", json!({"command": "id"})).await;
        assert_eq!(r.status, ToolStatus::Error);
        assert!(
            r.text.contains("No root box is configured. The operator sets [rootbox] in config.toml."),
            "{}",
            r.text
        );
        assert_eq!(NO_ROOTBOX, "No root box is configured. The operator sets [rootbox] in config.toml.");
        // A call without its argument, with or without a root box.
        // (The schema check refuses it before `run`, as for box_exec; the sentence in `run` is the backstop.)
        let r = rig.call("rootbox_exec", json!({})).await;
        assert_eq!(r.status, ToolStatus::Invalid);
        assert!(r.text.contains("command"), "{}", r.text);
        let (rig, _fake, _d) = with_root(|_| {});
        let r = rig.call("rootbox_exec", json!({})).await;
        assert_eq!(r.status, ToolStatus::Invalid);
        assert!(r.text.contains("command"), "{}", r.text);
    }

    #[tokio::test]
    async fn the_command_reaches_the_vm_on_stdin_only_and_the_result_is_bash_s() {
        let (rig, fake, _d) = with_root(|c| c.label = "disposable-vm".into());
        let script = "echo out-one; echo err-one >&2; echo out-two; echo '; ssh -o ProxyCommand=x'; exit 7";
        let r = rig.call("rootbox_exec", json!({"command": script, "timeout_s": 20})).await;
        assert_eq!(r.status, ToolStatus::Error, "{}", r.text);
        assert!(header(&r).starts_with("[rootbox_exec · exit 7 · in root box disposable-vm"), "{}", header(&r));
        // stdout and stderr merged in write order.
        assert!(r.text.contains("out-one\nerr-one\nout-two\n; ssh -o ProxyCommand=x"), "{}", r.text);
        // One ssh call, with the fixed argv: the host is one argument after `--`, the command `/bin/bash -s`.
        let calls = fake.calls();
        assert_eq!(calls.len(), 1, "{calls:?}");
        assert_eq!(
            calls[0],
            [
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=accept-new",
                "-o",
                "ConnectTimeout=10",
                "-o",
                "ServerAliveInterval=15",
                "-o",
                "LogLevel=ERROR",
                "--",
                "vm-alias",
                "/bin/bash",
                "-s"
            ]
        );
        // The script is on stdin verbatim, and nowhere in an argv.
        assert_eq!(fake.stdin(), script.as_bytes());
        assert!(calls.iter().flatten().all(|a| !a.contains("out-one")));
        // The environment of ssh is fixed.
        let env = std::fs::read_to_string(fake.dir.join("ssh.env")).unwrap();
        assert!(env.lines().any(|l| l == format!("PATH={}", loom_tools::boxctl::SYSTEM_PATH)), "{env}");
        // A clean exit is Ok, and with no label the host alias names the VM.
        let (rig, _fake, _d) = with_root(|_| {});
        let r = rig.call("rootbox_exec", json!({"command": "id -u"})).await;
        assert_eq!(r.status, ToolStatus::Ok, "{}", r.text);
        assert!(header(&r).starts_with("[rootbox_exec · exit 0 · in root box vm-alias"), "{}", header(&r));
    }

    #[tokio::test]
    async fn timeout_s_is_clamped_to_exec_timeout_s_and_a_stopped_call_says_nothing_further_ran() {
        let (rig, fake, _d) = with_root(|c| c.exec_timeout_s = 2);
        fake.slow();
        let started = std::time::Instant::now();
        let r = rig.call("rootbox_exec", json!({"command": "true", "timeout_s": 600})).await;
        assert!(started.elapsed() < std::time::Duration::from_secs(25), "stopped by the 2 s cap, not by 600 s");
        assert_eq!(r.status, ToolStatus::Timeout, "{}", r.text);
        assert!(r.text.contains("stopped after 2s") && r.text.contains("nothing further ran"), "{}", r.text);
        assert!(r.text.contains("in root box vm-alias"), "{}", r.text);
        // Leaving the time out uses the cap too; asking for less is honoured.
        let r = rig.call("rootbox_exec", json!({"command": "true", "timeout_s": 1})).await;
        assert!(r.text.contains("stopped after 1s"), "{}", r.text);
    }

    #[tokio::test]
    async fn an_unreachable_vm_is_an_error_that_names_the_class_and_never_the_address() {
        let (rig, fake, _d) = with_root(|_| {});
        fake.fail();
        let r = rig.call("rootbox_exec", json!({"command": "id", "timeout_s": 20})).await;
        assert_eq!(r.status, ToolStatus::Error, "{}", r.text);
        assert!(r.text.contains("could not be reached") && r.text.contains("nothing ran"), "{}", r.text);
        assert!(!r.text.contains("203.0.113.77") && !r.text.contains("Connection refused"), "{}", r.text);
        assert!(!r.text.contains("vm-alias") || r.text.contains("in root box vm-alias"), "{}", r.text);
    }

    #[tokio::test]
    async fn the_session_cannot_add_background_or_a_directory() {
        let (rig, fake, _d) = with_root(|_| {});
        let r = rig.call("rootbox_exec", json!({"command": "true", "background": true})).await;
        assert!(!r.text.contains("started as job"), "{}", r.text);
        let r = rig.call("rootbox_exec", json!({"command": "true", "cwd": "/etc"})).await;
        assert!(!r.text.contains("started as job"), "{}", r.text);
        let _ = fake;
    }
}
