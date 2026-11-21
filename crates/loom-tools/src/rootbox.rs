//! The root box: one disposable, sealed, root-capable Linux VM that the operator made out of band and that
//! a granted role reaches through `rootbox_exec`.
//!
//! CONTRACT.
//!
//! The same safety model as the box (`boxctl`): the agent holds no credential, no host address and no ssh
//! flag. The daemon runs the ssh client, outside every sandbox, with an argv that loom builds
//! ([`ssh_args`]), a fixed environment and the operator's own `HOME`, where the ssh configuration that
//! defines the alias `rootbox.ssh_host` (address, user, key, ProxyJump) lives. The agent's text is never an
//! argument of anything: it is the script that the remote `/bin/bash -s` reads on its standard input.
//!
//! ## Reaching the VM (`RootBox`)
//! `RootBox::new(cfg, loom_home)` resolves `ssh_cli` to an absolute path once, at start (a bare name is
//! looked for on the daemon's `PATH` then and never again; a relative path or a program that is not found
//! refuses the start with a sentence) and makes the private directory `<loom home>/keys/rootbox-run` (where
//! every launcher starts and where a script waits for its ssh, never the session's scratch directory;
//! `<loom home>/keys` is unreadable to commands). Nothing is started until the first call, and nothing is
//! kept between calls: each call is one ssh connection and one fresh remote shell.
//!
//! ## The command (`launch`)
//! [`ssh_args`] is `-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10
//! -o ServerAliveInterval=15 -o LogLevel=ERROR -- <ssh_host> /bin/bash -s` (`LogLevel=ERROR`: ssh's own
//! notices, such as the one that names the address of a host it has just learned, are not output of the
//! command). `launch(call, script)` writes the script to a private file `<run dir>/<call>-<n>.sh`
//! and returns the `bash::Launch` that `bash::run_launched` runs: a small fixed shell text that opens the
//! file, removes it, and `exec`s the ssh client with the file as its stdin. The script is therefore on stdin
//! verbatim and in no argv. The environment is `PATH` ([`SYSTEM_PATH`]) and the operator's `HOME` only.
//! stdout and stderr are merged in the order written; the status is the remote shell's, or 255 when ssh
//! itself failed (the tool does not show what ssh said then).
//!
//! ## Time
//! [`RootBox::timeout_s`] is the hard cap of one call: `exec_timeout_s`, or less when the call asked for
//! less.
//!
//! Tests required: the exact ssh argv; a hostile script reaches the VM on stdin only and its file is gone
//! after the call; the timeout clamp; a program that is not found, a relative one, or an option-like or
//! empty host refuses the start (see also `config`).

use crate::bash::Launch;
use crate::boxctl::{resolve_program, SYSTEM_PATH};
use crate::proc::Launcher;
use loom_core::config::RootBoxCfg;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Where the launchers start and the scripts wait, under `<loom home>/keys`.
const RUN_DIR: &str = "rootbox-run";

/// What the tool answers when the operator has not enabled a root box.
pub const NO_ROOTBOX: &str = "No root box is configured. The operator sets [rootbox] in config.toml.";

/// The fixed shell text of the launcher: `$1` is the script file, the rest of `$@` the ssh command. The
/// file is opened and removed before ssh starts, and ssh reads it as its stdin.
const LAUNCH_TEXT: &str = "f=$1; shift; exec 3< \"$f\" || exit 1; rm -f \"$f\"; exec \"$@\" <&3";

/// The ssh arguments of one call, after the program (the remote command is `/bin/bash -s`).
pub fn ssh_args(cfg: &RootBoxCfg) -> Vec<String> {
    let mut a: Vec<String> = [
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
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    a.push(cfg.ssh_host.trim().to_string());
    a.push("/bin/bash".into());
    a.push("-s".into());
    a
}

pub struct RootBox {
    cfg: RootBoxCfg,
    ssh: PathBuf,
    run_dir: PathBuf,
    next: AtomicU64,
}

impl RootBox {
    /// Prepare the connection (nothing is started yet). `loom_home` is where `keys/rootbox-run` is made.
    pub fn new(cfg: &RootBoxCfg, loom_home: &Path) -> Result<Arc<RootBox>, String> {
        let search = std::env::var_os("PATH").unwrap_or_default();
        Self::new_in(cfg, loom_home, &search)
    }

    /// [`RootBox::new`] looking for `ssh_cli` in `search` (a `PATH` value) instead of the daemon's.
    pub fn new_in(cfg: &RootBoxCfg, loom_home: &Path, search: &OsStr) -> Result<Arc<RootBox>, String> {
        let mut on = cfg.clone();
        on.enabled = true;
        on.check()?;
        let ssh = resolve_program(&cfg.ssh_cli, "rootbox.ssh_cli", search)?;
        let run_dir = loom_home.join("keys").join(RUN_DIR);
        loom_core::config::ensure_private_dir(&run_dir)
            .map_err(|e| format!("The root box's private directory {} cannot be made: {e}", run_dir.display()))?;
        Ok(Arc::new(RootBox { cfg: cfg.clone(), ssh, run_dir, next: AtomicU64::new(1) }))
    }

    /// What results call the VM.
    pub fn name(&self) -> &str {
        self.cfg.name()
    }

    pub fn cfg(&self) -> &RootBoxCfg {
        &self.cfg
    }

    /// The most bytes of output one call keeps.
    pub fn max_output_bytes(&self) -> u64 {
        self.cfg.max_output_mb.max(1).saturating_mul(1 << 20)
    }

    /// The seconds one call may run: what it asked for, never more than `exec_timeout_s`.
    pub fn timeout_s(&self, asked: Option<u64>) -> u64 {
        let cap = self.cfg.exec_timeout_s.max(1);
        asked.map_or(cap, |a| a.clamp(1, cap))
    }

    /// The absolute path of the ssh program that was resolved at start.
    pub fn ssh_program(&self) -> &Path {
        &self.ssh
    }

    /// The directory the launchers start in.
    pub fn run_dir(&self) -> &Path {
        &self.run_dir
    }

    /// The launcher of one call: `script` waits in a private file that the launcher turns into the stdin of
    /// ssh. `call` only names the file (anything but letters, digits, `-` and `_` is replaced).
    pub fn launch(&self, call: &str, script: &str) -> Result<Launch, String> {
        use std::os::unix::fs::OpenOptionsExt;
        let safe: String =
            call.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect();
        let n = self.next.fetch_add(1, Ordering::Relaxed);
        let file = self.run_dir.join(format!("{safe}-{n}.sh"));
        let written = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&file)
            .and_then(|mut f| f.write_all(script.as_bytes()).and_then(|()| f.sync_data()));
        if let Err(e) = written {
            let _ = std::fs::remove_file(&file);
            return Err(format!("The script could not be prepared ({e}), so nothing was run."));
        }
        let mut args = vec!["-c".to_string(), LAUNCH_TEXT.to_string(), "_".to_string(), file.display().to_string()];
        args.push(self.ssh.display().to_string());
        args.extend(ssh_args(&self.cfg));
        let mut env = BTreeMap::from([("PATH".to_string(), SYSTEM_PATH.to_string())]);
        env.extend(std::env::var("HOME").ok().map(|h| ("HOME".to_string(), h)));
        Ok(Launch {
            launcher: Launcher { program: "/bin/bash".to_string(), args, remote_stop: None },
            cwd: self.run_dir.clone(),
            env,
        })
    }
}

/// A fake `ssh` for tests, in a directory of its own: it logs its argv (one per line, entries ended by
/// `----`) and its stdin, and then behaves as the remote side would: the script runs with `/bin/bash -s`
/// on this machine. A file `fail` in the directory makes it fail as ssh does when it cannot connect
/// (exit 255, a message that names an address). Nothing here reaches a real host.
#[cfg(any(test, feature = "testutil"))]
pub mod fake {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    pub struct FakeSsh {
        pub dir: PathBuf,
        pub cli: PathBuf,
    }

    const SCRIPT: &str = r##"#!/bin/sh
D="@DIR@"
env > "$D/ssh.env"
{ for a in "$@"; do printf '%s\n' "$a"; done; echo '----'; } >> "$D/ssh.log"
if [ -f "$D/fail" ]; then echo "ssh: connect to host 203.0.113.77 port 22: Connection refused" >&2; exit 255; fi
[ -f "$D/slow" ] && exec sleep 30
cat > "$D/ssh.stdin"
exec /bin/bash -s < "$D/ssh.stdin"
"##;

    impl FakeSsh {
        pub fn new(dir: &Path) -> FakeSsh {
            let dir = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
            std::fs::create_dir_all(&dir).expect("fake ssh dir");
            let cli = dir.join("ssh");
            std::fs::write(&cli, SCRIPT.replace("@DIR@", &dir.display().to_string())).expect("fake ssh");
            std::fs::set_permissions(&cli, std::fs::Permissions::from_mode(0o755)).expect("fake ssh mode");
            FakeSsh { dir, cli }
        }

        pub fn cfg(&self) -> RootBoxCfg {
            RootBoxCfg {
                enabled: true,
                ssh_host: "vm-alias".into(),
                ssh_cli: self.cli.display().to_string(),
                ..RootBoxCfg::default()
            }
        }

        /// The argv of every ssh call, without the program.
        pub fn calls(&self) -> Vec<Vec<String>> {
            let text = std::fs::read_to_string(self.dir.join("ssh.log")).unwrap_or_default();
            text.split("----\n").filter(|e| !e.is_empty()).map(|e| e.lines().map(str::to_string).collect()).collect()
        }

        /// What the last call read on stdin.
        pub fn stdin(&self) -> Vec<u8> {
            std::fs::read(self.dir.join("ssh.stdin")).unwrap_or_default()
        }

        /// Make every later call fail like an unreachable host.
        pub fn fail(&self) {
            std::fs::write(self.dir.join("fail"), "").expect("fail marker");
        }

        /// Make every later call hang without reading its stdin.
        pub fn slow(&self) {
            std::fs::write(self.dir.join("slow"), "").expect("slow marker");
        }

        pub fn host(&self) -> Arc<RootBox> {
            RootBox::new(&self.cfg(), &self.dir).expect("fake rootbox")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeSsh;
    use super::*;

    fn cfg() -> RootBoxCfg {
        RootBoxCfg { enabled: true, ssh_host: "test-rootbox".into(), ..RootBoxCfg::default() }
    }

    #[test]
    fn the_ssh_argv_is_fixed_and_the_host_follows_the_double_dash() {
        assert_eq!(
            ssh_args(&cfg()),
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
                "test-rootbox",
                "/bin/bash",
                "-s"
            ]
        );
    }

    #[test]
    fn the_start_is_refused_for_a_missing_relative_or_option_like_program_or_host() {
        let dir = tempfile::tempdir().unwrap();
        let search = std::ffi::OsString::from(dir.path());
        let mut c = cfg();
        c.ssh_cli = "no-such-ssh".into();
        let err = RootBox::new_in(&c, dir.path(), &search).err().unwrap();
        assert!(err.contains("rootbox.ssh_cli") && err.contains("was not found on the daemon's PATH"), "{err}");
        c.ssh_cli = "bin/ssh".into();
        assert!(RootBox::new_in(&c, dir.path(), &search).err().unwrap().contains("relative path"));
        c.ssh_cli = "ssh".into();
        c.ssh_host = "-oProxyCommand=x".into();
        assert!(RootBox::new_in(&c, dir.path(), &search).err().unwrap().contains("must not start with '-'"));
        c.ssh_host = " ".into();
        assert!(RootBox::new_in(&c, dir.path(), &search).err().unwrap().contains("ssh_host is empty"));
    }

    #[test]
    fn a_call_may_ask_for_less_time_never_more() {
        let d = tempfile::tempdir().unwrap();
        let f = FakeSsh::new(d.path());
        let h = f.host();
        assert_eq!(h.timeout_s(None), 300);
        assert_eq!(h.timeout_s(Some(20)), 20);
        assert_eq!(h.timeout_s(Some(5000)), 300);
        assert_eq!(h.timeout_s(Some(0)), 1);
        assert_eq!(h.name(), "vm-alias");
    }

    #[test]
    fn the_script_is_in_a_private_file_for_stdin_and_never_in_an_argv() {
        let d = tempfile::tempdir().unwrap();
        let f = FakeSsh::new(d.path());
        let h = f.host();
        let script = "echo '; rm -rf /; $(id)'; echo -o ProxyCommand=evil";
        let l = h.launch("call/../1", script).unwrap();
        assert_eq!(l.launcher.program, "/bin/bash");
        assert!(!l.launcher.args.iter().any(|a| a.contains("rm -rf")), "{:?}", l.launcher.args);
        assert_eq!(l.cwd, h.run_dir());
        assert_eq!(l.env.get("PATH").map(String::as_str), Some(SYSTEM_PATH));
        assert!(l.env.keys().all(|k| k == "PATH" || k == "HOME"), "{:?}", l.env);
        let file = PathBuf::from(&l.launcher.args[3]);
        assert!(file.starts_with(h.run_dir()) && file.extension().is_some_and(|e| e == "sh"), "{}", file.display());
        assert_eq!(std::fs::read_to_string(&file).unwrap(), script);
        use std::os::unix::fs::MetadataExt;
        assert_eq!(std::fs::metadata(&file).unwrap().mode() & 0o777, 0o600);
        // Running the launcher: ssh got the script on stdin, the file is gone.
        let out = std::process::Command::new(&l.launcher.program)
            .args(&l.launcher.args)
            .env_clear()
            .envs(&l.env)
            .current_dir(&l.cwd)
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(f.stdin(), script.as_bytes());
        assert!(!file.exists());
    }
}
