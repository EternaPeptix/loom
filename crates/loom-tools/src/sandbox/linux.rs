//! Linux command confinement.
//!
//! CONTRACT: bubblewrap requires Linux, executable `/usr/bin/bwrap`, and no host proxy, loopback
//! exceptions or Unix socket grants. It never falls back to an unconfined shell. The host tree is
//! mounted read-only; explicit writable roots are bound writable, protected roots rebound read-only,
//! session temp rebound writable, and protected children rebound read-only again. Existing Git
//! metadata directories are read-only as a whole. Creating a new repository inside a writable root
//! is outside this snapshot-based Git protection; the operator must do that outside the session.
//! `/tmp`, `/var/tmp` and `/run` are private mounts. Credential/unreadable directories are empty
//! mounts, files are replaced by `/dev/null`. Socket creation and connection syscalls are denied by
//! seccomp in addition to isolated network namespaces, including filesystem Unix sockets. The filter
//! is a harness-owned file outside session temp, opened on fd 3 before entering bubblewrap. Only
//! x86_64 and aarch64 Linux are supported; unknown architectures fail closed. Seccomp checks the
//! syscall architecture (and x86 x32 bit) before allowing anything. Commands inherit no host proxy.
//! This provides command deny-all networking, not a bridge for proxied shell networking. In-process
//! tools use their own configured network policy and are not in this process sandbox.
//! Bind sources are open harness descriptors, resolved through the original host proc mount; source
//! aliases or replaced temp ancestors cannot broaden writable contents. The trusted launcher opens
//! them before namespace entry; bwrap uses inherited /proc/self/fd sources. A trusted confined
//! launcher closes them before
//! target execution (tested, since old-mount descriptors must never reach a read-only target). A missing protected path in
//! a writable root is refused unless an existing read-only ancestor covers it. Native CI requires
//! bubblewrap; absence or namespace failures are failures, not skipped qualification.

use super::{invalid, under, Sandbox};
use loom_core::config::SandboxCfg;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone, Debug)]
pub(super) struct PinnedPath {
    path: PathBuf,
    file: Arc<std::fs::File>,
}

/// Keep each existing bind source open in the harness. Bubblewrap resolves it through the original
/// host proc mount (`/proc/<harness pid>/fd/N`) before namespace entry. The launcher opens inherited
/// descriptors for bwrap sources (`/proc/self/fd/N`); a trusted confined shell closes them before
/// executing the target. Bwrap itself preserves arbitrary inherited descriptors.
/// The daemon owns the original descriptors for the Sandbox lifetime.
pub(super) fn pin(
    writable: &[PathBuf],
    protected: &[PathBuf],
    unreadable: &[PathBuf],
    credentials: &[PathBuf],
    git_dirs: &[PathBuf],
) -> io::Result<Vec<PinnedPath>> {
    use std::os::fd::AsFd;
    use std::os::unix::fs::OpenOptionsExt;
    let mut out: Vec<PinnedPath> = Vec::new();
    for path in writable.iter().chain(protected).chain(unreadable).chain(credentials).chain(git_dirs) {
        if !writable.contains(path) && !protected.contains(path) && !git_dirs.contains(path) {
            continue;
        }
        if out.iter().any(|p| &p.path == path) {
            continue;
        }
        if !path.exists() {
            // A missing protection inside a writable area has no mountable source. Refuse rather
            // than promise a future-path exclusion that a bind-mount policy cannot implement.
            let covered = protected.iter().chain(git_dirs).any(|p| p != path && under(path, p));
            if protected.contains(path) && writable.iter().any(|w| under(path, w)) && !covered {
                return Err(invalid(format!("Bubblewrap cannot protect the missing path {} inside a writable root. Create that protected path before starting the session, or use a read-only workspace.", path.display())));
            }
            if writable.contains(path) {
                return Err(invalid(format!(
                    "Bubblewrap writable root {} must already exist. Create it before starting the session.",
                    path.display()
                )));
            }
            continue;
        }
        let file =
            std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
        let real = crate::files::real_path(file.as_fd())?;
        if &real != path {
            return Err(invalid(format!("Bubblewrap bind source {} changed while its descriptor was opened (now {}). Stop concurrent filesystem changes and retry.", path.display(), real.display())));
        }
        out.push(PinnedPath { path: path.clone(), file: Arc::new(file) });
    }
    Ok(out)
}

fn source(sb: &Sandbox, path: &Path) -> Option<String> {
    sb.linux_pins
        .iter()
        .position(|p| p.path == path)
        .and_then(|i| i.checked_add(10))
        .map(|fd| format!("/proc/self/fd/{fd}"))
}

pub(super) fn preflight(cfg: &SandboxCfg, exec: &Path, linux: bool) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    if !linux {
        return Err("[sandbox] mode = \"bubblewrap\" requires Linux. Use seatbelt on macOS or explicitly choose unconfined mode = \"none\".".to_string());
    }
    if !cfg.loopback_ports.is_empty() || cfg.loopback_all || !cfg.unix_sockets.is_empty() {
        return Err("Bubblewrap supports deny-all command networking only. Remove loopback_ports, loopback_all and unix_sockets; no host proxy bridge is implemented.".to_string());
    }
    if !exec.metadata().is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0) {
        return Err(format!(
            "{} is missing or not executable. Install bubblewrap; Loom will not run the command unconfined.",
            exec.display()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn filter() -> io::Result<Vec<u8>> {
    let arch = if cfg!(target_arch = "x86_64") {
        0xc000_003e_u32
    } else if cfg!(target_arch = "aarch64") {
        0xc000_00b7_u32
    } else {
        return Err(invalid(
            "Bubblewrap seccomp supports x86_64 and aarch64 Linux only. Use a supported host.".to_string(),
        ));
    };
    // Classic BPF: load architecture, kill on a mismatch, then inspect syscall number.
    let mut code = vec![(0x20_u16, 0_u8, 0_u8, 4_u32), (0x15, 1, 0, arch), (0x06, 0, 0, 0x8000_0000), (0x20, 0, 0, 0)];
    if cfg!(target_arch = "x86_64") {
        // x32 uses the same audit architecture with different syscall numbers.
        code.extend([(0x45, 0, 1, 0x4000_0000), (0x06, 0, 0, 0x8000_0000)]);
    }
    for nr in [
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_sendto,
        libc::SYS_sendmsg,
        libc::SYS_sendmmsg,
        libc::SYS_io_uring_setup,
    ] {
        code.extend([(0x15, 0, 1, nr as u32), (0x06, 0, 0, 0x0005_0000 | libc::EPERM as u32)]);
    }
    code.push((0x06, 0, 0, 0x7fff_0000));
    let mut bytes = Vec::new();
    for (op, jt, jf, value) in code {
        bytes.extend_from_slice(&op.to_ne_bytes());
        bytes.extend([jt, jf]);
        bytes.extend_from_slice(&value.to_ne_bytes());
    }
    Ok(bytes)
}

pub(super) fn prepare(home: &Path) -> io::Result<PathBuf> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = home;
        Err(invalid("Bubblewrap requires Linux. Use seatbelt on macOS.".to_string()))
    }
    #[cfg(target_os = "linux")]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let bytes = filter()?;
        let dir = home.join("sandbox");
        loom_core::config::ensure_private_dir(&dir)?;
        let path = dir.join(format!("network-deny-v1-{}.bpf", std::env::consts::ARCH));
        // The path lies in protected Loom home, not model-writable session temp. Rewrite atomically
        // so concurrent session construction never exposes a partial program.
        let tmp = dir.join(format!(
            ".network-{}-{}.bpf",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
        let result = (|| {
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::rename(&tmp, &path)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result?;
        Ok(path)
    }
}

pub(super) fn command(sb: &Sandbox, script: &str) -> (String, Vec<String>) {
    use std::os::fd::AsRawFd;
    // Only harness-authored code executes before confinement; paths and script are positional args.
    let mut launcher = "exec 3<\"$1\" || exit 126; shift; ".to_string();
    for (i, _) in sb.linux_pins.iter().enumerate() {
        let Some(fd) = i.checked_add(10) else {
            return ("/bin/false".to_string(), Vec::new());
        };
        launcher.push_str(&format!("exec {fd}<\"$1\" || exit 126; shift; "));
    }
    launcher.push_str("exec \"$@\"");
    let mut args = vec![
        "--noprofile".to_string(),
        "--norc".to_string(),
        "-p".to_string(),
        "-c".to_string(),
        launcher,
        "loom-bwrap".to_string(),
    ];
    args.push(sb.linux_filter.as_ref().map(|p| p.display().to_string()).unwrap_or_default());
    for pin in &sb.linux_pins {
        args.push(format!("/proc/{}/fd/{}", std::process::id(), pin.file.as_raw_fd()));
    }
    args.extend(
        [
            super::BWRAP,
            "--die-with-parent",
            "--new-session",
            "--unshare-all",
            "--unshare-user",
            "--disable-userns",
            "--cap-drop",
            "ALL",
            "--ro-bind",
            "/",
            "/",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--tmpfs",
            "/var/tmp",
            "--tmpfs",
            "/run",
            "--seccomp",
            "3",
        ]
        .into_iter()
        .map(str::to_string),
    );
    // Hide the whole original home before restoring scoped roots. This also hides credential stores
    // created after launch, rather than relying on a mount for every currently-existing secret file.
    let hidden_home = sb.home.as_ref().filter(|_| !sb.credentials.is_empty());
    for path in hidden_home.into_iter().chain(std::iter::once(&sb.loom_home)) {
        args.extend(["--tmpfs".to_string(), path.display().to_string()]);
    }
    let bind = |args: &mut Vec<String>, flag: &str, path: &Path| {
        if let Some(source) = source(sb, path) {
            args.extend([flag.to_string(), source, path.display().to_string()]);
        }
    };
    for path in &sb.writable {
        if !sb.protected.iter().any(|p| under(path, p)) {
            bind(&mut args, "--bind", path);
        }
    }
    for path in sb.protected.iter().chain(&sb.git_dirs) {
        if under(path, &sb.loom_home) && !under(path, &sb.workspace) {
            continue;
        }
        bind(&mut args, "--ro-bind", path);
    }
    if !sb.inside_tmp_protected().iter().any(|p| under(&sb.tmp_dir, p)) {
        bind(&mut args, "--bind", &sb.tmp_dir);
    }
    for path in sb.inside_tmp_protected() {
        bind(&mut args, "--ro-bind", &path);
    }
    for path in sb.unreadable.iter().chain(&sb.credentials) {
        let restored = sb.writable.iter().chain(&sb.git_dirs).any(|root| under(path, root));
        if !restored && (under(path, &sb.loom_home) || hidden_home.is_some_and(|home| under(path, home))) {
            continue;
        }
        if under(path, &sb.workspace.join(".loom")) {
            continue;
        }
        if path.is_dir() {
            args.extend(["--tmpfs".to_string(), path.display().to_string()]);
        } else if path.exists() {
            args.extend(["--ro-bind".to_string(), "/dev/null".to_string(), path.display().to_string()]);
        }
    }
    let workspace_state = sb.workspace.join(".loom");
    args.extend([
        "--tmpfs".to_string(),
        workspace_state.display().to_string(),
        "--remount-ro".to_string(),
        workspace_state.display().to_string(),
    ]);
    // Only these top mounts become read-only; the scoped writable workspace/temp bind mounts below
    // them keep their own access modes.
    for path in hidden_home.into_iter().chain(std::iter::once(&sb.loom_home)) {
        args.extend(["--remount-ro".to_string(), path.display().to_string()]);
    }
    let mut close_sources = "exec 3<&-; ".to_string();
    for (i, _) in sb.linux_pins.iter().enumerate() {
        let Some(fd) = i.checked_add(10) else {
            return ("/bin/false".to_string(), Vec::new());
        };
        close_sources.push_str(&format!("exec {fd}<&-; "));
    }
    close_sources.push_str("exec /bin/bash -c \"$1\" \"${@:2}\"");
    args.extend([
        "--chdir".to_string(),
        sb.workspace.display().to_string(),
        "--".to_string(),
        "/bin/bash".to_string(),
        "--noprofile".to_string(),
        "--norc".to_string(),
        "-p".to_string(),
        "-c".to_string(),
        close_sources,
        "loom-confined-close".to_string(),
        script.to_string(),
    ]);
    ("/bin/bash".to_string(), args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use loom_core::config::SandboxMode;

    #[test]
    fn preflight_refuses_missing_launcher_wrong_platform_and_network_exceptions() {
        let cfg = SandboxCfg { mode: SandboxMode::Bubblewrap, ..SandboxCfg::default() };
        assert!(preflight(&cfg, Path::new("/bin/sh"), false).is_err());
        assert!(preflight(&cfg, Path::new("/does/not/exist/bwrap"), true).is_err());
        for cfg in [
            SandboxCfg { loopback_all: true, ..cfg.clone() },
            SandboxCfg { loopback_ports: vec![443], ..cfg.clone() },
            SandboxCfg { unix_sockets: vec!["/run/docker.sock".into()], ..cfg.clone() },
        ] {
            assert!(preflight(&cfg, Path::new("/bin/sh"), true).is_err());
        }
        assert!(preflight(&cfg, Path::new("/bin/sh"), true).is_ok());
    }

    #[test]
    fn pinning_refuses_missing_protections_and_replaced_source_aliases() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let ws = root.join("workspace");
        let outside = root.join("outside");
        std::fs::create_dir(&ws).unwrap();
        std::fs::create_dir(&outside).unwrap();
        assert!(pin(std::slice::from_ref(&ws), &[ws.join("missing-protection")], &[], &[], &[]).is_err());
        let alias = ws.join("alias");
        std::os::unix::fs::symlink(&outside, &alias).unwrap();
        assert!(pin(&[alias], &[], &[], &[], &[]).is_err());
    }

    #[test]
    fn host_launcher_environment_cannot_load_agent_writable_initialization_or_libraries() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("ws");
        let home = dir.path().join("home");
        let tmp = dir.path().join("tmp");
        for p in [&ws, &home, &tmp] {
            std::fs::create_dir(p).unwrap();
        }
        let cfg = SandboxCfg {
            mode: SandboxMode::None,
            protect_credentials: false,
            env_pass: vec!["LD_PRELOAD".into()],
            ..SandboxCfg::default()
        };
        let mut sb = Sandbox::new(&cfg, &ws, &tmp, &home, None).unwrap();
        sb.mode = SandboxMode::Bubblewrap;
        let parent = ["BASH_ENV", "ENV", "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "BASH_FUNC_exec%%"]
            .into_iter()
            .map(|key| (key.to_string(), "untrusted".to_string()))
            .collect();
        let env = sb.env(&parent);
        assert!(!env.contains_key("LD_PRELOAD"));
        assert!(!env.contains_key("BASH_ENV"));
        assert!(!env.contains_key("BASH_FUNC_exec%%"));
        assert!(!env.values().any(|value| value == "untrusted"));
    }

    #[test]
    fn command_keeps_readonly_workspace_and_uses_trusted_filter_not_session_temp() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("ws");
        let tmp = dir.path().join("tmp");
        let home = dir.path().join("home");
        for p in [&ws, &tmp, &home] {
            std::fs::create_dir(p).unwrap();
        }
        let ws = ws.canonicalize().unwrap();
        let tmp = tmp.canonicalize().unwrap();
        let home = home.canonicalize().unwrap();
        let cfg = SandboxCfg {
            protect_credentials: false,
            protected_paths: vec![ws.display().to_string()],
            ..SandboxCfg::default()
        };
        let mut sb = Sandbox::new(&cfg, &ws, &tmp, &home, None).unwrap();
        sb.mode = SandboxMode::Bubblewrap;
        sb.linux_filter = Some(home.join("sandbox/filter.bpf"));
        sb.linux_pins = pin(&sb.writable, &sb.protected, &sb.unreadable, &sb.credentials, &sb.git_dirs).unwrap();
        let (prog, args) = command(&sb, "printf 'literal $()'; true");
        assert_eq!(prog, "/bin/bash");
        assert!(args.iter().any(|x| x == "--unshare-all"));
        assert!(args.windows(2).any(|w| w == ["--seccomp", "3"]));
        assert!(!args.windows(3).any(|w| w == ["--bind", ws.to_str().unwrap(), ws.to_str().unwrap()]));
        assert!(args
            .windows(3)
            .any(|w| w[0] == "--ro-bind" && w[1].starts_with("/proc/") && w[2] == ws.to_str().unwrap()));
        assert!(args
            .windows(3)
            .any(|w| w[0] == "--bind" && w[1].starts_with("/proc/") && w[2] == tmp.to_str().unwrap()));
        assert_eq!(args.last().unwrap(), "printf 'literal $()'; true");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn filter_is_complete_and_outside_writable_temp() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let path = prepare(&home).unwrap();
        assert!(path.starts_with(home.join("sandbox")));
        let bytes = std::fs::read(path).unwrap();
        assert_eq!(bytes, filter().unwrap());
        assert_eq!(bytes.len() % 8, 0);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod native_tests {
    use super::*;
    use loom_core::config::SandboxMode;
    use std::os::unix::fs::symlink;
    use std::process::Command;

    fn required_launcher() -> bool {
        if Path::new(super::super::BWRAP).exists() {
            return true;
        }
        assert!(
            std::env::var_os("LOOM_BWRAP_REQUIRED").is_none(),
            "Linux CI requires /usr/bin/bwrap; install bubblewrap"
        );
        false
    }

    fn fixture(readonly: bool) -> (tempfile::TempDir, Sandbox, PathBuf) {
        // The fixture must be outside the sandbox's private /tmp mount so a sibling write tests
        // the read-only host tree, rather than a harmless file in the namespace's private /tmp.
        let executable = std::env::current_exe().unwrap();
        let root = tempfile::tempdir_in(executable.parent().unwrap()).unwrap();
        let ws = root.path().join("ws");
        let home = root.path().join("home");
        let tmp = home.join("sessions/test/tmp");
        for path in [ws.join(".loom"), tmp.clone(), ws.join(".git/hooks")] {
            std::fs::create_dir_all(path).unwrap();
        }
        std::fs::write(ws.join(".git/config"), "original").unwrap();
        let cfg = SandboxCfg {
            mode: SandboxMode::Bubblewrap,
            protect_credentials: false,
            protected_paths: if readonly { vec![ws.display().to_string()] } else { Vec::new() },
            ..SandboxCfg::default()
        };
        let sb = Sandbox::new(&cfg, &ws, &tmp, &home, None).unwrap();
        (root, sb, ws)
    }

    fn run(sb: &Sandbox, script: &str) -> std::process::Output {
        let (program, args) = sb.command(script);
        Command::new(program).args(args).envs(sb.env(&std::collections::BTreeMap::new())).output().unwrap()
    }

    #[test]
    fn bubblewrap_native_writable_readonly_temp_git_and_network_are_enforced() {
        if !required_launcher() {
            return;
        }
        let (root, sb, ws) = fixture(false);
        let out = run(&sb, "echo source > source.txt; echo own > \"$TMPDIR/own\"; echo private > /tmp/loom-private; test -r source.txt");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        assert!(ws.join("source.txt").exists());
        let hostile_init = root.path().join("hostile-bash-env");
        let host_canary = root.path().join("host-canary");
        std::fs::write(&hostile_init, format!("echo executed-before-confinement > '{}'", host_canary.display()))
            .unwrap();
        let (program, args) = sb.command("echo safe > source.txt");
        let out = Command::new(program).args(args).env("BASH_ENV", &hostile_init).output().unwrap();
        assert!(out.status.success());
        assert!(!host_canary.exists(), "host launcher must not source BASH_ENV");
        assert!(sb.tmp_dir.join("own").exists());
        let sibling = root.path().join("sibling");
        let out = run(&sb, &format!("echo forbidden > '{}'", sibling.display()));
        assert!(!out.status.success());
        assert!(!sibling.exists());
        let out = run(&sb, "echo changed > .git/config");
        assert!(!out.status.success());
        assert_eq!(std::fs::read_to_string(ws.join(".git/config")).unwrap(), "original");
        let exe = std::env::current_exe().unwrap().display().to_string().replace('\'', "'\"'\"'");
        let out = run(&sb, &format!("LOOM_BWRAP_SOCKET_PROBE=1 '{exe}' --ignored --exact sandbox::linux::native_tests::socket_probe --nocapture"));
        assert!(
            out.status.success(),
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let (_root, readonly, _ws) = fixture(true);
        assert!(!run(&readonly, "echo forbidden > source.txt").status.success());
        assert!(run(&readonly, "echo own > \"$TMPDIR/own\"").status.success());
    }

    #[test]
    #[ignore = "run only as a child of the native Bubblewrap test"]
    fn socket_probe() {
        assert!(std::env::var_os("LOOM_BWRAP_SOCKET_PROBE").is_some());
        assert!(!Path::new("/proc/self/fd/10").exists(), "old-mount source fd must be closed before target execution");
        assert!(
            std::fs::File::open("/proc/1/fd/10").is_err(),
            "PID namespace reaper must not expose an old-mount source fd"
        );
        for domain in [libc::AF_INET, libc::AF_INET6, libc::AF_UNIX] {
            // SAFETY: socket has no pointer arguments. Any unexpected descriptor is closed below.
            let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM, 0) };
            let error = io::Error::last_os_error();
            if fd >= 0 {
                unsafe { libc::close(fd) };
            }
            assert_eq!(fd, -1, "socket domain {domain} must be denied");
            assert_eq!(error.raw_os_error(), Some(libc::EPERM));
        }
    }

    #[test]
    fn bubblewrap_native_pins_sources_when_workspace_or_temp_ancestor_is_replaced() {
        if !required_launcher() {
            return;
        }
        let (root, sb, ws) = fixture(false);
        let outside = root.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("canary"), "original").unwrap();
        std::fs::rename(&ws, root.path().join("old-ws")).unwrap();
        symlink(&outside, &ws).unwrap();
        let _ = run(&sb, "echo corrupted > canary");
        assert_eq!(std::fs::read_to_string(outside.join("canary")).unwrap(), "original");
        // An ancestor of temp is replaced too; a pathname bind would expose outside writable here.
        let session = sb.tmp_dir.parent().unwrap();
        let moved = session.with_file_name("moved");
        std::fs::rename(session, &moved).unwrap();
        symlink(&outside, session).unwrap();
        let _ = run(&sb, "echo corrupted > \"$TMPDIR/canary\"");
        assert_eq!(std::fs::read_to_string(outside.join("canary")).unwrap(), "original");
    }

    #[tokio::test]
    async fn bubblewrap_native_works_with_the_tracked_process_wrapper() {
        if !required_launcher() {
            return;
        }
        let (root, sb, ws) = fixture(false);
        let spec = crate::proc::Spawn {
            script: "echo tracked; exit 0".to_string(),
            cwd: ws,
            env: sb.env(&std::collections::BTreeMap::new()),
            out_path: root.path().join("command.out"),
            exit_path: root.path().join("command.exit"),
        };
        let mut running = crate::proc::spawn(&sb, &spec).unwrap();
        let end = running
            .wait(&tokio_util::sync::CancellationToken::new(), Some(std::time::Duration::from_secs(10)), 1_000_000)
            .await;
        assert_eq!(
            end,
            crate::proc::WaitEnd::Ended(crate::proc::Ended::Exit(0)),
            "{}",
            String::from_utf8_lossy(&running.read_output(0).unwrap())
        );
        assert!(String::from_utf8_lossy(&running.read_output(0).unwrap()).contains("tracked"));
    }

    #[test]
    fn bubblewrap_native_hides_credentials_and_oracle_keys_created_after_construction() {
        if !required_launcher() {
            return;
        }
        let executable = std::env::current_exe().unwrap();
        let root = tempfile::tempdir_in(executable.parent().unwrap()).unwrap();
        let user_home = root.path().join("user-home");
        let ws = user_home.join("project");
        let home = user_home.join("loom-state");
        let tmp = home.join("sessions/test/tmp");
        for path in [ws.join(".loom"), tmp.clone()] {
            std::fs::create_dir_all(path).unwrap();
        }
        let cfg = SandboxCfg { mode: SandboxMode::Bubblewrap, ..SandboxCfg::default() };
        let sb = Sandbox::with_home(&cfg, &ws, &tmp, &home, None, Some(user_home.clone())).unwrap();
        for path in [user_home.join(".aws/credentials"), ws.join(".loom/oracle-secrets/key"), home.join("token")] {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "host-secret-created-after-policy").unwrap();
            let out = run(&sb, &format!("test ! -r '{}'", path.display()));
            assert!(
                out.status.success(),
                "late-created {} was readable: {}",
                path.display(),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        assert!(run(&sb, "echo source > source.txt; echo tmp > \"$TMPDIR/own\"").status.success());
        assert!(ws.join("source.txt").exists());
        assert!(tmp.join("own").exists());
    }
}
