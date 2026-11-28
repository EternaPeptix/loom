//! Linux command confinement.
//!
//! CONTRACT: bubblewrap requires Linux, executable `/usr/bin/bwrap`, and no host proxy, loopback
//! exceptions or Unix socket grants. It never falls back to an unconfined shell. The host tree is
//! mounted read-only; explicit writable roots are bound writable, protected roots rebound read-only,
//! session temp rebound writable, and protected children rebound read-only again. Existing Git
//! metadata directories are read-only as a whole. Creating a new repository inside a writable root
//! is outside this snapshot-based Git protection; the operator must do that outside the session.
//! The workspace `.ferret` is hidden by a read-only empty mount, except that an existing `.ferret/uploads` folder
//! is bound read-only inside it (`docs/UPLOADS.md`). `/tmp`, `/var/tmp` and `/run` are private mounts. Credential/unreadable directories are empty
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
use ferret_core::config::SandboxCfg;
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
    holders: &[PathBuf],
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
    for path in holders {
        if out.iter().any(|p| &p.path == path) {
            continue;
        }
        let Ok(meta) = std::fs::symlink_metadata(path) else {
            continue;
        };
        if !meta.is_dir() {
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
            "{} is missing or not executable. Install bubblewrap; Ferret will not run the command unconfined.",
            exec.display()
        ));
    }
    Ok(())
}

/// Linux `EPERM` value (identical on x86_64 and aarch64).
#[cfg(any(target_os = "linux", test))]
const LINUX_EPERM: u32 = 1;

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SeccompArch {
    X86_64,
    Aarch64,
}

/// Denied syscalls on x86_64 Linux: all network socket creation/connection syscalls plus high-risk
/// kernel-attack and cross-process escape syscalls (`io_uring_setup`, `userfaultfd`, `ptrace`,
/// `bpf`, `keyctl`, `add_key`, `request_key`, `process_vm_readv`, `process_vm_writev`).
#[cfg(any(target_os = "linux", test))]
const DENIED_SYSCALLS_X86_64: &[u32] = &[
    41,  // socket
    53,  // socketpair
    42,  // connect
    49,  // bind
    50,  // listen
    43,  // accept
    288, // accept4
    44,  // sendto
    46,  // sendmsg
    307, // sendmmsg
    425, // io_uring_setup
    323, // userfaultfd
    101, // ptrace
    321, // bpf
    250, // keyctl
    248, // add_key
    249, // request_key
    310, // process_vm_readv
    311, // process_vm_writev
];

/// Denied syscalls on aarch64 Linux (asm-generic syscall table).
#[cfg(any(target_os = "linux", test))]
const DENIED_SYSCALLS_AARCH64: &[u32] = &[
    198, // socket
    199, // socketpair
    203, // connect
    200, // bind
    201, // listen
    202, // accept
    242, // accept4
    206, // sendto
    211, // sendmsg
    269, // sendmmsg
    425, // io_uring_setup
    282, // userfaultfd
    117, // ptrace
    280, // bpf
    219, // keyctl
    217, // add_key
    218, // request_key
    270, // process_vm_readv
    271, // process_vm_writev
];

#[cfg(any(target_os = "linux", test))]
fn filter_for_arch(arch: SeccompArch) -> Vec<u8> {
    let (audit_arch, check_x32, denied) = match arch {
        SeccompArch::X86_64 => (0xc000_003e_u32, true, DENIED_SYSCALLS_X86_64),
        SeccompArch::Aarch64 => (0xc000_00b7_u32, false, DENIED_SYSCALLS_AARCH64),
    };
    // Classic BPF: load architecture, kill on a mismatch, then inspect syscall number.
    let mut code =
        vec![(0x20_u16, 0_u8, 0_u8, 4_u32), (0x15, 1, 0, audit_arch), (0x06, 0, 0, 0x8000_0000), (0x20, 0, 0, 0)];
    if check_x32 {
        // x32 uses the same audit architecture with different syscall numbers.
        code.extend([(0x45, 0, 1, 0x4000_0000), (0x06, 0, 0, 0x8000_0000)]);
    }
    for &nr in denied {
        code.extend([(0x15, 0, 1, nr), (0x06, 0, 0, 0x0005_0000 | LINUX_EPERM)]);
    }
    code.push((0x06, 0, 0, 0x7fff_0000));
    let mut bytes = Vec::with_capacity(code.len() * 8);
    for (op, jt, jf, value) in code {
        bytes.extend_from_slice(&op.to_ne_bytes());
        bytes.extend([jt, jf]);
        bytes.extend_from_slice(&value.to_ne_bytes());
    }
    bytes
}

#[cfg(target_os = "linux")]
fn filter() -> io::Result<Vec<u8>> {
    if cfg!(target_arch = "x86_64") {
        Ok(filter_for_arch(SeccompArch::X86_64))
    } else if cfg!(target_arch = "aarch64") {
        Ok(filter_for_arch(SeccompArch::Aarch64))
    } else {
        Err(invalid(
            "Bubblewrap seccomp supports x86_64 and aarch64 Linux only. Use a supported host.".to_string(),
        ))
    }
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
        ferret_core::config::ensure_private_dir(&dir)?;
        let path = dir.join(format!("network-deny-v2-{}.bpf", std::env::consts::ARCH));
        // The path lies in protected Ferret home, not model-writable session temp. Rewrite atomically
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
    command_with(sb, script, true)
}

pub(super) fn pty_command(sb: &Sandbox, script: &str) -> (String, Vec<String>) {
    command_with(sb, script, false)
}

fn command_with(sb: &Sandbox, script: &str, new_session: bool) -> (String, Vec<String>) {
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
        "ferret-bwrap".to_string(),
    ];
    args.push(sb.linux_filter.as_ref().map(|p| p.display().to_string()).unwrap_or_default());
    for pin in &sb.linux_pins {
        args.push(format!("/proc/{}/fd/{}", std::process::id(), pin.file.as_raw_fd()));
    }
    args.extend([super::BWRAP.to_string(), "--die-with-parent".to_string()]);
    if new_session {
        args.push("--new-session".to_string());
    }
    args.extend(
        [
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
    for path in hidden_home.into_iter().chain(std::iter::once(&sb.ferret_home)) {
        args.extend(["--tmpfs".to_string(), path.display().to_string()]);
    }
    let bind = |args: &mut Vec<String>, flag: &str, path: &Path| {
        if let Some(source) = source(sb, path) {
            args.extend([flag.to_string(), source, path.display().to_string()]);
        }
    };
    let bound_writable = |path: &Path| path != sb.tmp_dir.as_path() && !sb.protected.iter().any(|p| under(path, p));
    for path in &sb.writable {
        if bound_writable(path) {
            bind(&mut args, "--bind", path);
        }
    }
    // Mount writable ancestor holders (`holders()`) as read-write self-bind mountpoints so `rename(2)`
    // returns EBUSY instead of lifting multi-component protected/unreadable subtrees off their rules.
    let all_holders = sb.holders();
    let mut non_tmp_holders: Vec<PathBuf> = all_holders
        .iter()
        .filter(|h| {
            !under(h, &sb.tmp_dir)
                && !under(h, &sb.ferret_home)
                && !sb.writable.contains(h)
                && !sb.protected.contains(h)
                && !sb.git_dirs.contains(h)
        })
        .cloned()
        .collect();
    non_tmp_holders.sort_by(|a, b| a.components().count().cmp(&b.components().count()).then_with(|| a.cmp(b)));
    for h in &non_tmp_holders {
        bind(&mut args, "--bind", h);
    }
    // If any writable root or holder contains `ferret_home`, re-apply its masking tmpfs after those
    // writable `--bind`s and before mounting `tmp_dir`, `analysis_dir`, or replay staging inside it.
    if sb.writable.iter().any(|w| bound_writable(w) && under(&sb.ferret_home, w))
        || non_tmp_holders.iter().any(|h| under(&sb.ferret_home, h))
    {
        args.extend(["--tmpfs".to_string(), sb.ferret_home.display().to_string()]);
    }
    let mounted_protected = |path: &Path| -> bool {
        path != sb.ferret_home.as_path() && (!under(path, &sb.ferret_home) || (sb.replay && under(path, &sb.workspace)))
    };
    for path in sb.protected.iter().chain(&sb.git_dirs) {
        if mounted_protected(path) {
            bind(&mut args, "--ro-bind", path);
        }
    }
    let inside_tmp = sb.inside_tmp_protected();
    let tmp_bound = !inside_tmp.iter().any(|p| under(&sb.tmp_dir, p));
    if tmp_bound {
        bind(&mut args, "--bind", &sb.tmp_dir);
        let mut tmp_holders: Vec<PathBuf> = all_holders
            .iter()
            .filter(|h| {
                under(h, &sb.tmp_dir) && *h != &sb.tmp_dir && !sb.protected.contains(h) && !sb.git_dirs.contains(h)
            })
            .cloned()
            .collect();
        tmp_holders.sort_by(|a, b| a.components().count().cmp(&b.components().count()).then_with(|| a.cmp(b)));
        for h in &tmp_holders {
            bind(&mut args, "--bind", h);
        }
    }
    for path in &inside_tmp {
        bind(&mut args, "--ro-bind", path);
    }
    // The harness's staging of binary-analysis inputs: readable, never writable. It may not exist yet (it is
    // made on first use), so a missing one is not an error.
    let analysis_mounted = !sb.replay && under(&sb.analysis_dir, &sb.ferret_home);
    if analysis_mounted {
        let dir = sb.analysis_dir.display().to_string();
        args.extend(["--ro-bind-try".to_string(), dir.clone(), dir]);
    }
    let workspace_state = sb.workspace.join(".ferret");
    let state_is_ferret_home = workspace_state == sb.ferret_home;
    for path in sb.unreadable.iter().chain(&sb.credentials) {
        let restored =
            sb.writable.iter().any(|root| bound_writable(root) && under(path, root) && !under(path, &sb.ferret_home))
                || sb.protected.iter().chain(&sb.git_dirs).any(|root| mounted_protected(root) && under(path, root))
                || (tmp_bound && under(path, &sb.tmp_dir))
                || inside_tmp.iter().any(|root| under(path, root))
                || (analysis_mounted && under(path, &sb.analysis_dir));
        if !restored && (under(path, &sb.ferret_home) || hidden_home.is_some_and(|home| under(path, home))) {
            continue;
        }
        if under(path, &workspace_state) && (!state_is_ferret_home || !restored) {
            continue;
        }
        match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_symlink() => {}
            Ok(meta) if meta.is_dir() => {
                let p = path.display().to_string();
                args.extend(["--tmpfs".to_string(), p.clone(), "--remount-ro".to_string(), p]);
            }
            Ok(_) => {
                args.extend(["--ro-bind".to_string(), "/dev/null".to_string(), path.display().to_string()]);
            }
            Err(_) => {}
        }
    }
    if !state_is_ferret_home {
        args.extend(["--tmpfs".to_string(), workspace_state.display().to_string()]);
        // Uploads (`docs/UPLOADS.md`) are the one part of the hidden `.ferret` the commands may read. The bind goes
        // before the remount: the tmpfs is read-only afterwards and could no longer take the mount point.
        let uploads = workspace_state.join("uploads");
        if std::fs::symlink_metadata(&uploads).is_ok_and(|m| m.is_dir()) {
            let p = uploads.display().to_string();
            args.extend(["--ro-bind-try".to_string(), p.clone(), p]);
        }
        args.extend(["--remount-ro".to_string(), workspace_state.display().to_string()]);
    }
    // Only these top mounts become read-only; the scoped writable workspace/temp bind mounts below
    // them keep their own access modes.
    for path in hidden_home.into_iter().chain(std::iter::once(&sb.ferret_home)) {
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
        "ferret-confined-close".to_string(),
        script.to_string(),
    ]);
    ("/bin/bash".to_string(), args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferret_core::config::SandboxMode;

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
        assert!(pin(std::slice::from_ref(&ws), &[ws.join("missing-protection")], &[], &[], &[], &[]).is_err());
        let alias = ws.join("alias");
        std::os::unix::fs::symlink(&outside, &alias).unwrap();
        assert!(pin(&[alias], &[], &[], &[], &[], &[]).is_err());
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
        sb.linux_pins =
            pin(&sb.writable, &sb.protected, &sb.unreadable, &sb.credentials, &sb.git_dirs, &sb.holders()).unwrap();
        let (prog, args) = command(&sb, "printf 'literal $()'; true");
        assert_eq!(prog, "/bin/bash");
        assert!(args.iter().any(|x| x == "--unshare-all"));
        assert!(args.iter().any(|x| x == "--new-session"));
        let (_, pty_args) = pty_command(&sb, "printf 'literal $()'; true");
        assert!(!pty_args.iter().any(|x| x == "--new-session"));
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

    #[test]
    fn the_hidden_workspace_state_keeps_uploads_readable_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let (ws, tmp, home) = (root.join("ws"), root.join("tmp"), root.join("home"));
        for p in [&ws, &tmp, &home, &ws.join(".ferret/uploads")] {
            std::fs::create_dir_all(p).unwrap();
        }
        let cfg = SandboxCfg { protect_credentials: false, ..SandboxCfg::default() };
        let mut sb = Sandbox::new(&cfg, &ws, &tmp, &home, None).unwrap();
        sb.mode = SandboxMode::Bubblewrap;
        sb.linux_filter = Some(home.join("sandbox/filter.bpf"));
        sb.linux_pins =
            pin(&sb.writable, &sb.protected, &sb.unreadable, &sb.credentials, &sb.git_dirs, &sb.holders()).unwrap();
        let state = ws.join(".ferret").display().to_string();
        let uploads = ws.join(".ferret/uploads").display().to_string();
        let (_, args) = command(&sb, "true");
        let at = |pat: &[&str]| args.windows(pat.len()).position(|w| w == pat);
        let hide = at(&["--tmpfs", &state]).expect("state hidden");
        let bind = at(&["--ro-bind-try", &uploads, &uploads]).expect("uploads bound");
        let remount = at(&["--remount-ro", &state]).expect("state read-only");
        assert!(hide < bind && bind < remount, "{args:?}");
        // Without an uploads folder there is nothing to bind.
        std::fs::remove_dir(ws.join(".ferret/uploads")).unwrap();
        let (_, args) = command(&sb, "true");
        assert!(!args.iter().any(|a| a == &uploads), "{args:?}");
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
        // Verify compile-time syscall numbers match libc on this Linux target.
        let expected: &[u32] = &[
            libc::SYS_socket as u32,
            libc::SYS_socketpair as u32,
            libc::SYS_connect as u32,
            libc::SYS_bind as u32,
            libc::SYS_listen as u32,
            libc::SYS_accept as u32,
            libc::SYS_accept4 as u32,
            libc::SYS_sendto as u32,
            libc::SYS_sendmsg as u32,
            libc::SYS_sendmmsg as u32,
            libc::SYS_io_uring_setup as u32,
            libc::SYS_userfaultfd as u32,
            libc::SYS_ptrace as u32,
            libc::SYS_bpf as u32,
            libc::SYS_keyctl as u32,
            libc::SYS_add_key as u32,
            libc::SYS_request_key as u32,
            libc::SYS_process_vm_readv as u32,
            libc::SYS_process_vm_writev as u32,
        ];
        #[cfg(target_arch = "x86_64")]
        assert_eq!(DENIED_SYSCALLS_X86_64, expected);
        #[cfg(target_arch = "aarch64")]
        assert_eq!(DENIED_SYSCALLS_AARCH64, expected);
    }

    #[test]
    fn seccomp_bpf_blocks_network_and_kernel_escape_syscalls_on_x86_64_and_aarch64() {
        fn decode_denied(bytes: &[u8]) -> (u32, bool, Vec<u32>) {
            assert_eq!(bytes.len() % 8, 0);
            let insns: Vec<(u16, u8, u8, u32)> = bytes
                .as_chunks::<8>()
                .0
                .iter()
                .map(|c| {
                    (
                        u16::from_ne_bytes([c[0], c[1]]),
                        c[2],
                        c[3],
                        u32::from_ne_bytes([c[4], c[5], c[6], c[7]]),
                    )
                })
                .collect();
            let arch = insns[1].3;
            let has_x32 = insns.iter().any(|&(op, _, _, k)| op == 0x45 && k == 0x4000_0000);
            let mut denied = Vec::new();
            for pair in insns.windows(2) {
                if pair[0].0 == 0x15 && pair[0].1 == 0 && pair[0].2 == 1 && pair[1] == (0x06, 0, 0, 0x0005_0000 | LINUX_EPERM) {
                    denied.push(pair[0].3);
                }
            }
            assert_eq!(*insns.last().unwrap(), (0x06, 0, 0, 0x7fff_0000));
            (arch, has_x32, denied)
        }
        let (x_arch, x_x32, x_denied) = decode_denied(&filter_for_arch(SeccompArch::X86_64));
        assert_eq!(x_arch, 0xc000_003e);
        assert!(x_x32);
        assert_eq!(x_denied, DENIED_SYSCALLS_X86_64);
        for nr in [323, 101, 321, 250, 248, 249, 310, 311, 425] {
            assert!(x_denied.contains(&nr), "x86_64 syscall {nr} must be denied");
        }

        let (a_arch, a_x32, a_denied) = decode_denied(&filter_for_arch(SeccompArch::Aarch64));
        assert_eq!(a_arch, 0xc000_00b7);
        assert!(!a_x32);
        assert_eq!(a_denied, DENIED_SYSCALLS_AARCH64);
        for nr in [282, 117, 280, 219, 217, 218, 270, 271, 425] {
            assert!(a_denied.contains(&nr), "aarch64 syscall {nr} must be denied");
        }
    }

    #[test]
    fn command_masks_ferret_home_in_writable_roots_pins_holders_and_remounts_unreadable_ro() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let home = root.join(".ferret");
        let tmp = home.join("sessions/s1/tmp");
        let secret_dir = root.join("secret_dir");
        let locked = root.join("tools/hooks/post-checkout");
        for p in [&tmp, &secret_dir, locked.parent().unwrap()] {
            std::fs::create_dir_all(p).unwrap();
        }
        std::fs::write(&locked, "#!/bin/sh\n").unwrap();
        let cfg = SandboxCfg {
            protect_credentials: false,
            protected_paths: vec!["tools/hooks/post-checkout".into()],
            unreadable_paths: vec!["secret_dir".into()],
            ..SandboxCfg::default()
        };
        let mut sb = Sandbox::with_home(&cfg, &root, &tmp, &home, None, None).unwrap();
        sb.mode = SandboxMode::Bubblewrap;
        sb.linux_filter = Some(home.join("sandbox/filter.bpf"));
        sb.linux_pins =
            pin(&sb.writable, &sb.protected, &sb.unreadable, &sb.credentials, &sb.git_dirs, &sb.holders()).unwrap();
        let (_, args) = command(&sb, "true");
        let root_s = root.to_str().unwrap();
        let home_s = home.to_str().unwrap();
        let tmp_s = tmp.to_str().unwrap();
        let secret_s = secret_dir.to_str().unwrap();
        let tools_s = root.join("tools").to_str().unwrap().to_string();
        let hooks_s = root.join("tools/hooks").to_str().unwrap().to_string();

        // Must never re-bind live `ferret_home` read-only; must re-mask `ferret_home` AFTER writable root `--bind`
        // and BEFORE mounting `tmp_dir`, without clobbering `tmp_dir` afterwards when `ws/.ferret == ferret_home`.
        assert!(!args.windows(3).any(|w| w[0] == "--ro-bind" && w[2] == home_s), "{args:?}");
        let ws_bind = args.windows(3).position(|w| w[0] == "--bind" && w[2] == root_s).unwrap();
        let home_tmpfs_after =
            args[ws_bind..].windows(2).position(|w| w == ["--tmpfs", home_s]).map(|i| ws_bind + i).unwrap();
        let tmp_bind = args.windows(3).position(|w| w[0] == "--bind" && w[2] == tmp_s).unwrap();
        assert!(tmp_bind > home_tmpfs_after, "{args:?}");
        assert!(!args[tmp_bind..].windows(2).any(|w| w == ["--tmpfs", home_s]), "{args:?}");

        // Holders of multi-component `protected_paths` must be pinned/self-bound inside writable root.
        assert!(args.windows(3).any(|w| w[0] == "--bind" && w[1].starts_with("/proc/") && w[2] == tools_s));
        assert!(args.windows(3).any(|w| w[0] == "--bind" && w[1].starts_with("/proc/") && w[2] == hooks_s));

        // Unreadable directories must be remounted read-only.
        assert!(args.windows(4).any(|w| w == ["--tmpfs", secret_s, "--remount-ro", secret_s]), "{args:?}");
    }

    #[test]
    fn isolated_replay_command_under_home_and_readonly_never_rebinds_actor_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let user_home = root.join("user");
        let actor_ws = user_home.join("project");
        let ferret_home = user_home.join("ferret-state");
        let tmp = ferret_home.join("sessions/s1/tmp");
        let staging = ferret_home.join("oracle-runs/run-1");
        let (staged_ws, staged_tmp) = (staging.join("workspace"), staging.join("tmp"));
        for d in [actor_ws.join(".ferret/oracle-secrets"), tmp.clone(), staged_ws.clone(), staged_tmp.clone()] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(actor_ws.join("src.txt"), "untrusted").unwrap();
        std::fs::write(actor_ws.join(".ferret/oracle-secrets/k"), "secret").unwrap();
        let cfg = SandboxCfg {
            protect_credentials: true,
            protected_paths: vec![actor_ws.display().to_string()],
            ..SandboxCfg::default()
        };
        let mut actor = Sandbox::with_home(&cfg, &actor_ws, &tmp, &ferret_home, None, Some(user_home)).unwrap();
        actor.mode = SandboxMode::Bubblewrap;
        actor.linux_filter = Some(ferret_home.join("sandbox/filter.bpf"));
        let replay = actor.isolated_replay(&staged_ws, &staged_tmp).unwrap();
        let (_, args) = command(&replay, "true");
        let actor_s = actor_ws.to_str().unwrap();
        assert!(
            !args.windows(3).any(|w| (w[0] == "--bind" || w[0] == "--ro-bind") && w[2].starts_with(actor_s)),
            "replay must never bind actor workspace or its .ferret: {args:?}"
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
mod native_tests {
    use super::*;
    use ferret_core::config::SandboxMode;
    use std::os::unix::fs::symlink;
    use std::process::Command;

    fn required_launcher() -> bool {
        if Path::new(super::super::BWRAP).exists() {
            return true;
        }
        assert!(
            std::env::var_os("FERRET_BWRAP_REQUIRED").is_none(),
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
        for path in [ws.join(".ferret"), tmp.clone(), ws.join(".git/hooks")] {
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
        let out = run(&sb, "echo source > source.txt; echo own > \"$TMPDIR/own\"; echo private > /tmp/ferret-private; test -r source.txt");
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
        let out = run(&sb, &format!("FERRET_BWRAP_SOCKET_PROBE=1 '{exe}' --ignored --exact sandbox::linux::native_tests::socket_probe --nocapture"));
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
        assert!(std::env::var_os("FERRET_BWRAP_SOCKET_PROBE").is_some());
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
        let home = user_home.join("ferret-state");
        let tmp = home.join("sessions/test/tmp");
        for path in [ws.join(".ferret"), tmp.clone()] {
            std::fs::create_dir_all(path).unwrap();
        }
        let cfg = SandboxCfg { mode: SandboxMode::Bubblewrap, ..SandboxCfg::default() };
        let sb = Sandbox::with_home(&cfg, &ws, &tmp, &home, None, Some(user_home.clone())).unwrap();
        for path in [user_home.join(".aws/credentials"), ws.join(".ferret/oracle-secrets/key"), home.join("token")] {
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

    #[test]
    fn bubblewrap_native_replay_cannot_import_actor_workspace_extra_or_sibling_temp() {
        if !required_launcher() {
            return;
        }
        let (root, mut actor, ws) = fixture(false);
        let extra = root.path().join("actor-library-cache");
        let sibling = actor.ferret_home.join("sessions/other-agent/tmp");
        for path in [&extra, &sibling] {
            std::fs::create_dir_all(path).unwrap();
        }
        let paths = [ws.join("library.py"), extra.join("dependency.so"), sibling.join("payload.py")];
        for path in &paths {
            std::fs::write(path, "actor controlled").unwrap();
        }
        // A read-only judge retains this origin as metadata, without a write grant to it.
        actor.replay_untrusted.push(extra.clone());
        let private = actor.oracle_staging_root().join("test-replay");
        let workspace = private.join("workspace");
        let tmp = private.join("tmp");
        for path in [&workspace, &tmp] {
            std::fs::create_dir_all(path).unwrap();
        }
        std::fs::write(workspace.join("pinned.py"), "trusted snapshot").unwrap();
        let replay = actor.isolated_replay(&workspace, &tmp).unwrap();
        for path in &paths {
            assert!(replay.check_read(path).is_err());
            let out = run(&replay, &format!("cat '{}'", path.display()));
            assert!(!out.status.success(), "replay read actor origin {}", path.display());
        }
        let future = actor.ferret_home.join("sessions/future-agent/tmp");
        std::fs::create_dir_all(&future).unwrap();
        std::fs::write(future.join("payload.py"), "late actor import").unwrap();
        assert!(!run(&replay, &format!("cat '{}/payload.py'", future.display())).status.success());
        assert!(run(&replay, "cat pinned.py; echo result > \"$TMPDIR/result\"").status.success());
        assert!(tmp.join("result").exists());
        assert!(!run(&replay, "echo changed > pinned.py").status.success());
    }

    #[test]
    fn bubblewrap_native_replay_hides_actor_ferret_and_readonly_workspace_under_home() {
        if !required_launcher() {
            return;
        }
        let executable = std::env::current_exe().unwrap();
        let root = tempfile::tempdir_in(executable.parent().unwrap()).unwrap();
        let user_home = root.path().join("user-home");
        let actor_ws = user_home.join("project");
        let ferret_home = user_home.join("ferret-state");
        let tmp = ferret_home.join("sessions/judge/tmp");
        let staged = ferret_home.join("oracle-runs/r1");
        let (staged_ws, staged_tmp) = (staged.join("workspace"), staged.join("tmp"));
        for p in [actor_ws.join(".ferret/oracle-secrets"), tmp.clone(), staged_ws.clone(), staged_tmp.clone()] {
            std::fs::create_dir_all(p).unwrap();
        }
        std::fs::write(actor_ws.join("leak.txt"), "untrusted").unwrap();
        std::fs::write(actor_ws.join(".ferret/oracle-secrets/k"), "secret").unwrap();
        std::fs::write(staged_ws.join("pinned.txt"), "ok").unwrap();
        let cfg = SandboxCfg {
            mode: SandboxMode::Bubblewrap,
            protect_credentials: true,
            protected_paths: vec![actor_ws.display().to_string()],
            ..SandboxCfg::default()
        };
        let actor = Sandbox::with_home(&cfg, &actor_ws, &tmp, &ferret_home, None, Some(user_home)).unwrap();
        let replay = actor.isolated_replay(&staged_ws, &staged_tmp).unwrap();
        assert!(!run(&replay, &format!("test -e '{}'", actor_ws.join("leak.txt").display())).status.success());
        assert!(!run(&replay, &format!("test -e '{}'", actor_ws.join(".ferret/oracle-secrets/k").display()))
            .status
            .success());
        assert!(run(&replay, "cat pinned.txt").status.success());
    }

    #[test]
    fn bubblewrap_native_blocks_holder_rename_and_unreadable_dir_writes() {
        if !required_launcher() {
            return;
        }
        let executable = std::env::current_exe().unwrap();
        let root = tempfile::tempdir_in(executable.parent().unwrap()).unwrap();
        let ws = root.path().join("ws");
        let home = root.path().join("home");
        let tmp = home.join("sessions/t/tmp");
        let hooks = ws.join("tools/hooks");
        let secret_dir = ws.join("secret_dir");
        for p in [ws.join(".ferret"), tmp.clone(), hooks.clone(), secret_dir.clone()] {
            std::fs::create_dir_all(p).unwrap();
        }
        std::fs::write(hooks.join("post-checkout"), "original").unwrap();
        std::fs::write(secret_dir.join("k"), "secret").unwrap();
        let cfg = SandboxCfg {
            mode: SandboxMode::Bubblewrap,
            protect_credentials: false,
            protected_paths: vec!["tools/hooks".into()],
            unreadable_paths: vec!["secret_dir".into()],
            ..SandboxCfg::default()
        };
        let sb = Sandbox::new(&cfg, &ws, &tmp, &home, None).unwrap();
        assert!(!run(&sb, "mv tools tools.bak").status.success());
        assert!(!run(&sb, "touch secret_dir/new").status.success());
        assert!(run(&sb, "echo ok > tools/sibling.txt").status.success());
    }
}
