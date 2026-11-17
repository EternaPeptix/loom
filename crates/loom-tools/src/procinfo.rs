//! Process inspection that never starts a process: libproc and `sysctl` on macOS, `/proc` on Linux.
//!
//! CONTRACT.
//!
//! Everything here reads the kernel's tables directly. Nothing runs `ps`, `lsof` or any other program, so
//! it still works when the process table is full (a fork bomb, a spray of children) and costs microseconds
//! instead of a fork per look (`docs/MONITOR.md` §2.2, E3; the audit's "ps polling" and "no kill when ps
//! cannot spawn" findings). A read the kernel refuses is `None` ("unknown"), never "gone": callers decide
//! what to do with an unknown (`proc` still signals a group it cannot inspect, unless its leader is known to
//! be a different process).
//!
//! - `info(pid)`: `ProcInfo` (`pid`, `ppid`, `pgid`, `uid`, `start`, `zombie`) of one process, `None` when
//!   it is gone or unreadable. `start` is text comparable only with another `start` (macOS: seconds and
//!   microseconds of the start; Linux: the start time in ticks), what a pid record stores to tell a pid's
//!   reuse. `zombie` is a process that has exited and is not yet reaped (its descriptors are closed).
//! - `pids()`: every process id on the machine, `None` when the table cannot be read.
//! - `group(pgid)`: the members of a process group (zombies included, flagged), `Some(empty)` when the group
//!   is empty and `None` when the table cannot be read.
//! - `command_line(pid)`: `CommandLine { args, env }` of a process of this user, `None` when unreadable (the
//!   process is gone, belongs to another user or is exiting). `split_procargs` is the macOS format's parser.
//! - `listeners(pid)`: the TCP sockets in the listening state and the bound UDP sockets of a process
//!   (`Listener { pid, proto, addr, port }`), empty when it has none or they cannot be read.
//! - `exe_path(pid)`: the path of the executable a process runs, when the kernel gives it.
//! - `process_count()`: how many processes the machine has (an upper bound of this user's).
//! - `nproc_limit(base, headroom, current)`, `nproc_base()` and `set_nproc(limit)`: the RLIMIT_NPROC of a
//!   sandboxed command. The limit counts every process of the user, so a command whose limit is
//!   `base - headroom` stops forking `headroom` processes before the user's own limit, and the daemon (which
//!   has not lowered its own) can still fork its responder and its notifier. The limit is never below
//!   `current + NPROC_MIN_ROOM` (a command must be able to run on a busy machine) and never above `base`.
//!   `set_nproc` only calls `setrlimit` and is safe in a `pre_exec` hook; it lowers the soft and hard limit
//!   together, so the command cannot raise it again.
//!
//! Tests required: `a_process_is_described_by_the_kernel_and_a_gone_one_is_not`,
//! `a_group_lists_its_members_with_zombies_flagged`, `a_command_line_is_read_without_ps`,
//! `procargs_are_split_into_arguments_and_environment` (malformed input included),
//! `a_listening_socket_is_found_by_its_process` (macOS and Linux), `the_pid_table_lists_this_process`,
//! `the_nproc_limit_leaves_headroom_and_never_stops_a_command_from_running` and
//! `an_unreadable_table_reads_as_unknown_not_as_gone`.

use std::io;

/// The least number of processes beyond the ones that exist that a command's RLIMIT_NPROC leaves it.
pub const NPROC_MIN_ROOM: u64 = 64;

/// One process, as the kernel describes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    pub pgid: u32,
    pub uid: u32,
    /// Comparable only with another start of the same process (see the contract).
    pub start: String,
    /// Exited, not yet reaped.
    pub zombie: bool,
}

/// The arguments and the environment a process was started with.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CommandLine {
    pub args: Vec<String>,
    pub env: Vec<String>,
}

/// What a socket of a process listens (TCP) or is bound (UDP) on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn name(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct Listener {
    pub pid: u32,
    pub proto: Proto,
    /// The local address as text (`127.0.0.1`, `::1`, `0.0.0.0`).
    pub addr: String,
    pub port: u16,
}

#[cfg(test)]
thread_local! {
    /// Makes the table unreadable on this thread, as a table the kernel refuses is.
    pub(crate) static UNREADABLE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn unreadable() -> bool {
    #[cfg(test)]
    {
        UNREADABLE.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        false
    }
}

/// Splits the data of `sysctl kern.procargs2` (macOS): a native-endian `argc`, the executable path, padding
/// NULs, `argc` arguments, then the environment, each NUL-terminated. `None` when the data is too short or
/// holds fewer arguments than it says.
pub fn split_procargs(raw: &[u8]) -> Option<CommandLine> {
    let argc = i32::from_ne_bytes(raw.get(..4)?.try_into().ok()?);
    let argc = usize::try_from(argc).ok()?;
    let rest = raw.get(4..)?;
    // The executable path, then the NULs that pad it.
    let after_path = rest.iter().position(|b| *b == 0)?;
    let rest = rest.get(after_path..)?;
    let start = rest.iter().position(|b| *b != 0).unwrap_or(rest.len());
    let rest = rest.get(start..)?;
    let mut strings = rest.split(|b| *b == 0).map(|s| String::from_utf8_lossy(s).into_owned());
    let mut args = Vec::new();
    for _ in 0..argc {
        args.push(strings.next()?);
    }
    // The environment ends at the first empty string (the data ends with NULs).
    let env = strings.take_while(|s| !s.is_empty()).collect();
    Some(CommandLine { args, env })
}

#[cfg(target_os = "macos")]
mod sys {
    use super::*;
    use std::mem::size_of;

    const PROC_PIDFDSOCKETINFO: libc::c_int = 3;
    // Offsets into `struct socket_fdinfo` (sys/proc_info.h: 24 bytes of `proc_fileinfo`, then `socket_info`).
    const OFF_KIND: usize = 256;
    const OFF_PROTO: usize = 264;
    // Within `in_sockinfo` (at OFF_PROTO): `insi_lport`, `insi_vflag`, `insi_laddr`; `tcpsi_state` follows it.
    const IN_LPORT: usize = 4;
    const IN_VFLAG: usize = 24;
    const IN_LADDR: usize = 48;
    const IN_SIZE: usize = 80;
    const SOCKINFO_IN: i32 = 1;
    const SOCKINFO_TCP: i32 = 2;
    const TSI_S_LISTEN: i32 = 1;
    const INI_IPV4: u8 = 1;
    const INI_IPV6: u8 = 2;
    /// More than `socket_fdinfo` is long (792 bytes).
    const SOCKET_INFO_BYTES: usize = 1024;

    fn pid_arg(pid: u32) -> Option<libc::c_int> {
        libc::c_int::try_from(pid).ok().filter(|p| *p > 0)
    }

    pub fn info(pid: u32) -> Option<ProcInfo> {
        if unreadable() {
            return None;
        }
        let p = pid_arg(pid)?;
        let size = i32::try_from(size_of::<libc::proc_bsdinfo>()).ok()?;
        // The argument asks for a zombie's entry: the kernel answers an ordinary look only for a live process.
        let look = |zombie: u64| {
            // SAFETY: proc_bsdinfo is plain integers and arrays of them, for which all-zero is a valid value.
            let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
            // SAFETY: the buffer is `size` bytes of a live, exclusively borrowed struct.
            let n = unsafe {
                libc::proc_pidinfo(
                    p,
                    libc::PROC_PIDTBSDINFO,
                    zombie,
                    (&mut info as *mut libc::proc_bsdinfo).cast(),
                    size,
                )
            };
            (n == size).then_some(info)
        };
        let info = look(0).or_else(|| look(1))?;
        Some(ProcInfo {
            pid,
            ppid: info.pbi_ppid,
            pgid: info.pbi_pgid,
            uid: info.pbi_uid,
            start: format!("{}.{:06}", info.pbi_start_tvsec, info.pbi_start_tvusec),
            zombie: info.pbi_status == libc::SZOMB,
        })
    }

    pub fn pids() -> Option<Vec<u32>> {
        if unreadable() {
            return None;
        }
        let mut slots = 2048usize;
        loop {
            let mut buf: Vec<libc::pid_t> = vec![0; slots];
            let bytes = i32::try_from(slots.checked_mul(size_of::<libc::pid_t>())?).ok()?;
            // SAFETY: the buffer is `bytes` bytes of live, exclusively borrowed integers.
            let n = unsafe { libc::proc_listallpids(buf.as_mut_ptr().cast(), bytes) };
            if n < 0 {
                return None;
            }
            // The count is of entries; a full buffer may have cut the list, so it is made larger.
            let filled = usize::try_from(n).unwrap_or(0).min(slots);
            if filled >= slots.saturating_sub(16) {
                slots = slots.checked_mul(2).filter(|s| *s <= 1 << 20)?;
                continue;
            }
            return Some(buf.iter().take(filled).filter_map(|p| u32::try_from(*p).ok()).filter(|p| *p > 0).collect());
        }
    }

    pub fn group_pids(pgid: u32) -> Option<Vec<u32>> {
        if unreadable() {
            return None;
        }
        let pg = pid_arg(pgid)?;
        let mut slots = 1024usize;
        loop {
            let mut buf: Vec<libc::pid_t> = vec![0; slots];
            let bytes = i32::try_from(slots.checked_mul(size_of::<libc::pid_t>())?).ok()?;
            // SAFETY: the buffer is `bytes` bytes of live, exclusively borrowed integers.
            let n = unsafe { libc::proc_listpgrppids(pg, buf.as_mut_ptr().cast(), bytes) };
            if n < 0 {
                return None;
            }
            // Whether the call counts entries or bytes, what it did not write is still zero.
            let pids: Vec<u32> = buf.iter().filter_map(|p| u32::try_from(*p).ok()).filter(|p| *p > 0).collect();
            if pids.len() >= slots.saturating_sub(16) {
                slots = slots.checked_mul(2).filter(|s| *s <= 1 << 20)?;
                continue;
            }
            return Some(pids);
        }
    }

    fn procargs(pid: u32) -> Option<Vec<u8>> {
        let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid_arg(pid)?];
        let mut size: libc::size_t = 0;
        for _ in 0..3 {
            // SAFETY: `mib` has 3 entries; a null buffer asks for the size.
            let rc =
                unsafe { libc::sysctl(mib.as_mut_ptr(), 3, std::ptr::null_mut(), &mut size, std::ptr::null_mut(), 0) };
            if rc != 0 || size == 0 {
                return None;
            }
            size = size.checked_add(4096)?;
            let mut buf = vec![0u8; size];
            // SAFETY: `buf` is `size` writable bytes; `size` is updated to what was written.
            let rc = unsafe {
                libc::sysctl(mib.as_mut_ptr(), 3, buf.as_mut_ptr().cast(), &mut size, std::ptr::null_mut(), 0)
            };
            if rc == 0 {
                buf.truncate(size);
                return Some(buf);
            }
            if io::Error::last_os_error().raw_os_error() != Some(libc::ENOMEM) {
                return None;
            }
        }
        None
    }

    pub fn command_line(pid: u32) -> Option<CommandLine> {
        if unreadable() {
            return None;
        }
        split_procargs(&procargs(pid)?)
    }

    fn le_u32(bytes: &[u8], at: usize) -> Option<u32> {
        Some(u32::from_ne_bytes(bytes.get(at..at.checked_add(4)?)?.try_into().ok()?))
    }

    fn fd_listener(pid: u32, fd: i32) -> Option<Listener> {
        let p = pid_arg(pid)?;
        let mut buf = [0u8; SOCKET_INFO_BYTES];
        let size = i32::try_from(SOCKET_INFO_BYTES).ok()?;
        // SAFETY: the buffer is `size` writable bytes.
        let n = unsafe { libc::proc_pidfdinfo(p, fd, PROC_PIDFDSOCKETINFO, buf.as_mut_ptr().cast(), size) };
        let n = usize::try_from(n).ok().filter(|n| *n >= OFF_PROTO + IN_SIZE)?;
        let bytes = buf.get(..n)?;
        let kind = i32::from_ne_bytes(bytes.get(OFF_KIND..OFF_KIND + 4)?.try_into().ok()?);
        let proto = match kind {
            SOCKINFO_TCP => {
                let state =
                    i32::from_ne_bytes(bytes.get(OFF_PROTO + IN_SIZE..OFF_PROTO + IN_SIZE + 4)?.try_into().ok()?);
                if state != TSI_S_LISTEN {
                    return None;
                }
                Proto::Tcp
            }
            SOCKINFO_IN => Proto::Udp,
            _ => return None,
        };
        // The port is kept in network byte order in the low 16 bits of an int.
        let raw = le_u32(bytes, OFF_PROTO + IN_LPORT)?;
        let port = u16::from_be(u16::try_from(raw & 0xffff).ok()?);
        if port == 0 {
            return None;
        }
        let vflag = *bytes.get(OFF_PROTO + IN_VFLAG)?;
        let laddr = bytes.get(OFF_PROTO + IN_LADDR..OFF_PROTO + IN_LADDR + 16)?;
        let addr = if vflag & INI_IPV6 != 0 && vflag & INI_IPV4 == 0 {
            let octets: [u8; 16] = laddr.try_into().ok()?;
            std::net::Ipv6Addr::from(octets).to_string()
        } else {
            let octets: [u8; 4] = laddr.get(12..16)?.try_into().ok()?;
            std::net::Ipv4Addr::from(octets).to_string()
        };
        Some(Listener { pid, proto, addr, port })
    }

    pub fn listeners(pid: u32) -> Vec<Listener> {
        let Some(p) = pid_arg(pid) else { return Vec::new() };
        // SAFETY: a null buffer asks for the size of the descriptor list.
        let need = unsafe { libc::proc_pidinfo(p, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
        let Some(need) = usize::try_from(need).ok().filter(|n| *n > 0) else { return Vec::new() };
        let entry = size_of::<libc::proc_fdinfo>();
        let slots = need / entry + 16;
        // SAFETY: proc_fdinfo is two integers, for which all-zero is a valid value.
        let mut fds: Vec<libc::proc_fdinfo> = (0..slots).map(|_| unsafe { std::mem::zeroed() }).collect();
        let Ok(bytes) = i32::try_from(slots * entry) else { return Vec::new() };
        // SAFETY: the buffer is `bytes` bytes of live, exclusively borrowed structs.
        let n = unsafe { libc::proc_pidinfo(p, libc::PROC_PIDLISTFDS, 0, fds.as_mut_ptr().cast(), bytes) };
        let count = usize::try_from(n).unwrap_or(0) / entry;
        let mut out: Vec<Listener> = fds
            .iter()
            .take(count)
            .filter(|f| f.proc_fdtype == libc::PROX_FDTYPE_SOCKET as u32)
            .filter_map(|f| fd_listener(pid, f.proc_fd))
            .collect();
        out.sort();
        out.dedup();
        out
    }
}

#[cfg(target_os = "linux")]
mod sys {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    pub fn info(pid: u32) -> Option<ProcInfo> {
        if unreadable() {
            return None;
        }
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        // Fields after the parenthesised name begin at field 3: state, ppid, pgrp, … starttime (field 22).
        let rest = stat.rsplit_once(')')?.1;
        let mut fields = rest.split_whitespace();
        let state = fields.next()?;
        let ppid = fields.next()?.parse().ok()?;
        let pgid = fields.next()?.parse().ok()?;
        let start = fields.nth(16)?.to_string();
        let uid = std::fs::metadata(format!("/proc/{pid}")).ok()?.uid();
        Some(ProcInfo { pid, ppid, pgid, uid, start, zombie: state.starts_with('Z') })
    }

    pub fn pids() -> Option<Vec<u32>> {
        if unreadable() {
            return None;
        }
        let entries = std::fs::read_dir("/proc").ok()?;
        Some(entries.flatten().filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok()).collect())
    }

    pub fn group_pids(pgid: u32) -> Option<Vec<u32>> {
        let all = pids()?;
        Some(all.into_iter().filter(|p| info(*p).is_some_and(|i| i.pgid == pgid)).collect())
    }

    pub fn command_line(pid: u32) -> Option<CommandLine> {
        if unreadable() {
            return None;
        }
        let split = |raw: Vec<u8>| -> Vec<String> {
            raw.split(|b| *b == 0).filter(|s| !s.is_empty()).map(|s| String::from_utf8_lossy(s).into_owned()).collect()
        };
        let args = split(std::fs::read(format!("/proc/{pid}/cmdline")).ok()?);
        let env = std::fs::read(format!("/proc/{pid}/environ")).map(split).unwrap_or_default();
        Some(CommandLine { args, env })
    }

    fn table(path: &str, v6: bool, proto: Proto) -> Vec<(u64, String, u16)> {
        let Ok(text) = std::fs::read_to_string(path) else { return Vec::new() };
        text.lines()
            .skip(1)
            .filter_map(|line| {
                let f: Vec<&str> = line.split_whitespace().collect();
                let (local, state, inode) = (f.get(1)?, f.get(3)?, f.get(9)?);
                // 0A is TCP_LISTEN; a bound UDP socket is state 07.
                let wanted = if proto == Proto::Tcp { *state == "0A" } else { *state == "07" };
                if !wanted {
                    return None;
                }
                let (addr, port) = local.rsplit_once(':')?;
                let port = u16::from_str_radix(port, 16).ok()?;
                let addr = if v6 {
                    let mut octets = [0u8; 16];
                    for (i, chunk) in octets.chunks_mut(4).enumerate() {
                        let word = u32::from_str_radix(addr.get(i * 8..i * 8 + 8)?, 16).ok()?;
                        chunk.copy_from_slice(&word.to_ne_bytes());
                    }
                    std::net::Ipv6Addr::from(octets).to_string()
                } else {
                    let word = u32::from_str_radix(addr, 16).ok()?;
                    std::net::Ipv4Addr::from(word.to_ne_bytes()).to_string()
                };
                Some((inode.parse().ok()?, addr, port))
            })
            .collect()
    }

    pub fn listeners(pid: u32) -> Vec<Listener> {
        let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else { return Vec::new() };
        let inodes: std::collections::BTreeSet<u64> = fds
            .flatten()
            .filter_map(|e| {
                let target = std::fs::read_link(e.path()).ok()?;
                let text = target.to_str()?;
                text.strip_prefix("socket:[")?.strip_suffix(']')?.parse().ok()
            })
            .collect();
        let mut out = Vec::new();
        for (path, v6, proto) in [
            ("/proc/net/tcp", false, Proto::Tcp),
            ("/proc/net/tcp6", true, Proto::Tcp),
            ("/proc/net/udp", false, Proto::Udp),
            ("/proc/net/udp6", true, Proto::Udp),
        ] {
            for (inode, addr, port) in table(path, v6, proto) {
                if inodes.contains(&inode) {
                    out.push(Listener { pid, proto, addr, port });
                }
            }
        }
        out.sort();
        out.dedup();
        out
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod sys {
    use super::*;
    pub fn info(_pid: u32) -> Option<ProcInfo> {
        None
    }
    pub fn pids() -> Option<Vec<u32>> {
        None
    }
    pub fn group_pids(_pgid: u32) -> Option<Vec<u32>> {
        None
    }
    pub fn command_line(_pid: u32) -> Option<CommandLine> {
        None
    }
    pub fn listeners(_pid: u32) -> Vec<Listener> {
        Vec::new()
    }
}

/// The path of the executable a process runs, when the kernel gives it (empty for a process that has exited).
pub fn exe_path(pid: u32) -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let p = libc::c_int::try_from(pid).ok().filter(|p| *p > 0)?;
        let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        // SAFETY: the buffer is `PROC_PIDPATHINFO_MAXSIZE` writable bytes.
        let n = unsafe { libc::proc_pidpath(p, buf.as_mut_ptr().cast(), u32::try_from(buf.len()).ok()?) };
        let n = usize::try_from(n).ok().filter(|n| *n > 0)?;
        Some(String::from_utf8_lossy(buf.get(..n)?).into_owned())
    }
    #[cfg(target_os = "linux")]
    {
        let target = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
        Some(target.to_string_lossy().into_owned())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = pid;
        None
    }
}

/// One process; see the contract.
pub fn info(pid: u32) -> Option<ProcInfo> {
    sys::info(pid)
}

/// Every process id; see the contract.
pub fn pids() -> Option<Vec<u32>> {
    sys::pids()
}

/// The members of process group `pgid`; see the contract.
pub fn group(pgid: u32) -> Option<Vec<ProcInfo>> {
    let pids = sys::group_pids(pgid)?;
    // A member that exited while the list was read has no entry now; one that moved to another group is not one.
    Some(pids.into_iter().filter_map(info).filter(|p| p.pgid == pgid).collect())
}

/// The start of a process as `info` reports it.
pub fn start_of(pid: u32) -> Option<String> {
    info(pid).map(|p| p.start)
}

/// The arguments and environment of a process; see the contract.
pub fn command_line(pid: u32) -> Option<CommandLine> {
    sys::command_line(pid)
}

/// The listening TCP and bound UDP sockets of a process; see the contract.
pub fn listeners(pid: u32) -> Vec<Listener> {
    sys::listeners(pid)
}

/// How many processes exist.
pub fn process_count() -> Option<u64> {
    pids().and_then(|p| u64::try_from(p.len()).ok())
}

/// The process limit commands are measured against: this process's soft RLIMIT_NPROC, and on macOS no more
/// than `kern.maxprocperuid`. `None` when the limit is unlimited and nothing else says what it is.
pub fn nproc_base() -> Option<u64> {
    let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: `limit` is a valid, writable `rlimit`.
    if unsafe { libc::getrlimit(libc::RLIMIT_NPROC, &mut limit) } != 0 {
        return None;
    }
    let soft = (limit.rlim_cur != libc::RLIM_INFINITY).then_some(limit.rlim_cur);
    #[cfg(target_os = "macos")]
    let kernel = {
        let mut value: libc::c_int = 0;
        let mut size = std::mem::size_of::<libc::c_int>();
        // SAFETY: the name is NUL-terminated and `value` is `size` writable bytes.
        let rc = unsafe {
            libc::sysctlbyname(
                c"kern.maxprocperuid".as_ptr(),
                (&mut value as *mut libc::c_int).cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        (rc == 0).then(|| u64::try_from(value).ok()).flatten().filter(|v| *v > 0)
    };
    #[cfg(not(target_os = "macos"))]
    let kernel: Option<u64> = None;
    match (soft, kernel) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// The RLIMIT_NPROC of a command: `base - headroom`, at least `current + NPROC_MIN_ROOM`, at most `base`.
/// `None` when `headroom` is 0 (no limit is set).
pub fn nproc_limit(base: u64, headroom: u64, current: u64) -> Option<u64> {
    if headroom == 0 {
        return None;
    }
    let wanted = base.saturating_sub(headroom).max(current.saturating_add(NPROC_MIN_ROOM));
    Some(wanted.min(base))
}

/// The limit to give a command started now, for `headroom` processes of room: `None` when the headroom is 0
/// or the base limit is unknown.
pub fn nproc_limit_now(headroom: u64) -> Option<u64> {
    if headroom == 0 {
        return None;
    }
    let base = nproc_base()?;
    nproc_limit(base, headroom, process_count().unwrap_or(0))
}

/// Lowers this process's RLIMIT_NPROC (soft and hard) to `limit`. Only `setrlimit` runs, so it can be called
/// between `fork` and `exec`.
pub fn set_nproc(limit: u64) -> io::Result<()> {
    let value: libc::rlim_t = limit;
    let new = libc::rlimit { rlim_cur: value, rlim_max: value };
    // SAFETY: `new` is a valid `rlimit`.
    if unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &new) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt;

    struct Reap(std::process::Child);
    impl Drop for Reap {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn a_process_is_described_by_the_kernel_and_a_gone_one_is_not() {
        let me = info(std::process::id()).expect("this process");
        assert_eq!(me.pid, std::process::id());
        assert!(!me.zombie);
        // SAFETY: getppid/getpgrp/getuid take no arguments.
        let (ppid, pgid, uid) = unsafe { (libc::getppid(), libc::getpgrp(), libc::getuid()) };
        assert_eq!((i64::from(me.ppid), i64::from(me.pgid), me.uid), (i64::from(ppid), i64::from(pgid), uid));
        assert!(!me.start.is_empty());
        assert_eq!(start_of(me.pid), Some(me.start));
        let mut child = std::process::Command::new("/bin/sleep").arg("30").spawn().expect("spawn");
        let pid = child.id();
        assert!(info(pid).is_some());
        child.kill().expect("kill");
        child.wait().expect("reap");
        assert_eq!(info(pid), None);
        assert_eq!(info(0), None);
    }

    #[test]
    fn the_pid_table_lists_this_process() {
        let all = pids().expect("the table");
        assert!(all.contains(&std::process::id()));
        assert!(process_count().is_some_and(|n| n >= 1));
    }

    #[test]
    fn a_group_lists_its_members_with_zombies_flagged() {
        let leader = Reap(
            std::process::Command::new("/bin/bash")
                .args(["-c", "sleep 30 & sleep 30 & wait"])
                .process_group(0)
                .spawn()
                .expect("spawn"),
        );
        let pgid = leader.0.id();
        let mut members = Vec::new();
        for _ in 0..100 {
            members = group(pgid).expect("the table");
            if members.len() >= 3 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(members.len() >= 3, "{members:?}");
        assert!(members.iter().all(|m| m.pgid == pgid && !m.zombie), "{members:?}");
        assert!(members.iter().any(|m| m.pid == pgid));
        // SAFETY: kill(2) takes plain integers.
        unsafe { libc::kill(-i32::try_from(pgid).expect("pid"), libc::SIGKILL) };
        // A leader that exited and is not reaped is a zombie.
        let mut zombie = false;
        for _ in 0..100 {
            zombie = info(pgid).is_some_and(|p| p.zombie);
            if zombie {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(zombie, "{:?}", info(pgid));
        drop(leader);
        assert_eq!(group(pgid).expect("the table"), Vec::new());
    }

    #[test]
    fn a_command_line_is_read_without_ps() {
        let child = Reap(
            std::process::Command::new("/bin/sleep")
                .arg("31")
                .env_clear()
                .env("LOOM_PROCINFO_TEST", "marker-1")
                .spawn()
                .expect("spawn"),
        );
        let mut line = None;
        for _ in 0..100 {
            line = command_line(child.0.id()).filter(|l| l.args.iter().any(|a| a == "31"));
            if line.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let line = line.expect("the command line");
        assert!(line.args.last().is_some_and(|a| a == "31"), "{line:?}");
        assert!(line.env.iter().any(|e| e == "LOOM_PROCINFO_TEST=marker-1"), "{line:?}");
        drop(child);
        assert_eq!(command_line(u32::MAX), None);
    }

    #[test]
    fn procargs_are_split_into_arguments_and_environment() {
        let mut raw = 2i32.to_ne_bytes().to_vec();
        raw.extend_from_slice(b"/bin/echo\0\0\0echo\0hi there\0A=1\0B=2\0\0\0");
        let line = split_procargs(&raw).expect("parsed");
        assert_eq!(line.args, ["echo", "hi there"]);
        assert_eq!(line.env, ["A=1", "B=2"]);
        // No environment at all.
        let mut bare = 1i32.to_ne_bytes().to_vec();
        bare.extend_from_slice(b"/bin/ls\0\0ls\0");
        assert_eq!(split_procargs(&bare).expect("parsed").env, Vec::<String>::new());
        // An empty argument is an argument.
        let mut empty = 2i32.to_ne_bytes().to_vec();
        empty.extend_from_slice(b"/bin/x\0x\0\0E=1\0");
        assert_eq!(split_procargs(&empty).expect("parsed").args, ["x", ""]);
        // Malformed: too short, a negative count, fewer arguments than the count says, no path.
        assert_eq!(split_procargs(b""), None);
        assert_eq!(split_procargs(&[1, 0]), None);
        assert_eq!(split_procargs(&(-1i32).to_ne_bytes()), None);
        let mut few = 5i32.to_ne_bytes().to_vec();
        few.extend_from_slice(b"/bin/x\0x\0");
        assert_eq!(split_procargs(&few), None);
        assert_eq!(split_procargs(&2i32.to_ne_bytes()), None);
    }

    #[test]
    fn a_listening_socket_is_found_by_its_process() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        let udp_port = udp.local_addr().expect("addr").port();
        let found = listeners(std::process::id());
        assert!(found.iter().any(|l| l.proto == Proto::Tcp && l.port == port && l.addr == "127.0.0.1"), "{found:?}");
        assert!(found.iter().any(|l| l.proto == Proto::Udp && l.port == udp_port), "{found:?}");
        // A connected socket is not a listener.
        let client = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        let (accepted, _) = listener.accept().expect("accept");
        let found = listeners(std::process::id());
        let tcp: Vec<u16> = found.iter().filter(|l| l.proto == Proto::Tcp).map(|l| l.port).collect();
        assert!(tcp.contains(&port) && !tcp.contains(&client.local_addr().expect("addr").port()), "{found:?}");
        drop((client, accepted));
        drop(listener);
        let found = listeners(std::process::id());
        assert!(!found.iter().any(|l| l.proto == Proto::Tcp && l.port == port), "{found:?}");
        assert_eq!(listeners(u32::MAX), Vec::new());
    }

    #[test]
    fn the_nproc_limit_leaves_headroom_and_never_stops_a_command_from_running() {
        assert_eq!(nproc_limit(2666, 0, 100), None);
        assert_eq!(nproc_limit(2666, 256, 100), Some(2410));
        // A busy machine: the command still has room.
        assert_eq!(nproc_limit(2666, 256, 2500), Some(2564));
        // Never above the base.
        assert_eq!(nproc_limit(2666, 256, 2650), Some(2666));
        assert_eq!(nproc_limit(100, 500, 10), Some(74));
        assert_eq!(nproc_limit(u64::MAX, 1, u64::MAX), Some(u64::MAX));
        assert!(nproc_limit_now(0).is_none());
        if let (Some(base), Some(now)) = (nproc_base(), nproc_limit_now(256)) {
            assert!(now <= base && now > 0, "{now} of {base}");
        }
    }

    #[test]
    fn an_unreadable_table_reads_as_unknown_not_as_gone() {
        UNREADABLE.with(|u| u.set(true));
        let (one, all, group_of, line) = (info(std::process::id()), pids(), group(1), command_line(std::process::id()));
        UNREADABLE.with(|u| u.set(false));
        assert_eq!((one, all, group_of, line), (None, None, None, None));
        assert!(info(std::process::id()).is_some());
    }
}
