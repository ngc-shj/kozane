//! Starting a child (M9 plan C4): the fds it is given at exactly the numbers
//! `vm-args.json` names and no others, its credentials dropped, no
//! capability, `no_new_privs`, and killed if the launcher dies.

use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};

use crate::privs::{self, RealSys, Target};
use crate::resolve::Creds;

/// Keeps every fd below `upto` open (on /dev/null, close-on-exec), so that
/// nothing the launcher opens later lands on a number a child is given. A
/// `dup2` onto a target then never overwrites a source, and std's own
/// exec-error pipe never sits on a target.
pub fn reserve_low_fds(upto: RawFd) -> Result<Vec<File>, String> {
    let mut held = Vec::new();
    loop {
        let f = File::open("/dev/null").map_err(|e| format!("/dev/null: {e}"))?;
        if f.as_raw_fd() >= upto {
            return Ok(held);
        }
        held.push(f);
    }
}

pub struct Spec<'a> {
    pub program: &'a str,
    pub args: &'a [String],
    /// (the launcher's fd, the number the child gets it at).
    pub fds: Vec<(RawFd, RawFd)>,
    pub stdin: Stdio,
    pub stdout: Stdio,
    pub creds: &'a Creds,
    /// Raise RLIMIT_MEMLOCK (QEMU's `-overcommit mem-lock=on`, P14).
    pub memlock: bool,
    /// The first fd number the child is not given: from here up, every fd
    /// is marked close-on-exec.
    pub first_free: RawFd,
}

pub fn spawn(spec: Spec) -> Result<Child, String> {
    let Spec { program, args, fds, stdin, stdout, creds, memlock, first_free } = spec;
    if fds.iter().any(|&(src, dst)| src < first_free || dst >= first_free || dst < 3) {
        return Err(format!("{program}: fd layout overlaps the launcher's own fds"));
    }
    let uid = creds.uid;
    let gid = creds.gid;
    let groups = creds.groups.clone();
    // SAFETY: getpid cannot fail.
    let parent = unsafe { libc::getpid() };
    let mut cmd = Command::new(program);
    cmd.args(args).env_clear().current_dir("/").stdin(stdin).stdout(stdout).stderr(Stdio::inherit());
    // SAFETY: the closure runs in the forked child before exec and makes
    // only async-signal-safe system calls; it allocates nothing (`fds` and
    // `groups` were built before the fork).
    unsafe {
        cmd.pre_exec(move || {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::pthread_sigmask(libc::SIG_SETMASK, &set, std::ptr::null_mut());
            if memlock {
                let unlimited = libc::rlimit { rlim_cur: libc::RLIM_INFINITY, rlim_max: libc::RLIM_INFINITY };
                if libc::setrlimit(libc::RLIMIT_MEMLOCK, &unlimited) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            for &(src, dst) in &fds {
                if libc::dup2(src, dst) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if libc::syscall(libc::SYS_close_range, first_free as libc::c_uint, libc::c_uint::MAX, libc::CLOSE_RANGE_CLOEXEC) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            let target = Target { uid, gid, groups: groups.as_deref() };
            privs::drop_to(&mut RealSys, &target).map_err(std::io::Error::from_raw_os_error)?;
            // Set after the uid change, which clears it.
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong, 0, 0, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
            }
            Ok(())
        });
    }
    cmd.spawn().map_err(|e| format!("starting {program}: {e}"))
}

/// A pipe, both ends close-on-exec: (read, write).
pub fn pipe() -> Result<(OwnedFd, OwnedFd), String> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: pipe2 fills two fds.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } == -1 {
        return Err(format!("pipe: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: two new fds nothing else owns.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// A connected AF_UNIX stream pair, close-on-exec: the TPM's channel, so no
/// socket path exists (M9 plan C4).
pub fn socketpair() -> Result<(OwnedFd, OwnedFd), String> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: socketpair fills two fds.
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0, fds.as_mut_ptr()) } == -1 {
        return Err(format!("socketpair: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: two new fds nothing else owns.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// A pidfd for `pid`, readable once it exits.
pub fn pidfd(pid: u32) -> Result<OwnedFd, String> {
    // SAFETY: pidfd_open with integer arguments.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if fd < 0 {
        return Err(format!("pidfd_open {pid}: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: a new fd nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}
