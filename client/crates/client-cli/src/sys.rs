//! Every system call `kzc` and `kzc-psk` make, as safe wrappers. This is
//! the crate's only `unsafe`; each call carries its SAFETY comment. Nothing
//! here runs another program (D6).

#![allow(unsafe_code)]

use std::ffi::{CString, OsStr};
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

fn cstr(s: &OsStr) -> io::Result<CString> {
    CString::new(s.as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

fn check(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret < 0 { Err(io::Error::last_os_error()) } else { Ok(ret) }
}

fn check_size(ret: libc::ssize_t) -> io::Result<usize> {
    usize::try_from(ret).map_err(|_| io::Error::last_os_error())
}

fn owned(fd: libc::c_int) -> io::Result<OwnedFd> {
    let fd = check(fd)?;
    // SAFETY: `fd` was just returned by the kernel and is owned by no one
    // else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

pub fn geteuid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

pub fn getuid() -> u32 {
    // SAFETY: as geteuid.
    unsafe { libc::getuid() }
}

/// What the I10.1 adjudicator reads off an open fd.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Meta {
    pub mode: u32,
    pub uid: u32,
    pub size: u64,
}

pub fn fstat(fd: BorrowedFd<'_>) -> io::Result<Meta> {
    // SAFETY: an all-zero `stat` is a valid value of the plain C struct.
    let mut st: libc::stat = unsafe { zeroed() };
    // SAFETY: `fd` is open for the borrow and `st` is a valid out pointer.
    check(unsafe { libc::fstat(fd.as_raw_fd(), &mut st) })?;
    Ok(Meta { mode: st.st_mode, uid: st.st_uid, size: u64::try_from(st.st_size).unwrap_or(u64::MAX) })
}

/// open(2); `O_CLOEXEC` is always added.
pub fn open(path: &Path, flags: libc::c_int) -> io::Result<OwnedFd> {
    let p = cstr(path.as_os_str())?;
    // SAFETY: `p` is NUL-terminated and outlives the call.
    owned(unsafe { libc::open(p.as_ptr(), flags | libc::O_CLOEXEC) })
}

/// openat(2) relative to `dir`, with `mode` for `O_CREAT`; `O_CLOEXEC` is
/// always added.
pub fn openat(dir: BorrowedFd<'_>, name: &OsStr, flags: libc::c_int, mode: u32) -> io::Result<OwnedFd> {
    let n = cstr(name)?;
    // SAFETY: `dir` is open, `n` is NUL-terminated; the variadic mode is
    // passed as the `mode_t` open expects.
    owned(unsafe { libc::openat(dir.as_raw_fd(), n.as_ptr(), flags | libc::O_CLOEXEC, mode as libc::mode_t) })
}

pub fn mkdirat(dir: BorrowedFd<'_>, name: &OsStr, mode: u32) -> io::Result<()> {
    let n = cstr(name)?;
    // SAFETY: `dir` is open, `n` is NUL-terminated.
    check(unsafe { libc::mkdirat(dir.as_raw_fd(), n.as_ptr(), mode as libc::mode_t) }).map(drop)
}

pub fn unlinkat(dir: BorrowedFd<'_>, name: &OsStr) -> io::Result<()> {
    let n = cstr(name)?;
    // SAFETY: `dir` is open, `n` is NUL-terminated.
    check(unsafe { libc::unlinkat(dir.as_raw_fd(), n.as_ptr(), 0) }).map(drop)
}

pub fn fchmod(fd: BorrowedFd<'_>, mode: u32) -> io::Result<()> {
    // SAFETY: `fd` is open for the borrow.
    check(unsafe { libc::fchmod(fd.as_raw_fd(), mode as libc::mode_t) }).map(drop)
}

pub fn fchown(fd: BorrowedFd<'_>, uid: u32, gid: u32) -> io::Result<()> {
    // SAFETY: `fd` is open for the borrow.
    check(unsafe { libc::fchown(fd.as_raw_fd(), uid, gid) }).map(drop)
}

pub fn fsync(fd: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: `fd` is open for the borrow.
    check(unsafe { libc::fsync(fd.as_raw_fd()) }).map(drop)
}

pub fn umask(mask: u32) -> u32 {
    // SAFETY: umask has no preconditions and cannot fail.
    unsafe { libc::umask(mask as libc::mode_t) }
}

/// PR_SET_DUMPABLE 0 (D6): no core dump, and no ptrace or /proc/<pid>/mem
/// access by the same uid.
pub fn no_dump() -> io::Result<()> {
    // SAFETY: prctl with PR_SET_DUMPABLE takes an integer and nothing else.
    check(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) }).map(drop)
}

/// The uid and gid of `name` in the user database.
pub fn getpwnam(name: &str) -> io::Result<Option<(u32, u32)>> {
    let n = cstr(OsStr::new(name))?;
    // SAFETY: an all-zero `passwd` is a valid out value.
    let mut pw: libc::passwd = unsafe { zeroed() };
    let mut buf = vec![0u8; 16384];
    let mut res: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the call and `buf.len()` is its
    // real length; the result points into `pw` or is null.
    let err = unsafe { libc::getpwnam_r(n.as_ptr(), &mut pw, buf.as_mut_ptr().cast(), buf.len(), &mut res) };
    if err != 0 {
        return Err(io::Error::from_raw_os_error(err));
    }
    Ok((!res.is_null()).then_some((pw.pw_uid, pw.pw_gid)))
}

/// CLOCK_BOOTTIME in nanoseconds: it counts suspend (D5).
pub fn boottime_ns() -> io::Result<u64> {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: `ts` is a valid out pointer.
    check(unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) })?;
    let s = u64::try_from(ts.tv_sec).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    let ns = u64::try_from(ts.tv_nsec).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    s.checked_mul(1_000_000_000).and_then(|t| t.checked_add(ns)).ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))
}

static TERMINATED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_term(_: libc::c_int) {
    TERMINATED.store(true, Ordering::SeqCst);
}

/// SIGINT, SIGTERM and SIGHUP set a flag and interrupt blocking calls (no
/// SA_RESTART); SIGPIPE is ignored, so a closed peer is an error return.
pub fn install_signal_handlers() -> io::Result<()> {
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        // SAFETY: an all-zero `sigaction` is valid; the handler only stores
        // to an atomic, which is async-signal-safe.
        let mut sa: libc::sigaction = unsafe { zeroed() };
        sa.sa_sigaction = on_term as *const () as libc::sighandler_t;
        // SAFETY: `sa.sa_mask` is a valid sigset_t.
        unsafe { libc::sigemptyset(&mut sa.sa_mask) };
        // SAFETY: `sa` is fully initialised; the old action is not wanted.
        check(unsafe { libc::sigaction(sig, &sa, std::ptr::null_mut()) })?;
    }
    // SAFETY: SIG_IGN is a valid disposition for SIGPIPE.
    if unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) } == libc::SIG_ERR {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn terminated() -> bool {
    TERMINATED.load(Ordering::SeqCst)
}

/// poll(2) over `fds` (fd, events); returns each fd's revents, or `None`
/// when a signal interrupted it.
pub fn poll(fds: &[(BorrowedFd<'_>, i16)], timeout_ms: i32) -> io::Result<Option<Vec<i16>>> {
    let mut p: Vec<libc::pollfd> =
        fds.iter().map(|(fd, ev)| libc::pollfd { fd: fd.as_raw_fd(), events: *ev, revents: 0 }).collect();
    let n = libc::nfds_t::try_from(p.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `p` holds `n` valid pollfd entries.
    let ret = unsafe { libc::poll(p.as_mut_ptr(), n, timeout_ms) };
    if ret < 0 {
        let e = io::Error::last_os_error();
        return if e.kind() == io::ErrorKind::Interrupted { Ok(None) } else { Err(e) };
    }
    Ok(Some(p.iter().map(|x| x.revents).collect()))
}

/// Sleeps `ms`, or less when a signal arrives.
pub fn sleep_ms(ms: i32) {
    // SAFETY: poll with no fds only sleeps.
    unsafe { libc::poll(std::ptr::null_mut(), 0, ms) };
}

fn sockaddr_un(path: &[u8]) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    // SAFETY: an all-zero `sockaddr_un` is valid.
    let mut addr: libc::sockaddr_un = unsafe { zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    // Room for the terminating NUL of a filesystem path.
    if path.is_empty() || path.len() >= addr.sun_path.len() {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    for (d, s) in addr.sun_path.iter_mut().zip(path) {
        *d = *s as libc::c_char;
    }
    let base = std::mem::offset_of!(libc::sockaddr_un, sun_path);
    let len = base.checked_add(path.len()).ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    Ok((addr, libc::socklen_t::try_from(len).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?))
}

/// A unix SOCK_SEQPACKET socket: every Install or Scrub is one record.
pub fn seqpacket() -> io::Result<OwnedFd> {
    // SAFETY: socket takes integers only.
    owned(unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) })
}

pub fn bind_unix(fd: BorrowedFd<'_>, path: &Path) -> io::Result<()> {
    let (addr, len) = sockaddr_un(path.as_os_str().as_bytes())?;
    // SAFETY: `addr` is a valid sockaddr_un of length `len`.
    check(unsafe { libc::bind(fd.as_raw_fd(), (&raw const addr).cast(), len) }).map(drop)
}

pub fn listen(fd: BorrowedFd<'_>, backlog: i32) -> io::Result<()> {
    // SAFETY: `fd` is a bound socket.
    check(unsafe { libc::listen(fd.as_raw_fd(), backlog) }).map(drop)
}

pub fn accept(fd: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    // SAFETY: null address pointers are allowed.
    owned(unsafe { libc::accept4(fd.as_raw_fd(), std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_CLOEXEC) })
}

pub fn connect_unix(fd: BorrowedFd<'_>, path: &Path) -> io::Result<()> {
    let (addr, len) = sockaddr_un(path.as_os_str().as_bytes())?;
    // SAFETY: `addr` is a valid sockaddr_un of length `len`.
    check(unsafe { libc::connect(fd.as_raw_fd(), (&raw const addr).cast(), len) }).map(drop)
}

/// The uid of the process at the other end (SO_PEERCRED), as the kernel
/// recorded it at connect.
pub fn peer_uid(fd: BorrowedFd<'_>) -> io::Result<u32> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = libc::socklen_t::try_from(size_of::<libc::ucred>()).unwrap_or(0);
    // SAFETY: `cred` is a valid out buffer of `len` bytes.
    check(unsafe {
        libc::getsockopt(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, (&raw mut cred).cast(), &mut len)
    })?;
    if usize::try_from(len).ok() != Some(size_of::<libc::ucred>()) {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    Ok(cred.uid)
}

/// send(2) with MSG_NOSIGNAL; a short send is an error.
pub fn send(fd: BorrowedFd<'_>, buf: &[u8]) -> io::Result<()> {
    // SAFETY: `buf` is valid for `buf.len()` bytes.
    let n = check_size(unsafe { libc::send(fd.as_raw_fd(), buf.as_ptr().cast(), buf.len(), libc::MSG_NOSIGNAL) })?;
    if n != buf.len() {
        return Err(io::Error::from(io::ErrorKind::WriteZero));
    }
    Ok(())
}

/// recv(2) of one record into `buf`; returns the record's real length
/// (MSG_TRUNC), which exceeds `buf.len()` when it did not fit. `None` when
/// a signal interrupted it.
pub fn recv(fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<Option<usize>> {
    // SAFETY: `buf` is valid for `buf.len()` bytes of writes.
    let ret = unsafe { libc::recv(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), libc::MSG_TRUNC) };
    match check_size(ret) {
        Ok(n) => Ok(Some(n)),
        Err(e) if e.kind() == io::ErrorKind::Interrupted => Ok(None),
        Err(e) => Err(e),
    }
}

/// One datagram to the service manager's NOTIFY_SOCKET (a path, or an
/// abstract name written `@name`).
pub fn notify_datagram(socket: &OsStr, msg: &[u8]) -> io::Result<()> {
    let raw = socket.as_bytes();
    let mut path = raw.to_vec();
    if let Some(first) = path.first_mut()
        && *first == b'@'
    {
        *first = 0;
    }
    let (addr, len) = sockaddr_un(&path)?;
    // SAFETY: socket takes integers only.
    let fd = owned(unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) })?;
    // SAFETY: `msg` is valid for its length and `addr` for `len`.
    let n = check_size(unsafe {
        libc::sendto(fd.as_raw_fd(), msg.as_ptr().cast(), msg.len(), libc::MSG_NOSIGNAL, (&raw const addr).cast(), len)
    })?;
    if n != msg.len() {
        return Err(io::Error::from(io::ErrorKind::WriteZero));
    }
    Ok(())
}

/// A netlink socket for `protocol`, bound with a kernel-chosen port id,
/// which it returns. NETLINK_CAP_ACK keeps the kernel from echoing a
/// request, keys included, in its ack.
pub fn netlink(protocol: libc::c_int) -> io::Result<(OwnedFd, u32)> {
    // SAFETY: socket takes integers only.
    let fd = owned(unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, protocol) })?;
    let one: libc::c_int = 1;
    let optlen = libc::socklen_t::try_from(size_of::<libc::c_int>()).unwrap_or(0);
    // SAFETY: `one` is a valid c_int of `optlen` bytes.
    check(unsafe {
        libc::setsockopt(fd.as_raw_fd(), libc::SOL_NETLINK, libc::NETLINK_CAP_ACK, (&raw const one).cast(), optlen)
    })?;
    // SAFETY: an all-zero `sockaddr_nl` is valid: port 0 asks the kernel to
    // choose one.
    let mut addr: libc::sockaddr_nl = unsafe { zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    let len = libc::socklen_t::try_from(size_of::<libc::sockaddr_nl>()).unwrap_or(0);
    // SAFETY: `addr` is a valid sockaddr_nl of `len` bytes.
    check(unsafe { libc::bind(fd.as_raw_fd(), (&raw const addr).cast(), len) })?;
    let mut got = len;
    // SAFETY: `addr` is a valid out buffer of `got` bytes.
    check(unsafe { libc::getsockname(fd.as_raw_fd(), (&raw mut addr).cast(), &mut got) })?;
    Ok((fd, addr.nl_pid))
}

/// Sends `msg` to the kernel (port 0).
pub fn netlink_send(fd: BorrowedFd<'_>, msg: &[u8]) -> io::Result<()> {
    // SAFETY: an all-zero `sockaddr_nl` addresses the kernel.
    let mut addr: libc::sockaddr_nl = unsafe { zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    let len = libc::socklen_t::try_from(size_of::<libc::sockaddr_nl>()).unwrap_or(0);
    // SAFETY: `msg` is valid for its length and `addr` for `len`.
    let n = check_size(unsafe {
        libc::sendto(fd.as_raw_fd(), msg.as_ptr().cast(), msg.len(), 0, (&raw const addr).cast(), len)
    })?;
    if n != msg.len() {
        return Err(io::Error::from(io::ErrorKind::WriteZero));
    }
    Ok(())
}

/// One netlink datagram into `buf`: its real length (MSG_TRUNC) and the
/// sender's port id, which is 0 for the kernel.
pub fn netlink_recv(fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<(usize, u32)> {
    // SAFETY: an all-zero `sockaddr_nl` is a valid out value.
    let mut addr: libc::sockaddr_nl = unsafe { zeroed() };
    let mut len = libc::socklen_t::try_from(size_of::<libc::sockaddr_nl>()).unwrap_or(0);
    loop {
        // SAFETY: `buf` is valid for its length; `addr` for `len` bytes.
        let ret = unsafe {
            libc::recvfrom(
                fd.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                libc::MSG_TRUNC,
                (&raw mut addr).cast(),
                &mut len,
            )
        };
        match check_size(ret) {
            Ok(n) => return Ok((n, addr.nl_pid)),
            // A netlink reply is already queued; a signal does not lose it.
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}
