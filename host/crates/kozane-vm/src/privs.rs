//! The privilege drop each child makes between fork and exec (M9 plan C4):
//! no capability in any set, the service user's uid and gids, and
//! `no_new_privs`. The sequence runs over [`Sys`], so its order and its
//! refusals are unit-tested against injected results; the real cross-uid
//! cells are VE26.
//!
//! It runs in the forked child: nothing here allocates.

use std::os::fd::RawFd;

/// An errno.
pub type Errno = i32;

/// The system calls the drop makes, and `fchown` for the pin writer.
pub trait Sys {
    fn capbset_drop(&mut self, cap: u32) -> Result<(), Errno>;
    fn setgroups(&mut self, groups: &[u32]) -> Result<(), Errno>;
    fn setresgid(&mut self, gid: u32) -> Result<(), Errno>;
    fn setresuid(&mut self, uid: u32) -> Result<(), Errno>;
    fn getresuid(&mut self) -> (u32, u32, u32);
    fn getresgid(&mut self) -> (u32, u32, u32);
    /// Empties the ambient, inheritable, permitted and effective sets.
    fn clear_caps(&mut self) -> Result<(), Errno>;
    fn no_new_privs(&mut self) -> Result<(), Errno>;
    fn fchown(&mut self, fd: RawFd, uid: u32, gid: u32) -> Result<(), Errno>;
}

/// Who to become. `groups: None` keeps the supplementary groups (only under
/// the `--user-map` seam).
pub struct Target<'a> {
    pub uid: u32,
    pub gid: u32,
    pub groups: Option<&'a [u32]>,
}

/// One past the highest capability number Linux could define; the bounding
/// set is emptied until the kernel reports the first unknown one.
const CAP_LIMIT: u32 = 64;

/// Drop to `t`, in this order:
/// 1. empty the bounding set, while CAP_SETPCAP is still held, so no later
///    exec can grant a capability, a root uid's included;
/// 2. the supplementary groups, then the gids, then the uids;
/// 3. read back that every uid and gid is the target's;
/// 4. empty the remaining sets and set `no_new_privs`.
///
/// The first failure stops the sequence: the child exits before exec.
pub fn drop_to(sys: &mut impl Sys, t: &Target) -> Result<(), Errno> {
    for cap in 0..CAP_LIMIT {
        match sys.capbset_drop(cap) {
            Ok(()) => {}
            Err(libc::EINVAL) if cap > 0 => break,
            Err(e) => return Err(e),
        }
    }
    if let Some(groups) = t.groups {
        sys.setgroups(groups)?;
    }
    sys.setresgid(t.gid)?;
    sys.setresuid(t.uid)?;
    if sys.getresgid() != (t.gid, t.gid, t.gid) || sys.getresuid() != (t.uid, t.uid, t.uid) {
        return Err(libc::EPERM);
    }
    sys.clear_caps()?;
    sys.no_new_privs()
}

fn errno() -> Errno {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)
}

fn check(rc: libc::c_int) -> Result<(), Errno> {
    if rc == -1 { Err(errno()) } else { Ok(()) }
}

/// The real system calls.
pub struct RealSys;

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

impl Sys for RealSys {
    fn capbset_drop(&mut self, cap: u32) -> Result<(), Errno> {
        // SAFETY: prctl with integer arguments only.
        check(unsafe { libc::prctl(libc::PR_CAPBSET_DROP, libc::c_ulong::from(cap), 0, 0, 0) })
    }

    fn setgroups(&mut self, groups: &[u32]) -> Result<(), Errno> {
        // SAFETY: the pointer and the length describe `groups`.
        check(unsafe { libc::setgroups(groups.len(), groups.as_ptr()) })
    }

    fn setresgid(&mut self, gid: u32) -> Result<(), Errno> {
        // SAFETY: integer arguments only.
        check(unsafe { libc::setresgid(gid, gid, gid) })
    }

    fn setresuid(&mut self, uid: u32) -> Result<(), Errno> {
        // SAFETY: integer arguments only.
        check(unsafe { libc::setresuid(uid, uid, uid) })
    }

    fn getresuid(&mut self) -> (u32, u32, u32) {
        let (mut r, mut e, mut s) = (u32::MAX, u32::MAX, u32::MAX);
        // SAFETY: three valid out pointers.
        unsafe { libc::getresuid(&mut r, &mut e, &mut s) };
        (r, e, s)
    }

    fn getresgid(&mut self) -> (u32, u32, u32) {
        let (mut r, mut e, mut s) = (u32::MAX, u32::MAX, u32::MAX);
        // SAFETY: three valid out pointers.
        unsafe { libc::getresgid(&mut r, &mut e, &mut s) };
        (r, e, s)
    }

    fn clear_caps(&mut self) -> Result<(), Errno> {
        // SAFETY: prctl with integer arguments only.
        check(unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong, 0, 0, 0) })?;
        let mut header = CapHeader { version: LINUX_CAPABILITY_VERSION_3, pid: 0 };
        let data = [CapData { effective: 0, permitted: 0, inheritable: 0 }; 2];
        // SAFETY: capset reads one header and two data structs (version 3).
        let rc = unsafe { libc::syscall(libc::SYS_capset, &mut header as *mut CapHeader, data.as_ptr()) };
        if rc == -1 { Err(errno()) } else { Ok(()) }
    }

    fn no_new_privs(&mut self) -> Result<(), Errno> {
        // SAFETY: prctl with integer arguments only.
        check(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1 as libc::c_ulong, 0, 0, 0) })
    }

    fn fchown(&mut self, fd: RawFd, uid: u32, gid: u32) -> Result<(), Errno> {
        // SAFETY: integer arguments only.
        check(unsafe { libc::fchown(fd, uid, gid) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records each call, and fails the one named in `fail`.
    #[derive(Default)]
    struct Fake {
        calls: Vec<String>,
        fail: Option<(&'static str, Errno)>,
        caps_known: u32,
        uid: u32,
        gid: u32,
        /// What getresuid reports instead of the set uid.
        lie_uid: Option<u32>,
    }

    impl Fake {
        fn call(&mut self, name: &'static str, detail: String) -> Result<(), Errno> {
            self.calls.push(format!("{name}{detail}"));
            match self.fail {
                Some((f, e)) if f == name => Err(e),
                _ => Ok(()),
            }
        }
    }

    impl Sys for Fake {
        fn capbset_drop(&mut self, cap: u32) -> Result<(), Errno> {
            if cap >= self.caps_known {
                return Err(libc::EINVAL);
            }
            self.call("capbset_drop", String::new())
        }
        fn setgroups(&mut self, groups: &[u32]) -> Result<(), Errno> {
            self.call("setgroups", format!("{groups:?}"))
        }
        fn setresgid(&mut self, gid: u32) -> Result<(), Errno> {
            self.gid = gid;
            self.call("setresgid", format!("({gid})"))
        }
        fn setresuid(&mut self, uid: u32) -> Result<(), Errno> {
            self.uid = uid;
            self.call("setresuid", format!("({uid})"))
        }
        fn getresuid(&mut self) -> (u32, u32, u32) {
            let u = self.lie_uid.unwrap_or(self.uid);
            (u, u, u)
        }
        fn getresgid(&mut self) -> (u32, u32, u32) {
            (self.gid, self.gid, self.gid)
        }
        fn clear_caps(&mut self) -> Result<(), Errno> {
            self.call("clear_caps", String::new())
        }
        fn no_new_privs(&mut self) -> Result<(), Errno> {
            self.call("no_new_privs", String::new())
        }
        fn fchown(&mut self, _fd: RawFd, uid: u32, gid: u32) -> Result<(), Errno> {
            self.call("fchown", format!("({uid},{gid})"))
        }
    }

    fn fake(fail: Option<(&'static str, Errno)>) -> Fake {
        Fake { caps_known: 41, uid: 0, gid: 0, fail, ..Fake::default() }
    }

    const QEMU: Target<'static> = Target { uid: 991, gid: 991, groups: Some(&[991, 36]) };

    fn without_capbset(calls: &[String]) -> Vec<&str> {
        calls.iter().map(String::as_str).filter(|c| *c != "capbset_drop").collect()
    }

    #[test]
    fn the_drop_empties_the_bounding_set_then_sets_groups_gid_uid_then_clears_and_locks() {
        let mut sys = fake(None);
        assert_eq!(drop_to(&mut sys, &QEMU), Ok(()));
        assert_eq!(sys.calls.iter().filter(|c| *c == "capbset_drop").count(), 41);
        assert!(sys.calls.iter().take(41).all(|c| c == "capbset_drop"), "{:?}", sys.calls);
        assert_eq!(
            without_capbset(&sys.calls),
            ["setgroups[991, 36]", "setresgid(991)", "setresuid(991)", "clear_caps", "no_new_privs"]
        );
    }

    #[test]
    fn a_failed_setgroups_stops_before_any_uid_change() {
        let mut sys = fake(Some(("setgroups", libc::EPERM)));
        assert_eq!(drop_to(&mut sys, &QEMU), Err(libc::EPERM));
        assert_eq!(without_capbset(&sys.calls), ["setgroups[991, 36]"]);
    }

    #[test]
    fn a_failed_setresuid_stops_before_no_new_privs_and_exec() {
        let mut sys = fake(Some(("setresuid", libc::EAGAIN)));
        assert_eq!(drop_to(&mut sys, &QEMU), Err(libc::EAGAIN));
        assert_eq!(without_capbset(&sys.calls), ["setgroups[991, 36]", "setresgid(991)", "setresuid(991)"]);
    }

    #[test]
    fn a_uid_that_did_not_change_is_refused() {
        let mut sys = Fake { lie_uid: Some(0), ..fake(None) };
        assert_eq!(drop_to(&mut sys, &QEMU), Err(libc::EPERM));
        assert!(!sys.calls.iter().any(|c| c == "clear_caps" || c == "no_new_privs"), "{:?}", sys.calls);
    }

    #[test]
    fn a_failed_bounding_set_drop_stops_everything() {
        let mut sys = fake(Some(("capbset_drop", libc::EPERM)));
        assert_eq!(drop_to(&mut sys, &QEMU), Err(libc::EPERM));
        assert_eq!(sys.calls, ["capbset_drop"]);
    }

    #[test]
    fn an_unknown_first_capability_is_an_error_not_an_empty_set() {
        let mut sys = Fake { caps_known: 0, ..fake(None) };
        assert_eq!(drop_to(&mut sys, &QEMU), Err(libc::EINVAL));
    }

    #[test]
    fn without_groups_the_supplementary_groups_are_left_alone() {
        let mut sys = fake(None);
        let t = Target { uid: 5, gid: 6, groups: None };
        assert_eq!(drop_to(&mut sys, &t), Ok(()));
        assert_eq!(without_capbset(&sys.calls), ["setresgid(6)", "setresuid(5)", "clear_caps", "no_new_privs"]);
    }

    #[test]
    fn a_failed_no_new_privs_is_an_error() {
        let mut sys = fake(Some(("no_new_privs", libc::EINVAL)));
        assert_eq!(drop_to(&mut sys, &QEMU), Err(libc::EINVAL));
    }
}
