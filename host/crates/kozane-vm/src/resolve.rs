//! Path and service-user resolution, the one module the `test-seams`
//! feature reaches (M9 plan C4). Without the feature every path is the fixed
//! one, every input must be owned by root, and each service user comes from
//! the system's user database. With it, `--root-prefix <dir>` moves every
//! fixed path under `dir`, and `--user-map` maps each service user (and the
//! owner every input must have) to the current uid, so the tests run in a
//! single-uid user namespace (VE26).

use std::ffi::CString;
use std::path::PathBuf;

/// `--build-info`'s `SEAMS=`.
pub const SEAMS: bool = cfg!(feature = "test-seams");

/// The unprivileged users the launcher starts its children as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Service {
    /// swtpm.
    Swtpm,
    /// QEMU, with the kvm group.
    Qemu,
    /// The serial reader: QEMU's user, without the kvm group.
    Reader,
}

impl Service {
    fn user(self) -> &'static str {
        match self {
            Self::Swtpm => "kozane-swtpm",
            Self::Qemu | Self::Reader => "kozane-qemu",
        }
    }
}

/// Who a child runs as. `groups: None` keeps the supplementary groups as
/// they are, which only `--user-map` asks for: `setgroups` is denied in a
/// user namespace that `unshare -r` made.
#[derive(Debug, PartialEq, Eq)]
pub struct Creds {
    pub uid: u32,
    pub gid: u32,
    pub groups: Option<Vec<u32>>,
}

pub struct Resolver {
    #[cfg(feature = "test-seams")]
    prefix: Option<PathBuf>,
    #[cfg(feature = "test-seams")]
    user_map: bool,
}

impl Resolver {
    /// Takes the seam options out of `args`. Without the feature there are
    /// none, so `--root-prefix` stays in `args` and is refused as unknown.
    #[cfg_attr(not(feature = "test-seams"), allow(clippy::unnecessary_wraps, clippy::ptr_arg))]
    pub fn from_args(args: &mut Vec<String>) -> Result<Self, String> {
        #[cfg(feature = "test-seams")]
        {
            let mut prefix = None;
            let mut user_map = false;
            let mut rest = Vec::new();
            let mut it = std::mem::take(args).into_iter();
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--root-prefix" => prefix = Some(PathBuf::from(it.next().ok_or("--root-prefix needs a value")?)),
                    "--user-map" => user_map = true,
                    _ => rest.push(a),
                }
            }
            *args = rest;
            Ok(Self { prefix, user_map })
        }
        #[cfg(not(feature = "test-seams"))]
        {
            let _ = args;
            Ok(Self {})
        }
    }

    /// Where a fixed absolute path is.
    pub fn path(&self, fixed: &str) -> PathBuf {
        #[cfg(feature = "test-seams")]
        if let Some(prefix) = &self.prefix {
            return prefix.join(fixed.trim_start_matches('/'));
        }
        PathBuf::from(fixed)
    }

    /// The uid and gid every launcher input must be owned by, and every file
    /// it writes gets: root's.
    pub fn owner(&self) -> (u32, u32) {
        #[cfg(feature = "test-seams")]
        if self.user_map {
            // SAFETY: geteuid and getegid cannot fail.
            return unsafe { (libc::geteuid(), libc::getegid()) };
        }
        (0, 0)
    }

    /// The credentials `service` runs with.
    pub fn creds(&self, service: Service) -> Result<Creds, String> {
        #[cfg(feature = "test-seams")]
        if self.user_map {
            let (uid, gid) = self.owner();
            return Ok(Creds { uid, gid, groups: None });
        }
        let (uid, gid) = lookup(service.user())?;
        let kvm_gid = if service == Service::Qemu {
            // The group that may open /dev/kvm is the one that owns it.
            let kvm = std::fs::metadata(self.path("/dev/kvm")).map_err(|e| format!("/dev/kvm: {e}"))?;
            Some(std::os::unix::fs::MetadataExt::gid(&kvm))
        } else {
            None
        };
        service_creds(service.user(), uid, gid, kvm_gid)
    }
}

/// `user`'s credentials from its database entry and, for QEMU, /dev/kvm's
/// group. None of them may be root's: a root-owned /dev/kvm would hand QEMU
/// gid 0 as a supplementary group.
pub fn service_creds(user: &str, uid: u32, gid: u32, kvm_gid: Option<u32>) -> Result<Creds, String> {
    if uid == 0 || gid == 0 {
        return Err(format!("{user} resolves to uid {uid} gid {gid}; a service user is never root"));
    }
    if kvm_gid == Some(0) {
        return Err(format!("{user} resolves to kvm group gid 0 (/dev/kvm's); a service user is never root"));
    }
    Ok(Creds { uid, gid, groups: Some([gid].into_iter().chain(kvm_gid).collect()) })
}

/// `name`'s uid and primary gid, through the C library's user database.
fn lookup(name: &str) -> Result<(u32, u32), String> {
    let cname = CString::new(name).map_err(|_| format!("{name}: not a user name"))?;
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    // SAFETY: passwd is plain data that getpwnam_r fills in.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the call, and `buf` outlives it.
    let rc = unsafe { libc::getpwnam_r(cname.as_ptr(), &mut pw, buf.as_mut_ptr(), buf.len(), &mut found) };
    if rc != 0 {
        return Err(format!("{name}: user lookup failed (errno {rc})"));
    }
    if found.is_null() {
        return Err(format!("{name}: no such user"));
    }
    Ok((pw.pw_uid, pw.pw_gid))
}
