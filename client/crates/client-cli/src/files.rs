//! I10.1, fail-closed; the adjudicator is `fstat` on each opened fd.
//!
//! - Directories are opened `O_DIRECTORY|O_NOFOLLOW`, files
//!   `openat(…, O_NOFOLLOW)`: an ancestor may be a symlink, the leaf may
//!   not.
//! - A key directory is 0700 and owned by the euid; a secret key is 0600
//!   and a public key 0644, both owned by the euid.
//! - `client.conf` and `gw_rp_pub_path` are owned by root and neither
//!   group- nor world-writable.
//! - Every file is regular, and a key has exactly its length.
//!
//! `fstat` is a field of [`Checker`], so the cross-uid cells (another
//! owner, a non-root `client.conf`) are tested against an injected result
//! (VE26).

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;

use crate::sys::{self, Meta};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    KeyDir,
    SecretKey,
    PublicKey,
    /// `client.conf` and the gateway's pinned key.
    RootFile,
}

const S_IFMT: u32 = libc::S_IFMT;
const S_IFDIR: u32 = libc::S_IFDIR;
const S_IFREG: u32 = libc::S_IFREG;

/// Whether `meta` is acceptable for `kind` under `euid`.
pub fn adjudicate(kind: Kind, meta: &Meta, euid: u32) -> Result<(), String> {
    let (want_type, type_name) = if kind == Kind::KeyDir { (S_IFDIR, "a directory") } else { (S_IFREG, "a regular file") };
    if meta.mode & S_IFMT != want_type {
        return Err(format!("not {type_name}"));
    }
    let perm = meta.mode & 0o7777;
    let (owner, mode_ok, want) = match kind {
        Kind::KeyDir => (euid, perm == 0o700, "0700"),
        Kind::SecretKey => (euid, perm == 0o600, "0600"),
        Kind::PublicKey => (euid, perm == 0o644, "0644"),
        Kind::RootFile => (0, perm & 0o022 == 0, "not group- or world-writable"),
    };
    if meta.uid != owner {
        return Err(format!("owned by uid {}, want {owner}", meta.uid));
    }
    if !mode_ok {
        return Err(format!("mode {perm:04o}, want {want}"));
    }
    Ok(())
}

fn open_error(path: &Path, e: &io::Error) -> String {
    match e.raw_os_error() {
        Some(libc::ELOOP) => format!("{}: a symlink, refused", path.display()),
        Some(libc::ENOTDIR) => format!("{}: not a directory (or a symlink), refused", path.display()),
        _ => format!("{}: {e}", path.display()),
    }
}

pub type Fstat = fn(BorrowedFd<'_>) -> io::Result<Meta>;

/// The I10.1 checks for one process: its euid and its `fstat`.
#[derive(Clone, Copy)]
pub struct Checker {
    pub euid: u32,
    pub fstat: Fstat,
}

impl Checker {
    pub fn system() -> Self {
        Self { euid: sys::geteuid(), fstat: sys::fstat }
    }

    fn admit(&self, fd: &OwnedFd, kind: Kind, path: &Path) -> Result<Meta, String> {
        let meta = (self.fstat)(fd.as_fd()).map_err(|e| format!("{}: fstat: {e}", path.display()))?;
        adjudicate(kind, &meta, self.euid).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(meta)
    }

    /// A key directory, checked.
    pub fn open_key_dir<'a>(&'a self, path: &'a Path) -> Result<KeyDir<'a>, String> {
        let fd = sys::open(path, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .map_err(|e| open_error(path, &e))?;
        self.admit(&fd, Kind::KeyDir, path)?;
        Ok(KeyDir { fd, path, checker: self })
    }

    /// A root-owned settings file, at most `max` bytes.
    pub fn read_root_file(&self, path: &Path, max: u64) -> Result<Vec<u8>, String> {
        let fd = sys::open(path, libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
            .map_err(|e| open_error(path, &e))?;
        let meta = self.admit(&fd, Kind::RootFile, path)?;
        if meta.size > max {
            return Err(format!("{}: larger than {max} bytes", path.display()));
        }
        let mut out = Vec::new();
        File::from(fd).take(max.saturating_add(1)).read_to_end(&mut out).map_err(|e| format!("{}: {e}", path.display()))?;
        if u64::try_from(out.len()).map_or(true, |n| n > max) {
            return Err(format!("{}: larger than {max} bytes", path.display()));
        }
        Ok(out)
    }
}

/// An opened, checked key directory; its files are opened relative to it.
pub struct KeyDir<'a> {
    fd: OwnedFd,
    path: &'a Path,
    checker: &'a Checker,
}

impl KeyDir<'_> {
    fn open(&self, name: &str, kind: Kind, len: usize) -> Result<File, String> {
        let path = self.path.join(name);
        let fd = sys::openat(
            self.fd.as_fd(),
            OsStr::new(name),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY,
            0,
        )
        .map_err(|e| open_error(&path, &e))?;
        let meta = self.checker.admit(&fd, kind, &path)?;
        if u64::try_from(len).ok() != Some(meta.size) {
            return Err(format!("{}: {} bytes, want {len}", path.display(), meta.size));
        }
        Ok(File::from(fd))
    }

    /// A secret key of exactly `out.len()` bytes, read into `out` (which
    /// the caller locked and wipes).
    pub fn read_secret(&self, name: &str, out: &mut [u8]) -> Result<(), String> {
        let mut f = self.open(name, Kind::SecretKey, out.len())?;
        read_all(&mut f, out).map_err(|e| format!("{}: {e}", self.path.join(name).display()))
    }

    /// A public key of exactly `len` bytes.
    pub fn read_public(&self, name: &str, len: usize) -> Result<Vec<u8>, String> {
        let mut f = self.open(name, Kind::PublicKey, len)?;
        let mut out = vec![0u8; len];
        read_all(&mut f, &mut out).map_err(|e| format!("{}: {e}", self.path.join(name).display()))?;
        Ok(out)
    }
}

/// Fills `out` and requires the end of the file right after.
fn read_all(f: &mut File, out: &mut [u8]) -> io::Result<()> {
    f.read_exact(out)?;
    let mut extra = [0u8; 1];
    if f.read(&mut extra)? != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "longer than its length"));
    }
    Ok(())
}
