//! The I10.1 matrix. Owner cells that need a second uid run against an
//! injected `fstat` (VE26).

use std::ffi::CString;
use std::fs;
use std::io;
use std::os::fd::BorrowedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::files::{Checker, Kind, adjudicate};
use crate::sys::{self, Meta};

struct Tmp(PathBuf);

impl Tmp {
    fn new() -> Self {
        static N: AtomicUsize = AtomicUsize::new(0);
        let p = std::env::temp_dir().join(format!("kzc-files-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
        fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn chmod(p: &Path, mode: u32) {
    fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
}

/// A key directory with `sk` (0600, 8 bytes) and `pub` (0644, 4 bytes).
fn key_dir(t: &Tmp) -> PathBuf {
    let d = t.0.join("keys");
    fs::create_dir(&d).unwrap();
    chmod(&d, 0o700);
    fs::write(d.join("sk"), [1u8; 8]).unwrap();
    chmod(&d.join("sk"), 0o600);
    fs::write(d.join("pub"), [2u8; 4]).unwrap();
    chmod(&d.join("pub"), 0o644);
    d
}

fn me() -> Checker {
    Checker::system()
}

fn as_root(fd: BorrowedFd<'_>) -> io::Result<Meta> {
    sys::fstat(fd).map(|m| Meta { uid: 0, ..m })
}

fn as_other(fd: BorrowedFd<'_>) -> io::Result<Meta> {
    sys::fstat(fd).map(|m| Meta { uid: 4242, ..m })
}

fn read_keys(c: &Checker, dir: &Path) -> Result<(), String> {
    let d = c.open_key_dir(dir)?;
    let mut sk = [0u8; 8];
    d.read_secret("sk", &mut sk)?;
    assert_eq!(sk, [1; 8]);
    assert_eq!(d.read_public("pub", 4)?, vec![2; 4]);
    Ok(())
}

#[test]
fn allows_the_stated_modes() {
    let t = Tmp::new();
    let d = key_dir(&t);
    read_keys(&me(), &d).unwrap();
}

#[test]
fn allows_a_symlinked_ancestor() {
    let t = Tmp::new();
    let d = key_dir(&t);
    let real = t.0.join("real");
    fs::create_dir(&real).unwrap();
    fs::rename(&d, real.join("keys")).unwrap();
    symlink(&real, t.0.join("via")).unwrap();
    read_keys(&me(), &t.0.join("via").join("keys")).unwrap();
}

#[test]
fn denies_loose_secret_key_modes() {
    for mode in [0o640, 0o604, 0o644, 0o400] {
        let t = Tmp::new();
        let d = key_dir(&t);
        chmod(&d.join("sk"), mode);
        let e = read_keys(&me(), &d).expect_err("kzc: loose mode accepted");
        assert!(e.contains("mode"), "{mode:o}: {e}");
    }
}

#[test]
fn denies_loose_key_directory_modes() {
    for mode in [0o750, 0o777, 0o711] {
        let t = Tmp::new();
        let d = key_dir(&t);
        chmod(&d, mode);
        let e = read_keys(&me(), &d).expect_err("kzc: loose mode accepted");
        assert!(e.contains("mode"), "{mode:o}: {e}");
    }
}

#[test]
fn denies_a_public_key_other_than_0644() {
    for mode in [0o664, 0o600, 0o646] {
        let t = Tmp::new();
        let d = key_dir(&t);
        chmod(&d.join("pub"), mode);
        read_keys(&me(), &d).expect_err("kzc: loose mode accepted");
    }
}

#[test]
fn denies_a_symlinked_leaf_key() {
    let t = Tmp::new();
    let d = key_dir(&t);
    fs::rename(d.join("sk"), t.0.join("sk-real")).unwrap();
    symlink(t.0.join("sk-real"), d.join("sk")).unwrap();
    let e = read_keys(&me(), &d).expect_err("kzc: symlink accepted");
    assert!(e.contains("symlink"), "{e}");
}

#[test]
fn denies_a_symlinked_key_directory() {
    let t = Tmp::new();
    let d = key_dir(&t);
    symlink(&d, t.0.join("link")).unwrap();
    let e = read_keys(&me(), &t.0.join("link")).expect_err("kzc: symlink accepted");
    assert!(e.contains("symlink"), "{e}");
}

#[test]
fn denies_a_key_owned_by_another_uid() {
    let t = Tmp::new();
    let d = key_dir(&t);
    let other = Checker { euid: sys::geteuid(), fstat: as_other };
    let e = read_keys(&other, &d).unwrap_err();
    assert!(e.contains("owned by uid 4242"), "{e}");
}

#[test]
fn denies_a_key_of_the_wrong_length() {
    let t = Tmp::new();
    let d = key_dir(&t);
    fs::write(d.join("sk"), [1u8; 9]).unwrap();
    assert!(read_keys(&me(), &d).unwrap_err().contains("want 8"));
}

#[test]
fn denies_a_non_regular_key() {
    let t = Tmp::new();
    let d = key_dir(&t);
    fs::remove_file(d.join("sk")).unwrap();
    let fifo = CString::new(d.join("sk").as_os_str().as_bytes()).unwrap();
    // SAFETY: a NUL-terminated path; mkfifo only creates the node.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let e = read_keys(&me(), &d).unwrap_err();
    assert!(e.contains("not a regular file"), "{e}");
}

fn root_file(t: &Tmp, mode: u32) -> PathBuf {
    let p = t.0.join("client.conf");
    fs::write(&p, "interface = kz0\n").unwrap();
    chmod(&p, mode);
    p
}

fn root() -> Checker {
    Checker { euid: sys::geteuid(), fstat: as_root }
}

#[test]
fn allows_a_root_owned_0644_settings_file() {
    let t = Tmp::new();
    let p = root_file(&t, 0o644);
    assert_eq!(root().read_root_file(&p, 1024).unwrap(), b"interface = kz0\n");
    let p = root_file(&t, 0o600);
    root().read_root_file(&p, 1024).unwrap();
}

#[test]
fn denies_a_group_or_world_writable_settings_file() {
    // client.conf and gw_rp_pub_path go through the same check.
    for mode in [0o664, 0o646, 0o666] {
        let t = Tmp::new();
        let p = root_file(&t, mode);
        let e = root().read_root_file(&p, 1024).expect_err("kzc: loose mode accepted");
        assert!(e.contains("writable"), "{mode:o}: {e}");
    }
}

#[test]
fn denies_a_settings_file_not_owned_by_root() {
    let t = Tmp::new();
    let p = root_file(&t, 0o644);
    let other = Checker { euid: 0, fstat: as_other };
    let e = other.read_root_file(&p, 1024).unwrap_err();
    assert!(e.contains("owned by uid 4242, want 0"), "{e}");
}

#[test]
fn denies_a_symlinked_settings_file() {
    let t = Tmp::new();
    let p = root_file(&t, 0o644);
    symlink(&p, t.0.join("link.conf")).unwrap();
    let e = root().read_root_file(&t.0.join("link.conf"), 1024).expect_err("kzc: symlink accepted");
    assert!(e.contains("symlink"), "{e}");
}

#[test]
fn denies_a_directory_as_settings_file_and_an_oversized_one() {
    let t = Tmp::new();
    assert!(root().read_root_file(&t.0, 1024).unwrap_err().contains("not a regular file"));
    let p = root_file(&t, 0o644);
    assert!(root().read_root_file(&p, 4).unwrap_err().contains("larger than"));
}

#[test]
fn adjudicates_each_kind() {
    let m = |mode: u32, uid: u32| Meta { mode, uid, size: 0 };
    let (dir, reg) = (libc::S_IFDIR, libc::S_IFREG);
    assert!(adjudicate(Kind::KeyDir, &m(dir | 0o700, 7), 7).is_ok());
    assert!(adjudicate(Kind::KeyDir, &m(reg | 0o700, 7), 7).is_err());
    assert!(adjudicate(Kind::KeyDir, &m(dir | 0o700, 8), 7).is_err());
    assert!(adjudicate(Kind::SecretKey, &m(reg | 0o600, 7), 7).is_ok());
    assert!(adjudicate(Kind::SecretKey, &m(reg | 0o4600, 7), 7).is_err());
    assert!(adjudicate(Kind::PublicKey, &m(reg | 0o644, 7), 7).is_ok());
    assert!(adjudicate(Kind::RootFile, &m(reg | 0o644, 0), 7).is_ok());
    assert!(adjudicate(Kind::RootFile, &m(reg | 0o644, 7), 7).is_err());
    assert!(adjudicate(Kind::RootFile, &m(libc::S_IFLNK | 0o644, 0), 7).is_err());
}
