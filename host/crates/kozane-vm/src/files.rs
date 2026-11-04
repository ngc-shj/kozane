//! Opening the launcher's inputs, and the sealed copies QEMU reads.
//!
//! Every input is opened without following a symlink and checked on the
//! open fd: a regular file (or directory) owned by root, writable by no one
//! else, and for the secrets (the pin and the swtpm key) exactly mode 0600.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

pub const SEAL_ALL: libc::c_int = libc::F_SEAL_WRITE | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW;

/// What a checked input must be.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// Exactly this mode (the secrets).
    Exact(u32),
    /// Not writable by group or others.
    NotShared,
}

/// The ownership and mode check on an open file's metadata.
pub fn check_meta(what: &Path, meta: &std::fs::Metadata, owner: u32, mode: Mode, dir: bool) -> Result<(), String> {
    let kind_ok = if dir { meta.is_dir() } else { meta.is_file() };
    if !kind_ok {
        return Err(format!("{}: not a {}", what.display(), if dir { "directory" } else { "regular file" }));
    }
    if meta.uid() != owner {
        return Err(format!("{}: owned by uid {}, not {owner}", what.display(), meta.uid()));
    }
    let bits = meta.mode() & 0o7777;
    match mode {
        Mode::Exact(want) if bits != want => Err(format!("{}: mode {bits:04o}, expected {want:04o}", what.display())),
        Mode::NotShared if bits & 0o022 != 0 => Err(format!("{}: mode {bits:04o} is writable by others", what.display())),
        _ => Ok(()),
    }
}

/// `path`, opened read-only without following a symlink, after the check.
pub fn open_checked(path: &Path, owner: u32, mode: Mode) -> Result<File, String> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let meta = f.metadata().map_err(|e| format!("{}: {e}", path.display()))?;
    check_meta(path, &meta, owner, mode, false)?;
    Ok(f)
}

/// A directory on the path to the inputs: root-owned, not shared.
pub fn check_dir(path: &Path, owner: u32) -> Result<(), String> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let meta = f.metadata().map_err(|e| format!("{}: {e}", path.display()))?;
    check_meta(path, &meta, owner, Mode::NotShared, true)
}

/// At most `max` bytes of `f`; a longer file is refused.
pub fn read_bounded(f: &mut File, max: u64, what: &Path) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    f.take(max.saturating_add(1)).read_to_end(&mut out).map_err(|e| format!("{}: {e}", what.display()))?;
    if out.len() as u64 > max {
        return Err(format!("{}: larger than {max} bytes", what.display()));
    }
    Ok(out)
}

/// A memfd named `name` holding `src`'s bytes, sealed against write, shrink
/// and grow (M9 plan C4): what QEMU reads through `/dev/fd/<n>` is exactly
/// what was checked, and a memfd is readable by the unprivileged QEMU
/// although the source file is root's.
pub fn sealed_copy(name: &str, src: &mut File, max: u64, what: &Path) -> Result<File, String> {
    let size = src.metadata().map_err(|e| format!("{}: {e}", what.display()))?.len();
    if size > max {
        return Err(format!("{}: larger than {max} bytes", what.display()));
    }
    let cname = std::ffi::CString::new(name).map_err(|_| format!("{name}: bad memfd name"))?;
    // SAFETY: a valid C string and flags.
    let fd = unsafe { libc::memfd_create(cname.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    if fd == -1 {
        return Err(format!("memfd_create {name}: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: memfd_create returned a new fd that nothing else owns.
    let mut mem = unsafe { File::from_raw_fd(fd) };
    let copied = std::io::copy(&mut src.take(max.saturating_add(1)), &mut mem).map_err(|e| format!("{}: {e}", what.display()))?;
    if copied > max {
        return Err(format!("{}: larger than {max} bytes", what.display()));
    }
    mem.flush().map_err(|e| format!("{name}: {e}"))?;
    // SAFETY: fcntl on an fd we own, integer argument.
    if unsafe { libc::fcntl(mem.as_raw_fd(), libc::F_ADD_SEALS, SEAL_ALL) } == -1 {
        return Err(format!("sealing {name}: {}", std::io::Error::last_os_error()));
    }
    if seals(&mem)? & SEAL_ALL != SEAL_ALL {
        return Err(format!("{name}: the seals did not hold"));
    }
    Ok(mem)
}

/// The seals on `f`.
pub fn seals(f: &File) -> Result<libc::c_int, String> {
    // SAFETY: fcntl on an fd we own.
    let s = unsafe { libc::fcntl(f.as_raw_fd(), libc::F_GET_SEALS) };
    if s == -1 { Err(format!("F_GET_SEALS: {}", std::io::Error::last_os_error())) } else { Ok(s) }
}

/// The whole of a (sealed) memfd, read from offset 0 whatever its position.
pub fn read_all_at(f: &File, max: u64) -> Result<Vec<u8>, String> {
    let len = f.metadata().map_err(|e| e.to_string())?.len();
    if len > max {
        return Err(format!("larger than {max} bytes"));
    }
    let mut buf = vec![0u8; usize::try_from(len).map_err(|_| "too large")?];
    f.read_exact_at(&mut buf, 0).map_err(|e| e.to_string())?;
    Ok(buf)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    libcrux_sha2::sha256(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A fresh directory, removed on drop (a failing test's too).
    struct Scratch(std::path::PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    impl std::ops::Deref for Scratch {
        type Target = std::path::Path;
        fn deref(&self) -> &std::path::Path {
            &self.0
        }
    }

    fn scratch(name: &str) -> Scratch {
        let d = std::env::temp_dir().join(format!("kozane-vm-files-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let d = Scratch(d);
        std::fs::create_dir_all(&*d).unwrap();
        d
    }

    fn me() -> u32 {
        // SAFETY: cannot fail.
        unsafe { libc::geteuid() }
    }

    #[test]
    fn a_sealed_copy_holds_all_three_seals_and_the_bytes() {
        let d = scratch("seal");
        let p = d.join("u-boot.bin");
        std::fs::write(&p, b"firmware bytes").unwrap();
        let mem = sealed_copy("u-boot.bin", &mut File::open(&p).unwrap(), 1 << 20, &p).unwrap();
        assert_eq!(seals(&mem).unwrap() & SEAL_ALL, SEAL_ALL);
        assert_eq!(read_all_at(&mem, 1 << 20).unwrap(), b"firmware bytes");
        assert!((&mem).write_all(b"x").is_err(), "a sealed memfd took a write");
    }

    #[test]
    fn a_copy_larger_than_its_bound_is_refused() {
        let d = scratch("big");
        let p = d.join("big");
        std::fs::write(&p, [0u8; 100]).unwrap();
        assert!(sealed_copy("big", &mut File::open(&p).unwrap(), 99, &p).unwrap_err().contains("larger than 99"));
    }

    #[test]
    fn a_secret_with_a_loose_mode_or_through_a_symlink_is_refused() {
        let d = scratch("mode");
        let p = d.join("swtpm.key");
        std::fs::write(&p, b"k").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(open_checked(&p, me(), Mode::Exact(0o600)).unwrap_err().contains("mode 0640, expected 0600"));
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(open_checked(&p, me(), Mode::Exact(0o600)).is_ok());
        std::os::unix::fs::symlink(&p, d.join("link")).unwrap();
        assert!(open_checked(&d.join("link"), me(), Mode::Exact(0o600)).is_err());
    }

    #[test]
    fn an_input_owned_by_another_uid_is_refused() {
        let d = scratch("owner");
        let p = d.join("vm.conf");
        std::fs::write(&p, b"x").unwrap();
        let err = open_checked(&p, me().wrapping_add(1), Mode::NotShared).unwrap_err();
        assert!(err.contains("owned by uid"), "{err}");
    }

    #[test]
    fn a_group_writable_input_is_refused() {
        let d = scratch("shared");
        let p = d.join("vm.conf");
        std::fs::write(&p, b"x").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o664)).unwrap();
        assert!(open_checked(&p, me(), Mode::NotShared).unwrap_err().contains("writable by others"));
    }

    #[test]
    fn sha256_matches_a_known_answer() {
        assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
