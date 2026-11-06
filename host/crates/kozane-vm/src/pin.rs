//! `kozane-vm pin-firmware <release>` (M9 plan C4, I4.3): the only writer
//! of `/etc/kozane/firmware.pin`. The release's manifest must verify under
//! the operator's pinned release keys with the linked verifier, its
//! `RELEASE_SEQ` must not be below the pinned one, and its `u-boot.bin` must
//! be the one it signs. Only then is the new pin written, atomically; any
//! refusal leaves the old pin as it was.

use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::files::{self, Mode};
use crate::kv::{self, Pin};
use crate::privs::Sys;
use crate::resolve::Resolver;
use crate::{ETC, FIRMWARE_MAX, PIN, RELEASE_KEYS};

/// A manifest or signature file larger than this is no release.
const MANIFEST_MAX: u64 = 64 * 1024;

/// The pin as it stands, or `None` before the first one.
pub fn read_pin(path: &Path, owner: u32) -> Result<Option<Pin>, String> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
        Ok(_) => {}
    }
    let mut f = files::open_checked(path, owner, Mode::Exact(0o600))?;
    let text = files::read_bounded(&mut f, 1024, path)?;
    let text = String::from_utf8(text).map_err(|_| format!("{}: not UTF-8", path.display()))?;
    Pin::parse(&text).map(Some).map_err(|e| format!("{}: {e}", path.display()))
}

/// A release public key file's bound: ML-DSA-65's 1952 bytes in hex, and room.
const KEY_FILE_MAX: u64 = 8 << 10;

/// The pin a verified `release` gives, checked against `current`.
pub fn verified_pin(res: &Resolver, release: &Path, current: Option<&Pin>) -> Result<Pin, String> {
    let (owner, _) = res.owner();
    let keys_dir = res.path(RELEASE_KEYS);
    files::check_dir(&keys_dir, owner)?;
    // The keys are read from the descriptors checked, never reopened by name.
    let key_text = |name: &str| -> Result<String, String> {
        let p = keys_dir.join(name);
        let bytes = files::read_bounded(&mut files::open_checked(&p, owner, Mode::NotShared)?, KEY_FILE_MAX, &p)?;
        String::from_utf8(bytes).map_err(|_| format!("{}: not UTF-8", p.display()))
    };
    let keys = release::verifying_from_hex(&key_text("ed25519.pub")?, &key_text("ml-dsa-65.pub")?)?;
    let read = |name: &str, max: u64| -> Result<Vec<u8>, String> {
        let p = release.join(name);
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&p)
            .map_err(|e| format!("{}: {e}", p.display()))?;
        files::read_bounded(&mut f, max, &p)
    };
    let manifest = read("manifest", MANIFEST_MAX)?;
    let sig = read("manifest.sig", MANIFEST_MAX)?;
    let fields = release::verify_release(&keys, &manifest, &sig).map_err(|e| format!("the release does not verify: {e}"))?;
    let get = |key: &str| fields.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str()).unwrap_or_default();
    let hash = get("firmware_sha256");
    if !kv::is_sha256_hex(hash) {
        return Err("the signed firmware_sha256 is not a SHA-256".into());
    }
    let seq = kv::parse_seq(get("release_seq")).ok_or("the signed release_seq is not a canonical u32")?;
    if let Some(cur) = current
        && seq < cur.release_seq
    {
        return Err(format!("release_seq {seq} is below the pinned {}", cur.release_seq));
    }
    let shipped = files::sha256_hex(&read("u-boot.bin", FIRMWARE_MAX)?);
    if shipped != hash {
        return Err(format!("the release's u-boot.bin is {shipped}, its signed firmware_sha256 is {hash}"));
    }
    Ok(Pin { firmware_sha256: hash.to_string(), release_seq: seq })
}

/// Writes `pin` to `dir`/firmware.pin through a new 0600 file given to
/// `owner`, synced, then renamed over the old pin.
pub fn write_pin(sys: &mut impl Sys, dir: &Path, pin: &Pin, owner: (u32, u32)) -> Result<(), String> {
    let tmp = dir.join(".firmware.pin.new");
    match std::fs::remove_file(&tmp) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(format!("{}: {e}", tmp.display())),
        _ => {}
    }
    let result = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
        sys.fchown(f.as_raw_fd(), owner.0, owner.1)
            .map_err(|e| format!("{}: fchown: {}", tmp.display(), std::io::Error::from_raw_os_error(e)))?;
        f.write_all(pin.render().as_bytes()).and_then(|()| f.sync_all()).map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, dir.join(PIN_NAME)).map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::fs::File::open(dir).and_then(|d| d.sync_all()).map_err(|e| format!("{}: {e}", dir.display()))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

const PIN_NAME: &str = "firmware.pin";

pub fn pin_firmware(sys: &mut impl Sys, res: &Resolver, release: &Path) -> Result<Pin, String> {
    let owner = res.owner();
    let etc = res.path(ETC);
    files::check_dir(&etc, owner.0)?;
    let current = read_pin(&res.path(PIN), owner.0)?;
    let pin = verified_pin(res, release, current.as_ref())?;
    write_pin(sys, &etc, &pin, owner)?;
    Ok(pin)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privs::Errno;
    use std::os::fd::RawFd;

    /// Only `fchown` is reachable from the writer; it returns `result`.
    struct Chown {
        result: Result<(), Errno>,
        seen: Option<(u32, u32)>,
    }

    impl Sys for Chown {
        fn capbset_drop(&mut self, _: u32) -> Result<(), Errno> {
            unreachable!()
        }
        fn setgroups(&mut self, _: &[u32]) -> Result<(), Errno> {
            unreachable!()
        }
        fn setresgid(&mut self, _: u32) -> Result<(), Errno> {
            unreachable!()
        }
        fn setresuid(&mut self, _: u32) -> Result<(), Errno> {
            unreachable!()
        }
        fn getresuid(&mut self) -> (u32, u32, u32) {
            unreachable!()
        }
        fn getresgid(&mut self) -> (u32, u32, u32) {
            unreachable!()
        }
        fn clear_caps(&mut self) -> Result<(), Errno> {
            unreachable!()
        }
        fn no_new_privs(&mut self) -> Result<(), Errno> {
            unreachable!()
        }
        fn fchown(&mut self, _: RawFd, uid: u32, gid: u32) -> Result<(), Errno> {
            self.seen = Some((uid, gid));
            self.result
        }
    }

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
        let d = std::env::temp_dir().join(format!("kozane-vm-pin-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let d = Scratch(d);
        std::fs::create_dir_all(&*d).unwrap();
        d
    }

    fn pin(seq: u32) -> Pin {
        Pin { firmware_sha256: "ab".repeat(32), release_seq: seq }
    }

    #[test]
    fn the_pin_is_written_0600_and_handed_to_the_owner() {
        let d = scratch("ok");
        let mut sys = Chown { result: Ok(()), seen: None };
        write_pin(&mut sys, &d, &pin(3), (0, 0)).unwrap();
        assert_eq!(sys.seen, Some((0, 0)));
        let meta = std::fs::metadata(d.join(PIN_NAME)).unwrap();
        assert_eq!(std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o7777, 0o600);
        assert_eq!(Pin::parse(&std::fs::read_to_string(d.join(PIN_NAME)).unwrap()).unwrap(), pin(3));
        assert!(!d.join(".firmware.pin.new").exists());
    }

    #[test]
    fn a_failed_fchown_leaves_the_old_pin_and_no_new_file() {
        let d = scratch("chown");
        std::fs::write(d.join(PIN_NAME), pin(2).render()).unwrap();
        let mut sys = Chown { result: Err(libc::EPERM), seen: None };
        let err = write_pin(&mut sys, &d, &pin(3), (0, 0)).unwrap_err();
        assert!(err.contains("fchown"), "{err}");
        assert_eq!(std::fs::read_to_string(d.join(PIN_NAME)).unwrap(), pin(2).render());
        assert!(!d.join(".firmware.pin.new").exists());
    }

    #[test]
    fn a_stale_temporary_file_is_replaced() {
        let d = scratch("stale");
        std::fs::write(d.join(".firmware.pin.new"), b"junk").unwrap();
        write_pin(&mut Chown { result: Ok(()), seen: None }, &d, &pin(1), (0, 0)).unwrap();
        assert_eq!(std::fs::read_to_string(d.join(PIN_NAME)).unwrap(), pin(1).render());
    }

    #[test]
    fn the_pin_parses_only_its_canonical_text() {
        let good = pin(7).render();
        assert_eq!(good, format!("firmware_sha256={}\nrelease_seq=7\n", "ab".repeat(32)));
        assert_eq!(Pin::parse(&good).unwrap(), pin(7));
        for bad in [
            good.replace("release_seq=7", "release_seq=07"),
            good.replace("ab", "AB"),
            good.trim_end().to_string(),
            format!("release_seq=7\nfirmware_sha256={}\n", "ab".repeat(32)),
            format!("{good}extra=1\n"),
            good.replace("release_seq=7", "release_seq=4294967296"),
        ] {
            assert!(Pin::parse(&bad).is_err(), "{bad:?}");
        }
    }
}
