//! I4.3 (M9 plan C4): `kozane-vm pin-firmware` pins only a release whose
//! manifest verifies under the pinned release keys and whose RELEASE_SEQ is
//! not below the pin; every refusal leaves the pin as it was. Runs only in
//! a `test-seams` build (`--root-prefix`, `--user-map`).

// The stand-ins and the root prefix need the test seams.
#![cfg(feature = "test-seams")]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use release::{manifest, sig};

const BIN: &str = env!("CARGO_BIN_EXE_kozane-vm");
const FIRMWARE: &[u8] = b"u-boot stand-in, as released\n";

fn sha256_hex(b: &[u8]) -> String {
    libcrux_sha2::sha256(b).iter().map(|x| format!("{x:02x}")).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn rng(seed: u8) -> impl FnMut(&mut [u8]) -> bool {
    let mut n = seed;
    move |buf: &mut [u8]| {
        for b in buf.iter_mut() {
            *b = n;
            n = n.wrapping_add(13);
        }
        true
    }
}

struct Case {
    root: PathBuf,
    keys: sig::SigningKeys,
    other: sig::SigningKeys,
}

impl Drop for Case {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn case(name: &str) -> Case {
    let root = std::env::temp_dir().join(format!("kozane-vm-pin-it-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let (keys, public) = sig::keygen(&mut rng(1)).unwrap();
    let (other, _) = sig::keygen(&mut rng(2)).unwrap();
    let c = Case { root, keys, other };
    let root = &c.root;
    std::fs::create_dir_all(root.join("etc/kozane/release-keys")).unwrap();
    // Modes set, not left to the umask: the checks refuse shared ones.
    for d in [root.clone(), root.join("etc"), root.join("etc/kozane"), root.join("etc/kozane/release-keys")] {
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    for (name, text) in [("ed25519.pub", format!("{}\n", hex(&public.ed25519))), ("ml-dsa-65.pub", format!("{}\n", hex(public.ml_dsa.as_ref())))] {
        let p = root.join("etc/kozane/release-keys").join(name);
        std::fs::write(&p, text).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    c
}

impl Case {
    fn pin_path(&self) -> PathBuf {
        self.root.join("etc/kozane/firmware.pin")
    }

    fn set_pin(&self, seq: u32) -> String {
        let text = format!("firmware_sha256={}\nrelease_seq={seq}\n", "cd".repeat(32));
        std::fs::write(self.pin_path(), &text).unwrap();
        std::fs::set_permissions(self.pin_path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        text
    }

    fn pin(&self) -> Option<String> {
        std::fs::read_to_string(self.pin_path()).ok()
    }

    /// A release directory signed by `by`, with `release_seq` = `seq`.
    fn release(&self, name: &str, seq: u32, by: &sig::SigningKeys) -> PathBuf {
        let dir = self.root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let fw = sha256_hex(FIRMWARE);
        let seq = seq.to_string();
        let m = manifest::render(&[
            ("boot_desc_sha256", "aa"),
            ("cargo_lock_sha256", "bb"),
            ("commit", "0123456789abcdef0123456789abcdef01234567"),
            ("dev_image", "x"),
            ("firmware_sha256", &fw),
            ("kani", "x"),
            ("kozane_vm_sha256", "cc"),
            ("loader_img_sha256", "dd"),
            ("pcrs", "x"),
            ("release_seq", &seq),
            ("verus", "x"),
            ("version", "m9-test"),
        ])
        .unwrap();
        let s = sig::sign(by, &m, &mut rng(3)).unwrap();
        std::fs::write(dir.join("manifest"), m).unwrap();
        std::fs::write(dir.join("manifest.sig"), s).unwrap();
        std::fs::write(dir.join("u-boot.bin"), FIRMWARE).unwrap();
        dir
    }

    fn pin_firmware(&self, release: &Path) -> Output {
        Command::new(BIN).arg("--root-prefix").arg(&self.root).arg("--user-map").arg("pin-firmware").arg(release).output().unwrap()
    }
}

fn text(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

fn want_pin(seq: u32) -> String {
    format!("firmware_sha256={}\nrelease_seq={seq}\n", sha256_hex(FIRMWARE))
}

#[test]
fn i4_3_allow_a_verified_release_is_pinned_0600() {
    let c = case("first");
    let rel = c.release("rel", 3, &c.keys);
    let out = c.pin_firmware(&rel);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(c.pin(), Some(want_pin(3)));
    assert_eq!(std::fs::metadata(c.pin_path()).unwrap().permissions().mode() & 0o7777, 0o600);
}

#[test]
fn i4_3_allow_a_newer_or_equal_release_replaces_the_pin() {
    let c = case("newer");
    c.set_pin(5);
    for seq in [5, 6] {
        let out = c.pin_firmware(&c.release(&format!("rel{seq}"), seq, &c.keys));
        assert!(out.status.success(), "{}", text(&out));
        assert_eq!(c.pin(), Some(want_pin(seq)));
    }
}

#[test]
fn i4_3_deny_a_release_signed_by_another_key() {
    let c = case("other-key");
    let before = c.set_pin(1);
    let out = c.pin_firmware(&c.release("rel", 2, &c.other));
    assert!(!out.status.success() && c.pin() == Some(before), "pin-firmware: unsigned release pinned\n{}", text(&out));
    assert!(text(&out).contains("does not verify"), "{}", text(&out));
}

#[test]
fn a_release_key_file_past_its_bound_is_refused() {
    // Read from the checked descriptor, bounded (code review S4): padding
    // past 8 KiB is refused, though the key itself is intact.
    let c = case("key-bound");
    let before = c.set_pin(1);
    let path = c.root.join("etc/kozane/release-keys/ml-dsa-65.pub");
    let mut padded = std::fs::read_to_string(&path).unwrap();
    padded.push_str(&"\n".repeat(8 << 10));
    std::fs::write(&path, padded).unwrap();
    let out = c.pin_firmware(&c.release("rel", 2, &c.keys));
    assert!(!out.status.success() && c.pin() == Some(before), "pin-firmware: pinned with an oversized key file\n{}", text(&out));
    assert!(text(&out).contains("ml-dsa-65.pub") && text(&out).contains("larger than"), "{}", text(&out));
}

#[test]
fn i4_3_deny_a_manifest_edited_after_signing() {
    let c = case("edited");
    let before = c.set_pin(1);
    let rel = c.release("rel", 2, &c.keys);
    let m = std::fs::read_to_string(rel.join("manifest")).unwrap().replace("release_seq=2", "release_seq=9");
    std::fs::write(rel.join("manifest"), m).unwrap();
    let out = c.pin_firmware(&rel);
    assert!(!out.status.success() && c.pin() == Some(before), "pin-firmware: unsigned release pinned\n{}", text(&out));
}

#[test]
fn i4_3_deny_a_release_without_a_signature() {
    let c = case("unsigned");
    let rel = c.release("rel", 2, &c.keys);
    std::fs::remove_file(rel.join("manifest.sig")).unwrap();
    let out = c.pin_firmware(&rel);
    assert!(!out.status.success() && c.pin().is_none(), "pin-firmware: unsigned release pinned\n{}", text(&out));
}

#[test]
fn i4_3_deny_an_older_release() {
    let c = case("older");
    let before = c.set_pin(5);
    let out = c.pin_firmware(&c.release("rel", 4, &c.keys));
    assert!(!out.status.success() && c.pin() == Some(before), "pin-firmware: older release pinned\n{}", text(&out));
    assert!(text(&out).contains("release_seq 4 is below the pinned 5"), "{}", text(&out));
}

#[test]
fn deny_a_release_whose_u_boot_is_not_the_signed_one() {
    let c = case("swapped-fw");
    let rel = c.release("rel", 2, &c.keys);
    std::fs::write(rel.join("u-boot.bin"), b"another u-boot").unwrap();
    let out = c.pin_firmware(&rel);
    assert!(!out.status.success() && c.pin().is_none(), "{}", text(&out));
    assert!(text(&out).contains("its signed firmware_sha256 is"), "{}", text(&out));
}

#[test]
fn deny_release_keys_writable_by_others() {
    let c = case("loose-keys");
    std::fs::set_permissions(c.root.join("etc/kozane/release-keys"), std::fs::Permissions::from_mode(0o777)).unwrap();
    let out = c.pin_firmware(&c.release("rel", 2, &c.keys));
    assert!(!out.status.success() && c.pin().is_none(), "{}", text(&out));
    assert!(text(&out).contains("writable by others"), "{}", text(&out));
}
