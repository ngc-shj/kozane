//! I4.1 and I4.2 (M9 plan C4): `kozane-vm` boots a node whose QEMU and
//! swtpm are argv-recording stand-ins, in a user and network namespace
//! (`unshare -rn`, VE26) where it can create its taps and join them to two
//! bridges. Runs only in a `test-seams` build:
//! `cargo test --locked --features kozane-vm/test-seams`.

// The stand-ins and the root prefix need the test seams.
#![cfg(feature = "test-seams")]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_kozane-vm");
const MEDIA: [&str; 8] =
    ["published.img", "boot.desc", "secrets.env", "pq_secrets.env", "tls_secrets.env", "audit_secrets.env", "slot-a.bin", "slot-b.bin"];
const FIRMWARE: &[u8] = b"u-boot stand-in for the launcher's pin\n";

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn repo() -> PathBuf {
    crate_dir().join("../../..")
}

fn sha256_hex(b: &[u8]) -> String {
    libcrux_sha2::sha256(b).iter().map(|x| format!("{x:02x}")).collect()
}

fn write(p: &Path, data: &[u8], mode: u32) {
    std::fs::write(p, data).unwrap();
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// A test's root prefix, removed on drop (a failing test's too).
struct Node(PathBuf);

impl Drop for Node {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl std::ops::Deref for Node {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

/// A node under a fresh root prefix: the launcher's /etc/kozane, the node
/// directory, the swtpm state and log directories, and the stand-ins.
fn node(name: &str) -> Node {
    let root = std::env::temp_dir().join(format!("kozane-vm-it-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let root = Node(root);
    for d in ["etc/kozane", "var/lib/kozane/node", "var/lib/kozane/swtpm", "var/log/kozane", "stubs"] {
        std::fs::create_dir_all(root.join(d)).unwrap();
    }
    for stub in ["qemu", "swtpm", "inventory.py"] {
        std::fs::copy(crate_dir().join("tests/stubs").join(stub), root.join("stubs").join(stub)).unwrap();
    }
    let conf = format!(
        "inside_bridge=kzbr-in\noutside_bridge=kzbr-out\nqemu={}\nswtpm={}\n",
        root.join("stubs/qemu").display(),
        root.join("stubs/swtpm").display()
    );
    write(&root.join("etc/kozane/vm.conf"), conf.as_bytes(), 0o644);
    write(&root.join("etc/kozane/firmware.pin"), pin_text(&sha256_hex(FIRMWARE), 1).as_bytes(), 0o600);
    write(&root.join("etc/kozane/swtpm.key"), b"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n", 0o600);
    write(&root.join("var/lib/kozane/node/u-boot.bin"), FIRMWARE, 0o644);
    for m in MEDIA {
        write(&root.join("var/lib/kozane/node").join(m), format!("{m} bytes\n").as_bytes(), 0o644);
    }
    root
}

fn pin_text(hash: &str, seq: u32) -> String {
    format!("firmware_sha256={hash}\nrelease_seq={seq}\n")
}

/// `kozane-vm` as root of a new user and network namespace holding the two
/// bridges its config names.
fn boot(root: &Path) -> Output {
    Command::new("unshare")
        .args([
            "-rn",
            "sh",
            "-c",
            "ip link add kzbr-out type bridge && ip link add kzbr-in type bridge && exec \"$0\" --root-prefix \"$1\" --user-map",
            BIN,
        ])
        .arg(root)
        .output()
        .unwrap()
}

fn text(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

fn ran(root: &Path) -> bool {
    root.join("stubs/qemu.json").exists() || root.join("stubs/swtpm.json").exists()
}

#[test]
fn i4_1_the_children_get_vm_py_argv_and_exactly_their_checked_fds() {
    let root = node("allow");
    let out = boot(&root);
    let log = text(&out);
    assert!(out.status.success(), "kozane-vm failed:\n{log}");
    let check = Command::new("python3").arg(crate_dir().join("tests/stubs/check_launch.py")).arg(repo()).arg(&*root).output().unwrap();
    assert!(check.status.success(), "{}\nlauncher:\n{log}", text(&check));
    // The reader child teed the console and reported the heartbeat; root
    // never parsed it.
    let console = std::fs::read_to_string(root.join("var/log/kozane/console.log")).unwrap();
    assert!(console.contains("audit: Heartbeat ticks=60\r"), "console log: {console:?}");
    assert!(log.contains("kozane-vm: guest heartbeat"), "vm-launcher: heartbeat not reported\n{log}");
    assert!(!log.contains("U-Boot stand-in"), "vm-launcher: guest console outside the root-only log\n{log}");
    let mode = std::fs::metadata(root.join("var/log/kozane/console.log")).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode, 0o600);
}

#[test]
fn a_console_closed_before_qemu_exits_still_ends_cleanly() {
    let root = node("console-first");
    write(&root.join("stubs/console-first"), b"0", 0o644);
    let out = boot(&root);
    assert!(out.status.success(), "vm-launcher: the reader's EOF before QEMU's exit failed the boot\n{}", text(&out));
}

#[test]
fn a_qemu_failing_after_its_console_closed_fails_the_boot() {
    let root = node("console-first-fail");
    write(&root.join("stubs/console-first"), b"3", 0o644);
    let out = boot(&root);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("qemu exited (exit status: 3)"), "{}", text(&out));
}

#[test]
fn i4_2_a_firmware_other_than_the_pinned_one_is_refused() {
    let root = node("deny-hash");
    write(&root.join("etc/kozane/firmware.pin"), pin_text(&sha256_hex(b"another u-boot"), 1).as_bytes(), 0o600);
    let out = boot(&root);
    assert!(!out.status.success() && !ran(&root), "vm-launcher: unpinned firmware ran\n{}", text(&out));
    assert!(text(&out).contains("is not the pinned"), "{}", text(&out));
}

#[test]
fn i4_2_a_firmware_file_changed_after_pinning_is_refused() {
    let root = node("deny-file");
    write(&root.join("var/lib/kozane/node/u-boot.bin"), b"u-boot stand-in, one byte changed\n", 0o644);
    let out = boot(&root);
    assert!(!out.status.success() && !ran(&root), "vm-launcher: unpinned firmware ran\n{}", text(&out));
}

#[test]
fn i4_2_no_pin_means_no_boot() {
    let root = node("deny-nopin");
    std::fs::remove_file(root.join("etc/kozane/firmware.pin")).unwrap();
    let out = boot(&root);
    assert!(!out.status.success() && !ran(&root), "vm-launcher: unpinned firmware ran\n{}", text(&out));
    assert!(text(&out).contains("firmware.pin"), "{}", text(&out));
}

#[test]
fn a_pin_or_key_readable_by_others_is_refused() {
    for file in ["firmware.pin", "swtpm.key"] {
        let root = node(&format!("deny-mode-{file}"));
        std::fs::set_permissions(root.join("etc/kozane").join(file), std::fs::Permissions::from_mode(0o644)).unwrap();
        let out = boot(&root);
        assert!(!out.status.success() && !ran(&root), "{file}: {}", text(&out));
        assert!(text(&out).contains("mode 0644, expected 0600"), "{}", text(&out));
    }
}

#[test]
fn a_qemu_program_others_can_write_is_refused_before_any_child_starts() {
    let root = node("deny-program");
    std::fs::set_permissions(root.join("stubs/qemu"), std::fs::Permissions::from_mode(0o775)).unwrap();
    let out = boot(&root);
    assert!(!out.status.success() && !ran(&root), "vm-launcher: a writable qemu ran\n{}", text(&out));
    assert!(text(&out).contains("stubs/qemu: mode 0775 is writable by others"), "{}", text(&out));
}

#[test]
fn a_swtpm_program_others_can_write_is_refused_before_any_child_starts() {
    let root = node("deny-swtpm-program");
    std::fs::set_permissions(root.join("stubs/swtpm"), std::fs::Permissions::from_mode(0o775)).unwrap();
    let out = boot(&root);
    assert!(!out.status.success() && !ran(&root), "vm-launcher: a writable swtpm ran\n{}", text(&out));
    assert!(text(&out).contains("stubs/swtpm: mode 0775 is writable by others"), "{}", text(&out));
}

#[test]
fn a_missing_bridge_is_refused_before_any_child_starts() {
    let root = node("deny-bridge");
    let conf = std::fs::read_to_string(root.join("etc/kozane/vm.conf")).unwrap().replace("kzbr-in", "kzbr-none");
    write(&root.join("etc/kozane/vm.conf"), conf.as_bytes(), 0o644);
    let out = boot(&root);
    assert!(!out.status.success() && !ran(&root), "{}", text(&out));
    assert!(text(&out).contains("to bridge kzbr-none"), "{}", text(&out));
}
