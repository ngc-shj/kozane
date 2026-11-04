//! `kozane-vm --build-info` (M9 plan C4): SEAMS=1 exactly when the build has
//! the test seams, and the digest of the argv it embedded, which is the file
//! `tools/vm.py` rendered. The plain `cargo test` sees SEAMS=0, the
//! `--features kozane-vm/test-seams` run SEAMS=1.

use std::process::Command;

#[test]
fn build_info_reports_the_seams_and_the_embedded_argv() {
    let out = Command::new(env!("CARGO_BIN_EXE_kozane-vm")).arg("--build-info").output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    let seams = if cfg!(feature = "test-seams") { "SEAMS=1" } else { "SEAMS=0" };
    let rendered = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../build/host/vm-args.json")).unwrap();
    let digest: String = libcrux_sha2::sha256(&rendered).iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(text, format!("{seams}\nVM_ARGS_SHA256={digest}\n"));
}

#[test]
fn a_release_build_refuses_the_seam_options() {
    if cfg!(feature = "test-seams") {
        return;
    }
    let out = Command::new(env!("CARGO_BIN_EXE_kozane-vm")).args(["--root-prefix", "/tmp", "--build-info"]).output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("usage:"));
}
