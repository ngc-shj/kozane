//! M9 plan C9: the C harness, compiled with `cc -Wall -Werror` against
//! `include/kozane_client.h` and this crate's staticlib, then run under
//! valgrind with `--error-exitcode=1` and no suppressions.
//!
//! The staticlib is built here, in the shipped release profile
//! (`panic = "unwind"`) with the `test-panic` seam, so the harness proves
//! that a panic in that profile returns `KZ_ERR_INTERNAL`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn client_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

/// The release staticlib with the panic seam, in a target directory of its
/// own so the outer `cargo test` keeps its lock.
fn staticlib() -> PathBuf {
    let target = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi-release");
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = Command::new(cargo)
        .current_dir(client_dir())
        .args(["build", "--locked", "--release", "-p", "kozane-client-ffi", "--features", "test-panic", "--target-dir"])
        .arg(&target)
        .status()
        .expect("ffi: cargo not found");
    assert!(status.success(), "ffi: release staticlib does not build");
    target.join("release/libkozane_client_ffi.a")
}

#[test]
fn the_c_harness_passes_under_valgrind() {
    let lib = staticlib();
    let exe = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi-harness");
    let dir = client_dir();
    let status = Command::new("cc")
        .args(["-std=c11", "-Wall", "-Wextra", "-Werror", "-g", "-I"])
        .arg(dir.join("include"))
        .arg(dir.join("tests/ffi/harness.c"))
        .arg(&lib)
        .args(["-lgcc_s", "-lutil", "-lrt", "-lpthread", "-lm", "-ldl", "-lc", "-o"])
        .arg(&exe)
        .status()
        .expect("ffi: cc not found");
    assert!(status.success(), "ffi: harness does not compile against the header");

    let out = Command::new("valgrind")
        .args(["--error-exitcode=1", "--leak-check=full", "-q"])
        .arg(&exe)
        .output()
        .expect("ffi: valgrind not found");
    let stderr = String::from_utf8_lossy(&out.stderr);
    // The harness exits 2 on a failed check; valgrind exits 1 on an error.
    match out.status.code() {
        Some(0) => {}
        Some(1) => panic!("ffi: memcheck errors\n{stderr}"),
        Some(2) => panic!("ffi: harness checks failed\n{stderr}"),
        code => panic!("ffi: harness died ({code:?})\n{stderr}"),
    }
    assert_eq!(String::from_utf8_lossy(&out.stdout), "ffi harness: ok\n");
}
