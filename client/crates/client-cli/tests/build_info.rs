//! The test build of both binaries carries the seams; the release build's
//! `SEAMS=0` is checked where it is built (M9 plan C4's pin).

use std::process::Command;

#[test]
fn test_binaries_carry_the_seams() {
    for bin in [env!("CARGO_BIN_EXE_kzc"), env!("CARGO_BIN_EXE_kzc-psk")] {
        let out = Command::new(bin).arg("--build-info").output().unwrap();
        assert!(out.status.success());
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "SEAMS=1", "{bin}");
    }
}
