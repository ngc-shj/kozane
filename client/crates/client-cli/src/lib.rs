//! The Linux shell of the Kozane client (M9 plan C10): `kzc` (`keygen`,
//! `up`) and its privileged helper `kzc-psk`, two processes under two
//! uids (D6). No code here runs another program; the netlink, unix socket
//! and file handling are in-tree, over `libc` (`sys` is the only `unsafe`).

#![deny(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

pub mod b64;
pub mod conf;
pub mod device;
pub mod files;
pub mod ipc;
pub mod keygen;
pub mod net;
pub mod netlink;
pub mod notify;
pub mod psk;
pub mod rtnl;
pub mod seams;
pub mod sys;
pub mod wg;

use std::process::ExitCode;

/// Both binaries' `--build-info` line.
pub fn build_info() -> String {
    format!("SEAMS={}", u8::from(seams::SEAMS))
}

/// Prints `err` with the binary's prefix and fails.
pub fn exit(prefix: &str, r: Result<(), String>) -> ExitCode {
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{prefix}: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests;
