//! Unit tests (M9 plan C10). Failure messages that name an injection's
//! needle (`kzc: …`, `kzc-psk: …`) are printed only when the control they
//! test is gone.

#![allow(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

mod b64;
mod conf;
mod device;
mod files;
mod ipc;
mod netlink;
