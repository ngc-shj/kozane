//! WireGuard responder core: primitives, the Noise_IKpsk2 responder
//! handshake and transport sessions. The crypto-free codecs and replay
//! window live in `wg-wire` (re-exported as `wire` and `replay`) so Kani
//! can check them without compiling libcrux.
//!
//! `noise` never sees the gateway's static private key or any PSK: both
//! stay behind the `StaticKey` trait, which the `key` PD implements over PPC.

#![no_std]
#![deny(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

pub mod cookie;
pub mod crypto;
pub mod noise;
pub mod session;

pub use wg_wire as wire;
pub use wg_wire::replay;

/// Limits from the whitepaper, section 6.1.
pub use wg_wire::REJECT_AFTER_MESSAGES;
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
pub const REKEY_AFTER_TIME_NS: u64 = 120 * NS_PER_SEC;
pub const REJECT_AFTER_TIME_NS: u64 = 180 * NS_PER_SEC;
pub const REKEY_TIMEOUT_NS: u64 = 5 * NS_PER_SEC;
pub const KEEPALIVE_TIMEOUT_NS: u64 = 10 * NS_PER_SEC;

const NS_PER_SEC: u64 = 1_000_000_000;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod tests_cookie;

#[cfg(test)]
mod tests_handshake;
