//! The `tls` PD's TLS 1.3 server (M6 plan C7, C8, C10): the hybrid key
//! exchange, the key schedule and record protection over libcrux
//! primitives only; the handshake state machine; the connection slots with
//! their timers and close sequencing. The parsing and serializing is
//! `tls-wire`'s; the PD wires rings, smoltcp and `tlskey` to this.
//!
//! - [`hybrid`]: X25519MLKEM768 ([`HybridSecret`], L14).
//! - [`schedule`]: RFC 8446 section 7.1 over HKDF-SHA256.
//! - [`record`]: ChaCha20-Poly1305 record protection (section 5.2, 5.3).
//! - [`handshake`]: the server state machine ([`handshake::Session`]).
//! - [`rng`]: the hedged randomness seam.
//! - [`conn`]: slots, timeouts, per-source cap, close and wipe sequencing,
//!   and the proxy flow through them.
//! - [`halt`]: the PD's halt reasons, and the halt a refused sign ends in.

#![no_std]
#![deny(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

#[cfg(test)]
extern crate std;

pub mod conn;
pub mod halt;
pub mod handshake;
pub mod hybrid;
pub mod record;
pub mod rng;
pub mod schedule;

pub use hybrid::{HybridSecret, SCRUB_DEPTH_EXCHANGE, exchange_with_randomness, scrub_session_stack};
pub use tls_wire::{CLIENT_SHARE_LEN, Refusal, SERVER_SHARE_LEN, X25519MLKEM768};

/// The secret container (not `Copy`/`Clone`/`Debug`, zeroized on drop) and
/// the plaintext wipe (L12): the workspace's one copy, `secret`'s.
pub use secret::{Secret, wipe};

#[cfg(test)]
mod test_client;
#[cfg(test)]
mod tests;
