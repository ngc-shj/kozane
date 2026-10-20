//! Rosenpass V02 responder: hash domains, biscuits, the responder state
//! machine and OSK export (M3 plan C1).
//!
//! Interoperates with upstream rosenpass `9e72f1eb` (and 0.2.3) in V02:
//! Classic McEliece 460896 round 3, Kyber-512 round 3, the "incorrect HMAC"
//! over keyed BLAKE2b, ChaCha20-Poly1305 and XChaCha20-Poly1305. Responder
//! only (SC22), no PSK (SC25). The cookie mechanism's crypto is `cookie`
//! (M3b, SC26); the gate that uses it is `ingress`'s. The golden vectors in
//! `tests/vectors` come from upstream through `tools/rp-vectors`.
//!
//! The McEliece secret never enters this crate: decapsulation is the
//! `Decaps` seam (`pqkey`'s `PQ_DECAPS`). Randomness is the `Rng` seam (the
//! PD's hedged source) and time is the caller's monotonic `now` in ns.

#![no_std]
#![deny(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

mod chain;
pub mod cookie;
pub mod crypto;
pub mod kem;
mod responder;
mod secret;

pub use crypto::{CryptoError, Domains, KEY_LEN};
pub use kem::{
    Decaps, DecapsError, Encaps, EncapsError, HedgeHw, Hedged, Kyber512, McEliece460896, Rng, RngError, SHK_LEN, SPK_LEN,
};
pub use responder::{
    BISCUIT_EPOCH_NS, Conf, Error, KNOWN_RESPONSE_TTL_NS, PendingExport, PskInstall, Responder, Seams, envelope_mac,
    mac_key, peer_id,
};
pub use secret::Secret;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_responder;
