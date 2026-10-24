//! The TPM side of sealed secrets (M5 plan C10, C11): the client half of the
//! salted policy session that unseals an envelope's KEK ([`client`]), the
//! envelope format with its offline sealing ([`envelope`]), the primitives
//! both use ([`crypto`]), and the unseal the key PDs run at boot over
//! PPC to `tpm` ([`boot`]). The marshalling and the `tpm` PD's
//! gate are `tpm2_wire`'s.
//!
//! The crate takes its randomness from the caller (the PDs' `cpu`/hedged
//! source, `mksecrets`' /dev/urandom); it has no source of its own.

#![no_std]
#![deny(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

pub mod boot;
pub mod client;
pub mod crypto;
pub mod envelope;

/// N secret bytes: not `Copy`/`Clone`/`Debug`, zeroized on drop (L12);
/// the workspace's one container, `secret`'s.
pub use secret::Secret;

#[cfg(test)]
mod tests;
