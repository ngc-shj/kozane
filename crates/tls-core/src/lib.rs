//! The `tls` PD's TLS 1.3 server (M6 plan C7): the handshake, the key
//! schedule and record protection, over libcrux primitives only. The state
//! machine lands with the handshake; this is the crate's fixed frame.

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

/// The one key-exchange group (L14): X25519MLKEM768.
pub const X25519MLKEM768: u16 = 0x11ec;
/// The client's share: ML-KEM-768 encapsulation key, then X25519 public.
pub const CLIENT_SHARE_LEN: usize = 1184 + 32;
/// The server's share: ML-KEM-768 ciphertext, then X25519 public.
pub const SERVER_SHARE_LEN: usize = 1088 + 32;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_share_lengths_are_the_drafts() {
        assert_eq!((X25519MLKEM768, CLIENT_SHARE_LEN, SERVER_SHARE_LEN), (4588, 1216, 1120));
    }
}
