//! TLS 1.3 record and handshake parsing and serialization for the `tls`
//! PD (M6 plan C6): one suite, one group, one signature algorithm. The
//! parsers land with the handshake; this is the crate's fixed frame.

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

/// Content type, legacy version and length (RFC 8446 section 5.1).
pub const RECORD_HEADER_LEN: usize = 5;
/// Largest plaintext a record may carry (RFC 8446 section 5.1).
pub const MAX_PLAINTEXT: usize = 1 << 14;
/// Largest protected record body (RFC 8446 section 5.2).
pub const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 256;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_limits_are_rfc_8446s() {
        assert_eq!((RECORD_HEADER_LEN, MAX_PLAINTEXT, MAX_CIPHERTEXT), (5, 16_384, 16_640));
    }
}
