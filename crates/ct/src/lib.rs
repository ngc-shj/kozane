//! Constant-time comparison shared by every crate that checks a tag, MAC,
//! cookie or Finished value in hand-written code (`wg-core`, `tpm2`,
//! `key-core`, `tls-core`). A leaf crate so a caller gains no other edge.

#![no_std]
#![forbid(unsafe_code)]
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

/// Constant-time equality for tags compared in hand-written code.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y));
    core::hint::black_box(diff) == 0
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_compares_contents_and_length() {
        assert!(ct_eq(b"abcd", b"abcd"));
        assert!(!ct_eq(b"abcd", b"abce"));
        assert!(!ct_eq(b"abcd", b"abc"));
    }

    #[test]
    fn ct_eq_finds_a_difference_in_any_byte() {
        let a = [0x5au8; 32];
        for i in 0..32 {
            let mut b = a;
            b[i] ^= 0x01;
            assert!(!ct_eq(&a, &b), "byte {i}");
        }
        assert!(ct_eq(&[], &[]));
    }
}
