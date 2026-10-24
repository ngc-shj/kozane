//! The one zeroizing container for secret bytes (L12), shared by `tpm2`,
//! `tls-core` and `rosenpass-core` (each re-exports it under its own path),
//! and the plaintext-buffer wipe. A leaf with only `zeroize`, so a caller
//! gains no other edge.
//!
//! [`Secret`] is not `Clone`, `Copy` or `Debug`:
//!
//! ```compile_fail
//! fn twice(s: &secret::Secret<32>) -> secret::Secret<32> {
//!     s.clone()
//! }
//! ```
//!
//! ```compile_fail
//! fn twice(s: secret::Secret<32>) -> (secret::Secret<32>, secret::Secret<32>) {
//!     (s, s)
//! }
//! ```
//!
//! ```compile_fail
//! fn show(s: &secret::Secret<32>) -> String {
//!     format!("{s:?}")
//! }
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use zeroize::{Zeroize, ZeroizeOnDrop};

/// N secret bytes: not `Copy`/`Clone`/`Debug`, zeroized on drop (L12).
pub struct Secret<const N: usize>([u8; N]);

impl<const N: usize> Secret<N> {
    pub const fn zero() -> Self {
        Self([0; N])
    }

    /// Takes ownership of `bytes`. The caller's copy (arrays are `Copy`) is
    /// the caller's to zeroize.
    pub fn from_bytes(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Copies `bytes` straight into the container, so no by-value
    /// temporary of the secret is left on the stack.
    pub fn copy_from(bytes: &[u8; N]) -> Self {
        let mut s = Self::zero();
        s.0.copy_from_slice(bytes);
        s
    }

    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    pub fn as_mut_bytes(&mut self) -> &mut [u8; N] {
        &mut self.0
    }

    /// [`Self::as_bytes`] under `rosenpass-core`'s name for it.
    pub fn expose(&self) -> &[u8; N] {
        &self.0
    }

    /// [`Self::as_mut_bytes`] under `rosenpass-core`'s name for it.
    pub fn expose_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }

    pub fn wipe(&mut self) {
        self.0.zeroize();
    }

    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<const N: usize> ZeroizeOnDrop for Secret<N> {}

/// Wipes a plaintext buffer with writes the optimizer keeps (L12).
pub fn wipe(buf: &mut [u8]) {
    buf.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_from_holds_the_bytes_and_wipe_zeroes_them() {
        let mut s = Secret::copy_from(&[0xa5u8; 16]);
        assert_eq!(s.as_bytes(), &[0xa5; 16]);
        assert!(!s.is_zero());
        s.wipe();
        assert!(s.is_zero());
    }

    #[test]
    fn every_accessor_reaches_the_same_bytes() {
        let mut s = Secret::<4>::from_bytes([1, 2, 3, 4]);
        s.as_mut_bytes()[0] = 9;
        s.expose_mut()[3] = 7;
        assert_eq!(s.expose(), &[9, 2, 3, 7]);
        assert_eq!(s.as_bytes(), s.expose());
        assert!(Secret::<8>::zero().is_zero());
    }

    #[test]
    fn wipe_zeroes_a_whole_buffer() {
        let mut buf = [0x3cu8; 37];
        wipe(&mut buf);
        assert_eq!(buf, [0; 37]);
    }

    #[test]
    fn secret_is_zeroize_on_drop() {
        fn on_drop<T: ZeroizeOnDrop>() {}
        on_drop::<Secret<32>>();
    }
}
