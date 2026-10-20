//! The one container for every value derived from ck, a KEM shared secret,
//! a biscuit plaintext or the RNG (M3 plan S12).

use zeroize::{Zeroize, ZeroizeOnDrop};

/// N secret bytes. Not `Copy`/`Clone`/`Debug`; zeroized on drop.
pub struct Secret<const N: usize>([u8; N]);

impl<const N: usize> Secret<N> {
    /// Takes ownership of `bytes`. The caller's copy (arrays are `Copy`) is
    /// the caller's to zeroize.
    pub fn from_bytes(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    pub fn zero() -> Self {
        Self([0; N])
    }

    /// Copies `bytes` straight into the container, so no by-value
    /// temporary of the secret is left on the stack.
    pub fn copy_from(bytes: &[u8; N]) -> Self {
        let mut s = Self::zero();
        s.0.copy_from_slice(bytes);
        s
    }

    pub fn expose(&self) -> &[u8; N] {
        &self.0
    }

    pub fn expose_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }

    /// Constant time with respect to the contents.
    pub fn ct_eq(&self, other: &[u8; N]) -> bool {
        crate::crypto::ct_eq(&self.0, other)
    }
}

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<const N: usize> ZeroizeOnDrop for Secret<N> {}
