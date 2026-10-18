//! WireGuard's primitives (whitepaper section 5.4) over libcrux:
//! HASH = BLAKE2s-256, MAC = keyed BLAKE2s-128, HMAC = RFC 2104 over
//! BLAKE2s (64-byte block), KDF1..3, AEAD = ChaCha20-Poly1305 with nonce
//! `0u32 || counter_le64`, DH = X25519 rejecting the all-zero output.
//!
//! libcrux's internal stack state (BLAKE2s state, ChaCha20 key stream) is
//! not zeroized by libcrux; only values owned here are.

use libcrux_blake2::Blake2sBuilder;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const KEY_LEN: usize = 32;
pub const HASH_LEN: usize = 32;
pub const MAC_LEN: usize = 16;
pub const TAG_LEN: usize = 16;

const HMAC_BLOCK: usize = 64;

/// A 32-byte secret (private key, DH output, chaining key, KDF output).
/// Not `Copy`/`Clone`/`Debug`; zeroized on drop.
pub struct Key32([u8; KEY_LEN]);

impl Key32 {
    /// Takes ownership of `bytes`. The caller's copy (arrays are `Copy`) is
    /// the caller's to zeroize.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    pub(crate) fn zero() -> Self {
        Self([0; KEY_LEN])
    }

    pub(crate) fn as_mut_bytes(&mut self) -> &mut [u8; KEY_LEN] {
        &mut self.0
    }

    /// Constant time with respect to the contents.
    pub fn is_zero(&self) -> bool {
        let acc = self.0.iter().fold(0u8, |a, b| a | b);
        core::hint::black_box(acc) == 0
    }
}

impl Drop for Key32 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for Key32 {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// BLAKE2s refused its input (only for inputs > 4 GiB).
    Hash,
    /// Output buffer too small or input too short / too large.
    Buffer,
    /// AEAD tag mismatch.
    Auth,
    /// X25519 produced the all-zero output (low-order point).
    ZeroDh,
}

/// Constant-time equality for tags compared in hand-written code.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y));
    core::hint::black_box(diff) == 0
}

/// HASH(parts[0] || parts[1] || ...).
pub fn hash(parts: &[&[u8]]) -> Result<[u8; HASH_LEN], CryptoError> {
    let mut st = Blake2sBuilder::new_unkeyed().build_const_digest_len::<HASH_LEN>();
    for p in parts {
        st.update(p).map_err(|_| CryptoError::Hash)?;
    }
    let mut out = [0u8; HASH_LEN];
    st.finalize(&mut out);
    Ok(out)
}

/// MAC(key, parts...) = keyed BLAKE2s with a 16-byte digest.
pub fn mac(key: &[u8; HASH_LEN], parts: &[&[u8]]) -> Result<[u8; MAC_LEN], CryptoError> {
    let mut st = Blake2sBuilder::new_keyed_const(key).build_const_digest_len::<MAC_LEN>();
    for p in parts {
        st.update(p).map_err(|_| CryptoError::Hash)?;
    }
    let mut out = [0u8; MAC_LEN];
    st.finalize(&mut out);
    Ok(out)
}

/// HMAC-BLAKE2s(key, parts...) per RFC 2104 with a 64-byte block.
pub fn hmac(key: &[u8; KEY_LEN], parts: &[&[u8]]) -> Result<Key32, CryptoError> {
    let mut pad = [0x36u8; HMAC_BLOCK];
    for (p, k) in pad.iter_mut().zip(key) {
        *p ^= k;
    }
    let mut inner = Key32::zero();
    let mut st = Blake2sBuilder::new_unkeyed().build_const_digest_len::<HASH_LEN>();
    let r = st.update(&pad).and_then(|()| parts.iter().try_for_each(|p| st.update(p)));
    st.finalize(inner.as_mut_bytes());
    // ipad ^ opad turns the inner pad into the outer one.
    for p in pad.iter_mut() {
        *p ^= 0x36 ^ 0x5c;
    }
    let mut out = Key32::zero();
    let mut st = Blake2sBuilder::new_unkeyed().build_const_digest_len::<HASH_LEN>();
    let r = r.and_then(|()| st.update(&pad)).and_then(|()| st.update(inner.as_bytes()));
    st.finalize(out.as_mut_bytes());
    pad.zeroize();
    r.map_err(|_| CryptoError::Hash)?;
    Ok(out)
}

/// KDF1(key, input) = tau1.
pub fn kdf1(key: &Key32, input: &[u8]) -> Result<Key32, CryptoError> {
    let t0 = hmac(key.as_bytes(), &[input])?;
    hmac(t0.as_bytes(), &[&[1]])
}

/// KDF2(key, input) = (tau1, tau2).
pub fn kdf2(key: &Key32, input: &[u8]) -> Result<(Key32, Key32), CryptoError> {
    let t0 = hmac(key.as_bytes(), &[input])?;
    let t1 = hmac(t0.as_bytes(), &[&[1]])?;
    let t2 = hmac(t0.as_bytes(), &[t1.as_bytes(), &[2]])?;
    Ok((t1, t2))
}

/// KDF3(key, input) = (tau1, tau2, tau3).
pub fn kdf3(key: &Key32, input: &[u8]) -> Result<(Key32, Key32, Key32), CryptoError> {
    let t0 = hmac(key.as_bytes(), &[input])?;
    let t1 = hmac(t0.as_bytes(), &[&[1]])?;
    let t2 = hmac(t0.as_bytes(), &[t1.as_bytes(), &[2]])?;
    let t3 = hmac(t0.as_bytes(), &[t2.as_bytes(), &[3]])?;
    Ok((t1, t2, t3))
}

/// X25519(secret, public), rejecting the all-zero output.
pub fn dh(secret: &Key32, public: &[u8; KEY_LEN]) -> Result<Key32, CryptoError> {
    let mut out = Key32::zero();
    libcrux_curve25519::ecdh(out.as_mut_bytes(), public, secret.as_bytes())
        .map_err(|_| CryptoError::ZeroDh)?;
    // libcrux already rejects zero; keep the check local so the invariant
    // does not depend on a dependency's behaviour.
    if out.is_zero() {
        return Err(CryptoError::ZeroDh);
    }
    Ok(out)
}

pub fn public_key(secret: &Key32) -> [u8; KEY_LEN] {
    let mut pk = [0u8; KEY_LEN];
    libcrux_curve25519::secret_to_public(&mut pk, secret.as_bytes());
    pk
}

/// Clamps a private scalar in place (RFC 7748 section 5).
pub fn clamp(secret: &mut Key32) {
    libcrux_curve25519::clamp(secret.as_mut_bytes());
}

fn nonce(counter: u64) -> [u8; 12] {
    let [a, b, c, d, e, f, g, h] = counter.to_le_bytes();
    [0, 0, 0, 0, a, b, c, d, e, f, g, h]
}

/// AEAD(key, counter, plaintext, aad): writes ciphertext || tag to `out`,
/// returns its length.
pub fn aead_seal(
    key: &Key32,
    counter: u64,
    plaintext: &[u8],
    aad: &[u8],
    out: &mut [u8],
) -> Result<usize, CryptoError> {
    let len = plaintext.len().checked_add(TAG_LEN).ok_or(CryptoError::Buffer)?;
    libcrux_chacha20poly1305::encrypt(key.as_bytes(), plaintext, out, aad, &nonce(counter))
        .map_err(|_| CryptoError::Buffer)?;
    Ok(len)
}

/// Inverse of `aead_seal`. `out` is written only when the tag verifies.
pub fn aead_open(
    key: &Key32,
    counter: u64,
    ciphertext: &[u8],
    aad: &[u8],
    out: &mut [u8],
) -> Result<usize, CryptoError> {
    let len = ciphertext.len().checked_sub(TAG_LEN).ok_or(CryptoError::Buffer)?;
    if out.len() < len {
        return Err(CryptoError::Buffer);
    }
    libcrux_chacha20poly1305::decrypt(key.as_bytes(), out, ciphertext, aad, &nonce(counter))
        .map_err(|e| match e {
            libcrux_chacha20poly1305::AeadError::InvalidCiphertext => CryptoError::Auth,
            _ => CryptoError::Buffer,
        })?;
    Ok(len)
}
