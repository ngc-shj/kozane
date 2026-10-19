//! Rosenpass V02's primitives over libcrux: the keyed hash KH ("incorrect
//! HMAC" over keyed BLAKE2b-256, whitepaper L69-80 and its Errata), the
//! hash-domain tree, ChaCha20-Poly1305 and XChaCha20-Poly1305 with the nonce
//! prepended to the ciphertext.
//!
//! libcrux's internal stack state (BLAKE2b state, ChaCha20 key stream,
//! XChaCha subkey) is not zeroized by libcrux; only values owned here are.

use libcrux_blake2::Blake2bBuilder;
use libcrux_chacha20poly1305 as aead;
use libcrux_chacha20poly1305::xchacha20_poly1305 as xaead;
use zeroize::Zeroize;

use crate::Secret;

pub const KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const XNONCE_LEN: usize = 24;

/// The V02 protocol string. It names BLAKE2s although V02 hashes with
/// BLAKE2b: a historical quirk upstream keeps for compatibility
/// (`KeyedHash::protocol_string_hash_id`).
pub const PROTOCOL_V02: &[u8] = b"Rosenpass v1 mceliece460896 Kyber512 ChaChaPoly1305 BLAKE2s";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// BLAKE2b refused its input (only for inputs > 4 GiB).
    Hash,
    /// A buffer of the wrong size (a build error, not attacker-reachable).
    Buffer,
    /// AEAD tag mismatch.
    Auth,
}

/// Constant-time equality for tags and ids compared in hand-written code.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y));
    core::hint::black_box(diff) == 0
}

/// Keyed BLAKE2b-256 (RustCrypto's `Blake2bMac<U32>`).
pub fn blake2b(key: &[u8; KEY_LEN], parts: &[&[u8]], out: &mut [u8; KEY_LEN]) -> Result<(), CryptoError> {
    let mut st = Blake2bBuilder::new_keyed_const(key).build_const_digest_len::<KEY_LEN>();
    for p in parts {
        st.update(p).map_err(|_| CryptoError::Hash)?;
    }
    st.finalize(out);
    Ok(())
}

/// KH(key, data) = BLAKE2b(key ^ opad, BLAKE2b(key ^ ipad, data)) with
/// 32-byte pads, both keyed; not RFC 2104 (upstream's "incorrect HMAC").
pub fn kh_into(key: &[u8; KEY_LEN], data: &[u8], out: &mut [u8; KEY_LEN]) -> Result<(), CryptoError> {
    let mut pad = [0u8; KEY_LEN];
    for (p, k) in pad.iter_mut().zip(key) {
        *p = k ^ 0x36;
    }
    let mut inner = Secret::<KEY_LEN>::zero();
    let r = blake2b(&pad, &[data], inner.expose_mut());
    for p in pad.iter_mut() {
        *p ^= 0x36 ^ 0x5c;
    }
    let r = r.and_then(|()| blake2b(&pad, &[inner.expose()], out));
    pad.zeroize();
    r
}

pub fn kh(key: &[u8; KEY_LEN], data: &[u8]) -> Result<Secret<KEY_LEN>, CryptoError> {
    let mut out = Secret::zero();
    kh_into(key, data, out.expose_mut())?;
    Ok(out)
}

/// KH for public values (hash domains, peer ids, mac keys, biscuit ad).
pub fn kh_public(key: &[u8; KEY_LEN], data: &[u8]) -> Result<[u8; KEY_LEN], CryptoError> {
    let mut out = [0u8; KEY_LEN];
    kh_into(key, data, &mut out)?;
    Ok(out)
}

/// The V02 hash-domain tree (upstream `hash_domains.rs`). Every value is a
/// 32-byte public key for KH, derived from the protocol string down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Domains {
    pub protocol: [u8; KEY_LEN],
    pub mac: [u8; KEY_LEN],
    pub cookie: [u8; KEY_LEN],
    pub cookie_value: [u8; KEY_LEN],
    pub cookie_key: [u8; KEY_LEN],
    pub peerid: [u8; KEY_LEN],
    pub biscuit_ad: [u8; KEY_LEN],
    pub ckinit: [u8; KEY_LEN],
    pub ckextract: [u8; KEY_LEN],
    pub mix: [u8; KEY_LEN],
    pub hs_enc: [u8; KEY_LEN],
    pub ini_enc: [u8; KEY_LEN],
    pub res_enc: [u8; KEY_LEN],
    pub cke_user: [u8; KEY_LEN],
    pub cke_user_rosenpass: [u8; KEY_LEN],
    /// `ext_wireguard_psk_osk`: the OSK label for a WireGuard PSK.
    pub osk: [u8; KEY_LEN],
}

impl Domains {
    pub fn v02() -> Result<Self, CryptoError> {
        let protocol = kh_public(&[0; KEY_LEN], PROTOCOL_V02)?;
        let ckextract = kh_public(&protocol, b"chaining key extract")?;
        let cke_user = kh_public(&ckextract, b"user")?;
        let cke_user_rosenpass = kh_public(&cke_user, b"rosenpass.eu")?;
        Ok(Self {
            mac: kh_public(&protocol, b"mac")?,
            cookie: kh_public(&protocol, b"cookie")?,
            cookie_value: kh_public(&protocol, b"cookie-value")?,
            cookie_key: kh_public(&protocol, b"cookie-key")?,
            peerid: kh_public(&protocol, b"peer id")?,
            biscuit_ad: kh_public(&protocol, b"biscuit additional data")?,
            ckinit: kh_public(&protocol, b"chaining key init")?,
            mix: kh_public(&ckextract, b"mix")?,
            hs_enc: kh_public(&ckextract, b"handshake encryption")?,
            ini_enc: kh_public(&ckextract, b"initiator handshake encryption")?,
            res_enc: kh_public(&ckextract, b"responder handshake encryption")?,
            osk: kh_public(&cke_user_rosenpass, b"wireguard psk")?,
            protocol,
            ckextract,
            cke_user,
            cke_user_rosenpass,
        })
    }
}

/// ChaCha20-Poly1305 with empty associated data; `ct` is `pt ‖ tag`.
pub fn aead_seal(key: &Secret<KEY_LEN>, nonce: &[u8; NONCE_LEN], pt: &[u8], ct: &mut [u8]) -> Result<(), CryptoError> {
    if ct.len() != pt.len().checked_add(TAG_LEN).ok_or(CryptoError::Buffer)? {
        return Err(CryptoError::Buffer);
    }
    aead::encrypt(key.expose(), pt, ct, &[], nonce).map_err(|_| CryptoError::Buffer)?;
    Ok(())
}

pub fn aead_open(key: &Secret<KEY_LEN>, nonce: &[u8; NONCE_LEN], ct: &[u8], pt: &mut [u8]) -> Result<(), CryptoError> {
    if ct.len() != pt.len().checked_add(TAG_LEN).ok_or(CryptoError::Buffer)? {
        return Err(CryptoError::Buffer);
    }
    aead::decrypt(key.expose(), pt, ct, &[], nonce).map_err(|_| CryptoError::Auth)?;
    Ok(())
}

/// XChaCha20-Poly1305; `out` is `nonce ‖ ct ‖ tag` (upstream's
/// `encrypt_with_nonce_in_ctxt`).
pub fn xaead_seal(
    key: &Secret<KEY_LEN>,
    nonce: &[u8; XNONCE_LEN],
    ad: &[u8],
    pt: &[u8],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    let (n, ct) = out.split_first_chunk_mut::<XNONCE_LEN>().ok_or(CryptoError::Buffer)?;
    if ct.len() != pt.len().checked_add(TAG_LEN).ok_or(CryptoError::Buffer)? {
        return Err(CryptoError::Buffer);
    }
    *n = *nonce;
    xaead::encrypt(key.expose(), pt, ct, ad, nonce).map_err(|_| CryptoError::Buffer)?;
    Ok(())
}

pub fn xaead_open(key: &Secret<KEY_LEN>, ad: &[u8], sealed: &[u8], pt: &mut [u8]) -> Result<(), CryptoError> {
    let (nonce, ct) = sealed.split_first_chunk::<XNONCE_LEN>().ok_or(CryptoError::Buffer)?;
    if ct.len() != pt.len().checked_add(TAG_LEN).ok_or(CryptoError::Buffer)? {
        return Err(CryptoError::Buffer);
    }
    xaead::decrypt(key.expose(), pt, ct, ad, nonce).map_err(|_| CryptoError::Auth)?;
    Ok(())
}
