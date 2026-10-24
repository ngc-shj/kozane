//! The TLS 1.3 key schedule (RFC 8446 section 7.1) for
//! TLS_CHACHA20_POLY1305_SHA256 without PSK: HKDF-SHA256 (RFC 5869) over
//! libcrux's HMAC-SHA256. Every output here is at most one hash long, so
//! HKDF-Expand is its first block T(1) = HMAC(PRK, info ‖ 0x01).
//!
//! libcrux-hkdf 0.0.9 is not used in the PD: its expand allocates (hacl-rs
//! with `alloc`) and the `tls` PD has no heap; the tests check this
//! module's HKDF against it (M6 deviation log, slice 3a).
//!
//! L14: [`KeySchedule::new`] takes only a [`HybridSecret`]. The schedule
//! from raw input keying material ([`schedule_from_ikm`]) is private and
//! reachable from outside this module only under `cfg(test)`.

use crate::hybrid::HybridSecret;
use crate::{Refusal, Secret};

pub const HASH_LEN: usize = 32;
/// ChaCha20-Poly1305's key and nonce lengths.
pub const KEY_LEN: usize = 32;
pub const IV_LEN: usize = 12;

/// SHA-256 of the empty string: Derive-Secret's "derived" context.
const EMPTY_HASH: [u8; HASH_LEN] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41,
    0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];
const LABEL_PREFIX: &[u8] = b"tls13 ";

fn hmac(out: &mut [u8; HASH_LEN], key: &[u8], parts: &[&[u8]]) -> Result<(), Refusal> {
    libcrux_hmac::hmac_sha2_256_slices(out, key, parts).map_err(|_| Refusal::Internal)
}

/// HKDF-Extract(salt, IKM) = HMAC-SHA256(salt, IKM) (RFC 5869 section 2.2).
pub(crate) fn extract(out: &mut Secret<HASH_LEN>, salt: &[u8], ikm: &[u8]) -> Result<(), Refusal> {
    hmac(out.as_mut_bytes(), salt, &[ikm])
}

/// HKDF-Expand-Label(secret, label, context, out.len()) (section 7.1),
/// for outputs of at most one hash.
pub(crate) fn expand_label(out: &mut [u8], secret: &[u8; HASH_LEN], label: &[u8], context: &[u8]) -> Result<(), Refusal> {
    if out.len() > HASH_LEN {
        return Err(Refusal::Internal);
    }
    let length = u16::try_from(out.len()).map_err(|_| Refusal::Internal)?.to_be_bytes();
    let label_len = LABEL_PREFIX.len().checked_add(label.len()).and_then(|n| u8::try_from(n).ok()).ok_or(Refusal::Internal)?;
    let context_len = u8::try_from(context.len()).map_err(|_| Refusal::Internal)?;
    let mut t = Secret::<HASH_LEN>::zero();
    hmac(t.as_mut_bytes(), secret, &[&length, &[label_len], LABEL_PREFIX, label, &[context_len], context, &[1]])?;
    out.copy_from_slice(t.as_bytes().get(..out.len()).ok_or(Refusal::Internal)?);
    Ok(())
}

/// Derive-Secret(secret, label, messages) with the transcript hash given.
pub(crate) fn derive_secret(
    out: &mut Secret<HASH_LEN>,
    secret: &Secret<HASH_LEN>,
    label: &[u8],
    transcript_hash: &[u8; HASH_LEN],
) -> Result<(), Refusal> {
    expand_label(out.as_mut_bytes(), secret.as_bytes(), label, transcript_hash)
}

/// finished_key = HKDF-Expand-Label(base, "finished", "", 32) (4.4.4).
pub(crate) fn finished_key(base: &Secret<HASH_LEN>) -> Result<Secret<HASH_LEN>, Refusal> {
    let mut k = Secret::zero();
    expand_label(k.as_mut_bytes(), base.as_bytes(), b"finished", &[])?;
    Ok(k)
}

/// verify_data = HMAC(finished_key(base), transcript hash) (4.4.4).
pub(crate) fn verify_data(base: &Secret<HASH_LEN>, transcript_hash: &[u8; HASH_LEN]) -> Result<[u8; HASH_LEN], Refusal> {
    let key = finished_key(base)?;
    let mut out = [0u8; HASH_LEN];
    hmac(&mut out, key.as_bytes(), &[transcript_hash])?;
    Ok(out)
}

/// The next traffic secret (7.2): HKDF-Expand-Label(secret, "traffic upd",
/// "", 32).
pub(crate) fn next_traffic_secret(secret: &Secret<HASH_LEN>) -> Result<Secret<HASH_LEN>, Refusal> {
    let mut next = Secret::zero();
    expand_label(next.as_mut_bytes(), secret.as_bytes(), b"traffic upd", &[])?;
    Ok(next)
}

/// A traffic secret's record key and IV (7.3).
pub(crate) fn traffic_key(secret: &Secret<HASH_LEN>) -> Result<(Secret<KEY_LEN>, Secret<IV_LEN>), Refusal> {
    let mut key = Secret::zero();
    let mut iv = Secret::zero();
    expand_label(key.as_mut_bytes(), secret.as_bytes(), b"key", &[])?;
    expand_label(iv.as_mut_bytes(), secret.as_bytes(), b"iv", &[])?;
    Ok((key, iv))
}

/// The handshake traffic secrets and the master secret, from the hybrid
/// secret and the transcript hash of ClientHello..ServerHello. The early
/// and handshake secrets do not outlive [`KeySchedule::new`].
pub struct KeySchedule {
    client_hs: Secret<HASH_LEN>,
    server_hs: Secret<HASH_LEN>,
    master: Secret<HASH_LEN>,
    #[cfg(test)]
    early: Secret<HASH_LEN>,
    #[cfg(test)]
    handshake: Secret<HASH_LEN>,
}

impl KeySchedule {
    /// The schedule of an X25519MLKEM768 handshake (L14); `shared` is
    /// wiped when this returns.
    pub fn new(shared: HybridSecret, hello_hash: &[u8; HASH_LEN]) -> Result<Self, Refusal> {
        schedule_from_ikm(shared.ikm(), hello_hash)
    }

    /// client_handshake_traffic_secret.
    pub fn client_handshake(&self) -> &Secret<HASH_LEN> {
        &self.client_hs
    }

    /// server_handshake_traffic_secret.
    pub fn server_handshake(&self) -> &Secret<HASH_LEN> {
        &self.server_hs
    }

    /// The client and server application traffic secrets from the
    /// transcript hash through the server Finished. Consumes the schedule:
    /// the master and both handshake secrets are wiped, but the client
    /// handshake secret, which still verifies the client Finished, is
    /// handed back first (M6 plan C8 wipe points).
    pub fn application(
        mut self,
        server_finished_hash: &[u8; HASH_LEN],
    ) -> Result<ApplicationSecrets, Refusal> {
        let mut client = Secret::zero();
        let mut server = Secret::zero();
        derive_secret(&mut client, &self.master, b"c ap traffic", server_finished_hash)?;
        derive_secret(&mut server, &self.master, b"s ap traffic", server_finished_hash)?;
        let client_hs = core::mem::replace(&mut self.client_hs, Secret::zero());
        Ok(ApplicationSecrets { client_hs, client, server })
    }
}

/// What [`KeySchedule::application`] leaves: the client handshake secret
/// (until the client Finished verifies) and both application secrets.
pub struct ApplicationSecrets {
    pub client_hs: Secret<HASH_LEN>,
    pub client: Secret<HASH_LEN>,
    pub server: Secret<HASH_LEN>,
}

/// The schedule from raw input keying material: private, so only
/// [`KeySchedule::new`] (from a [`HybridSecret`]) reaches it outside tests.
fn schedule_from_ikm<const N: usize>(ikm: &[u8; N], hello_hash: &[u8; HASH_LEN]) -> Result<KeySchedule, Refusal> {
    let zeros = [0u8; HASH_LEN];
    let mut early = Secret::zero();
    extract(&mut early, &zeros, &zeros)?;
    let mut derived = Secret::zero();
    derive_secret(&mut derived, &early, b"derived", &EMPTY_HASH)?;
    let mut handshake = Secret::zero();
    extract(&mut handshake, derived.as_bytes(), ikm)?;
    let mut client_hs = Secret::zero();
    let mut server_hs = Secret::zero();
    derive_secret(&mut client_hs, &handshake, b"c hs traffic", hello_hash)?;
    derive_secret(&mut server_hs, &handshake, b"s hs traffic", hello_hash)?;
    derive_secret(&mut derived, &handshake, b"derived", &EMPTY_HASH)?;
    let mut master = Secret::zero();
    extract(&mut master, derived.as_bytes(), &zeros)?;
    Ok(KeySchedule {
        client_hs,
        server_hs,
        master,
        #[cfg(test)]
        early,
        #[cfg(test)]
        handshake,
    })
}

/// The tests' reach into the schedule (RFC 8448 and the host client, which
/// derives from the hybrid secret it computed itself).
#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    pub(crate) fn schedule_from_ikm<const N: usize>(
        ikm: &[u8; N],
        hello_hash: &[u8; HASH_LEN],
    ) -> Result<KeySchedule, Refusal> {
        super::schedule_from_ikm(ikm, hello_hash)
    }

    pub(crate) fn early(ks: &KeySchedule) -> &[u8; HASH_LEN] {
        ks.early.as_bytes()
    }

    pub(crate) fn handshake(ks: &KeySchedule) -> &[u8; HASH_LEN] {
        ks.handshake.as_bytes()
    }

    pub(crate) fn master(ks: &KeySchedule) -> &[u8; HASH_LEN] {
        ks.master.as_bytes()
    }
}
