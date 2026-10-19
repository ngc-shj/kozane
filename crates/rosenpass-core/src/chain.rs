//! The chaining key and its operations (upstream `HandshakeState`).

use crate::Secret;
use crate::crypto::{self, CryptoError, Domains, KEY_LEN, NONCE_LEN, TAG_LEN};

pub(crate) struct Chain<'d> {
    ck: Secret<KEY_LEN>,
    d: &'d Domains,
}

impl<'d> Chain<'d> {
    pub(crate) fn from_ck(ck: Secret<KEY_LEN>, d: &'d Domains) -> Self {
        Self { ck, d }
    }

    pub(crate) fn ck(&self) -> &Secret<KEY_LEN> {
        &self.ck
    }

    /// ck ← KH(KH(ck, mix), a).
    pub(crate) fn mix(&mut self, a: &[u8]) -> Result<&mut Self, CryptoError> {
        let k = crypto::kh(self.ck.expose(), &self.d.mix)?;
        crypto::kh_into(k.expose(), a, self.ck.expose_mut())?;
        Ok(self)
    }

    /// KH(ck, label): a key derived from the chain without advancing it.
    pub(crate) fn derive(&self, label: &[u8; KEY_LEN]) -> Result<Secret<KEY_LEN>, CryptoError> {
        crypto::kh(self.ck.expose(), label)
    }

    /// ct ← AEAD(KH(ck, hs_enc), nonce 0, pt); then mix(ct).
    pub(crate) fn encrypt_and_mix(&mut self, pt: &[u8], ct: &mut [u8]) -> Result<&mut Self, CryptoError> {
        let k = self.derive(&self.d.hs_enc)?;
        crypto::aead_seal(&k, &[0; NONCE_LEN], pt, ct)?;
        self.mix(ct)
    }

    /// pt ← AEAD⁻¹(KH(ck, hs_enc), nonce 0, ct); then mix(ct).
    pub(crate) fn decrypt_and_mix(&mut self, ct: &[u8], pt: &mut [u8]) -> Result<&mut Self, CryptoError> {
        let k = self.derive(&self.d.hs_enc)?;
        crypto::aead_open(&k, &[0; NONCE_LEN], ct, pt)?;
        self.mix(ct)
    }

    /// The empty-plaintext form used for every `auth` field.
    pub(crate) fn auth(&mut self, tag: &mut [u8; TAG_LEN]) -> Result<&mut Self, CryptoError> {
        self.encrypt_and_mix(&[], tag)
    }

    pub(crate) fn check_auth(&mut self, tag: &[u8; TAG_LEN]) -> Result<&mut Self, CryptoError> {
        self.decrypt_and_mix(tag, &mut [])
    }

    /// mix(pk), mix(shk), mix(ct): the tail of every KEM step.
    pub(crate) fn mix_kem(&mut self, pk: &[u8], shk: &Secret<KEY_LEN>, ct: &[u8]) -> Result<&mut Self, CryptoError> {
        self.mix(pk)?.mix(shk.expose())?.mix(ct)
    }
}
