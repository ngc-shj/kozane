//! ChaCha20-Poly1305 record protection (RFC 8446 section 5.2) with the
//! per-record nonce of section 5.3: the 64-bit sequence number, left-padded
//! to 12 bytes, XORed with the traffic IV. The additional data is the
//! protected record's header. A sequence number never wraps: the last one
//! is refused, and application data stops one earlier so a closing alert
//! always has a nonce (section 5.5).

use libcrux_chacha20poly1305::TAG_LEN;
use tls_wire::emit::record_header;
use tls_wire::{ContentType, MAX_CIPHERTEXT, RECORD_HEADER_LEN, Refusal};

use crate::schedule::{HASH_LEN, IV_LEN, KEY_LEN, traffic_key};
use crate::{Secret, wipe};

/// The Poly1305 tag every protected record ends with.
pub const RECORD_TAG_LEN: usize = TAG_LEN;
/// The sequence number no record may use.
pub const SEQ_LIMIT: u64 = u64::MAX;

/// One direction's key, IV and sequence number.
pub struct RecordKey {
    key: Secret<KEY_LEN>,
    iv: Secret<IV_LEN>,
    seq: u64,
}

impl RecordKey {
    pub const fn none() -> Self {
        Self { key: Secret::zero(), iv: Secret::zero(), seq: 0 }
    }

    /// The key and IV of a traffic secret, sequence number 0.
    pub fn new(secret: &Secret<HASH_LEN>) -> Result<Self, Refusal> {
        let (key, iv) = traffic_key(secret)?;
        Ok(Self { key, iv, seq: 0 })
    }

    fn nonce(&self) -> Result<Secret<IV_LEN>, Refusal> {
        if self.seq == SEQ_LIMIT {
            return Err(Refusal::Internal);
        }
        let mut n = Secret::copy_from(self.iv.as_bytes());
        let (_, tail) = n.as_mut_bytes().split_at_mut(IV_LEN - 8);
        for (b, s) in tail.iter_mut().zip(self.seq.to_be_bytes()) {
            *b ^= s;
        }
        Ok(n)
    }

    /// Seals `scratch[..len]` (the content) as one protected record of
    /// type `content_type` into `out`, without padding, and returns the
    /// record's length. The plaintext in `scratch` is wiped either way.
    pub fn seal(&mut self, content_type: ContentType, scratch: &mut [u8], len: usize, out: &mut [u8]) -> Result<usize, Refusal> {
        let r = self.seal_inner(content_type, scratch, len, out);
        let end = len.saturating_add(1).min(scratch.len());
        wipe(scratch.get_mut(..end).unwrap_or(&mut []));
        r
    }

    fn seal_inner(&mut self, content_type: ContentType, scratch: &mut [u8], len: usize, out: &mut [u8]) -> Result<usize, Refusal> {
        // Application data keeps the last nonce for a closing alert.
        if content_type == ContentType::ApplicationData && self.seq >= SEQ_LIMIT.saturating_sub(1) {
            return Err(Refusal::Internal);
        }
        let inner_len = len.checked_add(1).ok_or(Refusal::Internal)?;
        *scratch.get_mut(len).ok_or(Refusal::Internal)? = content_type as u8;
        let body_len = inner_len.checked_add(RECORD_TAG_LEN).filter(|&n| n <= MAX_CIPHERTEXT).ok_or(Refusal::Internal)?;
        let total = body_len.checked_add(RECORD_HEADER_LEN).ok_or(Refusal::Internal)?;
        let header = record_header(ContentType::ApplicationData, body_len)?;
        let (head, body) = out.get_mut(..total).ok_or(Refusal::Internal)?.split_at_mut(RECORD_HEADER_LEN);
        head.copy_from_slice(&header);
        let nonce = self.nonce()?;
        let plain = scratch.get(..inner_len).ok_or(Refusal::Internal)?;
        libcrux_chacha20poly1305::encrypt(self.key.as_bytes(), plain, body, &header, nonce.as_bytes())
            .map_err(|_| Refusal::Internal)?;
        self.seq = self.seq.checked_add(1).ok_or(Refusal::Internal)?;
        Ok(total)
    }

    /// Opens a protected record (its header and body) into `plain` and
    /// returns the TLSInnerPlaintext. A record that fails is
    /// `BadRecordMac` and leaves the sequence number where it was, so the
    /// caller may skip it (the early_data rule).
    pub fn open<'p>(&mut self, header: &[u8; RECORD_HEADER_LEN], body: &[u8], plain: &'p mut [u8]) -> Result<&'p [u8], Refusal> {
        let n = body.len().checked_sub(RECORD_TAG_LEN).ok_or(Refusal::BadRecordMac)?;
        let nonce = self.nonce()?;
        let out = plain.get_mut(..n).ok_or(Refusal::Internal)?;
        if libcrux_chacha20poly1305::decrypt(self.key.as_bytes(), out, body, header, nonce.as_bytes()).is_err() {
            wipe(out);
            return Err(Refusal::BadRecordMac);
        }
        self.seq = self.seq.checked_add(1).ok_or(Refusal::Internal)?;
        Ok(out)
    }

    pub fn wipe(&mut self) {
        self.key.wipe();
        self.iv.wipe();
        self.seq = 0;
    }

    pub fn is_zeroized(&self) -> bool {
        self.key.is_zero() && self.iv.is_zero() && self.seq == 0
    }

    #[cfg(test)]
    pub(crate) fn set_seq(&mut self, seq: u64) {
        self.seq = seq;
    }
}
