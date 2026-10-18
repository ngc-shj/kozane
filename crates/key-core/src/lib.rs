//! `key` oracle logic (plan C10, law L2): the only code that touches the
//! gateway's static private key and the PSKs. The PD maps the secrets
//! region read-only, validates it against the compiled configuration once
//! at boot (halting on any mismatch), and then answers exactly three
//! fixed-size PPC requests:
//!
//! | label        | request (words)        | reply (words)        |
//! |--------------|------------------------|----------------------|
//! | `STATIC_DH`  | peer point (4)         | DH(S_priv, point) (4)|
//! | `PSK_MIX`    | peer id (1), C (4)     | C', tau, kappa (12)  |
//! | `BOOT_SEED`  | — (0)                  | per-boot seed (4)    |
//!
//! Anything else, a wrong size, an all-zero DH, an unknown peer or an
//! exhausted caller budget gets an error label and no data. Words are
//! little-endian `u64`s, as in seL4 message registers.

#![no_std]
#![deny(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use secret_blob::{Blob, BlobError};
use wg_core::crypto::{self, Key32};

pub const LABEL_STATIC_DH: u64 = 1;
pub const LABEL_PSK_MIX: u64 = 2;
pub const LABEL_BOOT_SEED: u64 = 3;

/// Reply labels.
pub const OK: u64 = 0;
pub const ERR_BAD_REQUEST: u64 = 1;
pub const ERR_ZERO_DH: u64 = 2;
pub const ERR_UNKNOWN_PEER: u64 = 3;
pub const ERR_RATE_LIMITED: u64 = 4;
pub const ERR_CRYPTO: u64 = 5;

pub const STATIC_DH_REQ_WORDS: usize = 4;
pub const PSK_MIX_REQ_WORDS: usize = 5;
pub const BOOT_SEED_REQ_WORDS: usize = 0;
pub const STATIC_DH_REPLY_WORDS: usize = 4;
pub const PSK_MIX_REPLY_WORDS: usize = 12;
pub const BOOT_SEED_REPLY_WORDS: usize = 4;
/// Largest request or reply.
pub const MAX_WORDS: usize = PSK_MIX_REPLY_WORDS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootError {
    Blob(BlobError),
    GatewayKeyMismatch,
    PeerMismatch,
}

impl BootError {
    /// Stable text for the boot log, one per failure (plan C10).
    pub const fn message(self) -> &'static str {
        match self {
            BootError::Blob(e) => e.message(),
            BootError::GatewayKeyMismatch => "secrets: gateway key does not match the configuration",
            BootError::PeerMismatch => "secrets: peer keys do not match the configuration",
        }
    }
}

/// Checks the region against the compiled configuration: format, the
/// public key derived from the private key, and each peer's key hash in
/// configuration order.
pub fn validate<'a, 'p>(
    region: &'a [u8],
    gateway_public: &[u8; 32],
    peers: impl ExactSizeIterator<Item = &'p [u8; 32]>,
) -> Result<Blob<'a>, BootError> {
    let blob = Blob::parse(region, peers.len()).map_err(BootError::Blob)?;
    let private = Key32::from_bytes(*blob.gateway_private());
    if !crypto::ct_eq(&crypto::public_key(&private), gateway_public) {
        return Err(BootError::GatewayKeyMismatch);
    }
    for (i, public) in peers.enumerate() {
        let hash = blob.peer(i).map(|(h, _)| h).ok_or(BootError::PeerMismatch)?;
        if !crypto::ct_eq(hash, &secret_blob::blake2s(&[public])) {
            return Err(BootError::PeerMismatch);
        }
    }
    Ok(blob)
}

/// Per-caller CNTPCT token bucket: `burst` calls, refilled at one call per
/// `interval_ns`. Sized by the PD at or above what `hs`'s CPU budget can
/// drive, so it bounds a misbehaving caller without throttling real load.
#[derive(Debug, Clone, Copy)]
pub struct Bucket {
    capacity_ns: u64,
    interval_ns: u64,
    budget_ns: u64,
    last_ns: u64,
}

impl Bucket {
    pub const fn new(burst: u64, interval_ns: u64) -> Self {
        let capacity_ns = burst.saturating_mul(interval_ns);
        Self { capacity_ns, interval_ns, budget_ns: capacity_ns, last_ns: 0 }
    }

    pub fn take(&mut self, now_ns: u64) -> bool {
        let elapsed = now_ns.saturating_sub(self.last_ns);
        self.budget_ns = self.budget_ns.saturating_add(elapsed).min(self.capacity_ns);
        self.last_ns = self.last_ns.max(now_ns);
        if self.budget_ns < self.interval_ns {
            return false;
        }
        self.budget_ns = self.budget_ns.saturating_sub(self.interval_ns);
        true
    }
}

pub struct Oracle<'a> {
    blob: Blob<'a>,
    boot_seed: Key32,
}

fn words_to_bytes<const N: usize>(words: &[u64]) -> Option<[u8; N]> {
    let mut out = [0u8; N];
    let (chunks, rest) = out.as_chunks_mut::<8>();
    if !rest.is_empty() || chunks.len() != words.len() {
        return None;
    }
    for (c, w) in chunks.iter_mut().zip(words) {
        *c = w.to_le_bytes();
    }
    Some(out)
}

fn put_bytes(words: &mut [u64], bytes: &[u8]) -> Option<usize> {
    let (chunks, rest) = bytes.as_chunks::<8>();
    if !rest.is_empty() {
        return None;
    }
    let dst = words.get_mut(..chunks.len())?;
    for (w, c) in dst.iter_mut().zip(chunks) {
        *w = u64::from_le_bytes(*c);
    }
    Some(chunks.len())
}

impl<'a> Oracle<'a> {
    /// `boot_seed` is the per-boot value derived by the PD
    /// (BLAKE2s(blob seed ‖ RNDR ‖ CNTPCT)); the blob seed never leaves `key`.
    pub fn new(blob: Blob<'a>, boot_seed: Key32) -> Self {
        Self { blob, boot_seed }
    }

    /// Answers one request. Returns (reply label, reply word count); on any
    /// error the count is 0 and `reply` is zeroed, so no partial result
    /// leaks through a reused message register.
    pub fn handle(&self, bucket: &mut Bucket, now_ns: u64, label: u64, req: &[u64], reply: &mut [u64]) -> (u64, usize) {
        let r = self.dispatch(bucket, now_ns, label, req, reply);
        if r.0 != OK {
            reply.fill(0);
            return (r.0, 0);
        }
        r
    }

    fn dispatch(&self, bucket: &mut Bucket, now_ns: u64, label: u64, req: &[u64], reply: &mut [u64]) -> (u64, usize) {
        let expected = match label {
            LABEL_STATIC_DH => STATIC_DH_REQ_WORDS,
            LABEL_PSK_MIX => PSK_MIX_REQ_WORDS,
            LABEL_BOOT_SEED => BOOT_SEED_REQ_WORDS,
            _ => return (ERR_BAD_REQUEST, 0),
        };
        if req.len() != expected {
            return (ERR_BAD_REQUEST, 0);
        }
        if !bucket.take(now_ns) {
            return (ERR_RATE_LIMITED, 0);
        }
        let written = match label {
            LABEL_STATIC_DH => self.static_dh(req, reply),
            LABEL_PSK_MIX => self.psk_mix(req, reply),
            _ => put_bytes(reply, self.boot_seed.as_bytes()).ok_or(ERR_BAD_REQUEST),
        };
        match written {
            Ok(n) => (OK, n),
            Err(e) => (e, 0),
        }
    }

    fn static_dh(&self, req: &[u64], reply: &mut [u64]) -> Result<usize, u64> {
        let point: [u8; 32] = words_to_bytes(req).ok_or(ERR_BAD_REQUEST)?;
        let private = Key32::from_bytes(*self.blob.gateway_private());
        let shared = crypto::dh(&private, &point).map_err(|e| match e {
            crypto::CryptoError::ZeroDh => ERR_ZERO_DH,
            _ => ERR_CRYPTO,
        })?;
        put_bytes(reply, shared.as_bytes()).ok_or(ERR_BAD_REQUEST)
    }

    fn psk_mix(&self, req: &[u64], reply: &mut [u64]) -> Result<usize, u64> {
        let (&[peer], c) = req.split_first_chunk::<1>().ok_or(ERR_BAD_REQUEST)?;
        let peer = usize::try_from(peer).map_err(|_| ERR_UNKNOWN_PEER)?;
        let (_, psk) = self.blob.peer(peer).ok_or(ERR_UNKNOWN_PEER)?;
        let chaining = Key32::from_bytes(words_to_bytes(c).ok_or(ERR_BAD_REQUEST)?);
        let (c2, tau, kappa) = crypto::kdf3(&chaining, psk).map_err(|_| ERR_CRYPTO)?;
        let mut n = 0usize;
        for k in [&c2, &tau, &kappa] {
            let dst = reply.get_mut(n..).ok_or(ERR_BAD_REQUEST)?;
            n = n.saturating_add(put_bytes(dst, k.as_bytes()).ok_or(ERR_BAD_REQUEST)?);
        }
        Ok(n)
    }
}

/// Packs a 32-byte value into four words (used by callers and tests).
pub fn pack32(bytes: &[u8; 32]) -> [u64; 4] {
    let mut w = [0u64; 4];
    let _ = put_bytes(&mut w, bytes);
    w
}

/// Unpacks four words into 32 bytes.
pub fn unpack32(words: &[u64]) -> Option<[u8; 32]> {
    words_to_bytes(words)
}

#[cfg(test)]
mod tests;
