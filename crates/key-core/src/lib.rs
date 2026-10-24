//! `key` oracle logic (plan C10, law L2): the only code that touches the
//! gateway's static WireGuard private key. The PD maps the secrets region
//! read-only; it holds the blob sealed (M5 plan C11), which the PD unseals
//! through `tpm` into its own memory at boot (`tpm2::boot`). The plaintext
//! is validated against the compiled configuration once; then the PD
//! answers fixed-size PPC requests:
//!
//! | label        | request (words)        | reply (words)        |
//! |--------------|------------------------|----------------------|
//! | `STATIC_DH`  | peer point (4)         | DH(S_priv, point) (4)|
//! | `BOOT_SEED`  | — (0)                  | per-boot seed (4)    |
//!
//! Each caller may use only the labels in its row of a closed caller →
//! label table (M3 plan C2): `Hs → {STATIC_DH, BOOT_SEED}`. An unknown
//! caller, a label outside the caller's row, a wrong size, an all-zero DH
//! or an exhausted caller budget gets an error label and no data; the first
//! three before any budget is spent. Words are little-endian `u64`s, as in
//! seL4 message registers. WireGuard PSKs come only from Rosenpass (L8);
//! `key` holds none.
//!
//! A boot that fails (`BootError`) leaves the PD up but Unavailable (M5 plan
//! C6): it holds no secret and answers every call from a known caller with
//! `unavailable_label(code)` and no data, so `hs` can report the failure
//! (`key` has no audit ring and no console, L1).

#![no_std]
#![cfg_attr(test, feature(variant_count))]
#![deny(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use secret_blob::{Blob, BlobError};
use tpm2::boot::UnsealError;
use wg_core::crypto::{self, Key32};

pub const LABEL_STATIC_DH: u64 = 1;
pub const LABEL_BOOT_SEED: u64 = 3;

/// Reply labels.
pub const OK: u64 = 0;
pub const ERR_BAD_REQUEST: u64 = 1;
pub const ERR_ZERO_DH: u64 = 2;
pub const ERR_RATE_LIMITED: u64 = 4;
pub const ERR_CRYPTO: u64 = 5;
/// `ERR_UNAVAILABLE | code`: the boot failed with `BootError::code` `code`.
pub const ERR_UNAVAILABLE: u64 = 0x100;

pub const STATIC_DH_REQ_WORDS: usize = 4;
pub const BOOT_SEED_REQ_WORDS: usize = 0;
pub const STATIC_DH_REPLY_WORDS: usize = 4;
pub const BOOT_SEED_REPLY_WORDS: usize = 4;
/// Largest request or reply.
pub const MAX_WORDS: usize = STATIC_DH_REQ_WORDS;

/// The PDs allowed to call `key`. The PD maps its channel to a caller;
/// a channel with no caller is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Caller {
    Hs,
}

impl Caller {
    /// The closed caller → label table (M3 plan C2, law L2).
    pub const fn allows(self, label: u64) -> bool {
        match self {
            Caller::Hs => matches!(label, LABEL_STATIC_DH | LABEL_BOOT_SEED),
        }
    }
}

/// `hs`'s call budget: `KEY_BURST` calls, refilled at one per
/// `KEY_INTERVAL_NS` (2 000/s). Far beyond what `hs`'s CPU budget can drive,
/// while still bounding a runaway caller. The initiations `ingress` can
/// forward must never exhaust it (M2.5 plan C5).
pub const KEY_BURST: u64 = 256;
pub const KEY_INTERVAL_NS: u64 = 1_000_000_000 / 2_000;
/// Calls `hs` makes outside handshakes: the `BOOT_SEED` request at init
/// (crates/pds/hs/src/main.rs).
pub const KEY_BOOT_CALLS: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootError {
    Blob(BlobError),
    GatewayKeyMismatch,
    PeerMismatch,
    /// RNDR failed while drawing the boot seed's samples.
    RndrUnavailable,
    /// Hashing the boot seed failed.
    SeedDerivation,
    /// The secrets region is not a sealed envelope of `key`'s kind (M5
    /// plan C11: a plaintext blob is refused here).
    EnvelopeInvalid,
    /// `tpm` refused, failed or stayed busy (M5 plan C9).
    TpmUnavailable,
    /// The TPM's SRK is not the envelope's pinned one: another TPM (I10.2).
    SrkMismatch,
    /// The TPM refused the Unseal: PCR 8 is not the value sealed to.
    UnsealRefused,
    /// A TPM response failed the client's checks (A7).
    TpmResponseInvalid,
    /// The unsealed KEK did not open the envelope.
    EnvelopeOpen,
}

impl From<UnsealError> for BootError {
    fn from(e: UnsealError) -> Self {
        match e {
            UnsealError::Rndr => BootError::RndrUnavailable,
            UnsealError::EnvelopeInvalid => BootError::EnvelopeInvalid,
            UnsealError::TpmUnavailable => BootError::TpmUnavailable,
            UnsealError::SrkMismatch => BootError::SrkMismatch,
            UnsealError::UnsealRefused => BootError::UnsealRefused,
            UnsealError::ResponseInvalid => BootError::TpmResponseInvalid,
            UnsealError::EnvelopeOpen => BootError::EnvelopeOpen,
        }
    }
}

impl BootError {
    /// Stable text, one per failure (plan C10).
    pub const fn message(self) -> &'static str {
        match self {
            BootError::Blob(e) => e.message(),
            BootError::GatewayKeyMismatch => "secrets: gateway key does not match the configuration",
            BootError::PeerMismatch => "secrets: peer keys do not match the configuration",
            BootError::RndrUnavailable => "RNDR unavailable",
            BootError::SeedDerivation => "boot seed derivation failed",
            BootError::EnvelopeInvalid => "secrets: not a sealed envelope for key",
            BootError::TpmUnavailable => "secrets: tpm unavailable",
            BootError::SrkMismatch => "secrets: sealed to another TPM",
            BootError::UnsealRefused => "secrets: the TPM refused to unseal (PCR 8)",
            BootError::TpmResponseInvalid => "secrets: a TPM response failed its checks",
            BootError::EnvelopeOpen => "secrets: the unsealed KEK does not open the envelope",
        }
    }

    /// Stable code, one per failure, carried by the Unavailable reply label
    /// and by `hs`'s `KeyUnavailable` audit record (M5 plan C6). Never 0.
    pub const fn code(self) -> u32 {
        match self {
            BootError::Blob(BlobError::BadMagic) => 1,
            BootError::Blob(BlobError::BadVersion) => 2,
            BootError::Blob(BlobError::BadPeerCount) => 3,
            BootError::Blob(BlobError::BadChecksum) => 4,
            BootError::Blob(BlobError::NonZeroPadding) => 5,
            BootError::Blob(BlobError::TooSmall) => 6,
            BootError::GatewayKeyMismatch => 7,
            BootError::PeerMismatch => 8,
            BootError::RndrUnavailable => 9,
            BootError::SeedDerivation => 10,
            BootError::EnvelopeInvalid => 11,
            BootError::TpmUnavailable => 12,
            BootError::SrkMismatch => 13,
            BootError::UnsealRefused => 14,
            BootError::TpmResponseInvalid => 15,
            BootError::EnvelopeOpen => 16,
        }
    }
}

/// The reply label of an Unavailable `key` whose boot failed with `code`.
pub const fn unavailable_label(code: u32) -> u64 {
    ERR_UNAVAILABLE | (code as u64 & 0xff)
}

/// The boot error code an Unavailable reply label carries, if it is one.
pub const fn unavailable_code(label: u64) -> Option<u32> {
    if label & !0xff == ERR_UNAVAILABLE { Some((label & 0xff) as u32) } else { None }
}

/// The answer of an Unavailable `key` (no oracle, no secret): every call from
/// a known caller gets `unavailable_label(code)`, an unknown caller
/// `ERR_BAD_REQUEST`; never any data, and `reply` is zeroed.
pub fn unavailable(caller: Option<Caller>, code: u32, reply: &mut [u64]) -> (u64, usize) {
    reply.fill(0);
    match caller {
        Some(_) => (unavailable_label(code), 0),
        None => (ERR_BAD_REQUEST, 0),
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
    let private = Key32::copy_from(blob.gateway_private());
    if !crypto::ct_eq(&crypto::public_key(&private), gateway_public) {
        return Err(BootError::GatewayKeyMismatch);
    }
    for (i, public) in peers.enumerate() {
        let hash = blob.peer(i).ok_or(BootError::PeerMismatch)?;
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

/// RNDR samples mixed into the boot seed.
pub const SEED_SAMPLES: usize = 4;

/// The boot seed's entropy inputs; the PD implements it over `cpu`.
pub trait BootEntropy {
    /// Fills `out` from RNDR; false if the hardware failed.
    fn fill_random(&mut self, out: &mut [u8]) -> bool;
    fn cntpct(&mut self) -> u64;
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

    /// Everything `key` does with the unsealed region before it can answer:
    /// validation, then the per-boot seed (blob seed ‖ RNDR ‖ CNTPCT). One
    /// fallible call, so the PD wipes the region on any of its failures
    /// with a single guard, as `pqkey` does (M5 plan C6: an Unavailable
    /// `key` holds no secret).
    pub fn boot<'p>(
        region: &'a [u8],
        gateway_public: &[u8; 32],
        peers: impl ExactSizeIterator<Item = &'p [u8; 32]>,
        entropy: &mut impl BootEntropy,
    ) -> Result<Self, BootError> {
        let blob = validate(region, gateway_public, peers)?;
        // Both wipe themselves on drop (tpm2::Secret), on every return.
        let mut samples = tpm2::Secret::<{ SEED_SAMPLES * 8 }>::zero();
        if !entropy.fill_random(samples.as_mut_bytes()) {
            return Err(BootError::RndrUnavailable);
        }
        let mut seed = tpm2::Secret::<32>::zero();
        *seed.as_mut_bytes() = crypto::hash(&[blob.boot_seed(), samples.as_bytes(), &entropy.cntpct().to_le_bytes()])
            .map_err(|_| BootError::SeedDerivation)?;
        Ok(Self::new(blob, Key32::copy_from(seed.as_bytes())))
    }

    /// Answers one request from `caller` (None: a channel with no caller).
    /// Returns (reply label, reply word count); on any error the count is 0
    /// and `reply` is zeroed, so no partial result leaks through a reused
    /// message register.
    pub fn handle(
        &self,
        caller: Option<Caller>,
        bucket: &mut Bucket,
        now_ns: u64,
        label: u64,
        req: &[u64],
        reply: &mut [u64],
    ) -> (u64, usize) {
        let r = match caller {
            Some(c) if c.allows(label) => self.dispatch(bucket, now_ns, label, req, reply),
            _ => (ERR_BAD_REQUEST, 0),
        };
        if r.0 != OK {
            reply.fill(0);
            return (r.0, 0);
        }
        r
    }

    fn dispatch(&self, bucket: &mut Bucket, now_ns: u64, label: u64, req: &[u64], reply: &mut [u64]) -> (u64, usize) {
        let expected = match label {
            LABEL_STATIC_DH => STATIC_DH_REQ_WORDS,
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
            _ => put_bytes(reply, self.boot_seed.as_bytes()).ok_or(ERR_BAD_REQUEST),
        };
        match written {
            Ok(n) => (OK, n),
            Err(e) => (e, 0),
        }
    }

    fn static_dh(&self, req: &[u64], reply: &mut [u64]) -> Result<usize, u64> {
        let point: [u8; 32] = words_to_bytes(req).ok_or(ERR_BAD_REQUEST)?;
        let private = Key32::copy_from(self.blob.gateway_private());
        let shared = crypto::dh(&private, &point).map_err(|e| match e {
            crypto::CryptoError::ZeroDh => ERR_ZERO_DH,
            _ => ERR_CRYPTO,
        })?;
        put_bytes(reply, shared.as_bytes()).ok_or(ERR_BAD_REQUEST)
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
