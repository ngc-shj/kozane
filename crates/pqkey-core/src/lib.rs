//! `pqkey`'s oracle: McEliece decapsulation and the pq boot seed behind a
//! closed caller → label table (M3 plan C2).
//!
//! The PD maps its secrets region read-only, validates it once at boot
//! (format, `H(spkm)` against the configuration, then a known-answer
//! decapsulation). Afterwards it answers:
//!
//! | label           | request (words)                    | reply (words)          |
//! |-----------------|------------------------------------|------------------------|
//! | `PQ_DECAPS`     | ciphertext (24; last 4 bytes zero) | shared key (4)         |
//! | `PQ_BOOT_SEED`  | — (0)                              | per-boot seed (4)      |
//! | `PQ_STACK_MARK` | — (0)                              | boot stack mark (1)    |
//!
//! Callers: `Pq → {PQ_DECAPS, PQ_BOOT_SEED, PQ_STACK_MARK}`. An unknown
//! caller, a label outside the caller's row or a malformed request is
//! refused before any budget is spent. McEliece uses implicit rejection, so
//! a wrong but well-formed ciphertext yields a pseudorandom key, never an
//! error. Words are little-endian `u64`s, as in seL4 message registers.
//!
//! `PQ_STACK_MARK` hands `pq` the stack depth `pqkey` measured after its
//! boot KAT, for `pq` to audit: `pqkey` has no audit ring and no console
//! (M5 plan C6). The depth of the constant-time decapsulation does not
//! depend on the key.
//!
//! A boot that fails (`BootError`) leaves the PD up but Unavailable: it
//! holds no secret and answers every call from a known caller with
//! `unavailable_label(code)` and no data, so `pq` can report the failure.

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

use secret_blob::pq::{self, Blob};
use secret_blob::{BlobError, blake2s};
use zeroize::Zeroizing;

pub const LABEL_PQ_DECAPS: u64 = 1;
pub const LABEL_PQ_BOOT_SEED: u64 = 2;

pub const LABEL_PQ_STACK_MARK: u64 = 3;

/// Reply labels (the values `key-core` uses for the same meanings).
pub const OK: u64 = 0;
pub const ERR_BAD_REQUEST: u64 = 1;
pub const ERR_RATE_LIMITED: u64 = 4;
/// `ERR_UNAVAILABLE | code`: the boot failed with `BootError::code` `code`.
pub const ERR_UNAVAILABLE: u64 = 0x100;

pub const PQ_DECAPS_REQ_WORDS: usize = 24;
pub const PQ_DECAPS_REPLY_WORDS: usize = 4;
pub const PQ_BOOT_SEED_REQ_WORDS: usize = 0;
pub const PQ_BOOT_SEED_REPLY_WORDS: usize = 4;
pub const PQ_STACK_MARK_REQ_WORDS: usize = 0;
pub const PQ_STACK_MARK_REPLY_WORDS: usize = 1;
/// Largest request or reply.
pub const MAX_WORDS: usize = PQ_DECAPS_REQ_WORDS;

const DECAPS_REQ_BYTES: usize = PQ_DECAPS_REQ_WORDS * 8;

// The ciphertext fills all but the last 4 bytes of the request (M3 plan F13).
const _: () = assert!(DECAPS_REQ_BYTES - pq::CT_LEN == 4);
// The blob layout's sizes are the crate's (round 3, 460896).
const _: () = assert!(pq::SK_LEN == mce460896::SK_LEN);
const _: () = assert!(pq::PK_LEN == mce460896::PK_LEN);
const _: () = assert!(pq::CT_LEN == mce460896::CT_LEN);
const _: () = assert!(pq::SHK_LEN == mce460896::SS_LEN);

/// `pq`'s call budget: `PQ_KEY_BURST` calls, refilled at one per
/// `PQ_KEY_INTERVAL_NS` (M3 plan C2). Asserted below, at build time, so
/// ingress's InitHello meters cannot exhaust it: the burst covers the global
/// InitHello burst, the link backlog, the one in hand and the boot calls,
/// and the refill is no slower than the global InitHello refill.
pub const PQ_KEY_BURST: u64 = 32;
pub const PQ_KEY_INTERVAL_NS: u64 = 10_000_000_000;

// The pqkey budget invariant (M3 plan C2), checked when `pqkey-core` is
// built: every InitHello `ingress` can forward costs one `PQ_DECAPS`, so a
// burst is the global InitHello burst, all that can wait on the link, and
// the one `pq` has in hand.
const _: () = assert!(
    PQ_KEY_BURST - PQ_BOOT_CALLS > ingress_core::RP_HELLO_GLOBAL_BURST + ingress_core::RP_IN_FLIGHT as u64,
    "C2: forwarded InitHellos plus the pq backlog can exhaust pqkey's bucket"
);
const _: () = assert!(
    PQ_KEY_INTERVAL_NS <= ingress_core::RP_HELLO_GLOBAL_INTERVAL_NS,
    "C2: ingress can forward InitHellos faster than pqkey refills"
);
/// Calls `pq` makes outside handshakes: `PQ_BOOT_SEED` and `PQ_STACK_MARK`
/// at init.
pub const PQ_BOOT_CALLS: u64 = 2;
/// Wall-clock cost of one InitHello → RespHello in `pq` at its committed
/// budget under TCG, preemption included: what `RpCostHighWater` reports.
/// The measured maximum (16.1 s, N = 26, median 8.5 s) with 25% headroom;
/// the integration quiet window checks the boot's high-water mark against
/// it.
pub const PQ_HANDSHAKE_COST_NS: u64 = 20_000_000_000;

/// Domain label of the pq boot seed, distinct from `key`'s construction.
pub const BOOT_SEED_LABEL: &[u8] = b"pq-boot-seed";
/// RNDR samples mixed into the boot seed.
const SEED_SAMPLES: usize = 4;

/// The PDs allowed to call `pqkey`. The PD maps its channel to a caller;
/// a channel with no caller is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Caller {
    Pq,
}

impl Caller {
    /// The closed caller → label table (M3 plan C2, law L2).
    pub const fn allows(self, label: u64) -> bool {
        match self {
            Caller::Pq => matches!(label, LABEL_PQ_DECAPS | LABEL_PQ_BOOT_SEED | LABEL_PQ_STACK_MARK),
        }
    }
}

/// The boot seed's entropy inputs; the PD implements it over `cpu`.
pub trait BootEntropy {
    /// Fills `out` from RNDR; false if the hardware failed.
    fn fill_random(&mut self, out: &mut [u8]) -> bool;
    fn cntpct(&mut self) -> u64;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootError {
    Blob(BlobError),
    SpkmMismatch,
    KatMismatch,
    RndrUnavailable,
}

impl BootError {
    /// Stable text, one per failure (M3 plan C2).
    pub const fn message(self) -> &'static str {
        match self {
            BootError::Blob(e) => e.message(),
            BootError::SpkmMismatch => "pq secrets: public key hash does not match the configuration",
            BootError::KatMismatch => "pq secrets: boot KAT decapsulation mismatch",
            BootError::RndrUnavailable => "RNDR unavailable",
        }
    }

    /// Stable code, one per failure, carried by the Unavailable reply label
    /// and by `pq`'s `KeyUnavailable` audit record (M5 plan C6). Never 0.
    pub const fn code(self) -> u32 {
        match self {
            BootError::Blob(BlobError::BadMagic) => 1,
            BootError::Blob(BlobError::BadVersion) => 2,
            BootError::Blob(BlobError::BadPeerCount) => 3,
            BootError::Blob(BlobError::BadChecksum) => 4,
            BootError::Blob(BlobError::NonZeroPadding) => 5,
            BootError::Blob(BlobError::TooSmall) => 6,
            BootError::SpkmMismatch => 7,
            BootError::KatMismatch => 8,
            BootError::RndrUnavailable => 9,
        }
    }
}

/// The reply label of an Unavailable `pqkey` whose boot failed with `code`.
pub const fn unavailable_label(code: u32) -> u64 {
    ERR_UNAVAILABLE | (code as u64 & 0xff)
}

/// The boot error code an Unavailable reply label carries, if it is one.
pub const fn unavailable_code(label: u64) -> Option<u32> {
    if label & !0xff == ERR_UNAVAILABLE { Some((label & 0xff) as u32) } else { None }
}

/// The answer of an Unavailable `pqkey` (no oracle, no secret): every call
/// from a known caller gets `unavailable_label(code)`, an unknown caller
/// `ERR_BAD_REQUEST`; never any data, and `reply` is zeroed.
pub fn unavailable(caller: Option<Caller>, code: u32, reply: &mut [u64]) -> (u64, usize) {
    reply.fill(0);
    match caller {
        Some(_) => (unavailable_label(code), 0),
        None => (ERR_BAD_REQUEST, 0),
    }
}

fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let diff = a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y));
    core::hint::black_box(diff) == 0
}

/// Decapsulates `ct` with `sk` read in place: `mce460896::decaps` takes the
/// key by shared reference, so no copy of it is made (cmr needed a mutable
/// one, which this used to wipe).
fn decapsulate(sk: &[u8; pq::SK_LEN], ct: &[u8; pq::CT_LEN], out: &mut [u8; pq::SHK_LEN]) {
    mce460896::decaps(sk, ct, out);
}

/// Checks the region: format, `H(spkm)` against the configured value, then
/// the known-answer decapsulation against `H(shk)` (M3 plan C2; fixtures
/// a/b/c).
pub fn validate<'a>(region: &'a [u8], spkm_hash: &[u8; 32]) -> Result<Blob<'a>, BootError> {
    let blob = Blob::parse(region).map_err(BootError::Blob)?;
    if !ct_eq(blob.spkm_hash(), spkm_hash) {
        return Err(BootError::SpkmMismatch);
    }
    let mut shk = Zeroizing::new([0u8; pq::SHK_LEN]);
    decapsulate(blob.secret_key(), blob.kat_ct(), &mut shk);
    if !ct_eq(&blake2s(&[&shk[..]]), blob.kat_shk_hash()) {
        return Err(BootError::KatMismatch);
    }
    Ok(blob)
}

/// BLAKE2s("pq-boot-seed" ‖ blob_seed ‖ RNDR ‖ CNTPCT), drawn once per boot.
pub fn boot_seed(blob_seed: &[u8; 32], entropy: &mut impl BootEntropy) -> Result<Zeroizing<[u8; 32]>, BootError> {
    let mut samples = Zeroizing::new([0u8; SEED_SAMPLES * 8]);
    if !entropy.fill_random(&mut samples[..]) {
        return Err(BootError::RndrUnavailable);
    }
    let cntpct = entropy.cntpct().to_le_bytes();
    Ok(Zeroizing::new(blake2s(&[BOOT_SEED_LABEL, blob_seed, &samples[..], &cntpct])))
}

/// Per-caller CNTPCT token bucket: `burst` calls, refilled at one call per
/// `interval_ns` (the same rule as `key-core`'s, with its own state).
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

/// The ciphertext of a `PQ_DECAPS` request: exactly 24 words whose last 4
/// bytes are zero.
fn decaps_ct(req: &[u64]) -> Option<[u8; pq::CT_LEN]> {
    let words: &[u64; PQ_DECAPS_REQ_WORDS] = req.try_into().ok()?;
    let mut bytes = [0u8; DECAPS_REQ_BYTES];
    for (c, w) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(words) {
        *c = w.to_le_bytes();
    }
    let (ct, pad) = bytes.split_first_chunk::<{ pq::CT_LEN }>()?;
    pad.iter().all(|b| *b == 0).then_some(*ct)
}

pub struct Oracle<'a> {
    blob: Blob<'a>,
    boot_seed: Zeroizing<[u8; 32]>,
    stack_mark: u64,
}

impl<'a> Oracle<'a> {
    /// Boot: validates the region against the configured `H(spkm)` and
    /// draws the boot seed. On any error the PD stays Unavailable.
    pub fn boot(region: &'a [u8], spkm_hash: &[u8; 32], entropy: &mut impl BootEntropy) -> Result<Self, BootError> {
        let blob = validate(region, spkm_hash)?;
        let boot_seed = boot_seed(blob.blob_seed(), entropy)?;
        Ok(Self { blob, boot_seed, stack_mark: 0 })
    }

    /// Records the stack depth (bytes) the PD measured after the boot KAT,
    /// which `PQ_STACK_MARK` answers.
    pub fn set_stack_mark(&mut self, bytes: u64) {
        self.stack_mark = bytes;
    }

    /// Answers one request from `caller` (None: a channel with no caller).
    /// Returns (reply label, reply word count); on any error the count is 0
    /// and `reply` is zeroed.
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
        // Every request is checked in full before the bucket is touched.
        let ct = match label {
            LABEL_PQ_DECAPS => match decaps_ct(req) {
                Some(ct) => Some(ct),
                None => return (ERR_BAD_REQUEST, 0),
            },
            LABEL_PQ_BOOT_SEED if req.len() == PQ_BOOT_SEED_REQ_WORDS => None,
            LABEL_PQ_STACK_MARK if req.len() == PQ_STACK_MARK_REQ_WORDS => None,
            _ => return (ERR_BAD_REQUEST, 0),
        };
        if !bucket.take(now_ns) {
            return (ERR_RATE_LIMITED, 0);
        }
        let written = match ct {
            Some(ct) => {
                let mut shk = Zeroizing::new([0u8; pq::SHK_LEN]);
                decapsulate(self.blob.secret_key(), &ct, &mut shk);
                put_bytes(reply, &shk[..])
            }
            None if label == LABEL_PQ_STACK_MARK => put_bytes(reply, &self.stack_mark.to_le_bytes()),
            None => put_bytes(reply, &self.boot_seed[..]),
        };
        match written {
            Some(n) => (OK, n),
            None => (ERR_BAD_REQUEST, 0),
        }
    }
}

#[cfg(test)]
mod tests;
