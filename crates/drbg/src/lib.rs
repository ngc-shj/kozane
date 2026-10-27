//! The per-PD DRBG (M7 plan C7): every PD that drew from RNDR draws from
//! one of these instead, seeded by the `rng` PD (C6) and hedged with the
//! PD's own seed.
//!
//! State K (32 bytes) and a draw counter:
//!   instantiate  K = PRF(hedge, "init" ‖ rng_seed)
//!   draw block   out = PRF(K, "out" ‖ ctr ‖ cntpct); K = PRF(K, "next" ‖ ctr); ctr += 1
//!   reseed       K = PRF(K, "reseed" ‖ rng_seed), never an assignment
//! PRF is HMAC-SHA256; `ctr` and `cntpct` are u64 LE, the labels fixed and
//! distinct. A draw longer than 32 bytes takes one block per `ctr`, K
//! replaced after each (fast key erasure: a state read later gives no
//! earlier output).
//!
//! I7.2: fills 0..RESEED_DRAWS-1 after the last successful (re)seed succeed;
//! fill number RESEED_DRAWS needs a reseed first and fails otherwise. I7.3:
//! a counter that would wrap fails the draw.

#![no_std]
#![forbid(unsafe_code)]
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

pub use secret::Secret;

pub const KEY_LEN: usize = 32;
/// What the `rng` PD returns per `Seed` (C6).
pub const SEED_LEN: usize = 32;
const BLOCK: usize = 32;

/// Fills a PD may make between two successful seeds (I7.2). A fill is one
/// handshake's or one signature's draw; 2^16 bounds what a state read at
/// any moment exposes going forward.
pub const RESEED_DRAWS: u32 = 1 << 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrbgError {
    /// RESEED_DRAWS fills since the last seed: reseed first.
    ReseedDue,
    /// The draw counter would wrap.
    Exhausted,
    /// The PRF failed.
    Prf,
}

/// The PRF over a key and labelled parts: HMAC-SHA256 for every PD; the
/// Kani harnesses substitute a model to prove the state machine.
pub trait Prf {
    fn prf(key: &[u8; KEY_LEN], parts: &[&[u8]], out: &mut [u8; KEY_LEN]) -> Result<(), DrbgError>;
}

pub struct HmacSha256;

impl Prf for HmacSha256 {
    fn prf(key: &[u8; KEY_LEN], parts: &[&[u8]], out: &mut [u8; KEY_LEN]) -> Result<(), DrbgError> {
        libcrux_hmac::hmac_sha2_256_slices(out, key, parts).map_err(|_| DrbgError::Prf)
    }
}

const INIT: &[u8] = b"kozane drbg init";
const OUT: &[u8] = b"kozane drbg out";
const NEXT: &[u8] = b"kozane drbg next";
const RESEED: &[u8] = b"kozane drbg reseed";

pub struct Drbg<P: Prf = HmacSha256> {
    key: Secret<KEY_LEN>,
    ctr: u64,
    since_seed: u32,
    _prf: core::marker::PhantomData<P>,
}

impl<P: Prf> Drbg<P> {
    /// K = PRF(hedge, "init" ‖ rng_seed). `hedge` is the PD's own seed (a
    /// key PD's boot seed for `hs`, `pq`, `tls`), or zeros where there is
    /// none (`ingress`, the key PDs before their unseal).
    pub fn instantiate(hedge: &Secret<KEY_LEN>, rng_seed: &Secret<SEED_LEN>) -> Result<Self, DrbgError> {
        let mut key = Secret::<KEY_LEN>::zero();
        P::prf(hedge.as_bytes(), &[INIT, rng_seed.as_bytes()], key.as_mut_bytes())?;
        Ok(Self { key, ctr: 0, since_seed: 0, _prf: core::marker::PhantomData })
    }

    /// K = PRF(K, "reseed" ‖ rng_seed): combines with the old state.
    pub fn reseed(&mut self, rng_seed: &Secret<SEED_LEN>) -> Result<(), DrbgError> {
        let mut next = Secret::<KEY_LEN>::zero();
        P::prf(self.key.as_bytes(), &[RESEED, rng_seed.as_bytes()], next.as_mut_bytes())?;
        self.key = next;
        self.since_seed = 0;
        Ok(())
    }

    /// Whether the next fill needs a reseed first (I7.2's boundary).
    pub fn reseed_due(&self) -> bool {
        self.since_seed >= RESEED_DRAWS
    }

    /// Fills `out`, mixing `cntpct` (the counter at the draw) into each
    /// block. On any error `out` is zeroed and the state is unchanged
    /// except that a block already drawn is not drawn again.
    pub fn fill(&mut self, out: &mut [u8], cntpct: u64) -> Result<(), DrbgError> {
        let r = self.fill_inner(out, cntpct);
        if r.is_err() {
            out.fill(0);
        }
        r
    }

    fn fill_inner(&mut self, out: &mut [u8], cntpct: u64) -> Result<(), DrbgError> {
        if self.reseed_due() {
            return Err(DrbgError::ReseedDue);
        }
        for chunk in out.chunks_mut(BLOCK) {
            let ctr = self.ctr;
            self.ctr = ctr.checked_add(1).ok_or(DrbgError::Exhausted)?;
            let mut block = Secret::<BLOCK>::zero();
            P::prf(self.key.as_bytes(), &[OUT, &ctr.to_le_bytes(), &cntpct.to_le_bytes()], block.as_mut_bytes())?;
            let mut next = Secret::<KEY_LEN>::zero();
            P::prf(self.key.as_bytes(), &[NEXT, &ctr.to_le_bytes()], next.as_mut_bytes())?;
            self.key = next;
            let n = chunk.len();
            chunk.copy_from_slice(block.as_bytes().get(..n).ok_or(DrbgError::Prf)?);
        }
        self.since_seed = self.since_seed.saturating_add(1);
        Ok(())
    }
}

#[cfg(test)]
mod tests;

#[cfg(kani)]
mod proofs;
