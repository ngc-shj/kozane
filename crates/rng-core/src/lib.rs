//! The `rng` PD's seed oracle (M7 plan C6), apart from the device: who may
//! ask how often, and what a device block must look like before it leaves
//! as a seed.
//!
//! I6.1: a `Seed` reply holds 32 bytes the device returned for this request,
//! never zero-filled or partial; a short completion, a device error or
//! timeout, an all-zero block, or a block whose fingerprint (SHA-256) equals
//! the previous block's is `Unavailable`. The fingerprint is all that is
//! kept of a block. I6.2: the device buffer is wiped once copied out.
//! I6.3: one CNTPCT token bucket per caller, charged before the device is
//! touched, so draining one never empties another.

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

pub const SEED_LEN: usize = 32;

/// The callers, M7 plan C7's PD member set; the index is the bucket's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Caller {
    Hs,
    Pq,
    Ingress,
    Tls,
    Key,
    Pqkey,
    Tlskey,
}

pub const CALLERS: usize = 7;

impl Caller {
    fn index(self) -> usize {
        self as usize
    }
}

/// Seeds per caller: four at once (a boot's instantiation with its retries),
/// then one a second. A caller reseeds every `drbg::RESEED_DRAWS` draws,
/// far below this.
pub const SEED_BURST: u64 = 4;
pub const SEED_INTERVAL_NS: u64 = 1_000_000_000;

/// How long one request may wait for the device (CNTPCT-measured): a
/// completion at or after the deadline is `Unavailable`, and the request's
/// descriptor stays the device's until it returns it.
pub const RNG_POLL_NS: u64 = 100_000_000;

/// Why a `Seed` was refused; the value is the reply's reason word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unavailable {
    Quota = 1,
    Device = 2,
    Short = 3,
    Zero = 4,
    Stuck = 5,
}

/// The device gave no usable completion for a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceError;

/// What the PD's virtqueue driver does for one request: fills `out` and
/// returns the length the device reported, or fails (no completion before
/// the deadline, a stale request still outstanding, a device error).
pub trait Device {
    fn draw(&mut self, out: &mut [u8; SEED_LEN]) -> Result<usize, DeviceError>;
}

/// The CNTPCT token bucket (the key PDs' shape).
#[derive(Debug, Clone, Copy)]
struct Bucket {
    budget_ns: u64,
    last_ns: u64,
}

const CAPACITY_NS: u64 = SEED_BURST.saturating_mul(SEED_INTERVAL_NS);

impl Bucket {
    const FULL: Bucket = Bucket { budget_ns: CAPACITY_NS, last_ns: 0 };

    fn take(&mut self, now_ns: u64) -> bool {
        let elapsed = now_ns.saturating_sub(self.last_ns);
        self.budget_ns = self.budget_ns.saturating_add(elapsed).min(CAPACITY_NS);
        self.last_ns = self.last_ns.max(now_ns);
        if self.budget_ns < SEED_INTERVAL_NS {
            return false;
        }
        self.budget_ns = self.budget_ns.saturating_sub(SEED_INTERVAL_NS);
        true
    }
}

pub struct Server {
    buckets: [Bucket; CALLERS],
    last: Option<[u8; 32]>,
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

impl Server {
    pub const fn new() -> Self {
        Self { buckets: [Bucket::FULL; CALLERS], last: None }
    }

    /// One `Seed` request from `caller` at `now_ns`.
    pub fn seed<D: Device>(
        &mut self,
        caller: Caller,
        now_ns: u64,
        device: &mut D,
        out: &mut Secret<SEED_LEN>,
    ) -> Result<(), Unavailable> {
        out.wipe();
        let bucket = self.buckets.get_mut(caller.index()).ok_or(Unavailable::Quota)?;
        if !bucket.take(now_ns) {
            return Err(Unavailable::Quota);
        }
        let mut block = Secret::<SEED_LEN>::zero();
        let n = device.draw(block.as_mut_bytes()).map_err(|DeviceError| Unavailable::Device)?;
        if n != SEED_LEN {
            return Err(Unavailable::Short);
        }
        if block.is_zero() {
            return Err(Unavailable::Zero);
        }
        let fp = fingerprint(block.as_bytes());
        if self.last == Some(fp) {
            return Err(Unavailable::Stuck);
        }
        self.last = Some(fp);
        out.as_mut_bytes().copy_from_slice(block.as_bytes());
        Ok(())
    }
}

/// SHA-256 of a block: what the stuck check keeps instead of the block.
#[cfg(not(kani))]
fn fingerprint(block: &[u8; SEED_LEN]) -> [u8; 32] {
    use libcrux_sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(block);
    let mut out = [0u8; 32];
    h.finish(&mut out);
    out
}

/// The proofs are about the flow, not the hash: under Kani the
/// fingerprint is the block itself (injective, as SHA-256 is assumed).
#[cfg(kani)]
fn fingerprint(block: &[u8; SEED_LEN]) -> [u8; 32] {
    *block
}

#[cfg(test)]
mod tests;

#[cfg(kani)]
mod proofs;
