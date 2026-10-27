//! A PD's randomness (M7 plan C7): a `drbg::Drbg` instantiated from the
//! `rng` PD's seed (C6) and reseeded from it every `RESEED_DRAWS` fills,
//! each block mixing in CNTPCT. It takes the place of RNDR wherever a PD
//! read RNDR; the PD's own hedge (a key PD's boot seed, a blob seed) stays
//! where it was, in the construction RNDR used to feed.
//!
//! I7.2: no output without a seed from `rng` this boot; instantiation tries
//! `RNG_INIT_TRIES` times, and a reseed due and failed fails the draw (the
//! caller's handshake or signature is refused, L9).

#![no_std]

use drbg::{Drbg, Secret};
use layout::rng as ipc;
use sel4_microkit::{Channel, MessageInfo, with_msg_regs, with_msg_regs_mut};

/// Seed requests at instantiation before the PD gives up (D4, R2 SE-N5):
/// a transient `Unavailable` (a slow host, a stuck block) is retried.
pub const RNG_INIT_TRIES: usize = 4;

const SEED_WORDS: usize = drbg::SEED_LEN / 8;

/// One `SEED` call on `ch`: the seed, or the `UNAVAILABLE` reason (0 for a
/// malformed reply). The registers are zeroed after the copy.
pub fn seed(ch: Channel) -> Result<Secret<{ drbg::SEED_LEN }>, u64> {
    let info = ch.pp_call(MessageInfo::new(ipc::SEED, 0));
    let mut out = Secret::<{ drbg::SEED_LEN }>::zero();
    let r = with_msg_regs(|mrs| {
        if info.label() == ipc::SEED && info.count() == SEED_WORDS {
            for (chunk, w) in out.as_mut_bytes().as_chunks_mut::<8>().0.iter_mut().zip(mrs.iter()) {
                chunk.copy_from_slice(&w.to_le_bytes());
            }
            Ok(())
        } else if info.label() == ipc::UNAVAILABLE {
            Err(mrs.first().copied().unwrap_or(0))
        } else {
            Err(0)
        }
    });
    with_msg_regs_mut(|mrs| mrs.iter_mut().take(SEED_WORDS).for_each(|w| *w = 0));
    r.map(|()| out)
}

pub struct Entropy {
    drbg: Drbg,
    ch: Channel,
    /// The last `UNAVAILABLE` reason, for the PD's audit line.
    pub last_reason: u64,
}

impl Entropy {
    /// Instantiates from `rng` on `ch` (hedge: zeros; the PD's own hedge is
    /// in the construction this feeds), trying `RNG_INIT_TRIES` times.
    /// Returns the last reason when every try was refused.
    pub fn instantiate(ch: Channel) -> Result<Self, u64> {
        let mut reason = 0;
        for _ in 0..RNG_INIT_TRIES {
            match seed(ch) {
                Ok(s) => {
                    let drbg = Drbg::instantiate(&Secret::zero(), &s).map_err(|_| 0u64)?;
                    return Ok(Self { drbg, ch, last_reason: 0 });
                }
                Err(r) => reason = r,
            }
        }
        Err(reason)
    }

    /// Fills `out`; false (with `out` zeroed) if a reseed was due and
    /// refused, or the draw failed.
    pub fn fill(&mut self, out: &mut [u8]) -> bool {
        if self.drbg.reseed_due() {
            match seed(self.ch) {
                Ok(s) => {
                    if self.drbg.reseed(&s).is_err() {
                        out.fill(0);
                        return false;
                    }
                }
                Err(r) => {
                    self.last_reason = r;
                    out.fill(0);
                    return false;
                }
            }
        }
        self.drbg.fill(out, cpu::cntpct()).is_ok()
    }

    /// Eight bytes as one u64 (where a PD read one RNDR sample).
    pub fn u64(&mut self) -> Option<u64> {
        let mut b = [0u8; 8];
        self.fill(&mut b).then(|| u64::from_le_bytes(b))
    }
}

/// One PD's `Entropy` where only a plain `fn` or a unit `Transport` can
/// reach it (the cookie adapters, `tpm2::boot`'s salt, a key PD's boot
/// seed): set once in `init`, before anything draws. Empty, every draw
/// fails (a key PD's unseal then fails on its salt, sending `tpm` its
/// Failed as for any other unseal error).
pub struct Global(core::cell::UnsafeCell<Option<Entropy>>);

// SAFETY: a PD runs one thread, `set` runs once in init before any `fill`,
// and `fill` is never re-entered (nothing it calls draws).
unsafe impl Sync for Global {}

impl Global {
    pub const fn new() -> Self {
        Self(core::cell::UnsafeCell::new(None))
    }

    pub fn set(&self, entropy: Option<Entropy>) {
        // SAFETY: see the `Sync` impl; no other reference to the cell is live.
        unsafe { *self.0.get() = entropy };
    }

    pub fn fill(&self, out: &mut [u8]) -> bool {
        // SAFETY: see the `Sync` impl; no other reference to the cell is live.
        match unsafe { &mut *self.0.get() } {
            Some(e) => e.fill(out),
            None => {
                out.fill(0);
                false
            }
        }
    }
}

impl Default for Global {
    fn default() -> Self {
        Self::new()
    }
}
