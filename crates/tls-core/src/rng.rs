//! Randomness for the server random, the X25519 ephemeral, the ML-KEM
//! encapsulation randomness and smoltcp's ISN seed (M6 plan C7): a trait so
//! tests inject their own, and the hedged source the PD uses.

use crate::Secret;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RngError;

/// A source of randomness. A failed draw refuses the handshake that asked
/// for it (L9).
pub trait Rng {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RngError>;
}

/// What [`Hedged`] reads from the hardware: RNDR (None when it fails) and
/// the free-running counter (CNTPCT).
pub trait HedgeHw {
    fn rndr(&mut self) -> Option<u64>;
    fn counter(&mut self) -> u64;
}

/// Bytes of the boot seed `tlskey` returns to `tls` (M6 plan C12).
pub const SEED_LEN: usize = 32;
const BLOCK: usize = 32;

/// The hedged source (the `pq` pattern, `rosenpass_core::kem::Hedged`):
/// each 32-byte block is HMAC-SHA256 keyed with `tlskey`'s boot seed
/// over a draw counter, CNTPCT and RNDR, so it stays unpredictable if
/// either the seed or RNDR is sound, and never repeats within a boot. A
/// failed RNDR read, or a draw counter that would wrap, fails the draw.
pub struct Hedged<H: HedgeHw> {
    seed: Secret<SEED_LEN>,
    draws: u64,
    hw: H,
}

impl<H: HedgeHw> Hedged<H> {
    pub fn new(seed: Secret<SEED_LEN>, hw: H) -> Self {
        Self { seed, draws: 0, hw }
    }
}

impl<H: HedgeHw> Rng for Hedged<H> {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RngError> {
        for chunk in out.chunks_mut(BLOCK) {
            let rndr = self.hw.rndr().ok_or(RngError)?;
            self.draws = self.draws.checked_add(1).ok_or(RngError)?;
            let mut block = Secret::<BLOCK>::zero();
            libcrux_hmac::hmac_sha2_256_slices(
                block.as_mut_bytes(),
                self.seed.as_bytes(),
                &[&self.draws.to_le_bytes(), &self.hw.counter().to_le_bytes(), &rndr.to_le_bytes()],
            )
            .map_err(|_| RngError)?;
            chunk.copy_from_slice(block.as_bytes().get(..chunk.len()).ok_or(RngError)?);
        }
        Ok(())
    }
}
