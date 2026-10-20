//! Seams for randomness and the KEMs, so the PD supplies the hedged RNG and
//! the `pqkey` call, and tests replay upstream's values (M3 plan C1, T1).

use rosenpass_wire::{ECT_LEN, EPK_LEN, SCT_LEN};

use crate::{KEY_LEN, Secret};

/// Classic McEliece 460896 (round 3) public key.
pub const SPK_LEN: usize = 524_160;
/// Both KEMs' shared secret.
pub const SHK_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RngError;

/// The PD's hedged source (hs-core's `HedgedEntropy` pattern). A failed
/// draw aborts the handshake that asked for it.
pub trait Rng {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RngError>;
}

/// What `Hedged` reads from the hardware: RNDR (None when it fails) and a
/// free-running counter.
pub trait HedgeHw {
    fn rndr(&mut self) -> Option<u64>;
    fn counter(&mut self) -> u64;
}

/// The hedged source (hs-core's `HedgedEntropy` pattern): each 32-byte
/// block is BLAKE2b keyed with the boot seed over a draw counter, the
/// counter and RNDR, so it stays unpredictable if either the seed or RNDR
/// is sound, and never repeats within a boot. A failed RNDR read, or a
/// draw counter that would wrap, fails the draw.
pub struct Hedged<H: HedgeHw> {
    seed: Secret<KEY_LEN>,
    draws: u64,
    hw: H,
}

impl<H: HedgeHw> Hedged<H> {
    pub fn new(seed: Secret<KEY_LEN>, hw: H) -> Self {
        Self { seed, draws: 0, hw }
    }
}

impl<H: HedgeHw> Rng for Hedged<H> {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RngError> {
        for chunk in out.chunks_mut(KEY_LEN) {
            let rndr = self.hw.rndr().ok_or(RngError)?;
            self.draws = self.draws.checked_add(1).ok_or(RngError)?;
            let mut block = Secret::<KEY_LEN>::zero();
            crate::crypto::blake2b(
                self.seed.expose(),
                &[&self.draws.to_le_bytes(), &self.hw.counter().to_le_bytes(), &rndr.to_le_bytes()],
                block.expose_mut(),
            )
            .map_err(|_| RngError)?;
            chunk.copy_from_slice(block.expose().get(..chunk.len()).ok_or(RngError)?);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecapsError {
    /// `pqkey` refused the call for its rate limit (`RpDecapsRateLimited`).
    RateLimited,
    /// `pqkey` refused the call for any other reason.
    Refused,
}

/// Decapsulation under our McEliece secret key, which only `pqkey` holds
/// (`PQ_DECAPS`). McEliece rejects implicitly: a wrong ciphertext yields a
/// pseudorandom key that fails the next AEAD, never an error here.
pub trait Decaps {
    fn decaps(&mut self, sct: &[u8; SCT_LEN]) -> Result<Secret<SHK_LEN>, DecapsError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncapsError {
    Rng,
    /// The KEM refused the public key.
    PublicKey,
}

/// Encapsulation to a public key of `PK` bytes giving a `CT`-byte
/// ciphertext. Implemented for Kyber-512 (RHR4) and McEliece 460896 (RHR5).
pub trait Encaps<const PK: usize, const CT: usize> {
    fn encaps<R: Rng>(&mut self, pk: &[u8; PK], rng: &mut R) -> Result<([u8; CT], Secret<SHK_LEN>), EncapsError>;
}

/// Kyber-512 round 3 (libcrux-ml-kem's `kyber512`), the V02 ephemeral KEM.
/// Not ML-KEM-512: the two are not byte-compatible.
pub struct Kyber512;

impl Encaps<EPK_LEN, ECT_LEN> for Kyber512 {
    fn encaps<R: Rng>(
        &mut self,
        pk: &[u8; EPK_LEN],
        rng: &mut R,
    ) -> Result<([u8; ECT_LEN], Secret<SHK_LEN>), EncapsError> {
        use libcrux_ml_kem::{kyber512, mlkem512::MlKem512PublicKey};
        let mut r = Secret::<32>::zero();
        rng.fill(r.expose_mut()).map_err(|_| EncapsError::Rng)?;
        // libcrux takes the randomness by value; that copy is inside its
        // call (the dependency residue the deviation log records).
        let (ct, mut ss) = kyber512::encapsulate(&MlKem512PublicKey::from(pk), *r.expose());
        let shk = Secret::copy_from(&ss);
        zeroize::Zeroize::zeroize(&mut ss);
        Ok((*ct.as_slice(), shk))
    }
}

/// Classic McEliece 460896 round 3 (classic-mceliece-rust 2.0.2), the
/// static KEM for RHR5. cmr asks its RNG through `fill_bytes`, which cannot
/// fail, so a failed draw is remembered and the whole result discarded.
/// cmr rejection-samples the error vector until the bytes are usable, so
/// after a failure the adapter must still hand out varied filler, or the
/// encapsulation would never return.
pub struct McEliece460896;

struct CmrRng<'a, R: Rng> {
    rng: &'a mut R,
    failed: bool,
    filler: u64,
}

impl<R: Rng> rand_core::RngCore for CmrRng<'_, R> {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if self.failed || self.rng.fill(dest).is_err() {
            self.failed = true;
            // Discarded output; an LCG only has to end cmr's sampling loop.
            for b in dest.iter_mut() {
                self.filler = self.filler.wrapping_mul(0x5851_f42d_4c95_7f2d).wrapping_add(1);
                let [top, ..] = self.filler.to_be_bytes();
                *b = top;
            }
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl<R: Rng> rand_core::CryptoRng for CmrRng<'_, R> {}

impl Encaps<SPK_LEN, SCT_LEN> for McEliece460896 {
    fn encaps<R: Rng>(
        &mut self,
        pk: &[u8; SPK_LEN],
        rng: &mut R,
    ) -> Result<([u8; SCT_LEN], Secret<SHK_LEN>), EncapsError> {
        use classic_mceliece_rust as cmr;
        let mut r = CmrRng { rng, failed: false, filler: 0x9e37_79b9_7f4a_7c15 };
        let mut buf = [0u8; SHK_LEN];
        let (ct, ss) = cmr::encapsulate(&cmr::PublicKey::from(pk), &mut buf, &mut r);
        // cmr's `SharedSecret` zeroizes the borrowed buffer when it drops.
        let shk = Secret::copy_from(ss.as_array());
        drop(ss);
        if r.failed {
            return Err(EncapsError::Rng);
        }
        Ok((*ct.as_array(), shk))
    }
}
