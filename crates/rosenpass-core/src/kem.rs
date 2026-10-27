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
    fn random(&mut self) -> Option<u64>;
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
            let rndr = self.hw.random().ok_or(RngError)?;
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

/// Classic McEliece 460896 round 3 (`mce460896`), the static KEM for RHR5.
/// The shim draws its randomness through a closure over `Rng`, so a failed
/// draw surfaces directly as `EncapsError::Rng`, with no filler bytes
/// needed to keep a rejection-sampling loop moving.
pub struct McEliece460896;

impl Encaps<SPK_LEN, SCT_LEN> for McEliece460896 {
    fn encaps<R: Rng>(
        &mut self,
        pk: &[u8; SPK_LEN],
        rng: &mut R,
    ) -> Result<([u8; SCT_LEN], Secret<SHK_LEN>), EncapsError> {
        let mut ct = [0u8; SCT_LEN];
        let mut ss = [0u8; SHK_LEN];
        mce460896::encaps(pk, &mut |out| rng.fill(out).map_err(|_| mce460896::RngError), &mut ct, &mut ss)
            .map_err(|_| EncapsError::Rng)?;
        let shk = Secret::copy_from(&ss);
        zeroize::Zeroize::zeroize(&mut ss);
        Ok((ct, shk))
    }
}
