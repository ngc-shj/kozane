//! X25519MLKEM768 (draft-ietf-tls-ecdhe-mlkem), the only key exchange
//! (L14): the client share is an ML-KEM-768 encapsulation key followed by
//! an X25519 public key; the server encapsulates to the first and answers
//! the second with a fresh ephemeral. Shared secret = ML-KEM ss ‖ X25519
//! ss; server share = ML-KEM ciphertext ‖ X25519 public.
//!
//! [`HybridSecret`] is the only input [`crate::schedule::KeySchedule::new`]
//! takes, and [`HybridSecret::exchange`] (through its non-generic inner
//! function) the only way to make one:
//!
//! ```compile_fail,E0599
//! fn twice(s: tls_core::HybridSecret) -> (tls_core::HybridSecret, tls_core::HybridSecret) {
//!     (s.clone(), s)
//! }
//! ```
//!
//! ```compile_fail,E0382
//! fn twice(s: tls_core::HybridSecret) -> (tls_core::HybridSecret, tls_core::HybridSecret) {
//!     (s, s)
//! }
//! ```
//!
//! ```compile_fail,E0423
//! let forged = tls_core::HybridSecret(tls_core::Secret::<64>::zero());
//! ```
//!
//! ```compile_fail,E0277
//! let forged: tls_core::HybridSecret = Default::default();
//! ```

use libcrux_ml_kem::mlkem768::{self, MlKem768PublicKey};
use zeroize::Zeroize;

use crate::rng::Rng;
use crate::{CLIENT_SHARE_LEN, Refusal, SERVER_SHARE_LEN, Secret};

const MLKEM_EK_LEN: usize = 1184;
const MLKEM_CT_LEN: usize = 1088;
const X25519_LEN: usize = 32;
const SS_LEN: usize = 32;
/// ML-KEM ss ‖ X25519 ss.
pub const HYBRID_SECRET_LEN: usize = 2 * SS_LEN;
/// ML-KEM-768 encapsulation randomness ‖ X25519 ephemeral scalar.
pub const EXCHANGE_RANDOMNESS_LEN: usize = 2 * 32;

/// Bytes of stack [`scrub_session_stack`] zeroes below its caller: the
/// ML-KEM encapsulation and X25519 frames that held the randomness, the
/// ephemeral and both component secrets, and (from `on_hello_record`)
/// `handshake::hello_keys`' frames around them. Measured by the ct-harness
/// at the PD's opt-level (M6 code review T5): `hello_keys` 35 912 bytes
/// below its caller, the exchange alone 34 040; 52 KiB keeps about 30 %
/// headroom over the deeper, inside the 192 KiB `tls` stack. The residue
/// mode's `exchange-depth` and `hello-depth` runs fail above it.
pub const SCRUB_DEPTH_EXCHANGE: usize = 52 * 1024;

/// The X25519MLKEM768 shared secret: not `Copy`/`Clone`/`Debug`, wiped on
/// drop, made only by [`HybridSecret::exchange`] (the L14 adjudicating
/// control, with check-pins' constructor rule).
pub struct HybridSecret(Secret<HYBRID_SECRET_LEN>);

impl HybridSecret {
    /// The exchange with randomness drawn from `rng`: the RNG-generic shim
    /// over [`exchange_with_randomness`]. A failed draw refuses (L9).
    pub fn exchange<R: Rng>(
        client_share: &[u8; CLIENT_SHARE_LEN],
        rng: &mut R,
    ) -> Result<(HybridSecret, [u8; SERVER_SHARE_LEN]), Refusal> {
        let mut randomness = Secret::<EXCHANGE_RANDOMNESS_LEN>::zero();
        rng.fill(randomness.as_mut_bytes()).map_err(|_| Refusal::Internal)?;
        exchange_with_randomness(client_share, randomness.as_bytes())
    }

    /// The key schedule's input keying material.
    pub(crate) fn ikm(&self) -> &[u8; HYBRID_SECRET_LEN] {
        self.0.as_bytes()
    }
}

/// The exchange itself, with the randomness as bytes: the non-generic root
/// the ct-harness residue mode and ct-shape identify (M6 plan C7, F-R6-1).
/// The client's encapsulation key must pass FIPS 203's modulus check, and
/// the X25519 result must not be all zero; either failure is
/// `BadKeyShare`.
#[inline(never)]
pub fn exchange_with_randomness(
    client_share: &[u8; CLIENT_SHARE_LEN],
    randomness: &[u8; EXCHANGE_RANDOMNESS_LEN],
) -> Result<(HybridSecret, [u8; SERVER_SHARE_LEN]), Refusal> {
    let (ek, peer) = client_share.split_first_chunk::<MLKEM_EK_LEN>().ok_or(Refusal::Internal)?;
    let peer: &[u8; X25519_LEN] = peer.try_into().map_err(|_| Refusal::Internal)?;
    let (kem_rand, scalar) = randomness.split_first_chunk::<32>().ok_or(Refusal::Internal)?;
    let scalar: &[u8; 32] = scalar.try_into().map_err(|_| Refusal::Internal)?;

    let ek = MlKem768PublicKey::from(ek);
    if !mlkem768::validate_public_key(&ek) {
        return Err(Refusal::BadKeyShare);
    }
    let mut shared = Secret::<HYBRID_SECRET_LEN>::zero();
    let kem_rand = Secret::copy_from(kem_rand);
    // libcrux takes the randomness by value; that copy is inside its call
    // (the dependency residue the scrub covers).
    let (ct, mut kem_ss) = mlkem768::encapsulate(&ek, *kem_rand.as_bytes());
    let (kem_half, x_half) = shared.as_mut_bytes().split_at_mut(SS_LEN);
    kem_half.copy_from_slice(&kem_ss);
    kem_ss.zeroize();

    let mut ephemeral = Secret::copy_from(scalar);
    libcrux_curve25519::clamp(ephemeral.as_mut_bytes());
    let mut x_ss = Secret::<SS_LEN>::zero();
    libcrux_curve25519::ecdh(x_ss.as_mut_bytes(), peer, ephemeral.as_bytes()).map_err(|_| Refusal::BadKeyShare)?;
    // libcrux already refuses the zero output; the check stays local so
    // the rule does not rest on a dependency.
    if x_ss.is_zero() {
        return Err(Refusal::BadKeyShare);
    }
    x_half.copy_from_slice(x_ss.as_bytes());
    let mut public = [0u8; X25519_LEN];
    libcrux_curve25519::secret_to_public(&mut public, ephemeral.as_bytes());

    let mut share = [0u8; SERVER_SHARE_LEN];
    let (ct_half, pub_half) = share.split_at_mut(MLKEM_CT_LEN);
    ct_half.copy_from_slice(ct.as_slice());
    pub_half.copy_from_slice(&public);
    Ok((HybridSecret(shared), share))
}

/// Zeroes, with volatile writes, [`SCRUB_DEPTH_EXCHANGE`] bytes of stack
/// below the caller's frame: where the exchange just ran. Called by the
/// handshake from the frame that called the exchange and the key schedule
/// (`handshake::hello_keys`, so the hybrid secret's copies are covered
/// too; M6 plan C7, S-R3-2), and by the PD after its TlsSign call.
#[inline(never)]
pub fn scrub_session_stack() {
    let mut area = [0u64; SCRUB_DEPTH_EXCHANGE / 8];
    area.zeroize();
}
