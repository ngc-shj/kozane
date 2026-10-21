//! Classic McEliece 460896 with round-3 framing (188-byte ciphertexts,
//! `C1 = H(2, e)`, `K = H(1, e, C0 ‖ C1)`), no_std, constant-time
//! (M4 plan C7).
//!
//! - **Decoding core:** libmceliece 20260622 `crypto_kem/460896/vec`
//!   (bitsliced field arithmetic, additive FFT, bitsliced Berlekamp-Massey,
//!   Beneš), with every cryptoint mask call routed through [`barrier`].
//! - **Framing:** the round-3 KEM as the reference liboqs 0.8 vendors
//!   (PQClean `mceliece460896_vec/operations.c`), which is also
//!   libmceliece's `pc` variant. `H` is SHAKE256 with a 32-byte output.
//! - **Sampler:** round-3 `gen_e` semantics without branches or secret
//!   addresses (`encrypt::gen_e`); see [`encaps_attempt`].
//! - **Key generation:** libmceliece's round-3 `kem_keypair` (see
//!   `keygen`), host only.
//!
//! The secret-touching entry points are non-generic `#[inline(never)]`
//! roots that run their `_core` stage and then [`scrub_stack`]. The only
//! generic code is the [`encaps`] shim, whose one branch is on the accept
//! bit (invariant I8). `BARRIERS.md` lists every mask site.

#![no_std]
#![deny(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]
// The port keeps the C code's indexed loops so that it reads side by side
// with libmceliece and the round-3 reference.
#![allow(clippy::needless_range_loop)]

pub mod barrier;
mod benes;
mod bm;
mod consts;
mod decrypt;
mod encrypt;
mod fft;
mod fft_tr;
mod gf;
mod keygen;
mod params;
pub mod stages;
mod transpose;
mod util;
mod vec;

use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use zeroize::{Zeroize, Zeroizing};

use params::{COND_BYTES, IRR_BYTES, SYND_BYTES, SYS_N};

/// Public key: `PK_NROWS` rows of `PK_ROW_BYTES`.
pub const PK_LEN: usize = params::PK_NROWS * params::PK_ROW_BYTES;
/// Secret key, round-3 spec layout `delta ‖ c ‖ g ‖ alpha ‖ s` (cmr's and
/// the `secret_blob::pq` layout). Decapsulation never reads `delta ‖ c`.
pub const SK_LEN: usize = SK_S + SYS_N / 8;
/// Ciphertext `C0 ‖ C1`.
pub const CT_LEN: usize = SYND_BYTES + 32;
/// Shared secret.
pub const SS_LEN: usize = 32;
/// Random bytes one [`encaps_attempt`] consumes.
pub const ENCAPS_RAND_LEN: usize = encrypt::RAND_LEN;

/// Offsets into the secret key.
const SK_IRR: usize = 40;
const SK_COND: usize = SK_IRR + IRR_BYTES;
const SK_S: usize = SK_COND + COND_BYTES;

/// Bytes of stack [`scrub_stack`] zeroes. At least the measured stack peak
/// of `decaps_core` and `encaps_attempt_core` plus a margin
/// (`tests/stack.rs` measures it and holds this to it).
pub const SCRUB_DEPTH: usize = 96 * 1024;

/// The caller's random source failed. No output of the failed call is
/// valid; the output buffers are zeroed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RngError;

/// The secret key's `g ‖ alpha` (the decoder's input) and `s`.
fn sk_parts(sk: &[u8; SK_LEN]) -> (&[u8], &[u8]) {
    let (_, rest) = sk.split_at(SK_IRR);
    rest.split_at(SK_S - SK_IRR)
}

/// SHAKE256 of the concatenation of `parts`, 32 bytes, into `out`.
fn hash_32b(out: &mut [u8; 32], parts: &[&[u8]]) {
    let mut h = Shake256::default();
    for p in parts {
        h.update(p);
    }
    h.finalize_xof().read(out);
}

/// Decapsulation with implicit rejection; never fails. A ciphertext that
/// does not decode, or whose `C1` does not match, yields `H(0, s, C)`.
#[inline(never)]
pub fn decaps(sk: &[u8; SK_LEN], ct: &[u8; CT_LEN], ss_out: &mut [u8; SS_LEN]) {
    decaps_core(sk, ct, ss_out);
    scrub_stack();
}

/// The body of [`decaps`]. Public only for the stack-depth test, which
/// measures it apart from the scrub.
#[doc(hidden)]
#[inline(never)]
pub fn decaps_core(sk: &[u8; SK_LEN], ct: &[u8; CT_LEN], ss_out: &mut [u8; SS_LEN]) {
    let mut e = [0u8; SYS_N / 8];
    let mut conf = [0u8; 32];
    let mut preimage = [0u8; 1 + SYS_N / 8 + CT_LEN];
    let (c0, c1) = ct.split_at(SYND_BYTES);
    let (g_alpha, s) = sk_parts(sk);

    let mut fail = decrypt::decrypt(&mut e, g_alpha, c0);

    hash_32b(&mut conf, &[&[2], &e]);

    // C1 compare, OR-accumulated through the barrier (no early exit).
    for (a, b) in conf.iter().zip(c1) {
        fail = barrier::u8_or(fail, a ^ b);
    }

    // Merge of the decode and confirmation failures, then the e/s select.
    let m = barrier::u8_zero_mask(fail);
    let (head, rest) = preimage.split_at_mut(1);
    let (body, tail) = rest.split_at_mut(SYS_N / 8);
    head.fill(barrier::u8_bottombit_01(m));
    for ((x, ei), si) in body.iter_mut().zip(&e).zip(s) {
        *x = barrier::u8_select(m, *ei, *si);
    }
    tail.copy_from_slice(ct);

    hash_32b(ss_out, &[&preimage]);

    e.zeroize();
    conf.zeroize();
    preimage.zeroize();
    fail.zeroize();
}

/// One round-3 encapsulation attempt from `rand`. Returns the accept bit:
/// 1 when `rand` yields a valid error vector (as liboqs's `gen_e` would
/// accept these bytes), with `ct_out` and `ss_out` set; 0 otherwise, with
/// both zeroed. The bit is the only datum that leaves as public.
///
/// The candidate filter, compaction and duplicate check are branch-free
/// and touch no secret-dependent address. All of the work is done on
/// every attempt.
#[inline(never)]
pub fn encaps_attempt(
    pk: &[u8; PK_LEN],
    rand: &[u8; ENCAPS_RAND_LEN],
    ct_out: &mut [u8; CT_LEN],
    ss_out: &mut [u8; SS_LEN],
) -> u8 {
    let accept = encaps_attempt_core(pk, rand, ct_out, ss_out);
    scrub_stack();
    accept
}

/// The body of [`encaps_attempt`]. Public only for the stack-depth test.
#[doc(hidden)]
#[inline(never)]
pub fn encaps_attempt_core(
    pk: &[u8; PK_LEN],
    rand: &[u8; ENCAPS_RAND_LEN],
    ct_out: &mut [u8; CT_LEN],
    ss_out: &mut [u8; SS_LEN],
) -> u8 {
    let mut st = encrypt::Sample::new();
    let mut e = [0u8; SYS_N / 8];
    let mut c0 = [0u8; SYND_BYTES];
    let mut c1 = [0u8; 32];
    let mut ss = [0u8; SS_LEN];

    let accept = encrypt::gen_e(&mut st, &mut e, rand);
    encrypt::syndrome(&mut c0, pk, &e);
    hash_32b(&mut c1, &[&[2], &e]);
    hash_32b(&mut ss, &[&[1], &e, &c0, &c1]);

    let m = accept as u8;
    let (o0, o1) = ct_out.split_at_mut(SYND_BYTES);
    for (o, x) in o0.iter_mut().zip(&c0).chain(o1.iter_mut().zip(&c1)) {
        *o = x & m;
    }
    for (o, x) in ss_out.iter_mut().zip(&ss) {
        *o = x & m;
    }
    let bit = barrier::u8_bottombit_01(m);

    st.zeroize();
    e.zeroize();
    c0.zeroize();
    c1.zeroize();
    ss.zeroize();
    bit
}

/// Encapsulation: draws [`ENCAPS_RAND_LEN`] fresh bytes from `rng` per
/// attempt and repeats [`encaps_attempt`] until it accepts.
///
/// Invariant I8: every attempt gets a fresh full-length draw, and no byte
/// of a rejected draw is reused, so the attempt count is independent of
/// the accepted `e`. The draw is wiped after every attempt and on the
/// error path. On `Err`, `ct_out` and `ss_out` are zeroed.
pub fn encaps(
    pk: &[u8; PK_LEN],
    rng: &mut impl FnMut(&mut [u8]) -> Result<(), RngError>,
    ct_out: &mut [u8; CT_LEN],
    ss_out: &mut [u8; SS_LEN],
) -> Result<(), RngError> {
    let mut rand = Zeroizing::new([0u8; ENCAPS_RAND_LEN]);
    loop {
        if let Err(err) = rng(rand.as_mut_slice()) {
            rand.zeroize();
            ct_out.zeroize();
            ss_out.zeroize();
            return Err(err);
        }
        let accept = encaps_attempt(pk, &rand, ct_out, ss_out);
        rand.zeroize();
        if accept == 1 {
            return Ok(());
        }
    }
}

/// Key generation (host use; about 1.1 MB of stack). Draws one 32-byte
/// seed and derives the key pair as libmceliece (and cmr 2.0.2) do. On
/// `Err`, both outputs are zeroed.
pub fn keypair(
    rng: &mut impl FnMut(&mut [u8]) -> Result<(), RngError>,
    pk_out: &mut [u8; PK_LEN],
    sk_out: &mut [u8; SK_LEN],
) -> Result<(), RngError> {
    let mut seed = Zeroizing::new([0u8; 32]);
    if let Err(err) = rng(seed.as_mut_slice()) {
        pk_out.zeroize();
        sk_out.zeroize();
        return Err(err);
    }
    keygen::keypair_from_seed(&seed, pk_out, sk_out);
    Ok(())
}

/// The public key belonging to `sk` (test support: the liboqs vectors
/// store only a hash of their public keys). Returns `false`, with `pk_out`
/// unspecified, if `sk` does not yield a systematic matrix.
#[doc(hidden)]
pub fn pk_from_sk(sk: &[u8; SK_LEN], pk_out: &mut [u8; PK_LEN]) -> bool {
    keygen::pk_from_sk(sk, pk_out)
}

/// Zeroes, with volatile writes, `SCRUB_DEPTH` bytes of stack below the
/// caller's frame: what `sha3`, `keccak::f1600` and spills left in the
/// frames of the `_core` stage just returned from (invariant I5).
#[inline(never)]
pub fn scrub_stack() {
    let mut area = [0u64; SCRUB_DEPTH / 8];
    area.zeroize();
}
