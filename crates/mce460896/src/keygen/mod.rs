//! Key generation (host only: `tools/mksecrets`): libmceliece 20260622
//! `kem_keypair.c` with its `sk_gen`, `pk_gen` and `controlbits`, the
//! round-3 key generation cmr 2.0.2 also implements.
//!
//! The 32-byte seed `delta` from the caller's random source is expanded
//! with SHAKE256 (`64 ‖ delta`) into `s`, the support's sort keys, `f` and
//! the next `delta`. The secret key is the spec layout
//! `delta ‖ c ‖ g ‖ alpha ‖ s`, `c` being the pivot word `0xFFFFFFFF`.
//!
//! Key generation needs about 1.1 MB of stack (`pk_gen`'s matrices).

// Indices are public loop counters over fixed-size arrays (I4).
#![allow(clippy::indexing_slicing)]

mod controlbits;
mod pk_gen;
mod sk_gen;
mod sort;

use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use zeroize::Zeroize;

use crate::gf::Gf;
use crate::params::{COND_BYTES, GFBITS, SYS_N, SYS_T};
use crate::util::{load4, load_gf, store_gf, store8};
use crate::{PK_LEN, SK_COND, SK_IRR, SK_LEN, SK_S};

const PERM_BYTES: usize = (1 << GFBITS) * 4;
/// The expansion: `s`, the support's sort keys, `f`, then the next seed.
const R_LEN: usize = SYS_N / 8 + PERM_BYTES + SYS_T * 2 + 32;
const R_PERM: usize = SYS_N / 8;
const R_F: usize = R_PERM + PERM_BYTES;
const R_SEED: usize = R_LEN - 32;

/// `operation_keypair` after its one `randombytes(seed + 1, 32)`.
#[inline(never)]
pub(crate) fn keypair_from_seed(delta: &[u8; 32], pk: &mut [u8; PK_LEN], sk: &mut [u8; SK_LEN]) {
    let mut seed = [0u8; 33];
    let mut r = [0u8; R_LEN];
    let mut f = [0 as Gf; SYS_T];
    let mut irr = [0 as Gf; SYS_T];
    let mut perm = [0u32; 1 << GFBITS];
    let mut pi = [0u16; 1 << GFBITS];
    let mut cond = [0u8; COND_BYTES];

    seed[0] = 64;
    seed[1..].copy_from_slice(delta);
    *sk = [0; SK_LEN];

    loop {
        // Expanding and updating the seed.
        let mut h = Shake256::default();
        h.update(&seed);
        h.finalize_xof().read(&mut r);
        sk[..32].copy_from_slice(&seed[1..]);
        seed[1..].copy_from_slice(&r[R_SEED..]);

        // Generating the irreducible polynomial.
        for (x, c) in f.iter_mut().zip(r[R_F..R_SEED].as_chunks::<2>().0) {
            *x = load_gf(c);
        }
        if !sk_gen::genpoly_gen(&mut irr, &f) {
            continue;
        }
        for (c, x) in sk[SK_IRR..SK_COND].as_chunks_mut::<2>().0.iter_mut().zip(&irr) {
            store_gf(c, *x);
        }

        // Generating the permutation.
        for (p, c) in perm.iter_mut().zip(r[R_PERM..R_F].as_chunks::<4>().0) {
            *p = load4(c);
        }
        if !pk_gen::pk_gen(pk, &sk[SK_IRR..SK_COND], &perm, &mut pi) {
            continue;
        }

        controlbits::controlbits(&mut cond, &pi);
        sk[SK_COND..SK_S].copy_from_slice(&cond);

        // Storing the random string s.
        sk[SK_S..].copy_from_slice(&r[..SYS_N / 8]);

        // Storing the positions of the 32 pivots.
        store8(&mut sk[32..40], 0xFFFFFFFF);
        break;
    }

    seed.zeroize();
    r.zeroize();
    f.zeroize();
    irr.zeroize();
    perm.zeroize();
    pi.zeroize();
    cond.zeroize();
}

/// The public key of a secret key: the support is recovered by applying
/// the key's network to the identity, then `pk_gen` runs with sort keys
/// that reproduce exactly that support. `false` if `sk` is not a valid
/// key (its matrix is not systematic).
pub(crate) fn pk_from_sk(sk: &[u8; SK_LEN], pk: &mut [u8; PK_LEN]) -> bool {
    let mut cond = [0u8; COND_BYTES];
    let mut pi = [0u16; 1 << GFBITS];
    let mut perm = [0u32; 1 << GFBITS];

    cond.copy_from_slice(&sk[SK_COND..SK_S]);
    controlbits::apply_network(&mut pi, &cond);
    // Sorting by perm[i] = (position of i in pi) yields pi again.
    for (k, &p) in pi.iter().enumerate() {
        perm[usize::from(p)] = k as u32;
    }
    let mut out = [0u16; 1 << GFBITS];
    let ok = pk_gen::pk_gen(pk, &sk[SK_IRR..SK_COND], &perm, &mut out) && out == pi;

    cond.zeroize();
    pi.zeroize();
    perm.zeroize();
    out.zeroize();
    ok
}
