//! Secret-key generation: libmceliece `sk_gen.c` (`genpoly_gen`) and
//! `gf_2mt_mul.c` (`GF_mul`, modulo the round-3/4 field polynomial
//! `y^96 + y^10 + y^9 + y^6 + 1`).

// Indices are public loop counters over fixed-size arrays (I4).
#![allow(clippy::indexing_slicing)]
// Every `+`/`-`/`*` here is on a public loop index bounded by a constant.
#![allow(clippy::arithmetic_side_effects)]

use zeroize::Zeroize;

use crate::barrier;
use crate::gf::{self, Gf};
use crate::params::SYS_T;

/// `GF_mul`: `out = in0 * in1` in GF((2^13)^96).
fn big_mul(out: &mut [Gf; SYS_T], in0: &[Gf; SYS_T], in1: &[Gf; SYS_T]) {
    let mut prod = [0 as Gf; SYS_T * 2 - 1];

    for i in 0..SYS_T {
        for j in 0..SYS_T {
            prod[i + j] ^= gf::mul(in0[i], in1[j]);
        }
    }

    for i in (SYS_T..=(SYS_T - 1) * 2).rev() {
        prod[i - SYS_T + 10] ^= prod[i];
        prod[i - SYS_T + 9] ^= prod[i];
        prod[i - SYS_T + 6] ^= prod[i];
        prod[i - SYS_T] ^= prod[i];
    }

    out.copy_from_slice(&prod[..SYS_T]);
    prod.zeroize();
}

/// `genpoly_gen(out, f)`: the minimal polynomial of `f`. `false` when
/// the system is not systematic: libmceliece declassifies that bit and
/// the caller draws again.
pub(crate) fn genpoly_gen(out: &mut [Gf; SYS_T], f: &[Gf; SYS_T]) -> bool {
    let mut mat = [[0 as Gf; SYS_T]; SYS_T + 1];

    mat[0][0] = 1;
    mat[1] = *f;
    for j in 2..=SYS_T {
        let prev = mat[j - 1];
        big_mul(&mut mat[j], &prev, f);
    }

    let mut ok = true;
    for j in 0..SYS_T {
        for k in j + 1..SYS_T {
            let mask = gf::iszero(mat[j][j]);
            for c in j..=SYS_T {
                mat[c][j] ^= mat[c][k] & mask;
            }
        }

        // gf_is_zero_declassify: a public rejection.
        if barrier::u16_zero_mask(mat[j][j]) != 0 {
            ok = false;
            break;
        }

        let inv = gf::inv(mat[j][j]);
        for c in j..=SYS_T {
            mat[c][j] = gf::mul(mat[c][j], inv);
        }

        for k in 0..SYS_T {
            if k != j {
                let t = mat[j][k];
                for c in j..=SYS_T {
                    mat[c][k] ^= gf::mul(mat[c][j], t);
                }
            }
        }
    }

    if ok {
        *out = mat[SYS_T];
    }
    mat.zeroize();
    ok
}
