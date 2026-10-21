//! Public-key generation: libmceliece `460896/vec/pk_gen.c` (systematic
//! form; `crypto_sort_int64` replaced by the Batcher network of `sort.rs`,
//! whose order on these non-negative keys is the same).

// Indices are public loop counters over fixed-size arrays (I4).
#![allow(clippy::indexing_slicing)]
// Every `+`/`-`/`*` on a `usize` here is a public index; the masks use
// `wrapping_*`.
#![allow(clippy::arithmetic_side_effects)]

use zeroize::Zeroize;

use super::sort::sort_63b;
use crate::barrier;
use crate::fft::fft;
use crate::params::{GFBITS, GFMASK, PK_NROWS, PK_ROW_BYTES, SYS_N, SYS_T};
use crate::util::{irr_load, store8};
use crate::vec::{self, Vec13};

const NBLOCKS_H: usize = SYS_N.div_ceil(64);
const NBLOCKS_I: usize = (GFBITS * SYS_T).div_ceil(64);
const BLOCK_IDX: usize = NBLOCKS_I - 1;
const TAIL: usize = (GFBITS * SYS_T) % 64;
const N: usize = 1 << GFBITS;

fn de_bitslicing(out: &mut [u64; N], inp: &[Vec13; 128]) {
    *out = [0; N];
    for i in 0..128 {
        for j in (0..GFBITS).rev() {
            for r in 0..64 {
                out[i * 64 + r] <<= 1;
                out[i * 64 + r] |= barrier::u64_bitmod_01(inp[i][j], r);
            }
        }
    }
}

fn to_bitslicing_2x(out0: &mut [Vec13; 128], out1: &mut [Vec13; 128], inp: &[u64; N]) {
    for i in 0..128 {
        out0[i] = [0; GFBITS];
        out1[i] = [0; GFBITS];
        for j in (0..GFBITS).rev() {
            for r in (0..64).rev() {
                out1[i][j] <<= 1;
                out1[i][j] |= barrier::u64_bitmod_01(inp[i * 64 + r], j + GFBITS);
            }
        }
        for j in (0..GFBITS).rev() {
            for r in (0..64).rev() {
                out0[i][GFBITS - 1 - j] <<= 1;
                out0[i][GFBITS - 1 - j] |= barrier::u64_bitmod_01(inp[i * 64 + r], j);
            }
        }
    }
}

/// `crypto_uint64_bitmod_mask(row[pos / 64], pos)`: the bit at `pos` of a
/// row of 64-bit blocks, as a mask.
#[inline(always)]
fn bit_mask(row: &[u64], pos: usize) -> u64 {
    barrier::u64_bitmod_mask(row[pos / 64], pos)
}

/// `pk_gen(pk, irr, perm, pi)`: the systematic public key for the Goppa
/// polynomial at `irr` (`IRR_BYTES`) and the support `perm` sorts to,
/// which is written to `pi`. `false` when two `perm` values collide or
/// the matrix is not systematic: libmceliece declassifies both, and the
/// caller draws again.
#[inline(never)]
pub(crate) fn pk_gen(pk: &mut [u8], irr: &[u8], perm: &[u32; N], pi: &mut [u16; N]) -> bool {
    let mut mat = [[0u64; NBLOCKS_H]; PK_NROWS];
    let mut ops = [[0u64; NBLOCKS_I]; PK_NROWS];
    let mut irr_int = [[0u64; GFBITS]; 2];
    let mut consts = [[0u64; GFBITS]; 128];
    let mut eval = [[0u64; GFBITS]; 128];
    let mut prod = [[0u64; GFBITS]; 128];
    let mut list = [0u64; N];
    let mut column = [0u64; PK_NROWS];

    let ok = 'build: {
        // Compute the inverses.
        irr_load(&mut irr_int, irr);
        fft(&mut eval, &mut irr_int);

        prod[0] = eval[0];
        for i in 1..128 {
            prod[i] = vec::mul(&prod[i - 1], &eval[i]);
        }

        let mut tmp = vec::inv(&prod[127]);
        for i in (0..127).rev() {
            prod[i + 1] = vec::mul(&prod[i], &tmp);
            tmp = vec::mul(&tmp, &eval[i + 1]);
        }
        prod[0] = tmp;
        tmp.zeroize();

        // Fill the matrix.
        de_bitslicing(&mut list, &prod);
        for (i, l) in list.iter_mut().enumerate() {
            *l <<= GFBITS;
            *l |= i as u64;
            *l |= u64::from(perm[i]) << 31;
        }
        sort_63b(&mut list);

        for w in list.windows(2) {
            // uint64_is_equal_declassify: a public rejection.
            if barrier::u64_equal_mask(w[0] >> 31, w[1] >> 31) != 0 {
                break 'build false;
            }
        }

        to_bitslicing_2x(&mut consts, &mut prod, &list);
        for (p, l) in pi.iter_mut().zip(&list) {
            *p = (*l & u64::from(GFMASK)) as u16;
        }

        for j in 0..NBLOCKS_I {
            for k in 0..GFBITS {
                mat[k][j] = prod[j][k];
            }
        }
        for i in 1..SYS_T {
            for j in 0..NBLOCKS_I {
                prod[j] = vec::mul(&prod[j], &consts[j]);
                for k in 0..GFBITS {
                    mat[i * GFBITS + k][j] = prod[j][k];
                }
            }
        }

        // Gaussian elimination to an upper triangular matrix, recording
        // the row operations in `ops`.
        for (i, o) in ops.iter_mut().enumerate() {
            *o = [0; NBLOCKS_I];
            o[i / 64] = 1 << (i % 64);
        }
        for (c, m) in column.iter_mut().zip(&mat) {
            *c = m[BLOCK_IDX];
        }

        for row in 0..PK_NROWS {
            for k in row + 1..PK_NROWS {
                let mask = !bit_mask(&mat[row], row);
                for c in 0..NBLOCKS_I {
                    mat[row][c] ^= mat[k][c] & mask;
                    ops[row][c] ^= ops[k][c] & mask;
                }
            }

            // uint64_is_zero_declassify: a public rejection.
            if barrier::u64_zero_mask(bit_mask(&mat[row], row)) != 0 {
                break 'build false; // not systematic
            }

            for k in row + 1..PK_NROWS {
                let mask = bit_mask(&mat[k], row);
                for c in 0..NBLOCKS_I {
                    mat[k][c] ^= mat[row][c] & mask;
                    ops[k][c] ^= ops[row][c] & mask;
                }
            }
        }

        // The linear map to the systematic form.
        for row in (0..PK_NROWS).rev() {
            for k in 0..row {
                let mask = bit_mask(&mat[k], row);
                for c in 0..NBLOCKS_I {
                    ops[k][c] ^= ops[row][c] & mask;
                }
            }
        }

        // Apply it to the non-systematic part.
        for j in NBLOCKS_I..NBLOCKS_H {
            for k in 0..GFBITS {
                mat[k][j] = prod[j][k];
            }
        }
        for i in 1..SYS_T {
            for j in NBLOCKS_I..NBLOCKS_H {
                prod[j] = vec::mul(&prod[j], &consts[j]);
                for k in 0..GFBITS {
                    mat[i * GFBITS + k][j] = prod[j][k];
                }
            }
        }
        for (m, c) in mat.iter_mut().zip(&column) {
            m[BLOCK_IDX] = *c;
        }

        for (row, out) in pk.as_chunks_mut::<PK_ROW_BYTES>().0.iter_mut().take(PK_NROWS).enumerate() {
            let mut one_row = [0u64; NBLOCKS_H];
            for c in 0..PK_NROWS {
                let mask = bit_mask(&ops[row], c);
                for k in BLOCK_IDX..NBLOCKS_H {
                    one_row[k] ^= mat[c][k] & mask;
                }
            }

            let mut at = 0;
            for k in BLOCK_IDX..NBLOCKS_H - 1 {
                one_row[k] = (one_row[k] >> TAIL) | (one_row[k + 1] << (64 - TAIL));
                store8(&mut out[at..], one_row[k]);
                at += 8;
            }
            let last = one_row[NBLOCKS_H - 1] >> TAIL;
            out[at..].copy_from_slice(&last.to_le_bytes()[..PK_ROW_BYTES % 8]);
        }
        true
    };

    mat.zeroize();
    ops.zeroize();
    irr_int.zeroize();
    consts.zeroize();
    eval.zeroize();
    prod.zeroize();
    list.zeroize();
    column.zeroize();
    ok
}
