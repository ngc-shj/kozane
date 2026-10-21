//! Bitsliced GF(2^13) arithmetic: libmceliece `vec.c` and `vec.h`.
//!
//! A `[u64; GFBITS]` holds 64 field elements, bit `i` of word `j` being bit
//! `j` of element `i`. Every operation is a fixed sequence of `^`, `&` and
//! shifts by constants, so neither time nor addresses depend on the data.

// Indices are public loop counters over fixed-size arrays (I4).
#![allow(clippy::indexing_slicing)]
// Every `+`/`-` here is on a public loop index bounded by a constant.
#![allow(clippy::arithmetic_side_effects)]

use zeroize::Zeroize;

use crate::barrier;
use crate::params::GFBITS;

pub(crate) type Vec13 = [u64; GFBITS];

/// `vec_setbits`: 0 or 1 to a mask. The input comes from a barrier helper.
#[inline(always)]
pub(crate) fn setbits(b: u64) -> u64 {
    b.wrapping_neg()
}

/// `vec_set1_16b`: replicates a 16-bit value into the four lanes.
#[inline(always)]
pub(crate) fn set1_16b(v: u16) -> u64 {
    let mut ret = u64::from(v);
    ret |= barrier::u64_shlmod(ret, 16);
    ret |= barrier::u64_shlmod(ret, 32);
    ret
}

/// `vec_or_reduce`.
#[inline(always)]
pub(crate) fn or_reduce(a: &Vec13) -> u64 {
    let mut ret = a[0];
    for x in &a[1..] {
        ret |= x;
    }
    ret
}

/// `vec_testz`: 1 iff `a == 0`.
#[inline(always)]
pub(crate) fn testz(a: u64) -> u64 {
    let mut a = a;
    a |= a >> 32;
    a |= a >> 16;
    a |= a >> 8;
    a |= a >> 4;
    a |= a >> 2;
    a |= a >> 1;
    barrier::u64_bottombit_01(a) ^ 1
}

/// `vec_mul`: bitsliced multiplication, `f * g`.
#[inline(never)]
pub(crate) fn mul(f: &Vec13, g: &Vec13) -> Vec13 {
    let mut buf = [0u64; 2 * GFBITS - 1];

    for i in 0..GFBITS {
        for j in 0..GFBITS {
            buf[i + j] ^= f[i] & g[j];
        }
    }

    for i in (GFBITS..=2 * GFBITS - 2).rev() {
        buf[i - GFBITS + 4] ^= buf[i];
        buf[i - GFBITS + 3] ^= buf[i];
        buf[i - GFBITS + 1] ^= buf[i];
        buf[i - GFBITS] ^= buf[i];
    }

    let mut h = [0u64; GFBITS];
    h.copy_from_slice(&buf[..GFBITS]);
    buf.zeroize();
    h
}

/// `vec_sq`: bitsliced squaring.
#[inline(never)]
pub(crate) fn sq(inp: &Vec13) -> Vec13 {
    let t = inp[11] ^ inp[12];
    [
        inp[0] ^ inp[11],
        inp[7] ^ t,
        inp[1] ^ inp[7],
        inp[8] ^ t,
        inp[2] ^ inp[7] ^ inp[8] ^ t,
        inp[7] ^ inp[9],
        inp[3] ^ inp[8] ^ inp[9] ^ inp[12],
        inp[8] ^ inp[10],
        inp[4] ^ inp[9] ^ inp[10],
        inp[9] ^ inp[11],
        inp[5] ^ inp[10] ^ inp[11],
        inp[10] ^ inp[12],
        inp[6] ^ t,
    ]
}

/// `vec_inv`: bitsliced inversion, `in^(2^13 - 2)`.
#[inline(never)]
pub(crate) fn inv(inp: &Vec13) -> Vec13 {
    let mut out = sq(inp);
    let mut tmp_11 = mul(&out, inp); // ^11

    out = sq(&sq(&tmp_11));
    let mut tmp_1111 = mul(&out, &tmp_11); // ^1111

    out = sq(&sq(&sq(&sq(&tmp_1111))));
    out = mul(&out, &tmp_1111); // ^11111111

    out = sq(&sq(&sq(&sq(&out))));
    out = mul(&out, &tmp_1111); // ^111111111111

    tmp_11.zeroize();
    tmp_1111.zeroize();
    sq(&out) // ^1111111111110
}
