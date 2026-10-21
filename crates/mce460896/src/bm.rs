//! Inversion-free Berlekamp-Massey, bitsliced: libmceliece `bm.c`.
//!
//! cmr 2.0.2 leaked here (M4 plan F1). This version keeps the discrepancy
//! `d`, the length `L` and the update decision as masks: every iteration
//! performs the same operations on the same addresses, and the decision
//! is applied with `vec_cmov` and mask selects only.

// Indices are public loop counters over fixed-size arrays (I4).
#![allow(clippy::indexing_slicing)]

use zeroize::Zeroize;

use crate::barrier;
use crate::params::{GFBITS, GFMASK, SYS_T};
use crate::vec::{self, Vec13};

/// `vec_cmov`: `out = mask ? inp : out`, per 16-bit lane mask.
#[inline(always)]
fn vec_cmov(out: &mut Vec13, inp: &Vec13, mask: u16) {
    let m0 = vec::set1_16b(mask);
    let m1 = !m0;
    for (o, i) in out.iter_mut().zip(inp) {
        *o = (i & m0) | (*o & m1);
    }
}

/// `interleave` of `buf[idx0]` and `buf[idx1]` at bit distance `1 << b`.
#[inline(always)]
fn interleave(buf: &mut [u64; 16], idx0: usize, idx1: usize, mask: &[u64; 2], b: usize) {
    let s = 1 << b;
    let x = (buf[idx0] & mask[0]) | ((buf[idx1] & mask[0]) << s);
    let y = ((buf[idx0] & mask[1]) >> s) | (buf[idx1] & mask[1]);
    buf[idx0] = x;
    buf[idx1] = y;
}

/// `get_coefs`: 64 bitsliced field elements to plain form.
fn get_coefs(out: &mut [u16], inp: &Vec13) {
    let mut buf = [0u64; 16];
    buf[..GFBITS].copy_from_slice(inp);

    let mask = [
        [vec::set1_16b(0x5555), vec::set1_16b(0xAAAA)],
        [vec::set1_16b(0x3333), vec::set1_16b(0xCCCC)],
        [vec::set1_16b(0x0F0F), vec::set1_16b(0xF0F0)],
        [vec::set1_16b(0x00FF), vec::set1_16b(0xFF00)],
    ];

    // The 32 interleaves of the C code, stage by stage: at distance 8,
    // then 4, 2 and 1 (the pairs inside a stage are disjoint).
    for b in (0..4).rev() {
        let s = 1usize << b;
        for base in (0..16usize).step_by(s << 1) {
            for i in base..base.wrapping_add(s) {
                interleave(&mut buf, i, i.wrapping_add(s), &mask[b], b);
            }
        }
    }

    for (k, lane) in out.as_chunks_mut::<16>().0.iter_mut().enumerate() {
        for (o, w) in lane.iter_mut().zip(&buf) {
            *o = (w >> (k << 4)) as u16 & GFMASK;
        }
    }
    buf.zeroize();
}

/// `update`: shifts the 128-element window by one and inserts `e` on top.
#[inline(always)]
fn update(inp: &mut [Vec13; 2], e: u16) {
    for i in 0..GFBITS {
        let tmp = barrier::u64_bitmod_01(u64::from(e), i);
        inp[0][i] = (inp[0][i] >> 1) | (inp[1][i] << 63);
        inp[1][i] = (inp[1][i] >> 1) | (tmp << 63);
    }
}

/// `vec_reduce`: the sum of all 128 elements.
#[inline(always)]
fn vec_reduce(inp: &[Vec13; 2]) -> u16 {
    let mut ret = 0u16;
    for i in (0..GFBITS).rev() {
        let mut tmp = inp[0][i] ^ inp[1][i];
        tmp ^= tmp >> 32;
        tmp ^= tmp >> 16;
        tmp ^= tmp >> 8;
        tmp ^= tmp >> 4;
        tmp ^= tmp >> 2;
        tmp ^= tmp >> 1;
        ret <<= 1;
        ret |= barrier::u64_bottombit_01(tmp) as u16;
    }
    ret
}

/// `bm(out, in)`: the error locator of the 2t-element syndrome `inp`.
#[inline(never)]
pub(crate) fn bm(out: &mut [Vec13; 2], inp: &[Vec13; 4]) {
    let mut prod = [[0u64; GFBITS]; 2];
    let mut interval = [[0u64; GFBITS]; 2];
    let mut dd = [[0u64; GFBITS]; 2];
    let mut bb = [[0u64; GFBITS]; 2];
    let mut b_poly = [[0u64; GFBITS]; 2];
    let mut c_poly = [[0u64; GFBITS]; 2];
    let mut b_tmp = [[0u64; GFBITS]; 2];
    let mut c_tmp = [[0u64; GFBITS]; 2];
    let mut coefs = [0u16; 256];

    for (chunk, v) in coefs.chunks_mut(64).zip(inp) {
        get_coefs(chunk, v);
    }

    c_poly[1][0] = 1 << 63;
    b_poly[1][0] = 1 << 62;

    let mut b: u16 = 1;
    let mut l: u16 = 0;

    for n in 0..(SYS_T * 2) as u16 {
        update(&mut interval, coefs[usize::from(n)]);

        prod[0] = vec::mul(&c_poly[0], &interval[0]);
        prod[1] = vec::mul(&c_poly[1], &interval[1]);

        let d = vec_reduce(&prod);

        let mask = (barrier::u64_nonzero_mask(u64::from(d))
            & barrier::u64_leq_mask(u64::from(l.wrapping_mul(2)), u64::from(n))) as u16;

        for i in 0..GFBITS {
            let dv = vec::setbits(barrier::u64_bitmod_01(u64::from(d), i));
            dd[0][i] = dv;
            dd[1][i] = dv;
            let bv = vec::setbits(barrier::u64_bitmod_01(u64::from(b), i));
            bb[0][i] = bv;
            bb[1][i] = bv;
        }

        b_tmp[0] = vec::mul(&dd[0], &b_poly[0]);
        b_tmp[1] = vec::mul(&dd[1], &b_poly[1]);
        c_tmp[0] = vec::mul(&bb[0], &c_poly[0]);
        c_tmp[1] = vec::mul(&bb[1], &c_poly[1]);

        vec_cmov(&mut b_poly[0], &c_poly[0], mask);
        vec_cmov(&mut b_poly[1], &c_poly[1], mask);
        update(&mut b_poly, 0);

        for i in 0..GFBITS {
            c_poly[0][i] = b_tmp[0][i] ^ c_tmp[0][i];
            c_poly[1][i] = b_tmp[1][i] ^ c_tmp[1][i];
        }

        b = (d & mask) | (b & !mask);
        l = (n.wrapping_add(1).wrapping_sub(l) & mask) | (l & !mask);
    }

    for i in 0..GFBITS {
        out[0][i] = (c_poly[0][i] >> 31) | (c_poly[1][i] << 33);
        out[1][i] = c_poly[1][i] >> 31;
    }

    prod.zeroize();
    interval.zeroize();
    dd.zeroize();
    bb.zeroize();
    b_poly.zeroize();
    c_poly.zeroize();
    b_tmp.zeroize();
    c_tmp.zeroize();
    coefs.zeroize();
    b.zeroize();
    l.zeroize();
}
