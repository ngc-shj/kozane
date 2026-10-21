//! Little-endian loads and stores, and `irr_load`: libmceliece `util.h`.

// Indices are public loop counters over fixed-size arrays (I4).
#![allow(clippy::indexing_slicing)]
// Every `+`/`*` here is on a public loop index bounded by a constant.
#![allow(clippy::arithmetic_side_effects)]

use zeroize::Zeroize;

use crate::barrier;
use crate::params::{GFBITS, GFMASK, SYS_T};
use crate::vec::Vec13;

/// `load_gf`: a 13-bit field element from two little-endian bytes.
#[inline(always)]
pub(crate) fn load_gf(src: &[u8]) -> u16 {
    u16::from_le_bytes([src[0], src[1]]) & GFMASK
}

/// `store_gf`.
#[inline(always)]
pub(crate) fn store_gf(dest: &mut [u8], a: u16) {
    dest[..2].copy_from_slice(&a.to_le_bytes());
}

/// `load4`.
#[inline(always)]
pub(crate) fn load4(src: &[u8]) -> u32 {
    u32::from_le_bytes([src[0], src[1], src[2], src[3]])
}

/// `load8`.
#[inline(always)]
pub(crate) fn load8(src: &[u8]) -> u64 {
    u64::from_le_bytes([src[0], src[1], src[2], src[3], src[4], src[5], src[6], src[7]])
}

/// `store8`.
#[inline(always)]
pub(crate) fn store8(out: &mut [u8], x: u64) {
    out[..8].copy_from_slice(&x.to_le_bytes());
}

/// `irr_load`: the Goppa polynomial `g` (`SYS_T` coefficients and the
/// implicit leading 1), bitsliced into two 64-element vectors.
#[inline(never)]
pub(crate) fn irr_load(out: &mut [Vec13; 2], inp: &[u8]) {
    let mut irr = [0u16; SYS_T + 1];
    for i in 0..SYS_T {
        irr[i] = load_gf(&inp[i * 2..]);
    }
    irr[SYS_T] = 1;

    for i in 0..GFBITS {
        let mut v0 = 0u64;
        for j in (0..64).rev() {
            v0 <<= 1;
            v0 |= barrier::u64_bitmod_01(u64::from(irr[j]), i);
        }
        let mut v1 = 0u64;
        for j in (64..=SYS_T).rev() {
            v1 <<= 1;
            v1 |= barrier::u64_bitmod_01(u64::from(irr[j]), i);
        }
        out[0][i] = v0;
        out[1][i] = v1;
    }
    irr.zeroize();
}
