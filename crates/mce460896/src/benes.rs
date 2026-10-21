//! The Beneš network: libmceliece `benes.c`.
//!
//! The condition bits (`COND_BYTES` of the secret key) are applied with
//! masked swaps; which words are touched depends only on the layer.

// Indices are public loop counters over fixed-size arrays (I4).
#![allow(clippy::indexing_slicing)]
// Every `+`/`-`/`*` here is on a public loop index bounded by a constant.
#![allow(clippy::arithmetic_side_effects)]

use zeroize::Zeroize;

use crate::transpose::transpose_64x64;
use crate::util::load8;

/// Bytes of condition bits per layer.
const LAYER_BYTES: usize = 512;
/// Layers: 7 outer, 6 + 5 inner, 7 outer.
const LAYERS: usize = 25;

/// Middle layers of the network.
fn layer_in(data: &mut [[u64; 64]; 2], bits: &[u64; 64], lgs: usize) {
    let s = 1usize << lgs;
    let mut k = 0;
    for i in (0..64).step_by(s * 2) {
        for j in i..i + s {
            let d = (data[0][j] ^ data[0][j + s]) & bits[k];
            data[0][j] ^= d;
            data[0][j + s] ^= d;
            k += 1;

            let d = (data[1][j] ^ data[1][j + s]) & bits[k];
            data[1][j] ^= d;
            data[1][j + s] ^= d;
            k += 1;
        }
    }
}

/// First and last layers of the network.
fn layer_ex(data: &mut [[u64; 64]; 2], bits: &[u64; 64], lgs: usize) {
    let s = 1usize << lgs;
    let mut k = 0;
    for i in (0..128).step_by(s * 2) {
        for j in i..i + s {
            let (a, b) = (j, j + s);
            let d = (data[a / 64][a % 64] ^ data[b / 64][b % 64]) & bits[k];
            data[a / 64][a % 64] ^= d;
            data[b / 64][b % 64] ^= d;
            k += 1;
        }
    }
}

/// Loads layer `layer` (counted in application order) of the condition
/// bits. `rev` walks the layers backwards, which applies the inverse.
fn load_layer(out: &mut [u64; 64], bits: &[u8], layer: usize, rev: bool) {
    let at = if rev { LAYERS - 1 - layer } else { layer } * LAYER_BYTES;
    for (i, w) in out.iter_mut().enumerate() {
        *w = load8(&bits[at + i * 8..]);
    }
}

/// `benes(r, bits, rev)`: permutes the 8192 bits of `r` by the network
/// `bits` (`COND_BYTES` long), or by its inverse when `rev`.
#[inline(never)]
pub(crate) fn benes(r: &mut [u64; 128], bits: &[u8], rev: bool) {
    let mut r_int_v = [[0u64; 64]; 2];
    let mut b_int_v = [0u64; 64];
    let mut b_int_h = [0u64; 64];
    let mut layer = 0;

    for i in 0..64 {
        r_int_v[0][i] = r[i * 2];
        r_int_v[1][i] = r[i * 2 + 1];
    }

    let mut r_int_h = r_int_v;
    transpose_64x64(&mut r_int_h[0]);
    transpose_64x64(&mut r_int_h[1]);

    for iter in 0..=6 {
        load_layer(&mut b_int_v, bits, layer, rev);
        layer += 1;
        b_int_h = b_int_v;
        transpose_64x64(&mut b_int_h);
        layer_ex(&mut r_int_h, &b_int_h, iter);
    }

    r_int_v = r_int_h;
    transpose_64x64(&mut r_int_v[0]);
    transpose_64x64(&mut r_int_v[1]);

    for iter in 0..=5 {
        load_layer(&mut b_int_v, bits, layer, rev);
        layer += 1;
        layer_in(&mut r_int_v, &b_int_v, iter);
    }

    for iter in (0..=4).rev() {
        load_layer(&mut b_int_v, bits, layer, rev);
        layer += 1;
        layer_in(&mut r_int_v, &b_int_v, iter);
    }

    r_int_h = r_int_v;
    transpose_64x64(&mut r_int_h[0]);
    transpose_64x64(&mut r_int_h[1]);

    for iter in (0..=6).rev() {
        load_layer(&mut b_int_v, bits, layer, rev);
        layer += 1;
        b_int_h = b_int_v;
        transpose_64x64(&mut b_int_h);
        layer_ex(&mut r_int_h, &b_int_h, iter);
    }

    r_int_v = r_int_h;
    transpose_64x64(&mut r_int_v[0]);
    transpose_64x64(&mut r_int_v[1]);

    for i in 0..64 {
        r[i * 2] = r_int_v[0][i];
        r[i * 2 + 1] = r_int_v[1][i];
    }

    r_int_v.zeroize();
    r_int_h.zeroize();
    b_int_v.zeroize();
    b_int_h.zeroize();
}
