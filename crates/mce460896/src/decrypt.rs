//! Niederreiter decryption with the Berlekamp decoder: libmceliece
//! `decrypt.c`.

// Indices are public loop counters over fixed-size arrays (I4).
#![allow(clippy::indexing_slicing)]

use zeroize::Zeroize;

use crate::barrier;
use crate::benes::benes;
use crate::bm::bm;
use crate::fft::fft;
use crate::fft_tr::fft_tr;
use crate::params::{GFBITS, IRR_BYTES, SYND_BYTES, SYS_N, SYS_T};
use crate::util::{irr_load, load8, store8};
use crate::vec::{self, Vec13};

/// `scaling`: `inv[i] = 1 / g(a_i)^2` for every field element, and
/// `out = inv * recv`. `sk` starts at the Goppa polynomial.
#[inline(never)]
pub(crate) fn scaling(out: &mut [Vec13; 128], inv: &mut [Vec13; 128], sk: &[u8], recv: &[u64; 128]) {
    let mut irr_int = [[0u64; GFBITS]; 2];
    let mut eval = [[0u64; GFBITS]; 128];

    irr_load(&mut irr_int, sk);
    fft(&mut eval, &mut irr_int);

    for e in eval.iter_mut() {
        *e = vec::sq(e);
    }

    inv[0] = eval[0];
    for i in 1..128usize {
        inv[i] = vec::mul(&inv[i.wrapping_sub(1)], &eval[i]);
    }

    let mut tmp = vec::inv(&inv[127]);

    for i in (0..127usize).rev() {
        inv[i.wrapping_add(1)] = vec::mul(&tmp, &inv[i]);
        tmp = vec::mul(&tmp, &eval[i.wrapping_add(1)]);
    }

    inv[0] = tmp;

    for i in 0..128 {
        for j in 0..GFBITS {
            out[i][j] = inv[i][j] & recv[i];
        }
    }

    irr_int.zeroize();
    eval.zeroize();
    tmp.zeroize();
}

/// `preprocess`: the syndrome bytes, zero-padded to 8192 bits.
fn preprocess(recv: &mut [u64; 128], s: &[u8]) {
    let mut r = [0u8; 1024];
    r[..SYND_BYTES].copy_from_slice(&s[..SYND_BYTES]);
    for (w, c) in recv.iter_mut().zip(r.as_chunks::<8>().0) {
        *w = load8(c);
    }
    r.zeroize();
}

/// `postprocess`: the first `SYS_N` error bits as bytes.
fn postprocess(e: &mut [u8; SYS_N / 8], err: &[u64; 128]) {
    let mut error8 = [0u8; (1 << GFBITS) / 8];
    for (c, w) in error8.as_chunks_mut::<8>().0.iter_mut().zip(err) {
        store8(c, *w);
    }
    e.copy_from_slice(&error8[..SYS_N / 8]);
    error8.zeroize();
}

/// `scaling_inv`: `out = inv * recv`.
fn scaling_inv(out: &mut [Vec13; 128], inv: &[Vec13; 128], recv: &[u64; 128]) {
    for i in 0..128 {
        for j in 0..GFBITS {
            out[i][j] = inv[i][j] & recv[i];
        }
    }
}

/// `weight_check`: 1 iff both weights (before and after the inverse
/// network) are `SYS_T`.
fn weight_check(e: &[u8; SYS_N / 8], error: &[u64; 128]) -> u16 {
    let mut w0: u16 = 0;
    let mut w1: u16 = 0;

    for i in 0..(1usize << GFBITS) {
        w0 = w0.wrapping_add(barrier::u64_bitmod_01(error[i / 64], i) as u16);
    }
    for i in 0..SYS_N {
        w1 = w1.wrapping_add(barrier::u8_bitmod_01(e[i / 8], i));
    }

    let check = (w0 ^ SYS_T as u16) | (w1 ^ SYS_T as u16);
    let ok = barrier::u16_zero_01(check);
    w0.zeroize();
    w1.zeroize();
    ok
}

/// `synd_cmp`: 1 iff the two syndromes are equal.
fn synd_cmp(s0: &[Vec13; 4], s1: &[Vec13; 4]) -> u16 {
    let mut diff = 0u64;
    for (a, b) in s0.iter().zip(s1) {
        for (x, y) in a.iter().zip(b) {
            diff |= x ^ y;
        }
    }
    vec::testz(diff) as u16
}

/// The decoder's secret intermediates. They live in one place so that
/// `decrypt` wipes them all on its single return path, and so that the
/// test-support stages (`crate::stages`) can expose them.
pub(crate) struct Work {
    pub(crate) inv: [Vec13; 128],
    pub(crate) scaled: [Vec13; 128],
    pub(crate) eval: [Vec13; 128],
    pub(crate) error: [u64; 128],
    pub(crate) s_priv: [Vec13; 4],
    pub(crate) s_priv_cmp: [Vec13; 4],
    pub(crate) locator: [Vec13; 2],
    pub(crate) recv: [u64; 128],
}

impl Work {
    pub(crate) const fn new() -> Self {
        Self {
            inv: [[0; GFBITS]; 128],
            scaled: [[0; GFBITS]; 128],
            eval: [[0; GFBITS]; 128],
            error: [0; 128],
            s_priv: [[0; GFBITS]; 4],
            s_priv_cmp: [[0; GFBITS]; 4],
            locator: [[0; GFBITS]; 2],
            recv: [0; 128],
        }
    }
}

impl Zeroize for Work {
    fn zeroize(&mut self) {
        self.inv.zeroize();
        self.scaled.zeroize();
        self.eval.zeroize();
        self.error.zeroize();
        self.s_priv.zeroize();
        self.s_priv_cmp.zeroize();
        self.locator.zeroize();
        self.recv.zeroize();
    }
}

/// The decoder up to the syndrome: permutes the received word through the
/// network, scales it by `1/g^2` and takes the transposed FFT (`s_priv`).
/// `sk` is the secret key from the Goppa polynomial on (`IRR_BYTES` then
/// `COND_BYTES`), `c` the ciphertext's first `SYND_BYTES`.
#[inline(never)]
pub(crate) fn syndrome(w: &mut Work, sk: &[u8], c: &[u8]) {
    preprocess(&mut w.recv, c);
    benes(&mut w.recv, &sk[IRR_BYTES..], true);
    scaling(&mut w.scaled, &mut w.inv, sk, &w.recv);
    fft_tr(&mut w.s_priv, &mut w.scaled);
}

/// `decrypt(e, sk, c)`: decodes `c` into the weight-`SYS_T` error vector
/// `e`. Returns 0 on success, 1 on failure; `e` is then garbage, which
/// the caller masks.
#[inline(never)]
pub(crate) fn decrypt(e: &mut [u8; SYS_N / 8], sk: &[u8], c: &[u8]) -> u8 {
    let mut w = Work::new();

    // Berlekamp decoder.
    syndrome(&mut w, sk, c);
    bm(&mut w.locator, &w.s_priv);
    fft(&mut w.eval, &mut w.locator);

    // Re-encryption and weight check.
    let allone = vec::setbits(1);
    for (err, ev) in w.error.iter_mut().zip(&w.eval) {
        *err = vec::or_reduce(ev) ^ allone;
    }

    scaling_inv(&mut w.scaled, &w.inv, &w.error);
    fft_tr(&mut w.s_priv_cmp, &mut w.scaled);

    let check_synd = synd_cmp(&w.s_priv, &w.s_priv_cmp);

    benes(&mut w.error, &sk[IRR_BYTES..], false);
    postprocess(e, &w.error);

    let check_weight = weight_check(e, &w.error);

    w.zeroize();
    1u8.wrapping_sub((check_synd & check_weight) as u8)
}
