//! Niederreiter encryption: the error-vector sampler and the syndrome.
//!
//! `syndrome` is libmceliece `encrypt.c`. The sampler is not libmceliece's
//! `gen_e`, which rejects with declassified branches and sorts: it is the
//! round-3 `gen_e` of the reference liboqs 0.8 vendors (PQClean
//! `mceliece460896_vec/encrypt.c`), which the peers run, rewritten without
//! branches or secret addresses. Given the same bytes it accepts exactly
//! when liboqs accepts and then yields the same `e` (M4 plan C7, S-N3).

// Indices are public loop counters over fixed-size arrays (I4).
#![allow(clippy::indexing_slicing)]

use zeroize::Zeroize;

use crate::barrier;
use crate::params::{PK_NCOLS, PK_NROWS, PK_ROW_BYTES, SYND_BYTES, SYS_N, SYS_T};
use crate::util::{load_gf, load4, load8, store8};

/// Bytes one sampling attempt consumes: `SYS_T * 2` little-endian `u16`
/// candidates, as liboqs's one `randombytes` call per attempt.
pub const RAND_LEN: usize = SYS_T * 2 * 2;

/// The sampler's secret state, kept together for one wipe.
pub(crate) struct Sample {
    /// The candidates, `load_gf` of the random bytes.
    pub(crate) nums: [u16; SYS_T * 2],
    /// The first `SYS_T` candidates below `SYS_N`, in order (`ind32`).
    pub(crate) ind: [u16; SYS_T],
    /// `e` as 64-bit words (`e_int`).
    pub(crate) e_int: [u64; SYS_N / 64],
}

impl Sample {
    pub(crate) const fn new() -> Self {
        Self { nums: [0; SYS_T * 2], ind: [0; SYS_T], e_int: [0; SYS_N / 64] }
    }
}

impl Zeroize for Sample {
    fn zeroize(&mut self) {
        self.nums.zeroize();
        self.ind.zeroize();
        self.e_int.zeroize();
    }
}

/// One attempt of round-3 `gen_e`: writes `e` (bytes) and returns the
/// accept mask (all ones iff liboqs would accept these bytes).
///
/// - filter: `ind[i] < SYS_N`, a barrier mask per candidate;
/// - compaction: candidate `i` is OR-ed into slot `k` under the mask
///   `valid & (count == k)`, for every `k`, so the slot written is never an
///   address; `count` keeps counting past `SYS_T`, and later candidates
///   match no slot (liboqs keeps the first `SYS_T`);
/// - `count < SYS_T` and the duplicate check (every pair, OR-accumulated
///   through the barrier) only feed the returned mask.
#[inline(never)]
pub(crate) fn gen_e(st: &mut Sample, e: &mut [u8; SYS_N / 8], rand: &[u8; RAND_LEN]) -> u16 {
    for (n, c) in st.nums.iter_mut().zip(rand.as_chunks::<2>().0) {
        *n = load_gf(c);
    }

    st.ind = [0; SYS_T];
    let mut count: u16 = 0;
    for &n in &st.nums {
        let valid = barrier::u16_smaller_mask(n, SYS_N as u16);
        for (k, slot) in st.ind.iter_mut().enumerate() {
            *slot |= n & valid & barrier::u16_equal_mask(count, k as u16);
        }
        count = count.wrapping_add(valid & 1);
    }
    let short = barrier::u16_smaller_mask(count, SYS_T as u16);

    let mut dup: u16 = 0;
    for (i, &a) in st.ind.iter().enumerate().skip(1) {
        for &b in &st.ind[..i] {
            dup = barrier::u16_or_equal_mask(dup, a, b);
        }
    }

    for (i, w) in st.e_int.iter_mut().enumerate() {
        *w = 0;
        for &j in &st.ind {
            let bit = barrier::u64_shlmod(1, u64::from(j));
            *w |= bit & barrier::u64_equal_mask(i as u64, u64::from(j >> 6));
        }
    }
    for (c, w) in e.as_chunks_mut::<8>().0.iter_mut().zip(&st.e_int) {
        store8(c, *w);
    }

    let accept = barrier::u16_equal_mask(short | dup, 0);
    count.zeroize();
    dup.zeroize();
    accept
}

/// `syndrome(s, pk, e)`: `s = H e` for the systematic `H = (I | T)`, `pk`
/// holding `T` row by row.
#[inline(never)]
pub(crate) fn syndrome(s: &mut [u8; SYND_BYTES], pk: &[u8], e: &[u8; SYS_N / 8]) {
    let mut eword = [0u64; PK_NCOLS / 64];
    let e_ptr = &e[SYND_BYTES..];

    s.copy_from_slice(&e[..SYND_BYTES]);

    for (w, c) in eword.iter_mut().zip(e_ptr.as_chunks::<8>().0) {
        *w = load8(c);
    }
    let e_tail = load4(&e_ptr[(PK_NCOLS / 64) * 8..]);

    for (i, row) in pk.as_chunks::<PK_ROW_BYTES>().0.iter().take(PK_NROWS).enumerate() {
        let mut b = 0u64;
        for (w, c) in eword.iter().zip(row.as_chunks::<8>().0) {
            b ^= load8(c) & w;
        }
        b ^= u64::from(load4(&row[(PK_NCOLS / 64) * 8..]) & e_tail);

        b ^= b >> 32;
        b ^= b >> 16;
        b ^= b >> 8;
        b ^= b >> 4;
        b ^= b >> 2;
        b ^= b >> 1;
        b = barrier::u64_bottombit_01(b);

        s[i / 8] ^= (b << (i % 8)) as u8;
    }

    eword.zeroize();
}
