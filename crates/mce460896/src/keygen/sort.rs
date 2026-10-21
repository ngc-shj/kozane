//! Batcher's merge sorts (as in the round-2 reference's `controlbits.c`),
//! standing in for libmceliece's `crypto_sort_int32` / `crypto_sort_int64`:
//! fixed compare-exchange networks, so the schedule never depends on the
//! values. Sorting is unique, so the output equals djbsort's on the
//! non-negative keys key generation sorts.

// Indices are public positions in the network (I4).
#![allow(clippy::indexing_slicing)]
// Every `+`/`-`/`*` on a `usize` here is a public network position.
#![allow(clippy::arithmetic_side_effects)]

/// `is_smaller`: 1 iff `a < b`, for `a, b < 2^31`.
#[inline(always)]
fn is_smaller(a: u32, b: u32) -> u32 {
    a.wrapping_sub(b) >> 31
}

/// `cswap`: swaps `x[a]` and `x[b]` iff `swap` is 1.
#[inline(always)]
fn cswap(x: &mut [u32], a: usize, b: usize, swap: u32) {
    let d = (x[a] ^ x[b]) & 0u32.wrapping_sub(swap);
    x[a] ^= d;
    x[b] ^= d;
}

fn minmax(x: &mut [u32], a: usize, b: usize) {
    let m = is_smaller(x[b], x[a]);
    cswap(x, a, b, m);
}

fn minmax_63b(x: &mut [u64], a: usize, b: usize) {
    let m = x[b].wrapping_sub(x[a]) >> 63;
    let d = (x[a] ^ x[b]) & 0u64.wrapping_sub(m);
    x[a] ^= d;
    x[b] ^= d;
}

/// `merge`: merges the halves of `x[base], x[base + step], ...` (2n items).
fn merge(n: usize, x: &mut [u32], base: usize, step: usize) {
    if n == 1 {
        minmax(x, base, base + step);
    } else {
        merge(n / 2, x, base, step * 2);
        merge(n / 2, x, base + step, step * 2);
        for i in (1..2 * n - 1).step_by(2) {
            minmax(x, base + i * step, base + (i + 1) * step);
        }
    }
}

fn merge_63b(n: usize, x: &mut [u64], base: usize, step: usize) {
    if n == 1 {
        minmax_63b(x, base, base + step);
    } else {
        merge_63b(n / 2, x, base, step * 2);
        merge_63b(n / 2, x, base + step, step * 2);
        for i in (1..2 * n - 1).step_by(2) {
            minmax_63b(x, base + i * step, base + (i + 1) * step);
        }
    }
}

/// `sort`: sorts `x` (length a power of 2, values below 2^31).
pub(crate) fn sort(x: &mut [u32]) {
    let n = x.len();
    if n <= 1 {
        return;
    }
    sort(&mut x[..n / 2]);
    sort(&mut x[n / 2..]);
    merge(n / 2, x, 0, 1);
}

/// `sort_63b`: sorts `x` (length a power of 2, values below 2^63).
pub(crate) fn sort_63b(x: &mut [u64]) {
    let n = x.len();
    if n <= 1 {
        return;
    }
    sort_63b(&mut x[..n / 2]);
    sort_63b(&mut x[n / 2..]);
    merge_63b(n / 2, x, 0, 1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorts_sort() {
        let mut x: [u32; 64] = core::array::from_fn(|i| (i as u32).wrapping_mul(2_654_435_761) >> 2);
        sort(&mut x);
        assert!(x.windows(2).all(|w| w[0] <= w[1]));
        let mut y: [u64; 32] = core::array::from_fn(|i| (i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 2);
        sort_63b(&mut y);
        assert!(y.windows(2).all(|w| w[0] <= w[1]));
    }
}
