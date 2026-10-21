//! 64x64 bit-matrix transposition: libmceliece `transpose.h`.

// Indices are public loop counters over fixed-size arrays (I4).
#![allow(clippy::indexing_slicing)]
// Every `+`/`*` here is on a public loop index bounded by a constant.
#![allow(clippy::arithmetic_side_effects)]

const MASKS: [[u64; 2]; 6] = [
    [0x5555555555555555, 0xAAAAAAAAAAAAAAAA],
    [0x3333333333333333, 0xCCCCCCCCCCCCCCCC],
    [0x0F0F0F0F0F0F0F0F, 0xF0F0F0F0F0F0F0F0],
    [0x00FF00FF00FF00FF, 0xFF00FF00FF00FF00],
    [0x0000FFFF0000FFFF, 0xFFFF0000FFFF0000],
    [0x00000000FFFFFFFF, 0xFFFFFFFF00000000],
];

/// `transpose_64x64`, in place (libmceliece calls it with `out == in`
/// wherever the input is not needed again).
#[inline(never)]
pub fn transpose_64x64(out: &mut [u64; 64]) {
    for d in (0..6).rev() {
        let s = 1usize << d;
        for i in (0..64).step_by(s * 2) {
            for j in i..i + s {
                let x = (out[j] & MASKS[d][0]) | ((out[j + s] & MASKS[d][0]) << s);
                let y = ((out[j] & MASKS[d][1]) >> s) | (out[j + s] & MASKS[d][1]);
                out[j] = x;
                out[j + s] = y;
            }
        }
    }
}
