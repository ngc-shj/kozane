//! The additive (Gao-Mateer) FFT: libmceliece `fft.c`.
//!
//! Evaluates a polynomial at every element of GF(2^13), in bitsliced form.
//! The schedule (radix conversions, then butterflies) is fixed; data only
//! meets `^`, `&`, constant shifts and [`vec::mul`].

// Indices are public loop counters over fixed-size arrays (I4).
#![allow(clippy::indexing_slicing)]
// Every `+`/`-`/`*` here is on a public loop index bounded by a constant.
#![allow(clippy::arithmetic_side_effects)]

use zeroize::Zeroize;

use crate::barrier;
use crate::consts::{FFT_CONSTS, FFT_SCALARS_2X};
use crate::params::GFBITS;
use crate::transpose::transpose_64x64;
use crate::vec::{self, Vec13};

const REVERSAL: [usize; 128] = [
    0, 64, 32, 96, 16, 80, 48, 112, 8, 72, 40, 104, 24, 88, 56, 120, 4, 68, 36, 100, 20, 84, 52, 116, 12, 76, 44, 108,
    28, 92, 60, 124, 2, 66, 34, 98, 18, 82, 50, 114, 10, 74, 42, 106, 26, 90, 58, 122, 6, 70, 38, 102, 22, 86, 54, 118,
    14, 78, 46, 110, 30, 94, 62, 126, 1, 65, 33, 97, 17, 81, 49, 113, 9, 73, 41, 105, 25, 89, 57, 121, 5, 69, 37, 101,
    21, 85, 53, 117, 13, 77, 45, 109, 29, 93, 61, 125, 3, 67, 35, 99, 19, 83, 51, 115, 11, 75, 43, 107, 27, 91, 59, 123,
    7, 71, 39, 103, 23, 87, 55, 119, 15, 79, 47, 111, 31, 95, 63, 127,
];

const BETA: [u16; 7] = [2522, 7827, 7801, 8035, 6897, 8167, 3476];

const RADIX_MASK: [[u64; 2]; 5] = [
    [0x8888888888888888, 0x4444444444444444],
    [0xC0C0C0C0C0C0C0C0, 0x3030303030303030],
    [0xF000F000F000F000, 0x0F000F000F000F00],
    [0xFF000000FF000000, 0x00FF000000FF0000],
    [0xFFFF000000000000, 0x0000FFFF00000000],
];

/// `radix_conversions`, in place.
fn radix_conversions(inp: &mut [Vec13; 2]) {
    for j in 0..=5 {
        for i in 0..GFBITS {
            inp[1][i] ^= inp[1][i] >> 32;
            inp[0][i] ^= inp[1][i] << 32;
        }

        for i in 0..GFBITS {
            for k in (j..=4).rev() {
                inp[0][i] ^= (inp[0][i] & RADIX_MASK[k][0]) >> (1 << k);
                inp[0][i] ^= (inp[0][i] & RADIX_MASK[k][1]) >> (1 << k);
                inp[1][i] ^= (inp[1][i] & RADIX_MASK[k][0]) >> (1 << k);
                inp[1][i] ^= (inp[1][i] & RADIX_MASK[k][1]) >> (1 << k);
            }
        }

        if j < 5 {
            inp[0] = vec::mul(&inp[0], &FFT_SCALARS_2X[j][0]);
            inp[1] = vec::mul(&inp[1], &FFT_SCALARS_2X[j][1]);
        }
    }
}

/// `butterflies`: the evaluation stage.
fn butterflies(out: &mut [Vec13; 128], inp: &[Vec13; 2]) {
    let mut pre = [[0u64; GFBITS]; 7];
    let mut buf = [0u64; 128];

    for (p, beta) in pre.iter_mut().zip(BETA) {
        for (j, w) in p.iter_mut().enumerate() {
            *w = barrier::u64_bitmod_mask(u64::from(beta), j);
        }
        *p = vec::mul(&inp[1], p);
    }

    for i in 0..GFBITS {
        let in0 = inp[0][i];

        buf[0] = in0;
        buf[1] = buf[0] ^ pre[0][i];
        buf[32] = in0 ^ pre[5][i];
        buf[3] = buf[1] ^ pre[1][i];
        buf[96] = buf[32] ^ pre[6][i];
        buf[97] = buf[96] ^ pre[0][i];
        buf[2] = in0 ^ pre[1][i];
        buf[99] = buf[97] ^ pre[1][i];
        buf[6] = buf[2] ^ pre[2][i];
        buf[98] = buf[99] ^ pre[0][i];
        buf[7] = buf[6] ^ pre[0][i];
        buf[102] = buf[98] ^ pre[2][i];
        buf[5] = buf[7] ^ pre[1][i];
        buf[103] = buf[102] ^ pre[0][i];
        buf[101] = buf[103] ^ pre[1][i];
        buf[4] = in0 ^ pre[2][i];
        buf[100] = buf[101] ^ pre[0][i];
        buf[12] = buf[4] ^ pre[3][i];
        buf[108] = buf[100] ^ pre[3][i];
        buf[13] = buf[12] ^ pre[0][i];
        buf[109] = buf[108] ^ pre[0][i];
        buf[15] = buf[13] ^ pre[1][i];
        buf[111] = buf[109] ^ pre[1][i];
        buf[14] = buf[15] ^ pre[0][i];
        buf[110] = buf[111] ^ pre[0][i];
        buf[10] = buf[14] ^ pre[2][i];
        buf[106] = buf[110] ^ pre[2][i];
        buf[11] = buf[10] ^ pre[0][i];
        buf[107] = buf[106] ^ pre[0][i];
        buf[9] = buf[11] ^ pre[1][i];
        buf[105] = buf[107] ^ pre[1][i];
        buf[104] = buf[105] ^ pre[0][i];
        buf[8] = in0 ^ pre[3][i];
        buf[120] = buf[104] ^ pre[4][i];
        buf[24] = buf[8] ^ pre[4][i];
        buf[121] = buf[120] ^ pre[0][i];
        buf[25] = buf[24] ^ pre[0][i];
        buf[123] = buf[121] ^ pre[1][i];
        buf[27] = buf[25] ^ pre[1][i];
        buf[122] = buf[123] ^ pre[0][i];
        buf[26] = buf[27] ^ pre[0][i];
        buf[126] = buf[122] ^ pre[2][i];
        buf[30] = buf[26] ^ pre[2][i];
        buf[127] = buf[126] ^ pre[0][i];
        buf[31] = buf[30] ^ pre[0][i];
        buf[125] = buf[127] ^ pre[1][i];
        buf[29] = buf[31] ^ pre[1][i];
        buf[124] = buf[125] ^ pre[0][i];
        buf[28] = buf[29] ^ pre[0][i];
        buf[116] = buf[124] ^ pre[3][i];
        buf[20] = buf[28] ^ pre[3][i];
        buf[117] = buf[116] ^ pre[0][i];
        buf[21] = buf[20] ^ pre[0][i];
        buf[119] = buf[117] ^ pre[1][i];
        buf[23] = buf[21] ^ pre[1][i];
        buf[118] = buf[119] ^ pre[0][i];
        buf[22] = buf[23] ^ pre[0][i];
        buf[114] = buf[118] ^ pre[2][i];
        buf[18] = buf[22] ^ pre[2][i];
        buf[115] = buf[114] ^ pre[0][i];
        buf[19] = buf[18] ^ pre[0][i];
        buf[113] = buf[115] ^ pre[1][i];
        buf[17] = buf[19] ^ pre[1][i];
        buf[112] = buf[113] ^ pre[0][i];
        buf[80] = buf[112] ^ pre[5][i];
        buf[16] = in0 ^ pre[4][i];
        buf[81] = buf[80] ^ pre[0][i];
        buf[48] = buf[16] ^ pre[5][i];
        buf[83] = buf[81] ^ pre[1][i];
        buf[49] = buf[48] ^ pre[0][i];
        buf[82] = buf[83] ^ pre[0][i];
        buf[51] = buf[49] ^ pre[1][i];
        buf[86] = buf[82] ^ pre[2][i];
        buf[50] = buf[51] ^ pre[0][i];
        buf[87] = buf[86] ^ pre[0][i];
        buf[54] = buf[50] ^ pre[2][i];
        buf[85] = buf[87] ^ pre[1][i];
        buf[55] = buf[54] ^ pre[0][i];
        buf[84] = buf[85] ^ pre[0][i];
        buf[53] = buf[55] ^ pre[1][i];
        buf[92] = buf[84] ^ pre[3][i];
        buf[52] = buf[53] ^ pre[0][i];
        buf[93] = buf[92] ^ pre[0][i];
        buf[60] = buf[52] ^ pre[3][i];
        buf[95] = buf[93] ^ pre[1][i];
        buf[61] = buf[60] ^ pre[0][i];
        buf[94] = buf[95] ^ pre[0][i];
        buf[63] = buf[61] ^ pre[1][i];
        buf[90] = buf[94] ^ pre[2][i];
        buf[62] = buf[63] ^ pre[0][i];
        buf[91] = buf[90] ^ pre[0][i];
        buf[58] = buf[62] ^ pre[2][i];
        buf[89] = buf[91] ^ pre[1][i];
        buf[59] = buf[58] ^ pre[0][i];
        buf[88] = buf[89] ^ pre[0][i];
        buf[57] = buf[59] ^ pre[1][i];
        buf[72] = buf[88] ^ pre[4][i];
        buf[56] = buf[57] ^ pre[0][i];
        buf[73] = buf[72] ^ pre[0][i];
        buf[40] = buf[56] ^ pre[4][i];
        buf[75] = buf[73] ^ pre[1][i];
        buf[41] = buf[40] ^ pre[0][i];
        buf[74] = buf[75] ^ pre[0][i];
        buf[43] = buf[41] ^ pre[1][i];
        buf[78] = buf[74] ^ pre[2][i];
        buf[42] = buf[43] ^ pre[0][i];
        buf[79] = buf[78] ^ pre[0][i];
        buf[46] = buf[42] ^ pre[2][i];
        buf[77] = buf[79] ^ pre[1][i];
        buf[47] = buf[46] ^ pre[0][i];
        buf[76] = buf[77] ^ pre[0][i];
        buf[45] = buf[47] ^ pre[1][i];
        buf[68] = buf[76] ^ pre[3][i];
        buf[44] = buf[45] ^ pre[0][i];
        buf[69] = buf[68] ^ pre[0][i];
        buf[36] = buf[44] ^ pre[3][i];
        buf[71] = buf[69] ^ pre[1][i];
        buf[37] = buf[36] ^ pre[0][i];
        buf[70] = buf[71] ^ pre[0][i];
        buf[39] = buf[37] ^ pre[1][i];
        buf[66] = buf[70] ^ pre[2][i];
        buf[38] = buf[39] ^ pre[0][i];
        buf[67] = buf[66] ^ pre[0][i];
        buf[34] = buf[38] ^ pre[2][i];
        buf[65] = buf[67] ^ pre[1][i];
        buf[35] = buf[34] ^ pre[0][i];
        buf[33] = buf[35] ^ pre[1][i];
        buf[64] = in0 ^ pre[6][i];

        for half in buf.as_chunks_mut::<64>().0 {
            transpose_64x64(half);
        }

        for (j, w) in buf.iter().enumerate() {
            out[REVERSAL[j]][i] = *w;
        }
    }

    let mut consts_ptr = 2;
    for i in 1..=6 {
        let s = 1 << i;
        for j in (0..128).step_by(2 * s) {
            for k in j..j + s {
                let mut tmp = vec::mul(&out[k + s], &FFT_CONSTS[consts_ptr + (k - j)]);
                for b in 0..GFBITS {
                    out[k][b] ^= tmp[b];
                }
                for b in 0..GFBITS {
                    out[k + s][b] ^= out[k][b];
                }
                tmp.zeroize();
            }
        }
        consts_ptr += 1 << i;
    }

    pre.zeroize();
    buf.zeroize();
}

/// `fft(out, in)`: evaluates the polynomial `inp` (128 bitsliced
/// coefficients, consumed) at every field element.
#[inline(never)]
pub(crate) fn fft(out: &mut [Vec13; 128], inp: &mut [Vec13; 2]) {
    radix_conversions(inp);
    butterflies(out, inp);
}
