//! GF(2^13) arithmetic on plain elements: libmceliece `gf.c` and
//! `gf_2m_mul.c`. Only key generation uses it; decapsulation and
//! encapsulation work on bitsliced vectors ([`crate::vec`]).

use crate::barrier;
use crate::params::{GFBITS, GFMASK};

pub(crate) type Gf = u16;

/// `gf_iszero`: `GFMASK` iff `a == 0`.
#[inline(always)]
pub(crate) fn iszero(a: Gf) -> Gf {
    barrier::u32_zero_mask(u32::from(a)) as Gf & GFMASK
}

/// `gf_mul`.
#[inline(never)]
pub(crate) fn mul(in0: Gf, in1: Gf) -> Gf {
    let mut t0 = u32::from(in0);
    let mut t1 = u32::from(in1);

    let mut tmp = t0 & barrier::u32_bottombit_mask(t1);
    for _ in 1..GFBITS {
        t0 <<= 1;
        t1 >>= 1;
        tmp ^= t0 & barrier::u32_bottombit_mask(t1);
    }

    let t = tmp & 0x1FF0000;
    tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);

    let t = tmp & 0x000E000;
    tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);

    (tmp as Gf) & GFMASK
}

/// `gf_sq`.
fn sq(inp: Gf) -> Gf {
    const B: [u32; 4] = [0x55555555, 0x33333333, 0x0F0F0F0F, 0x00FF00FF];

    let mut x = u32::from(inp);
    x = (x | barrier::u32_shlmod(x, 8)) & B[3];
    x = (x | barrier::u32_shlmod(x, 4)) & B[2];
    x = (x | barrier::u32_shlmod(x, 2)) & B[1];
    x = (x | barrier::u32_shlmod(x, 1)) & B[0];

    let t = x & 0xFF80000;
    x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);

    let t = x & 0x007E000;
    x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);

    (x as Gf) & GFMASK
}

/// `gf_sq2`: two squarings.
fn sq2(inp: Gf) -> Gf {
    const B: [u64; 4] = [0x1111111111111111, 0x0303030303030303, 0x000F000F000F000F, 0x000000FF000000FF];
    const M: [u64; 4] = [0x0001FF0000000000, 0x000000FF80000000, 0x000000007FC00000, 0x00000000003FE000];

    let mut x = u64::from(inp);
    x = (x | barrier::u64_shlmod(x, 24)) & B[3];
    x = (x | barrier::u64_shlmod(x, 12)) & B[2];
    x = (x | barrier::u64_shlmod(x, 6)) & B[1];
    x = (x | barrier::u64_shlmod(x, 3)) & B[0];

    for m in M {
        let t = x & m;
        x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
    }

    (x as Gf) & GFMASK
}

/// `gf_inv`: `den^(2^13 - 2)`.
#[inline(never)]
pub(crate) fn inv(den: Gf) -> Gf {
    let tmp_11 = mul(sq(den), den); // ^11
    let tmp_1111 = mul(sq2(tmp_11), tmp_11); // ^1111
    let mut out = sq2(tmp_1111);
    out = mul(sq2(out), tmp_1111); // ^11111111
    out = sq2(out);
    out = mul(sq2(out), tmp_1111); // ^111111111111
    sq(out) // ^1111111111110
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inverse_times_element_is_one() {
        for a in [1u16, 2, 3, 0x1000, 0x1fff, 4607, 1234] {
            assert_eq!(mul(a, inv(a)), 1, "{a}");
        }
        assert_eq!(inv(0), 0);
        assert_eq!(iszero(0), GFMASK);
        assert_eq!(iszero(5), 0);
    }
}
