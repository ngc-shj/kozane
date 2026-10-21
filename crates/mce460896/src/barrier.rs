//! The value barrier (M4 plan C7, invariant I3).
//!
//! Every mask or 1-bit operation on a secret goes through exactly one call
//! into this module. Each helper passes its result (or, for the shifts, the
//! shift amount) through [`opaque`], an `asm!` identity that the optimiser
//! cannot see through: cryptoint's `__asm__ ("" : "+r"(x))`. LLVM therefore
//! never learns that a mask is all-zero or all-one, and cannot turn the
//! branch-free code that consumes it back into a compare and a branch.
//!
//! The helpers are named after the cryptoint functions they replace;
//! `BARRIERS.md` maps every libmceliece and round-3 call site to them.
//! This is the only module of the crate that contains `unsafe` (check-pins
//! P14).

#![allow(unsafe_code)]

use core::arch::asm;

/// The identity the optimiser cannot see through.
#[inline(always)]
pub fn opaque(x: u64) -> u64 {
    let mut x = x;
    // SAFETY: the template is a comment. It reads and writes one general
    // register and touches no memory, stack or flags.
    unsafe { asm!("/* {0} */", inout(reg) x, options(pure, nomem, nostack, preserves_flags)) };
    x
}

/// 1 iff `x < y` (unsigned), from the borrow of `x - y`; no compare.
#[inline(always)]
fn borrow(x: u64, y: u64) -> u64 {
    ((!x & y) | ((!x | y) & x.wrapping_sub(y))) >> 63
}

/// All ones iff `x != 0`.
#[inline(always)]
fn nonzero(x: u64) -> u64 {
    (((x | x.wrapping_neg()) as i64) >> 63) as u64
}

/// `crypto_int64_bottombit_01`.
#[inline(always)]
pub fn u64_bottombit_01(x: u64) -> u64 {
    opaque(x & 1)
}

/// `crypto_int64_bitmod_01(x, s)`: bit `s mod 64` of `x`, as 0 or 1.
#[inline(always)]
pub fn u64_bitmod_01(x: u64, s: usize) -> u64 {
    opaque((x >> (s & 63)) & 1)
}

/// `crypto_int64_bitmod_mask(x, s)`: bit `s mod 64` of `x`, as a mask.
#[inline(always)]
pub fn u64_bitmod_mask(x: u64, s: usize) -> u64 {
    opaque((x >> (s & 63)) & 1).wrapping_neg()
}

/// `crypto_int8_bitmod_01(x, s)`: bit `s mod 8` of `x`, as 0 or 1.
#[inline(always)]
pub fn u8_bitmod_01(x: u8, s: usize) -> u16 {
    opaque((u64::from(x) >> (s & 7)) & 1) as u16
}

/// `crypto_uint64_nonzero_mask`.
#[inline(always)]
pub fn u64_nonzero_mask(x: u64) -> u64 {
    opaque(nonzero(x))
}

/// `crypto_uint64_leq_mask(x, y)`: all ones iff `x <= y`.
#[inline(always)]
pub fn u64_leq_mask(x: u64, y: u64) -> u64 {
    opaque(borrow(y, x).wrapping_sub(1))
}

/// `crypto_int64_shlmod(x, s)`: `x << (s mod 64)`, the shift amount hidden.
#[inline(always)]
pub fn u64_shlmod(x: u64, s: u64) -> u64 {
    x << (opaque(s) & 63)
}

/// `crypto_int32_shlmod(x, s)`.
#[inline(always)]
pub fn u32_shlmod(x: u32, s: u32) -> u32 {
    x << (opaque(u64::from(s)) as u32 & 31)
}

/// `crypto_int32_zero_mask`.
#[inline(always)]
pub fn u32_zero_mask(x: u32) -> u32 {
    opaque(!nonzero(u64::from(x))) as u32
}

/// `crypto_int32_bottombit_mask`.
#[inline(always)]
pub fn u32_bottombit_mask(x: u32) -> u32 {
    (opaque(u64::from(x & 1)) as u32).wrapping_neg()
}

/// `crypto_int16_zero_mask`, as 0 or 1 (`-crypto_int16_zero_mask(x)`).
#[inline(always)]
pub fn u16_zero_01(x: u16) -> u16 {
    opaque(!nonzero(u64::from(x)) & 1) as u16
}

/// `crypto_uint16_smaller_mask(x, y)`: all ones iff `x < y`.
#[inline(always)]
pub fn u16_smaller_mask(x: u16, y: u16) -> u16 {
    opaque(borrow(u64::from(x), u64::from(y)).wrapping_neg()) as u16
}

/// `crypto_uint16_equal_mask(x, y)`: all ones iff `x == y`.
#[inline(always)]
pub fn u16_equal_mask(x: u16, y: u16) -> u16 {
    opaque(!nonzero(u64::from(x ^ y))) as u16
}

/// The duplicate check's step: `acc | equal_mask(x, y)`, accumulated
/// through the barrier so that no early exit can be derived.
#[inline(always)]
pub fn u16_or_equal_mask(acc: u16, x: u16, y: u16) -> u16 {
    opaque(u64::from(acc) | !nonzero(u64::from(x ^ y))) as u16
}

/// `crypto_uint64_equal_mask(x, y)`: all ones iff `x == y`.
#[inline(always)]
pub fn u64_equal_mask(x: u64, y: u64) -> u64 {
    opaque(!nonzero(x ^ y))
}

/// `crypto_uint8_zero_mask`.
#[inline(always)]
pub fn u8_zero_mask(x: u8) -> u8 {
    opaque(!nonzero(u64::from(x))) as u8
}

/// `crypto_uint8_bottombit_01`.
#[inline(always)]
pub fn u8_bottombit_01(x: u8) -> u8 {
    opaque(u64::from(x & 1)) as u8
}

/// `crypto_uint64_zero_mask`.
#[inline(always)]
pub fn u64_zero_mask(x: u64) -> u64 {
    opaque(!nonzero(x))
}

/// `crypto_uint16_zero_mask`.
#[inline(always)]
pub fn u16_zero_mask(x: u16) -> u16 {
    opaque(!nonzero(u64::from(x))) as u16
}

/// `crypto_int16_nonzero_mask`.
#[inline(always)]
pub fn u16_nonzero_mask(x: u16) -> u16 {
    opaque(nonzero(u64::from(x))) as u16
}

/// `crypto_int8_bitmod_mask(x, s)`: bit `s mod 8` of `x`, as a mask.
#[inline(always)]
pub fn u8_bitmod_mask(x: u8, s: usize) -> u16 {
    (opaque((u64::from(x) >> (s & 7)) & 1) as u16).wrapping_neg()
}

/// `crypto_int32_bottombit_01`.
#[inline(always)]
pub fn u32_bottombit_01(x: u32) -> u32 {
    opaque(u64::from(x & 1)) as u32
}

/// `crypto_int32_min(x, y)` for non-negative `x, y < 2^31` (the values
/// the control-bit recursion compares).
#[inline(always)]
pub fn u32_min(x: u32, y: u32) -> u32 {
    let lt = opaque(borrow(u64::from(x), u64::from(y)).wrapping_neg()) as u32;
    y ^ ((x ^ y) & lt)
}

/// The C1 compare's step: `acc | x`, accumulated through the barrier so
/// that it cannot become an early-exit compare.
#[inline(always)]
pub fn u8_or(acc: u8, x: u8) -> u8 {
    opaque(u64::from(acc | x)) as u8
}

/// `(a & m) | (b & !m)` with the mask hidden: the `e`/`s` select.
#[inline(always)]
pub fn u8_select(m: u8, a: u8, b: u8) -> u8 {
    let m = opaque(u64::from(m)) as u8;
    (a & m) | (b & !m)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLES: [u64; 10] = [0, 1, 2, 63, 64, 0x7fff_ffff_ffff_ffff, 0x8000_0000_0000_0000, u64::MAX - 1, u64::MAX, 4608];

    #[test]
    fn borrow_is_unsigned_less_than() {
        for x in SAMPLES {
            for y in SAMPLES {
                assert_eq!(borrow(x, y), u64::from(x < y), "{x} < {y}");
                assert_eq!(u64_leq_mask(x, y), if x <= y { u64::MAX } else { 0 }, "{x} <= {y}");
            }
        }
    }

    #[test]
    fn masks_are_all_or_nothing() {
        for x in SAMPLES {
            assert_eq!(u64_nonzero_mask(x), if x != 0 { u64::MAX } else { 0 });
            assert_eq!(u64_equal_mask(x, 4608), if x == 4608 { u64::MAX } else { 0 });
            let h = x as u16;
            assert_eq!(u16_smaller_mask(h, 4608), if h < 4608 { 0xffff } else { 0 });
            assert_eq!(u16_equal_mask(h, 64), if h == 64 { 0xffff } else { 0 });
            assert_eq!(u16_or_equal_mask(0, h, 2), if h == 2 { 0xffff } else { 0 });
            assert_eq!(u16_zero_01(h), u16::from(h == 0));
            let b = x as u8;
            assert_eq!(u8_zero_mask(b), if b == 0 { 0xff } else { 0 });
            assert_eq!(u8_select(0xff, b, !b), b);
            assert_eq!(u8_select(0, b, !b), !b);
            assert_eq!(u32_zero_mask(x as u32), if x as u32 == 0 { u32::MAX } else { 0 });
            assert_eq!(u32_bottombit_mask(x as u32), if x & 1 == 1 { u32::MAX } else { 0 });
            assert_eq!(u64_zero_mask(x), if x == 0 { u64::MAX } else { 0 });
            assert_eq!(u16_zero_mask(h), if h == 0 { 0xffff } else { 0 });
            assert_eq!(u16_nonzero_mask(h), if h != 0 { 0xffff } else { 0 });
            assert_eq!(u32_bottombit_01(x as u32), (x & 1) as u32);
            let (a, c) = ((x as u32) >> 1, (x >> 33) as u32);
            assert_eq!(u32_min(a, c), a.min(c));
        }
    }

    #[test]
    fn bit_extraction_wraps_the_position() {
        assert_eq!(u64_bitmod_01(1 << 5, 64 + 5), 1);
        assert_eq!(u64_bitmod_mask(1 << 5, 5), u64::MAX);
        assert_eq!(u8_bitmod_01(0x80, 15), 1);
        assert_eq!(u8_bitmod_mask(0x80, 15), 0xffff);
        assert_eq!(u8_bitmod_mask(0x80, 14), 0);
        assert_eq!(u64_shlmod(1, 65), 2);
        assert_eq!(u32_shlmod(1, 33), 2);
    }
}
