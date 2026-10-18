//! EL0-readable aarch64 counters and the RNDR random number register.
//! CNTPCT/CNTFRQ are exported to user level by the kernel config
//! (CONFIG_EXPORT_PCNT_USER); RNDR needs FEAT_RNG (plan VE8, L9).

#![no_std]

use core::arch::asm;

/// Physical counter ticks (monotonic, shared by all PDs).
pub fn cntpct() -> u64 {
    let v: u64;
    // SAFETY: reads a system register exported to EL0; no memory access.
    unsafe { asm!("isb", "mrs {}, cntpct_el0", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// Counter frequency in Hz.
pub fn cntfrq() -> u64 {
    let v: u64;
    // SAFETY: as in `cntpct`.
    unsafe { asm!("mrs {}, cntfrq_el0", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// Converts counter ticks to nanoseconds; 0 if the frequency is unset.
pub fn ticks_to_ns(ticks: u64, freq: u64) -> u64 {
    if freq == 0 {
        return 0;
    }
    let ns = u128::from(ticks).saturating_mul(1_000_000_000) / u128::from(freq);
    u64::try_from(ns).unwrap_or(u64::MAX)
}

/// The counter frequency, or None if firmware left it unset: with 0 every
/// timestamp reads 0 and nothing would ever expire, so callers halt.
pub fn checked_frequency(freq: u64) -> Option<u64> {
    (freq != 0).then_some(freq)
}

pub fn now_ns() -> u64 {
    ticks_to_ns(cntpct(), cntfrq())
}

/// Attempts per `rndr` call before giving up; RNDR reports transient
/// failure by setting Z, and a hardware source that keeps failing must
/// make the caller fail closed rather than spin.
pub const RNDR_RETRIES: usize = 32;

/// One 64-bit sample from RNDR, or None if the hardware kept failing.
pub fn rndr() -> Option<u64> {
    for _ in 0..RNDR_RETRIES {
        let (v, ok): (u64, u64);
        // SAFETY: reads RNDR (s3_3_c2_c4_0), which sets NZCV.Z = 1 on
        // failure; `cset` captures that. No memory access.
        unsafe { asm!("mrs {v}, s3_3_c2_c4_0", "cset {ok}, ne", v = out(reg) v, ok = out(reg) ok, options(nomem, nostack)) };
        if ok == 1 {
            return Some(v);
        }
    }
    None
}

/// Fills `out` from RNDR; false (with `out` zeroed) if any sample failed.
pub fn fill_random(out: &mut [u8]) -> bool {
    for chunk in out.chunks_mut(8) {
        let Some(v) = rndr() else {
            out.fill(0);
            return false;
        };
        let bytes = v.to_le_bytes();
        chunk.copy_from_slice(bytes.get(..chunk.len()).unwrap_or(&[]));
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticks_to_ns_is_exact_at_one_gigahertz() {
        assert_eq!(ticks_to_ns(123_456_789, 1_000_000_000), 123_456_789);
    }

    #[test]
    fn ticks_to_ns_scales_the_qemu_counter() {
        // QEMU virt: 62.5 MHz, 16 ns per tick.
        assert_eq!(ticks_to_ns(62_500_000, 62_500_000), 1_000_000_000);
        assert_eq!(ticks_to_ns(1, 62_500_000), 16);
    }

    #[test]
    fn ticks_to_ns_without_a_frequency_is_zero() {
        assert_eq!(ticks_to_ns(42, 0), 0);
    }

    #[test]
    fn unset_frequency_is_refused_and_qemus_accepted() {
        assert_eq!(checked_frequency(0), None);
        assert_eq!(checked_frequency(62_500_000), Some(62_500_000));
    }

    #[test]
    fn ticks_to_ns_saturates_instead_of_wrapping() {
        assert_eq!(ticks_to_ns(u64::MAX, 1), u64::MAX);
    }
}
