//! EL0-readable aarch64 counters. CNTPCT/CNTFRQ are exported to user level
//! by the kernel config (CONFIG_EXPORT_PCNT_USER). No RNDR: the platform
//! CPU has no FEAT_RNG, and every PD draws from the DRBG the `rng` PD seeds
//! (M7 plan C7, D3).
//! Also the stack high-water probe the McEliece PDs print (M4 plan C8).

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

/// Microkit maps every PD's stack to end here (tools/laws checks maps
/// against the same value).
const STACK_TOP: usize = 0xff_ffff_e000;
const STACK_PAINT: u8 = 0xa5;

/// The stack high-water mark (M4 plan C8): the free stack is painted once
/// at init, and `report` prints the deepest byte no longer holding the
/// paint each time it moves deeper, for the PD to print. The McEliece
/// stack scrub writes zeros, so the scrubbed depth counts as used.
/// `tests/integration` reads the lines and checks the headroom against the
/// `stack_size` in the system file.
pub struct StackProbe {
    size: usize,
    reported: usize,
}

impl StackProbe {
    /// # Safety
    /// `size` must be this PD's `stack_size`, and nothing may be live below
    /// the caller's frame (call it first thing in `init`).
    pub unsafe fn paint(size: usize) -> Self {
        let sp: usize;
        // SAFETY: reads the stack pointer only.
        unsafe { asm!("mov {}, sp", out(reg) sp, options(nomem, nostack, preserves_flags)) };
        // A margin below this frame for the calls made while painting.
        let end = sp.saturating_sub(1024);
        let mut at = STACK_TOP.saturating_sub(size);
        while at < end {
            // SAFETY: [STACK_TOP - size, end) is this PD's own mapped stack,
            // below every live frame (the caller's contract).
            unsafe { core::ptr::write_volatile(at as *mut u8, STACK_PAINT) };
            at = at.saturating_add(1);
        }
        Self { size, reported: 0 }
    }

    /// Bytes below the stack top ever used, to the word: the paint is read
    /// a word at a time up to the first word that differs. (Not to the
    /// byte: which bytes of that word still hold the paint is stack
    /// content, and would show in the printed figure.)
    pub fn high_water(&self) -> usize {
        const WORD: u64 = u64::from_ne_bytes([STACK_PAINT; 8]);
        let mut at = STACK_TOP.saturating_sub(self.size);
        // SAFETY: as in `paint`; the stack is mapped for the PD's lifetime,
        // and `at` stays 8-aligned (STACK_TOP and the stack size are).
        while at < STACK_TOP && unsafe { core::ptr::read_volatile(at as *const u64) } == WORD {
            at = at.saturating_add(8);
        }
        STACK_TOP.saturating_sub(at)
    }

    /// The high-water mark and the stack size, when the mark is deeper
    /// than last reported.
    pub fn deeper(&mut self) -> Option<(usize, usize)> {
        let mut out = None;
        self.deeper_with(|hw, size| {
            out = Some((hw, size));
            true
        });
        out
    }

    /// Offers a deeper mark to `report`, and counts it reported only if
    /// `report` returns true: a mark lost on the way (a full audit ring) is
    /// offered again next time, as `CostHighWater` does.
    pub fn deeper_with(&mut self, report: impl FnOnce(usize, usize) -> bool) {
        let hw = self.high_water();
        self.offer(hw, report);
    }

    fn offer(&mut self, hw: usize, report: impl FnOnce(usize, usize) -> bool) {
        if hw > self.reported && report(hw, self.size) {
            self.reported = hw;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lost_stack_mark_is_offered_again_and_a_delivered_one_once() {
        extern crate std;
        let mut probe = StackProbe { size: 0x20_000, reported: 0 };
        let mut offered = std::vec::Vec::new();
        probe.offer(0x1000, |hw, _| {
            offered.push(hw);
            false
        });
        probe.offer(0x1000, |hw, _| {
            offered.push(hw);
            true
        });
        probe.offer(0x1000, |hw, _| {
            offered.push(hw);
            true
        });
        probe.offer(0x1100, |hw, _| {
            offered.push(hw);
            true
        });
        assert_eq!(offered, [0x1000, 0x1000, 0x1100]);
    }

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
