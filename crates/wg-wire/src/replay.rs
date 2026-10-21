//! Sliding-window replay protection for transport counters (RFC 6479 idea,
//! semantics of Linux `drivers/net/wireguard/receive.c:counter_validate`).
//!
//! The window is exact: a counter is accepted iff it is below
//! `REJECT_AFTER_MESSAGES`, not seen before, and no more than `WINDOW` below
//! the highest accepted counter. Linux keeps one redundant word so that it
//! can clear whole words (window = bits - 64); this version keeps one flag
//! per slot and clears slot by slot, so the window is `BITS - 1`.

use crate::REJECT_AFTER_MESSAGES;
use vstd::prelude::*;

verus! {

/// Whether a counter `c` (plus one) lies more than `window` below `top`:
/// the saturating sum never wraps, so this is the comparison over the
/// integers.
#[inline]
fn below_window(c: u64, window: u64, top: u64) -> (r: bool)
    ensures
        r == (c + window < top),
{
    c.saturating_add(window) < top
}

} // verus!

pub struct ReplayWindow<const BITS: usize> {
    /// Highest accepted counter plus one; 0 before the first accept.
    top: u64,
    seen: [bool; BITS],
}

impl<const BITS: usize> Default for ReplayWindow<BITS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const BITS: usize> ReplayWindow<BITS> {
    /// How far below the highest accepted counter a counter may still be accepted.
    pub const WINDOW: u64 = (BITS as u64).saturating_sub(1);

    pub const fn new() -> Self {
        const { assert!(BITS >= 2, "replay window needs at least two slots") };
        Self { top: 0, seen: [false; BITS] }
    }

    /// Accepts `counter` once. Call only after the packet authenticated.
    pub fn check_and_update(&mut self, counter: u64) -> bool {
        if counter >= REJECT_AFTER_MESSAGES {
            return false;
        }
        let Some(c) = counter.checked_add(1) else {
            return false;
        };
        if below_window(c, Self::WINDOW, self.top) {
            return false;
        }
        if c > self.top {
            // Slots between the old and new top hold counters at least BITS
            // older than `c`, i.e. outside the window: forget them.
            let steps = c.saturating_sub(self.top).min(BITS as u64);
            for i in 1..=steps {
                if let Some(flag) = self.slot(self.top.wrapping_add(i)) {
                    *flag = false;
                }
            }
            self.top = c;
        }
        match self.slot(c) {
            Some(flag) if !*flag => {
                *flag = true;
                true
            }
            _ => false,
        }
    }

    fn slot(&mut self, c: u64) -> Option<&mut bool> {
        let i = usize::try_from(c.checked_rem(BITS as u64)?).ok()?;
        self.seen.get_mut(i)
    }
}
