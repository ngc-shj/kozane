//! A write-once record log (M8 plan C10): the audit source of an untainted
//! producer, `policy`. A ring's consumer writes its read index into the
//! shared page, which would carry data from the tainted `audit` into the
//! producer (L1); this page `audit` maps read-only instead. The producer
//! appends at most `SLOTS` records, each before the count that publishes
//! it, and never reuses a slot; `audit` keeps how far it printed itself.
//! Enough for a producer with a bounded number of records per boot.
//!
//! Layout, in 64-bit words: the count of records written, then two words
//! per record. Every bit pattern is valid: `audit` clamps the count.

/// Records one log holds.
pub const SLOTS: usize = 8;
/// Words of one log: the count, then two per record.
pub const WORDS: usize = 1 + 2 * SLOTS;

/// A record's two words: `code`, `_reserved` and `a` in the first, `b` in
/// the second.
pub const fn encode(r: crate::Record) -> [u64; 2] {
    [(r.code as u64) | ((r._reserved as u64) << 16) | ((r.a as u64) << 32), r.b as u64]
}

pub const fn decode(w: [u64; 2]) -> crate::Record {
    crate::Record { code: w[0] as u16, _reserved: (w[0] >> 16) as u16, a: (w[0] >> 32) as u32, b: w[1] as u32 }
}

/// The word index of slot `i`'s first word (`i < SLOTS`).
pub const fn slot_word(i: usize) -> usize {
    i.wrapping_mul(2).wrapping_add(1)
}

/// The producer's side: where the next record goes.
#[derive(Default)]
pub struct Writer {
    next: usize,
}

impl Writer {
    pub const fn new() -> Self {
        Self { next: 0 }
    }

    /// Writes `r` into the next slot through `write(word, value)`, then the
    /// new count into word 0, which publishes it. False, writing nothing,
    /// once every slot is used.
    pub fn push(&mut self, r: crate::Record, mut write: impl FnMut(usize, u64)) -> bool {
        if self.next >= SLOTS {
            return false;
        }
        let [w0, w1] = encode(r);
        let at = slot_word(self.next);
        write(at, w0);
        write(at.saturating_add(1), w1);
        self.next = self.next.saturating_add(1);
        write(0, self.next as u64);
        true
    }
}

/// The slots `audit` has yet to print: from `printed` up to the published
/// `count`, clamped to `SLOTS`, whatever the page holds.
pub fn pending(count: u64, printed: usize) -> core::ops::Range<usize> {
    let end = usize::try_from(count).map_or(SLOTS, |c| c.min(SLOTS));
    printed.min(end)..end
}
