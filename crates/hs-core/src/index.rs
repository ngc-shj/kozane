//! Receiver indices (plan, Indices [F3, F8, S15]): `index = F_k(n)` for a
//! per-boot counter `n`, where `F_k` is an 8-round Feistel permutation of
//! 32-bit values keyed by `k_idx = BLAKE2s("wg-index" ‖ boot_seed)`. A
//! Feistel network is a permutation whatever its round function, so
//! indices never repeat within a boot (until `n` wraps after 2^32
//! handshakes, when `next` refuses). Unpredictability is not relied on.

use wg_core::crypto::{self, CryptoError, Key32};

pub const ROUNDS: u8 = 8;
const LABEL: &[u8] = b"wg-index";

/// Feistel over two `half_bits`-wide halves (1..=16) with round function
/// `f(round, right) -> u16` (masked to the half width).
pub fn feistel(x: u32, half_bits: u32, f: &mut impl FnMut(u8, u16) -> u16) -> u32 {
    let mask: u32 = (1u32 << half_bits).wrapping_sub(1);
    let mut l = (x >> half_bits) & mask;
    let mut r = x & mask;
    for round in 0..ROUNDS {
        let fr = u32::from(f(round, r as u16)) & mask;
        (l, r) = (r, l ^ fr);
    }
    (l << half_bits) | r
}

pub struct Indices {
    key: Key32,
    counter: u32,
    exhausted: bool,
}

impl Indices {
    pub fn new(boot_seed: &Key32) -> Result<Self, CryptoError> {
        let key = Key32::from_bytes(crypto::hash(&[LABEL, boot_seed.as_bytes()])?);
        Ok(Self { key, counter: 0, exhausted: false })
    }

    fn round(key: &Key32, round: u8, half: u16) -> u16 {
        let mut out = [0u8; 2];
        if let Ok(h) = crypto::hash(&[key.as_bytes(), &[round], &half.to_le_bytes()]) {
            out.copy_from_slice(h.get(..2).unwrap_or(&[0, 0]));
        }
        u16::from_le_bytes(out)
    }

    /// The next unused index, or None once all 2^32 have been issued.
    pub fn next_index(&mut self) -> Option<u32> {
        if self.exhausted {
            return None;
        }
        let n = self.counter;
        match self.counter.checked_add(1) {
            Some(c) => self.counter = c,
            None => self.exhausted = true,
        }
        let key = &self.key;
        Some(feistel(n, 16, &mut |round, half| Self::round(key, round, half)))
    }
}

#[cfg(test)]
impl Indices {
    pub(crate) fn set_counter_for_test(&mut self, n: u32) {
        self.counter = n;
    }
}
