//! The supervisor's decision and its record (M7 plan C8, Re-plan R1), apart
//! from seL4. Every fault a child takes ends in a whole-system reset (D4); a
//! boot stop never faults, so it never reaches here. The record is what
//! `audit` prints before the reset: which child, which fault label, and how
//! many further faults arrived before the reset (`lost`).

#![no_std]
#![forbid(unsafe_code)]
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

/// The supervisor's children, by Microkit child id (the `.system` gives
/// each its index here as `id`; `layout`'s tests check the two agree).
pub const CHILDREN: [&str; 15] = [
    "eth_out", "eth_in", "timer", "tpm", "rng", "key", "pqkey", "tlskey", "hs", "pq", "ingress", "data", "inner",
    "tls", "audit",
];

/// What the supervisor does with a fault: always a reset. The child and
/// the label are only recorded; no input changes the outcome (I8.1, I8.2:
/// no fault is ever answered, so no child resumes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Reset,
}

pub fn decide(_child: usize, _label: u64) -> Action {
    Action::Reset
}

/// The record page's three words: a sequence number (0 = no record yet),
/// then child id and fault label, then faults counted after the first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record {
    pub seq: u64,
    pub child: u32,
    pub label: u32,
    pub lost: u64,
}

pub const RECORD_WORDS: usize = 3;

impl Record {
    pub fn encode(&self) -> [u64; RECORD_WORDS] {
        [self.seq, (u64::from(self.child) << 32) | u64::from(self.label), self.lost]
    }

    pub fn decode(words: [u64; RECORD_WORDS]) -> Record {
        let [seq, packed, lost] = words;
        Record { seq, child: (packed >> 32) as u32, label: packed as u32, lost }
    }

    /// The child's name, or None for an id no child has.
    pub fn child_name(&self) -> Option<&'static str> {
        CHILDREN.get(self.child as usize).copied()
    }
}

#[cfg(test)]
mod tests;

#[cfg(kani)]
mod proofs;
