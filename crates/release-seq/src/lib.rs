//! This release's sequence number (M8 plan D5, C9): a leaf with no
//! dependencies, so raising it rebuilds only what reads it.

#![no_std]

/// Raised by one for every release; signed into the release manifest.
/// Only the `policy` PD reads it: a bundle whose `min_release` is above it
/// is refused (`BelowFloor`), so a signed older release keeps every parsing
/// PD closed once the fleet's bundle raises the floor.
pub const RELEASE_SEQ: u32 = 1;

#[cfg(test)]
mod tests;
