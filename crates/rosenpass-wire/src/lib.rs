//! Rosenpass V02 message codecs, free of any cryptography so that Kani can
//! check them without compiling libcrux (M3 plan C1).

#![no_std]
#![deny(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]
