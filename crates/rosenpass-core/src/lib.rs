//! Rosenpass V02 responder: hash domains, biscuits, the responder state
//! machine and OSK export (M3 plan C1).

#![no_std]
#![deny(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]
