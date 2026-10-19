//! `pqkey`'s oracle: McEliece decapsulation and the pq boot seed behind a
//! closed caller → label table (M3 plan C2).

#![no_std]
#![deny(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]
