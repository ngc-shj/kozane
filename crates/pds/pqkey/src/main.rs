//! Placeholder; filled by the M3a wiring batch (plan C2).

#![no_std]
#![no_main]

use sel4_microkit::{Handler, Infallible, debug_println, protection_domain};

struct Pd;

impl Handler for Pd {
    type Error = Infallible;
}

#[protection_domain]
fn init() -> Pd {
    debug_println!("pqkey: placeholder");
    Pd
}
