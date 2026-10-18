#![no_std]
#![no_main]

use sel4_microkit::{Handler, Infallible, debug_println, protection_domain};

#[protection_domain]
fn init() -> HandlerImpl {
    debug_println!("secureos: hello PD up");
    HandlerImpl
}

struct HandlerImpl;

impl Handler for HandlerImpl {
    type Error = Infallible;
}
