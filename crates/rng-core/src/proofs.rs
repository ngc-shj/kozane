#![allow(clippy::indexing_slicing)]

//! I6.1, I6.4 over any device behaviour: a served seed is exactly a full,
//! non-zero device block; anything else leaves the output zeroed.

use super::*;

struct AnyDevice;

impl Device for AnyDevice {
    fn draw(&mut self, out: &mut [u8; SEED_LEN]) -> Result<usize, DeviceError> {
        if kani::any() {
            return Err(DeviceError);
        }
        *out = kani::any();
        Ok(kani::any())
    }
}

#[kani::proof]
fn a_seed_is_a_full_nonzero_block_or_nothing() {
    let mut s = Server::new();
    let mut out = Secret::<SEED_LEN>::from_bytes(kani::any());
    let caller: u8 = kani::any();
    kani::assume(caller < CALLERS as u8);
    let caller = [Caller::Hs, Caller::Pq, Caller::Ingress, Caller::Tls, Caller::Key, Caller::Pqkey, Caller::Tlskey]
        [caller as usize];
    let r = s.seed(caller, kani::any(), &mut AnyDevice, &mut out);
    match r {
        Ok(()) => assert!(!out.is_zero()),
        Err(_) => assert!(out.is_zero()),
    }
    kani::cover!(r.is_ok());
    kani::cover!(r == Err(Unavailable::Short));
}
