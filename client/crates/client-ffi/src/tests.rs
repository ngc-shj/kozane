//! What the C side cannot see: the PSK slot is wiped as it is taken.

#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::panic)]

#[path = "../../client/tests/support/mod.rs"]
mod support;

use super::*;
use support::{Gateway, S, client_pair, gateway_pair};

fn take_one(h: &mut kz_client, buf: &mut [u8]) -> (c_int, c_int, usize) {
    let (mut kind, mut len) = (0, 0);
    let code = take(h, buf.as_mut_ptr(), buf.len(), &mut kind, &mut len);
    (code, kind, len)
}

#[test]
fn the_psk_slot_is_wiped_as_the_psk_is_taken() {
    let (gw_pair, me) = (gateway_pair(), client_pair());
    let addr = "192.0.2.1:9999".parse().unwrap();
    let mut h = new(addr, &gw_pair.public[..], [7; 32], &me.public[..], &me.secret_oqs[..]).unwrap();
    let mut buf = [0u8; KZ_MAX_DATAGRAM];
    assert_eq!(take_one(&mut h, &mut buf), (KZ_OK, KZ_ACTION_SCRUB, 0));
    assert_eq!(h.process(|c| c.on_timer(S)), KZ_OK);
    let (_, _, len) = take_one(&mut h, &mut buf);
    let mut gw = Gateway::new(0);
    let rh = gw.respond(&buf[..len], S);
    assert_eq!(h.process(|c| c.on_datagram(S, &rh)), KZ_OK);

    let slot = h.head;
    assert!(!h.slots[slot].psk.is_zero());
    assert_eq!(take_one(&mut h, &mut buf), (KZ_OK, KZ_ACTION_INSTALL_PSK, KZ_PSK_LEN));
    assert!(h.slots[slot].psk.is_zero(), "ffi: psk slot not wiped on take");
    assert_eq!(take_one(&mut h, &mut buf).1, KZ_ACTION_SEND);
    assert!(h.slots.iter().all(|s| s.psk.is_zero()));
}
