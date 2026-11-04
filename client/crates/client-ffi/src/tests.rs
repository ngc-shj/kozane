//! What the C side cannot see: the PSK slot is wiped as it is taken, and
//! pointers that overlap each other or the handle are refused.

#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::panic)]

#[path = "../../client/tests/support/mod.rs"]
mod support;

use super::*;
use support::{Gateway, S, client_pair, gateway_pair};

fn take_one(h: &mut kz_client, buf: &mut [u8]) -> (c_int, c_int, usize) {
    take(h, buf.as_mut_ptr(), buf.len())
}

fn handle() -> Box<kz_client> {
    let (gw_pair, me) = (gateway_pair(), client_pair());
    let addr = "192.0.2.1:9999".parse().unwrap();
    new(addr, &gw_pair.public[..], [7; 32], &me.public[..], &me.secret_oqs[..]).unwrap()
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

/// `kz_client_take_action` with these pointers: (status, the queue length
/// after the call). A refusal must leave the queued scrub in place.
fn take_raw(h: &mut Box<kz_client>, buf: *mut u8, cap: usize, kind: *mut c_int, len: *mut usize) -> (c_int, usize) {
    let p: *mut kz_client = &mut **h;
    // SAFETY: `p` is a live handle and the pointers are valid for writes;
    // whether they overlap is what is under test.
    let code = unsafe { kz_client_take_action(p, buf, cap, kind, len) };
    (code, h.queued)
}

#[test]
fn take_action_refuses_kind_and_len_that_overlap() {
    let mut h = handle();
    let mut out = [0usize; 2];
    let at = out.as_mut_ptr();
    assert_eq!(take_raw(&mut h, core::ptr::null_mut(), 0, at.cast(), at), (KZ_ERR_INVALID, 1));
}

#[test]
fn take_action_refuses_a_buffer_over_kind() {
    let mut h = handle();
    let mut buf = [0u8; 64];
    let mut len = 0usize;
    let at = buf.as_mut_ptr();
    assert_eq!(take_raw(&mut h, at, buf.len(), at.cast(), &mut len), (KZ_ERR_INVALID, 1));
}

#[test]
fn take_action_refuses_a_buffer_inside_the_handle() {
    let mut h = handle();
    let (mut kind, mut len) = (0, 0);
    let inside = h.slots[1].datagram.as_mut_ptr();
    assert_eq!(take_raw(&mut h, inside, 16, &mut kind, &mut len), (KZ_ERR_INVALID, 1));
}

#[test]
fn take_action_accepts_disjoint_pointers() {
    let mut h = handle();
    let mut buf = [0u8; KZ_MAX_DATAGRAM];
    let (mut kind, mut len) = (0, 0);
    assert_eq!(take_raw(&mut h, buf.as_mut_ptr(), buf.len(), &mut kind, &mut len), (KZ_OK, 0));
    assert_eq!((kind, len), (KZ_ACTION_SCRUB, 0));
}

#[test]
fn next_deadline_refuses_an_output_inside_the_handle() {
    let mut h = handle();
    let inside: *mut u64 = &mut h.slots[1].len as *mut usize as *mut u64;
    let p: *mut kz_client = &mut *h;
    // SAFETY: `p` is a live handle; `inside` is writable, and inside it.
    assert_eq!(unsafe { kz_client_next_deadline(p, inside) }, KZ_ERR_INVALID);
}

#[test]
fn on_datagram_refuses_input_inside_the_handle() {
    let mut h = handle();
    let inside = h.slots[1].datagram.as_ptr();
    let p: *mut kz_client = &mut *h;
    // SAFETY: `p` is a live handle; `inside` is readable for 16 bytes.
    assert_eq!(unsafe { kz_client_on_datagram(p, S, inside, 16) }, KZ_ERR_INVALID);
}
