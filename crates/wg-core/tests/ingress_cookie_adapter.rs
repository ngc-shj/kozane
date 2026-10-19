//! The ingress PD's cookie adapter (crates/pds/ingress/src/cookie.rs), built
//! on the host (plan C1 deny/allow through the real adapter). The PD crate
//! itself only builds for seL4, so its seL4-free module is included here by
//! path, as an integration test of wg-core.

#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::panic)]

#[path = "../../pds/ingress/src/cookie.rs"]
mod cookie;

use cookie::CookieAdapter;
use ingress_core::{CookieCrypto, Endpoint};
use wg_core::cookie::{CookieSecret, cookie_key, make_cookie, reply_nonce, seal_cookie_reply};
use wg_core::crypto;
use wg_core::wire::{COOKIE_REPLY_LEN, INITIATION_LEN, INITIATION_MAC2_OFFSET, MessageInitiation};

const GW_PUBLIC: [u8; 32] = [9; 32];
const SECRET: [u8; 32] = [0x5a; 32];
const SRC: Endpoint = Endpoint { ip: [10, 0, 2, 2], port: 51820 };

fn fill_ok(b: &mut [u8]) -> bool {
    b.copy_from_slice(&SECRET);
    true
}

fn fill_fail(b: &mut [u8]) -> bool {
    b.fill(0);
    false
}

thread_local! {
    static FILL_WORKS: core::cell::Cell<bool> = const { core::cell::Cell::new(true) };
}

/// Succeeds while this thread's FILL_WORKS holds (tests run on separate threads).
fn fill_switchable(b: &mut [u8]) -> bool {
    if FILL_WORKS.get() { fill_ok(b) } else { fill_fail(b) }
}

fn adapter(fill: fn(&mut [u8]) -> bool) -> CookieAdapter {
    CookieAdapter::new(&GW_PUBLIC, fill).unwrap()
}

/// A parseable initiation (type 1, sender 0x04030201) with `mac2` appended.
fn initiation(mac2: [u8; 16]) -> [u8; INITIATION_LEN] {
    let mut m: [u8; INITIATION_LEN] = core::array::from_fn(|i| (3 * i) as u8);
    m[..8].copy_from_slice(&[1, 0, 0, 0, 1, 2, 3, 4]);
    m[INITIATION_MAC2_OFFSET..].copy_from_slice(&mac2);
    m
}

/// mac2 for `src` under the cookie a 32-byte secret `secret` gives.
fn mac2_under(secret: &[u8; 32], src: Endpoint) -> [u8; 16] {
    let cookie = crypto::mac(secret, &[&src.ip, &src.port.to_be_bytes()]).unwrap();
    crypto::mac16(&cookie, &[&initiation([0; 16])[..INITIATION_MAC2_OFFSET]]).unwrap()
}

fn assert_denies(a: &mut CookieAdapter, what: &str) {
    assert!(!a.mac2_valid(SRC, &initiation(mac2_under(&[0; 32], SRC))), "{what}: zero-key mac2 accepted");
    assert!(!a.mac2_valid(SRC, &initiation(mac2_under(&SECRET, SRC))), "{what}: stale-secret mac2 accepted");
    let mut out = [0u8; COOKIE_REPLY_LEN];
    assert!(!a.seal_reply(SRC, &initiation([0; 16]), &mut out), "{what}: reply sealed");
}

/// The reply wg-core's primitives give for counter `counter` under SECRET.
fn expected_reply(counter: u64, m: &[u8; INITIATION_LEN]) -> [u8; COOKIE_REPLY_LEN] {
    let mut s = CookieSecret::new();
    assert!(s.fill(|b| fill_ok(b)));
    let init = MessageInitiation::parse(m).unwrap();
    let nonce = reply_nonce(&s, counter).unwrap();
    let c = make_cookie(&s, SRC.ip, SRC.port).unwrap();
    seal_cookie_reply(&cookie_key(&GW_PUBLIC).unwrap(), init.sender, &nonce, &c, &init.mac1).unwrap()
}

#[test]
fn unfilled_adapter_denies() {
    assert_denies(&mut adapter(fill_ok), "unfilled");
}

#[test]
fn failed_fill_denies() {
    let mut a = adapter(fill_fail);
    assert!(!a.rotate());
    assert_denies(&mut a, "failed fill");
}

#[test]
fn failed_fill_after_a_good_one_denies() {
    let mut a = adapter(fill_switchable);
    assert!(a.rotate());
    FILL_WORKS.set(false);
    assert!(!a.rotate());
    assert_denies(&mut a, "failed refill");
}

#[test]
fn cleared_adapter_denies() {
    let mut a = adapter(fill_ok);
    assert!(a.rotate());
    a.clear();
    assert_denies(&mut a, "cleared");
}

#[test]
fn filled_adapter_accepts_the_correct_mac2_for_its_source_only() {
    let mut a = adapter(fill_ok);
    assert!(a.rotate());
    let m = initiation(mac2_under(&SECRET, SRC));
    assert!(a.mac2_valid(SRC, &m));
    assert!(!a.mac2_valid(Endpoint { port: SRC.port + 1, ..SRC }, &m));
    assert!(!a.mac2_valid(SRC, &initiation(mac2_under(&[0; 32], SRC))));
}

#[test]
fn sealed_replies_follow_the_counter_and_restart_after_rotate() {
    let mut a = adapter(fill_ok);
    assert!(a.rotate());
    let m = initiation([0; 16]);
    let mut out = [0u8; COOKIE_REPLY_LEN];
    for counter in 0..3 {
        assert!(a.seal_reply(SRC, &m, &mut out));
        assert_eq!(out, expected_reply(counter, &m), "counter {counter}");
    }
    assert!(a.rotate());
    assert!(a.seal_reply(SRC, &m, &mut out));
    assert_eq!(out, expected_reply(0, &m), "after rotate");
}
