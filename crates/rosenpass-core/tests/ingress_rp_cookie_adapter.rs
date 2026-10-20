//! The ingress PD's Rosenpass cookie adapter (crates/pds/ingress/src/
//! rp_cookie.rs, M3b plan C3) against the cookie vectors from upstream: the
//! secret rotates current → previous, a cookie under either is accepted and
//! one two rotations old is not, a failed rotation clears both, and the
//! CookieReply opens with the public cookie key and the InitHello's mac. The
//! PD crate builds only for seL4, so its seL4-free module is included here
//! by path, as `ingress_rp_mac_adapter.rs` does.

#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::panic)]

#[path = "../../pds/ingress/src/rp_cookie.rs"]
mod rp_cookie;

use std::cell::Cell;

use ingress_core::{Endpoint, RP_COOKIE_REPLY_LEN, RP_INIT_HELLO_LEN, RpCookieCheck};
use rosenpass_core::{SPK_LEN, Secret, cookie, crypto};
use rp_cookie::RpCookieAdapter;

static SPKM: &[u8; SPK_LEN] = include_bytes!("vectors/spkm.bin");
const COOKIE: &str = include_str!("vectors/cookie.txt");

fn cv(name: &str) -> Vec<u8> {
    let line = COOKIE.lines().find(|l| l.split_once(' ').is_some_and(|(k, _)| k == name)).unwrap();
    let hex = line.split_once(' ').unwrap().1;
    (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect()
}

std::thread_local! {
    /// The bytes the next fills write, and whether they succeed.
    static NEXT: Cell<(u8, bool)> = const { Cell::new((0x11, true)) };
}

fn fill(out: &mut [u8]) -> bool {
    let (b, ok) = NEXT.with(Cell::get);
    out.fill(if ok { b } else { 0 });
    ok
}

fn next(b: u8, ok: bool) {
    NEXT.with(|n| n.set((b, ok)));
}

const SRC: Endpoint = Endpoint { ip: [10, 0, 3, 1], port: 41001 };

fn msg() -> [u8; RP_INIT_HELLO_LEN] {
    cv("cookie.msg").try_into().unwrap()
}

/// `msg` with the cookie field an initiator writes for `secret`'s value.
fn cookied(secret: u8) -> [u8; RP_INIT_HELLO_LEN] {
    let mut m = msg();
    let value = cookie::cookie_value(&Secret::from_bytes([secret; 16]), &cookie::host_info(SRC.ip, SRC.port));
    let cut = RP_INIT_HELLO_LEN - 16;
    let field = cookie::cookie_field(&value, &m[..cut]);
    m[cut..].copy_from_slice(&field);
    m
}

#[test]
fn a_cookie_is_valid_under_the_current_and_the_previous_secret_only() {
    let mut a = RpCookieAdapter::new(SPKM, fill);
    next(0x11, true);
    assert!(a.rotate());
    assert!(a.valid(SRC, &cookied(0x11)));
    next(0x22, true);
    assert!(a.rotate());
    assert!(a.valid(SRC, &cookied(0x22)), "current");
    assert!(a.valid(SRC, &cookied(0x11)), "previous, for one epoch");
    next(0x33, true);
    assert!(a.rotate());
    assert!(!a.valid(SRC, &cookied(0x11)), "two rotations old");
    assert!(!a.valid(Endpoint { port: 41002, ..SRC }, &cookied(0x33)), "bound to the endpoint");
}

#[test]
fn a_failed_rotation_clears_both_secrets() {
    let mut a = RpCookieAdapter::new(SPKM, fill);
    next(0x11, true);
    assert!(a.rotate());
    next(0x22, false);
    assert!(!a.rotate());
    assert!(!a.valid(SRC, &cookied(0x11)));
    assert!(!a.valid(SRC, &cookied(0x00)));
    assert!(!a.seal(SRC, &msg(), &mut [0u8; RP_COOKIE_REPLY_LEN]), "no secret, no reply");
}

#[test]
fn the_cookie_reply_opens_with_the_public_key_and_the_init_hellos_mac() {
    let mut a = RpCookieAdapter::new(SPKM, fill);
    next(0x11, true);
    assert!(a.rotate());
    let m = msg();
    let mut out = [0u8; RP_COOKIE_REPLY_LEN];
    assert!(a.seal(SRC, &m, &mut out));
    assert_eq!(out.len(), m.len(), "no amplification");
    assert_eq!(out[0], rosenpass_wire::MSG_COOKIE_REPLY);
    assert_eq!(&out[4..8], &m[4..8], "sid = the InitHello's sidi");
    // As the initiator does (upstream `handle_cookie_reply`).
    let key = Secret::from_bytes(cookie::cookie_key(SPKM));
    assert_eq!(key.expose().to_vec(), cv("cookie.key"));
    let mac = &m[RP_INIT_HELLO_LEN - 32..RP_INIT_HELLO_LEN - 16];
    let mut value = [0u8; 16];
    crypto::xaead_open(&key, mac, &out[8..64], &mut value).unwrap();
    assert_eq!(value.to_vec(), cv("cookie.value"), "the vectors' secret and host");
    // Another mac does not open it.
    let mut other = [0u8; 16];
    assert!(crypto::xaead_open(&key, &[0u8; 16], &out[8..64], &mut other).is_err());
}

#[test]
fn reply_nonces_never_repeat_under_one_secret() {
    let mut a = RpCookieAdapter::new(SPKM, fill);
    next(0x11, true);
    assert!(a.rotate());
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..100 {
        let mut out = [0u8; RP_COOKIE_REPLY_LEN];
        assert!(a.seal(SRC, &msg(), &mut out));
        assert!(seen.insert(out[8..32].to_vec()), "nonce reused");
    }
}
