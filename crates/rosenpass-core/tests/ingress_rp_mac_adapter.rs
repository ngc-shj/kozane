//! The ingress PD's Rosenpass mac adapter (crates/pds/ingress/src/rp_mac.rs)
//! against the rp-vectors messages (M3 plan C4 [R2-T-N4]): upstream's
//! initiator sealed them to the gateway's `spkm`, so their mac fields are
//! upstream's own values. The PD crate builds only for seL4, so its
//! seL4-free module is included here by path, as an integration test of
//! rosenpass-core, as wg-core does for the cookie adapter.

#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::panic)]

#[path = "../../pds/ingress/src/rp_mac.rs"]
mod rp_mac;

use rosenpass_core::SPK_LEN;
use rosenpass_wire::{COOKIE_LEN, MAC_LEN, mac_offset};
use rp_mac::RpMacKey;

static SPKM: &[u8; SPK_LEN] = include_bytes!("vectors/spkm.bin");
static SPKT: &[u8; SPK_LEN] = include_bytes!("vectors/spkt.bin");
const V02: &str = include_str!("vectors/v02.txt");

fn v(name: &str) -> Vec<u8> {
    let line = V02.lines().find(|l| l.split_once(' ').is_some_and(|(k, _)| k == name)).unwrap();
    let hex = line.split_once(' ').unwrap().1;
    (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect()
}

fn messages() -> [Vec<u8>; 2] {
    [v("msg.init_hello"), v("msg.init_conf")]
}

#[test]
fn upstream_init_hello_and_init_conf_pass_under_spkm() {
    let a = RpMacKey::new(SPKM).unwrap();
    for m in messages() {
        assert!(a.verify(&m), "type {:#x}", m[0]);
    }
}

#[test]
fn a_flipped_mac_byte_fails() {
    let a = RpMacKey::new(SPKM).unwrap();
    for mut m in messages() {
        let off = mac_offset(m.len());
        for i in [off, off + MAC_LEN - 1] {
            m[i] ^= 1;
            assert!(!a.verify(&m), "type {:#x} mac byte {i}", m[0]);
            m[i] ^= 1;
        }
    }
}

#[test]
fn a_flipped_covered_byte_fails() {
    let a = RpMacKey::new(SPKM).unwrap();
    for mut m in messages() {
        let last = mac_offset(m.len()) - 1;
        for i in [0, 4, last] {
            m[i] ^= 0x80;
            assert!(!a.verify(&m), "type {:#x} byte {i}", m[0]);
            m[i] ^= 0x80;
        }
    }
}

#[test]
fn the_cookie_field_is_not_covered() {
    let a = RpMacKey::new(SPKM).unwrap();
    for mut m in messages() {
        let n = m.len();
        m[n - COOKIE_LEN..].fill(0xaa);
        assert!(a.verify(&m), "type {:#x}", m[0]);
    }
}

#[test]
fn another_public_key_fails() {
    let a = RpMacKey::new(SPKT).unwrap();
    for m in messages() {
        assert!(!a.verify(&m), "type {:#x}", m[0]);
    }
}

#[test]
fn the_mac_is_upstreams_incorrect_hmac_under_the_vector_key() {
    // Recomputed from the vector key, so a key derivation that drifted from
    // upstream's `mac_key.spkm` would fail here rather than only on traffic.
    let key: [u8; 32] = v("mac_key.spkm").try_into().unwrap();
    for m in messages() {
        let off = mac_offset(m.len());
        let full = rosenpass_core::crypto::kh_public(&key, &m[..off]).unwrap();
        assert_eq!(&full[..MAC_LEN], &m[off..off + MAC_LEN], "type {:#x}", m[0]);
    }
}

#[test]
fn messages_too_short_to_hold_a_mac_fail() {
    let a = RpMacKey::new(SPKM).unwrap();
    for len in [0, 1, MAC_LEN - 1] {
        assert!(!a.verify(&vec![0u8; len]), "len {len}");
    }
}
