//! Cookie primitives against golden vectors from an independent oracle.
//! Regenerate with `python3 tests/tools/cookie_vectors.py`; its inputs are
//! the constants below.

#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::panic)]

use static_assertions::assert_not_impl_any;
use wg_wire::{COOKIE_REPLY_LEN, CookieReply, INITIATION_LEN, INITIATION_MAC1_OFFSET, INITIATION_MAC2_OFFSET};

use crate::cookie::*;
use crate::crypto::{self, Key32};
use crate::tests::hex;

assert_not_impl_any!(CookieSecret: Clone, Copy, core::fmt::Debug);
assert_not_impl_any!(Cookie: Clone, Copy, core::fmt::Debug);

const GW_PUBLIC: [u8; 32] = {
    let mut k = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        k[i] = i as u8;
        i += 1;
    }
    k
};
const SECRET: [u8; 32] = {
    let mut k = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        k[i] = 0x40 + i as u8;
        i += 1;
    }
    k
};
const IP: [u8; 4] = [10, 0, 2, 2];
const PORT: u16 = 51820;
const COUNTER: u64 = 0x0102_0304_0506_0708;
const RECEIVER: u32 = 0x0403_0201;

const COOKIE_KEY: &str = "3dd5869c5202e45146936d1644f76ff697061661c181f3fd450eae43932eacec";
const MAC16: &str = "2493c5a085546bb1c7dcc11d9c5f9289";
const COOKIE: &str = "53394be9b5ee9105486447b159e06cf2";
const COOKIE_OTHER_PORT: &str = "89d3ab3eb1aaf5a8c0e8989f169287b7";
const MAC2: &str = "ab1a194221b9651d952c60cc4c996b40";
const REPLY_NONCE: &str = "7881d975525e852b188376548406bcb5cd2a21c538500cb8";
const SEAL_COOKIE_REPLY: &str = "03000000010203047881d975525e852b188376548406bcb5cd2a21c538500cb8
     a8558b0d20e1b0bcf50345f5f89a6db1a08cadea7a4d78282a83e7d6c11a7ccc";

fn secret() -> CookieSecret {
    let mut s = CookieSecret::new();
    assert!(s.fill(|b| {
        *b = SECRET;
        true
    }));
    s
}

/// Type 1, reserved zero, then byte i = 7 * i mod 256, with `mac2` appended.
fn initiation(mac2: [u8; 16]) -> [u8; INITIATION_LEN] {
    let mut m: [u8; INITIATION_LEN] = core::array::from_fn(|i| (7 * i) as u8);
    m[..4].copy_from_slice(&[1, 0, 0, 0]);
    m[INITIATION_MAC2_OFFSET..].copy_from_slice(&mac2);
    m
}

fn mac1_of(m: &[u8; INITIATION_LEN]) -> [u8; 16] {
    m[INITIATION_MAC1_OFFSET..INITIATION_MAC2_OFFSET].try_into().unwrap()
}

/// The shape of the ingress adapter's check: no cookie, no acceptance.
fn adapter_mac2_valid(s: &CookieSecret, port: u16, m: &[u8; INITIATION_LEN]) -> bool {
    make_cookie(s, IP, port).is_some_and(|c| mac2_valid(&c, m))
}

/// What a cookie looks like through the reply: opened with the public key.
fn cookie_bytes(c: &Cookie) -> [u8; 16] {
    let key = cookie_key(&GW_PUBLIC).unwrap();
    let reply = seal_cookie_reply(&key, 0, &[0; 24], c, &[0; 16]).unwrap();
    let r = CookieReply::parse(&reply).unwrap();
    let mut out = [0u8; 16];
    libcrux_chacha20poly1305::xchacha20_poly1305::decrypt(key.as_bytes(), &mut out, &r.encrypted_cookie, &[0; 16], &[0; 24])
        .unwrap();
    out
}

#[test]
fn cookie_key_matches_python() {
    assert_eq!(cookie_key(&GW_PUBLIC).unwrap().as_bytes(), &hex::<32>(COOKIE_KEY));
}

#[test]
fn mac16_matches_python_with_a_16_byte_key() {
    let key: [u8; 16] = core::array::from_fn(|i| i as u8);
    assert_eq!(crypto::mac16(&key, &[b"kozane ", b"wg-core"]).unwrap(), hex(MAC16));
}

// BLAKE2s carries the key length in its parameter block [M18].
#[test]
fn mac16_differs_from_mac_over_the_zero_padded_key() {
    let key: [u8; 16] = core::array::from_fn(|i| i as u8);
    let mut padded = [0u8; 32];
    padded[..16].copy_from_slice(&key);
    assert_ne!(crypto::mac16(&key, &[b"x"]).unwrap(), crypto::mac(&padded, &[b"x"]).unwrap());
}

#[test]
fn make_cookie_matches_python_with_a_big_endian_port() {
    let s = secret();
    assert_eq!(cookie_bytes(&make_cookie(&s, IP, PORT).unwrap()), hex(COOKIE));
    assert_eq!(cookie_bytes(&make_cookie(&s, IP, PORT + 1).unwrap()), hex(COOKIE_OTHER_PORT));
}

#[test]
fn correct_mac2_is_accepted_after_a_successful_fill() {
    let m = initiation(hex(MAC2));
    assert!(mac2_valid(&make_cookie(&secret(), IP, PORT).unwrap(), &m));
    assert!(adapter_mac2_valid(&secret(), PORT, &m));
}

#[test]
fn mac2_with_one_bit_flipped_is_rejected() {
    let c = make_cookie(&secret(), IP, PORT).unwrap();
    for bit in [0, 7, 127] {
        let mut mac2 = hex::<16>(MAC2);
        mac2[bit / 8] ^= 1 << (bit % 8);
        assert!(!mac2_valid(&c, &initiation(mac2)), "mac2 bit {bit}");
    }
    let mut m = initiation(hex(MAC2));
    m[INITIATION_MAC2_OFFSET - 1] ^= 0x80;
    assert!(!mac2_valid(&c, &m), "covered byte");
}

#[test]
fn mac2_made_for_another_port_is_rejected() {
    let m = initiation(hex(MAC2));
    assert!(!adapter_mac2_valid(&secret(), PORT + 1, &m));
}

#[test]
fn all_zero_mac2_is_rejected() {
    assert!(!mac2_valid(&make_cookie(&secret(), IP, PORT).unwrap(), &initiation([0; 16])));
}

#[test]
fn reply_nonce_matches_python_with_a_little_endian_counter() {
    assert_eq!(reply_nonce(&secret(), COUNTER), Some(hex(REPLY_NONCE)));
    assert_ne!(reply_nonce(&secret(), COUNTER), reply_nonce(&secret(), COUNTER + 1));
}

#[test]
fn seal_cookie_reply_matches_python() {
    let s = secret();
    let m = initiation(hex(MAC2));
    let key = cookie_key(&GW_PUBLIC).unwrap();
    let nonce = reply_nonce(&s, COUNTER).unwrap();
    let reply = seal_cookie_reply(&key, RECEIVER, &nonce, &make_cookie(&s, IP, PORT).unwrap(), &mac1_of(&m)).unwrap();
    assert_eq!(reply, hex::<COOKIE_REPLY_LEN>(SEAL_COOKIE_REPLY));
}

#[test]
fn cookie_reply_opens_only_with_the_initiation_mac1() {
    let s = secret();
    let m = initiation(hex(MAC2));
    let key = cookie_key(&GW_PUBLIC).unwrap();
    let nonce = reply_nonce(&s, COUNTER).unwrap();
    let reply = seal_cookie_reply(&key, RECEIVER, &nonce, &make_cookie(&s, IP, PORT).unwrap(), &mac1_of(&m)).unwrap();
    let r = CookieReply::parse(&reply).unwrap();
    assert_eq!((r.receiver, r.nonce), (RECEIVER, nonce));
    let open = |aad: &[u8]| {
        let mut out = [0u8; 16];
        libcrux_chacha20poly1305::xchacha20_poly1305::decrypt(key.as_bytes(), &mut out, &r.encrypted_cookie, aad, &nonce)
            .map(|p| <[u8; 16]>::try_from(p).unwrap())
    };
    assert_eq!(open(&mac1_of(&m)).unwrap(), hex(COOKIE));
    assert!(open(&[0; 16]).is_err());
}

#[test]
fn failed_fill_denies_and_zeroes_the_secret() {
    let mut s = secret();
    assert!(!s.fill(|b| {
        *b = [7; 32];
        false
    }));
    assert!(make_cookie(&s, IP, PORT).is_none());
    assert!(reply_nonce(&s, COUNTER).is_none());
    assert!(!adapter_mac2_valid(&s, PORT, &initiation(hex(MAC2))));
    let mut seen = [0xffu8; 32];
    s.fill(|b| {
        seen = *b;
        false
    });
    assert_eq!(seen, [0; 32]);
}

// A failed fill leaves the zero key behind; a mac2 made under the cookie
// that key would give must still be refused.
#[test]
fn mac2_under_the_zero_secret_cookie_is_rejected_after_a_failed_fill() {
    let mut s = CookieSecret::new();
    assert!(!s.fill(|_| false));
    let zero_cookie = crypto::mac(&[0; 32], &[&IP, &PORT.to_be_bytes()]).unwrap();
    let covered = initiation([0; 16]);
    let mac2 = crypto::mac16(&zero_cookie, &[&covered[..INITIATION_MAC2_OFFSET]]).unwrap();
    assert!(!adapter_mac2_valid(&s, PORT, &initiation(mac2)));
}

#[test]
fn new_secret_is_invalid_until_filled() {
    let s = CookieSecret::new();
    assert!(make_cookie(&s, IP, PORT).is_none());
    assert!(reply_nonce(&s, COUNTER).is_none());
}

#[test]
fn clear_denies_and_zeroes_the_secret() {
    let mut s = secret();
    s.clear();
    assert!(make_cookie(&s, IP, PORT).is_none());
    assert!(reply_nonce(&s, COUNTER).is_none());
    assert!(!adapter_mac2_valid(&s, PORT, &initiation(hex(MAC2))));
    let mut seen = [0xffu8; 32];
    s.fill(|b| {
        seen = *b;
        false
    });
    assert_eq!(seen, [0; 32]);
}

#[test]
fn fill_writes_in_place_and_refill_after_failure_recovers() {
    let mut s = CookieSecret::new();
    assert!(!s.fill(|_| false));
    assert!(s.fill(|b| {
        *b = SECRET;
        true
    }));
    assert_eq!(reply_nonce(&s, COUNTER), Some(hex(REPLY_NONCE)));
}

const XCHACHA_PT: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
const XCHACHA_CT: &str = "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb
     731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452
     2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9
     21f9664c97637da9768812f615c68b13b52e";
const XCHACHA_TAG: &str = "c0875924c1c7987947deafd8780acf49";

// draft-irtf-cfrg-xchacha-03 section A.3.1, through libcrux directly.
#[test]
fn xchacha20poly1305_draft_a_3_1_vector() {
    let key: [u8; 32] = core::array::from_fn(|i| 0x80 + i as u8);
    let nonce: [u8; 24] = core::array::from_fn(|i| 0x40 + i as u8);
    let aad = hex::<12>("50515253c0c1c2c3c4c5c6c7");
    let mut out = [0u8; 130];
    libcrux_chacha20poly1305::xchacha20_poly1305::encrypt(&key, XCHACHA_PT, &mut out, &aad, &nonce).unwrap();
    assert_eq!(&out[..114], &hex::<114>(XCHACHA_CT));
    assert_eq!(&out[114..], &hex::<16>(XCHACHA_TAG));
    let mut ours = [0u8; 130];
    assert_eq!(crypto::xaead_seal(&Key32::from_bytes(key), &nonce, XCHACHA_PT, &aad, &mut ours), Ok(130));
    assert_eq!(ours, out);
}
