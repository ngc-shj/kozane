#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::panic)]

use static_assertions::assert_not_impl_any;

use super::crypto::*;
use super::noise::{Accepted, SessionKeys};
use super::session::{Session, SessionError};
use super::*;

assert_not_impl_any!(Key32: Clone, Copy, core::fmt::Debug);
assert_not_impl_any!(SessionKeys: Clone, Copy, core::fmt::Debug);
assert_not_impl_any!(Accepted: Clone, Copy, core::fmt::Debug);
assert_not_impl_any!(Session: Clone, Copy, core::fmt::Debug);

pub(crate) fn hex<const N: usize>(s: &str) -> [u8; N] {
    let s: std::string::String = s.split_whitespace().collect();
    assert_eq!(s.len(), 2 * N, "hex length");
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

extern crate std;

#[test]
fn limits_match_whitepaper_section_6_1() {
    assert_eq!(u128::from(REJECT_AFTER_MESSAGES), (1u128 << 64) - (1 << 13) - 1);
    assert_eq!(REKEY_AFTER_MESSAGES, 1u64 << 60);
    assert_eq!(REKEY_AFTER_TIME_NS, 120_000_000_000);
    assert_eq!(REJECT_AFTER_TIME_NS, 180_000_000_000);
    assert_eq!(REKEY_TIMEOUT_NS, 5_000_000_000);
    assert_eq!(KEEPALIVE_TIMEOUT_NS, 10_000_000_000);
}

// RFC 7748 section 5.2 (the first scalar is unclamped: X25519 clamps internally).
#[test]
fn x25519_rfc7748_5_2_vectors() {
    let k = Key32::from_bytes(hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"));
    let u = hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    assert_eq!(
        dh(&k, &u).unwrap().as_bytes(),
        &hex::<32>("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
    );
    let k = Key32::from_bytes(hex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"));
    let u = hex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
    assert_eq!(
        dh(&k, &u).unwrap().as_bytes(),
        &hex::<32>("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")
    );
}

// RFC 7748 section 6.1.
#[test]
fn x25519_rfc7748_6_1_diffie_hellman() {
    let a = Key32::from_bytes(hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
    let b = Key32::from_bytes(hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"));
    let ka = public_key(&a);
    let kb = public_key(&b);
    assert_eq!(ka, hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
    assert_eq!(kb, hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"));
    let k = hex::<32>("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    assert_eq!(dh(&a, &kb).unwrap().as_bytes(), &k);
    assert_eq!(dh(&b, &ka).unwrap().as_bytes(), &k);
}

#[test]
fn x25519_rejects_low_order_points() {
    let a = Key32::from_bytes(hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
    let mut one = [0u8; 32];
    one[0] = 1;
    assert_eq!(dh(&a, &[0; 32]).err(), Some(CryptoError::ZeroDh));
    assert_eq!(dh(&a, &one).err(), Some(CryptoError::ZeroDh));
}

// RFC 8439 section 2.8.2. Our nonce is 0u32 || counter_le64, so the RFC's
// nonce 07000000 || 4041424344454647 is not expressible with a zero prefix;
// the vector is checked through libcrux directly and our nonce layout by
// `aead_nonce_is_zero_prefix_then_le_counter`.
#[test]
fn chacha20poly1305_rfc8439_2_8_2_vector() {
    let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let aad = hex::<12>("50515253c0c1c2c3c4c5c6c7");
    let key = hex::<32>("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    let nonce = hex::<12>("070000004041424344454647");
    let ct = hex::<114>(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6
         3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36
         92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc
         3ff4def08e4b7a9de576d26586cec64b6116",
    );
    let tag = hex::<16>("1ae10b594f09e26a7e902ecbd0600691");
    let mut out = [0u8; 130];
    libcrux_chacha20poly1305::encrypt(&key, pt, &mut out, &aad, &nonce).unwrap();
    assert_eq!(&out[..114], &ct);
    assert_eq!(&out[114..], &tag);
}

#[test]
fn aead_nonce_is_zero_prefix_then_le_counter() {
    let key = Key32::from_bytes([7; 32]);
    let counter = 0x0102_0304_0506_0708u64;
    let mut ours = [0u8; 21];
    assert_eq!(aead_seal(&key, counter, b"hello", b"ad", &mut ours), Ok(21));
    let nonce = [0, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1];
    let mut reference = [0u8; 21];
    libcrux_chacha20poly1305::encrypt(&[7; 32], b"hello", &mut reference, b"ad", &nonce).unwrap();
    assert_eq!(ours, reference);
    let mut pt = [0u8; 5];
    assert_eq!(aead_open(&key, counter, &ours, b"ad", &mut pt), Ok(5));
    assert_eq!(&pt, b"hello");
}

#[test]
fn aead_open_rejects_tampering_and_leaves_output_untouched() {
    let key = Key32::from_bytes([7; 32]);
    let mut ct = [0u8; 21];
    aead_seal(&key, 1, b"hello", &[], &mut ct).unwrap();
    let mut pt = [0xeeu8; 5];
    assert_eq!(aead_open(&key, 2, &ct, &[], &mut pt), Err(CryptoError::Auth));
    assert_eq!(aead_open(&key, 1, &ct, b"x", &mut pt), Err(CryptoError::Auth));
    ct[0] ^= 1;
    assert_eq!(aead_open(&key, 1, &ct, &[], &mut pt), Err(CryptoError::Auth));
    assert_eq!(pt, [0xee; 5]);
    assert_eq!(aead_open(&key, 1, &ct[..15], &[], &mut pt), Err(CryptoError::Buffer));
}

// RFC 7693 Appendix B.
#[test]
fn blake2s_rfc7693_appendix_b_abc() {
    assert_eq!(
        hash(&[b"abc"]).unwrap(),
        hex("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982")
    );
    // Chunking does not change the digest.
    assert_eq!(hash(&[b"a", b"", b"bc"]).unwrap(), hash(&[b"abc"]).unwrap());
}

// python3 -c "import hashlib; print(hashlib.blake2s(b'kozane wg-core', key=bytes(range(32)), digest_size=16).hexdigest())"
#[test]
fn keyed_blake2s_128_matches_python_hashlib() {
    let key: [u8; 32] = core::array::from_fn(|i| i as u8);
    assert_eq!(mac(&key, &[b"kozane ", b"wg-core"]).unwrap(), hex("76b98da795ad9efbdee12d310fa1ed81"));
}

// python3 -c "import hashlib,hmac; print(hmac.new(bytes(range(32)), b'hmac test', hashlib.blake2s).hexdigest())"
// python3 -c "import hashlib,hmac; print(hmac.new(bytes(range(32)), b'', hashlib.blake2s).hexdigest())"
#[test]
fn hmac_blake2s_matches_python_hmac() {
    let key: [u8; 32] = core::array::from_fn(|i| i as u8);
    assert_eq!(
        hmac(&key, &[b"hmac test"]).unwrap().as_bytes(),
        &hex::<32>("be441bdb9efedf3b37fdec61c2b544a96b2039c6943e80ee202d0d5949ce0362")
    );
    assert_eq!(
        hmac(&key, &[]).unwrap().as_bytes(),
        &hex::<32>("e2641d24dfa8dd89e8cb77f1cdc77d8c006e5bebdfc4d6a3a3a6f8d5b7586fb0")
    );
}

// python3 -c "
// import hashlib,hmac; H=lambda k,m: hmac.new(k,m,hashlib.blake2s).digest(); k=bytes(range(32))
// t0=H(k,b'kdf input'); t1=H(t0,b'\x01'); t2=H(t0,t1+b'\x02'); t3=H(t0,t2+b'\x03')
// print(t1.hex(), t2.hex(), t3.hex())"
#[test]
fn kdf_matches_python_reference() {
    let key = Key32::from_bytes(core::array::from_fn(|i| i as u8));
    let t1 = hex::<32>("f0f68421988336e20ce9e9251e4440497d9798985798b8f7fcf2c32ba1752467");
    let t2 = hex::<32>("f9ec09ac5a46c71f76a8b06d37497a03fcde6448a396c864298d4344f902cf1b");
    let t3 = hex::<32>("ea7bfa571e8873ad63e74dd0047867e451c43c0790f055ef36079851788ef4d4");
    let (a, b, c) = kdf3(&key, b"kdf input").unwrap();
    assert_eq!((a.as_bytes(), b.as_bytes(), c.as_bytes()), (&t1, &t2, &t3));
    let (a, b) = kdf2(&key, b"kdf input").unwrap();
    assert_eq!((a.as_bytes(), b.as_bytes()), (&t1, &t2));
    assert_eq!(kdf1(&key, b"kdf input").unwrap().as_bytes(), &t1);
}

// python3 -c "import hashlib; c=hashlib.blake2s(b'Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s').digest();
//   print(c.hex(), hashlib.blake2s(c+b'WireGuard v1 zx2c4 Jason@zx2c4.com').hexdigest())"
// (equal to wireguard-go's InitialChainKey / InitialHash)
#[test]
fn initial_chaining_key_and_hash_match_wireguard() {
    let c = hash(&[noise::CONSTRUCTION]).unwrap();
    assert_eq!(c, hex("60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36"));
    assert_eq!(
        hash(&[&c, noise::IDENTIFIER]).unwrap(),
        hex("2211b361081ac566691243db458ad5322d9c6c662293e8b70ee19c65ba079ef3")
    );
}

// --- session ---

const T0: u64 = 1_000_000_000_000;

fn session_pair() -> (Session, Session) {
    let a_keys = SessionKeys { send: Key32::from_bytes([1; 32]), recv: Key32::from_bytes([2; 32]) };
    let b_keys = SessionKeys { send: Key32::from_bytes([2; 32]), recv: Key32::from_bytes([1; 32]) };
    (Session::new(a_keys, 10, 20, T0), Session::new(b_keys, 20, 10, T0))
}

#[test]
fn session_seal_open_round_trip_with_increasing_counters() {
    let (mut a, mut b) = session_pair();
    for i in 0..3u64 {
        let mut ct = [0u8; 32];
        assert_eq!(a.seal(b"0123456789abcdef", &mut ct, T0), Ok((i, 32)));
        let mut pt = [0u8; 16];
        assert_eq!(b.open(i, &ct, &mut pt, T0), Ok(16));
        assert_eq!(&pt, b"0123456789abcdef");
    }
    let mut ct = [0u8; 16];
    let (c, n) = b.seal(&[], &mut ct, T0).unwrap();
    assert_eq!(a.open(c, &ct[..n], &mut [], T0), Ok(0));
}

#[test]
fn session_forged_packet_does_not_consume_its_counter() {
    let (mut a, mut b) = session_pair();
    let mut ct = [0u8; 20];
    let (c, _) = a.seal(b"ping", &mut ct, T0).unwrap();
    let mut forged = ct;
    forged[0] ^= 1;
    let mut pt = [0u8; 4];
    assert_eq!(b.open(c, &forged, &mut pt, T0), Err(SessionError::Auth));
    assert_eq!(b.open(c, &ct, &mut pt, T0), Ok(4));
}

#[test]
fn session_rejects_replay_and_wipes_plaintext() {
    let (mut a, mut b) = session_pair();
    let mut ct = [0u8; 20];
    let (c, _) = a.seal(b"ping", &mut ct, T0).unwrap();
    let mut pt = [0u8; 4];
    assert_eq!(b.open(c, &ct, &mut pt, T0), Ok(4));
    assert_eq!(b.open(c, &ct, &mut pt, T0), Err(SessionError::Replay));
    assert_eq!(pt, [0; 4]);
}

#[test]
fn session_expires_at_reject_after_time() {
    let (mut a, mut b) = session_pair();
    let last_ok = T0 + REJECT_AFTER_TIME_NS - 1;
    assert!(!a.expired(last_ok));
    assert!(a.expired(last_ok + 1));
    let mut ct = [0u8; 20];
    let (c, _) = a.seal(b"ping", &mut ct, last_ok).unwrap();
    let mut pt = [0u8; 4];
    assert_eq!(b.open(c, &ct, &mut pt, last_ok + 1), Err(SessionError::Expired));
    assert_eq!(a.seal(b"ping", &mut ct, last_ok + 1), Err(SessionError::Expired));
    // Expiry is final: the keys are gone even if the clock reads earlier later.
    assert_eq!(b.open(c, &ct, &mut pt, last_ok), Err(SessionError::Auth));
}

#[test]
fn session_enforces_reject_after_messages() {
    let (mut a, mut b) = session_pair();
    let mut pt = [0u8; 4];
    assert_eq!(b.open(REJECT_AFTER_MESSAGES, &[0; 20], &mut pt, T0), Err(SessionError::CounterLimit));
    a.set_send_counter(REJECT_AFTER_MESSAGES - 1);
    let mut ct = [0u8; 20];
    assert_eq!(a.seal(b"ping", &mut ct, T0), Ok((REJECT_AFTER_MESSAGES - 1, 20)));
    assert_eq!(b.open(REJECT_AFTER_MESSAGES - 1, &ct, &mut pt, T0), Ok(4));
    assert_eq!(a.seal(b"ping", &mut ct, T0), Err(SessionError::CounterLimit));
}

#[test]
fn session_tracks_highest_accepted_counter_only() {
    let (mut a, mut b) = session_pair();
    let mut cts = [[0u8; 20]; 3];
    for ct in &mut cts {
        a.seal(b"ping", ct, T0).unwrap();
    }
    let mut pt = [0u8; 4];
    assert_eq!(b.highest_received(), None);
    assert_eq!(b.open(1, &cts[1], &mut pt, T0), Ok(4));
    assert_eq!(b.highest_received(), Some(1));
    // An older in-window counter is accepted but does not lower the maximum.
    assert_eq!(b.open(0, &cts[0], &mut pt, T0), Ok(4));
    assert_eq!(b.highest_received(), Some(1));
    // Neither a forgery nor a replay moves it.
    let mut forged = cts[2];
    forged[0] ^= 1;
    assert_eq!(b.open(2, &forged, &mut pt, T0), Err(SessionError::Auth));
    assert_eq!(b.open(1, &cts[1], &mut pt, T0), Err(SessionError::Replay));
    assert_eq!(b.highest_received(), Some(1));
    assert_eq!(b.open(2, &cts[2], &mut pt, T0), Ok(4));
    assert_eq!(b.highest_received(), Some(2));
}

#[test]
fn session_reports_short_buffers() {
    let (mut a, mut b) = session_pair();
    assert_eq!(a.seal(b"ping", &mut [0u8; 19], T0), Err(SessionError::Buffer));
    assert_eq!(b.open(0, &[0u8; 15], &mut [0u8; 4], T0), Err(SessionError::Buffer));
    let mut ct = [0u8; 20];
    a.seal(b"ping", &mut ct, T0).unwrap();
    assert_eq!(b.open(0, &ct, &mut [0u8; 3], T0), Err(SessionError::Buffer));
}
