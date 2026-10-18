//! Full handshake against a minimal initiator written from the whitepaper
//! (section 5.4.2 / 5.4.4), plus the responder's negative paths.

#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::arithmetic_side_effects, clippy::panic)]

use wg_wire::{INITIATION_LEN, INITIATION_MAC1_OFFSET, MessageInitiation, MessageResponse, RESPONSE_MAC1_OFFSET};

use crate::crypto::{self, Key32};
use crate::noise::*;
use crate::session::{Session, SessionError};

const MS: u64 = 1_000_000;
const T0: u64 = 5_000 * MS;

const GW_PRIV: [u8; 32] = [0x41; 32];
const PEER_PRIV: [u8; 32] = [0x42; 32];
const STRANGER_PRIV: [u8; 32] = [0x43; 32];
const PSK: [u8; 32] = [0x50; 32];

fn gw_pub() -> [u8; 32] {
    crypto::public_key(&Key32::from_bytes(GW_PRIV))
}

/// Test double for the `key` PD.
struct TestKey {
    s: Key32,
    psk: [u8; 32],
    dh_calls: usize,
    /// Return raw zeros instead of an error for low-order points, as a
    /// careless key holder might.
    permissive: bool,
}

impl TestKey {
    fn new() -> Self {
        Self { s: Key32::from_bytes(GW_PRIV), psk: PSK, dh_calls: 0, permissive: false }
    }
}

impl StaticKey for TestKey {
    fn dh(&mut self, peer_point: &[u8; 32]) -> Result<Key32, KeyError> {
        self.dh_calls += 1;
        match crypto::dh(&self.s, peer_point) {
            Ok(k) => Ok(k),
            Err(crypto::CryptoError::ZeroDh) if self.permissive => Ok(Key32::from_bytes([0; 32])),
            Err(_) => Err(KeyError),
        }
    }

    fn psk_mix(&mut self, peer: PeerId, chaining: &Key32) -> Result<(Key32, Key32, Key32), KeyError> {
        assert_eq!(peer, PeerId(1));
        crypto::kdf3(chaining, &self.psk).map_err(|_| KeyError)
    }
}

struct CountingEntropy(u8);

impl Entropy for CountingEntropy {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), EntropyError> {
        self.0 = self.0.wrapping_add(1);
        for (i, b) in out.iter_mut().enumerate() {
            *b = self.0 ^ (i as u8).wrapping_mul(31);
        }
        Ok(())
    }
}

struct NoEntropy;

impl Entropy for NoEntropy {
    fn fill(&mut self, _: &mut [u8]) -> Result<(), EntropyError> {
        Err(EntropyError)
    }
}

/// One configured peer (`PEER_PRIV`) at id 1.
struct Peers;

impl PeerTable for Peers {
    fn lookup(&self, static_pub: &[u8; 32]) -> Option<PeerId> {
        (*static_pub == crypto::public_key(&Key32::from_bytes(PEER_PRIV))).then_some(PeerId(1))
    }
}

fn tai64n(secs: u64, nanos: u32) -> [u8; 12] {
    let mut t = [0u8; 12];
    t[..8].copy_from_slice(&(0x4000_0000_0000_0000u64 + secs).to_be_bytes());
    t[8..].copy_from_slice(&nanos.to_be_bytes());
    t
}

/// Initiator state between its two messages.
struct Initiator {
    s: Key32,
    s_pub: [u8; 32],
    e: Key32,
    c: Key32,
    h: [u8; 32],
    sender: u32,
    psk: [u8; 32],
}

impl Initiator {
    fn initiation(s_priv: [u8; 32], e_priv: [u8; 32], psk: [u8; 32], ts: [u8; 12]) -> (Self, [u8; INITIATION_LEN]) {
        let sr_pub = gw_pub();
        let s = Key32::from_bytes(s_priv);
        let s_pub = crypto::public_key(&s);
        let mut e = Key32::from_bytes(e_priv);
        crypto::clamp(&mut e);
        let e_pub = crypto::public_key(&e);

        let c = Key32::from_bytes(crypto::hash(&[CONSTRUCTION]).unwrap());
        let h = crypto::hash(&[c.as_bytes(), IDENTIFIER]).unwrap();
        let h = crypto::hash(&[&h, &sr_pub]).unwrap();
        let c = crypto::kdf1(&c, &e_pub).unwrap();
        let h = crypto::hash(&[&h, &e_pub]).unwrap();
        let (c, k) = crypto::kdf2(&c, crypto::dh(&e, &sr_pub).unwrap().as_bytes()).unwrap();
        let mut enc_static = [0u8; 48];
        crypto::aead_seal(&k, 0, &s_pub, &h, &mut enc_static).unwrap();
        let h = crypto::hash(&[&h, &enc_static]).unwrap();
        let (c, k) = crypto::kdf2(&c, crypto::dh(&s, &sr_pub).unwrap().as_bytes()).unwrap();
        let mut enc_timestamp = [0u8; 28];
        crypto::aead_seal(&k, 0, &ts, &h, &mut enc_timestamp).unwrap();
        let h = crypto::hash(&[&h, &enc_timestamp]).unwrap();

        let sender = 0x1122_3344;
        let mut m = MessageInitiation { sender, ephemeral: e_pub, enc_static, enc_timestamp, mac1: [0; 16], mac2: [0; 16] };
        let msg = with_mac1(&mut m, &sr_pub);
        (Self { s, s_pub, e, c, h, sender, psk }, msg)
    }

    /// Returns `(T_send, T_recv)` or `None` if the response does not verify.
    fn consume_response(self, resp: &[u8]) -> Option<(Key32, Key32)> {
        let r = MessageResponse::parse(resp).ok()?;
        assert_eq!(r.receiver, self.sender);
        let mac1_key = crypto::hash(&[LABEL_MAC1, &self.s_pub]).unwrap();
        assert_eq!(crypto::mac(&mac1_key, &[&resp[..RESPONSE_MAC1_OFFSET]]).unwrap(), r.mac1, "response mac1");
        assert_eq!(r.mac2, [0; 16]);
        let c = crypto::kdf1(&self.c, &r.ephemeral).unwrap();
        let h = crypto::hash(&[&self.h, &r.ephemeral]).unwrap();
        let c = crypto::kdf1(&c, crypto::dh(&self.e, &r.ephemeral).unwrap().as_bytes()).unwrap();
        let c = crypto::kdf1(&c, crypto::dh(&self.s, &r.ephemeral).unwrap().as_bytes()).unwrap();
        let (c, tau, kappa) = crypto::kdf3(&c, &self.psk).unwrap();
        let h = crypto::hash(&[&h, tau.as_bytes()]).unwrap();
        crypto::aead_open(&kappa, 0, &r.enc_nothing, &h, &mut []).ok()?;
        Some(crypto::kdf2(&c, &[]).unwrap())
    }
}

fn with_mac1(m: &mut MessageInitiation, sr_pub: &[u8; 32]) -> [u8; INITIATION_LEN] {
    let mut msg = [0u8; INITIATION_LEN];
    m.emit(&mut msg).unwrap();
    let key = crypto::hash(&[LABEL_MAC1, sr_pub]).unwrap();
    m.mac1 = crypto::mac(&key, &[&msg[..INITIATION_MAC1_OFFSET]]).unwrap();
    m.emit(&mut msg).unwrap();
    msg
}

fn responder() -> Responder<4> {
    Responder::new(&gw_pub()).unwrap()
}

fn valid_initiation(ts: [u8; 12]) -> (Initiator, [u8; INITIATION_LEN]) {
    Initiator::initiation(PEER_PRIV, [0x61; 32], PSK, ts)
}

fn consume(r: &mut Responder<4>, msg: &[u8; INITIATION_LEN], now: u64, key: &mut TestKey) -> Result<Accepted, Reject> {
    r.consume_initiation(msg, now, || Some(0xaabb_ccdd), key, &mut CountingEntropy(0), &Peers)
}

#[test]
fn full_handshake_and_transport_in_both_directions() {
    let mut r = responder();
    let mut key = TestKey::new();
    let (init, msg) = valid_initiation(tai64n(100, 0));
    let acc = consume(&mut r, &msg, T0, &mut key).unwrap();
    assert_eq!(acc.peer, PeerId(1));
    assert_eq!(acc.initiator_index, 0x1122_3344);
    assert_eq!(acc.responder_index, 0xaabb_ccdd);
    assert_eq!(MessageResponse::parse(&acc.response).unwrap().sender, 0xaabb_ccdd);
    assert_eq!(key.dh_calls, 2);

    let (i_send, i_recv) = init.consume_response(&acc.response).expect("initiator accepts response");
    // Responder keys are the initiator's swapped.
    assert_eq!(acc.keys.recv.as_bytes(), i_send.as_bytes());
    assert_eq!(acc.keys.send.as_bytes(), i_recv.as_bytes());

    let mut gw = Session::new(acc.keys, acc.responder_index, acc.initiator_index, T0);
    let mut client = Session::new(SessionKeys { send: i_send, recv: i_recv }, 0x1122_3344, 0xaabb_ccdd, T0);

    let mut ct = [0u8; 64];
    let (c, n) = client.seal(b"hello gateway", &mut ct, T0).unwrap();
    let mut pt = [0u8; 64];
    let m = gw.open(c, &ct[..n], &mut pt, T0 + MS).unwrap();
    assert_eq!(&pt[..m], b"hello gateway");

    let (c, n) = gw.seal(b"hello client", &mut ct, T0 + MS).unwrap();
    let m = client.open(c, &ct[..n], &mut pt, T0 + 2 * MS).unwrap();
    assert_eq!(&pt[..m], b"hello client");
}

#[test]
fn responder_ephemeral_comes_from_entropy() {
    let (_, msg) = valid_initiation(tai64n(100, 0));
    let a = responder()
        .consume_initiation(&msg, T0, || Some(1), &mut TestKey::new(), &mut CountingEntropy(0), &Peers)
        .unwrap();
    let b = responder()
        .consume_initiation(&msg, T0, || Some(1), &mut TestKey::new(), &mut CountingEntropy(7), &Peers)
        .unwrap();
    let ea = MessageResponse::parse(&a.response).unwrap().ephemeral;
    let eb = MessageResponse::parse(&b.response).unwrap().ephemeral;
    assert_ne!(ea, eb);
    assert_ne!(a.keys.send.as_bytes(), b.keys.send.as_bytes());
}

#[test]
fn wrong_psk_gets_a_response_the_initiator_cannot_use() {
    let mut r = responder();
    let (init, msg) = Initiator::initiation(PEER_PRIV, [0x61; 32], [0x51; 32], tai64n(100, 0));
    let acc = consume(&mut r, &msg, T0, &mut TestKey::new()).unwrap();
    assert!(init.consume_response(&acc.response).is_none());
}

#[test]
fn bad_mac1_is_rejected_before_any_dh() {
    let mut r = responder();
    let mut key = TestKey::new();
    let (_, mut msg) = valid_initiation(tai64n(100, 0));
    msg[INITIATION_MAC1_OFFSET] ^= 1;
    assert_eq!(consume(&mut r, &msg, T0, &mut key).err(), Some(Reject::BadMac1));
    // A covered byte changed under an unchanged mac1.
    let (_, mut msg) = valid_initiation(tai64n(100, 0));
    msg[50] ^= 1;
    assert_eq!(consume(&mut r, &msg, T0, &mut key).err(), Some(Reject::BadMac1));
    assert_eq!(key.dh_calls, 0);
}

#[test]
fn mac1_keyed_to_another_responder_is_rejected() {
    let (_, msg) = valid_initiation(tai64n(100, 0));
    let mut other = Responder::<4>::new(&[9; 32]).unwrap();
    let mut key = TestKey::new();
    assert_eq!(consume(&mut other, &msg, T0, &mut key).err(), Some(Reject::BadMac1));
    assert_eq!(key.dh_calls, 0);
}

#[test]
fn unknown_peer_is_rejected_after_exactly_one_dh() {
    let mut r = responder();
    let mut key = TestKey::new();
    let (_, msg) = Initiator::initiation(STRANGER_PRIV, [0x61; 32], PSK, tai64n(100, 0));
    assert_eq!(consume(&mut r, &msg, T0, &mut key).err(), Some(Reject::UnknownPeer));
    assert_eq!(key.dh_calls, 1);
}

#[test]
fn tampered_encrypted_static_fails_to_decrypt() {
    let mut r = responder();
    let mut key = TestKey::new();
    let (_, msg) = valid_initiation(tai64n(100, 0));
    let mut m = MessageInitiation::parse(&msg).unwrap();
    m.enc_static[0] ^= 1;
    let msg = with_mac1(&mut m, &gw_pub());
    assert_eq!(consume(&mut r, &msg, T0, &mut key).err(), Some(Reject::Decrypt));
    assert_eq!(key.dh_calls, 1);
}

#[test]
fn replayed_initiation_is_rejected() {
    let mut r = responder();
    let mut key = TestKey::new();
    let (_, msg) = valid_initiation(tai64n(100, 0));
    assert!(consume(&mut r, &msg, T0, &mut key).is_ok());
    assert_eq!(consume(&mut r, &msg, T0 + 1_000 * MS, &mut key).err(), Some(Reject::Replay));
    // An older timestamp is a replay too; a newer one is accepted.
    let (_, older) = valid_initiation(tai64n(99, 999_999_999));
    assert_eq!(consume(&mut r, &older, T0 + 2_000 * MS, &mut key).err(), Some(Reject::Replay));
    let (_, newer) = valid_initiation(tai64n(100, 1));
    assert!(consume(&mut r, &newer, T0 + 3_000 * MS, &mut key).is_ok());
}

#[test]
fn second_initiation_within_20ms_is_a_flood() {
    let mut r = responder();
    let mut key = TestKey::new();
    let (_, m1) = valid_initiation(tai64n(100, 0));
    let (_, m2) = valid_initiation(tai64n(101, 0));
    let (_, m3) = valid_initiation(tai64n(102, 0));
    assert!(consume(&mut r, &m1, T0, &mut key).is_ok());
    assert_eq!(consume(&mut r, &m2, T0 + 20 * MS - 1, &mut key).err(), Some(Reject::Flood));
    // A rejected flood does not move the window.
    assert!(consume(&mut r, &m2, T0 + 20 * MS, &mut key).is_ok());
    assert_eq!(consume(&mut r, &m3, T0 + 30 * MS, &mut key).err(), Some(Reject::Flood));
}

fn low_order_initiation() -> [u8; INITIATION_LEN] {
    let mut m = MessageInitiation {
        sender: 1,
        ephemeral: [0; 32],
        enc_static: [0; 48],
        enc_timestamp: [0; 28],
        mac1: [0; 16],
        mac2: [0; 16],
    };
    with_mac1(&mut m, &gw_pub())
}

#[test]
fn all_zero_dh_from_the_key_holder_is_rejected() {
    let mut r = responder();
    let mut key = TestKey { permissive: true, ..TestKey::new() };
    assert_eq!(consume(&mut r, &low_order_initiation(), T0, &mut key).err(), Some(Reject::ZeroDh));
    assert_eq!(key.dh_calls, 1);
}

#[test]
fn low_order_ephemeral_refused_by_key_holder_is_rejected() {
    let mut r = responder();
    let mut key = TestKey::new();
    assert_eq!(consume(&mut r, &low_order_initiation(), T0, &mut key).err(), Some(Reject::Key(KeyError)));
}

#[test]
fn entropy_failure_refuses_the_handshake() {
    let mut r = responder();
    let (_, msg) = valid_initiation(tai64n(100, 0));
    let res = r.consume_initiation(&msg, T0, || Some(1), &mut TestKey::new(), &mut NoEntropy, &Peers);
    assert_eq!(res.err(), Some(Reject::Entropy));
}

#[test]
fn peer_id_beyond_capacity_is_rejected_before_ss() {
    struct FarPeers;
    impl PeerTable for FarPeers {
        fn lookup(&self, _: &[u8; 32]) -> Option<PeerId> {
            Some(PeerId(4))
        }
    }
    let mut r = responder();
    let mut key = TestKey::new();
    let (_, msg) = valid_initiation(tai64n(100, 0));
    let res = r.consume_initiation(&msg, T0, || Some(1), &mut key, &mut CountingEntropy(0), &FarPeers);
    assert_eq!(res.err(), Some(Reject::PeerOutOfRange));
    assert_eq!(key.dh_calls, 1);
}

#[test]
fn wrong_type_byte_is_malformed() {
    let mut r = responder();
    let (_, mut msg) = valid_initiation(tai64n(100, 0));
    msg[0] = 2;
    assert_eq!(
        consume(&mut r, &msg, T0, &mut TestKey::new()).err(),
        Some(Reject::Malformed(wg_wire::WireError::WrongType))
    );
}

#[test]
fn transport_from_wrong_session_does_not_open() {
    let mut r = responder();
    let (init, msg) = valid_initiation(tai64n(100, 0));
    let acc = consume(&mut r, &msg, T0, &mut TestKey::new()).unwrap();
    let (_, i_recv) = init.consume_response(&acc.response).unwrap();
    // Encrypting with the initiator's receive key (wrong direction) must fail.
    let mut client = Session::new(SessionKeys { send: i_recv, recv: Key32::from_bytes([0; 32]) }, 0, 0, T0);
    let mut gw = Session::new(acc.keys, 0, 0, T0);
    let mut ct = [0u8; 32];
    let (c, n) = client.seal(b"x", &mut ct, T0).unwrap();
    assert_eq!(gw.open(c, &ct[..n], &mut [0u8; 32], T0), Err(SessionError::Auth));
}

/// One handshake initiation captured from wireguard-go (Debian package, in
/// an unprivileged netns): initiator private key [0x42; 32] (`PEER_PRIV`),
/// responder public key derived from [0x41; 32] (`GW_PRIV`), PSK [0x50; 32].
/// The only fixture produced by an independent implementation, so a shared
/// misreading of the whitepaper by this crate and its test initiator cannot
/// pass it (code review T3).
const WG_GO_INITIATION: &str = "01000000ffe5f42220cf3e9ad5c074b52f168acdef0bb3bd295b492d4e574fbdaf0a0a41\
36893e2776567209857f129f163dd0dd353e85e93c15e7e2fa925b116ae4136602ab70248b56f970048d6c1aeda6d3acf3cbe\
a5cab885a4f89b15e9cd1b0c8f76f8dbc4db699674ccda40c5f1a284a35de20bce1537a0456c34f1eecdb2c8ca50000000000\
0000000000000000000000";

fn wg_go_initiation() -> [u8; INITIATION_LEN] {
    let mut msg = [0u8; INITIATION_LEN];
    assert_eq!(WG_GO_INITIATION.len(), 2 * INITIATION_LEN);
    for (i, b) in msg.iter_mut().enumerate() {
        *b = u8::from_str_radix(&WG_GO_INITIATION[2 * i..2 * i + 2], 16).unwrap();
    }
    msg
}

#[test]
fn captured_wireguard_go_initiation_is_accepted() {
    let msg = wg_go_initiation();
    let acc = consume(&mut responder(), &msg, T0, &mut TestKey::new()).expect("wireguard-go initiation");
    // The encrypted static decrypted to the configured peer's key.
    assert_eq!(acc.peer, PeerId(1));
    assert_eq!(acc.initiator_index, u32::from_le_bytes(msg[4..8].try_into().unwrap()));
}

#[test]
fn captured_initiation_with_a_tampered_static_fails_to_decrypt() {
    let mut msg = wg_go_initiation();
    msg[40] ^= 1; // inside enc_static
    // Re-MAC so the tamper reaches the AEAD instead of the mac1 check.
    let key = crypto::hash(&[LABEL_MAC1, &gw_pub()]).unwrap();
    let mac1 = crypto::mac(&key, &[&msg[..INITIATION_MAC1_OFFSET]]).unwrap();
    msg[INITIATION_MAC1_OFFSET..INITIATION_MAC1_OFFSET + 16].copy_from_slice(&mac1);
    assert!(matches!(consume(&mut responder(), &msg, T0, &mut TestKey::new()), Err(Reject::Decrypt)));
}

#[test]
fn captured_initiation_for_another_responder_fails_mac1() {
    let mut r: Responder<4> = Responder::new(&crypto::public_key(&Key32::from_bytes(STRANGER_PRIV))).unwrap();
    assert!(matches!(consume(&mut r, &wg_go_initiation(), T0, &mut TestKey::new()), Err(Reject::BadMac1)));
}
