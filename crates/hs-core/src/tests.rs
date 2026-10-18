#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::arithmetic_side_effects, clippy::panic)]

extern crate std;

use std::collections::BTreeSet;

use super::*;
use key_core::{Bucket, Oracle};
use wg_core::noise::{CONSTRUCTION, IDENTIFIER, LABEL_MAC1};
use wg_core::wire::{INITIATION_LEN, INITIATION_MAC1_OFFSET, MessageInitiation, MessageResponse, RESPONSE_LEN};

const GW_PRIVATE: [u8; 32] = [0x11; 32];
const PEER_PRIVATE: [u8; 32] = [0x22; 32];
const PSK: [u8; 32] = [0xa1; 32];
const SRC: msgs::Endpoint = msgs::Endpoint { ip: [10, 0, 2, 2], port: 40000 };

fn clamped(k: [u8; 32]) -> Key32 {
    let mut k = Key32::from_bytes(k);
    crypto::clamp(&mut k);
    k
}

fn gw_pub() -> [u8; 32] {
    crypto::public_key(&clamped(GW_PRIVATE))
}

fn peer_pub() -> [u8; 32] {
    crypto::public_key(&clamped(PEER_PRIVATE))
}

fn region() -> [u8; secret_blob::REGION_SIZE] {
    let mut r = [0u8; secret_blob::REGION_SIZE];
    secret_blob::write(&mut r, clamped(GW_PRIVATE).as_bytes(), &[0x99; 32], &[(peer_pub(), PSK)]).unwrap();
    r
}

/// `key` reached directly instead of over PPC.
struct Direct<'a> {
    oracle: Oracle<'a>,
    bucket: Bucket,
    calls: usize,
}

impl KeyCall for &mut Direct<'_> {
    fn call(&mut self, label: u64, req: &[u64], reply: &mut [u64]) -> (u64, usize) {
        self.calls += 1;
        self.oracle.handle(&mut self.bucket, 0, label, req, reply)
    }
}

fn direct(r: &[u8], burst: u64) -> Direct<'_> {
    let peers = [peer_pub()];
    let blob = key_core::validate(r, &gw_pub(), peers.iter()).unwrap();
    Direct { oracle: Oracle::new(blob, Key32::from_bytes([0x5e; 32])), bucket: Bucket::new(burst, 1), calls: 0 }
}

struct FakeHw {
    tick: u64,
    rndr: Option<u64>,
}

impl Hardware for FakeHw {
    fn counter(&mut self) -> u64 {
        self.tick += 1;
        self.tick
    }
    fn random(&mut self) -> Option<u64> {
        self.rndr
    }
}

fn entropy() -> HedgedEntropy<FakeHw> {
    HedgedEntropy::new(Key32::from_bytes([3; 32]), FakeHw { tick: 0, rndr: Some(42) })
}

/// Minimal initiator from the whitepaper (as in wg-core's tests).
struct Initiator {
    s: Key32,
    e: Key32,
    c: Key32,
    h: [u8; 32],
}

impl Initiator {
    fn initiation(ts: [u8; 12]) -> (Self, [u8; INITIATION_LEN]) {
        let sr_pub = gw_pub();
        let s = clamped(PEER_PRIVATE);
        let s_pub = crypto::public_key(&s);
        let e = clamped([0x61; 32]);
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
        let mut m =
            MessageInitiation { sender: 0x1122_3344, ephemeral: e_pub, enc_static, enc_timestamp, mac1: [0; 16], mac2: [0; 16] };
        let mut msg = [0u8; INITIATION_LEN];
        m.emit(&mut msg).unwrap();
        let mac1_key = crypto::hash(&[LABEL_MAC1, &sr_pub]).unwrap();
        m.mac1 = crypto::mac(&mac1_key, &[&msg[..INITIATION_MAC1_OFFSET]]).unwrap();
        m.emit(&mut msg).unwrap();
        (Self { s, e, c, h }, msg)
    }

    /// (T_send, T_recv) if the response verifies with `psk`.
    fn finish(self, resp: &[u8], psk: &[u8; 32]) -> Option<(Key32, Key32)> {
        let r = MessageResponse::parse(resp).ok()?;
        let c = crypto::kdf1(&self.c, &r.ephemeral).unwrap();
        let h = crypto::hash(&[&self.h, &r.ephemeral]).unwrap();
        let c = crypto::kdf1(&c, crypto::dh(&self.e, &r.ephemeral).unwrap().as_bytes()).unwrap();
        let c = crypto::kdf1(&c, crypto::dh(&self.s, &r.ephemeral).unwrap().as_bytes()).unwrap();
        let (c, tau, kappa) = crypto::kdf3(&c, psk).unwrap();
        let h = crypto::hash(&[&h, tau.as_bytes()]).unwrap();
        crypto::aead_open(&kappa, 0, &r.enc_nothing, &h, &mut []).ok()?;
        Some(crypto::kdf2(&c, &[]).unwrap())
    }
}

fn ts(secs: u64) -> [u8; 12] {
    let mut t = [0u8; 12];
    t[..8].copy_from_slice(&(0x4000_0000_0000_0000u64 + secs).to_be_bytes());
    t
}

fn input(msg: &[u8; INITIATION_LEN]) -> std::vec::Vec<u8> {
    let mut b = std::vec![0u8; msgs::INITIATION_MSG_LEN];
    let n = msgs::Initiation { src: SRC, msg }.encode(&mut b).unwrap();
    b.truncate(n);
    b
}

fn handshaker() -> Handshaker<4> {
    Handshaker::new(&gw_pub(), &Key32::from_bytes([0x5e; 32])).unwrap()
}

#[test]
fn full_handshake_through_the_real_key_oracle() {
    let r = region();
    let mut d = direct(&r, 100);
    let (init, msg) = Initiator::initiation(ts(1));
    let (mut install, mut response) = ([0u8; 128], [0u8; 128]);
    let peers = [peer_pub()];
    let out = handshaker().handle(&input(&msg), 0, &mut KeyClient::new(&mut d), &mut entropy(), &Peers(&peers), &mut install, &mut response);
    let Outcome::Accepted { peer, install_len, response_len } = out else { panic!("{out:?}") };
    assert_eq!(peer, PeerId(0));
    assert_eq!(d.calls, 3, "StaticDh for es and ss, then PskMix");

    let resp = msgs::Response::decode(&response[..response_len]).unwrap();
    assert_eq!(resp.dst, SRC);
    let (t_send, t_recv) = init.finish(resp.msg, &PSK).expect("initiator verifies the response");
    let inst = msgs::Install::decode(&install[..install_len]).unwrap();
    assert_eq!((inst.peer, inst.remote_index), (0, 0x1122_3344));
    assert_eq!(inst.recv, t_send.as_bytes());
    assert_eq!(inst.send, t_recv.as_bytes());
    assert_eq!(resp.msg.len(), RESPONSE_LEN);
}

#[test]
fn response_does_not_verify_with_another_psk() {
    let r = region();
    let mut d = direct(&r, 100);
    let (init, msg) = Initiator::initiation(ts(1));
    let (mut install, mut response) = ([0u8; 128], [0u8; 128]);
    let peers = [peer_pub()];
    let Outcome::Accepted { response_len, .. } =
        handshaker().handle(&input(&msg), 0, &mut KeyClient::new(&mut d), &mut entropy(), &Peers(&peers), &mut install, &mut response)
    else {
        panic!("not accepted")
    };
    let resp = msgs::Response::decode(&response[..response_len]).unwrap();
    assert!(init.finish(resp.msg, &[0xb2; 32]).is_none());
}

#[test]
fn key_refusal_rejects_and_records_the_reason() {
    let r = region();
    let mut d = direct(&r, 0);
    let (_, msg) = Initiator::initiation(ts(1));
    let mut client = KeyClient::new(&mut d);
    let peers = [peer_pub()];
    let out = handshaker().handle(&input(&msg), 0, &mut client, &mut entropy(), &Peers(&peers), &mut [0; 128], &mut [0; 128]);
    assert_eq!(out, Outcome::Rejected(Reject::Key(KeyError)));
    assert_eq!(client.last_error, key_core::ERR_RATE_LIMITED);
}

#[test]
fn bad_mac1_is_rejected_without_calling_key() {
    let r = region();
    let mut d = direct(&r, 100);
    let (_, mut msg) = Initiator::initiation(ts(1));
    msg[INITIATION_MAC1_OFFSET] ^= 1;
    let peers = [peer_pub()];
    let out = handshaker().handle(&input(&msg), 0, &mut KeyClient::new(&mut d), &mut entropy(), &Peers(&peers), &mut [0; 128], &mut [0; 128]);
    assert_eq!(out, Outcome::Rejected(Reject::BadMac1));
    assert_eq!(d.calls, 0);
}

#[test]
fn unknown_peer_is_rejected_after_one_key_call() {
    let r = region();
    let mut d = direct(&r, 100);
    let (_, msg) = Initiator::initiation(ts(1));
    let out = handshaker().handle(&input(&msg), 0, &mut KeyClient::new(&mut d), &mut entropy(), &Peers(&[[7; 32]]), &mut [0; 128], &mut [0; 128]);
    assert_eq!(out, Outcome::Rejected(Reject::UnknownPeer));
    assert_eq!(d.calls, 1);
}

#[test]
fn malformed_ingress_message_is_bad_input() {
    let r = region();
    let mut d = direct(&r, 100);
    let out = handshaker().handle(&[0; 10], 0, &mut KeyClient::new(&mut d), &mut entropy(), &Peers(&[]), &mut [0; 128], &mut [0; 128]);
    assert_eq!(out, Outcome::BadInput);
}

#[test]
fn successive_handshakes_get_distinct_indices() {
    let r = region();
    let mut d = direct(&r, 100);
    let mut h = handshaker();
    let peers = [peer_pub()];
    let mut seen = BTreeSet::new();
    for i in 0..3u64 {
        let (_, msg) = Initiator::initiation(ts(10 + i));
        let mut install = [0u8; 128];
        let Outcome::Accepted { install_len, .. } = h.handle(
            &input(&msg),
            i * 1_000_000_000,
            &mut KeyClient::new(&mut d),
            &mut entropy(),
            &Peers(&peers),
            &mut install,
            &mut [0; 128],
        ) else {
            panic!("not accepted")
        };
        assert!(seen.insert(msgs::Install::decode(&install[..install_len]).unwrap().local_index));
    }
}

#[test]
fn small_install_buffer_is_reported_and_left_zeroed() {
    let r = region();
    let mut d = direct(&r, 100);
    let (_, msg) = Initiator::initiation(ts(1));
    let mut install = [0xffu8; 20];
    let peers = [peer_pub()];
    let out = handshaker().handle(&input(&msg), 0, &mut KeyClient::new(&mut d), &mut entropy(), &Peers(&peers), &mut install, &mut [0; 128]);
    assert_eq!(out, Outcome::NoBuffer);
    assert_eq!(install, [0; 20]);
}

#[test]
fn feistel_is_a_bijection_at_8_bit_halves_with_the_real_round_function() {
    let key = Key32::from_bytes([9; 32]);
    let mut seen = std::vec![false; 1 << 16];
    for x in 0..(1u32 << 16) {
        let y = index::feistel(x, 8, &mut |r, h| {
            let d = crypto::hash(&[key.as_bytes(), &[r], &h.to_le_bytes()]).unwrap();
            u16::from_le_bytes([d[0], d[1]])
        });
        assert!(y < (1 << 16));
        assert!(!seen[y as usize], "collision at {x}");
        seen[y as usize] = true;
    }
}

#[test]
fn feistel_is_a_bijection_even_with_a_degenerate_round_function() {
    let mut seen = std::vec![false; 1 << 16];
    for x in 0..(1u32 << 16) {
        let y = index::feistel(x, 8, &mut |_, _| 0);
        assert!(!seen[y as usize]);
        seen[y as usize] = true;
    }
}

#[test]
fn indices_differ_per_boot_seed() {
    let a = index::Indices::new(&Key32::from_bytes([1; 32])).unwrap().next_index();
    let b = index::Indices::new(&Key32::from_bytes([2; 32])).unwrap().next_index();
    assert_ne!(a, b);
}

#[test]
fn indices_refuse_after_the_counter_wraps() {
    let mut i = index::Indices::new(&Key32::from_bytes([1; 32])).unwrap();
    i.set_counter_for_test(u32::MAX);
    assert!(i.next_index().is_some());
    assert_eq!(i.next_index(), None);
}

#[test]
fn entropy_never_repeats_and_fails_closed_without_rndr() {
    let mut e = entropy();
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    e.fill(&mut a).unwrap();
    e.fill(&mut b).unwrap();
    assert_ne!(a, b);
    let mut dead = HedgedEntropy::new(Key32::from_bytes([3; 32]), FakeHw { tick: 0, rndr: None });
    assert_eq!(dead.fill(&mut a), Err(EntropyError));
}

#[test]
fn peer_table_maps_configuration_order() {
    let peers = [[1u8; 32], [2u8; 32]];
    assert_eq!(Peers(&peers).lookup(&[2; 32]), Some(PeerId(1)));
    assert_eq!(Peers(&peers).lookup(&[3; 32]), None);
}

#[test]
fn key_client_dh_matches_the_peer_side_computation() {
    let r = region();
    let mut d = direct(&r, 100);
    let shared = KeyClient::new(&mut d).dh(&peer_pub()).unwrap();
    let expected = crypto::dh(&clamped(PEER_PRIVATE), &gw_pub()).unwrap();
    assert_eq!(shared.as_bytes(), expected.as_bytes());
}
