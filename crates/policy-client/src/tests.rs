#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::panic, clippy::arithmetic_side_effects)]

extern crate std;

use std::vec::Vec;

use layout::tpm::pack;
use policy_wire::Prefix;
use policy_wire::render::{PlainBundle, PlainPeer, render};

use super::*;
use limits::SPK_LEN;

fn verified_words(slot: Slot, version: u32) -> [u64; VERIFIED_WORDS] {
    let mut w = [0u64; VERIFIED_WORDS];
    assert_eq!(pack(&policy_wire::verified_reply(slot, version, &[7; 32]), &mut w), Some(VERIFIED_WORDS));
    w
}

fn token(slot: Slot, version: u32) -> Verified {
    decode(ch::VERIFIED, VERIFIED_WORDS, &verified_words(slot, version)).unwrap()
}

// --- decode -------------------------------------------------------------

#[test]
fn a_verified_reply_decodes_to_its_slot_version_and_digest() {
    for slot in [Slot::A, Slot::B] {
        let t = token(slot, 41);
        assert_eq!((t.slot(), t.version(), t.body_sha256()), (slot, 41, &[7; 32]));
    }
}

#[test]
fn a_verified_reply_with_another_word_count_is_malformed() {
    let w = verified_words(Slot::A, 1);
    assert_eq!(decode(ch::VERIFIED, VERIFIED_WORDS - 1, &w), Err(Reject::Malformed));
    let mut long = [0u64; VERIFIED_WORDS + 1];
    long[..VERIFIED_WORDS].copy_from_slice(&w);
    assert_eq!(decode(ch::VERIFIED, VERIFIED_WORDS + 1, &long), Err(Reject::Malformed));
    // A count the registers do not hold.
    assert_eq!(decode(ch::VERIFIED, VERIFIED_WORDS, &w[..2]), Err(Reject::Malformed));
}

#[test]
fn a_verified_reply_naming_no_slot_is_malformed() {
    let mut w = verified_words(Slot::A, 1);
    w[0] = (w[0] & !0xff) | 2;
    assert_eq!(decode(ch::VERIFIED, VERIFIED_WORDS, &w), Err(Reject::Malformed));
}

#[test]
fn an_unavailable_reply_carries_policys_reason() {
    for r in Reject::ALL {
        assert_eq!(decode(ch::UNAVAILABLE, 1, &[u64::from(r.code())]), Err(r), "{r:?}");
    }
}

#[test]
fn an_unavailable_reply_with_an_unknown_reason_or_count_is_malformed() {
    assert_eq!(decode(ch::UNAVAILABLE, 1, &[Reject::ALL.len() as u64]), Err(Reject::Malformed));
    assert_eq!(decode(ch::UNAVAILABLE, 1, &[u64::MAX]), Err(Reject::Malformed));
    assert_eq!(decode(ch::UNAVAILABLE, 0, &[]), Err(Reject::Malformed));
    assert_eq!(decode(ch::UNAVAILABLE, 2, &[0, 0]), Err(Reject::Malformed));
}

#[test]
fn a_bad_request_or_unknown_label_is_never_a_token() {
    let w = verified_words(Slot::A, 1);
    assert_eq!(decode(ch::BAD_REQUEST, 0, &[]), Err(Reject::Malformed));
    assert_eq!(decode(ch::BAD_REQUEST, VERIFIED_WORDS, &w), Err(Reject::Malformed));
    assert_eq!(decode(99, VERIFIED_WORDS, &w), Err(Reject::Malformed));
}

// --- slot choice and open -------------------------------------------------

const FLEET: [u8; 16] = [3; 16];

fn node() -> NodeConfig<'static> {
    NodeConfig {
        fleet_id: FLEET,
        inside_prefix: Prefix { addr: [10, 99, 0, 0], len: 24 },
        inside_ip: [10, 99, 0, 1],
        outside_ip: [10, 0, 2, 15],
        neighbors: &[[10, 99, 0, 2]],
        gateway_wg_public: [0xAA; 32],
        gateway_rp_digest: [0xEE; 32],
    }
}

fn slot(version: u32, wg: u8) -> Vec<u8> {
    let rp: Vec<u8> = std::vec![wg; SPK_LEN];
    let rp: &[u8; SPK_LEN] = rp.as_slice().try_into().unwrap();
    let allowed = [Prefix { addr: [10, 200, 0, wg], len: 32 }];
    let peers = [PlainPeer { wg_pub: [wg; 32], rp_pub: rp, groups: 0, allowed: &allowed }];
    render(&PlainBundle {
        fleet_id: FLEET,
        version,
        min_release: 0,
        prev_sha256: [0; 32],
        roster_sha256: [0; 32],
        peers: &peers,
        groups: &[],
        sig_ed25519: [0; 64],
        sig_mldsa65: [0; 3309],
    })
}

#[test]
fn pick_takes_the_slot_the_token_names() {
    let (a, b) = ([1u8], [2u8]);
    assert_eq!(pick(&token(Slot::A, 1), &a, &b), &a);
    assert_eq!(pick(&token(Slot::B, 1), &a, &b), &b);
}

#[test]
fn open_reads_the_named_slot_only() {
    let (zero, b) = (std::vec![0u8; limits::BUNDLE_MAX], slot(5, 4));
    let bundle = open_in(&token(Slot::B, 5), &zero, &b, &node()).unwrap();
    assert_eq!((bundle.version(), bundle.peer_count()), (5, 1));
    assert_eq!(bundle.peer(0).unwrap().wg_pub(), &[4; 32]);
    // Slot A holds nothing: a token naming it opens nothing, whatever B holds.
    assert_eq!(open_in(&token(Slot::A, 5), &zero, &b, &node()).err(), Some(Reject::Malformed));
}

#[test]
fn open_refuses_a_slot_whose_version_is_not_the_tokens() {
    let a = slot(5, 4);
    assert!(open_in(&token(Slot::A, 5), &a, &a, &node()).is_ok());
    assert_eq!(open_in(&token(Slot::A, 6), &a, &a, &node()).err(), Some(Reject::Malformed));
}

#[test]
fn open_checks_the_bundle_against_the_node() {
    let a = slot(5, 4);
    let other = NodeConfig { fleet_id: [4; 16], ..node() };
    assert_eq!(open_in(&token(Slot::A, 5), &a, &a, &other).err(), Some(Reject::WrongFleet));
}

