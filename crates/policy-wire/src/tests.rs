#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::panic, clippy::arithmetic_side_effects)]

extern crate std;

use std::vec::Vec;

use super::render::{PlainBundle, PlainGroup, PlainPeer, render};
use super::*;

// --- Prefix -----------------------------------------------------------

#[test]
fn prefix_contains_is_inclusive_at_both_ends() {
    let p = Prefix { addr: [10, 0, 0, 0], len: 24 };
    assert!(p.contains([10, 0, 0, 0]));
    assert!(p.contains([10, 0, 0, 255]));
    assert!(!p.contains([10, 0, 1, 0]));
}

#[test]
fn prefix_slash_zero_contains_everything() {
    let p = Prefix { addr: [0, 0, 0, 0], len: 0 };
    assert!(p.contains([1, 2, 3, 4]));
    assert!(p.contains([255, 255, 255, 255]));
}

#[test]
fn prefix_overlaps_is_inclusive_and_symmetric() {
    let a = Prefix { addr: [10, 0, 0, 0], len: 24 };
    let b = Prefix { addr: [10, 0, 0, 255], len: 32 };
    let c = Prefix { addr: [10, 0, 1, 0], len: 32 };
    assert!(a.overlaps(&b) && b.overlaps(&a));
    assert!(!a.overlaps(&c) && !c.overlaps(&a));
}

#[test]
fn prefix_checked_rejects_a_bad_length_or_host_bits() {
    assert!(Prefix::checked([10, 0, 0, 0], 33).is_none());
    assert!(Prefix::checked([10, 0, 0, 1], 24).is_none());
    assert!(Prefix::checked([10, 0, 0, 0], 24).is_some());
    assert!(Prefix::checked([10, 0, 0, 1], 32).is_some());
}

// --- Fixture building ---------------------------------------------------

const FLEET: [u8; 16] = [9; 16];
const GATEWAY_WG: [u8; 32] = [0xAA; 32];
/// A content pattern no test peer's rp_pub ever uses, so its digest never
/// collides with a peer's by accident.
const GATEWAY_RP_FILL: u8 = 0xEE;

fn rp_fill(byte: u8) -> Vec<u8> {
    std::vec![byte; SPK_LEN]
}

/// The test's stand-in for a real hash: the key's first 32 bytes. Opaque
/// enough for `parse` (which never inspects it), and avoids a crypto
/// dependency in a crate that must stay free of one.
fn fake_digest(k: &[u8; SPK_LEN]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&k[..32]);
    out
}

fn gateway_rp_digest() -> [u8; 32] {
    fake_digest(rp_fill(GATEWAY_RP_FILL).as_slice().try_into().unwrap())
}

fn node() -> NodeConfig<'static> {
    NodeConfig {
        fleet_id: FLEET,
        inside_prefix: Prefix { addr: [10, 0, 0, 0], len: 24 },
        inside_ip: [10, 0, 0, 1],
        outside_ip: [192, 0, 2, 1],
        neighbors: &[[10, 0, 0, 2]],
        gateway_wg_public: GATEWAY_WG,
        gateway_rp_digest: gateway_rp_digest(),
    }
}

/// A peer whose `wg_pub` is `[byte; 32]` (so peers sort by `byte`) and
/// whose `rp_pub` is `rp_fill(byte)`, in group 0 only, allowed
/// `10.<byte>.0.0/24` (never overlapping `node()`'s fields).
struct Fixture {
    rp: Vec<Vec<u8>>,
    allowed: Vec<[Prefix; 1]>,
}

impl Fixture {
    fn new(bytes: &[u8]) -> Fixture {
        Fixture { rp: bytes.iter().map(|&b| rp_fill(b)).collect(), allowed: bytes.iter().map(|&b| [Prefix { addr: [10, b, 0, 0], len: 24 }]).collect() }
    }

    fn peers(&self, bytes: &[u8]) -> Vec<PlainPeer<'_>> {
        bytes
            .iter()
            .enumerate()
            .map(|(i, &b)| PlainPeer {
                wg_pub: [b; 32],
                rp_pub: self.rp[i].as_slice().try_into().unwrap(),
                groups: 1,
                allowed: &self.allowed[i],
            })
            .collect()
    }
}

fn one_group() -> [PlainGroup<'static>; 1] {
    const RULES: [Rule; 1] = [Rule { dst: Prefix { addr: [10, 60, 0, 0], len: 24 }, proto: PROTO_TCP, port_lo: 80, port_hi: 80 }];
    [PlainGroup { rules: &RULES }]
}

fn base_bundle<'a>(peers: &'a [PlainPeer<'a>], groups: &'a [PlainGroup<'a>]) -> PlainBundle<'a> {
    PlainBundle {
        fleet_id: FLEET,
        version: 5,
        min_release: 0,
        prev_sha256: [0; 32],
        roster_sha256: [0; 32],
        peers,
        groups,
        sig_ed25519: [0; 64],
        sig_mldsa65: [0; 3309],
    }
}

/// A valid two-peer, one-group bundle, rendered to `BUNDLE_MAX` bytes.
fn valid_slot() -> Vec<u8> {
    let fx = Fixture::new(&[1, 2]);
    let peers = fx.peers(&[1, 2]);
    let groups = one_group();
    render(&base_bundle(&peers, &groups))
}

// --- parse: structural and semantic rejections --------------------------

#[test]
fn a_valid_bundle_parses() {
    let slot = valid_slot();
    let b = parse(&slot, &node(), &fake_digest).unwrap();
    assert_eq!(b.version(), 5);
    assert_eq!(b.peer_count(), 2);
    assert_eq!(b.group_count(), 1);
    assert_eq!(*b.peer(0).unwrap().wg_pub(), [1; 32]);
    assert_eq!(b.owner_of([10, 2, 0, 5]), Some(1));
    assert_eq!(b.owner_of([10, 99, 0, 5]), None);
    let rules: Vec<Rule> = b.group(0).unwrap().rules().collect();
    assert_eq!(rules, [Rule { dst: Prefix { addr: [10, 60, 0, 0], len: 24 }, proto: PROTO_TCP, port_lo: 80, port_hi: 80 }]);
}

#[test]
fn wrong_length_is_malformed() {
    let mut slot = valid_slot();
    slot.pop();
    assert_eq!(parse(&slot, &node(), &fake_digest).unwrap_err(), Reject::Malformed);
}

#[test]
fn bad_magic_is_malformed() {
    let mut slot = valid_slot();
    slot[0] ^= 1;
    assert_eq!(parse(&slot, &node(), &fake_digest).unwrap_err(), Reject::Malformed);
}

#[test]
fn bad_format_is_malformed() {
    let mut slot = valid_slot();
    slot[5] = 2;
    assert_eq!(parse(&slot, &node(), &fake_digest).unwrap_err(), Reject::Malformed);
}

#[test]
fn zero_peer_count_is_malformed() {
    let mut slot = valid_slot();
    slot[PEER_COUNT_AT] = 0;
    assert_eq!(parse(&slot, &node(), &fake_digest).unwrap_err(), Reject::Malformed);
}

#[test]
fn peer_count_over_the_max_is_malformed() {
    let mut slot = valid_slot();
    slot[PEER_COUNT_AT] = (MAX_PEERS + 1) as u8;
    assert_eq!(parse(&slot, &node(), &fake_digest).unwrap_err(), Reject::Malformed);
}

#[test]
fn group_count_over_the_max_is_malformed() {
    let mut slot = valid_slot();
    slot[GROUP_COUNT_AT] = (MAX_GROUPS + 1) as u8;
    assert_eq!(parse(&slot, &node(), &fake_digest).unwrap_err(), Reject::Malformed);
}

#[test]
fn peers_out_of_ascending_order_are_malformed() {
    let fx = Fixture::new(&[2, 1]);
    let peers = fx.peers(&[2, 1]);
    let groups = one_group();
    let slot = render(&base_bundle(&peers, &groups));
    assert_eq!(parse(&slot, &node(), &fake_digest).unwrap_err(), Reject::Malformed);
}

#[test]
fn duplicate_wg_pub_is_malformed() {
    let fx = Fixture::new(&[1, 1]);
    let peers = fx.peers(&[1, 1]);
    let groups = one_group();
    let slot = render(&base_bundle(&peers, &groups));
    assert_eq!(parse(&slot, &node(), &fake_digest).unwrap_err(), Reject::Malformed);
}

#[test]
fn zero_allowed_count_is_malformed() {
    let fx = Fixture::new(&[1]);
    let groups = one_group();
    let peer = PlainPeer { wg_pub: [1; 32], rp_pub: fx.rp[0].as_slice().try_into().unwrap(), groups: 1, allowed: &[] };
    let slot = render(&base_bundle(&[peer], &groups));
    assert_eq!(parse(&slot, &node(), &fake_digest).unwrap_err(), Reject::Malformed);
}

#[test]
fn allowed_count_over_the_max_is_malformed() {
    let fx = Fixture::new(&[1]);
    let many: Vec<Prefix> = (0..=MAX_ALLOWED as u8).map(|i| Prefix { addr: [10, 100, i, 0], len: 24 }).collect();
    let peer = PlainPeer { wg_pub: [1; 32], rp_pub: fx.rp[0].as_slice().try_into().unwrap(), groups: 1, allowed: &many };
    let groups = one_group();
    let slot = render(&base_bundle(&[peer], &groups));
    assert_eq!(parse(&slot, &node(), &fake_digest).unwrap_err(), Reject::Malformed);
}

#[test]
fn host_bits_in_an_allowed_prefix_are_malformed() {
    let fx = Fixture::new(&[1]);
    let bad = [Prefix { addr: [10, 100, 0, 1], len: 24 }];
    let peer = PlainPeer { wg_pub: [1; 32], rp_pub: fx.rp[0].as_slice().try_into().unwrap(), groups: 1, allowed: &bad };
    let groups = one_group();
    let slot = render(&base_bundle(&[peer], &groups));
    assert_eq!(parse(&slot, &node(), &fake_digest).unwrap_err(), Reject::Malformed);
}

#[test]
fn a_groups_bit_at_or_past_group_count_is_malformed() {
    let fx = Fixture::new(&[1]);
    let allowed = [Prefix { addr: [10, 100, 0, 0], len: 24 }];
    // group_count will be 1 (one group below), so bit 1 is out of range.
    let peer = PlainPeer { wg_pub: [1; 32], rp_pub: fx.rp[0].as_slice().try_into().unwrap(), groups: 0b10, allowed: &allowed };
    let groups = one_group();
    let slot = render(&base_bundle(&[peer], &groups));
    assert_eq!(parse(&slot, &node(), &fake_digest).unwrap_err(), Reject::Malformed);
}

#[test]
fn zero_rule_count_is_malformed() {
    let fx = Fixture::new(&[1]);
    let allowed = [Prefix { addr: [10, 100, 0, 0], len: 24 }];
    let peer = PlainPeer { wg_pub: [1; 32], rp_pub: fx.rp[0].as_slice().try_into().unwrap(), groups: 0, allowed: &allowed };
    let groups = [PlainGroup { rules: &[] }];
    let slot = render(&base_bundle(&[peer], &groups));
    assert_eq!(parse(&slot, &node(), &fake_digest).unwrap_err(), Reject::Malformed);
}

#[test]
fn rule_count_over_the_max_is_malformed() {
    let fx = Fixture::new(&[1]);
    let allowed = [Prefix { addr: [10, 100, 0, 0], len: 24 }];
    let peer = PlainPeer { wg_pub: [1; 32], rp_pub: fx.rp[0].as_slice().try_into().unwrap(), groups: 0, allowed: &allowed };
    let rules: Vec<Rule> =
        (0..=MAX_RULES as u16).map(|p| Rule { dst: Prefix { addr: [10, 60, 0, 0], len: 24 }, proto: PROTO_TCP, port_lo: p, port_hi: p }).collect();
    let groups = [PlainGroup { rules: &rules }];
    let slot = render(&base_bundle(&[peer], &groups));
    assert_eq!(parse(&slot, &node(), &fake_digest).unwrap_err(), Reject::Malformed);
}

#[test]
fn rules_out_of_ascending_order_are_malformed() {
    let fx = Fixture::new(&[1]);
    let allowed = [Prefix { addr: [10, 100, 0, 0], len: 24 }];
    let peer = PlainPeer { wg_pub: [1; 32], rp_pub: fx.rp[0].as_slice().try_into().unwrap(), groups: 0, allowed: &allowed };
    let rules = [
        Rule { dst: Prefix { addr: [10, 60, 0, 0], len: 24 }, proto: PROTO_TCP, port_lo: 443, port_hi: 443 },
        Rule { dst: Prefix { addr: [10, 60, 0, 0], len: 24 }, proto: PROTO_TCP, port_lo: 80, port_hi: 80 },
    ];
    let groups = [PlainGroup { rules: &rules }];
    let slot = render(&base_bundle(&[peer], &groups));
    assert_eq!(parse(&slot, &node(), &fake_digest).unwrap_err(), Reject::Malformed);
}

#[test]
fn host_bits_in_a_rule_dst_are_malformed() {
    let fx = Fixture::new(&[1]);
    let allowed = [Prefix { addr: [10, 100, 0, 0], len: 24 }];
    let peer = PlainPeer { wg_pub: [1; 32], rp_pub: fx.rp[0].as_slice().try_into().unwrap(), groups: 0, allowed: &allowed };
    let rules = [Rule { dst: Prefix { addr: [10, 60, 0, 1], len: 24 }, proto: PROTO_TCP, port_lo: 80, port_hi: 80 }];
    let groups = [PlainGroup { rules: &rules }];
    let slot = render(&base_bundle(&[peer], &groups));
    assert_eq!(parse(&slot, &node(), &fake_digest).unwrap_err(), Reject::Malformed);
}

#[test]
fn an_unknown_proto_is_malformed() {
    let fx = Fixture::new(&[1]);
    let allowed = [Prefix { addr: [10, 100, 0, 0], len: 24 }];
    let peer = PlainPeer { wg_pub: [1; 32], rp_pub: fx.rp[0].as_slice().try_into().unwrap(), groups: 0, allowed: &allowed };
    let rules = [Rule { dst: Prefix { addr: [10, 60, 0, 0], len: 24 }, proto: 2, port_lo: 0, port_hi: 0 }];
    let groups = [PlainGroup { rules: &rules }];
    let slot = render(&base_bundle(&[peer], &groups));
    assert_eq!(parse(&slot, &node(), &fake_digest).unwrap_err(), Reject::Malformed);
}

#[test]
fn port_lo_above_port_hi_is_malformed() {
    let fx = Fixture::new(&[1]);
    let allowed = [Prefix { addr: [10, 100, 0, 0], len: 24 }];
    let peer = PlainPeer { wg_pub: [1; 32], rp_pub: fx.rp[0].as_slice().try_into().unwrap(), groups: 0, allowed: &allowed };
    let rules = [Rule { dst: Prefix { addr: [10, 60, 0, 0], len: 24 }, proto: PROTO_TCP, port_lo: 81, port_hi: 80 }];
    let groups = [PlainGroup { rules: &rules }];
    let slot = render(&base_bundle(&[peer], &groups));
    assert_eq!(parse(&slot, &node(), &fake_digest).unwrap_err(), Reject::Malformed);
}

#[test]
fn icmp_with_a_nonzero_port_is_malformed() {
    let fx = Fixture::new(&[1]);
    let allowed = [Prefix { addr: [10, 100, 0, 0], len: 24 }];
    let peer = PlainPeer { wg_pub: [1; 32], rp_pub: fx.rp[0].as_slice().try_into().unwrap(), groups: 0, allowed: &allowed };
    let rules = [Rule { dst: Prefix { addr: [10, 60, 0, 0], len: 24 }, proto: PROTO_ICMP, port_lo: 0, port_hi: 1 }];
    let groups = [PlainGroup { rules: &rules }];
    let slot = render(&base_bundle(&[peer], &groups));
    assert_eq!(parse(&slot, &node(), &fake_digest).unwrap_err(), Reject::Malformed);
}

#[test]
fn icmp_echo_only_is_accepted() {
    let fx = Fixture::new(&[1]);
    let allowed = [Prefix { addr: [10, 100, 0, 0], len: 24 }];
    let peer = PlainPeer { wg_pub: [1; 32], rp_pub: fx.rp[0].as_slice().try_into().unwrap(), groups: 0, allowed: &allowed };
    let rules = [Rule { dst: Prefix { addr: [10, 60, 0, 0], len: 24 }, proto: PROTO_ICMP, port_lo: 0, port_hi: 0 }];
    let groups = [PlainGroup { rules: &rules }];
    let slot = render(&base_bundle(&[peer], &groups));
    assert!(parse(&slot, &node(), &fake_digest).is_ok());
}

#[test]
fn a_nonzero_tail_is_malformed() {
    let mut slot = valid_slot();
    *slot.last_mut().unwrap() = 1;
    assert_eq!(parse(&slot, &node(), &fake_digest).unwrap_err(), Reject::Malformed);
}

#[test]
fn a_fleet_id_mismatch_is_wrong_fleet() {
    let slot = valid_slot();
    let mut n = node();
    n.fleet_id = [0; 16];
    assert_eq!(parse(&slot, &n, &fake_digest).unwrap_err(), Reject::WrongFleet);
}

#[test]
fn a_peer_using_the_gateways_wg_key_is_malformed() {
    let fx = Fixture::new(&[1]);
    let allowed = [Prefix { addr: [10, 100, 0, 0], len: 24 }];
    let peer = PlainPeer { wg_pub: GATEWAY_WG, rp_pub: fx.rp[0].as_slice().try_into().unwrap(), groups: 0, allowed: &allowed };
    let groups = one_group();
    let slot = render(&base_bundle(&[peer], &groups));
    assert_eq!(parse(&slot, &node(), &fake_digest).unwrap_err(), Reject::Malformed);
}

#[test]
fn a_peer_using_the_gateways_rp_key_is_malformed() {
    let rp = rp_fill(GATEWAY_RP_FILL);
    let allowed = [Prefix { addr: [10, 100, 0, 0], len: 24 }];
    let peer = PlainPeer { wg_pub: [1; 32], rp_pub: rp.as_slice().try_into().unwrap(), groups: 0, allowed: &allowed };
    let groups = one_group();
    let slot = render(&base_bundle(&[peer], &groups));
    assert_eq!(parse(&slot, &node(), &fake_digest).unwrap_err(), Reject::Malformed);
}

/// `open` leaves the gateway-rp check to `policy`, which ran it on the same
/// read-only bytes (D-13): the slot `parse` refuses above opens.
#[test]
fn open_does_not_rehash_the_rp_keys() {
    let rp = rp_fill(GATEWAY_RP_FILL);
    let allowed = [Prefix { addr: [10, 100, 0, 0], len: 24 }];
    let peer = PlainPeer { wg_pub: [1; 32], rp_pub: rp.as_slice().try_into().unwrap(), groups: 0, allowed: &allowed };
    let groups = one_group();
    let peers = [peer];
    let plain = base_bundle(&peers, &groups);
    let slot = render(&plain);
    let reply = reply_bytes(Slot::A, plain.version, [0; 32]);
    let token = Verified::from_reply(&reply).unwrap();
    assert!(open(&token, &slot, &node()).is_ok());
}

#[test]
fn duplicate_rp_pub_across_distinct_peers_is_malformed() {
    let rp = rp_fill(1);
    let allowed0 = [Prefix { addr: [10, 100, 0, 0], len: 24 }];
    let allowed1 = [Prefix { addr: [10, 101, 0, 0], len: 24 }];
    let peers = [
        PlainPeer { wg_pub: [1; 32], rp_pub: rp.as_slice().try_into().unwrap(), groups: 0, allowed: &allowed0 },
        PlainPeer { wg_pub: [2; 32], rp_pub: rp.as_slice().try_into().unwrap(), groups: 0, allowed: &allowed1 },
    ];
    let groups = one_group();
    let slot = render(&base_bundle(&peers, &groups));
    assert_eq!(parse(&slot, &node(), &fake_digest).unwrap_err(), Reject::Malformed);
}

#[test]
fn an_allowed_ip_containing_inside_ip_is_malformed() {
    let fx = Fixture::new(&[1]);
    let allowed = [Prefix { addr: [10, 0, 0, 0], len: 24 }];
    let peer = PlainPeer { wg_pub: [1; 32], rp_pub: fx.rp[0].as_slice().try_into().unwrap(), groups: 0, allowed: &allowed };
    let groups = one_group();
    let slot = render(&base_bundle(&[peer], &groups));
    assert_eq!(parse(&slot, &node(), &fake_digest).unwrap_err(), Reject::Malformed);
}

#[test]
fn an_allowed_ip_containing_the_outside_ip_is_malformed() {
    let fx = Fixture::new(&[1]);
    let allowed = [Prefix { addr: [192, 0, 2, 0], len: 24 }];
    let peer = PlainPeer { wg_pub: [1; 32], rp_pub: fx.rp[0].as_slice().try_into().unwrap(), groups: 0, allowed: &allowed };
    let groups = one_group();
    let slot = render(&base_bundle(&[peer], &groups));
    assert_eq!(parse(&slot, &node(), &fake_digest).unwrap_err(), Reject::Malformed);
}

#[test]
fn an_allowed_ip_containing_a_neighbor_is_malformed() {
    let fx = Fixture::new(&[1]);
    let allowed = [Prefix { addr: [10, 0, 0, 2], len: 32 }];
    let peer = PlainPeer { wg_pub: [1; 32], rp_pub: fx.rp[0].as_slice().try_into().unwrap(), groups: 0, allowed: &allowed };
    let groups = one_group();
    let slot = render(&base_bundle(&[peer], &groups));
    assert_eq!(parse(&slot, &node(), &fake_digest).unwrap_err(), Reject::Malformed);
}

#[test]
fn an_allowed_ip_overlapping_inside_prefix_is_malformed() {
    let fx = Fixture::new(&[1]);
    let allowed = [Prefix { addr: [10, 0, 0, 128], len: 25 }];
    let peer = PlainPeer { wg_pub: [1; 32], rp_pub: fx.rp[0].as_slice().try_into().unwrap(), groups: 0, allowed: &allowed };
    let groups = one_group();
    let slot = render(&base_bundle(&[peer], &groups));
    assert_eq!(parse(&slot, &node(), &fake_digest).unwrap_err(), Reject::Malformed);
}

#[test]
fn allowed_ips_overlapping_across_distinct_peers_are_malformed() {
    let fx = Fixture::new(&[1, 2]);
    let allowed0 = [Prefix { addr: [10, 100, 0, 0], len: 23 }];
    let allowed1 = [Prefix { addr: [10, 100, 1, 0], len: 24 }];
    let peers = [
        PlainPeer { wg_pub: [1; 32], rp_pub: fx.rp[0].as_slice().try_into().unwrap(), groups: 0, allowed: &allowed0 },
        PlainPeer { wg_pub: [2; 32], rp_pub: fx.rp[1].as_slice().try_into().unwrap(), groups: 0, allowed: &allowed1 },
    ];
    let groups = one_group();
    let slot = render(&base_bundle(&peers, &groups));
    assert_eq!(parse(&slot, &node(), &fake_digest).unwrap_err(), Reject::Malformed);
}

#[test]
fn adjacent_allowed_ips_across_peers_are_accepted() {
    let slot = valid_slot();
    assert!(parse(&slot, &node(), &fake_digest).is_ok());
}

// --- split / DOMAIN -----------------------------------------------------

#[test]
fn split_separates_body_from_the_two_signatures() {
    let slot = valid_slot();
    let u = split(&slot).unwrap();
    assert_eq!(u.sig_ed25519(), &[0u8; 64]);
    assert_eq!(u.sig_mldsa65(), &[0u8; 3309]);
    assert!(slot.starts_with(u.body()));
    let after_body = &slot[u.body().len()..];
    assert_eq!(&after_body[..64], u.sig_ed25519().as_slice());
    assert_eq!(&after_body[64..64 + 3309], u.sig_mldsa65().as_slice());
}

#[test]
fn domain_is_the_fixed_label() {
    assert_eq!(DOMAIN, b"kozane-peer-policy-v1\0");
}

// --- Verified / open ------------------------------------------------------

fn reply_bytes(slot: Slot, version: u32, body_sha256: [u8; 32]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(if slot == Slot::A { 0 } else { 1 });
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&body_sha256);
    out
}

#[test]
fn verified_from_reply_decodes_a_well_formed_reply() {
    let reply = reply_bytes(Slot::B, 7, [3; 32]);
    let v = Verified::from_reply(&reply).unwrap();
    assert_eq!((v.slot(), v.version(), *v.body_sha256()), (Slot::B, 7, [3; 32]));
}

#[test]
fn verified_from_reply_rejects_malformed_replies() {
    let good = reply_bytes(Slot::A, 1, [0; 32]);
    assert!(Verified::from_reply(&good[..good.len() - 1]).is_none());
    let mut too_long = good.clone();
    too_long.push(0);
    assert!(Verified::from_reply(&too_long).is_none());
    let mut bad_slot = good.clone();
    bad_slot[0] = 2;
    assert!(Verified::from_reply(&bad_slot).is_none());
    assert!(Verified::from_reply(&[]).is_none());
}

#[test]
fn open_accepts_a_token_matching_the_slots_version() {
    let slot = valid_slot();
    let b = parse(&slot, &node(), &fake_digest).unwrap();
    let token = Verified::from_reply(&reply_bytes(Slot::A, b.version(), [0; 32])).unwrap();
    assert!(open(&token, &slot, &node()).is_ok());
}

#[test]
fn open_refuses_a_token_at_the_wrong_version() {
    let slot = valid_slot();
    let token = Verified::from_reply(&reply_bytes(Slot::A, 999, [0; 32])).unwrap();
    assert_eq!(open(&token, &slot, &node()).unwrap_err(), Reject::Malformed);
}

// --- render -> parse round trip -----------------------------------------

#[test]
fn render_then_parse_round_trips_every_field() {
    let fx = Fixture::new(&[1, 2]);
    let peers = fx.peers(&[1, 2]);
    let groups = one_group();
    let plain = PlainBundle {
        fleet_id: FLEET,
        version: 42,
        min_release: 3,
        prev_sha256: [7; 32],
        roster_sha256: [8; 32],
        peers: &peers,
        groups: &groups,
        sig_ed25519: [1; 64],
        sig_mldsa65: [2; 3309],
    };
    let slot = render(&plain);
    assert_eq!(slot.len(), BUNDLE_MAX);
    let b = parse(&slot, &node(), &fake_digest).unwrap();
    assert_eq!(b.version(), 42);
    assert_eq!(b.min_release(), 3);
    assert_eq!(*b.prev_sha256(), [7; 32]);
    assert_eq!(*b.roster_sha256(), [8; 32]);
    for (i, byte) in [1u8, 2].into_iter().enumerate() {
        let p = b.peer(i as u8).unwrap();
        assert_eq!(*p.wg_pub(), [byte; 32]);
        assert_eq!(p.rp_pub().as_slice(), rp_fill(byte).as_slice());
        assert!(p.in_group(0));
    }
}

// --- select ---------------------------------------------------------------

fn valid(version: u32, min_release: u32, prev: [u8; 32], body: [u8; 32]) -> SlotView {
    SlotView::Valid { version, min_release, prev_sha256: prev, body_sha256: body }
}

#[test]
fn a_current_version_candidate_is_used() {
    assert_eq!(select(5, 0, valid(5, 0, [0; 32], [1; 32]), SlotView::Empty), Decision::Use { slot: Slot::A });
    assert_eq!(select(5, 0, SlotView::Empty, valid(5, 0, [0; 32], [1; 32])), Decision::Use { slot: Slot::B });
}

#[test]
fn a_next_version_candidate_whose_prev_matches_the_anchor_advances() {
    let anchor_body = [9; 32];
    let a = valid(5, 0, [0; 32], anchor_body);
    let b = valid(6, 0, anchor_body, [1; 32]);
    assert_eq!(select(5, 0, a, b), Decision::Advance { slot: Slot::B });
    assert_eq!(select(5, 0, b, a), Decision::Advance { slot: Slot::A });
}

#[test]
fn a_next_version_candidate_whose_prev_does_not_match_is_prev_mismatch() {
    let a = valid(5, 0, [0; 32], [9; 32]);
    let b = valid(6, 0, [77; 32], [1; 32]);
    assert_eq!(select(5, 0, a, b), Decision::Refuse { reason: Reject::PrevMismatch });
}

#[test]
fn a_next_version_candidate_needs_an_anchor_even_if_the_anchor_is_below_floor() {
    // The anchor counts whatever its own floor (M8 plan C5 "floor-lowering").
    let anchor_body = [9; 32];
    let a = valid(5, 100, [0; 32], anchor_body); // min_release above release_seq
    let b = valid(6, 0, anchor_body, [1; 32]);
    assert_eq!(select(5, 50, a, b), Decision::Advance { slot: Slot::B });
}

#[test]
fn two_candidates_at_the_same_version_with_different_bodies_are_equivocation() {
    let a = valid(5, 0, [0; 32], [1; 32]);
    let b = valid(5, 0, [0; 32], [2; 32]);
    assert_eq!(select(5, 0, a, b), Decision::Refuse { reason: Reject::Equivocation });
}

#[test]
fn two_candidates_at_the_same_version_with_identical_bodies_pick_slot_a() {
    let a = valid(5, 0, [0; 32], [1; 32]);
    let b = valid(5, 0, [0; 32], [1; 32]);
    assert_eq!(select(5, 0, a, b), Decision::Use { slot: Slot::A });
}

#[test]
fn a_rolled_back_slot_is_refused() {
    assert_eq!(select(5, 0, valid(4, 0, [0; 32], [1; 32]), SlotView::Empty), Decision::Refuse { reason: Reject::RolledBack });
}

#[test]
fn a_skipped_slot_is_refused() {
    assert_eq!(select(5, 0, valid(7, 0, [0; 32], [1; 32]), SlotView::Empty), Decision::Refuse { reason: Reject::Skipped });
}

#[test]
fn a_below_floor_slot_is_refused() {
    assert_eq!(select(5, 0, valid(5, 1, [0; 32], [1; 32]), SlotView::Empty), Decision::Refuse { reason: Reject::BelowFloor });
}

/// C9 [T17]: the boundary triple of the floor against the release `policy`
/// passes in (`RELEASE_SEQ` there): a bundle whose `min_release` is below or
/// equal to it is used, one above it is `BelowFloor`.
#[test]
fn min_release_below_equal_and_above_the_release_seq() {
    let release_seq = 7;
    for (min_release, want) in [
        (release_seq - 1, Decision::Use { slot: Slot::A }),
        (release_seq, Decision::Use { slot: Slot::A }),
        (release_seq + 1, Decision::Refuse { reason: Reject::BelowFloor }),
    ] {
        assert_eq!(select(5, release_seq, valid(5, min_release, [0; 32], [1; 32]), SlotView::Empty), want, "{min_release}");
    }
}

#[test]
fn a_bad_signature_slot_is_refused() {
    assert_eq!(select(5, 0, SlotView::BadSignature, SlotView::Empty), Decision::Refuse { reason: Reject::BadSignature });
}

#[test]
fn a_malformed_slot_is_refused() {
    assert_eq!(select(5, 0, SlotView::Malformed, SlotView::Empty), Decision::Refuse { reason: Reject::Malformed });
}

#[test]
fn both_slots_empty_is_refused_empty() {
    assert_eq!(select(5, 0, SlotView::Empty, SlotView::Empty), Decision::Refuse { reason: Reject::Empty });
}

#[test]
fn precedence_picks_the_worse_reason_when_neither_slot_is_a_candidate() {
    // BelowFloor outranks everything else.
    assert_eq!(select(5, 0, valid(5, 1, [0; 32], [1; 32]), SlotView::Malformed), Decision::Refuse { reason: Reject::BelowFloor });
    assert_eq!(select(5, 0, SlotView::Malformed, SlotView::Malformed), Decision::Refuse { reason: Reject::Malformed });
    // Skipped outranks RolledBack, BadSignature, Malformed and Empty.
    assert_eq!(select(5, 0, valid(7, 0, [0; 32], [1; 32]), valid(3, 0, [0; 32], [1; 32])), Decision::Refuse { reason: Reject::Skipped });
    // RolledBack outranks BadSignature, Malformed and Empty.
    assert_eq!(select(5, 0, valid(3, 0, [0; 32], [1; 32]), SlotView::BadSignature), Decision::Refuse { reason: Reject::RolledBack });
    // BadSignature outranks Malformed and Empty.
    assert_eq!(select(5, 0, SlotView::BadSignature, SlotView::Malformed), Decision::Refuse { reason: Reject::BadSignature });
    // Malformed outranks Empty.
    assert_eq!(select(5, 0, SlotView::Malformed, SlotView::Empty), Decision::Refuse { reason: Reject::Malformed });
}

/// I5.1: a lone `current+1` slot is never used without its anchor,
/// whatever the other slot is (the allow side: an anchor present advances,
/// above).
#[test]
fn a_next_version_candidate_without_an_anchor_is_prev_mismatch() {
    let next = valid(6, 0, [9; 32], [1; 32]);
    for other in [SlotView::Empty, SlotView::Malformed, SlotView::BadSignature, valid(4, 0, [0; 32], [9; 32])] {
        assert_eq!(select(5, 0, next, other), Decision::Refuse { reason: Reject::PrevMismatch }, "{other:?}");
        assert_eq!(select(5, 0, other, next), Decision::Refuse { reason: Reject::PrevMismatch }, "{other:?}");
    }
}

#[test]
fn current_plus_one_overflow_never_makes_u32_max_plus_one_a_candidate() {
    let a = valid(u32::MAX, 0, [0; 32], [1; 32]);
    assert_eq!(select(u32::MAX, 0, a, SlotView::Empty), Decision::Use { slot: Slot::A });
}

// --- init step machine ----------------------------------------------------

const PCR9: [u8; 32] = [4; 32];

#[test]
fn a_refused_state_reply_is_unavailable() {
    let step = after_state(StateReply::Refused, &PCR9, 0, SlotView::Empty, SlotView::Empty);
    assert_eq!(step, Step::Done(Outcome::Unavailable { reason: Reject::StateRefused }));
}

#[test]
fn a_pcr9_mismatch_is_unavailable() {
    let reply = StateReply::Ok { current: 5, pcr9: [0; 32] };
    let step = after_state(reply, &PCR9, 0, SlotView::Empty, SlotView::Empty);
    assert_eq!(step, Step::Done(Outcome::Unavailable { reason: Reject::MeasureMismatch }));
}

#[test]
fn a_use_decision_finishes_as_verified_at_the_current_version() {
    let reply = StateReply::Ok { current: 5, pcr9: PCR9 };
    let a = valid(5, 0, [0; 32], [1; 32]);
    let step = after_state(reply, &PCR9, 0, a, SlotView::Empty);
    assert_eq!(step, Step::Done(Outcome::Verified { slot: Slot::A, version: 5, body_sha256: [1; 32] }));
}

#[test]
fn an_advance_decision_is_pending_until_the_advance_reply_arrives() {
    let reply = StateReply::Ok { current: 5, pcr9: PCR9 };
    let anchor_body = [9; 32];
    let a = valid(5, 0, [0; 32], anchor_body);
    let b = valid(6, 0, anchor_body, [1; 32]);
    let step = after_state(reply, &PCR9, 0, a, b);
    let Step::Advance(pending) = step else { panic!("expected Advance, got {step:?}") };
    assert_eq!(after_advance(pending, AdvanceReply::Ok(6)), Outcome::Verified { slot: Slot::B, version: 6, body_sha256: [1; 32] });
}

#[test]
fn advance_refused_is_unavailable_with_no_fallback() {
    let reply = StateReply::Ok { current: 5, pcr9: PCR9 };
    let anchor_body = [9; 32];
    let a = valid(5, 0, [0; 32], anchor_body);
    let b = valid(6, 0, anchor_body, [1; 32]);
    let Step::Advance(pending) = after_state(reply, &PCR9, 0, a, b) else { panic!("expected Advance") };
    assert_eq!(after_advance(pending, AdvanceReply::Refused), Outcome::Unavailable { reason: Reject::AdvanceFailed });
}

#[test]
fn advance_returning_the_wrong_value_is_unavailable() {
    let reply = StateReply::Ok { current: 5, pcr9: PCR9 };
    let anchor_body = [9; 32];
    let a = valid(5, 0, [0; 32], anchor_body);
    let b = valid(6, 0, anchor_body, [1; 32]);
    let Step::Advance(pending) = after_state(reply, &PCR9, 0, a, b) else { panic!("expected Advance") };
    assert_eq!(after_advance(pending, AdvanceReply::Ok(5)), Outcome::Unavailable { reason: Reject::AdvanceFailed });
    assert_eq!(after_advance(pending, AdvanceReply::Ok(7)), Outcome::Unavailable { reason: Reject::AdvanceFailed });
}

#[test]
fn a_refuse_decision_finishes_unavailable_with_its_reason() {
    let reply = StateReply::Ok { current: 5, pcr9: PCR9 };
    let step = after_state(reply, &PCR9, 0, SlotView::Empty, SlotView::Empty);
    assert_eq!(step, Step::Done(Outcome::Unavailable { reason: Reject::Empty }));
}

// --- bolero: parse never panics, render -> parse round-trips ------------

/// Builds a small, always-structurally-valid bundle whose content varies
/// with `bytes`: one peer (allowed IPs in `10.<b0>.0.0/24`, never
/// overlapping `node()`'s fields) and one group with one rule whose
/// proto/ports vary too. Exercises I1.3's round trip over varying content
/// without needing a `TypeGenerator` for the whole format.
fn fuzz_one(bytes: &[u8]) {
    let b0 = bytes.first().copied().unwrap_or(0);
    let b1 = bytes.get(1).copied().unwrap_or(0);
    // Never the gateway's own wg_pub or rp_pub fill byte (both would make
    // `parse` correctly reject the bundle, which this round trip is not
    // about).
    let wg_byte = if b0 == GATEWAY_WG[0] { b0 ^ 1 } else { b0 };
    let wg = [wg_byte; 32];
    let rp_byte = {
        let f = b0.wrapping_add(1);
        if f == GATEWAY_RP_FILL { f ^ 1 } else { f }
    };
    let rp = rp_fill(rp_byte);
    let allowed = [Prefix { addr: [10, 100, 0, 0], len: 24 }];
    let peer = PlainPeer { wg_pub: wg, rp_pub: rp.as_slice().try_into().unwrap(), groups: u8::from(b1 & 1 == 1), allowed: &allowed };
    let proto = match b1 % 3 {
        0 => PROTO_TCP,
        1 => PROTO_UDP,
        _ => PROTO_ICMP,
    };
    let (port_lo, port_hi) = if proto == PROTO_ICMP { (0, 0) } else { (u16::from(b1), u16::from(b1).saturating_add(1)) };
    let rules = [Rule { dst: Prefix { addr: [10, 60, 0, 0], len: 24 }, proto, port_lo, port_hi }];
    let groups = [PlainGroup { rules: &rules }];
    // The header and the signature bytes vary with the input too, so the
    // byte-identity check below sees every accessor (`parse` does not look
    // at signatures).
    let mut plain = base_bundle(core::slice::from_ref(&peer), &groups);
    let word = |at: usize| u32::from_be_bytes(core::array::from_fn(|i| bytes.get(at + i).copied().unwrap_or(0)));
    plain.version = word(2);
    plain.min_release = word(6);
    plain.prev_sha256 = [bytes.get(10).copied().unwrap_or(0); 32];
    plain.roster_sha256 = [bytes.get(11).copied().unwrap_or(0); 32];
    plain.sig_ed25519 = [bytes.get(12).copied().unwrap_or(0); 64];
    plain.sig_mldsa65 = [bytes.get(13).copied().unwrap_or(0); 3309];
    let slot = render(&plain);
    let parsed = parse(&slot, &node(), &fake_digest).unwrap();
    assert_eq!(parsed.version(), plain.version);
    let p = parsed.peer(0).unwrap();
    assert_eq!(*p.wg_pub(), wg);
    let rules_again: Vec<Rule> = parsed.group(0).unwrap().rules().collect();
    assert_eq!(rules_again, rules);

    // I1.3 byte for byte: the slot re-rendered from what `parse` returned
    // (and `split`'s signatures) is the slot.
    let u = split(&slot).unwrap();
    let views: Vec<_> = (0..parsed.peer_count()).map(|i| parsed.peer(i).unwrap()).collect();
    let allowed_again: Vec<Vec<Prefix>> = views.iter().map(|p| p.allowed().collect()).collect();
    let peers_again: Vec<PlainPeer> = views
        .iter()
        .zip(&allowed_again)
        .map(|(p, a)| PlainPeer { wg_pub: *p.wg_pub(), rp_pub: p.rp_pub(), groups: p.groups(), allowed: a })
        .collect();
    let group_rules: Vec<Vec<Rule>> = (0..parsed.group_count()).map(|g| parsed.group(g).unwrap().rules().collect()).collect();
    let groups_again: Vec<PlainGroup> = group_rules.iter().map(|r| PlainGroup { rules: r }).collect();
    let again = render(&PlainBundle {
        fleet_id: FLEET,
        version: parsed.version(),
        min_release: parsed.min_release(),
        prev_sha256: *parsed.prev_sha256(),
        roster_sha256: *parsed.roster_sha256(),
        peers: &peers_again,
        groups: &groups_again,
        sig_ed25519: *u.sig_ed25519(),
        sig_mldsa65: *u.sig_mldsa65(),
    });
    assert!(again == slot, "the re-rendered slot differs");

    // Parse and split never panic on a valid slot with a window of it
    // overwritten by the input, at an offset the input picks among the
    // header, the peer entry, the group and the signatures: every
    // structural branch sees arbitrary bytes at full slot length.
    let mut mutated = slot.clone();
    let rest = bytes.get(2..).unwrap_or(&[]);
    // The last window starts 16 bytes before the signatures (the body's
    // end), so it reaches into them.
    let sig_at = split(&slot).unwrap().body().len();
    let anchors = [0usize, 96, 96 + 32 + limits::SPK_LEN, sig_at - 16];
    let at = anchors[usize::from(b1) % anchors.len()] + usize::from(b0 % 16);
    for (i, &b) in rest.iter().take(64).enumerate() {
        if let Some(m) = mutated.get_mut(at + i) {
            *m = b;
        }
    }
    let _ = parse(&mutated, &node(), &fake_digest);
    let _ = split(&mutated);
    let _ = header(&mutated);
}

#[test]
fn fuzz_render_round_trips_and_parse_never_panics() {
    bolero::check!().for_each(fuzz_one);
}

// --- the `policy` PD's reply and audit helpers (M8 slice 3) ---------------

#[test]
fn a_verified_reply_decodes_to_the_same_token() {
    for (slot, version, body) in [(Slot::A, 0, [0; 32]), (Slot::B, u32::MAX, [0xA5; 32]), (Slot::A, 0x0102_0304, [7; 32])] {
        let reply = verified_reply(slot, version, &body);
        let token = Verified::from_reply(&reply).unwrap();
        assert_eq!((token.slot(), token.version(), token.body_sha256()), (slot, version, &body));
    }
    assert_eq!(verified_reply(Slot::B, 0x0102_0304, &[7; 32])[..5], [1, 1, 2, 3, 4]);
    assert_eq!((Slot::A.index(), Slot::B.index()), (0, 1));
}

/// `not_candidate` is `select`'s own classification: the version window
/// `{current, current+1}` and the floor's boundary triple (C9: below,
/// equal, above `release_seq`).
#[test]
fn not_candidate_follows_selects_classification() {
    assert_eq!(not_candidate(5, 0, SlotView::Empty), Some(Reject::Empty));
    assert_eq!(not_candidate(5, 0, SlotView::Malformed), Some(Reject::Malformed));
    assert_eq!(not_candidate(5, 0, SlotView::BadSignature), Some(Reject::BadSignature));
    assert_eq!(not_candidate(5, 0, valid(4, 0, [0; 32], [1; 32])), Some(Reject::RolledBack));
    assert_eq!(not_candidate(5, 0, valid(5, 0, [0; 32], [1; 32])), None);
    assert_eq!(not_candidate(5, 0, valid(6, 0, [0; 32], [1; 32])), None);
    assert_eq!(not_candidate(5, 0, valid(7, 0, [0; 32], [1; 32])), Some(Reject::Skipped));
    assert_eq!(not_candidate(5, 3, valid(5, 2, [0; 32], [1; 32])), None);
    assert_eq!(not_candidate(5, 3, valid(5, 3, [0; 32], [1; 32])), None);
    assert_eq!(not_candidate(5, 3, valid(5, 4, [0; 32], [1; 32])), Some(Reject::BelowFloor));
    assert_eq!(not_candidate(u32::MAX, 0, valid(0, 0, [0; 32], [1; 32])), Some(Reject::RolledBack));
}

/// `Reject::ALL` lists every reason once, in code order, under its Debug
/// name (the audit table the `policy` PD checks mirrors it).
#[test]
fn reject_all_is_every_reason_in_code_order() {
    for (i, r) in Reject::ALL.iter().enumerate() {
        assert_eq!(usize::from(r.code()), i);
        assert_eq!(r.name(), std::format!("{r:?}"));
    }
}
