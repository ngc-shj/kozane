#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::panic)]

extern crate std;

use std::vec::Vec;

use super::*;

const CFG: Config =
    Config { mac: [0x52, 0x54, 0, 0x12, 0x34, 0x56], ipv4: [10, 0, 2, 15], router_mac: [0x52, 0x55, 10, 0, 2, 2], port: 51820 };
const PEER_MAC: Mac = [0x52, 0x55, 10, 0, 2, 2];
const PEER_IP: Ipv4 = [10, 0, 2, 2];
const SRC: Endpoint = Endpoint { ip: PEER_IP, port: 40000 };

/// mac1 is valid iff byte 116 (its first byte) is 0x11.
struct FakeMac1;

impl Mac1 for FakeMac1 {
    fn verify(&self, msg: &[u8; INITIATION_LEN]) -> bool {
        msg[wg_wire::INITIATION_MAC1_OFFSET] == 0x11
    }
}

fn initiation(mac1_ok: bool) -> Vec<u8> {
    let mut m = std::vec![0u8; INITIATION_LEN];
    m[0] = MSG_INITIATION;
    m[wg_wire::INITIATION_MAC1_OFFSET] = if mac1_ok { 0x11 } else { 0x22 };
    m
}

fn transport(len: usize) -> Vec<u8> {
    let mut m = std::vec![0u8; len];
    m[0] = MSG_TRANSPORT;
    m
}

fn build(f: &Frame<'_>) -> Vec<u8> {
    let mut out = [0u8; wire::MAX_FRAME];
    let n = wire::emit(f, &mut out).unwrap();
    out[..n].to_vec()
}

fn udp_to(dst_mac: Mac, dst_ip: Ipv4, dport: u16, payload: &[u8]) -> Vec<u8> {
    build(&Frame {
        eth: EthAddrs { src: PEER_MAC, dst: dst_mac },
        body: Body::Udp4(Udp4 { src: PEER_IP, dst: dst_ip, sport: 40000, dport, payload }),
    })
}

fn arp(op: ArpOp, dst_mac: Mac, tpa: Ipv4) -> Vec<u8> {
    build(&Frame {
        eth: EthAddrs { src: PEER_MAC, dst: dst_mac },
        body: Body::Arp(ArpPacket { op, sha: PEER_MAC, spa: PEER_IP, tha: [0; 6], tpa }),
    })
}

fn run(frame: &[u8]) -> Outcome<'_> {
    respond(&CFG, &FakeMac1, &mut Buckets::<4>::default(), 0, frame, &mut [0u8; wire::MAX_FRAME])
}

fn class(payload: &[u8]) -> Outcome<'_> {
    classify(&FakeMac1, &mut Buckets::<4>::default(), 0, SRC, payload)
}

#[test]
fn valid_initiation_on_the_listen_port_goes_to_hs() {
    let m = initiation(true);
    let f = udp_to(CFG.mac, CFG.ipv4, CFG.port, &m);
    let Outcome::Initiation { src, msg } = run(&f) else { panic!("not forwarded") };
    assert_eq!(src, SRC);
    assert_eq!(&msg[..], &m[..]);
}

#[test]
fn transport_message_goes_to_data() {
    let m = transport(TRANSPORT_MIN_LEN);
    let f = udp_to(CFG.mac, CFG.ipv4, CFG.port, &m);
    assert_eq!(run(&f), Outcome::Transport { src: SRC, msg: &f[f.len() - m.len()..] });
}

#[test]
fn initiation_with_bad_mac1_is_dropped() {
    assert_eq!(class(&initiation(false)), Outcome::BadMac1);
}

#[test]
fn initiation_of_wrong_length_is_bad() {
    let mut m = initiation(true);
    m.push(0);
    assert_eq!(class(&m), Outcome::BadMessage);
    assert_eq!(class(&m[..INITIATION_LEN - 1]), Outcome::BadMessage);
}

#[test]
fn short_transport_is_bad() {
    assert_eq!(class(&transport(TRANSPORT_MIN_LEN - 1)), Outcome::BadMessage);
}

#[test]
fn responses_and_cookie_replies_are_not_accepted_by_a_responder() {
    for kind in [2u8, 3] {
        let mut m = transport(92);
        m[0] = kind;
        assert_eq!(class(&m), Outcome::BadMessage);
    }
}

#[test]
fn nonzero_reserved_bytes_are_bad() {
    let mut m = transport(64);
    m[2] = 1;
    assert_eq!(class(&m), Outcome::BadMessage);
}

#[test]
fn empty_payload_is_bad() {
    assert_eq!(class(&[]), Outcome::BadMessage);
}

#[test]
fn initiations_beyond_the_burst_are_rate_limited_then_refill() {
    let mut b = Buckets::<4>::default();
    let m = initiation(true);
    for _ in 0..BURST {
        assert!(matches!(classify(&FakeMac1, &mut b, 0, SRC, &m), Outcome::Initiation { .. }));
    }
    assert_eq!(classify(&FakeMac1, &mut b, 0, SRC, &m), Outcome::RateLimited);
    assert!(matches!(classify(&FakeMac1, &mut b, INTERVAL_NS, SRC, &m), Outcome::Initiation { .. }));
}

#[test]
fn bad_mac1_does_not_spend_the_budget() {
    let mut b = Buckets::<4>::default();
    for _ in 0..100 {
        assert_eq!(classify(&FakeMac1, &mut b, 0, SRC, &initiation(false)), Outcome::BadMac1);
    }
    assert!(matches!(classify(&FakeMac1, &mut b, 0, SRC, &initiation(true)), Outcome::Initiation { .. }));
}

#[test]
fn sources_have_separate_budgets() {
    let mut b = Buckets::<4>::default();
    for _ in 0..BURST {
        assert!(b.allow(PEER_IP, 0));
    }
    assert!(!b.allow(PEER_IP, 0));
    assert!(b.allow([10, 0, 2, 3], 0));
}

#[test]
fn a_full_table_evicts_the_least_recently_used_source() {
    let mut b = Buckets::<2>::default();
    for _ in 0..BURST {
        assert!(b.allow([1, 1, 1, 1], 10));
    }
    assert!(b.allow([2, 2, 2, 2], 20));
    // Third source evicts [1,1,1,1] (oldest), which then starts fresh.
    assert!(b.allow([3, 3, 3, 3], 30));
    assert!(b.allow([1, 1, 1, 1], 40));
}

#[test]
fn a_clock_going_backwards_refills_nothing() {
    let mut b = Buckets::<1>::default();
    for _ in 0..BURST {
        assert!(b.allow(PEER_IP, u64::MAX / 2));
    }
    assert!(!b.allow(PEER_IP, 0));
}

#[test]
fn wireguard_on_another_port_is_no_service() {
    assert_eq!(run(&udp_to(CFG.mac, CFG.ipv4, 7, &initiation(true))), Outcome::NoService);
}

#[test]
fn udp_to_other_mac_or_ip_is_not_for_us() {
    let m = transport(32);
    assert_eq!(run(&udp_to(PEER_MAC, CFG.ipv4, CFG.port, &m)), Outcome::NotForUs);
    assert_eq!(run(&udp_to([0xff; 6], CFG.ipv4, CFG.port, &m)), Outcome::NotForUs);
    assert_eq!(run(&udp_to(CFG.mac, [10, 0, 2, 16], CFG.port, &m)), Outcome::NotForUs);
}

#[test]
fn udp_claiming_our_own_source_ip_is_spoofed() {
    let f = build(&Frame {
        eth: EthAddrs { src: PEER_MAC, dst: CFG.mac },
        body: Body::Udp4(Udp4 { src: CFG.ipv4, dst: CFG.ipv4, sport: 40000, dport: CFG.port, payload: b"x" }),
    });
    assert_eq!(run(&f), Outcome::Spoofed);
}

#[test]
fn answers_broadcast_arp_request_for_our_ip() {
    let mut out = [0u8; wire::MAX_FRAME];
    let req = arp(ArpOp::Request, [0xff; 6], CFG.ipv4);
    let Outcome::ArpReplied(n) = respond(&CFG, &FakeMac1, &mut Buckets::<1>::default(), 0, &req, &mut out) else {
        panic!("no reply")
    };
    let f = wire::parse_frame(&out[..n]).unwrap();
    assert_eq!(f.eth.dst, PEER_MAC);
    let Body::Arp(a) = f.body else { panic!("not arp") };
    assert_eq!((a.op, a.sha, a.spa, a.tha, a.tpa), (ArpOp::Reply, CFG.mac, CFG.ipv4, PEER_MAC, PEER_IP));
}

#[test]
fn arp_for_other_ip_is_not_for_us() {
    assert_eq!(run(&arp(ArpOp::Request, [0xff; 6], [10, 0, 2, 16])), Outcome::NotForUs);
}

#[test]
fn arp_reply_to_us_is_no_service() {
    assert_eq!(run(&arp(ArpOp::Reply, CFG.mac, CFG.ipv4)), Outcome::NoService);
}

#[test]
fn arp_with_sender_mac_differing_from_ethernet_source_is_spoofed() {
    let f = build(&Frame {
        eth: EthAddrs { src: PEER_MAC, dst: [0xff; 6] },
        body: Body::Arp(ArpPacket { op: ArpOp::Request, sha: [0x52, 0x55, 1, 2, 3, 4], spa: PEER_IP, tha: [0; 6], tpa: CFG.ipv4 }),
    });
    assert_eq!(run(&f), Outcome::Spoofed);
}

#[test]
fn malformed_frame_reports_parser_reason() {
    assert_eq!(run(&[0u8; 10]), Outcome::Dropped(DropReason::TooShort));
}

#[test]
fn emit_udp_goes_from_the_listen_port_to_the_router() {
    let mut out = [0u8; wire::MAX_FRAME];
    let n = emit_udp(&CFG, SRC, b"resp", &mut out).unwrap();
    let f = wire::parse_frame(&out[..n]).unwrap();
    assert_eq!(f.eth, EthAddrs { src: CFG.mac, dst: CFG.router_mac });
    let Body::Udp4(u) = f.body else { panic!("not udp") };
    assert_eq!((u.src, u.sport, u.dst, u.dport, u.payload), (CFG.ipv4, CFG.port, PEER_IP, 40000, &b"resp"[..]));
}
