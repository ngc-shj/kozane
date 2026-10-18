#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::panic)]

extern crate std;

use std::vec::Vec;

use super::*;

const CFG: Config = Config { mac: [0x52, 0x54, 0, 0x12, 0x34, 0x56], ipv4: [10, 0, 2, 15], echo_port: 7 };
const PEER_MAC: Mac = [0x52, 0x55, 10, 0, 2, 2];
const PEER_IP: Ipv4 = [10, 0, 2, 2];

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

fn run(frame: &[u8]) -> (Outcome, Vec<u8>) {
    let mut out = [0u8; wire::MAX_FRAME];
    let o = respond(&CFG, frame, &mut out);
    let n = match o {
        Outcome::ArpReplied(n) | Outcome::UdpEchoed(n) => n,
        _ => 0,
    };
    (o, out[..n].to_vec())
}

#[cfg(not(feature = "echo"))]
#[test]
fn without_echo_feature_udp_to_echo_port_is_no_service() {
    assert_eq!(run(&udp_to(CFG.mac, CFG.ipv4, 7, b"nonce-42")).0, Outcome::NoService);
}

#[cfg(feature = "echo")]
#[test]
fn echoes_udp_with_swapped_addresses_and_same_payload() {
    let (o, reply) = run(&udp_to(CFG.mac, CFG.ipv4, 7, b"nonce-42"));
    assert!(matches!(o, Outcome::UdpEchoed(_)));
    let f = wire::parse_frame(&reply).unwrap();
    assert_eq!(f.eth, EthAddrs { src: CFG.mac, dst: PEER_MAC });
    let Body::Udp4(u) = f.body else { panic!("not udp") };
    assert_eq!((u.src, u.dst, u.sport, u.dport, u.payload), (CFG.ipv4, PEER_IP, 7, 40000, &b"nonce-42"[..]));
}

#[test]
fn answers_broadcast_arp_request_for_our_ip() {
    let (o, reply) = run(&arp(ArpOp::Request, [0xff; 6], CFG.ipv4));
    assert!(matches!(o, Outcome::ArpReplied(_)));
    let f = wire::parse_frame(&reply).unwrap();
    assert_eq!(f.eth.dst, PEER_MAC);
    let Body::Arp(a) = f.body else { panic!("not arp") };
    assert_eq!((a.op, a.sha, a.spa, a.tha, a.tpa), (ArpOp::Reply, CFG.mac, CFG.ipv4, PEER_MAC, PEER_IP));
}

#[test]
fn answers_unicast_arp_request_to_our_mac() {
    assert!(matches!(run(&arp(ArpOp::Request, CFG.mac, CFG.ipv4)).0, Outcome::ArpReplied(_)));
}

#[test]
fn arp_for_other_ip_is_not_for_us() {
    assert_eq!(run(&arp(ArpOp::Request, [0xff; 6], [10, 0, 2, 16])).0, Outcome::NotForUs);
}

#[test]
fn arp_to_other_unicast_mac_is_not_for_us() {
    assert_eq!(run(&arp(ArpOp::Request, PEER_MAC, CFG.ipv4)).0, Outcome::NotForUs);
}

#[test]
fn arp_reply_to_us_is_no_service() {
    assert_eq!(run(&arp(ArpOp::Reply, CFG.mac, CFG.ipv4)).0, Outcome::NoService);
}

#[test]
fn udp_to_other_mac_or_ip_is_not_for_us() {
    assert_eq!(run(&udp_to(PEER_MAC, CFG.ipv4, 7, b"x")).0, Outcome::NotForUs);
    assert_eq!(run(&udp_to([0xff; 6], CFG.ipv4, 7, b"x")).0, Outcome::NotForUs);
    assert_eq!(run(&udp_to(CFG.mac, [10, 0, 2, 16], 7, b"x")).0, Outcome::NotForUs);
}

#[test]
fn udp_to_other_port_is_no_service() {
    assert_eq!(run(&udp_to(CFG.mac, CFG.ipv4, 8, b"x")).0, Outcome::NoService);
}

#[test]
fn udp_from_echo_port_is_not_answered() {
    let f = build(&Frame {
        eth: EthAddrs { src: PEER_MAC, dst: CFG.mac },
        body: Body::Udp4(Udp4 { src: PEER_IP, dst: CFG.ipv4, sport: 7, dport: 7, payload: b"x" }),
    });
    assert_eq!(run(&f).0, Outcome::NoService);
}

#[test]
fn udp_claiming_our_own_source_ip_is_spoofed() {
    let f = build(&Frame {
        eth: EthAddrs { src: PEER_MAC, dst: CFG.mac },
        body: Body::Udp4(Udp4 { src: CFG.ipv4, dst: CFG.ipv4, sport: 40000, dport: 7, payload: b"x" }),
    });
    assert_eq!(run(&f).0, Outcome::Spoofed);
}

#[test]
fn arp_with_sender_mac_differing_from_ethernet_source_is_spoofed() {
    let f = build(&Frame {
        eth: EthAddrs { src: PEER_MAC, dst: [0xff; 6] },
        body: Body::Arp(ArpPacket { op: ArpOp::Request, sha: [0x52, 0x55, 1, 2, 3, 4], spa: PEER_IP, tha: [0; 6], tpa: CFG.ipv4 }),
    });
    assert_eq!(run(&f).0, Outcome::Spoofed);
}

#[test]
fn arp_claiming_our_own_ip_is_spoofed() {
    let f = build(&Frame {
        eth: EthAddrs { src: PEER_MAC, dst: [0xff; 6] },
        body: Body::Arp(ArpPacket { op: ArpOp::Request, sha: PEER_MAC, spa: CFG.ipv4, tha: [0; 6], tpa: CFG.ipv4 }),
    });
    assert_eq!(run(&f).0, Outcome::Spoofed);
}

#[test]
fn frames_from_our_own_mac_are_spoofed() {
    let udp = build(&Frame {
        eth: EthAddrs { src: CFG.mac, dst: CFG.mac },
        body: Body::Udp4(Udp4 { src: PEER_IP, dst: CFG.ipv4, sport: 40000, dport: 7, payload: b"x" }),
    });
    assert_eq!(run(&udp).0, Outcome::Spoofed);
    let arp = build(&Frame {
        eth: EthAddrs { src: CFG.mac, dst: [0xff; 6] },
        body: Body::Arp(ArpPacket { op: ArpOp::Request, sha: CFG.mac, spa: PEER_IP, tha: [0; 6], tpa: CFG.ipv4 }),
    });
    assert_eq!(run(&arp).0, Outcome::Spoofed);
}

#[test]
fn malformed_frame_reports_parser_reason() {
    assert_eq!(run(&[0u8; 10]).0, Outcome::Dropped(DropReason::TooShort));
}

#[test]
fn too_small_output_buffer_does_not_panic() {
    let mut out = [0u8; 20];
    assert_eq!(respond(&CFG, &udp_to(CFG.mac, CFG.ipv4, 7, b"x"), &mut out), Outcome::NoService);
}
