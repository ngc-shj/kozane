#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::panic)]

extern crate std;

use std::vec::Vec;

use super::*;
use wire::{MAX_FRAME, Udp4};

const GW_MAC: Mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x57];
const GW_IP: Ipv4 = [10, 99, 0, 1];
const HOST_MAC: Mac = [0x02, 0, 0, 0, 0x99, 0x02];
const HOST_IP: Ipv4 = [10, 99, 0, 2];
const OTHER_MAC: Mac = [0x02, 0, 0, 0, 0x99, 0x03];
const PEER_IP: Ipv4 = [10, 200, 0, 2];
const NEIGHBORS: &[(Ipv4, Mac)] = &[(HOST_IP, HOST_MAC)];
const CFG: Config<'static> = Config { mac: GW_MAC, ipv4: GW_IP, neighbors: NEIGHBORS };

fn emit(f: &Frame<'_>) -> Vec<u8> {
    let mut out = [0u8; MAX_FRAME];
    let n = wire::emit(f, &mut out).unwrap();
    out[..n].to_vec()
}

/// An IPv4 datagram built via the UDP emitter (any valid datagram will do).
fn datagram(src: Ipv4, dst: Ipv4) -> Vec<u8> {
    let f = Frame {
        eth: EthAddrs { src: HOST_MAC, dst: GW_MAC },
        body: Body::Udp4(Udp4 { src, dst, sport: 1, dport: 2, payload: b"ping" }),
    };
    emit(&f)[wire::ETH_HDR..].to_vec()
}

fn lan_frame(src_mac: Mac, dst_mac: Mac, src: Ipv4, dst: Ipv4) -> Vec<u8> {
    let mut b = std::vec![0u8; 0];
    b.extend_from_slice(&dst_mac);
    b.extend_from_slice(&src_mac);
    b.extend_from_slice(&[0x08, 0x00]);
    b.extend_from_slice(&datagram(src, dst));
    b
}

fn arp(op: ArpOp, sha: Mac, eth_src: Mac, spa: Ipv4, tpa: Ipv4) -> Vec<u8> {
    emit(&Frame {
        eth: EthAddrs { src: eth_src, dst: [0xff; 6] },
        body: Body::Arp(ArpPacket { op, sha, spa, tha: [0; 6], tpa }),
    })
}

fn from(frame: &[u8]) -> FromLan<'_> {
    from_lan(&CFG, frame, &mut [0u8; MAX_FRAME])
}

#[test]
fn neighbor_traffic_is_forwarded_verbatim() {
    let b = lan_frame(HOST_MAC, GW_MAC, HOST_IP, PEER_IP);
    assert_eq!(from(&b), FromLan::Forward(&b[wire::ETH_HDR..]));
}

#[test]
fn neighbor_ip_from_another_mac_is_spoofed() {
    assert_eq!(from(&lan_frame(OTHER_MAC, GW_MAC, HOST_IP, PEER_IP)), FromLan::Spoofed);
}

#[test]
fn unknown_source_ip_is_spoofed() {
    assert_eq!(from(&lan_frame(HOST_MAC, GW_MAC, [10, 99, 0, 9], PEER_IP)), FromLan::Spoofed);
}

#[test]
fn ipv4_for_another_mac_is_not_for_us() {
    assert_eq!(from(&lan_frame(HOST_MAC, OTHER_MAC, HOST_IP, PEER_IP)), FromLan::NotForUs);
}

#[test]
fn ipv4_to_the_gateway_itself_has_no_service() {
    assert_eq!(from(&lan_frame(HOST_MAC, GW_MAC, HOST_IP, GW_IP)), FromLan::NoService);
}

#[test]
fn arp_request_from_neighbor_is_answered_to_the_neighbor() {
    let mut out = [0u8; MAX_FRAME];
    let req = arp(ArpOp::Request, HOST_MAC, HOST_MAC, HOST_IP, GW_IP);
    let FromLan::ArpReplied(n) = from_lan(&CFG, &req, &mut out) else { panic!("no reply") };
    let f = wire::parse_frame_ip(&out[..n]).unwrap();
    assert_eq!(f.eth, EthAddrs { src: GW_MAC, dst: HOST_MAC });
    assert_eq!(
        f.body,
        Body::Arp(ArpPacket { op: ArpOp::Reply, sha: GW_MAC, spa: GW_IP, tha: HOST_MAC, tpa: HOST_IP })
    );
}

#[test]
fn arp_from_a_non_neighbor_is_spoofed() {
    assert_eq!(from(&arp(ArpOp::Request, OTHER_MAC, OTHER_MAC, HOST_IP, GW_IP)), FromLan::Spoofed);
}

#[test]
fn arp_with_sender_differing_from_ethernet_source_is_spoofed() {
    assert_eq!(from(&arp(ArpOp::Request, HOST_MAC, OTHER_MAC, HOST_IP, GW_IP)), FromLan::Spoofed);
}

#[test]
fn arp_for_another_address_is_not_for_us() {
    assert_eq!(from(&arp(ArpOp::Request, HOST_MAC, HOST_MAC, HOST_IP, [10, 99, 0, 7])), FromLan::NotForUs);
}

#[test]
fn arp_reply_has_no_service() {
    assert_eq!(from(&arp(ArpOp::Reply, HOST_MAC, HOST_MAC, HOST_IP, GW_IP)), FromLan::NoService);
}

#[test]
fn malformed_frame_is_dropped_with_its_reason() {
    assert_eq!(from(&[0u8; 5]), FromLan::Dropped(DropReason::TooShort));
}

#[test]
fn decrypted_packet_for_neighbor_is_framed_to_its_mac() {
    let p = datagram(PEER_IP, HOST_IP);
    let mut out = [0u8; MAX_FRAME];
    let ToLan::Emitted(n) = to_lan(&CFG, &p, &mut out) else { panic!("not emitted") };
    assert_eq!(&out[..6], &HOST_MAC);
    assert_eq!(&out[6..12], &GW_MAC);
    assert_eq!(&out[wire::ETH_HDR..n], &p[..]);
}

#[test]
fn decrypted_packet_for_unknown_host_is_refused() {
    assert_eq!(to_lan(&CFG, &datagram(PEER_IP, [10, 99, 0, 9]), &mut [0u8; MAX_FRAME]), ToLan::UnknownNeighbor);
}

#[test]
fn malformed_decrypted_packet_is_dropped() {
    let mut p = datagram(PEER_IP, HOST_IP);
    p[10] ^= 1;
    assert_eq!(to_lan(&CFG, &p, &mut [0u8; MAX_FRAME]), ToLan::Dropped(DropReason::Ipv4BadChecksum));
}

#[test]
fn small_output_buffer_is_reported_not_panicked() {
    assert_eq!(to_lan(&CFG, &datagram(PEER_IP, HOST_IP), &mut [0u8; 20]), ToLan::NoBuffer);
}
