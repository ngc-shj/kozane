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
const OTHER_HOST_IP: Ipv4 = [10, 99, 0, 3];
const OTHER_HOST_MAC: Mac = [0x02, 0, 0, 0, 0x99, 0x04];
const NEIGHBORS: &[(Ipv4, Mac)] = &[(HOST_IP, HOST_MAC), (OTHER_HOST_IP, OTHER_HOST_MAC)];
/// The backend is `HOST_IP`; `tls` owns ports 40000..=41023.
const BACKEND_PORT: u16 = 8080;
const TLS_START: u16 = 40000;
const TLS_LAST: u16 = 41023;
const CFG: Config<'static> = Config {
    mac: GW_MAC,
    ipv4: GW_IP,
    neighbors: NEIGHBORS,
    backend: (HOST_IP, BACKEND_PORT),
    tls_ports: (TLS_START, 1024),
};

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

fn from(frame: &[u8]) -> FromLan {
    from_lan(&CFG, frame, &mut [0u8; MAX_FRAME])
}

/// `p` with its TTL lowered by one and the header checksum recomputed.
fn hopped(p: &[u8]) -> Vec<u8> {
    let mut h = p.to_vec();
    set_ttl(&mut h, p[8] - 1);
    h
}

fn set_ttl(p: &mut [u8], ttl: u8) {
    // Recompute the checksum so the parser accepts it: only TTL is under test.
    p[8] = ttl;
    p[10..12].copy_from_slice(&[0, 0]);
    let mut sum: u32 = p[..20].chunks(2).map(|c| u32::from(u16::from_be_bytes([c[0], c[1]]))).sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    p[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
}

#[test]
fn neighbor_traffic_is_forwarded_with_ttl_decremented() {
    let b = lan_frame(HOST_MAC, GW_MAC, HOST_IP, PEER_IP);
    let mut out = [0u8; MAX_FRAME];
    let FromLan::Forward(n) = from_lan(&CFG, &b, &mut out) else { panic!("not forwarded") };
    assert_eq!(&out[..n], &hopped(&b[wire::ETH_HDR..])[..]);
    assert_eq!(out[8], b[wire::ETH_HDR + 8] - 1);
}

#[test]
fn lan_datagram_with_ttl_one_is_dropped() {
    let mut b = lan_frame(HOST_MAC, GW_MAC, HOST_IP, PEER_IP);
    set_ttl(&mut b[wire::ETH_HDR..], 1);
    assert_eq!(from(&b), FromLan::Dropped(DropReason::TtlExpired));
    set_ttl(&mut b[wire::ETH_HDR..], 2);
    assert!(matches!(from(&b), FromLan::Forward(_)));
}

#[test]
fn tunnel_datagram_with_ttl_two_is_delivered_with_ttl_one() {
    let mut p = datagram(PEER_IP, HOST_IP);
    set_ttl(&mut p, 2);
    let mut out = [0u8; MAX_FRAME];
    let ToLan::Emitted(n) = to_lan(&CFG, &p, &mut out) else { panic!("not emitted") };
    assert_eq!(out[wire::ETH_HDR + 8], 1);
    assert_eq!(&out[wire::ETH_HDR..n], &hopped(&p)[..]);
}

#[test]
fn tunnel_datagram_with_ttl_one_is_dropped() {
    let mut p = datagram(PEER_IP, HOST_IP);
    set_ttl(&mut p, 1);
    assert_eq!(to_lan(&CFG, &p, &mut [0u8; MAX_FRAME]), ToLan::Dropped(DropReason::TtlExpired));
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
    assert_eq!(&out[wire::ETH_HDR..n], &hopped(&p)[..]);
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

// ---- HTTPS backend link (M6 plan C4) ----

fn checksum(bytes: &[u8], initial: u32) -> u16 {
    let mut sum = initial;
    for c in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// A TCP/IPv4 datagram (TTL 64) with both checksums right.
fn tcp(src: Ipv4, sport: u16, dst: Ipv4, dport: u16, flags: u8) -> Vec<u8> {
    let mut seg = std::vec![0u8; wire::TCP_HDR];
    seg[0..2].copy_from_slice(&sport.to_be_bytes());
    seg[2..4].copy_from_slice(&dport.to_be_bytes());
    seg[4..8].copy_from_slice(&0x1234_5678u32.to_be_bytes());
    seg[12] = 5 << 4;
    seg[13] = flags;
    seg[14..16].copy_from_slice(&64240u16.to_be_bytes());
    seg.extend_from_slice(b"GET");
    let mut pseudo = std::vec![0u8; 0];
    pseudo.extend_from_slice(&src);
    pseudo.extend_from_slice(&dst);
    pseudo.extend_from_slice(&[0, wire::IPPROTO_TCP]);
    pseudo.extend_from_slice(&(seg.len() as u16).to_be_bytes());
    let pseudo_sum = pseudo.chunks(2).map(|c| u32::from(u16::from_be_bytes([c[0], c[1]]))).sum();
    let c = checksum(&seg, pseudo_sum);
    seg[16..18].copy_from_slice(&c.to_be_bytes());
    let mut p = std::vec![0x45, 0];
    p.extend_from_slice(&((20 + seg.len()) as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0, 0x40, 0, 64, wire::IPPROTO_TCP, 0, 0]);
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    let c = checksum(&p, 0);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p.extend_from_slice(&seg);
    p
}

fn eth(src_mac: Mac, dst_mac: Mac, packet: &[u8]) -> Vec<u8> {
    let mut b = std::vec![0u8; 0];
    b.extend_from_slice(&dst_mac);
    b.extend_from_slice(&src_mac);
    b.extend_from_slice(&[0x08, 0x00]);
    b.extend_from_slice(packet);
    b
}

/// The backend's segment from its port to `dport`, framed from its MAC.
fn from_backend(dport: u16) -> Vec<u8> {
    eth(HOST_MAC, GW_MAC, &tcp(HOST_IP, BACKEND_PORT, GW_IP, dport, wire::TCP_SYN | wire::TCP_ACK))
}

/// `tls`'s connection request from `sport` to the backend.
fn to_backend(sport: u16) -> Vec<u8> {
    tcp(GW_IP, sport, HOST_IP, BACKEND_PORT, wire::TCP_SYN)
}

fn out_of_tls(packet: &[u8]) -> FromTls {
    from_tls(&CFG, packet, &mut [0u8; MAX_FRAME])
}

#[test]
fn backend_syn_ack_to_a_tls_port_is_delivered_unchanged() {
    let b = from_backend(TLS_START + 7);
    let mut out = [0u8; MAX_FRAME];
    let FromLan::Tls(n) = from_lan(&CFG, &b, &mut out) else { panic!("not delivered") };
    assert_eq!(&out[..n], &b[wire::ETH_HDR..]);
    assert_eq!(out[8], 64);
}

#[test]
fn backend_segment_with_ttl_one_is_still_delivered() {
    let mut b = from_backend(TLS_START);
    set_ttl(&mut b[wire::ETH_HDR..], 1);
    let mut out = [0u8; MAX_FRAME];
    let FromLan::Tls(n) = from_lan(&CFG, &b, &mut out) else { panic!("not delivered") };
    assert_eq!(out[8], 1);
    assert_eq!(&out[..n], &b[wire::ETH_HDR..]);
}

#[test]
fn backend_segment_to_the_first_and_last_tls_port_is_delivered() {
    assert!(matches!(from(&from_backend(TLS_START)), FromLan::Tls(_)));
    assert!(matches!(from(&from_backend(TLS_LAST)), FromLan::Tls(_)));
}

#[test]
fn backend_segment_to_a_port_outside_tls_ports_has_no_service() {
    assert_eq!(from(&from_backend(TLS_START - 1)), FromLan::NoService);
    assert_eq!(from(&from_backend(TLS_LAST + 1)), FromLan::NoService);
}

#[test]
fn tls_ports_ending_at_65535_include_it_without_overflow() {
    let cfg = Config { tls_ports: (65535 - 1023, 1024), ..CFG };
    let mut out = [0u8; MAX_FRAME];
    assert!(matches!(from_lan(&cfg, &from_backend(65535), &mut out), FromLan::Tls(_)));
    assert_eq!(from_lan(&cfg, &from_backend(65535 - 1024), &mut out), FromLan::NoService);
}

#[test]
fn backend_segment_from_another_port_has_no_service() {
    let b = eth(HOST_MAC, GW_MAC, &tcp(HOST_IP, BACKEND_PORT + 1, GW_IP, TLS_START, wire::TCP_ACK));
    assert_eq!(from(&b), FromLan::NoService);
}

#[test]
fn segment_from_another_inside_host_does_not_reach_tls() {
    let b = eth(OTHER_HOST_MAC, GW_MAC, &tcp(OTHER_HOST_IP, BACKEND_PORT, GW_IP, TLS_START, wire::TCP_ACK));
    assert_eq!(from(&b), FromLan::NoService);
}

#[test]
fn backend_address_from_another_mac_is_spoofed() {
    let b = eth(OTHER_HOST_MAC, GW_MAC, &tcp(HOST_IP, BACKEND_PORT, GW_IP, TLS_START, wire::TCP_ACK));
    assert_eq!(from(&b), FromLan::Spoofed);
}

#[test]
fn non_tcp_from_the_backend_has_no_service() {
    assert_eq!(from(&lan_frame(HOST_MAC, GW_MAC, HOST_IP, GW_IP)), FromLan::NoService);
}

#[test]
fn malformed_backend_segment_is_dropped_with_its_reason() {
    let mut b = from_backend(TLS_START);
    let last = b.len() - 1;
    b[last] ^= 1;
    assert_eq!(from(&b), FromLan::Dropped(DropReason::TcpBadChecksum));
}

#[test]
fn backend_segment_to_another_host_is_forwarded_as_before() {
    let b = eth(HOST_MAC, GW_MAC, &tcp(HOST_IP, BACKEND_PORT, PEER_IP, TLS_START, wire::TCP_ACK));
    let mut out = [0u8; MAX_FRAME];
    let FromLan::Forward(n) = from_lan(&CFG, &b, &mut out) else { panic!("not forwarded") };
    assert_eq!(&out[..n], &hopped(&b[wire::ETH_HDR..])[..]);
}

#[test]
fn backend_segment_larger_than_the_output_is_dropped_not_panicked() {
    assert_eq!(from_lan(&CFG, &from_backend(TLS_START), &mut [0u8; 40]), FromLan::Dropped(DropReason::TooLong));
}

#[test]
fn tls_syn_to_the_backend_leaves_framed_to_its_mac_unchanged() {
    let p = to_backend(TLS_START + 7);
    let mut out = [0u8; MAX_FRAME];
    let FromTls::Emitted(n) = from_tls(&CFG, &p, &mut out) else { panic!("not emitted") };
    assert_eq!(&out[..6], &HOST_MAC);
    assert_eq!(&out[6..12], &GW_MAC);
    assert_eq!(&out[wire::ETH_HDR..n], &p[..]);
    assert_eq!(out[wire::ETH_HDR + 8], 64);
}

#[test]
fn tls_segment_with_ttl_one_still_leaves() {
    let mut p = to_backend(TLS_START);
    set_ttl(&mut p, 1);
    let mut out = [0u8; MAX_FRAME];
    let FromTls::Emitted(n) = from_tls(&CFG, &p, &mut out) else { panic!("not emitted") };
    assert_eq!(&out[wire::ETH_HDR..n], &p[..]);
}

#[test]
fn tls_segment_from_the_first_and_last_tls_port_leaves() {
    assert!(matches!(out_of_tls(&to_backend(TLS_START)), FromTls::Emitted(_)));
    assert!(matches!(out_of_tls(&to_backend(TLS_LAST)), FromTls::Emitted(_)));
}

#[test]
fn tls_segment_from_a_port_outside_tls_ports_is_refused() {
    assert_eq!(out_of_tls(&to_backend(TLS_START - 1)), FromTls::Refused);
    assert_eq!(out_of_tls(&to_backend(TLS_LAST + 1)), FromTls::Refused);
}

#[test]
fn tls_segment_from_another_source_address_is_refused() {
    assert_eq!(out_of_tls(&tcp(OTHER_HOST_IP, TLS_START, HOST_IP, BACKEND_PORT, wire::TCP_SYN)), FromTls::Refused);
}

#[test]
fn tls_segment_to_another_inside_host_is_refused() {
    assert_eq!(out_of_tls(&tcp(GW_IP, TLS_START, OTHER_HOST_IP, BACKEND_PORT, wire::TCP_SYN)), FromTls::Refused);
}

#[test]
fn tls_segment_to_another_backend_port_is_refused() {
    assert_eq!(out_of_tls(&tcp(GW_IP, TLS_START, HOST_IP, BACKEND_PORT + 1, wire::TCP_SYN)), FromTls::Refused);
    assert_eq!(out_of_tls(&tcp(GW_IP, TLS_START, HOST_IP, 22, wire::TCP_SYN)), FromTls::Refused);
}

#[test]
fn tls_segment_to_a_tunnel_peer_is_refused() {
    assert_eq!(out_of_tls(&tcp(GW_IP, TLS_START, PEER_IP, BACKEND_PORT, wire::TCP_SYN)), FromTls::Refused);
}

#[test]
fn non_tcp_from_tls_is_refused() {
    assert_eq!(out_of_tls(&datagram(GW_IP, HOST_IP)), FromTls::Refused);
}

#[test]
fn malformed_tls_segment_is_dropped_with_its_reason() {
    let mut p = to_backend(TLS_START);
    let last = p.len() - 1;
    p[last] ^= 1;
    assert_eq!(out_of_tls(&p), FromTls::Dropped(DropReason::TcpBadChecksum));
    let mut p = to_backend(TLS_START);
    p[10] ^= 1;
    assert_eq!(out_of_tls(&p), FromTls::Dropped(DropReason::Ipv4BadChecksum));
}

#[test]
fn oversized_tls_packet_is_dropped() {
    let mut p = to_backend(TLS_START);
    p.resize(MAX_FRAME - wire::ETH_HDR + 1, 0);
    assert_eq!(out_of_tls(&p), FromTls::Dropped(DropReason::TooLong));
}

#[test]
fn backend_that_is_not_a_neighbor_is_unknown() {
    let cfg = Config { neighbors: &[(OTHER_HOST_IP, OTHER_HOST_MAC)], ..CFG };
    assert_eq!(from_tls(&cfg, &to_backend(TLS_START), &mut [0u8; MAX_FRAME]), FromTls::UnknownNeighbor);
}

#[test]
fn small_output_buffer_for_tls_is_reported_not_panicked() {
    assert_eq!(from_tls(&CFG, &to_backend(TLS_START), &mut [0u8; 20]), FromTls::NoBuffer);
}
