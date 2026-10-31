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
    from_tls(&CFG, packet, NET_BUFFERS, &mut [0u8; MAX_FRAME])
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
    let FromTls::Emitted(n) = from_tls(&CFG, &p, NET_BUFFERS, &mut out) else { panic!("not emitted") };
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
    let FromTls::Emitted(n) = from_tls(&CFG, &p, NET_BUFFERS, &mut out) else { panic!("not emitted") };
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
    assert_eq!(from_tls(&cfg, &to_backend(TLS_START), NET_BUFFERS, &mut [0u8; MAX_FRAME]), FromTls::UnknownNeighbor);
}

#[test]
fn small_output_buffer_for_tls_is_reported_not_panicked() {
    assert_eq!(from_tls(&CFG, &to_backend(TLS_START), NET_BUFFERS, &mut [0u8; 20]), FromTls::NoBuffer);
}

/// S1 (M6 code review): `tls`'s segments take an inside TX buffer only
/// above the reserve and their share; at the boundary itself they are
/// refused, one buffer above it they leave.
#[test]
fn tls_segment_at_its_tier_boundary_is_refused() {
    let edge = INNER_TX_RESERVE + TLS_TX_SHARE_INSIDE;
    assert_eq!(from_tls(&CFG, &to_backend(TLS_START), edge, &mut [0u8; MAX_FRAME]), FromTls::TxReserve);
}

#[test]
fn tls_segment_one_buffer_above_its_tier_leaves() {
    let edge = INNER_TX_RESERVE + TLS_TX_SHARE_INSIDE;
    assert!(matches!(from_tls(&CFG, &to_backend(TLS_START), edge + 1, &mut [0u8; MAX_FRAME]), FromTls::Emitted(_)));
}

/// Code review round 2 (S-N2): a backend abort's bare RST|ACK has no tier
/// of its own; at the inside tier's edge it is refused like any other
/// `tls` segment and not resent (the inside RST-loss residual).
#[test]
fn a_bare_rst_ack_is_refused_at_the_inside_tier_edge() {
    let rst = tcp(GW_IP, TLS_START, HOST_IP, BACKEND_PORT, wire::TCP_RST | wire::TCP_ACK);
    let edge = INNER_TX_RESERVE + TLS_TX_SHARE_INSIDE;
    assert_eq!(from_tls(&CFG, &rst, edge, &mut [0u8; MAX_FRAME]), FromTls::TxReserve);
}

#[test]
fn a_bare_rst_ack_leaves_one_buffer_above_the_inside_tier_edge() {
    let rst = tcp(GW_IP, TLS_START, HOST_IP, BACKEND_PORT, wire::TCP_RST | wire::TCP_ACK);
    let edge = INNER_TX_RESERVE + TLS_TX_SHARE_INSIDE;
    assert!(matches!(from_tls(&CFG, &rst, edge + 1, &mut [0u8; MAX_FRAME]), FromTls::Emitted(_)));
}

// ---- Group authorization and the flow table (M8 plan C8, T26) ----

mod flows {
    use super::{HOST_IP, OTHER_HOST_IP, PEER_IP, datagram, std, tcp};
    use crate::flow::*;
    use policy_wire::{PROTO_ICMP, PROTO_TCP, PROTO_UDP, Prefix, Rule};
    use wire::{DropReason, Ipv4, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};

    /// Peer X (0) is in groups 0 (TCP 8000 on the host), 2 (ICMP echo to the
    /// inside /24) and 3 (all UDP to the inside /24); Y (1) only in group 1
    /// (TCP 9000 on the host); Z (2) in none. The bundle names three peers.
    const X: u8 = 0;
    const Y: u8 = 1;
    const Z: u8 = 2;
    const Y_IP: Ipv4 = [10, 200, 0, 3];
    const P: u16 = 8000;
    const Q: u16 = 8001;
    const R: u16 = 9000;
    const HOST: Prefix = Prefix { addr: HOST_IP, len: 32 };
    const INSIDE: Prefix = Prefix { addr: [10, 99, 0, 0], len: 24 };
    const G0: &[Rule] = &[Rule { dst: HOST, proto: PROTO_TCP, port_lo: P, port_hi: P }];
    const G1: &[Rule] = &[Rule { dst: HOST, proto: PROTO_TCP, port_lo: R, port_hi: R }];
    const G2: &[Rule] = &[Rule { dst: INSIDE, proto: PROTO_ICMP, port_lo: 0, port_hi: 0 }];
    const G3: &[Rule] = &[Rule { dst: INSIDE, proto: PROTO_UDP, port_lo: 0, port_hi: 65535 }];
    const GROUPS: &[&[Rule]] = &[G0, G1, G2, G3];
    const PEERS: &[u8] = &[0b1101, 0b0010, 0];
    const RULES: ModelRules<'static> = ModelRules { peers: PEERS, groups: GROUPS };
    const T0: u64 = 1_000_000_000;

    fn tcp_in(src: Ipv4, sport: u16, dport: u16, flags: u8) -> Packet {
        Packet { src, dst: HOST_IP, transport: Transport::Tcp { sport, dport, flags } }
    }

    /// The LAN host's segment back to `dst`.
    fn tcp_out(dst: Ipv4, dport: u16, sport: u16, flags: u8) -> Packet {
        Packet { src: HOST_IP, dst, transport: Transport::Tcp { sport, dport, flags } }
    }

    fn icmp(src: Ipv4, dst: Ipv4, transport: Transport) -> Packet {
        Packet { src, dst, transport }
    }

    fn inbound(t: &mut FlowTable, peer: u8, p: Packet, now: u64) -> Inbound {
        t.authorize_inbound(&RULES, peer, &p, now)
    }

    fn outbound(t: &mut FlowTable, p: Packet, now: u64) -> Outbound {
        t.authorize_outbound(&p, now)
    }

    fn no_flow(dst: Ipv4) -> Outbound {
        Outbound::Deny { reason: Denied::NoFlow, dst }
    }

    /// X opens 40000 → host:P with a SYN at T0.
    fn opened() -> FlowTable {
        let mut t = FlowTable::new();
        assert_eq!(inbound(&mut t, X, tcp_in(PEER_IP, 40000, P, TCP_SYN), T0), Inbound::Allow);
        t
    }

    fn reply(flags: u8) -> Packet {
        tcp_out(PEER_IP, 40000, P, flags)
    }

    #[test]
    fn a_peer_reaches_its_groups_rule_port_and_not_the_next_one() {
        let mut t = FlowTable::new();
        assert_eq!(inbound(&mut t, X, tcp_in(PEER_IP, 40000, P, TCP_SYN), T0), Inbound::Allow);
        assert_eq!(inbound(&mut t, X, tcp_in(PEER_IP, 40001, Q, TCP_SYN), T0), Inbound::Deny(Denied::NoRule));
        assert_eq!((t.live(X, T0), t.live(Y, T0)), (1, 0));
    }

    #[test]
    fn a_peer_outside_a_group_is_denied_its_rule_but_reaches_its_own() {
        let mut t = FlowTable::new();
        assert_eq!(inbound(&mut t, Y, tcp_in(Y_IP, 40000, P, TCP_SYN), T0), Inbound::Deny(Denied::NoRule));
        assert_eq!(inbound(&mut t, Y, tcp_in(Y_IP, 40000, R, TCP_SYN), T0), Inbound::Allow);
        assert_eq!(inbound(&mut t, X, tcp_in(PEER_IP, 40000, R, TCP_SYN), T0), Inbound::Deny(Denied::NoRule));
    }

    #[test]
    fn a_peer_with_no_groups_reaches_nothing() {
        let mut t = FlowTable::new();
        let echo = icmp(PEER_IP, HOST_IP, Transport::EchoRequest { id: 1 });
        for p in [tcp_in(PEER_IP, 40000, P, TCP_SYN), echo] {
            assert_eq!(inbound(&mut t, Z, p, T0), Inbound::Deny(Denied::NoRule));
            assert_eq!(inbound(&mut t, X, p, T0), Inbound::Allow);
        }
        assert_eq!(t.live(Z, T0), 0);
    }

    #[test]
    fn a_peer_the_bundle_does_not_name_is_unknown() {
        let mut t = FlowTable::new();
        let p = tcp_in(PEER_IP, 40000, P, TCP_SYN);
        for peer in [3, 7, 8, 200, u8::MAX] {
            assert_eq!(inbound(&mut t, peer, p, T0), Inbound::Deny(Denied::UnknownPeer), "peer {peer}");
        }
        assert_eq!(inbound(&mut t, X, p, T0), Inbound::Allow);
        // The byte path refuses it before parsing anything.
        assert_eq!(t.inbound(&RULES, 3, b"not even ipv4", T0), Inbound::Deny(Denied::UnknownPeer));
    }

    #[test]
    fn icmp_rules_admit_echo_requests_only() {
        let mut t = FlowTable::new();
        let to = [10, 99, 0, 7];
        assert_eq!(inbound(&mut t, X, icmp(PEER_IP, to, Transport::EchoRequest { id: 7 }), T0), Inbound::Allow);
        assert_eq!(inbound(&mut t, X, icmp(PEER_IP, to, Transport::EchoReply { id: 7 }), T0), Inbound::Deny(Denied::NoRule));
        assert_eq!(inbound(&mut t, X, icmp(PEER_IP, to, Transport::Other), T0), Inbound::Deny(Denied::NoRule));
        assert_eq!(inbound(&mut t, X, icmp(PEER_IP, to, Transport::IcmpError), T0), Inbound::Deny(Denied::IcmpError));
        // Outside the rule's prefix.
        let away = icmp(PEER_IP, [10, 98, 0, 7], Transport::EchoRequest { id: 7 });
        assert_eq!(inbound(&mut t, X, away, T0), Inbound::Deny(Denied::NoRule));
    }

    #[test]
    fn an_icmp_echo_reply_passes_only_with_the_requests_id() {
        let mut t = FlowTable::new();
        let request = icmp(PEER_IP, HOST_IP, Transport::EchoRequest { id: 7 });
        assert_eq!(inbound(&mut t, X, request, T0), Inbound::Allow);
        assert_eq!(outbound(&mut t, icmp(HOST_IP, PEER_IP, Transport::EchoReply { id: 7 }), T0), Outbound::Allow { peer: X });
        assert_eq!(outbound(&mut t, icmp(HOST_IP, PEER_IP, Transport::EchoReply { id: 8 }), T0), no_flow(PEER_IP));
        // The LAN cannot ping the peer back on the same id.
        assert_eq!(outbound(&mut t, icmp(HOST_IP, PEER_IP, Transport::EchoRequest { id: 7 }), T0), no_flow(PEER_IP));
    }

    #[test]
    fn icmp_errors_from_the_lan_are_dropped_even_on_a_live_flow() {
        let mut t = opened();
        let error = icmp(HOST_IP, PEER_IP, Transport::IcmpError);
        assert_eq!(outbound(&mut t, error, T0), Outbound::Deny { reason: Denied::IcmpError, dst: PEER_IP });
        assert_eq!(outbound(&mut t, reply(TCP_SYN | TCP_ACK), T0), Outbound::Allow { peer: X });
    }

    #[test]
    fn an_unsolicited_lan_packet_is_denied_and_a_reply_passes() {
        let mut t = FlowTable::new();
        assert_eq!(outbound(&mut t, reply(TCP_SYN | TCP_ACK), T0), no_flow(PEER_IP));
        let mut t = opened();
        assert_eq!(outbound(&mut t, reply(TCP_SYN | TCP_ACK), T0), Outbound::Allow { peer: X });
        // Another LAN host, or another port, is not the flow's other end.
        assert_eq!(outbound(&mut t, Packet { src: OTHER_HOST_IP, ..reply(TCP_ACK) }, T0), no_flow(PEER_IP));
        assert_eq!(outbound(&mut t, tcp_out(PEER_IP, 40000, Q, TCP_ACK), T0), no_flow(PEER_IP));
        // A LAN-opened connection to the peer is no reply either.
        assert_eq!(outbound(&mut t, tcp_out(PEER_IP, 22, 50000, TCP_SYN), T0), no_flow(PEER_IP));
    }

    #[test]
    fn a_reply_on_xs_flow_never_leaves_as_peer_y() {
        let mut t = opened();
        assert_eq!(inbound(&mut t, Y, tcp_in(Y_IP, 40000, R, TCP_SYN), T0), Inbound::Allow);
        assert_eq!(outbound(&mut t, reply(TCP_SYN | TCP_ACK), T0), Outbound::Allow { peer: X });
        assert_eq!(outbound(&mut t, tcp_out(Y_IP, 40000, R, TCP_SYN | TCP_ACK), T0), Outbound::Allow { peer: Y });
        // Y's flow is from Y's address: a reply to X's address on Y's ports
        // matches neither.
        assert_eq!(outbound(&mut t, tcp_out(PEER_IP, 40000, R, TCP_ACK), T0), no_flow(PEER_IP));
    }

    #[test]
    fn a_full_share_evicts_the_peers_own_least_recently_used_flow_only() {
        let mut t = FlowTable::new();
        assert_eq!(inbound(&mut t, Y, tcp_in(Y_IP, 40000, R, TCP_SYN), T0), Inbound::Allow);
        for i in 0..QUOTA as u16 {
            assert_eq!(inbound(&mut t, X, tcp_in(PEER_IP, 1000 + i, P, TCP_SYN), T0 + 1 + u64::from(i)), Inbound::Allow);
        }
        let later = T0 + 1000;
        // The oldest of X's flows is still there while the share has room.
        assert_eq!(t.live(X, later), QUOTA);
        // Used again, the first is no longer the least recently used.
        assert_eq!(outbound(&mut t, tcp_out(PEER_IP, 1000, P, TCP_ACK), later), Outbound::Allow { peer: X });
        assert_eq!(inbound(&mut t, X, tcp_in(PEER_IP, 2000, P, TCP_SYN), later + 1), Inbound::Allow);
        assert_eq!(t.live(X, later + 1), QUOTA);
        assert_eq!(outbound(&mut t, tcp_out(PEER_IP, 1001, P, TCP_ACK), later + 2), no_flow(PEER_IP));
        assert_eq!(outbound(&mut t, tcp_out(PEER_IP, 1000, P, TCP_ACK), later + 2), Outbound::Allow { peer: X });
        assert_eq!(outbound(&mut t, tcp_out(PEER_IP, 2000, P, TCP_ACK), later + 2), Outbound::Allow { peer: X });
        // Y's one flow, older than all of X's, was never a candidate.
        assert_eq!(t.live(Y, later + 2), 1);
        assert_eq!(outbound(&mut t, tcp_out(Y_IP, 40000, R, TCP_ACK), later + 2), Outbound::Allow { peer: Y });
    }

    #[test]
    fn a_flow_ends_after_the_idle_time_by_the_clock_input() {
        let mut t = opened();
        assert_eq!(outbound(&mut t, reply(TCP_ACK), T0 + limits::FLOW_IDLE_NS), Outbound::Allow { peer: X });
        let mut t = opened();
        assert_eq!(outbound(&mut t, reply(TCP_ACK), T0 + limits::FLOW_IDLE_NS + 1), no_flow(PEER_IP));
        assert_eq!(t.live(X, T0 + limits::FLOW_IDLE_NS + 1), 0);
    }

    #[test]
    fn traffic_either_way_keeps_a_flow_alive() {
        let mut t = opened();
        let half = limits::FLOW_IDLE_NS / 2 + 1;
        assert_eq!(outbound(&mut t, reply(TCP_ACK), T0 + half), Outbound::Allow { peer: X });
        assert_eq!(inbound(&mut t, X, tcp_in(PEER_IP, 40000, P, TCP_ACK), T0 + 2 * half), Inbound::Allow);
        assert_eq!(outbound(&mut t, reply(TCP_ACK), T0 + 3 * half), Outbound::Allow { peer: X });
    }

    #[test]
    fn a_half_closed_flow_stays_until_both_fins_and_the_linger() {
        let linger = limits::FLOW_LINGER_NS;
        let mut t = opened();
        assert_eq!(inbound(&mut t, X, tcp_in(PEER_IP, 40000, P, TCP_FIN | TCP_ACK), T0), Inbound::Allow);
        // One FIN only: the LAN's data still flows well past the linger.
        let t1 = T0 + 2 * linger;
        assert_eq!(outbound(&mut t, reply(TCP_ACK), t1), Outbound::Allow { peer: X });
        assert_eq!(outbound(&mut t, reply(TCP_FIN | TCP_ACK), t1), Outbound::Allow { peer: X });
        // Both FINs seen at t1: the last ACKs pass for the linger, then not.
        assert_eq!(inbound(&mut t, X, tcp_in(PEER_IP, 40000, P, TCP_ACK), t1 + linger), Inbound::Allow);
        assert_eq!(outbound(&mut t, reply(TCP_ACK), t1 + linger), Outbound::Allow { peer: X });
        assert_eq!(outbound(&mut t, reply(TCP_ACK), t1 + linger + 1), no_flow(PEER_IP));
    }

    #[test]
    fn a_fin_from_the_lan_alone_keeps_the_flow() {
        let mut t = opened();
        assert_eq!(outbound(&mut t, reply(TCP_FIN | TCP_ACK), T0), Outbound::Allow { peer: X });
        let t1 = T0 + 2 * limits::FLOW_LINGER_NS;
        assert_eq!(inbound(&mut t, X, tcp_in(PEER_IP, 40000, P, TCP_ACK), t1), Inbound::Allow);
        assert_eq!(outbound(&mut t, reply(TCP_ACK), t1), Outbound::Allow { peer: X });
    }

    #[test]
    fn a_reset_from_the_peer_ends_its_flow() {
        let mut t = opened();
        assert_eq!(inbound(&mut t, X, tcp_in(PEER_IP, 40000, P, TCP_RST), T0), Inbound::Allow);
        assert_eq!(outbound(&mut t, reply(TCP_ACK), T0), no_flow(PEER_IP));
        // Allow side: the same reply without the reset passes.
        let mut t = opened();
        assert_eq!(outbound(&mut t, reply(TCP_ACK), T0), Outbound::Allow { peer: X });
    }

    #[test]
    fn a_reset_from_the_lan_passes_and_ends_the_flow() {
        let mut t = opened();
        assert_eq!(outbound(&mut t, reply(TCP_RST | TCP_ACK), T0), Outbound::Allow { peer: X });
        assert_eq!(outbound(&mut t, reply(TCP_ACK), T0), no_flow(PEER_IP));
        // A reset of nothing tracked opens nothing.
        let mut t = FlowTable::new();
        assert_eq!(inbound(&mut t, X, tcp_in(PEER_IP, 40000, P, TCP_RST), T0), Inbound::Allow);
        assert_eq!(t.live(X, T0), 0);
    }

    #[test]
    fn a_reset_in_a_spoofed_direction_leaves_the_flow() {
        let mut t = opened();
        // From the LAN but on the forward tuple, as if the peer had sent it.
        let forward = Packet { src: PEER_IP, dst: HOST_IP, transport: Transport::Tcp { sport: 40000, dport: P, flags: TCP_RST } };
        assert_eq!(outbound(&mut t, forward, T0), no_flow(HOST_IP));
        // From peer Y with X's tuple: Y has no rule for P, and X's share is
        // not Y's to touch.
        assert_eq!(inbound(&mut t, Y, tcp_in(PEER_IP, 40000, P, TCP_RST), T0), Inbound::Deny(Denied::NoRule));
        assert_eq!(outbound(&mut t, reply(TCP_ACK), T0), Outbound::Allow { peer: X });
    }

    #[test]
    fn a_new_syn_reopens_a_lingering_tuple() {
        let mut t = opened();
        assert_eq!(inbound(&mut t, X, tcp_in(PEER_IP, 40000, P, TCP_FIN | TCP_ACK), T0), Inbound::Allow);
        assert_eq!(outbound(&mut t, reply(TCP_FIN | TCP_ACK), T0), Outbound::Allow { peer: X });
        assert_eq!(inbound(&mut t, X, tcp_in(PEER_IP, 40000, P, TCP_SYN), T0 + 1), Inbound::Allow);
        let t1 = T0 + 2 * limits::FLOW_LINGER_NS;
        assert_eq!(outbound(&mut t, reply(TCP_SYN | TCP_ACK), t1), Outbound::Allow { peer: X });
    }

    #[test]
    fn udp_rules_admit_any_port_inside_the_prefix_only() {
        let mut t = FlowTable::new();
        let udp = |dst, dport| Packet { src: PEER_IP, dst, transport: Transport::Udp { sport: 5000, dport } };
        assert_eq!(inbound(&mut t, X, udp([10, 99, 0, 9], 53), T0), Inbound::Allow);
        assert_eq!(inbound(&mut t, X, udp([10, 99, 1, 9], 53), T0), Inbound::Deny(Denied::NoRule));
        assert_eq!(inbound(&mut t, Y, udp([10, 99, 0, 9], 53), T0), Inbound::Deny(Denied::NoRule));
        let back = Packet { src: [10, 99, 0, 9], dst: PEER_IP, transport: Transport::Udp { sport: 53, dport: 5000 } };
        assert_eq!(outbound(&mut t, back, T0), Outbound::Allow { peer: X });
    }

    #[test]
    fn classify_reads_tcp_udp_and_icmp_from_the_bytes() {
        let p = classify(&tcp(PEER_IP, 40000, HOST_IP, P, TCP_SYN)).unwrap();
        assert_eq!(p, tcp_in(PEER_IP, 40000, P, TCP_SYN));
        let p = classify(&datagram(PEER_IP, HOST_IP)).unwrap();
        assert_eq!(p.transport, Transport::Udp { sport: 1, dport: 2 });
        let mut echo = std::vec![0x45, 0, 0, 28, 0, 0, 0x40, 0, 64, 1, 0, 0];
        echo.extend_from_slice(&PEER_IP);
        echo.extend_from_slice(&HOST_IP);
        let c = super::checksum(&echo, 0);
        echo[10..12].copy_from_slice(&c.to_be_bytes());
        echo.extend_from_slice(&[8, 0, 0, 0, 0, 9, 0, 1]);
        assert_eq!(classify(&echo).unwrap().transport, Transport::EchoRequest { id: 9 });
        echo[20] = 0;
        assert_eq!(classify(&echo).unwrap().transport, Transport::EchoReply { id: 9 });
        echo[20] = 11;
        assert_eq!(classify(&echo).unwrap().transport, Transport::IcmpError);
        echo[20] = 13;
        assert_eq!(classify(&echo).unwrap().transport, Transport::Other);
    }

    #[test]
    fn classify_refuses_a_bad_udp_length_and_a_fragment() {
        let mut d = datagram(PEER_IP, HOST_IP);
        assert!(classify(&d).is_ok());
        d[25] ^= 1; // UDP length
        assert_eq!(classify(&d), Err(DropReason::UdpBadLength));
        let mut f = datagram(PEER_IP, HOST_IP);
        f[6] = 0x20; // MF, the header checksum made right again
        f[10..12].copy_from_slice(&[0, 0]);
        let c = super::checksum(&f[..20], 0);
        f[10..12].copy_from_slice(&c.to_be_bytes());
        assert_eq!(classify(&f), Err(DropReason::Ipv4Fragment));
    }

    #[test]
    fn the_byte_paths_authorize_as_the_packet_paths_do() {
        let mut t = FlowTable::new();
        let syn = tcp(PEER_IP, 40000, HOST_IP, P, TCP_SYN);
        assert_eq!(t.inbound(&RULES, X, &syn, T0), Inbound::Allow);
        assert_eq!(t.inbound(&RULES, Y, &syn, T0), Inbound::Deny(Denied::NoRule));
        let mut bad = syn.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(t.inbound(&RULES, X, &bad, T0), Inbound::Malformed(DropReason::TcpBadChecksum));
        assert_eq!(t.outbound(&tcp(HOST_IP, P, PEER_IP, 40000, TCP_SYN | TCP_ACK), T0), Outbound::Allow { peer: X });
        assert_eq!(t.outbound(&tcp(HOST_IP, P, PEER_IP, 40001, TCP_SYN | TCP_ACK), T0), no_flow(PEER_IP));
    }

    #[test]
    fn the_reasons_have_stable_codes_and_names() {
        for (i, d) in Denied::ALL.iter().enumerate() {
            assert_eq!(usize::from(d.code()), i);
        }
        let names: std::vec::Vec<&str> = Denied::ALL.iter().map(|d| d.name()).collect();
        assert_eq!(names, ["NoRule", "UnknownPeer", "NoFlow", "IcmpError"]);
        assert_eq!(QUOTA * limits::MAX_PEERS, MAX_FLOWS);
    }
}
